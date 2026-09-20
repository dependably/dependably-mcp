import type { Config } from './config.js';

type QueryValue = string | number | boolean | undefined | null;
/** Array values become repeated query params (?action=a&action=b). */
type Query = Record<string, QueryValue | QueryValue[]>;

export class DependablyApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly method: string,
    readonly url: string,
    readonly body?: string,
  ) {
    super(message);
    this.name = 'DependablyApiError';
  }
}

/** Response bodies larger than this are aborted rather than buffered in full. */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * Marks a message already written for the end reader (a manual-redirect or
 * response-size rejection), so the outer catch does not re-wrap it through
 * `describeFetchError` — that function is for transport failures with no HTTP
 * response at all, and its generic phrasing would bury the specific reason.
 */
class ActionableError extends Error {}

export class DependablyClient {
  constructor(private readonly cfg: Config) {}

  /** The configured per-request timeout, for callers computing their own bounded override. */
  get timeoutMs(): number {
    return this.cfg.timeoutMs;
  }

  get(path: string, query?: Query, opts?: { timeoutMs?: number }): Promise<unknown> {
    return this.request('GET', path, query, opts?.timeoutMs);
  }

  private async request(method: string, path: string, query?: Query, timeoutMs?: number): Promise<unknown> {
    const url = this.buildUrl(path, query);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.cfg.token}`,
      Accept: 'application/json, application/problem+json',
    };
    const init: RequestInit = {
      method,
      headers,
      // The Dependably API never legitimately 3xx's a client; a redirect means
      // DEPENDABLY_BASE_URL points somewhere other than the instance itself
      // (e.g. an http:// URL bounced to https://, or a load balancer front
      // door). Following it silently would also resend the bearer token to
      // whatever host the Location header names.
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs ?? this.cfg.timeoutMs),
    };

    let res: Response;
    let text: string;
    try {
      res = await fetch(url, init);
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location') ?? '(no Location header)';
        throw new ActionableError(
          `${method} ${url} was redirected to ${location}; DEPENDABLY_BASE_URL must point at the instance itself.`,
        );
      }
      const lengthHeader = res.headers.get('content-length');
      if (lengthHeader && Number(lengthHeader) > MAX_RESPONSE_BYTES) {
        // Release the connection rather than leaving it half-read: we are
        // refusing the body on the strength of the header alone.
        try {
          await res.body?.cancel();
        } catch {
          // Best-effort; the ActionableError below is what matters to the caller.
        }
        throw new ActionableError(
          `${method} ${url} returned a body of ${lengthHeader} bytes, which exceeds the ${MAX_RESPONSE_BYTES}-byte cap.`,
        );
      }
      text = await res.text();
    } catch (err) {
      if (err instanceof ActionableError) throw new Error(err.message);
      throw new Error(describeFetchError(method, url, err, timeoutMs ?? this.cfg.timeoutMs));
    }

    // `text.length` counts UTF-16 code units, not bytes — a body full of
    // multi-byte characters could clear the cap in `.length` while still
    // being under it in bytes, or vice versa. Measure what the message and
    // the cap both claim to mean.
    const byteLength = Buffer.byteLength(text);
    if (byteLength > MAX_RESPONSE_BYTES) {
      throw new Error(
        `${method} ${url} returned a body of ${byteLength} bytes, which exceeds the ${MAX_RESPONSE_BYTES}-byte cap.`,
      );
    }

    const ctype = res.headers.get('content-type') ?? '';

    if (!res.ok) {
      const message = formatHttpError(method, url, res.status, ctype, text, res.headers);
      throw new DependablyApiError(message, res.status, method, url, text);
    }

    if (res.status === 204 || text.length === 0) return null;
    if (ctype.includes('application/json') || ctype.includes('application/problem+json')) {
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    }
    return text;
  }

  private buildUrl(path: string, query?: Query): string {
    const p = path.startsWith('/') ? path : `/${path}`;
    const url = new URL(`${this.cfg.baseUrl}${p}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        for (const item of Array.isArray(v) ? v : [v]) {
          if (item === undefined || item === null || item === '') continue;
          url.searchParams.append(k, String(item));
        }
      }
    }
    return url.toString();
  }
}

/**
 * Turns a failed `fetch` (no HTTP response at all) into a message that says
 * what to check. Node reports every transport failure as a bare "fetch failed"
 * with the real reason on `cause`, which is useless to a user staring at a
 * config dialog; surface the cause and the setting that fixes it.
 */
export function describeFetchError(method: string, url: string, err: unknown, timeoutMs: number): string {
  if (err instanceof Error && err.name === 'TimeoutError') {
    return `${method} ${url} timed out after ${timeoutMs}ms. Raise DEPENDABLY_TIMEOUT_MS if the instance is just slow.`;
  }
  const cause = err instanceof Error && err.cause instanceof Error ? err.cause : undefined;
  const code = (cause as (Error & { code?: string }) | undefined)?.code ?? '';
  const reason = cause?.message ?? (err instanceof Error ? err.message : String(err));
  const codeSuffix = code ? ` (${code})` : '';
  return `${method} ${url} failed: ${reason}${codeSuffix}. ${transportHint(code, hostOf(url))}`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN']);
const UNREACHABLE_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH']);
const DROPPED_CODES = new Set(['ECONNRESET', 'EPIPE']);
const TLS_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_HAS_EXPIRED',
  'ERR_SSL_WRONG_VERSION_NUMBER',
]);

/** Which setting to check, given the transport-level failure code. */
function transportHint(code: string, host: string): string {
  if (DNS_CODES.has(code)) {
    return `Could not resolve "${host}". Check DEPENDABLY_BASE_URL for a typo, and that this machine can reach the instance (VPN?).`;
  }
  if (UNREACHABLE_CODES.has(code)) {
    return `Nothing is listening at ${host}. Check DEPENDABLY_BASE_URL (scheme and port) and that the Dependably instance is up.`;
  }
  if (TLS_CODES.has(code) || code.startsWith('ERR_TLS_')) {
    return (
      `TLS handshake with ${host} failed. If the instance uses a private CA, point NODE_EXTRA_CA_CERTS at the CA bundle (PEM) ` +
      `in the environment that launches this server; never disable certificate verification. ` +
      `If the instance is plain HTTP, use http:// in DEPENDABLY_BASE_URL.`
    );
  }
  if (DROPPED_CODES.has(code)) {
    return `The connection to ${host} was dropped. Retry; if it persists, check a proxy or load balancer in front of the instance.`;
  }
  return `Check DEPENDABLY_BASE_URL and that the instance is reachable from this machine.`;
}

export function formatHttpError(
  method: string,
  url: string,
  status: number,
  ctype: string,
  body: string,
  headers: Headers,
): string {
  const problem = parseProblem(ctype, body);
  const detail = problem?.detail ?? '';
  const where = `(${method} ${url})`;

  if (status === 401) return authFailed(detail, body, where);
  if (status === 403) return permissionDenied(detail, body, where);
  if (status === 429) return rateLimited(detail, headers, where);
  if (status >= 500) return serverError(status, detail, where);
  if (problem) return problemMessage(status, problem, detail, where);
  return bareMessage(status, method, url, body);
}

/** Join the non-empty parts of a message with single spaces. */
function sentence(...parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/**
 * A 401 whose detail names a capability is ambiguous by construction: Dependably
 * sends the same body for "no token" and for "a valid token without this
 * capability", so the cause cannot be told apart from here. Name the capability
 * without claiming which it is — leading with "check that the token has not
 * expired" alone sends someone to rotate a credential that is working.
 */
function authFailed(detail: string, body: string, where: string): string {
  const cap = extractCapability(detail) ?? extractCapability(body);
  return sentence(
    '401 Authentication failed.',
    cap
      ? `This endpoint needs the "${cap}" capability: either DEPENDABLY_TOKEN is unset or expired, or it is valid but was not minted with that capability.`
      : 'Check that DEPENDABLY_TOKEN is set, has not expired, and is for the right Dependably instance.',
    detail && `Server detail: ${detail}`,
    where,
  );
}

function permissionDenied(detail: string, body: string, where: string): string {
  const cap = extractCapability(detail) ?? extractCapability(body);
  return sentence(
    '403 Permission denied.',
    cap ? `Your token lacks the "${cap}" capability.` : 'Your token lacks the capability required for this operation.',
    !cap && detail && `Server detail: ${detail}`,
    where,
  );
}

function rateLimited(detail: string, headers: Headers, where: string): string {
  const retryAfter = headers.get('retry-after');
  return sentence(
    '429 Rate limited.',
    retryAfter ? `Retry after ${retryAfter} (seconds or HTTP date).` : 'Retry after a short delay.',
    detail && `Server detail: ${detail}`,
    where,
  );
}

/**
 * A 5xx means something answered at that URL, so the base URL resolved and the
 * network path works — telling the reader to check `DEPENDABLY_BASE_URL` sends
 * them to verify config that the response itself has already proven correct.
 * `/lookup` in particular returns 503 when an *upstream* registry is unreachable,
 * which is a fault beyond the instance rather than a client misconfiguration.
 */
function serverError(status: number, detail: string, where: string): string {
  return sentence(
    `${status} Dependably server error.`,
    detail && `Server detail: ${detail}`,
    'The instance answered, so DEPENDABLY_BASE_URL is reachable — this is a fault on the server or on an upstream it depends on. Retry, then check the instance logs.',
    where,
  );
}

function problemMessage(status: number, problem: Problem, detail: string, where: string): string {
  const title = problem.title ?? `HTTP ${status}`;
  const detailPart = detail ? `: ${detail}` : '';
  const errorsPart = problem.errors ? ` ${JSON.stringify(problem.errors)}` : '';
  return `${status} ${title}${detailPart}${errorsPart} ${where}`;
}

function bareMessage(status: number, method: string, url: string, body: string): string {
  const snippet = body.length > 500 ? `${body.slice(0, 500)}…` : body;
  const snippetPart = snippet ? `: ${snippet}` : '';
  return `${status} ${method} ${url}${snippetPart}`;
}

type Problem = { title?: string; detail?: string; errors?: unknown };

function parseProblem(ctype: string, body: string): Problem | null {
  if (!ctype.includes('application/problem+json') && !ctype.includes('application/json')) {
    return null;
  }
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    return {
      title: typeof parsed.title === 'string' ? parsed.title : undefined,
      detail: typeof parsed.detail === 'string' ? parsed.detail : undefined,
      errors: parsed.errors,
    };
  } catch {
    return null;
  }
}

/**
 * A capability is `verb:leaf` — `read:tenant`, `publish:cargo`, `tenant:configure`,
 * `yank:*`. Requiring that shape is what keeps an ordinary English word out of the
 * message.
 */
const CAPABILITY = String.raw`[a-z][a-z0-9_-]*:[a-z0-9:_*-]+`;

/**
 * Pull the capability name out of a server error detail.
 *
 * Dependably writes the name on either side of the noun: `"read:tenant capability
 * required."` is the dominant form across the controllers, `"…with read:audit
 * capability."` the other. Both positions are searched, the leading form first.
 *
 * The capture has to look like a capability rather than merely sit next to the
 * word. Matching any adjacent token turned `"…capability required."` into a claim
 * that the token lacked a capability named "required", sending the reader after a
 * grant that does not exist. A wrong name is worse than none, so anything that
 * does not match the shape falls through to the generic message.
 */
export function extractCapability(text: string): string | null {
  const leading = new RegExp(`(${CAPABILITY})\\s+capability`, 'i').exec(text);
  if (leading) return leading[1];
  const trailing = new RegExp(`capability[^\\w]*['"\`]?(${CAPABILITY})`, 'i').exec(text);
  return trailing ? trailing[1] : null;
}
