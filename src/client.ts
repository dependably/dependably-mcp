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

export class DependablyClient {
  constructor(private readonly cfg: Config) {}

  get(path: string, query?: Query): Promise<unknown> {
    return this.request('GET', path, query);
  }
  post(path: string, body?: unknown, query?: Query): Promise<unknown> {
    return this.request('POST', path, query, body);
  }
  put(path: string, body?: unknown, query?: Query): Promise<unknown> {
    return this.request('PUT', path, query, body);
  }
  patch(path: string, body?: unknown, query?: Query): Promise<unknown> {
    return this.request('PATCH', path, query, body);
  }
  del(path: string, query?: Query): Promise<unknown> {
    return this.request('DELETE', path, query);
  }

  private async request(method: string, path: string, query?: Query, body?: unknown): Promise<unknown> {
    const url = this.buildUrl(path, query);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.cfg.token}`,
      Accept: 'application/json, application/problem+json',
    };
    let init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.cfg.timeoutMs),
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init = { ...init, body: JSON.stringify(body) };
    }

    let res: Response;
    try {
      res = await fetch(url, init);
    } catch (err) {
      throw new Error(describeFetchError(method, url, err, this.cfg.timeoutMs));
    }

    const text = await res.text();
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

  if (status === 401) return authFailed(detail, where);
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

function authFailed(detail: string, where: string): string {
  return sentence(
    '401 Authentication failed.',
    'Check that DEPENDABLY_TOKEN is set, has not expired, and is for the right Dependably instance.',
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

function serverError(status: number, detail: string, where: string): string {
  return sentence(
    `${status} Dependably server error.`,
    detail && `Server detail: ${detail}.`,
    'Check that DEPENDABLY_BASE_URL is correct and the instance is reachable.',
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

function extractCapability(text: string): string | null {
  const match = /capability[^\w]*['"`]?([a-z][a-z0-9:_*-]+)/i.exec(text);
  return match ? match[1] : null;
}
