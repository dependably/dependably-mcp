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
  const host = (() => {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  })();

  let hint: string;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    hint = `Could not resolve "${host}". Check DEPENDABLY_BASE_URL for a typo, and that this machine can reach the instance (VPN?).`;
  } else if (code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    hint = `Nothing is listening at ${host}. Check DEPENDABLY_BASE_URL (scheme and port) and that the Dependably instance is up.`;
  } else if (
    code.startsWith('ERR_TLS_') ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' ||
    code === 'CERT_HAS_EXPIRED' ||
    code === 'ERR_SSL_WRONG_VERSION_NUMBER'
  ) {
    hint =
      `TLS handshake with ${host} failed. If the instance uses a private CA, point NODE_EXTRA_CA_CERTS at the CA bundle (PEM) ` +
      `in the environment that launches this server; never disable certificate verification. ` +
      `If the instance is plain HTTP, use http:// in DEPENDABLY_BASE_URL.`;
  } else if (code === 'ECONNRESET' || code === 'EPIPE') {
    hint = `The connection to ${host} was dropped. Retry; if it persists, check a proxy or load balancer in front of the instance.`;
  } else {
    hint = `Check DEPENDABLY_BASE_URL and that the instance is reachable from this machine.`;
  }
  return `${method} ${url} failed: ${reason}${code ? ` (${code})` : ''}. ${hint}`;
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

  if (status === 401) {
    return [
      '401 Authentication failed.',
      'Check that DEPENDABLY_TOKEN is set, has not expired, and is for the right Dependably instance.',
      detail ? `Server detail: ${detail}` : '',
      `(${method} ${url})`,
    ]
      .filter(Boolean)
      .join(' ');
  }

  if (status === 403) {
    const cap = extractCapability(detail) ?? extractCapability(body);
    return [
      '403 Permission denied.',
      cap
        ? `Your token lacks the "${cap}" capability.`
        : 'Your token lacks the capability required for this operation.',
      detail && !cap ? `Server detail: ${detail}` : '',
      `(${method} ${url})`,
    ]
      .filter(Boolean)
      .join(' ');
  }

  if (status === 429) {
    const retryAfter = headers.get('retry-after');
    return [
      '429 Rate limited.',
      retryAfter ? `Retry after ${retryAfter} (seconds or HTTP date).` : 'Retry after a short delay.',
      detail ? `Server detail: ${detail}` : '',
      `(${method} ${url})`,
    ]
      .filter(Boolean)
      .join(' ');
  }

  if (status >= 500) {
    return [
      `${status} Dependably server error.`,
      detail ? `Server detail: ${detail}.` : '',
      'Check that DEPENDABLY_BASE_URL is correct and the instance is reachable.',
      `(${method} ${url})`,
    ]
      .filter(Boolean)
      .join(' ');
  }

  if (problem) {
    const title = problem.title ?? `HTTP ${status}`;
    const errors = problem.errors ? ` ${JSON.stringify(problem.errors)}` : '';
    return `${status} ${title}${detail ? `: ${detail}` : ''}${errors} (${method} ${url})`;
  }

  const snippet = body.length > 500 ? `${body.slice(0, 500)}…` : body;
  return `${status} ${method} ${url}${snippet ? `: ${snippet}` : ''}`;
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
