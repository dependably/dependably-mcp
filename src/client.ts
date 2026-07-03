import type { Config } from './config.js';

type Query = Record<string, string | number | boolean | undefined | null>;

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
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`${method} ${url} failed: ${msg}`);
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
        if (v === undefined || v === null || v === '') continue;
        url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }
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
