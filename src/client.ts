import type { Config } from './config.js';

type Query = Record<string, string | number | boolean | undefined | null>;

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
      throw new Error(formatHttpError(method, url, res.status, ctype, text));
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

function formatHttpError(method: string, url: string, status: number, ctype: string, body: string): string {
  if (ctype.includes('application/problem+json') || ctype.includes('application/json')) {
    try {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const title = typeof parsed.title === 'string' ? parsed.title : `HTTP ${status}`;
      const detail = typeof parsed.detail === 'string' ? parsed.detail : '';
      const errors = parsed.errors ? ` ${JSON.stringify(parsed.errors)}` : '';
      return `${status} ${title}${detail ? `: ${detail}` : ''}${errors} (${method} ${url})`;
    } catch {
      // fall through
    }
  }
  const snippet = body.length > 500 ? `${body.slice(0, 500)}…` : body;
  return `${status} ${method} ${url}${snippet ? `: ${snippet}` : ''}`;
}
