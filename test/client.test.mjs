import { deepStrictEqual, ok, rejects, strictEqual } from 'node:assert';
import { afterEach, describe, it } from 'node:test';

import { DependablyApiError, DependablyClient, describeFetchError, formatHttpError } from '../dist/client.js';

const cfg = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000 };
const realFetch = globalThis.fetch;

/** Replace global fetch with a recorder returning a canned response. */
function stubFetch({ status = 200, body = '{}', ctype = 'application/json', headers = {} } = {}) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(status === 204 ? null : body, {
      status,
      headers: { 'content-type': ctype, ...headers },
    });
  };
  return calls;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('DependablyClient request building', () => {
  it('sends the bearer token and accepts json', async () => {
    const calls = stubFetch({ body: '{"ok":true}' });
    const client = new DependablyClient(cfg);
    deepStrictEqual(await client.get('/api/v1/thing'), { ok: true });
    strictEqual(calls[0].url, 'https://dep.example.com/api/v1/thing');
    strictEqual(calls[0].init.headers.Authorization, 'Bearer tok');
    ok(calls[0].init.headers.Accept.includes('application/json'));
    strictEqual(calls[0].init.method, 'GET');
  });

  it('prefixes a path that lacks a leading slash', async () => {
    const calls = stubFetch();
    await new DependablyClient(cfg).get('health');
    strictEqual(calls[0].url, 'https://dep.example.com/health');
  });

  it('appends query params, skipping undefined, null and empty values', async () => {
    const calls = stubFetch();
    await new DependablyClient(cfg).get('/x', { a: 1, b: undefined, c: null, d: '', e: false, f: 'y' });
    const url = new URL(calls[0].url);
    deepStrictEqual([...url.searchParams.entries()], [
      ['a', '1'],
      ['e', 'false'],
      ['f', 'y'],
    ]);
  });

  it('repeats an array value as multiple params', async () => {
    const calls = stubFetch();
    await new DependablyClient(cfg).get('/x', { action: ['login.failure', 'token.revoked'] });
    deepStrictEqual(new URL(calls[0].url).searchParams.getAll('action'), ['login.failure', 'token.revoked']);
  });

  it('sends a json body and content-type for write verbs', async () => {
    const calls = stubFetch();
    const client = new DependablyClient(cfg);
    await client.post('/x', { a: 1 });
    strictEqual(calls[0].init.method, 'POST');
    strictEqual(calls[0].init.headers['Content-Type'], 'application/json');
    strictEqual(calls[0].init.body, '{"a":1}');

    await client.put('/x', { b: 2 });
    strictEqual(calls[1].init.method, 'PUT');
    await client.patch('/x', { c: 3 });
    strictEqual(calls[2].init.method, 'PATCH');
    await client.del('/x');
    strictEqual(calls[3].init.method, 'DELETE');
    strictEqual(calls[3].init.body, undefined);
  });
});

describe('DependablyClient response handling', () => {
  it('returns null for 204 and for an empty body', async () => {
    stubFetch({ status: 204 });
    strictEqual(await new DependablyClient(cfg).del('/x'), null);
    stubFetch({ body: '' });
    strictEqual(await new DependablyClient(cfg).get('/x'), null);
  });

  it('returns text unchanged for a non-json content type', async () => {
    stubFetch({ body: '# HELP foo\n', ctype: 'text/plain' });
    strictEqual(await new DependablyClient(cfg).get('/metrics'), '# HELP foo\n');
  });

  it('returns the raw text when a json content type carries invalid json', async () => {
    stubFetch({ body: 'not json', ctype: 'application/json' });
    strictEqual(await new DependablyClient(cfg).get('/x'), 'not json');
  });

  it('throws DependablyApiError carrying status, method and url', async () => {
    stubFetch({ status: 404, body: '{"title":"Not Found"}' });
    const err = await new DependablyClient(cfg).get('/missing').catch((e) => e);
    ok(err instanceof DependablyApiError);
    strictEqual(err.status, 404);
    strictEqual(err.method, 'GET');
    ok(err.url.endsWith('/missing'));
    strictEqual(err.name, 'DependablyApiError');
  });

  it('wraps a transport failure with actionable guidance', async () => {
    globalThis.fetch = async () => {
      const e = new Error('fetch failed');
      e.cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
      throw e;
    };
    await rejects(() => new DependablyClient(cfg).get('/x'), /Nothing is listening/);
  });
});

describe('describeFetchError', () => {
  const call = (code, message = 'boom') => {
    const e = new Error('fetch failed');
    e.cause = Object.assign(new Error(message), { code });
    return describeFetchError('GET', 'https://host.example/x', e, 1000);
  };

  it('names the timeout setting on a timeout', () => {
    const e = new Error('timed out');
    e.name = 'TimeoutError';
    const msg = describeFetchError('GET', 'https://host.example/x', e, 1234);
    ok(msg.includes('1234ms'));
    ok(msg.includes('DEPENDABLY_TIMEOUT_MS'));
  });

  it('explains DNS failures', () => {
    for (const code of ['ENOTFOUND', 'EAI_AGAIN']) {
      const msg = call(code);
      ok(msg.includes('Could not resolve'), code);
      ok(msg.includes('host.example'), code);
      ok(msg.includes('DEPENDABLY_BASE_URL'), code);
    }
  });

  it('explains refused and unreachable connections', () => {
    for (const code of ['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH']) {
      ok(call(code).includes('Nothing is listening'), code);
    }
  });

  it('explains TLS failures without ever suggesting verification be disabled', () => {
    for (const code of [
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'DEPTH_ZERO_SELF_SIGNED_CERT',
      'SELF_SIGNED_CERT_IN_CHAIN',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
      'CERT_HAS_EXPIRED',
      'ERR_SSL_WRONG_VERSION_NUMBER',
    ]) {
      const msg = call(code);
      ok(msg.includes('NODE_EXTRA_CA_CERTS'), code);
      ok(msg.includes('never disable certificate verification'), code);
    }
  });

  it('explains a dropped connection', () => {
    for (const code of ['ECONNRESET', 'EPIPE']) {
      ok(call(code).includes('was dropped'), code);
    }
  });

  it('falls back to a generic hint for an unknown cause', () => {
    ok(call('ESOMETHINGELSE').includes('DEPENDABLY_BASE_URL'));
  });

  it('survives a non-Error input and an unparseable url', () => {
    const msg = describeFetchError('GET', 'not a url', 'a string failure', 1000);
    ok(msg.includes('not a url'));
  });
});

describe('formatHttpError', () => {
  const h = (init = {}) => new Headers(init);
  const problem = (o) => JSON.stringify(o);

  it('names the token settings on 401', () => {
    const msg = formatHttpError('GET', '/x', 401, 'application/json', problem({ detail: 'expired' }), h());
    ok(msg.includes('401 Authentication failed.'));
    ok(msg.includes('DEPENDABLY_TOKEN'));
    ok(msg.includes('expired'));
  });

  it('names the missing capability on 403 when the detail carries one', () => {
    const msg = formatHttpError('GET', '/x', 403, 'application/json', problem({ detail: 'requires capability "read:packages"' }), h());
    ok(msg.includes('read:packages'));
  });

  it('falls back to a generic 403 when no capability is named', () => {
    const msg = formatHttpError('GET', '/x', 403, 'application/json', problem({ detail: 'nope' }), h());
    ok(msg.includes('lacks the capability required'));
  });

  it('surfaces retry-after on 429', () => {
    ok(formatHttpError('GET', '/x', 429, 'application/json', '{}', h({ 'retry-after': '30' })).includes('Retry after 30'));
    ok(formatHttpError('GET', '/x', 429, 'application/json', '{}', h()).includes('Retry after a short delay'));
  });

  it('reports server errors with the base url hint', () => {
    const msg = formatHttpError('GET', '/x', 503, 'application/json', problem({ detail: 'down' }), h());
    ok(msg.includes('503 Dependably server error.'));
    ok(msg.includes('DEPENDABLY_BASE_URL'));
  });

  it('renders a problem+json title, detail and errors for other statuses', () => {
    const msg = formatHttpError('POST', '/x', 422, 'application/problem+json', problem({ title: 'Unprocessable', detail: 'bad', errors: { f: ['x'] } }), h());
    ok(msg.includes('422 Unprocessable'));
    ok(msg.includes('bad'));
    ok(msg.includes('"f"'));
  });

  it('falls back to HTTP <status> when a problem body has no title', () => {
    ok(formatHttpError('GET', '/x', 418, 'application/json', problem({ detail: 'teapot' }), h()).includes('HTTP 418'));
  });

  it('truncates a long non-json body', () => {
    const msg = formatHttpError('GET', '/x', 400, 'text/html', 'y'.repeat(600), h());
    ok(msg.includes('…'));
    ok(msg.length < 600);
  });

  it('handles a non-json body and an unparseable json body', () => {
    ok(formatHttpError('GET', '/x', 400, 'text/html', 'plain', h()).includes('plain'));
    ok(formatHttpError('GET', '/x', 400, 'application/json', '{bad', h()).includes('{bad'));
    ok(formatHttpError('GET', '/x', 400, 'text/html', '', h()).includes('400 GET /x'));
  });
});
