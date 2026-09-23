import { deepStrictEqual, ok, rejects, strictEqual } from 'node:assert';
import { afterEach, describe, it } from 'node:test';

import {
  DependablyApiError,
  DependablyClient,
  MAX_RESPONSE_BYTES,
  describeFetchError,
  extractCapability,
  formatHttpError,
} from '../dist/client.js';

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

  it('never follows a redirect automatically', async () => {
    const calls = stubFetch();
    await new DependablyClient(cfg).get('/x');
    strictEqual(calls[0].init.redirect, 'manual');
  });
});

describe('DependablyClient response handling', () => {
  it('returns null for 204 and for an empty body', async () => {
    stubFetch({ status: 204 });
    strictEqual(await new DependablyClient(cfg).get('/x'), null);
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

  it('names method, url and cause when reading the response body fails', async () => {
    globalThis.fetch = async (url) => ({
      status: 200,
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      text: async () => {
        const e = new Error('terminated');
        e.cause = Object.assign(new Error('other side closed'), { code: 'UND_ERR_SOCKET' });
        throw e;
      },
    });
    const err = await new DependablyClient(cfg).get('/thing').catch((e) => e);
    ok(err instanceof Error);
    ok(err.message.includes('GET'), err.message);
    ok(err.message.includes('https://dep.example.com/thing'), err.message);
    ok(err.message.includes('other side closed'), err.message);
  });

  it('rejects a 3xx response instead of following it, naming the Location', async () => {
    globalThis.fetch = async () =>
      new Response(null, { status: 302, headers: { location: 'https://evil.example/steal' } });
    await rejects(
      () => new DependablyClient(cfg).get('/x'),
      /was redirected to https:\/\/evil\.example\/steal; DEPENDABLY_BASE_URL must point at the instance itself/,
    );
  });

  it('rejects a redirect with no Location header without throwing on the missing header', async () => {
    globalThis.fetch = async () => new Response(null, { status: 301 });
    await rejects(() => new DependablyClient(cfg).get('/x'), /was redirected to \(no Location header\)/);
  });

  it('aborts when Content-Length exceeds the response-size cap', async () => {
    globalThis.fetch = async () =>
      new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json', 'content-length': String(9 * 1024 * 1024) },
      });
    const err = await new DependablyClient(cfg).get('/big').catch((e) => e);
    ok(err instanceof Error);
    ok(err.message.includes('exceeds the'), err.message);
    ok(err.message.includes(String(9 * 1024 * 1024)), err.message);
  });

  it('cancels the response body once the Content-Length cap trips, to release the connection', async () => {
    let cancelled = false;
    const stream = new ReadableStream({
      cancel() {
        cancelled = true;
      },
    });
    globalThis.fetch = async () =>
      new Response(stream, {
        status: 200,
        headers: { 'content-type': 'application/json', 'content-length': String(9 * 1024 * 1024) },
      });
    const err = await new DependablyClient(cfg).get('/big').catch((e) => e);
    ok(err instanceof Error);
    ok(err.message.includes('exceeds the'), err.message);
    ok(cancelled, 'the body stream should be cancelled once the Content-Length cap trips');
  });

  it('aborts when the streamed body exceeds the response-size cap even without a Content-Length', async () => {
    const bigBody = 'x'.repeat(MAX_RESPONSE_BYTES + 1);
    globalThis.fetch = async () => new Response(bigBody, { status: 200, headers: { 'content-type': 'text/plain' } });
    const err = await new DependablyClient(cfg).get('/big').catch((e) => e);
    ok(err instanceof Error);
    ok(err.message.includes('exceeds the'), err.message);
    ok(err.message.includes(`${bigBody.length} bytes`), err.message);
  });

  it('measures the streamed-body cap in bytes, not UTF-16 length, so the reported count matches the cap', async () => {
    // Each '€' is 1 UTF-16 code unit but 3 bytes: a body whose *character*
    // count sits under MAX_RESPONSE_BYTES can still be over the cap in bytes.
    // The rejection message must report the byte count the cap actually
    // enforces, or the two figures disagree with each other.
    const charCount = Math.floor(MAX_RESPONSE_BYTES / 3) + 10;
    const bigBody = '€'.repeat(charCount);
    const expectedBytes = Buffer.byteLength(bigBody);
    ok(expectedBytes > MAX_RESPONSE_BYTES, 'fixture must actually exceed the byte cap');
    ok(bigBody.length < expectedBytes, 'fixture must have fewer UTF-16 units than bytes, or it does not distinguish the two measures');
    globalThis.fetch = async () =>
      new Response(bigBody, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    const err = await new DependablyClient(cfg).get('/big').catch((e) => e);
    ok(err instanceof Error);
    ok(err.message.includes(`${expectedBytes} bytes`), err.message);
    ok(!err.message.includes(`${bigBody.length} bytes`), err.message);
  });

  it('accepts a body at or under the cap', async () => {
    globalThis.fetch = async () =>
      new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    deepStrictEqual(await new DependablyClient(cfg).get('/x'), { ok: true });
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

  it('explains a refused connection', () => {
    ok(call('ECONNREFUSED').includes('Nothing is listening'));
  });

  it('explains an unreachable host without claiming nothing is listening', () => {
    for (const code of ['EHOSTUNREACH', 'ENETUNREACH']) {
      const msg = call(code);
      ok(msg.includes('No network route'), code);
      ok(msg.includes('Local Network'), code);
      ok(!msg.includes('Nothing is listening'), code);
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

  // These are the phrasings Dependably actually emits — the capability leads, the
  // noun follows. Reading only after the noun captured the next English word and
  // reported a capability named "required", which does not exist.
  for (const [detail, cap] of [
    ['read:tenant capability required.', 'read:tenant'],
    ['read:audit capability required.', 'read:audit'],
    ['publish:cargo capability required.', 'publish:cargo'],
    ['yank:cargo capability required.', 'yank:cargo'],
    ['Authentication required. Provide a JWT or a Bearer token with read:audit capability.', 'read:audit'],
  ]) {
    it(`names ${cap} from the server's own wording: ${JSON.stringify(detail)}`, () => {
      strictEqual(extractCapability(detail), cap);
    });
  }

  it('never reports an ordinary word as a capability name', () => {
    // A capability is verb:leaf. Anything else adjacent to the noun is prose.
    for (const detail of [
      'Your token lacks the capability required for this operation.',
      'Insufficient token scope.',
      'capability missing',
      'nope',
    ]) {
      strictEqual(extractCapability(detail), null, detail);
    }
  });

  it('falls back to a generic 403 when no capability is named', () => {
    const msg = formatHttpError('GET', '/x', 403, 'application/json', problem({ detail: 'nope' }), h());
    ok(msg.includes('lacks the capability required'));
  });

  it('names the capability on a 401 without asserting which cause it is', () => {
    // Dependably sends one body for "no token" and for "valid token, missing
    // capability", so the message must not pick one.
    const msg = formatHttpError('GET', '/x', 401, 'application/json',
      problem({ detail: 'Authentication required. Provide a JWT or a Bearer token with read:audit capability.' }), h());
    ok(msg.includes('read:audit'), 'names the capability');
    ok(msg.includes('unset or expired'), 'still offers the expiry cause');
    ok(msg.includes('not minted with that capability'), 'and the capability cause');
  });

  it('keeps the plain 401 wording when no capability is named', () => {
    const msg = formatHttpError('GET', '/x', 401, 'application/json', problem({ detail: 'bad token' }), h());
    ok(msg.includes('has not expired'));
  });

  it('surfaces retry-after on 429', () => {
    ok(formatHttpError('GET', '/x', 429, 'application/json', '{}', h({ 'retry-after': '30' })).includes('Retry after 30'));
    ok(formatHttpError('GET', '/x', 429, 'application/json', '{}', h()).includes('Retry after a short delay'));
  });

  it('tells the reader a 5xx is not a client configuration problem', () => {
    // The instance answered, so the URL demonstrably resolves; sending someone to
    // re-check DEPENDABLY_BASE_URL is a wrong lead. /lookup returns 503 when an
    // upstream registry is down, which is beyond the instance entirely.
    const msg = formatHttpError('GET', '/x', 503, 'application/json', problem({ detail: 'down' }), h());
    ok(msg.includes('503 Dependably server error.'));
    ok(msg.includes('The instance answered'));
    ok(msg.includes('upstream'));
  });

  it('does not double the period when a detail already ends in one', () => {
    const msg = formatHttpError('GET', '/x', 503, 'application/json', problem({ detail: 'Upstream registry unavailable.' }), h());
    ok(!msg.includes('unavailable..'), msg);
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
