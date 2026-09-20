import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { afterEach, describe, it } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';
import {
  FALLBACK_LOOKUP_ECOSYSTEMS,
  FALLBACK_PLANES,
  FALLBACK_REGISTRY_ECOSYSTEMS,
  FALLBACK_SETUP_ECOSYSTEMS,
  fetchEcosystems,
  parsePlanes,
} from '../dist/ecosystems.js';

const cfg = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000 };
const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

function stubFetch({ status = 200, body = '{}', ctype = 'application/json' } = {}) {
  globalThis.fetch = async () => new Response(body, { status, headers: { 'content-type': ctype } });
}

// The GET /api/v1/ecosystems response body, exactly as spelled in
// CONTRACT-ecosystems.md.
const CONTRACT_BODY = {
  items: [
    { id: 'npm', registry: true, lookup: true, setup: true },
    { id: 'pypi', registry: true, lookup: true, setup: true },
    { id: 'nuget', registry: true, lookup: true, setup: true },
    { id: 'maven', registry: true, lookup: true, setup: true },
    { id: 'rpm', registry: true, lookup: false, setup: true },
    { id: 'cargo', registry: true, lookup: true, setup: true },
    { id: 'golang', registry: true, lookup: true, setup: true },
    { id: 'oci', registry: true, lookup: false, setup: true },
    { id: 'apk', registry: true, lookup: false, setup: true },
    { id: 'terraform', registry: true, lookup: false, setup: true },
    { id: 'hex', registry: true, lookup: true, setup: true },
  ],
  planes: {
    registry: ['pypi', 'npm', 'nuget', 'maven', 'rpm', 'cargo', 'golang', 'oci', 'apk', 'terraform', 'hex'],
    lookup: ['npm', 'pypi', 'nuget', 'maven', 'golang', 'cargo', 'hex'],
    setup: ['npm', 'pypi', 'nuget', 'maven', 'cargo', 'oci', 'golang', 'rpm', 'apk', 'terraform', 'hex'],
  },
};

describe('parsePlanes', () => {
  it('accepts the contract example', () => {
    deepStrictEqual(parsePlanes(CONTRACT_BODY), CONTRACT_BODY.planes);
  });

  it('rejects a body with no planes key', () => {
    strictEqual(parsePlanes({}), null);
    strictEqual(parsePlanes(null), null);
    strictEqual(parsePlanes(undefined), null);
    strictEqual(parsePlanes('just a string'), null);
    strictEqual(parsePlanes([1, 2, 3]), null);
  });

  it('rejects an empty registry array', () => {
    strictEqual(parsePlanes({ planes: { registry: [], lookup: [], setup: [] } }), null);
  });

  it('rejects an empty lookup or setup array', () => {
    strictEqual(parsePlanes({ planes: { registry: ['npm'], lookup: [], setup: ['npm'] } }), null);
    strictEqual(parsePlanes({ planes: { registry: ['npm'], lookup: ['npm'], setup: [] } }), null);
  });

  it('rejects a lookup id not present in registry', () => {
    strictEqual(parsePlanes({ planes: { registry: ['npm'], lookup: ['npm', 'pypi'], setup: ['npm'] } }), null);
  });

  it('rejects a setup id not present in registry', () => {
    strictEqual(parsePlanes({ planes: { registry: ['npm'], lookup: ['npm'], setup: ['npm', 'pypi'] } }), null);
  });

  it('rejects non-string ids', () => {
    strictEqual(parsePlanes({ planes: { registry: ['npm', 1], lookup: ['npm'], setup: ['npm'] } }), null);
    strictEqual(parsePlanes({ planes: { registry: ['npm', ''], lookup: ['npm'], setup: ['npm'] } }), null);
  });
});

describe('fetchEcosystems', () => {
  it('reads the live vocabulary from a 200 contract response', async () => {
    stubFetch({ body: JSON.stringify(CONTRACT_BODY) });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    deepStrictEqual(result, { planes: CONTRACT_BODY.planes, source: 'instance' });
  });

  it('falls back with a reason naming 404 when the endpoint does not exist on this instance', async () => {
    stubFetch({ status: 404, body: '{"title":"Not Found"}' });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    deepStrictEqual(result.planes, FALLBACK_PLANES);
    strictEqual(result.reason, 'returned 404');
  });

  it('falls back, never throwing, on a network error', async () => {
    globalThis.fetch = async () => {
      const e = new Error('fetch failed');
      e.cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
      throw e;
    };
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    deepStrictEqual(result.planes, FALLBACK_PLANES);
    ok(result.reason.includes('ECONNREFUSED'), result.reason);
  });

  it('falls back with an unexpected-shape reason on an HTML body', async () => {
    stubFetch({ body: '<html>not json</html>', ctype: 'text/html' });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    deepStrictEqual(result.planes, FALLBACK_PLANES);
    ok(result.reason.includes('unexpected shape'), result.reason);
  });

  it('falls back with an unexpected-shape reason when planes is missing from an otherwise-200 body', async () => {
    stubFetch({ body: JSON.stringify({ items: [] }) });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    ok(result.reason.includes('unexpected shape'), result.reason);
  });

  // The reason must never be built from response bytes: an HTTP status other
  // than 200 is "returned <status>" and nothing else, regardless of what body
  // or content-type came with it. Otherwise an HTML error page (or a MITM'd
  // instance) can turn one intended stderr line into several, or leak the
  // body onto stderr.
  it('falls back with exactly "returned 400" on a 400 with a multi-line HTML body, never the body itself', async () => {
    stubFetch({
      status: 400,
      body: '<html>\n<head><title>400 Bad Request</title></head>\n<body>\nbad request\n</body>\n</html>\n',
      ctype: 'text/html',
    });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    strictEqual(result.reason, 'returned 400');
    ok(!result.reason.includes('\n'), result.reason);
  });

  it('falls back with "returned 401" rather than "unreachable" when the instance demands auth', async () => {
    stubFetch({ status: 401, body: '{"title":"Unauthorized"}' });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    strictEqual(result.reason, 'returned 401');
    ok(!result.reason.includes('unreachable'), result.reason);
  });

  it('falls back with "returned 500" on a server error', async () => {
    stubFetch({ status: 500, body: '{"title":"Internal Server Error"}' });
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    strictEqual(result.reason, 'returned 500');
  });

  it('falls back on a timeout without echoing the DEPENDABLY_TIMEOUT_MS advice, which is wrong for this capped call', async () => {
    // A server that never responds: the stub rejects only when the request's
    // own AbortSignal fires, the same way real `fetch` behaves against a
    // signal whose timeout elapses. A real socket would keep the event loop
    // alive while it waits; `AbortSignal.timeout`'s own timer is unref'd, so
    // without the referenced timer below Node 22 drains the loop before the
    // signal fires and the runner abandons the pending promise.
    globalThis.fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        const keepAlive = setTimeout(() => reject(new Error('stub outlived the cap')), 10_000);
        init.signal.addEventListener('abort', () => {
          clearTimeout(keepAlive);
          reject(init.signal.reason);
        }, { once: true });
      });
    const result = await fetchEcosystems(new DependablyClient({ ...cfg, timeoutMs: 200 }));
    strictEqual(result.source, 'fallback');
    ok(result.reason.startsWith('was unreachable: timed out'), result.reason);
    ok(!result.reason.includes('DEPENDABLY_TIMEOUT_MS'), result.reason);
  });

  it('clamps an overlong reason to 160 characters', async () => {
    globalThis.fetch = async () => {
      throw new Error('x'.repeat(400));
    };
    const result = await fetchEcosystems(new DependablyClient(cfg));
    strictEqual(result.source, 'fallback');
    ok(result.reason.length <= 160, `expected <= 160 chars, got ${result.reason.length}`);
  });
});

describe('buildServer with a custom plane set', () => {
  it('reaches the live tool enums: registry offers an added ecosystem, lookup honours a dropped one, setup withholds an unbuildable one', async () => {
    const customPlanes = {
      registry: [...FALLBACK_REGISTRY_ECOSYSTEMS, 'zig'],
      lookup: FALLBACK_LOOKUP_ECOSYSTEMS.filter((e) => e !== 'hex'),
      setup: [...FALLBACK_SETUP_ECOSYSTEMS, 'zig'],
    };
    const server = buildServer(new DependablyClient(cfg), cfg, customPlanes);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'ecosystems-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { tools } = await client.listTools();
      const schemaOf = (name) => tools.find((t) => t.name === name)?.inputSchema;

      ok(
        schemaOf('list_packages')?.properties?.ecosystem?.enum?.includes('zig'),
        'registry tools should offer an ecosystem the custom plane added',
      );
      ok(
        !schemaOf('lookup_package')?.properties?.ecosystem?.enum?.includes('hex'),
        'lookup_package should not offer an ecosystem the custom plane dropped',
      );
      ok(
        !schemaOf('get_install_command')?.properties?.ecosystem?.enum?.includes('zig'),
        'setup tools should never offer an ecosystem no command builder knows, even if the instance lists it',
      );
      ok(
        !schemaOf('get_publish_command')?.properties?.ecosystem?.enum?.includes('zig'),
        'setup tools should never offer an ecosystem no command builder knows, even if the instance lists it',
      );
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('defaults to FALLBACK_PLANES when no planes argument is given', async () => {
    const server = buildServer(new DependablyClient(cfg), cfg);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'ecosystems-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { tools } = await client.listTools();
      const listPackages = tools.find((t) => t.name === 'list_packages');
      deepStrictEqual(listPackages.inputSchema.properties.ecosystem.enum, [...FALLBACK_REGISTRY_ECOSYSTEMS]);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
