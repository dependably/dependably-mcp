import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, it } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';
import { json, err, withSummary, run } from '../dist/format.js';

const base = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000, toolset: 'full' };
const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Record every outbound request and reply with a canned body. */
function stubFetch(reply = () => ({ ok: true })) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET', body: init?.body });
    const out = reply(String(url), init);
    const isText = typeof out === 'string';
    return new Response(isText ? out : JSON.stringify(out), {
      status: 200,
      headers: { 'content-type': isText ? 'text/plain' : 'application/json' },
    });
  };
  return calls;
}

async function withServer(cfg, fn) {
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'unit', version: '0.0.0' });
  await Promise.all([server.connect(st), client.connect(ct)]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

const call = (cfg, name, args = {}) => withServer(cfg, (c) => c.callTool({ name, arguments: args }));
const payload = (res) => JSON.parse(res.content[0].text);

describe('format helpers', () => {
  it('json stringifies objects and passes strings through', () => {
    strictEqual(json({ a: 1 }).content[0].text, '{\n  "a": 1\n}');
    strictEqual(json('raw').content[0].text, 'raw');
  });

  it('withSummary prefixes the body', () => {
    ok(withSummary('done.', { a: 1 }).content[0].text.startsWith('done.\n\n'));
    ok(withSummary('done.', 'text').content[0].text.startsWith('done.\n\n'));
  });

  it('err marks the result as an error', () => {
    const e = err('boom');
    strictEqual(e.isError, true);
    strictEqual(e.content[0].text, 'boom');
  });

  it('run converts a throw into an error result, including a non-Error throw', async () => {
    const thrown = await run(async () => {
      throw new Error('nope');
    });
    strictEqual(thrown.isError, true);
    ok(thrown.content[0].text.includes('nope'));

    const raw = await run(async () => {
      throw 'a string';
    });
    strictEqual(raw.isError, true);
    ok(raw.content[0].text.includes('a string'));
  });
});

describe('read tools', () => {
  it('list_packages forwards every filter', async () => {
    const calls = stubFetch();
    await call(base, 'list_packages', {
      ecosystem: 'npm',
      search: 'left',
      limit: 10,
      page: 2,
      sortBy: 'name',
      sortDir: 'desc',
    });
    const u = new URL(calls[0].url);
    strictEqual(u.pathname, '/api/v1/packages');
    strictEqual(u.searchParams.get('ecosystem'), 'npm');
    strictEqual(u.searchParams.get('search'), 'left');
    strictEqual(u.searchParams.get('sortDir'), 'desc');
  });

  it('get_package url-encodes a scoped name', async () => {
    const calls = stubFetch();
    await call(base, 'get_package', { ecosystem: 'npm', name: '@scope/pkg' });
    ok(calls[0].url.includes('/api/v1/packages/npm/%40scope%2Fpkg'));
  });

  it('search_packages passes q and limit', async () => {
    const calls = stubFetch();
    await call(base, 'search_packages', { q: 'ab', limit: 5 });
    const u = new URL(calls[0].url);
    strictEqual(u.pathname, '/api/v1/search');
    strictEqual(u.searchParams.get('q'), 'ab');
  });

  it('get_vulnerability passes the installed version through', async () => {
    const calls = stubFetch();
    await call(base, 'get_vulnerability', { osvId: 'GHSA-a/b', version: '1.2.3' });
    ok(calls[0].url.includes('GHSA-a%2Fb'));
    strictEqual(new URL(calls[0].url).searchParams.get('version'), '1.2.3');
  });

  it('list_activity, whoami, get_license_policy and lookup_package hit their endpoints', async () => {
    const calls = stubFetch();
    await call(base, 'list_activity', { since: '7d', event_type: 'publish' });
    await call(base, 'whoami');
    await call(base, 'get_license_policy');
    await call(base, 'lookup_package', { ecosystem: 'npm', name: 'x', version: '1.0.0' });
    const paths = calls.map((c) => new URL(c.url).pathname);
    deepStrictEqual(paths, ['/api/v1/activity', '/api/v1/auth/me', '/api/v1/license-policy', '/api/v1/lookup']);
  });

  it('surfaces an API error as an error result rather than throwing', async () => {
    globalThis.fetch = async () =>
      new Response('{"detail":"nope"}', { status: 403, headers: { 'content-type': 'application/json' } });
    const res = await call(base, 'whoami');
    strictEqual(res.isError, true);
    ok(res.content[0].text.includes('403'));
  });
});

describe('list_vulnerabilities verbosity', () => {
  const item = {
    packageName: 'hono',
    version: '4.12.27',
    osvId: 'GHSA-x',
    severity: 'MODERATE',
    cvssScore: 5.3,
    epssScore: 0.004,
    isKev: false,
    summary: 's',
    purl: 'pkg:npm/hono@4.12.27',
    orgSlug: 'default',
    firstSeenAt: 'x',
  };

  it('compacts items by default', async () => {
    stubFetch(() => ({ items: [item], total: 1 }));
    const body = payload(await call(base, 'list_vulnerabilities', {}));
    strictEqual(body.total, 1);
    ok(!('purl' in body.items[0]));
    ok(!('orgSlug' in body.items[0]));
    strictEqual(body.items[0].name, 'hono');
    strictEqual(body.items[0].severity, 'MEDIUM');
  });

  it('returns the raw server fields when asked for full', async () => {
    stubFetch(() => ({ items: [item], total: 1 }));
    const body = payload(await call(base, 'list_vulnerabilities', { verbosity: 'full' }));
    strictEqual(body.items[0].purl, 'pkg:npm/hono@4.12.27');
    strictEqual(body.items[0].severity, 'MODERATE');
  });

  it('passes a response with no items through untouched', async () => {
    stubFetch(() => ({ total: 0 }));
    deepStrictEqual(payload(await call(base, 'list_vulnerabilities', {})), { total: 0 });
  });
});

describe('check_dependencies', () => {
  const report = {
    items: [
      { packageName: 'hono', version: '4.12.27', osvId: 'A', severity: 'HIGH', cvssScore: 7.5 },
      { packageName: 'hono', version: '4.12.27', osvId: 'B', severity: 'LOW', cvssScore: 2 },
      { packageName: 'other', version: '9.9.9', osvId: 'C', severity: 'HIGH' },
    ],
    total: 3,
  };

  function stubReportAndAdvisories(fixedBy = { A: '4.13.5', B: '4.12.34' }) {
    return stubFetch((url) => {
      const u = new URL(url);
      if (u.pathname === '/api/v1/vuln-report') return u.searchParams.get('page') === '1' ? report : { items: [], total: 3 };
      const id = u.pathname.split('/').pop();
      return { remediation: { fixedVersion: fixedBy[id], cweIds: ['CWE-1'], entries: [{ owaspId: 'A01:2025', skillId: 'fix-x' }] } };
    });
  }

  it('returns only the advisories affecting the given packages, with a bump ceiling', async () => {
    stubReportAndAdvisories();
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'npm',
        packages: [{ name: 'hono', version: '4.12.27' }],
      }),
    );
    strictEqual(body.clean, false);
    strictEqual(body.summary.packagesAffected, 1);
    strictEqual(body.summary.advisories, 2);
    strictEqual(body.summary.packagesChecked, 1);
    strictEqual(body.findings[0].bumpTo, '4.13.5');
    strictEqual(body.reportSize, 3);
  });

  it('reports a clean tree when nothing matches', async () => {
    stubReportAndAdvisories();
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'npm',
        packages: [{ name: 'hono', version: '4.13.7' }],
      }),
    );
    strictEqual(body.clean, true);
    deepStrictEqual(body.findings, []);
    strictEqual(body.summary.advisories, 0);
  });

  it('omits cwe/owasp/skill detail unless asked', async () => {
    stubReportAndAdvisories();
    const withoutDetail = payload(
      await call(base, 'check_dependencies', { packages: [{ name: 'hono', version: '4.12.27' }] }),
    );
    ok(!('cwes' in withoutDetail.findings[0].advisories[0]));

    stubReportAndAdvisories();
    const withDetail = payload(
      await call(base, 'check_dependencies', {
        packages: [{ name: 'hono', version: '4.12.27' }],
        includeAdvisoryDetail: true,
      }),
    );
    deepStrictEqual(withDetail.findings[0].advisories[0].cwes, ['CWE-1']);
    deepStrictEqual(withDetail.findings[0].advisories[0].skills, ['fix-x']);
  });

  it('carries the dev marker into the runtime/dev split', async () => {
    stubReportAndAdvisories();
    const body = payload(
      await call(base, 'check_dependencies', {
        packages: [{ name: 'hono', version: '4.12.27', dev: true }],
      }),
    );
    strictEqual(body.summary.devOnly, 2);
    strictEqual(body.summary.runtime, 0);
    strictEqual(body.findings[0].dev, true);
  });

  it('defaults the ecosystem to npm', async () => {
    const calls = stubReportAndAdvisories();
    const body = payload(await call(base, 'check_dependencies', { packages: [{ name: 'x', version: '1' }] }));
    strictEqual(body.ecosystem, 'npm');
    strictEqual(new URL(calls[0].url).searchParams.get('ecosystem'), 'npm');
  });

  it('exposes no argument that could name a local file', async () => {
    const tools = await withServer(base, (c) => c.listTools());
    const schema = tools.tools.find((t) => t.name === 'check_dependencies').inputSchema;
    const props = Object.keys(schema.properties ?? {});
    for (const forbidden of ['lockfile', 'path', 'file', 'dir']) {
      ok(!props.includes(forbidden), `must not accept ${forbidden}`);
    }
    ok((schema.required ?? []).includes('packages'));
  });
});

describe('get_remediation', () => {
  it('resolves several advisories and keeps the installed version', async () => {
    stubFetch((url) => {
      const id = new URL(url).pathname.split('/').pop();
      return {
        summary: `${id} summary`,
        databaseSpecific: { severity: 'HIGH' },
        remediation: { fixedVersion: `${id}-fix`, cweIds: ['CWE-1'], entries: [{ skillId: 'fix-x' }] },
      };
    });
    const body = payload(
      await call(base, 'get_remediation', {
        advisories: [
          { osvId: 'A', version: '1.0.0' },
          { osvId: 'B' },
        ],
      }),
    );
    strictEqual(body.advisories.length, 2);
    strictEqual(body.advisories[0].fixedVersion, 'A-fix');
    strictEqual(body.advisories[0].installed, '1.0.0');
    strictEqual(body.advisories[0].severity, 'HIGH');
    deepStrictEqual(body.advisories[0].skills, ['fix-x']);
    ok(!('installed' in body.advisories[1]), 'no version passed means none echoed');
  });

  it('reports a per-advisory failure without sinking the batch', async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes('BAD')) {
        return new Response('{"detail":"gone"}', { status: 404, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ remediation: { fixedVersion: '1.0.0' } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const body = payload(
      await call(base, 'get_remediation', { advisories: [{ osvId: 'BAD' }, { osvId: 'GOOD' }] }),
    );
    ok(body.advisories[0].error.includes('404'));
    strictEqual(body.advisories[1].fixedVersion, '1.0.0');
  });
});

describe('yank, siem and observability tools', () => {
  it('yank_version deletes the encoded version path and summarizes', async () => {
    const calls = stubFetch();
    const res = await call(base, 'yank_version', { ecosystem: 'npm', name: '@scope/p', version: '1.0.0' });
    strictEqual(calls[0].method, 'DELETE');
    ok(calls[0].url.includes('/api/v1/packages/npm/%40scope%2Fp/1.0.0'));
    ok(res.content[0].text.startsWith('Yanked npm/@scope/p@1.0.0.'));
  });

  it('siem tools hit their endpoints and repeat array filters', async () => {
    const calls = stubFetch();
    await call(base, 'siem_list_auth_events', {
      since: '2026-01-01T00:00:00Z',
      action: ['login.failure', 'token.revoked'],
      limit: 10,
    });
    await call(base, 'siem_vulnerabilities_summary', {});
    const u = new URL(calls[0].url);
    ok(u.pathname.includes('/siem/events/auth'));
    deepStrictEqual(u.searchParams.getAll('action'), ['login.failure', 'token.revoked']);
    ok(new URL(calls[1].url).pathname.includes('/siem/'));
  });

  it('health and readiness probes hit the unauthenticated paths', async () => {
    const calls = stubFetch();
    await call(base, 'health_check');
    await call(base, 'readiness_check');
    deepStrictEqual(calls.map((c) => new URL(c.url).pathname), ['/health', '/ready']);
  });

  it('loopback probes are present in full and absent in remote', async () => {
    const calls = stubFetch(() => '# HELP x');
    await call(base, 'get_version');
    const metrics = await call(base, 'get_prometheus_metrics');
    deepStrictEqual(calls.map((c) => new URL(c.url).pathname), ['/version', '/metrics']);
    strictEqual(metrics.content[0].text, '# HELP x');

    const remote = await withServer({ ...base, toolset: 'remote' }, (c) => c.listTools());
    const names = remote.tools.map((t) => t.name);
    ok(!names.includes('get_version'));
    ok(!names.includes('get_prometheus_metrics'));
  });
});

describe('setup tools', () => {
  it('build commands locally without calling the server', async () => {
    const calls = stubFetch();
    const install = await call(base, 'get_install_command', { ecosystem: 'npm', package: 'left-pad', version: '1.0.0' });
    const publish = await call(base, 'get_publish_command', { ecosystem: 'npm', artifact_path: './package.tgz' });
    strictEqual(calls.length, 0, 'setup tools must not touch the network');
    ok(!install.isError, install.content[0].text);
    ok(!publish.isError, publish.content[0].text);
    ok(install.content[0].text.includes('dep.example.com'), 'the command should target the configured instance');
  });

  it('covers every ecosystem, both with and without a pinned version', async () => {
    stubFetch();
    for (const eco of ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo']) {
      for (const version of ['1.0.0', undefined]) {
        const install = await call(base, 'get_install_command', { ecosystem: eco, package: 'pkg', version });
        ok(!install.isError, `${eco} install: ${install.content[0].text}`);
      }
      const publish = await call(base, 'get_publish_command', { ecosystem: eco, artifact_path: './artifact' });
      ok(!publish.isError, `${eco} publish: ${publish.content[0].text}`);
    }
  });

  it('tells golang publishers to push a VCS tag, since there is no hosted endpoint', async () => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem: 'golang', artifact_path: './artifact' });
    ok(!res.isError);
    ok(/tag/i.test(res.content[0].text), res.content[0].text);
  });
});

describe('import tools', () => {
  it('are absent unless an import root is configured', async () => {
    const names = (await withServer(base, (c) => c.listTools())).tools.map((t) => t.name);
    ok(!names.includes('admin_upload'));
    ok(!names.includes('import_manifest'));
  });

  it('appear once an import root is set', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-imp-'));
    const names = (await withServer({ ...base, importRoot: dir }, (c) => c.listTools())).tools.map((t) => t.name);
    ok(names.includes('admin_upload'));
    ok(names.includes('import_manifest'));
  });

  it('refuse a path outside the root, naming the setting', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-imp-'));
    const res = await call({ ...base, importRoot: dir }, 'admin_upload', { files: ['/etc/hosts'] });
    strictEqual(res.isError, true);
    ok(res.content[0].text.includes('DEPENDABLY_IMPORT_ROOT'));
  });

  it('report a missing file as not found', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-imp-'));
    const res = await call({ ...base, importRoot: dir }, 'admin_upload', { files: [join(dir, 'nope.tgz')] });
    strictEqual(res.isError, true);
    ok(res.content[0].text.includes('File not found'));
  });

  it('upload a file that lives inside the root', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-imp-'));
    const file = join(dir, 'pkg.tgz');
    writeFileSync(file, 'artefact-bytes');
    const calls = stubFetch(() => ({ accepted: 1 }));
    const res = await call({ ...base, importRoot: dir }, 'admin_upload', { files: [file], dryRun: true });
    ok(!res.isError, res.content[0].text);
    strictEqual(calls[0].method, 'POST');
    ok(calls[0].url.includes('/api/v1/admin/upload'));
  });
});
