import { deepStrictEqual, match, ok, strictEqual } from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, it } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';
import { json, err, withSummary, run, RESULT_CHAR_BUDGET } from '../dist/format.js';
import { compactAnalysis } from '../dist/tools/projects.js';
import { liveCheckNpm } from '../dist/vuln.js';

const base = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000 };
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
  it('json stringifies objects compactly (no pretty-print indent) and passes strings through', () => {
    strictEqual(json({ a: 1 }).content[0].text, '{"a":1}');
    strictEqual(json('raw').content[0].text, 'raw');
  });

  it('withSummary prefixes the body', () => {
    ok(withSummary('done.', { a: 1 }).content[0].text.startsWith('done.\n\n'));
    ok(withSummary('done.', 'text').content[0].text.startsWith('done.\n\n'));
    strictEqual(withSummary('done.', { a: 1 }).content[0].text, 'done.\n\n{"a":1}');
  });

  it('err marks the result as an error', () => {
    const e = err('boom');
    strictEqual(e.isError, true);
    strictEqual(e.content[0].text, 'boom');
  });

  it('err applies the same character budget as json/withSummary', () => {
    // A 500 with a huge application/problem+json `detail` (proven: 3 MB) must not
    // bypass the budget just because it is reported through err() rather than
    // json(). isError must stay true and the trailer must still be machine-readable.
    const huge = 'x'.repeat(RESULT_CHAR_BUDGET + 50_000);
    const e = err(huge);
    strictEqual(e.isError, true);
    ok(e.content[0].text.length < huge.length, 'the error message must be truncated');
    ok(e.content[0].text.includes(`[truncated: result exceeded ${RESULT_CHAR_BUDGET} characters`), e.content[0].text.slice(-200));
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

  it('leaves a small result untouched', () => {
    const small = { hello: 'world' };
    const text = json(small).content[0].text;
    strictEqual(text, JSON.stringify(small));
    ok(!text.includes('[truncated'));
  });

  it('truncates a result exceeding the shared character budget and appends a machine-readable trailer', () => {
    const big = { items: Array.from({ length: RESULT_CHAR_BUDGET }, (_, i) => i) };
    const text = json(big).content[0].text;
    ok(text.length > RESULT_CHAR_BUDGET, 'truncated text still carries the trailer past the budget');
    ok(text.includes(`[truncated: result exceeded ${RESULT_CHAR_BUDGET} characters`), text.slice(-200));
    ok(text.startsWith('{"items":['));
  });

  it('applies the same truncation to withSummary', () => {
    const text = withSummary('done.', 'x'.repeat(RESULT_CHAR_BUDGET + 1000)).content[0].text;
    ok(text.includes('[truncated:'));
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

  it('get_vulnerability is compact by default: ranges, not every affected version', async () => {
    const detail = {
      id: 'GHSA-frmv-pr5f-9mcr',
      schemaVersion: '1.9.0',
      summary: 'Django SQL injection',
      aliases: ['CVE-2025-64459', 'PYSEC-2025-108'],
      references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-64459' }],
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }],
      affected: [
        {
          package: { ecosystem: 'PyPI', name: 'django', purl: 'pkg:pypi/django' },
          ranges: [{ type: 'ECOSYSTEM', repo: null, events: [{ introduced: '5.0a1', fixed: null }, { introduced: null, fixed: '5.1.14' }] }],
          versions: Array.from({ length: 400 }, (_, i) => `5.0.${i}`),
          databaseSpecific: { source: 'x' },
        },
      ],
      databaseSpecific: { severity: 'CRITICAL', cwe_ids: ['CWE-89'], github_reviewed: true },
      remediation: { fixedVersion: '5.1.14', upgradeSkillId: 'fix-vulnerable-dependency' },
      threatIntel: { isKev: false, epssScore: 0.19 },
    };
    stubFetch(() => detail);
    const compact = payload(await call(base, 'get_vulnerability', { osvId: 'GHSA-frmv-pr5f-9mcr' }));
    deepStrictEqual(compact.affected, [
      { package: { ecosystem: 'PyPI', name: 'django' }, ranges: [{ type: 'ECOSYSTEM', introduced: ['5.0a1'], fixed: ['5.1.14'] }], versionCount: 400 },
    ]);
    deepStrictEqual(compact.references, ['https://nvd.nist.gov/vuln/detail/CVE-2025-64459']);
    deepStrictEqual(compact.databaseSpecific, { severity: 'CRITICAL', cwe_ids: ['CWE-89'] });
    deepStrictEqual(compact.remediation, detail.remediation);
    deepStrictEqual(compact.threatIntel, detail.threatIntel);
    deepStrictEqual(compact.aliases, detail.aliases);
    strictEqual(compact.schemaVersion, undefined);

    stubFetch(() => detail);
    const full = payload(await call(base, 'get_vulnerability', { osvId: 'GHSA-frmv-pr5f-9mcr', verbosity: 'full' }));
    deepStrictEqual(full, detail);
  });

  it('get_vulnerability compact keeps explicit versions when an entry has no ranges', async () => {
    const mk = (n) => ({ id: 'X-1', affected: [{ package: { ecosystem: 'npm', name: 'p' }, versions: Array.from({ length: n }, (_, i) => `1.0.${i}`) }] });
    stubFetch(() => mk(3));
    const small = payload(await call(base, 'get_vulnerability', { osvId: 'X-1' }));
    deepStrictEqual(small.affected, [
      { package: { ecosystem: 'npm', name: 'p' }, ranges: [], versionCount: 3, versions: ['1.0.0', '1.0.1', '1.0.2'] },
    ]);

    stubFetch(() => mk(120));
    const big = payload(await call(base, 'get_vulnerability', { osvId: 'X-1' }));
    strictEqual(big.affected[0].versionCount, 120);
    strictEqual(big.affected[0].versions.length, 50);
    strictEqual(big.affected[0].versions[49], '1.0.49');
    strictEqual(big.affected[0].versionsTruncated, true);
  });

  it('get_vulnerability compact keeps repo on a GIT range', async () => {
    stubFetch(() => ({
      id: 'X-2',
      affected: [{
        package: { ecosystem: 'Go', name: 'm' },
        ranges: [{ type: 'GIT', repo: 'https://example.com/o/r', events: [{ introduced: '0' }, { fixed: 'abc123' }] }],
        versions: ['v1.0.0'],
      }],
    }));
    const body = payload(await call(base, 'get_vulnerability', { osvId: 'X-2' }));
    deepStrictEqual(body.affected[0].ranges, [{ type: 'GIT', repo: 'https://example.com/o/r', introduced: ['0'], fixed: ['abc123'] }]);
    strictEqual(body.affected[0].versions, undefined);
  });

  it('get_vulnerability passes the installed version through', async () => {
    const calls = stubFetch();
    await call(base, 'get_vulnerability', { osvId: 'GHSA-a/b', version: '1.2.3' });
    ok(calls[0].url.includes('GHSA-a%2Fb'));
    strictEqual(new URL(calls[0].url).searchParams.get('version'), '1.2.3');
  });

  it('get_license_policy and lookup_package hit their endpoints', async () => {
    const calls = stubFetch();
    await call(base, 'get_license_policy');
    await call(base, 'lookup_package', { ecosystem: 'npm', name: 'x', version: '1.0.0' });
    const paths = calls.map((c) => new URL(c.url).pathname);
    deepStrictEqual(paths, ['/api/v1/license-policy', '/api/v1/lookup']);
  });

  it('get_policies returns the full policy from /api/v1/policies unchanged', async () => {
    const policy = {
      allowlistMode: 'off',
      proxyPassthroughEnabled: true,
      license: { installMode: 'block', publishMode: 'off', allowlist: [{ licenseSpdx: 'MIT' }], blocklist: [] },
      controls: {
        kev: { mode: 'block', effect: 'block', active: false },
        vuln_score: { maxScore: 10, effect: 'off', active: true },
        provenance: { npm: { mode: 'block', effect: 'block', anchorsConfigured: false } },
      },
    };
    const calls = stubFetch(() => policy);
    const res = await call(base, 'get_policies');
    deepStrictEqual(calls.map((c) => new URL(c.url).pathname), ['/api/v1/policies']);
    strictEqual(res.isError, undefined);
    deepStrictEqual(payload(res), policy);
  });

  it('get_policies falls back to the licence policy on an older server that 404s', async () => {
    const paths = [];
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      paths.push(path);
      if (path === '/api/v1/policies') {
        return new Response('{"title":"Not Found"}', { status: 404, headers: { 'content-type': 'application/problem+json' } });
      }
      return new Response('{"mode":"warn","allowlist":[],"blocklist":[]}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const res = await call(base, 'get_policies');
    deepStrictEqual(paths, ['/api/v1/policies', '/api/v1/license-policy']);
    strictEqual(res.isError, undefined);
    const [note, body] = res.content[0].text.split('\n\n');
    ok(note.includes('does not expose the full package policy yet'), note);
    ok(note.includes('licence policy follows'), note);
    ok(note.includes('Do not conclude the org has no other controls'), note);
    deepStrictEqual(JSON.parse(body), { mode: 'warn', allowlist: [], blocklist: [] });
  });

  for (const status of [400, 401, 403, 500, 503]) {
    it(`get_policies reports a ${status} as an error without falling back`, async () => {
      const paths = [];
      globalThis.fetch = async (url) => {
        paths.push(new URL(String(url)).pathname);
        return new Response('{"detail":"read:packages capability required."}', {
          status,
          headers: { 'content-type': 'application/json' },
        });
      };
      const res = await call(base, 'get_policies');
      strictEqual(res.isError, true);
      ok(res.content[0].text.includes(String(status)), res.content[0].text);
      deepStrictEqual(paths, ['/api/v1/policies'], `a ${status} must not be papered over with the licence policy`);
    });
  }

  it('get_policies reports a network failure as an error without falling back', async () => {
    const paths = [];
    globalThis.fetch = async (url) => {
      paths.push(new URL(String(url)).pathname);
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) });
    };
    const res = await call(base, 'get_policies');
    strictEqual(res.isError, true);
    deepStrictEqual(paths, ['/api/v1/policies']);
  });

  it('get_policies describes itself as the whole policy and carries the glossary; get_license_policy defers to it', async () => {
    const tools = await withServer(base, async (c) => (await c.listTools()).tools);
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    const policies = byName.get_policies;
    ok(policies, 'get_policies is registered');
    deepStrictEqual(policies.inputSchema.properties ?? {}, {});
    strictEqual(policies.inputSchema.additionalProperties, false);
    const d = policies.description;
    for (const needle of [
      'GET /api/v1/policies',
      'third-party',
      'prefer it over get_license_policy',
      'call lookup_package',
      'X-Dependably-Block-Reason',
      'not its raw `mode`',
      'never "no policy"',
      'still enforcing on data already recorded',
      '`anchorsConfigured` is false',
      'block_new refuses only versions not yet cached',
      'vuln_score.maxScore 10',
      'CISA Known Exploited Vulnerabilities Catalog',
      'the installing client sees no warning',
      'refuses more versions over time as their enrichment goes stale',
      '`manual` has no key',
      'any licence not on the allowlist',
    ]) {
      ok(d.includes(needle), `get_policies description should mention ${JSON.stringify(needle)}`);
    }
    // Every reason token the server keys `controls` by has a glossary line.
    for (const key of [
      'malicious', 'malicious_live', 'kev', 'kev_ransomware', 'ssvc_exploitation', 'vuln_score', 'epss',
      'epss_percentile', 'release_age', 'deprecated', 'revoked', 'install_script', 'license', 'provenance',
    ]) {
      ok(d.includes(`\n- ${key}: `), `glossary is missing the "${key}" control`);
    }
    const lic = byName.get_license_policy.description;
    ok(lic.startsWith('Licence rules only'), lic);
    ok(lic.includes('use get_policies'), lic);
    strictEqual(byName.get_license_policy.title, 'Get licence policy');
  });

  it('surfaces an API error as an error result rather than throwing', async () => {
    globalThis.fetch = async () =>
      new Response('{"detail":"nope"}', { status: 403, headers: { 'content-type': 'application/json' } });
    const res = await call(base, 'get_license_policy');
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

  it('rejects a limit above 200, matching list_packages', async () => {
    stubFetch(() => ({ items: [item], total: 1 }));
    const res = await call(base, 'list_vulnerabilities', { limit: 201 });
    ok(res.isError, 'limit above 200 must be rejected');
  });

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
      if (u.pathname === '/npm/-/npm/v1/security/advisories/bulk') return {};
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
      await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'hono', version: '4.12.27' }] }),
    );
    ok(!('cwes' in withoutDetail.findings[0].advisories[0]));

    stubReportAndAdvisories();
    const withDetail = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm',
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
      await call(base, 'check_dependencies', { ecosystem: 'npm',
        packages: [{ name: 'hono', version: '4.12.27', dev: true }],
      }),
    );
    strictEqual(body.summary.devOnly, 2);
    strictEqual(body.summary.runtime, 0);
    strictEqual(body.findings[0].dev, true);
  });

  it('requires the ecosystem, so a pip list is never silently checked as npm', async () => {
    stubReportAndAdvisories();
    const res = await call(base, 'check_dependencies', { packages: [{ name: 'django', version: '5.0.6' }] });
    ok(res.isError, res.content[0].text);
    const tools = await withServer(base, (c) => c.listTools());
    ok(tools.tools.find((x) => x.name === 'check_dependencies').inputSchema.required.includes('ecosystem'));
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

  it('never reports clean on a truncated scan, even when no match was found on the pages it did read (B2)', async () => {
    // A truncated fetch stops before every page of the org-wide report has
    // been read; the page it never got to could contain the very match that
    // would have made this dirty, so `clean` must not be true just because
    // nothing matched among the pages it did see.
    stubFetch((url) => {
      const u = new URL(url);
      if (u.pathname === '/api/v1/vuln-report') {
        return {
          items: Array.from({ length: 200 }, (_, i) => ({
            packageName: `pkg-${i}`,
            version: '1.0.0',
            osvId: `O${i}`,
            severity: 'LOW',
          })),
          total: 999999,
        };
      }
      return { remediation: {} };
    });
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'hono', version: '4.12.27' }] }),
    );
    strictEqual(body.truncated, true);
    strictEqual(body.clean, false, 'a truncated scan must never claim clean');
    ok(body.note.toLowerCase().includes('inconclusive'), body.note);
  });

  it('does not recommend a downgrade for an rpm "version-release" string (B4)', async () => {
    // rpm's NEVRA glues a release onto the version with a hyphen ("1.2.3-4"):
    // read as semver's hyphen, that is a prerelease of 1.2.3 and sorts BELOW
    // it, so an installed 1.2.3-4 against a fix of 1.2.3 used to come back as
    // a bump — a downgrade recommendation for a package already fixed.
    stubFetch((url) => {
      const u = new URL(url);
      if (u.pathname === '/api/v1/vuln-report') {
        return u.searchParams.get('page') === '1'
          ? { items: [{ packageName: 'openssl', version: '1.2.3-4', osvId: 'A', severity: 'HIGH' }], total: 1 }
          : { items: [], total: 1 };
      }
      return { remediation: { fixedVersion: '1.2.3' } };
    });
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'rpm',
        packages: [{ name: 'openssl', version: '1.2.3-4' }],
      }),
    );
    strictEqual(body.findings[0].bumpTo, null, '1.2.3-4 already clears a fix pinned to the bare release 1.2.3');
  });

  it('recommends the real release as the bump target for an installed rpm tilde pre-release (B4)', async () => {
    // "~" sorts below everything, including a plain release: an installed
    // 1.2.3~rc1-1 has not reached a fix of 1.2.3-1 and must be told to bump.
    stubFetch((url) => {
      const u = new URL(url);
      if (u.pathname === '/api/v1/vuln-report') {
        return u.searchParams.get('page') === '1'
          ? { items: [{ packageName: 'openssl', version: '1.2.3~rc1-1', osvId: 'A', severity: 'HIGH' }], total: 1 }
          : { items: [], total: 1 };
      }
      return { remediation: { fixedVersion: '1.2.3-1' } };
    });
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'rpm',
        packages: [{ name: 'openssl', version: '1.2.3~rc1-1' }],
      }),
    );
    strictEqual(body.findings[0].bumpTo, '1.2.3-1');
  });
});

describe('check_dependencies live coverage', () => {
  const emptyReport = { items: [], total: 0 };

  /** Like stubFetch, but a route may answer `{ status, body }` to send a non-200. */
  function stubRoutes(routes) {
    const calls = [];
    globalThis.fetch = async (url, init) => {
      const u = new URL(String(url));
      calls.push({ path: u.pathname, query: u.searchParams, method: init?.method ?? 'GET', body: init?.body });
      const handler = routes[u.pathname] ?? routes['*'];
      const out = handler ? handler(u, init) : {};
      const status = out && typeof out === 'object' && 'status' in out ? out.status : 200;
      const body = out && typeof out === 'object' && 'status' in out ? out.body : out;
      return new Response(JSON.stringify(body ?? {}), { status, headers: { 'content-type': 'application/json' } });
    };
    return calls;
  }

  it('reports a range, tag or source spec as unverified rather than checking it as a version', async () => {
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      // The server answers an unparseable version with "no advisories".
      '/npm/-/npm/v1/security/advisories/bulk': () => ({}),
    });
    const specs = ['^4.17.20', '~4.17.0', '4.17', '4.17.x', 'latest', '=4.17.20', 'npm:lodash@4.17.20', 'git+https://x/y#4.17.20', 'file:../lodash', '>=4 <5'];
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm', packages: specs.map((version) => ({ name: 'lodash', version })) }),
    );
    strictEqual(body.clean, false);
    strictEqual(body.coverage.unverified, specs.length);
    strictEqual(body.coverage.liveChecked, 0);
    strictEqual(body.summary.packagesChecked, 0);
    ok(body.coverage.unverifiedPackages.every((u) => /not an exact version/.test(u.reason)));
    strictEqual(calls.filter((c) => c.path === '/npm/-/npm/v1/security/advisories/bulk').length, 0);
  });

  it('accepts exact npm versions with a v prefix, prerelease or build metadata', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport, '/npm/-/npm/v1/security/advisories/bulk': () => ({}) });
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'npm',
        packages: ['4.17.20', 'v4.17.20', '1.0.0-rc.1', '1.0.0+build.5'].map((version, i) => ({ name: `p${i}`, version })),
      }),
    );
    strictEqual(body.clean, true);
    deepStrictEqual(body.coverage, { liveChecked: 4, unverified: 0 });
  });

  it('reports a range as unverified on the lookup path too', async () => {
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/api/v1/lookup': () => ({ found: true, vulnerabilities: { available: true, scored: [], unscored: [] } }),
    });
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'django', version: '>=5.0' }, { name: 'requests', version: '2.32.4' }] }),
    );
    strictEqual(body.clean, false);
    deepStrictEqual(body.coverage.unverifiedPackages.map((u) => u.name), ['django']);
    deepStrictEqual(calls.filter((c) => c.path === '/api/v1/lookup').map((c) => c.query.get('name')), ['requests']);
  });

  it('requires an exact version per ecosystem: a Go branch, a bracket range, a Gradle dynamic version or a Cargo requirement is unverified', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      // An air-gapped lookup accepts any explicit version and finds nothing.
      '/api/v1/lookup': () => ({ found: true, vulnerabilities: { available: true, scored: [], unscored: [] } }),
    });
    const cases = {
      golang: { bad: ['master', 'abcdef1', 'v1', 'upgrade'], good: ['v1.10.0', 'v0.0.0-20230101000000-abcdef123456', 'v2.0.0+incompatible'] },
      maven: { bad: ['[1.0]', '[1.0,2.0)', '1.+', 'latest.release', 'RELEASE', 'LATEST'], good: ['1.0-SNAPSHOT', '2.14.1'] },
      nuget: { bad: ['[1.0.0]', '(1.0,2.0]'], good: ['1.0.0-beta.1', '13.0.3'] },
      cargo: { bad: ['1.0', '1', '^1.0.0'], good: ['1.0.200', '0.4.0-alpha.1'] },
      pypi: { bad: ['>=5.0', '~=1.4', '==1.0', '1.*'], good: ['1.0.post1', '2!1.0', '1.0+local'] },
      rpm: { bad: ['>= 2.0', 'file:./x.rpm'], good: ['2.0~rc1', '1.0^20230101git0abc', '1:2.3-4.el9', '5.2.26-3.fc40'] },
      apk: { bad: ['>1.2'], good: ['1.2.3-r0', '1.2.3_p1-r2', '1.2.3~rc1-r0'] },
    };
    for (const [ecosystem, { bad, good }] of Object.entries(cases)) {
      const packages = [...bad, ...good].map((version, i) => ({ name: `p${i}`, version }));
      const body = payload(await call(base, 'check_dependencies', { ecosystem, packages }));
      // rpm and apk have no live source, so their exact versions are unverified for that
      // reason; only the "not an exact version" entries are the inexact ones.
      deepStrictEqual(
        body.coverage.unverifiedPackages.filter((u) => /not an exact version/.test(u.reason)).map((u) => u.version).sort(),
        [...bad].sort(),
        `${ecosystem}: ${JSON.stringify(body.coverage)}`,
      );
    }
  });

  it('treats an npm version whose numeric part overflows the server parser as unverified', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport, '/npm/-/npm/v1/security/advisories/bulk': () => ({}) });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'p', version: '2147483648.0.0' }] }));
    strictEqual(body.clean, false);
    strictEqual(body.coverage.unverified, 1);
  });

  it('folds the same way whatever order the advisories arrive in, even when a twin repeats a predecessor CVE', async () => {
    const rows = [
      { osvId: 'GHSA-aaaa', aliases: ['CVE-1'] },
      { osvId: 'PYSEC-a', aliases: ['CVE-1'] },
      { osvId: 'GHSA-bbbb', aliases: ['GHSA-aaaa', 'CVE-1', 'CVE-2'] },
      { osvId: 'PYSEC-b', aliases: ['CVE-1', 'CVE-2'] },
    ];
    const permutations = (xs) => (xs.length <= 1 ? [xs] : xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p])));
    const results = new Set();
    for (const order of permutations(rows)) {
      stubRoutes({
        '/api/v1/vuln-report': () => ({
          items: order.map((r) => ({ packageName: 'p', version: '1.0', osvId: r.osvId, severity: 'HIGH', summary: r.osvId, aliases: r.aliases })),
          total: order.length,
        }),
        '*': () => ({ status: 404, body: {} }),
      });
      const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'p', version: '1.0' }] }));
      results.add(JSON.stringify(body.findings[0].advisories.map((a) => [a.osvId, a.aliases ?? []]).sort()));
    }
    strictEqual(results.size, 1, [...results].join('\n'));
    // GHSA-bbbb is a follow-up of GHSA-aaaa: never folded with GHSA-aaaa's twin.
    ok(!JSON.parse([...results][0]).some(([id, al]) => id === 'GHSA-aaaa' && al.includes('PYSEC-b')));
  });

  it('flags a finding whose bumpTo may miss a capped advisory', async () => {
    const items = Array.from({ length: 201 }, (_, i) => ({ packageName: 'p', version: '1.0.0', osvId: `GHSA-${i}`, severity: i === 0 ? 'LOW' : 'HIGH', cvssScore: i === 0 ? 1 : 8 }));
    stubRoutes({
      '/api/v1/vuln-report': () => ({ items, total: items.length }),
      '/npm/-/npm/v1/security/advisories/bulk': () => ({}),
      '*': () => ({ remediation: { fixedVersion: '2.0.0' } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'p', version: '1.0.0' }] }));
    strictEqual(body.findings[0].bumpToPartial, true);
  });

  it('splits an over-budget npm bulk round into several requests and merges the results', async () => {
    // Long versions push 5000 names past the budget even though each name is within its cap.
    const packages = Array.from({ length: 5000 }, (_, i) => ({ name: `p${i}-`.padEnd(512, 'x'), version: `1.0.0-${'y'.repeat(200)}` }));
    const bodies = [];
    const client = {
      post: async (path, body) => {
        strictEqual(path, '/npm/-/npm/v1/security/advisories/bulk');
        bodies.push(JSON.stringify(body));
        const out = {};
        for (const n of [packages[0].name, packages[4999].name]) if (n in body) out[n] = [{ id: `GHSA-${n.slice(0, 5)}`, severity: 'high' }];
        return out;
      },
    };
    const res = await liveCheckNpm(client, packages);
    ok(bodies.length > 1, `expected several POSTs, got ${bodies.length}`);
    ok(bodies.every((b) => Buffer.byteLength(b) <= 3 * 1024 * 1024), 'every body stays under the budget');
    strictEqual(res.hits.length, 2, 'hits from different chunks are merged');
    strictEqual(res.unverified.length, 0);
    strictEqual(res.checked, 5000);
  });

  it('rejects a package name over 512 characters with a validation error', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport });
    const res = await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'x'.repeat(513), version: '1.0.0' }] });
    strictEqual(res.isError, true);
    match(res.content[0].text, /512/);
  });

  it('marks a dependency unverified when an advisory for it comes back without an id', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/npm/-/npm/v1/security/advisories/bulk': () => ({ a: [{ severity: 'high' }] }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'a', version: '1.0.0' }, { name: 'b', version: '1.0.0' }] }));
    strictEqual(body.clean, false);
    deepStrictEqual(body.coverage.unverifiedPackages.map((u) => u.name), ['a']);
    strictEqual(body.coverage.liveChecked, 1);
  });

  it('caps fixed-version lookups at the most severe advisories and says so', async () => {
    const items = Array.from({ length: 205 }, (_, i) => ({
      packageName: 'p', version: '1.0.0', osvId: `GHSA-${i}`, severity: i < 5 ? 'LOW' : 'HIGH', cvssScore: i < 5 ? 1 : 8,
    }));
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => ({ items, total: items.length }),
      '/npm/-/npm/v1/security/advisories/bulk': () => ({}),
      '*': () => ({ remediation: { fixedVersion: '2.0.0' } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'p', version: '1.0.0' }] }));
    strictEqual(calls.filter((c) => c.path.startsWith('/api/v1/vulnerabilities/')).length, 200);
    match(body.remediationNote, /200 most severe advisories; 5 more/);
    const low = body.findings[0].advisories.filter((a) => a.severity === 'LOW');
    ok(low.every((a) => a.fixedVersion === null), 'the 5 least severe were the ones skipped');
  });

  it('counts each distinct dependency once in packagesChecked', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport, '/npm/-/npm/v1/security/advisories/bulk': () => ({}) });
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'a', version: '1.0.0' }, { name: 'a', version: '1.0.0' }, { name: 'b', version: '^1' }] }),
    );
    strictEqual(body.summary.packagesChecked, 1);
  });

  it('finds an advisory on an npm version the registry has never served (the lodash false clean)', async () => {
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/npm/-/npm/v1/security/advisories/bulk': () => ({
        // The server renders OSV intervals as an npm range, not the requested version.
        lodash: [{ id: 'GHSA-35jh-r3h4-6jhm', title: 'Command Injection in lodash', severity: 'high', vulnerable_versions: '<4.17.21', cvss: { score: 7.2 } }],
      }),
      '*': () => ({ status: 404, body: { title: 'Not Found' } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'lodash', version: '4.17.20' }] }));
    strictEqual(body.clean, false);
    strictEqual(body.findings[0].package, 'lodash');
    strictEqual(body.findings[0].advisories[0].osvId, 'GHSA-35jh-r3h4-6jhm');
    strictEqual(body.findings[0].advisories[0].severity, 'HIGH');
    strictEqual(body.findings[0].advisories[0].cvss, 7.2);
    strictEqual(body.coverage.liveChecked, 1);
    strictEqual(body.coverage.unverified, 0);
    const bulk = calls.find((c) => c.path === '/npm/-/npm/v1/security/advisories/bulk');
    strictEqual(bulk.method, 'POST');
    deepStrictEqual(JSON.parse(bulk.body), { lodash: ['4.17.20'] });
  });

  it('asks about one version per name per request, so a listed advisory applies to that version', async () => {
    // The server lists an advisory under a name only if it affects a requested
    // version of it; with two versions in one request the client could not tell
    // which one. Each request therefore carries one version per name.
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/npm/-/npm/v1/security/advisories/bulk': (u, init) => {
        const asked = JSON.parse(init.body);
        const out = {};
        if (asked.a?.[0] === '1.0.0') out.a = [{ id: 'GHSA-1', severity: 'moderate', vulnerable_versions: '<1.5.0' }];
        if (asked.b) out.b = [{ id: 'GHSA-2', severity: 'info', vulnerable_versions: '>=3.0.0 <3.1.0' }];
        return out;
      },
      '*': () => ({ status: 404, body: {} }),
    });
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm',
        packages: [
          { name: 'a', version: '1.0.0' },
          { name: 'a', version: '2.0.0' },
          { name: 'b', version: '3.0.0' },
        ],
      }),
    );
    deepStrictEqual(
      calls.filter((c) => c.path === '/npm/-/npm/v1/security/advisories/bulk').map((c) => JSON.parse(c.body)),
      [{ a: ['1.0.0'], b: ['3.0.0'] }, { a: ['2.0.0'] }],
    );
    deepStrictEqual(
      body.findings.map((f) => `${f.package}@${f.installed}:${f.advisories.map((a) => `${a.osvId}/${a.severity}`).join(',')}`).sort(),
      ['a@1.0.0:GHSA-1/MEDIUM', 'b@3.0.0:GHSA-2/UNKNOWN'],
    );
    strictEqual(body.clean, false);
    deepStrictEqual(body.coverage, { liveChecked: 3, unverified: 0 });
  });

  it('leaves only the failed round unverified when one of several npm requests fails', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/npm/-/npm/v1/security/advisories/bulk': (u, init) =>
        JSON.parse(init.body).a?.[0] === '2.0.0' ? { status: 503, body: {} } : {},
    });
    const body = payload(
      await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'a', version: '1.0.0' }, { name: 'a', version: '2.0.0' }] }),
    );
    strictEqual(body.clean, false);
    strictEqual(body.coverage.liveChecked, 1);
    deepStrictEqual(body.coverage.unverifiedPackages.map((u) => `${u.name}@${u.version}`), ['a@2.0.0']);
  });

  it('is never clean when the npm advisory check cannot vouch for the tree', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/npm/-/npm/v1/security/advisories/bulk': () => ({ status: 503, body: { title: 'Service Unavailable' } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'left-pad', version: '1.3.0' }] }));
    strictEqual(body.clean, false);
    strictEqual(body.coverage.unverified, 1);
    strictEqual(body.coverage.unverifiedPackages[0].name, 'left-pad');
    match(body.coverage.unverifiedPackages[0].reason, /live npm advisory check failed: 503/);
    match(body.coverage.note, /1 dependency was not checked/);
  });

  it('treats a non-object npm advisory answer (a proxy page, an array) as unverified, not clean', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport, '/npm/-/npm/v1/security/advisories/bulk': () => [] });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'x', version: '1.0.0' }] }));
    strictEqual(body.clean, false);
    match(body.coverage.unverifiedPackages[0].reason, /unexpected body/);
  });

  it('looks up, one by one, the non-npm dependencies the report has nothing on', async () => {
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => ({ items: [{ packageName: 'django', version: '5.0.6', osvId: 'GHSA-d', severity: 'HIGH' }], total: 1 }),
      '/api/v1/lookup': (u) => {
        const name = u.searchParams.get('name');
        if (name === 'requests') {
          return { found: true, vulnerabilities: { available: true, scored: [{ id: 'GHSA-r', severity: 'MEDIUM', cvssScore: 5.3, epss: 0.01, isKev: false, summary: 'netrc leak' }], unscored: [] } };
        }
        if (name === 'ghost') return { found: false, vulnerabilities: { available: true, scored: [], unscored: [] } };
        if (name === 'offline') return { found: true, vulnerabilities: { available: false, scored: [], unscored: [] } };
        if (name === 'broken') return { status: 503, body: { title: 'upstream down' } };
        return { found: true, vulnerabilities: { available: true, scored: [], unscored: [] } };
      },
      '*': () => ({ status: 404, body: {} }),
    });
    const body = payload(
      await call(base, 'check_dependencies', {
        ecosystem: 'pypi',
        packages: [
          { name: 'django', version: '5.0.6' },
          { name: 'requests', version: '2.32.3' },
          { name: 'clean-pkg', version: '1.0' },
          { name: 'ghost', version: '1.0' },
          { name: 'offline', version: '1.0' },
          { name: 'broken', version: '1.0' },
        ],
      }),
    );
    const looked = calls.filter((c) => c.path === '/api/v1/lookup').map((c) => c.query.get('name')).sort();
    deepStrictEqual(looked, ['broken', 'clean-pkg', 'ghost', 'offline', 'requests'], 'django was in the report, so it is not looked up again');
    deepStrictEqual(body.findings.map((f) => f.package).sort(), ['django', 'requests']);
    strictEqual(body.clean, false);
    strictEqual(body.coverage.liveChecked, 2);
    deepStrictEqual(
      body.coverage.unverifiedPackages.map((u) => u.name).sort(),
      ['broken', 'ghost', 'offline'],
    );
  });

  it('reports a malicious version from lookup as a critical finding, never clean', async () => {
    // Lookup keeps MAL- ids out of scored/unscored and reports them under malware.
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/api/v1/lookup': () => ({
        found: true,
        malware: { detected: true, advisoryIds: ['MAL-2024-1'] },
        vulnerabilities: { available: true, scored: [], unscored: [] },
      }),
      '*': () => ({ status: 404, body: {} }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'evil', version: '1.0.0' }] }));
    strictEqual(body.clean, false);
    strictEqual(body.findings[0].advisories[0].osvId, 'MAL-2024-1');
    strictEqual(body.findings[0].advisories[0].severity, 'CRITICAL');
    match(body.findings[0].advisories[0].summary, /Malicious package/);
  });

  it('rejects a blank name or version, which no advisory source would check', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport });
    const res = await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'x', version: '   ' }] });
    ok(res.isError, res.content[0].text);
  });

  it('caps the per-package lookups and reports the rest as unverified', async () => {
    const calls = stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/api/v1/lookup': () => ({ found: true, vulnerabilities: { available: true, scored: [], unscored: [] } }),
    });
    const packages = Array.from({ length: 105 }, (_, i) => ({ name: `p${i}`, version: '1.0' }));
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages }));
    strictEqual(calls.filter((c) => c.path === '/api/v1/lookup').length, 100);
    strictEqual(body.clean, false);
    strictEqual(body.coverage.liveChecked, 100);
    strictEqual(body.coverage.unverified, 5);
    match(body.coverage.unverifiedPackages[0].reason, /100-dependency live-check limit/);
  });

  it('leaves dependencies of an ecosystem with no live source unverified, never clean', async () => {
    stubRoutes({ '/api/v1/vuln-report': () => emptyReport });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'rpm', packages: [{ name: 'bash', version: '5.2.26-3.fc40' }] }));
    strictEqual(body.clean, false);
    match(body.coverage.unverifiedPackages[0].reason, /no live advisory source for rpm/);
  });

  it('is clean only when every dependency was checked and nothing matched', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => emptyReport,
      '/api/v1/lookup': () => ({ found: true, vulnerabilities: { available: true, scored: [], unscored: [] } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'cargo', packages: [{ name: 'serde', version: '1.0.200' }] }));
    strictEqual(body.clean, true);
    deepStrictEqual(body.coverage, { liveChecked: 1, unverified: 0 });
  });

  it('folds using the aliases a report row carries when the advisory detail is unavailable', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => ({
        items: [
          { packageName: 'django', version: '5.0.6', osvId: 'GHSA-f6f8', severity: 'HIGH', cvssScore: 8.7, summary: 'DoS', aliases: ['CVE-2024-1'] },
          { packageName: 'django', version: '5.0.6', osvId: 'PYSEC-2024-59', severity: 'HIGH', cvssScore: 8.7, summary: 'DoS', aliases: ['CVE-2024-1', 'GHSA-f6f8'] },
        ],
        total: 2,
      }),
      '*': () => ({ status: 404, body: {} }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'django', version: '5.0.6' }] }));
    strictEqual(body.summary.advisories, 1);
    deepStrictEqual(body.findings[0].advisories[0].aliases, ['PYSEC-2024-59']);
  });

  it('does not fold two GHSAs when a follow-up advisory lists its predecessor as an alias', async () => {
    // Real data: GHSA-r5fr-rjxr-66jc (2026, fixed 4.18.0) names GHSA-35jh-r3h4-6jhm
    // and CVE-2021-23337 (fixed 4.17.21) among its aliases. They are two flaws.
    stubRoutes({
      '/api/v1/vuln-report': () => ({
        items: [
          { packageName: 'lodash', version: '4.17.20', osvId: 'GHSA-35jh-r3h4-6jhm', severity: 'HIGH', cvssScore: 7.2, summary: 'Command Injection' },
          { packageName: 'lodash', version: '4.17.20', osvId: 'GHSA-r5fr-rjxr-66jc', severity: 'HIGH', cvssScore: 8.1, summary: 'Code Injection via imports' },
          { packageName: 'lodash', version: '4.17.20', osvId: 'PYSEC-0000-1', severity: 'UNKNOWN', summary: '' },
        ],
        total: 3,
      }),
      '/api/v1/vulnerabilities/GHSA-35jh-r3h4-6jhm': () => ({ aliases: ['CVE-2021-23337'], remediation: { fixedVersion: '4.17.21' } }),
      '/api/v1/vulnerabilities/GHSA-r5fr-rjxr-66jc': () => ({ aliases: ['CVE-2021-23337', 'CVE-2026-4800', 'GHSA-35jh-r3h4-6jhm'], remediation: { fixedVersion: '4.18.0' } }),
      '/api/v1/vulnerabilities/PYSEC-0000-1': () => ({ aliases: ['CVE-2026-4800'], remediation: { fixedVersion: '4.18.0' } }),
      '/npm/-/npm/v1/security/advisories/bulk': () => ({}),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'npm', packages: [{ name: 'lodash', version: '4.17.20' }] }));
    const ids = body.findings[0].advisories.map((a) => `${a.osvId}:${(a.aliases ?? []).join('+')}:${a.fixedVersion}`).sort();
    deepStrictEqual(ids, ['GHSA-35jh-r3h4-6jhm::4.17.21', 'GHSA-r5fr-rjxr-66jc:PYSEC-0000-1:4.18.0']);
    strictEqual(body.summary.advisories, 2);
  });

  it('attaches a PYSEC record to the GHSA it names, whatever order the advisories arrive in', async () => {
    // GHSA-b is a follow-up naming GHSA-a and CVE-1; PYSEC-x names GHSA-a and CVE-1.
    const rows = {
      a: { packageName: 'django', version: '5.0.6', osvId: 'GHSA-a', severity: 'HIGH', summary: 'first' },
      b: { packageName: 'django', version: '5.0.6', osvId: 'GHSA-b', severity: 'HIGH', summary: 'follow-up' },
      x: { packageName: 'django', version: '5.0.6', osvId: 'PYSEC-x', severity: 'UNKNOWN', summary: '' },
    };
    for (const order of [['a', 'x', 'b'], ['b', 'x', 'a'], ['x', 'b', 'a']]) {
      stubRoutes({
        '/api/v1/vuln-report': () => ({ items: order.map((k) => rows[k]), total: 3 }),
        '/api/v1/vulnerabilities/GHSA-a': () => ({ aliases: ['CVE-1'] }),
        '/api/v1/vulnerabilities/GHSA-b': () => ({ aliases: ['CVE-1', 'GHSA-a'] }),
        '/api/v1/vulnerabilities/PYSEC-x': () => ({ aliases: ['CVE-1', 'GHSA-a'] }),
      });
      const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'django', version: '5.0.6' }] }));
      const byId = Object.fromEntries(body.findings[0].advisories.map((a) => [a.osvId, a.aliases ?? []]));
      deepStrictEqual(byId, { 'GHSA-a': ['PYSEC-x'], 'GHSA-b': [] }, order.join(','));
    }
  });

  it('never folds a follow-up into an unrelated record through its predecessor\'s CVE', async () => {
    // GHSA-b is a follow-up naming GHSA-a (absent) and the old CVE-1; PYSEC-x names only CVE-1.
    // PYSEC-x may be GHSA-a's twin, not GHSA-b's, so they must stay two advisories.
    stubRoutes({
      '/api/v1/vuln-report': () => ({
        items: [
          { packageName: 'p', version: '1.0', osvId: 'GHSA-b', severity: 'HIGH', summary: 'follow-up' },
          { packageName: 'p', version: '1.0', osvId: 'PYSEC-x', severity: 'UNKNOWN', summary: '' },
        ],
        total: 2,
      }),
      '/api/v1/vulnerabilities/GHSA-b': () => ({ aliases: ['CVE-1', 'GHSA-a'] }),
      '/api/v1/vulnerabilities/PYSEC-x': () => ({ aliases: ['CVE-1'] }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'p', version: '1.0' }] }));
    strictEqual(body.summary.advisories, 2);
  });

  it('ignores an empty alias, which would otherwise link unrelated records', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => ({
        items: [
          { packageName: 'django', version: '5.0.6', osvId: 'GHSA-p', severity: 'HIGH', summary: 'one', aliases: [''] },
          { packageName: 'django', version: '5.0.6', osvId: 'PYSEC-q', severity: 'LOW', summary: 'two', aliases: [''] },
        ],
        total: 2,
      }),
      '*': () => ({ status: 404, body: {} }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'django', version: '5.0.6' }] }));
    strictEqual(body.summary.advisories, 2);
  });

  it('folds a PYSEC record into its GHSA alias, so one flaw counts once', async () => {
    stubRoutes({
      '/api/v1/vuln-report': () => ({
        items: [
          { packageName: 'django', version: '5.0.6', osvId: 'GHSA-f6f8', severity: 'HIGH', cvssScore: 8.7, epssScore: 0.2, summary: 'DoS' },
          { packageName: 'django', version: '5.0.6', osvId: 'PYSEC-2024-59', severity: 'UNKNOWN', cvssScore: null, epssScore: 0.28, summary: '' },
          { packageName: 'django', version: '5.0.6', osvId: 'GHSA-other', severity: 'LOW', summary: 'unrelated' },
        ],
        total: 3,
      }),
      '/api/v1/vulnerabilities/GHSA-f6f8': () => ({ aliases: ['CVE-2024-1', 'PYSEC-2024-59'], remediation: { fixedVersion: '5.0.7' } }),
      '/api/v1/vulnerabilities/PYSEC-2024-59': () => ({ aliases: ['CVE-2024-1', 'GHSA-f6f8'], remediation: { fixedVersion: '5.0.8' } }),
      '/api/v1/vulnerabilities/GHSA-other': () => ({ aliases: ['CVE-2024-2'], remediation: { fixedVersion: '5.0.7' } }),
    });
    const body = payload(await call(base, 'check_dependencies', { ecosystem: 'pypi', packages: [{ name: 'django', version: '5.0.6' }] }));
    strictEqual(body.summary.advisories, 2);
    deepStrictEqual(body.summary.bySeverity, { critical: 0, high: 1, medium: 0, low: 1, unknown: 0 });
    const kept = body.findings[0].advisories[0];
    strictEqual(kept.osvId, 'GHSA-f6f8');
    deepStrictEqual(kept.aliases, ['PYSEC-2024-59']);
    strictEqual(kept.epss, 0.28, 'the folded record keeps the higher score');
    strictEqual(kept.fixedVersion, '5.0.8', 'and the higher fix');
    strictEqual(body.findings[0].advisories[1].aliases, undefined);
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

  it('marks the whole result as an error when every advisory lookup fails (B6)', async () => {
    globalThis.fetch = async () =>
      new Response('{"detail":"down"}', { status: 503, headers: { 'content-type': 'application/json' } });
    const res = await call(base, 'get_remediation', { advisories: [{ osvId: 'A' }, { osvId: 'B' }] });
    strictEqual(res.isError, true, 'a batch that is 100% failures is a tool error, not a quiet empty result');
    const body = payload(res);
    ok(body.advisories.every((a) => 'error' in a));
  });

  it('leaves isError unset when only some advisory lookups fail (a mixed batch stays a normal result)', async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes('BAD')) {
        return new Response('{"detail":"gone"}', { status: 404, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify({ remediation: { fixedVersion: '1.0.0' } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const res = await call(base, 'get_remediation', { advisories: [{ osvId: 'BAD' }, { osvId: 'GOOD' }] });
    ok(!res.isError, 'a partial failure must not sink the whole result');
  });
});

describe('list_remediation_skills', () => {
  it('returns the catalog as-is', async () => {
    const calls = stubFetch(() => [{ id: 'fix-xss', name: 'Fix XSS', description: 'Neutralize XSS.' }]);
    const body = payload(await call(base, 'list_remediation_skills', {}));
    deepStrictEqual(body, [{ id: 'fix-xss', name: 'Fix XSS', description: 'Neutralize XSS.' }]);
    strictEqual(new URL(calls[0].url).pathname, '/api/v1/remediation/skills');
  });
});

describe('get_remediation_skill', () => {
  it('fetches markdown content for several skill ids', async () => {
    const calls = stubFetch((url) => `# ${new URL(url).pathname.split('/').pop()}\n\nHow to fix it.`);
    const body = payload(
      await call(base, 'get_remediation_skill', { skillIds: ['fix-xss', 'fix-ssrf'] }),
    );
    strictEqual(body.skills.length, 2);
    ok(body.skills.find((s) => s.skillId === 'fix-xss').content.startsWith('# fix-xss'));
    ok(body.skills.find((s) => s.skillId === 'fix-ssrf').content.startsWith('# fix-ssrf'));
    ok(calls.every((c) => c.url.startsWith('https://dep.example.com/api/v1/remediation/skills/')));
  });

  it('reports a per-id failure without sinking the batch', async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes('unknown-skill')) {
        return new Response('{"detail":"not found"}', { status: 404, headers: { 'content-type': 'application/json' } });
      }
      return new Response('# fix-xss', { status: 200, headers: { 'content-type': 'text/markdown' } });
    };
    const body = payload(
      await call(base, 'get_remediation_skill', { skillIds: ['unknown-skill', 'fix-xss'] }),
    );
    ok(body.skills.find((s) => s.skillId === 'unknown-skill').error.includes('404'));
    strictEqual(body.skills.find((s) => s.skillId === 'fix-xss').content, '# fix-xss');
  });

  it('marks the whole result as an error when every skill lookup fails (B6)', async () => {
    globalThis.fetch = async () =>
      new Response('{"detail":"down"}', { status: 503, headers: { 'content-type': 'application/json' } });
    const res = await call(base, 'get_remediation_skill', { skillIds: ['fix-a', 'fix-b'] });
    strictEqual(res.isError, true, 'a batch that is 100% failures is a tool error, not a quiet empty result');
    const body = payload(res);
    ok(body.skills.every((s) => 'error' in s));
  });

  it('rejects more than 5 skill ids per call (B7)', async () => {
    const res = await call(base, 'get_remediation_skill', {
      skillIds: Array.from({ length: 6 }, (_, i) => `skill-${i}`),
    });
    ok(res.isError, 'more than 5 ids per call must be rejected');
  });

  it('accepts exactly 5 skill ids', async () => {
    stubFetch(() => '# doc');
    const res = await call(base, 'get_remediation_skill', {
      skillIds: Array.from({ length: 5 }, (_, i) => `skill-${i}`),
    });
    ok(!res.isError, res.content[0].text);
  });

  it('documents the 5-per-call cap and frames the returned markdown as third-party content (B7, B8)', async () => {
    const tools = await withServer(base, (c) => c.listTools());
    const tool = tools.tools.find((t) => t.name === 'get_remediation_skill');
    ok(tool.inputSchema.properties.skillIds.description.includes('5'), tool.inputSchema.properties.skillIds.description);
    ok(tool.description.includes('not by Anthropic'), tool.description);
  });
});

describe('project tools', () => {
  it('list_projects forwards exactly the given filters, offset absent when unset', async () => {
    const stub = { total: 1, limit: 10, offset: 0, sort: 'policy', dir: 'desc', items: [{ id: 'p1' }] };
    const calls = stubFetch(() => stub);
    const body = payload(await call(base, 'list_projects', { q: 'api', limit: 10, sort: 'policy', dir: 'desc' }));
    const u = new URL(calls[0].url);
    strictEqual(u.pathname, '/api/v1/projects');
    deepStrictEqual([...u.searchParams.keys()].sort(), ['dir', 'limit', 'q', 'sort']);
    strictEqual(u.searchParams.get('q'), 'api');
    strictEqual(u.searchParams.get('limit'), '10');
    strictEqual(u.searchParams.get('sort'), 'policy');
    strictEqual(u.searchParams.get('dir'), 'desc');
    ok(!u.searchParams.has('offset'), 'offset must be absent when not given');
    deepStrictEqual(body, stub);
  });

  it('list_projects rejects an out-of-range limit and an unrecognised sort value', async () => {
    stubFetch();
    const badLimit = await call(base, 'list_projects', { limit: 201 });
    ok(badLimit.isError, 'limit above 200 must be rejected');
    const badSort = await call(base, 'list_projects', { sort: 'bogus' });
    ok(badSort.isError, 'an unrecognised sort value must be rejected');
  });

  it('get_project url-encodes the id and returns the body unchanged', async () => {
    const stub = { id: 'a/b', name: 'x', versions: [], ancestors: [], children: [], rollup: null };
    const calls = stubFetch(() => stub);
    const body = payload(await call(base, 'get_project', { projectId: 'a/b' }));
    ok(calls[0].url.includes('/api/v1/projects/a%2Fb'), calls[0].url);
    deepStrictEqual(body, stub);
  });

  it('get_project surfaces a 404 problem+json as an error result carrying the server detail', async () => {
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ type: 'about:blank', title: 'Not Found', status: 404, detail: 'project not found' }),
        { status: 404, headers: { 'content-type': 'application/problem+json' } },
      );
    const res = await call(base, 'get_project', { projectId: 'missing' });
    strictEqual(res.isError, true);
    ok(res.content[0].text.includes('project not found'), res.content[0].text);
  });

  it('get_project_version with only projectId hits /versions/latest/analysis and sends no query params', async () => {
    const calls = stubFetch(() => ({ rollup: {}, page: 1, limit: 50, total: 0, items: [], orphanAnalysis: [] }));
    await call(base, 'get_project_version', { projectId: 'p1' });
    const u = new URL(calls[0].url);
    strictEqual(u.pathname, '/api/v1/projects/p1/versions/latest/analysis');
    strictEqual([...u.searchParams.keys()].length, 0, `expected no query params, got: ${u.search}`);
  });

  it('get_project_version forwards every filter exactly once', async () => {
    const calls = stubFetch(() => ({ rollup: {}, page: 1, limit: 50, total: 0, items: [], orphanAnalysis: [] }));
    await call(base, 'get_project_version', {
      projectId: 'p1',
      versionId: 'v1',
      page: 2,
      limit: 25,
      sort: 'severity',
      dir: 'asc',
      q: 'left',
      scope: 'prod',
      sev: 'high',
      reach: 'reachable',
      registry: 'present',
      violations: true,
      suppressed: true,
    });
    const u = new URL(calls[0].url);
    strictEqual(u.pathname, '/api/v1/projects/p1/versions/v1/analysis');
    strictEqual(u.searchParams.get('page'), '2');
    strictEqual(u.searchParams.get('limit'), '25');
    strictEqual(u.searchParams.get('sort'), 'severity');
    strictEqual(u.searchParams.get('dir'), 'asc');
    strictEqual(u.searchParams.get('q'), 'left');
    strictEqual(u.searchParams.get('scope'), 'prod');
    strictEqual(u.searchParams.get('sev'), 'high');
    strictEqual(u.searchParams.get('reach'), 'reachable');
    strictEqual(u.searchParams.get('registry'), 'present');
    strictEqual(u.searchParams.get('violations'), 'true');
    strictEqual(u.searchParams.get('suppressed'), 'true');
    strictEqual([...u.searchParams.keys()].length, 11, 'each filter must appear exactly once');
  });

  it('get_project_version rejects an invalid scope, a zero limit, a zero page, and an unknown property', async () => {
    stubFetch();
    ok((await call(base, 'get_project_version', { projectId: 'p1', scope: 'both' })).isError);
    ok((await call(base, 'get_project_version', { projectId: 'p1', limit: 0 })).isError);
    ok((await call(base, 'get_project_version', { projectId: 'p1', page: 0 })).isError);
    ok((await call(base, 'get_project_version', { projectId: 'p1', bogus: true })).isError);
  });

  it('compactAnalysis produces exactly the documented compact shape', () => {
    const fixture = {
      rollup: { componentTotal: 2 },
      page: 1,
      limit: 50,
      total: 2,
      items: [
        {
          componentId: 'c1',
          purl: 'pkg:npm/a@1.0.0',
          purlKey: 'k1',
          name: 'a',
          version: '1.0.0',
          ecosystem: 'npm',
          componentType: 'library',
          sbomScope: 'required',
          dependencyScope: 'runtime',
          isProd: true,
          dependencyKind: 'direct',
          dependencyPath: null,
          licenseSpdx: 'MIT',
          description: 'desc',
          author: null,
          copyright: null,
          group: null,
          websiteUrl: null,
          vcsUrl: null,
          issueTrackerUrl: null,
          distributionUrl: null,
          hashes: null,
          versionRange: null,
          isExternal: false,
          metadataSource: 'registry',
          inRegistry: true,
          registryLink: 'https://x',
          registry: {
            presence: 'present',
            hosted: true,
            cached: false,
            blocked: null,
            deprecated: null,
            latestVersion: '1.0.1',
            outdated: true,
          },
          policyViolations: [{ arm: 'license', detail: 'blocked license', vulnKey: null, licenseSpdx: 'GPL-3.0' }],
          advisories: [
            {
              vulnKey: 'v1',
              osvId: 'GHSA-1',
              aliases: [],
              severity: 'HIGH',
              cvss: 7.5,
              isKev: false,
              epss: 0.01,
              effectivePriority: 'act',
              unscored: false,
              severityBucket: 'high',
              vexState: null,
              vexJustification: null,
              vexResponse: null,
              vexDetail: null,
              vexSource: null,
              vexUpdatedBy: null,
              vexUpdatedAt: null,
              reachability: 'reachable',
              confidence: null,
              sarifSuppressed: false,
              securitySeverity: null,
              severityOrigin: null,
              inherited: false,
              policyViolations: [],
            },
            {
              vulnKey: 'v2',
              osvId: 'GHSA-2',
              aliases: [],
              severity: 'LOW',
              cvss: 2.1,
              isKev: true,
              epss: 0.001,
              effectivePriority: 'track',
              unscored: false,
              severityBucket: 'low',
              vexState: 'exploitable',
              vexJustification: null,
              vexResponse: null,
              vexDetail: null,
              vexSource: 'manual',
              vexUpdatedBy: 'jane',
              vexUpdatedAt: '2026-01-01T00:00:00Z',
              reachability: 'unknown',
              confidence: null,
              sarifSuppressed: false,
              securitySeverity: null,
              severityOrigin: null,
              inherited: false,
              policyViolations: [],
            },
          ],
        },
        {
          componentId: 'c2',
          purl: null,
          purlKey: null,
          name: 'b',
          version: null,
          ecosystem: null,
          componentType: null,
          sbomScope: null,
          dependencyScope: 'unknown',
          isProd: false,
          dependencyKind: null,
          dependencyPath: null,
          licenseSpdx: null,
          description: null,
          author: null,
          copyright: null,
          group: null,
          websiteUrl: null,
          vcsUrl: null,
          issueTrackerUrl: null,
          distributionUrl: null,
          hashes: null,
          versionRange: null,
          isExternal: null,
          metadataSource: null,
          inRegistry: false,
          registryLink: null,
          registry: null,
          policyViolations: [],
          advisories: [],
        },
      ],
      orphanAnalysis: [
        {
          purlKey: 'orphan1',
          vulnKey: 'vOrphan',
          vexState: 'resolved',
          vexJustification: null,
          vexResponse: null,
          vexDetail: null,
          vexSource: 'manual',
          vexUpdatedBy: null,
          vexUpdatedAt: null,
          reachability: null,
          confidence: null,
          sarifSuppressed: false,
          securitySeverity: null,
          severityOrigin: null,
          inherited: false,
        },
      ],
    };

    deepStrictEqual(compactAnalysis(fixture), {
      rollup: { componentTotal: 2 },
      page: 1,
      limit: 50,
      total: 2,
      items: [
        {
          componentId: 'c1',
          purl: 'pkg:npm/a@1.0.0',
          name: 'a',
          version: '1.0.0',
          ecosystem: 'npm',
          dependencyScope: 'runtime',
          isProd: true,
          dependencyKind: 'direct',
          licenseSpdx: 'MIT',
          registry: { presence: 'present', blocked: null, deprecated: null, latestVersion: '1.0.1', outdated: true },
          policyViolations: [{ arm: 'license', detail: 'blocked license' }],
          advisories: [
            {
              vulnKey: 'v1',
              osvId: 'GHSA-1',
              severityBucket: 'high',
              cvss: 7.5,
              isKev: false,
              effectivePriority: 'act',
              vexState: null,
              reachability: 'reachable',
            },
            {
              vulnKey: 'v2',
              osvId: 'GHSA-2',
              severityBucket: 'low',
              cvss: 2.1,
              isKev: true,
              effectivePriority: 'track',
              vexState: 'exploitable',
              reachability: 'unknown',
            },
          ],
        },
        {
          componentId: 'c2',
          purl: null,
          name: 'b',
          version: null,
          ecosystem: null,
          dependencyScope: 'unknown',
          isProd: false,
          dependencyKind: null,
          licenseSpdx: null,
          registry: null,
          policyViolations: [],
          advisories: [],
        },
      ],
      orphanAnalysisCount: 1,
    });
  });

  it('get_project_version returns the fixture unchanged when verbosity is full', async () => {
    const stub = {
      rollup: {},
      page: 1,
      limit: 50,
      total: 1,
      items: [{ componentId: 'c1', extra: 'field' }],
      orphanAnalysis: [],
    };
    stubFetch(() => stub);
    const body = payload(await call(base, 'get_project_version', { projectId: 'p1', verbosity: 'full' }));
    deepStrictEqual(body, stub);
  });

  it('get_project_version is compact by default (no verbosity argument): matches compactAnalysis(stub) exactly', async () => {
    const stub = {
      rollup: { componentTotal: 1 },
      page: 1,
      limit: 50,
      total: 1,
      items: [
        {
          componentId: 'c1',
          purl: 'pkg:npm/a@1.0.0',
          name: 'a',
          version: '1.0.0',
          ecosystem: 'npm',
          dependencyScope: 'runtime',
          isProd: true,
          dependencyKind: 'direct',
          licenseSpdx: 'MIT',
          description: 'a description that should be dropped',
          author: 'someone that should be dropped',
          hashes: [{ alg: 'SHA-256', content: 'deadbeef' }],
          registry: null,
          policyViolations: [],
          advisories: [],
        },
      ],
      orphanAnalysis: [{ purlKey: 'orphan1', vulnKey: 'vOrphan' }],
    };
    stubFetch(() => stub);
    // Called with NO verbosity argument at all — proves "compact by default" rather than
    // merely "compact when asked", which a default flip to 'full' would not fail without this.
    const body = payload(await call(base, 'get_project_version', { projectId: 'p1' }));
    deepStrictEqual(body, compactAnalysis(stub));
    strictEqual(body.items[0].description, undefined, 'droppable fields like description must not survive compaction');
    ok(!('author' in body.items[0]), 'droppable fields like author must not survive compaction');
    ok(!('hashes' in body.items[0]), 'droppable fields like hashes must not survive compaction');
    strictEqual(body.orphanAnalysisCount, 1);
  });

  it('get_project_version reports an actionable error rather than a false-clean result on a non-JSON body', async () => {
    // A misrouted proxy or a stale DEPENDABLY_BASE_URL can return an HTML login page with a
    // 200 status; the client decodes a non-JSON content type to a plain string. Feeding that
    // into compactAnalysis would previously produce `{"items":[],"orphanAnalysisCount":0}`
    // with no isError — indistinguishable from a real "nothing vulnerable" answer.
    globalThis.fetch = async () =>
      new Response('<html><body>Please log in</body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
    const res = await call(base, 'get_project_version', { projectId: 'p1' });
    ok(res.isError, 'a non-JSON body must not be reported as a normal (and falsely clean) result');
    ok(res.content[0].text.includes('DEPENDABLY_BASE_URL'), res.content[0].text);
    ok(res.content[0].text.includes('/versions/latest/analysis'), res.content[0].text);
  });

  it('get_project_version reports an actionable error rather than throwing on a 204/empty body', async () => {
    globalThis.fetch = async () => new Response(null, { status: 204 });
    const res = await call(base, 'get_project_version', { projectId: 'p1' });
    ok(res.isError, 'a 204/empty body must not throw or be silently misread');
    ok(!res.content[0].text.includes("Cannot read properties of null"), res.content[0].text);
    ok(res.content[0].text.includes('DEPENDABLY_BASE_URL'), res.content[0].text);
  });

  it('get_project_version rejects an empty projectId and an empty versionId', async () => {
    stubFetch();
    ok((await call(base, 'get_project_version', { projectId: '' })).isError, 'empty projectId must be a schema error');
    ok(
      (await call(base, 'get_project_version', { projectId: 'p1', versionId: '' })).isError,
      'empty versionId must be a schema error',
    );
  });
});

describe('observability tools', () => {
  it('the readiness probe hits the unauthenticated path', async () => {
    const calls = stubFetch();
    await call(base, 'readiness_check');
    deepStrictEqual(calls.map((c) => new URL(c.url).pathname), ['/ready']);
  });

  it('does not expose the host-allowlisted /version and /metrics probes', async () => {
    const { tools } = await withServer(base, (c) => c.listTools());
    const names = tools.map((t) => t.name);
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
    // Each ecosystem validates `package` against its own rules (see the
    // "package validation" describe block below), so this needs one name per
    // ecosystem that actually satisfies its rule rather than one generic `pkg`.
    const validPackage = {
      npm: 'pkg', pypi: 'pkg', nuget: 'pkg', maven: 'group:pkg', rpm: 'pkg', oci: 'pkg', golang: 'example.com/pkg', cargo: 'pkg',
      apk: 'pkg', terraform: 'hashicorp/pkg', hex: 'pkg',
    };
    for (const eco of ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo', 'apk', 'terraform', 'hex']) {
      for (const version of ['1.0.0', undefined]) {
        const install = await call(base, 'get_install_command', { ecosystem: eco, package: validPackage[eco], version });
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

  for (const eco of ['apk', 'terraform']) {
    it(`tells ${eco} publishers there is no hosted endpoint instead of inventing one`, async () => {
      stubFetch();
      const res = await call(base, 'get_publish_command', { ecosystem: eco, artifact_path: './artifact' });
      ok(!res.isError);
      ok(/proxy-only/.test(res.content[0].text), res.content[0].text);
      ok(!res.content[0].text.includes('```'), 'a proxy-only ecosystem must not return a command fence');
    });
  }

  it('publishes hex through the Hex API plane, reading the key without putting it in history', async () => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem: 'hex', artifact_path: './my_lib' });
    ok(!res.isError);
    ok(res.content[0].text.includes('read -rs HEX_API_KEY   #'), res.content[0].text);
    ok(
      res.content[0].text.includes(`cd './my_lib' && HEX_API_KEY="$HEX_API_KEY" HEX_API_URL=https://dep.example.com/hex/api mix hex.publish; unset HEX_API_KEY\n`),
      res.content[0].text,
    );
    ok(!res.content[0].text.includes('HEX_API_KEY=<token>'), 'no token typed into the command line');
    ok(!res.content[0].text.includes('--yes'), 'the user should confirm the publish interactively');
  });
});

describe('setup tools — apk, terraform and hex install shapes', () => {
  // The version lands inside an HCL or Elixir double-quoted string, so the
  // shell-metacharacter cases above do not cover it: quotes and each
  // language's interpolation opener must be rejected too.
  const versionBreakouts = [
    ['terraform', 'hashicorp/aws', '5.0"\n  evil = "x'],
    ['terraform', 'hashicorp/aws', '5.0${file("/etc/passwd")}'],
    ['terraform', 'hashicorp/aws', '5.0%{if true}x%{endif}'],
    ['hex', 'jason', '1.0#{System.cmd("id", [])}'],
    ['hex', 'jason', '1.0", override: true, x: "'],
  ];
  for (const [eco, pkg, version] of versionBreakouts) {
    it(`rejects ${eco} version ${JSON.stringify(version)} that would break out of its string`, async () => {
      stubFetch();
      const res = await call(base, 'get_install_command', { ecosystem: eco, package: pkg, version });
      ok(res.isError, res.content[0].text);
      ok(!res.content[0].text.includes('```'), 'no command fence may be emitted for a rejected version');
    });
  }

  it('pins apk with name=version and points at the /apk/ repository', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'apk', package: 'busybox', version: '1.36.1-r2' });
    const text = res.content[0].text;
    ok(!res.isError, text);
    ok(text.includes('https://dep.example.com/apk/<release>/<repo>'), text);
    ok(text.includes("apk add 'busybox=1.36.1-r2'"), text);
  });

  it('declares a terraform provider in HCL, with a mirror hint on the instance scheme', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', {
      ecosystem: 'terraform',
      package: 'registry.terraform.io/hashicorp/aws',
      version: '5.70.0',
    });
    strictEqual(
      res.content[0].text,
      '```hcl\n' +
        '# In ~/.terraformrc: provider_installation { network_mirror { url = "https://user:<token>@dep.example.com/terraform/" } }\n' +
        '# Then declare the provider and run terraform init:\n' +
        'terraform {\n  required_providers {\n    aws = {\n      source  = "registry.terraform.io/hashicorp/aws"\n      version = "5.70.0"\n    }\n  }\n}\n```',
    );
  });

  it('omits the terraform version constraint when unpinned', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'terraform', package: 'hashicorp/aws' });
    ok(!res.isError);
    ok(!res.content[0].text.includes('version ='), res.content[0].text);
  });

  it('warns that terraform refuses a plain-HTTP mirror', async () => {
    stubFetch();
    const res = await call({ ...base, baseUrl: 'http://dep.example.com' }, 'get_install_command', { ecosystem: 'terraform', package: 'hashicorp/aws' });
    ok(res.content[0].text.includes('url = "http://user:<token>@dep.example.com/terraform/"'), res.content[0].text);
    ok(/refuses an http:\/\/ network mirror/.test(res.content[0].text), res.content[0].text);
  });

  it('writes a hex dependency on the dependably repository, pinned and unpinned', async () => {
    stubFetch();
    const pinnedRes = await call(base, 'get_install_command', { ecosystem: 'hex', package: 'jason', version: '1.4.4' });
    const text = pinnedRes.content[0].text;
    ok(text.startsWith('```elixir\n'), text);
    ok(text.includes('mix hex.repo add dependably https://dep.example.com/hex --public-key dependably-hex.pem --auth-key <token>'), text);
    ok(text.includes('{:jason, "~> 1.4.4", repo: :dependably}'), text);
    const unpinned = await call(base, 'get_install_command', { ecosystem: 'hex', package: 'jason' });
    ok(unpinned.content[0].text.includes('{:jason, ">= 0.0.0", repo: :dependably}'), unpinned.content[0].text);
  });
});

describe('setup tools — command injection hardening', () => {
  const shellMetaCases = [
    ['semicolon', '; rm -rf ~'],
    ['command substitution', '$(rm -rf ~)'],
    ['backtick', '`rm -rf ~`'],
    ['ampersand', '& rm -rf ~'],
    ['pipe', '| rm -rf ~'],
    ['newline', '\nrm -rf ~'],
  ];

  for (const [label, suffix] of shellMetaCases) {
    it(`rejects a ${label} in package and never echoes it`, async () => {
      stubFetch();
      const res = await call(base, 'get_install_command', { ecosystem: 'npm', package: `left-pad${suffix}`, version: '1.0.0' });
      ok(res.isError, res.content[0].text);
      ok(!res.content[0].text.includes('rm -rf'), res.content[0].text);
    });

    it(`rejects a ${label} in version and never echoes it`, async () => {
      stubFetch();
      const res = await call(base, 'get_install_command', { ecosystem: 'npm', package: 'left-pad', version: `1.0.0${suffix}` });
      ok(res.isError, res.content[0].text);
      ok(!res.content[0].text.includes('rm -rf'), res.content[0].text);
    });

    it(`rejects a ${label} in artifact_path and never echoes it`, async () => {
      stubFetch();
      const res = await call(base, 'get_publish_command', { ecosystem: 'rpm', artifact_path: `a.rpm${suffix}` });
      ok(res.isError, res.content[0].text);
      ok(!res.content[0].text.includes('rm -rf'), res.content[0].text);
    });
  }

  it('rejects a leading - in package, version and artifact_path', async () => {
    stubFetch();
    const pkgRes = await call(base, 'get_install_command', { ecosystem: 'npm', package: '-rf', version: '1.0.0' });
    const verRes = await call(base, 'get_install_command', { ecosystem: 'npm', package: 'left-pad', version: '-rf' });
    const artifactRes = await call(base, 'get_publish_command', { ecosystem: 'rpm', artifact_path: '-rf' });
    ok(pkgRes.isError, pkgRes.content[0].text);
    ok(verRes.isError, verRes.content[0].text);
    ok(artifactRes.isError, artifactRes.content[0].text);
  });

  it('produces the exact command for a scoped npm name and pinned version', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'npm', package: '@scope/name', version: '1.2.3' });
    strictEqual(
      res.content[0].text,
      "```bash\nnpm install --registry=https://dep.example.com/npm/ '@scope/name@1.2.3'\n```",
    );
  });

  it('produces the exact command for an oci name and pinned version', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'oci', package: 'library/nginx', version: '1.27' });
    strictEqual(
      res.content[0].text,
      "```bash\n# docker login dep.example.com first\ndocker pull dep.example.com/'library/nginx':'1.27'\n```",
    );
  });
});

describe('setup tools — maven artifact coordinate', () => {
  it('pins :LATEST and warns when no version is given', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'maven', package: 'org.slf4j:slf4j-api' });
    strictEqual(
      res.content[0].text,
      "```bash\n# Add https://dep.example.com/maven/ as a <repository> in your pom.xml or settings.xml, then:\n" +
        "mvn dependency:get -Dartifact='org.slf4j:slf4j-api:LATEST'\n# pin a version in production\n```",
    );
  });

  it('uses the pinned version verbatim when one is given', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'maven', package: 'org.slf4j:slf4j-api', version: '2.0.9' });
    strictEqual(
      res.content[0].text,
      "```bash\n# Add https://dep.example.com/maven/ as a <repository> in your pom.xml or settings.xml, then:\n" +
        "mvn dependency:get -Dartifact='org.slf4j:slf4j-api:2.0.9'\n```",
    );
  });
});

describe('setup tools — cargo config hint', () => {
  it('emits valid TOML for the registry config, split across comment lines', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'cargo', package: 'serde', version: '1.0.0' });
    strictEqual(
      res.content[0].text,
      '```bash\n# In ~/.cargo/config.toml:\n#   [registries.dependably]\n#   index = "sparse+https://dep.example.com/cargo/"\n' +
        "cargo add 'serde@1.0.0' --registry dependably\n```",
    );
  });
});

describe('setup tools — credential prerequisites', () => {
  it('tells pypi installers to put their token in ~/.netrc, since --index-url would override pip.conf', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'pypi', package: 'requests', version: '2.31.0' });
    ok(res.content[0].text.includes('# Put your token in ~/.netrc for dep.example.com (machine dep.example.com login user password <token>) first'), res.content[0].text);
    ok(!res.content[0].text.includes('pip.conf'), res.content[0].text);
    ok(res.content[0].text.includes('--index-url https://dep.example.com/simple/'), res.content[0].text);
  });

  it('tells nuget installers to add the authenticated source first', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'nuget', package: 'Newtonsoft.Json', version: '13.0.3' });
    ok(res.content[0].text.includes('# dotnet nuget add source https://dep.example.com/nuget/v3/index.json --name dependably --username user --password <token> first'), res.content[0].text);
  });

  it('tells oci installers to docker login first', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'oci', package: 'nginx', version: 'latest' });
    ok(res.content[0].text.includes('# docker login dep.example.com first'), res.content[0].text);
  });

  it('tells golang installers to configure netrc, and never falls back around the proxy', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'golang', package: 'github.com/foo/bar', version: 'v1.2.3' });
    ok(res.content[0].text.includes('(machine dep.example.com login user password <token>)'), res.content[0].text);
    ok(res.content[0].text.includes('GOPROXY=https://dep.example.com/go go get'), res.content[0].text);
    ok(!res.content[0].text.includes(',direct'), 'a ,direct fallback would fetch refused modules around the proxy');
    ok(!res.content[0].text.includes('GONOSUMDB'), 'GONOSUMDB takes module paths, not a host; the sumdb is proxied');
  });
});

describe('setup tools — publish commands keep tokens out of history and name real inputs', () => {
  const text = async (ecosystem, artifact_path) => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem, artifact_path });
    ok(!res.isError, res.content[0].text);
    return res.content[0].text;
  };

  it('never types a token into a command line', async () => {
    for (const eco of ['pypi', 'nuget', 'rpm', 'hex', 'maven', 'npm', 'cargo', 'oci']) {
      const t = await text(eco, eco === 'cargo' || eco === 'hex' ? './crate' : './dist/a.bin');
      const commandLines = t.split('\n').filter((l) => !l.startsWith('#') && !l.startsWith('```'));
      for (const line of commandLines) ok(!line.includes('<token>'), `${eco}: ${line}`);
    }
  });

  it('pypi reads the password into TWINE_PASSWORD', async () => {
    const t = await text('pypi', './dist/pkg-1.0.0.tar.gz');
    ok(t.includes('read -rs TWINE_PASSWORD   #'), t);
    ok(t.includes(`TWINE_PASSWORD="$TWINE_PASSWORD" TWINE_USERNAME=user twine upload --repository-url https://dep.example.com/pypi/legacy/ './dist/pkg-1.0.0.tar.gz'; unset TWINE_PASSWORD`), t);
  });

  it('nuget reads the key, passes it to the one push, and unsets it', async () => {
    const t = await text('nuget', './bin/Pkg.1.0.0.nupkg');
    ok(t.includes('read -rs NUGET_API_KEY   #'), t);
    ok(t.includes(`dotnet nuget push './bin/Pkg.1.0.0.nupkg' --source https://dep.example.com/nuget/v3/index.json --api-key "$NUGET_API_KEY"; unset NUGET_API_KEY`), t);
  });

  it('no publish command exports a secret, and every secret it reads is unset', async () => {
    for (const eco of ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'cargo', 'hex']) {
      const t = await text(eco, eco === 'cargo' || eco === 'hex' ? './crate' : './dist/a.bin');
      ok(!/\bexport\b/.test(t), `${eco}: ${t}`);
      for (const [, v] of t.matchAll(/read -rs (\w+)/g)) ok(t.includes(`; unset ${v}`), `${eco}: ${v} is not unset`);
    }
  });

  it('rpm lets curl prompt for the password', async () => {
    const t = await text('rpm', './out.rpm');
    ok(t.includes("curl -u user --upload-file './out.rpm' https://dep.example.com/rpm/upload"), t);
  });

  it('oci loads the image tarball rather than tagging a file path', async () => {
    const t = await text('oci', './image.tar');
    ok(t.includes("docker load -i './image.tar'"), t);
    ok(!t.includes("docker tag './image.tar'"), t);
  });

  it('maven uploads the named file with deploy:deploy-file', async () => {
    const t = await text('maven', './target/app-1.0.jar');
    ok(t.includes("mvn deploy:deploy-file -Dfile='./target/app-1.0.jar' -Durl=https://dep.example.com/maven/ -DrepositoryId=dependably"), t);
  });

  it('cargo publishes from the crate directory, given the directory or its Cargo.toml', async () => {
    ok((await text('cargo', './my-crate')).includes("--manifest-path './my-crate/Cargo.toml'"));
    ok((await text('cargo', './my-crate/')).includes("--manifest-path './my-crate/Cargo.toml'"));
    ok((await text('cargo', './my-crate/Cargo.toml')).includes("--manifest-path './my-crate/Cargo.toml'"));
    const crate = await text('cargo', 'target/package/foo-1.0.0.crate');
    ok(crate.includes('not a packaged .crate') && !crate.includes('--manifest-path'), crate);
    ok((await text('cargo', 'Cargo.toml')).includes("--manifest-path './Cargo.toml'"));
    ok((await text('cargo', '/Cargo.toml')).includes("--manifest-path '/Cargo.toml'"));
  });

  it('a directory name with a dot is the directory, not a file in its parent', async () => {
    // cargo package leaves the unpacked crate in target/package/<name>-<version>.
    const t = await text('cargo', './target/package/foo-0.1.0');
    ok(t.includes("--manifest-path './target/package/foo-0.1.0/Cargo.toml'"), t);
    ok((await text('cargo', './my.crate.dir/')).includes("--manifest-path './my.crate.dir/Cargo.toml'"));
    ok((await text('hex', './vendor/my_lib-1.2')).includes("cd './vendor/my_lib-1.2' && "));
    ok((await text('hex', './vendor/my_lib-1.2/mix.exs')).includes("cd './vendor/my_lib-1.2' && "));
    ok((await text('hex', 'mix.exs')).includes("cd '.' && "));
  });
});

describe('readiness_check on a 503', () => {
  it('returns the readiness body as the answer, not a generic server error', async () => {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ status: 'unready', strict: false, checks: { db: 'fail', blob_store: 'ok' }, required: ['db'], degraded: ['db'] }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    const res = await call(base, 'readiness_check');
    ok(!res.isError, res.content[0].text);
    match(res.content[0].text, /answered 503: it is not ready/);
    match(res.content[0].text, /"status":"unready"/);
    match(res.content[0].text, /"degraded":\["db"\]/);
  });

  it('still reports a 503 without a readable body as an error', async () => {
    globalThis.fetch = async () => new Response('<html>bad gateway</html>', { status: 503, headers: { 'content-type': 'text/html' } });
    const res = await call(base, 'readiness_check');
    ok(res.isError);
  });
});

describe('setup tools — netrc and artefact path hygiene', () => {
  const ported = { baseUrl: 'https://dep.example.com:8443', token: 'tok', timeoutMs: 5000 };

  it('names the hostname without the port in pip\'s netrc line, since requests matches on hostname', async () => {
    stubFetch();
    const t = (await call(ported, 'get_install_command', { ecosystem: 'pypi', package: 'requests', version: '1.0.0' })).content[0].text;
    ok(t.includes('machine dep.example.com login'), t);
    ok(!t.includes('machine dep.example.com:8443'), t);
  });

  it('passes credentials in the index URL userinfo for an IPv6 host with a port, not a netrc line', async () => {
    stubFetch();
    const v6 = { baseUrl: 'http://[::1]:8443', token: 'tok', timeoutMs: 5000 };
    const t = (await call(v6, 'get_install_command', { ecosystem: 'pypi', package: 'requests', version: '1.0.0' })).content[0].text;
    ok(!t.includes('machine'), t);
    ok(t.includes('read -rs PIP_TOKEN'), t);
    ok(t.includes('PIP_INDEX_URL="http://user:${PIP_TOKEN}@[::1]:8443/simple/" pip install \'requests==1.0.0\'; unset PIP_TOKEN'), t);
    ok(!t.includes('export PIP_TOKEN') && !t.includes('--index-url'), 'the token stays out of the environment and argv');
    ok(!t.includes('user:tok'), t);
  });

  it('passes credentials in the index URL userinfo for an IPv6 host without a port', async () => {
    stubFetch();
    const v6 = { baseUrl: 'https://[2001:db8::1]', token: 'tok', timeoutMs: 5000 };
    const t = (await call(v6, 'get_install_command', { ecosystem: 'pypi', package: 'requests' })).content[0].text;
    ok(!t.includes('machine'), t);
    ok(t.includes('PIP_INDEX_URL="https://user:${PIP_TOKEN}@[2001:db8::1]/simple/" pip install'), t);
  });

  it('leaves the pip output for a DNS host byte-identical', async () => {
    stubFetch();
    const t = (await call(ported, 'get_install_command', { ecosystem: 'pypi', package: 'requests', version: '1.0.0' })).content[0].text;
    ok(t.includes("# Put your token in ~/.netrc for dep.example.com (machine dep.example.com login user password <token>) first\npip install --index-url https://dep.example.com:8443/simple/ 'requests==1.0.0'"), t);
  });

  it('keeps the port in Go\'s netrc line, since Go matches netrc on host:port', async () => {
    stubFetch();
    const t = (await call(ported, 'get_install_command', { ecosystem: 'golang', package: 'github.com/foo/bar', version: 'v1.0.0' })).content[0].text;
    ok(t.includes('machine dep.example.com:8443 login'), t);
  });

  it('refuses control characters in an artefact path', async () => {
    stubFetch();
    for (const bad of ['./a\rb.tgz', './a\tb.tgz', './a\x1bb.tgz', './a\x7fb.tgz', './a\x00b.tgz']) {
      const res = await call(base, 'get_publish_command', { ecosystem: 'npm', artifact_path: bad });
      ok(res.isError, JSON.stringify(bad));
    }
  });
});

describe('setup tools — path-prefixed base URL', () => {
  const prefixed = { baseUrl: 'https://host.example.com/dependably', token: 'tok', timeoutMs: 5000 };

  it('warns about OCI and a URL path prefix when the base URL has one', async () => {
    stubFetch();
    const res = await call(prefixed, 'get_install_command', { ecosystem: 'oci', package: 'library/nginx', version: '1.27' });
    ok(res.content[0].text.includes('# Note: OCI registries cannot live under a URL path; use the instance host directly'), res.content[0].text);
  });

  it('omits the warning when the base URL has no path component', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'oci', package: 'library/nginx', version: '1.27' });
    ok(!res.content[0].text.includes('cannot live under a URL path'), res.content[0].text);
  });

  it('keeps host-only destinations bare even when the base URL carries a path prefix', async () => {
    stubFetch();
    const oci = await call(prefixed, 'get_install_command', { ecosystem: 'oci', package: 'library/nginx', version: '1.27' });
    ok(oci.content[0].text.includes('# docker login host.example.com first'), oci.content[0].text);
    ok(!oci.content[0].text.includes('docker login host.example.com/dependably'), oci.content[0].text);

    const ociPublish = await call(prefixed, 'get_publish_command', { ecosystem: 'oci', artifact_path: './image.tar' });
    ok(ociPublish.content[0].text.includes('docker login host.example.com\n'), ociPublish.content[0].text);
    ok(!ociPublish.content[0].text.includes('docker login host.example.com/dependably'), ociPublish.content[0].text);

    const golang = await call(prefixed, 'get_install_command', { ecosystem: 'golang', package: 'github.com/foo/bar', version: 'v1.2.3' });
    ok(golang.content[0].text.includes('(machine host.example.com login user password <token>)'), golang.content[0].text);
    // GOPROXY is a URL, not a bare host, so it keeps the path prefix.
    ok(golang.content[0].text.includes('GOPROXY=https://host.example.com/dependably/go go get'), golang.content[0].text);

    const pypi = await call(prefixed, 'get_install_command', { ecosystem: 'pypi', package: 'requests', version: '2.31.0' });
    ok(pypi.content[0].text.includes('# Put your token in ~/.netrc for host.example.com (machine host.example.com login user password <token>) first'), pypi.content[0].text);
    // --index-url is a URL, not a bare host, so it keeps the path prefix.
    ok(pypi.content[0].text.includes('--index-url https://host.example.com/dependably/simple/'), pypi.content[0].text);
  });
});

describe('setup tools — per-ecosystem package validation', () => {
  const maliciousCases = [
    ['npm', 'https://evil.tld/x.tgz', 'a bare URL instead of a registry-resolved name'],
    ['npm', 'github:evil/pwn', 'npm git shorthand, which resolves outside --registry'],
    ['npm', '../../tmp/evil', 'a local path traversal'],
    ['npm', '@Scope/name', 'an upper-case scope, which npm never issued'],
    ['pypi', 'https://evil.tld/x.whl', 'a bare URL instead of a PEP 508 name'],
    ['rpm', 'https://evil.tld/x.rpm', 'a bare URL instead of an rpm name'],
    ['oci', '../evil', 'a .. path segment'],
    ['golang', 'evil.tld/../x', 'a .. path segment in a module path'],
    ['maven', 'org.slf4j/slf4j-api', 'a / where a Maven coordinate needs exactly one :'],
    ['apk', 'https://evil.tld/x.apk', 'a bare URL instead of an apk name'],
    ['apk', 'busybox=1.0', 'an embedded = pin, which belongs in version'],
    ['apk', '-X', 'a leading - read as an apk flag'],
    ['terraform', 'aws', 'a bare type with no namespace'],
    ['terraform', 'https://evil.tld/hashicorp/aws', 'a scheme in the source address'],
    ['terraform', 'hashicorp/aws"\n  evil = "x', 'a quote that would break out of the HCL string'],
    ['terraform', 'a/b/c/d', 'more than three segments'],
    ['terraform', 'evil.tld/../aws', 'a .. segment'],
    ['terraform', 'evil..tld/acme/widget', 'an empty hostname label'],
    ['terraform', 'acme/my_provider', 'an underscore, which Terraform addresses never carry'],
    ['terraform', 'acme/-widget', 'a leading dash in the type'],
    ['hex', 'jason, override: true', 'Mix options injected after the atom'],
    ['hex', 'Jason', 'an upper-case name, which is not a plain atom'],
    ['hex', '"jason"', 'a quoted atom'],
    ['hex', '_jason', 'a leading underscore'],
  ];

  for (const [eco, pkg, why] of maliciousCases) {
    it(`rejects ${eco} package ${JSON.stringify(pkg)} (${why})`, async () => {
      stubFetch();
      const res = await call(base, 'get_install_command', { ecosystem: eco, package: pkg, version: '1.0.0' });
      ok(res.isError, res.content[0].text);
    });
  }

  const legitCases = [
    ['npm', '@scope/name', "npm install --registry=https://dep.example.com/npm/ '@scope/name@1.2.3'"],
    ['npm', 'JSONStream', "npm install --registry=https://dep.example.com/npm/ 'JSONStream@1.2.3'"],
    ['pypi', 'zope.interface', "pip install --index-url https://dep.example.com/simple/ 'zope.interface==1.2.3'"],
    ['nuget', 'Microsoft.Extensions.Logging', "dotnet add package 'Microsoft.Extensions.Logging' --version '1.2.3' --source https://dep.example.com/nuget/v3/index.json"],
    ['maven', 'org.slf4j:slf4j-api', "mvn dependency:get -Dartifact='org.slf4j:slf4j-api:1.2.3'"],
    ['golang', 'github.com/org/repo/v2', "go get 'github.com/org/repo/v2'@'1.2.3'"],
    ['cargo', 'serde_json', "cargo add 'serde_json@1.2.3' --registry dependably"],
    ['rpm', 'kernel-devel', "dnf install 'kernel-devel-1.2.3'"],
    ['oci', 'library/nginx', "docker pull dep.example.com/'library/nginx':'1.2.3'"],
    ['apk', 'py3-setuptools', "apk add 'py3-setuptools=1.2.3'"],
    ['apk', 'libstdc++', "apk add 'libstdc++=1.2.3'"],
    ['terraform', 'hashicorp/google-beta', '    google-beta = {\n      source  = "hashicorp/google-beta"'],
    ['terraform', 'localhost:8443/acme/widget', 'source  = "localhost:8443/acme/widget"'],
    ['hex', 'phoenix_live_view', '{:phoenix_live_view, "~> 1.2.3", repo: :dependably}'],
  ];

  for (const [eco, pkg, expectedSubstring] of legitCases) {
    it(`accepts the legitimate ${eco} package name ${JSON.stringify(pkg)}`, async () => {
      stubFetch();
      const res = await call(base, 'get_install_command', { ecosystem: eco, package: pkg, version: '1.2.3' });
      ok(!res.isError, res.content[0].text);
      ok(res.content[0].text.includes(expectedSubstring), res.content[0].text);
    });
  }
});

describe('setup tools — artifact path globs and spaces', () => {
  it('rejects a shell glob rather than single-quoting it into a no-op', async () => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem: 'npm', artifact_path: './dist/*.tgz' });
    ok(res.isError, res.content[0].text);
  });

  it('accepts and quotes one concrete artefact file', async () => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem: 'npm', artifact_path: './dist/package.tgz' });
    ok(!res.isError, res.content[0].text);
    ok(res.content[0].text.includes("'./dist/package.tgz'"), res.content[0].text);
  });

  it('accepts a path with spaces, quoted as one shell word', async () => {
    stubFetch();
    const res = await call(base, 'get_publish_command', { ecosystem: 'rpm', artifact_path: '/Users/me/My Builds/out.rpm' });
    ok(!res.isError, res.content[0].text);
    ok(res.content[0].text.includes("'/Users/me/My Builds/out.rpm'"), res.content[0].text);
  });

  it('describes artifact_path in Canadian English prose, keeping the identifier as-is', async () => {
    const { tools } = await withServer(base, (c) => c.listTools());
    const publish = tools.find((t) => t.name === 'get_publish_command');
    ok('artifact_path' in publish.inputSchema.properties, 'the field identifier stays artifact_path');
    ok(publish.inputSchema.properties.artifact_path.description.includes('artefact'), publish.inputSchema.properties.artifact_path.description);
  });
});

describe('setup tools — empty version means unpinned', () => {
  it('treats an empty string version the same as omitting it', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'npm', package: 'left-pad', version: '' });
    ok(!res.isError, res.content[0].text);
    strictEqual(res.content[0].text, "```bash\nnpm install --registry=https://dep.example.com/npm/ 'left-pad'\n```");
  });

  it('treats a whitespace-only version the same as omitting it', async () => {
    stubFetch();
    const res = await call(base, 'get_install_command', { ecosystem: 'npm', package: 'left-pad', version: '   ' });
    ok(!res.isError, res.content[0].text);
    strictEqual(res.content[0].text, "```bash\nnpm install --registry=https://dep.example.com/npm/ 'left-pad'\n```");
  });
});

describe('local file surface', () => {
  it('registers no tool that reads local files', async () => {
    const names = (await withServer(base, (c) => c.listTools())).tools.map((t) => t.name);
    ok(!names.includes('admin_upload'));
    ok(!names.includes('import_manifest'));
  });
});
