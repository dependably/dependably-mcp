import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { describe, it } from 'node:test';

import {
  buildFindings,
  compactReportItem,
  fetchRemediations,
  fetchReport,
  mapLimit,
  matchPackages,
  parseNpmLockfile,
  summarize,
  summarizeRemediation,
} from '../dist/vuln.js';

/** A client stub that records calls and replays canned responses. */
function stubClient(handler) {
  const calls = [];
  return {
    calls,
    async get(path, query) {
      calls.push({ path, query });
      return handler(path, query, calls.length);
    },
  };
}

function reportItem(over = {}) {
  return {
    packageName: 'hono',
    version: '4.12.27',
    osvId: 'GHSA-aaaa',
    severity: 'MEDIUM',
    cvssScore: 5.3,
    epssScore: 0.004,
    isKev: false,
    summary: 'something',
    ecosystem: 'npm',
    purl: 'pkg:npm/hono@4.12.27',
    orgSlug: 'default',
    revokedAt: null,
    firstSeenAt: '2026-09-03T05:34:51Z',
    vulnCheckedAt: '2026-09-14T04:09:34Z',
    ...over,
  };
}

describe('fetchReport', () => {
  it('pages until it has collected total', async () => {
    const client = stubClient((_p, q) => {
      const page = q.page;
      if (page === 1) return { items: [reportItem({ osvId: 'A' }), reportItem({ osvId: 'B' })], total: 3 };
      return { items: [reportItem({ osvId: 'C' })], total: 3 };
    });
    const { items, total, truncated } = await fetchReport(client, { ecosystem: 'npm' });
    strictEqual(items.length, 3);
    strictEqual(total, 3);
    strictEqual(truncated, false);
    strictEqual(client.calls.length, 2);
    strictEqual(client.calls[0].query.ecosystem, 'npm');
  });

  it('stops on an empty page even if total overstates the rows available', async () => {
    const client = stubClient((_p, q) => (q.page === 1 ? { items: [reportItem()], total: 99 } : { items: [], total: 99 }));
    const { items } = await fetchReport(client);
    strictEqual(items.length, 1);
    strictEqual(client.calls.length, 2);
  });

  it('flags truncation rather than paging forever', async () => {
    const client = stubClient(() => ({ items: [reportItem(), reportItem()], total: 1000 }));
    const { truncated, items } = await fetchReport(client, { pageSize: 2, maxItems: 4 });
    strictEqual(truncated, true);
    ok(items.length >= 4);
  });

  it('treats a null response as an empty report', async () => {
    const client = stubClient(() => null);
    const { items, total } = await fetchReport(client);
    deepStrictEqual(items, []);
    strictEqual(total, 0);
  });

  it('falls back to batch length when the server omits total', async () => {
    const client = stubClient((_p, q) => (q.page === 1 ? { items: [reportItem()] } : { items: [] }));
    const { total } = await fetchReport(client);
    strictEqual(total, 1);
  });
});

describe('matchPackages', () => {
  const report = [
    reportItem({ packageName: 'hono', version: '4.12.27' }),
    reportItem({ packageName: 'hono', version: '4.13.0' }),
    reportItem({ packageName: 'left-pad', version: '1.0.0' }),
  ];

  it('matches on exact name@version only', () => {
    const { hits } = matchPackages(report, [{ name: 'hono', version: '4.12.27' }]);
    strictEqual(hits.length, 1);
    strictEqual(hits[0].version, '4.12.27');
  });

  it('returns nothing when no installed version matches', () => {
    const { hits } = matchPackages(report, [{ name: 'hono', version: '4.13.7' }]);
    deepStrictEqual(hits, []);
  });

  it('records the dev flag, defaulting to runtime', () => {
    const { devOf } = matchPackages(report, [
      { name: 'hono', version: '4.12.27', dev: true },
      { name: 'left-pad', version: '1.0.0' },
    ]);
    strictEqual(devOf.get('hono@4.12.27'), true);
    strictEqual(devOf.get('left-pad@1.0.0'), false);
  });

  it('classifies a package as runtime when any occurrence is runtime', () => {
    // A package hoisted into both trees ships, so the stricter tier wins.
    const { devOf } = matchPackages(report, [
      { name: 'hono', version: '4.12.27', dev: true },
      { name: 'hono', version: '4.12.27', dev: false },
    ]);
    strictEqual(devOf.get('hono@4.12.27'), false);
  });
});

describe('mapLimit', () => {
  it('preserves input order in the results', async () => {
    const out = await mapLimit([5, 1, 3], 2, async (n) => {
      await new Promise((r) => setTimeout(r, n));
      return n * 2;
    });
    deepStrictEqual(out, [10, 2, 6]);
  });

  it('never exceeds the concurrency limit', async () => {
    let inFlight = 0;
    let peak = 0;
    await mapLimit([1, 2, 3, 4, 5, 6], 2, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
    });
    ok(peak <= 2, `peak concurrency was ${peak}`);
  });

  it('handles an empty input', async () => {
    deepStrictEqual(await mapLimit([], 4, async () => 1), []);
  });
});

describe('summarizeRemediation', () => {
  it('extracts the fixed version, cwes, owasp ids and skill ids', () => {
    const r = summarizeRemediation({
      summary: 'a summary',
      databaseSpecific: { severity: 'HIGH' },
      remediation: {
        fixedVersion: '10.3.1',
        cweIds: ['CWE-20', 'CWE-918'],
        entries: [
          { cweId: 'CWE-20', owaspId: 'A05:2025', skillId: 'fix-injection' },
          { cweId: 'CWE-918', owaspId: 'A01:2025', skillId: 'fix-ssrf' },
        ],
      },
    });
    strictEqual(r.fixedVersion, '10.3.1');
    deepStrictEqual(r.cwes, ['CWE-20', 'CWE-918']);
    deepStrictEqual(r.owasp, ['A05:2025', 'A01:2025']);
    deepStrictEqual(r.skills, ['fix-injection', 'fix-ssrf']);
    strictEqual(r.severity, 'HIGH');
    strictEqual(r.summary, 'a summary');
  });

  it('de-duplicates owasp and skill ids', () => {
    const r = summarizeRemediation({
      remediation: {
        entries: [
          { owaspId: 'A01:2025', skillId: 'fix-ssrf' },
          { owaspId: 'A01:2025', skillId: 'fix-ssrf' },
        ],
      },
    });
    deepStrictEqual(r.owasp, ['A01:2025']);
    deepStrictEqual(r.skills, ['fix-ssrf']);
  });

  it('drops null entries rather than emitting them as ids', () => {
    const r = summarizeRemediation({ remediation: { entries: [{ owaspId: null, skillId: null }] } });
    deepStrictEqual(r.owasp, []);
    deepStrictEqual(r.skills, []);
  });

  it('returns nulls and empties for a missing or empty advisory', () => {
    for (const input of [null, {}, { remediation: {} }, { remediation: { fixedVersion: '' } }]) {
      const r = summarizeRemediation(input);
      strictEqual(r.fixedVersion, null);
      deepStrictEqual(r.cwes, []);
    }
  });
});

describe('fetchRemediations', () => {
  it('asks once per distinct advisory+version pair and passes the version through', async () => {
    const client = stubClient((path, q) => ({
      remediation: { fixedVersion: `${path.split('/').pop()}-${q.version}` },
    }));
    const map = await fetchRemediations(client, [
      { osvId: 'A', version: '1.0.0' },
      { osvId: 'A', version: '1.0.0' },
      { osvId: 'A', version: '2.0.0' },
    ]);
    strictEqual(client.calls.length, 2, 'the duplicate pair must be collapsed');
    strictEqual(map.get('A@@1.0.0').fixedVersion, 'A-1.0.0');
    strictEqual(map.get('A@@2.0.0').fixedVersion, 'A-2.0.0');
  });

  it('url-encodes the advisory id', async () => {
    const client = stubClient(() => ({}));
    await fetchRemediations(client, [{ osvId: 'GHSA a/b', version: '1' }]);
    ok(client.calls[0].path.includes('GHSA%20a%2Fb'));
  });

  it('degrades a failed lookup to a null fixed version instead of sinking the scan', async () => {
    const client = stubClient((path) => {
      if (path.endsWith('BAD')) throw new Error('404');
      return { remediation: { fixedVersion: '1.2.3' } };
    });
    const map = await fetchRemediations(client, [
      { osvId: 'BAD', version: '1' },
      { osvId: 'GOOD', version: '1' },
    ]);
    strictEqual(map.get('BAD@@1').fixedVersion, null);
    strictEqual(map.get('GOOD@@1').fixedVersion, '1.2.3');
  });

  it('handles an advisory with no version', async () => {
    const client = stubClient(() => ({ remediation: { fixedVersion: '9.9.9' } }));
    const map = await fetchRemediations(client, [{ osvId: 'A' }]);
    strictEqual(map.get('A@@').fixedVersion, '9.9.9');
  });
});

describe('buildFindings', () => {
  const rem = (fixedVersion, over = {}) => ({ fixedVersion, cwes: [], owasp: [], skills: [], ...over });

  it('groups advisories under one package and takes the highest fix as the bump target', () => {
    const hits = [
      reportItem({ packageName: 'fast-uri', version: '3.1.3', osvId: 'A', severity: 'HIGH', cvssScore: 7.5 }),
      reportItem({ packageName: 'fast-uri', version: '3.1.3', osvId: 'B', severity: 'HIGH', cvssScore: 7.5 }),
    ];
    const [finding] = buildFindings(
      hits,
      new Map([['fast-uri@3.1.3', false]]),
      new Map([
        ['A@@3.1.3', rem('3.1.4')],
        ['B@@3.1.3', rem('3.1.6')],
      ]),
    );
    strictEqual(finding.bumpTo, '3.1.6', 'the lowest fix would leave the follow-up advisory open');
    strictEqual(finding.advisories.length, 2);
    strictEqual(finding.dev, false);
  });

  it('suggests no bump when the installed version already clears every fix', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'x', version: '2.0.0', osvId: 'C' })],
      new Map([['x@2.0.0', true]]),
      new Map([['C@@2.0.0', rem('1.9.0')]]),
    );
    strictEqual(finding.bumpTo, null);
    strictEqual(finding.dev, true);
  });

  it('suggests no bump when no advisory carries a fixed version', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'x', version: '1.0.0', osvId: 'C' })],
      new Map([['x@1.0.0', false]]),
      new Map([['C@@1.0.0', rem(null)]]),
    );
    strictEqual(finding.bumpTo, null);
    strictEqual(finding.advisories[0].fixedVersion, null);
  });

  it('sorts advisories by severity then cvss, and packages by worst advisory', () => {
    const hits = [
      reportItem({ packageName: 'low-pkg', version: '1.0.0', osvId: 'L', severity: 'LOW', cvssScore: 2 }),
      reportItem({ packageName: 'bad-pkg', version: '1.0.0', osvId: 'M', severity: 'MEDIUM', cvssScore: 5 }),
      reportItem({ packageName: 'bad-pkg', version: '1.0.0', osvId: 'H', severity: 'HIGH', cvssScore: 9 }),
    ];
    const findings = buildFindings(
      hits,
      new Map([
        ['low-pkg@1.0.0', false],
        ['bad-pkg@1.0.0', false],
      ]),
      new Map(),
    );
    strictEqual(findings[0].package, 'bad-pkg');
    strictEqual(findings[0].advisories[0].osvId, 'H');
    strictEqual(findings[1].package, 'low-pkg');
  });

  it('normalizes MODERATE to MEDIUM so severities are one vocabulary', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'x', version: '1.0.0', osvId: 'A', severity: 'MODERATE' })],
      new Map([['x@1.0.0', false]]),
      new Map(),
    );
    strictEqual(finding.advisories[0].severity, 'MEDIUM');
  });

  it('carries cwe/owasp/skill detail through only when present', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'x', version: '1.0.0', osvId: 'A' })],
      new Map([['x@1.0.0', false]]),
      new Map([['A@@1.0.0', rem('2.0.0', { cwes: ['CWE-20'], owasp: ['A01:2025'], skills: ['fix-ssrf'] })]]),
    );
    deepStrictEqual(finding.advisories[0].cwes, ['CWE-20']);
    deepStrictEqual(finding.advisories[0].owasp, ['A01:2025']);
    deepStrictEqual(finding.advisories[0].skills, ['fix-ssrf']);
  });

  it('defaults missing scores and flags rather than emitting undefined', () => {
    const [finding] = buildFindings(
      [{ packageName: 'x', version: '1.0.0', osvId: 'A' }],
      new Map([['x@1.0.0', false]]),
      new Map(),
    );
    const advisory = finding.advisories[0];
    strictEqual(advisory.cvss, null);
    strictEqual(advisory.epss, null);
    strictEqual(advisory.kev, false);
    strictEqual(advisory.summary, '');
    strictEqual(advisory.severity, 'UNKNOWN');
  });

  it('returns nothing for no hits', () => {
    deepStrictEqual(buildFindings([], new Map(), new Map()), []);
  });
});

describe('summarize', () => {
  it('counts advisories by severity and splits runtime from dev', () => {
    const findings = [
      {
        package: 'a',
        installed: '1',
        dev: false,
        bumpTo: '2',
        advisories: [
          { severity: 'HIGH', kev: true, fixedVersion: '2' },
          { severity: 'CRITICAL', kev: false, fixedVersion: '2' },
        ],
      },
      {
        package: 'b',
        installed: '1',
        dev: true,
        bumpTo: null,
        advisories: [
          { severity: 'LOW', kev: false, fixedVersion: null },
          { severity: 'MEDIUM', kev: false, fixedVersion: '3' },
          { severity: 'WEIRD', kev: false, fixedVersion: '3' },
        ],
      },
    ];
    const s = summarize(findings, 296);
    strictEqual(s.packagesChecked, 296);
    strictEqual(s.packagesAffected, 2);
    strictEqual(s.advisories, 5);
    deepStrictEqual(s.bySeverity, { critical: 1, high: 1, medium: 1, low: 1, unknown: 1 });
    strictEqual(s.kev, 1);
    strictEqual(s.runtime, 2);
    strictEqual(s.devOnly, 3);
    strictEqual(s.withoutFixedVersion, 1);
  });

  it('reports a clean tree as all zeroes', () => {
    const s = summarize([], 296);
    strictEqual(s.packagesAffected, 0);
    strictEqual(s.advisories, 0);
    strictEqual(s.withoutFixedVersion, 0);
  });
});

describe('compactReportItem', () => {
  it('keeps the actionable fields and drops the redundant ones', () => {
    const out = compactReportItem(reportItem());
    deepStrictEqual(Object.keys(out).sort(), ['cvss', 'epss', 'name', 'osvId', 'severity', 'summary', 'version'].sort());
    strictEqual(out.name, 'hono');
    strictEqual(out.version, '4.12.27');
    for (const dropped of ['purl', 'orgSlug', 'revokedAt', 'firstSeenAt', 'vulnCheckedAt', 'packageName', 'ecosystem']) {
      ok(!(dropped in out), `${dropped} should be dropped`);
    }
  });

  it('omits absent scores instead of emitting nulls', () => {
    const out = compactReportItem({ packageName: 'x', version: '1', osvId: 'A', cvssScore: null, epssScore: null });
    ok(!('cvss' in out));
    ok(!('epss' in out));
    ok(!('summary' in out));
  });

  it('surfaces kev flags only when set', () => {
    const plain = compactReportItem({ packageName: 'x', version: '1', osvId: 'A', isKev: false });
    ok(!('kev' in plain));
    const kev = compactReportItem({ packageName: 'x', version: '1', osvId: 'A', isKev: true, isKevRansomware: true });
    strictEqual(kev.kev, true);
    strictEqual(kev.kevRansomware, true);
  });
});

describe('parseNpmLockfile', () => {
  it('extracts name, version and the dev marker', () => {
    const pkgs = parseNpmLockfile(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'root', version: '1.0.0' },
          'node_modules/a': { version: '1.0.0' },
          'node_modules/b': { version: '2.0.0', dev: true },
          'node_modules/@scope/c': { version: '3.0.0' },
        },
      }),
    );
    deepStrictEqual(pkgs.sort((x, y) => x.name.localeCompare(y.name)), [
      { name: '@scope/c', version: '3.0.0', dev: false },
      { name: 'a', version: '1.0.0', dev: false },
      { name: 'b', version: '2.0.0', dev: true },
    ]);
  });

  it('prefers an explicit name over the path, for nested and aliased entries', () => {
    const pkgs = parseNpmLockfile(
      JSON.stringify({
        packages: { 'node_modules/x/node_modules/y': { name: 'real-name', version: '1.0.0' } },
      }),
    );
    deepStrictEqual(pkgs, [{ name: 'real-name', version: '1.0.0', dev: false }]);
  });

  it('skips the project root, link entries and entries with no version', () => {
    const pkgs = parseNpmLockfile(
      JSON.stringify({
        packages: {
          '': { name: 'root', version: '1.0.0' },
          'node_modules/linked': { version: '1.0.0', link: true },
          'node_modules/versionless': {},
        },
      }),
    );
    deepStrictEqual(pkgs, []);
  });

  it('refuses a v1 lockfile by name rather than scanning nothing', () => {
    let msg = '';
    try {
      parseNpmLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
    } catch (e) {
      msg = e.message;
    }
    ok(msg.includes('lockfileVersion 1'), msg);
    ok(msg.includes('npm install'), 'the refusal should name the fix');
  });

  it('reports invalid JSON without echoing the input', () => {
    // V8 embeds the offending bytes in its parse error; surfacing that would turn
    // this into a read oracle if the input ever came from a path.
    let msg = '';
    try {
      parseNpmLockfile('root:x:0:0:SECRET-CONTENT:/root:/bin/bash');
    } catch (e) {
      msg = e.message;
    }
    ok(msg.includes('not valid JSON'), msg);
    ok(!msg.includes('SECRET-CONTENT'), `must not echo input: ${msg}`);
    ok(!msg.includes('root:x'), `must not echo input: ${msg}`);
  });
});
