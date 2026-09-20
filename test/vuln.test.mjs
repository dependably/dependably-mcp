import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { describe, it } from 'node:test';

import {
  buildFindings,
  canonicalVersion,
  compactReportItem,
  fetchRemediations,
  fetchReport,
  foldName,
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

  it('slices the returned array to maxItems instead of shipping the whole page that crossed it', async () => {
    // maxItems: 500 with pageSize: 200 used to return 600 items: the cap was
    // only checked as a loop-exit condition, after the whole 200-row page had
    // already been pushed onto items.
    const client = stubClient(() => ({
      items: Array.from({ length: 200 }, () => reportItem()),
      total: 100000,
    }));
    const { items, truncated } = await fetchReport(client, { pageSize: 200, maxItems: 500 });
    strictEqual(items.length, 500, 'the cap must be exact, not rounded up to the next full page');
    strictEqual(truncated, true);
  });

  it('keeps paging past a response that omits total, until an empty page', async () => {
    // A missing `total` used to be read as "the report is exactly this page
    // long", so fetchReport stopped after page 1 even when more rows were
    // still on the way, silently truncating without ever setting `truncated`.
    const client = stubClient((_p, q) => {
      if (q.page === 1) return { items: [reportItem(), reportItem()] }; // no total field
      if (q.page === 2) return { items: [reportItem(), reportItem(), reportItem()] }; // still none
      return { items: [] };
    });
    const { items, total, truncated } = await fetchReport(client);
    strictEqual(items.length, 5, 'must not stop after page 1 just because total was absent');
    strictEqual(total, 5);
    strictEqual(truncated, false);
    strictEqual(client.calls.length, 3);
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

  // The report stores canonical lower-case names; lockfiles do not. Matching raw
  // answers "clean" for a package that is in the report, which is the one wrong
  // answer this tool must not give.
  it('matches a lockfile name that differs from the report only by case', () => {
    const { hits } = matchPackages(report, [{ name: 'Hono', version: '4.12.27' }], 'npm');
    strictEqual(hits.length, 1, 'a capitalized lockfile name still finds its advisory');
    strictEqual(hits[0].packageName, 'hono');
  });

  it('matches a NuGet lockfile name verbatim from packages.lock.json', () => {
    const nuget = [reportItem({ packageName: 'newtonsoft.json', version: '12.0.3' })];
    const { hits } = matchPackages(nuget, [{ name: 'Newtonsoft.Json', version: '12.0.3' }], 'nuget');
    strictEqual(hits.length, 1);
  });

  it('folds pypi separators per PEP 503, but only for pypi', () => {
    const pypi = [reportItem({ packageName: 'typing-extensions', version: '4.12.2' })];
    strictEqual(
      matchPackages(pypi, [{ name: 'Typing_Extensions', version: '4.12.2' }], 'pypi').hits.length,
      1,
      'underscore and case both fold on pypi',
    );
    strictEqual(
      matchPackages(pypi, [{ name: 'typing_extensions', version: '4.12.2' }], 'npm').hits.length,
      0,
      'npm keeps the separator significant — they are different packages there',
    );
  });

  it('keeps the version exact while folding the name', () => {
    const { hits } = matchPackages(report, [{ name: 'HONO', version: '4.12.28' }], 'npm');
    deepStrictEqual(hits, [], 'a near-miss version is still a miss');
  });

  it('keys devOf on the folded name so the dev flag survives a case difference', () => {
    const { devOf } = matchPackages(report, [{ name: 'Hono', version: '4.12.27', dev: true }], 'npm');
    strictEqual(devOf.get('hono@4.12.27'), true);
  });
});

describe('foldName', () => {
  it('lower-cases every ecosystem', () => {
    strictEqual(foldName('npm', 'Hono'), 'hono');
    strictEqual(foldName('nuget', 'Newtonsoft.Json'), 'newtonsoft.json');
    strictEqual(foldName(undefined, 'Hono'), 'hono');
  });

  it('collapses . - and _ runs to a single hyphen on pypi only', () => {
    strictEqual(foldName('pypi', 'Typing_Extensions'), 'typing-extensions');
    strictEqual(foldName('pypi', 'zope.interface'), 'zope-interface');
    strictEqual(foldName('pypi', 'a__b'), 'a-b');
    strictEqual(foldName('nuget', 'Newtonsoft.Json'), 'newtonsoft.json', 'nuget keeps the dot');
  });
});

describe('canonicalVersion', () => {
  it('collapses an equivalent trailing-zero spelling on pypi, nuget and maven', () => {
    strictEqual(canonicalVersion('nuget', '4.5.0'), canonicalVersion('nuget', '4.5'));
    strictEqual(canonicalVersion('pypi', '1.0.0'), canonicalVersion('pypi', '1.0'));
    strictEqual(canonicalVersion('maven', '2.0.0'), canonicalVersion('maven', '2'));
  });

  it('does not strip trailing zeros for npm, cargo or golang', () => {
    ok(canonicalVersion('npm', '4.5.0') !== canonicalVersion('npm', '4.5'));
    ok(canonicalVersion('cargo', '4.5.0') !== canonicalVersion('cargo', '4.5'));
    ok(canonicalVersion('golang', '4.5.0') !== canonicalVersion('golang', '4.5'));
  });

  it('does not collide a genuinely different version', () => {
    ok(canonicalVersion('nuget', '4.5.1') !== canonicalVersion('nuget', '4.5'));
  });

  it('strips a leading v/V and lower-cases regardless of ecosystem', () => {
    strictEqual(canonicalVersion('npm', 'V1.2.3'), canonicalVersion('npm', 'v1.2.3'));
  });
});

// B5: an exact-string version join missed equivalent spellings, e.g. a NuGet
// pin of "4.5" against a registry row of "4.5.0" — reported clean when it
// was not.
describe('matchPackages joins an equivalent version spelling', () => {
  it('matches a NuGet pin of "4.5" against a registry row of "4.5.0"', () => {
    const report = [reportItem({ packageName: 'left-pad', version: '4.5.0' })];
    const { hits } = matchPackages(report, [{ name: 'left-pad', version: '4.5' }], 'nuget');
    strictEqual(hits.length, 1);
  });

  it('matches a PyPI requirement of "1.0" against a registry row of "1.0.0"', () => {
    const report = [reportItem({ packageName: 'left-pad', version: '1.0.0' })];
    const { hits } = matchPackages(report, [{ name: 'left-pad', version: '1.0' }], 'pypi');
    strictEqual(hits.length, 1);
  });

  it('still misses a genuinely different, non-equivalent version', () => {
    const report = [reportItem({ packageName: 'left-pad', version: '4.5.1' })];
    const { hits } = matchPackages(report, [{ name: 'left-pad', version: '4.5' }], 'nuget');
    deepStrictEqual(hits, []);
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

  it('normalizes the raw GHSA severity vocabulary to the report vocabulary', () => {
    // The detail endpoint serves database_specific verbatim ("MODERATE"); the
    // report endpoint serves "MEDIUM". One advisory must not have two spellings
    // across sibling tools, or a severity filter misses it.
    const r = summarizeRemediation({ databaseSpecific: { severity: 'MODERATE' } });
    strictEqual(r.severity, 'MEDIUM');
  });

  it('leaves severity undefined when the advisory carries none', () => {
    // Not "UNKNOWN": absent and unknown are different, and the caller renders them differently.
    strictEqual(summarizeRemediation({ databaseSpecific: {} }).severity, undefined);
    strictEqual(summarizeRemediation({}).severity, undefined);
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

// B1: buildFindings keyed a finding on the RAW report name, but matchPackages
// built devOf keyed on the FOLDED name. A report row whose spelling differs
// from the lockfile's (case, PEP 503 separators) found no devOf entry and
// silently fell back to "runtime" — dropping the dev flag the caller sent.
describe('buildFindings keeps the dev flag across a name-folding difference (B1)', () => {
  it('for a pypi package the report spells with underscores and the lockfile with a hyphen and different case', () => {
    const report = [reportItem({ packageName: 'typing_extensions', version: '4.5.0', osvId: 'A' })];
    const { hits, devOf } = matchPackages(
      report,
      [{ name: 'Typing-Extensions', version: '4.5.0', dev: true }],
      'pypi',
    );
    const findings = buildFindings(hits, devOf, new Map(), 'pypi');
    strictEqual(findings.length, 1);
    strictEqual(findings[0].dev, true, 'the dev flag must survive the pypi name fold');
    const s = summarize(findings, 1);
    strictEqual(s.runtime, 0);
    strictEqual(s.devOnly, 1);
  });

  it('for a NuGet package the report spells Pascal-case and the lockfile spells lower-case', () => {
    // The report row must NOT already be in the folded (lower-case) form, or
    // buildFindings's old unfolded key (`hit.packageName@hit.version`) happens
    // to equal the folded key by coincidence and the test passes even on the
    // broken code.
    const report = [reportItem({ packageName: 'Newtonsoft.Json', version: '12.0.3', osvId: 'A' })];
    const { hits, devOf } = matchPackages(
      report,
      [{ name: 'newtonsoft.json', version: '12.0.3', dev: true }],
      'nuget',
    );
    const findings = buildFindings(hits, devOf, new Map(), 'nuget');
    strictEqual(findings.length, 1);
    strictEqual(findings[0].dev, true, 'the dev flag must survive the nuget name fold');
    const s = summarize(findings, 1);
    strictEqual(s.runtime, 0);
    strictEqual(s.devOnly, 1);
  });
});

// B4: rpm's NEVRA "version-release" was read as a semver prerelease, so
// gte('1.2.3-4', '1.2.3') came back false and a project already at a fixed
// release got told to bump to the same (or an older) version.
describe('buildFindings orders rpm version-release strings correctly (B4)', () => {
  it('does not recommend a bump when the installed release already clears the fix', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'openssl', version: '1.2.3-4', osvId: 'A' })],
      new Map([['openssl@1.2.3-4', false]]),
      new Map([['A@@1.2.3-4', { fixedVersion: '1.2.3', cwes: [], owasp: [], skills: [] }]]),
      'rpm',
    );
    strictEqual(finding.bumpTo, null, '1.2.3-4 already clears a fix pinned to the bare release 1.2.3');
  });

  it('does recommend a bump when the installed release genuinely predates the fix', () => {
    const [finding] = buildFindings(
      [reportItem({ packageName: 'openssl', version: '1.2.3-4', osvId: 'A' })],
      new Map([['openssl@1.2.3-4', false]]),
      new Map([['A@@1.2.3-4', { fixedVersion: '1.2.3-10', cwes: [], owasp: [], skills: [] }]]),
      'rpm',
    );
    strictEqual(finding.bumpTo, '1.2.3-10');
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
