import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { describe, it } from 'node:test';

import { compare, gte, maxVersion } from '../dist/semver.js';

describe('compare', () => {
  it('orders release segments numerically, not lexically', () => {
    ok(compare('3.1.3', '3.1.6') < 0);
    ok(compare('10.7.0', '10.3.1') > 0);
    ok(compare('4.13.7', '4.13.5') > 0);
    // The case that breaks string comparison: 9 vs 10.
    ok(compare('1.9.0', '1.10.0') < 0);
  });

  it('lets the most significant differing segment win', () => {
    ok(compare('1.19.14', '2.0.5') < 0);
    ok(compare('2.0.0', '1.99.99') > 0);
  });

  it('treats missing segments as zero', () => {
    strictEqual(compare('1.2', '1.2.0'), 0);
    ok(compare('1.2', '1.2.1') < 0);
    ok(compare('1.2.1', '1.2') > 0);
  });

  it('handles 0.x lines, where an npm-era version like 0.0.33 lives', () => {
    ok(compare('0.0.33', '0.2.6') < 0);
    ok(compare('0.2.7', '0.2.6') > 0);
    ok(compare('0.0.33', '0.0.33') === 0);
  });

  it('sorts a prerelease below its release', () => {
    ok(compare('1.2.3-rc.1', '1.2.3') < 0);
    ok(compare('1.2.3', '1.2.3-rc.1') > 0);
    ok(compare('1.2.3-rc.1', '1.2.3-rc.2') < 0);
    ok(compare('1.2.3-alpha', '1.2.3-beta') < 0);
    // A longer prerelease chain is greater when the shared prefix matches.
    ok(compare('1.2.3-rc', '1.2.3-rc.1') < 0);
  });

  it('ignores build metadata', () => {
    strictEqual(compare('1.2.3+build.1', '1.2.3'), 0);
    strictEqual(compare('1.2.3+a', '1.2.3+b'), 0);
  });

  it('tolerates a leading v and surrounding whitespace', () => {
    strictEqual(compare('v1.2.3', '1.2.3'), 0);
    strictEqual(compare('  1.2.3  ', '1.2.3'), 0);
  });

  it('falls back to string ordering for non-numeric segments', () => {
    // Not valid semver, but must yield a total order rather than NaN chaos.
    strictEqual(compare('1.x.0', '1.x.0'), 0);
    ok(compare('1.a.0', '1.b.0') < 0);
  });

  it('compares numeric prerelease identifiers numerically', () => {
    ok(compare('1.0.0-2', '1.0.0-10') < 0);
  });
});

describe('gte', () => {
  it('is true at and above the boundary, false below', () => {
    ok(gte('7.5.22', '7.5.21'));
    ok(gte('7.5.21', '7.5.21'));
    ok(!gte('7.5.20', '7.5.21'));
  });
});

describe('maxVersion', () => {
  it('returns the ceiling, which is what a bump target must clear', () => {
    strictEqual(maxVersion(['3.1.4', '3.1.6', '3.1.5']), '3.1.6');
    strictEqual(maxVersion(['10.2.1', '10.2.2', '10.3.1']), '10.3.1');
  });

  it('returns undefined for an empty list', () => {
    strictEqual(maxVersion([]), undefined);
  });

  it('skips empty entries rather than ranking them', () => {
    strictEqual(maxVersion(['', '1.0.0', '']), '1.0.0');
    strictEqual(maxVersion(['']), undefined);
  });

  it('handles a single entry', () => {
    strictEqual(maxVersion(['4.13.5']), '4.13.5');
  });

  it('is order-independent', () => {
    const versions = ['1.0.0', '3.0.0', '2.0.0'];
    deepStrictEqual(maxVersion(versions), maxVersion([...versions].reverse()));
  });
});

describe('PEP 440 pre/post tails', () => {
  // Python spells a prerelease without semver's hyphen. Splitting only on "-"
  // left the marker glued to the last release segment, where "0rc1" compared
  // lexically ABOVE "0" — so 2.0.0rc1 sorted after 2.0.0, and a project pinned
  // to an RC was told the advisory needed no bump.
  for (const [lower, higher] of [
    ['2.0.0rc1', '2.0.0'],
    ['1.0a1', '1.0'],
    ['1.0b2', '1.0'],
    ['1.0rc1', '1.0'],
    ['1.0alpha1', '1.0'],
    ['1.0beta1', '1.0'],
    ['1.0.dev1', '1.0'],
    ['1.0_pre1', '1.0'],
  ]) {
    it(`${lower} sorts below ${higher}`, () => {
      ok(compare(lower, higher) < 0, `${lower} < ${higher}`);
      ok(compare(higher, lower) > 0, 'and the reverse');
    });
  }

  it('sorts a post-release above its release', () => {
    ok(compare('1.0.post1', '1.0') > 0);
    ok(compare('1.0post1', '1.0') > 0);
    ok(compare('1.0', '1.0.post1') < 0);
    ok(compare('1.0.post1', '1.0.post2') < 0);
  });

  it('orders the phases dev < pre < release < post', () => {
    const ordered = ['1.0.dev1', '1.0a1', '1.0b1', '1.0rc1', '1.0', '1.0.post1'];
    for (let i = 0; i < ordered.length - 1; i++) {
      ok(compare(ordered[i], ordered[i + 1]) < 0, `${ordered[i]} < ${ordered[i + 1]}`);
    }
    deepStrictEqual(maxVersion(ordered), '1.0.post1');
  });

  it('does not treat a dev release as later than a real patch', () => {
    ok(compare('1.0.dev1', '1.0.1') < 0);
  });

  it('accepts a marker with no number', () => {
    ok(compare('1.0rc', '1.0') < 0);
    ok(compare('1.0rc', '1.0rc1') < 0);
  });

  it('leaves a plain release alone when it merely ends in a marker letter', () => {
    // The tail only splits when a digit precedes the marker, so these stay releases.
    strictEqual(compare('1.0.0', '1.0.0'), 0);
    ok(compare('1.0.0', '1.0.1') < 0);
  });

  it('keeps gte false for a prerelease below its ceiling', () => {
    // This is the bug's real consequence: bumpTarget returns null once
    // gte(installed, ceiling) is true, so a wrong gte silently drops the finding.
    ok(!gte('2.0.0rc1', '2.0.0'), 'an RC has not reached its release');
    ok(gte('2.0.0', '2.0.0'));
    ok(gte('2.0.0.post1', '2.0.0'));
  });

  it('does not disturb the semver spellings', () => {
    ok(compare('1.2.3-rc.1', '1.2.3') < 0);
    ok(compare('1.0.0-beta1', '1.0.0') < 0);
    strictEqual(compare('1.2.3+build', '1.2.3'), 0);
    strictEqual(compare('1.2', '1.2.0'), 0);
    ok(compare('0.0.33', '0.2.6') < 0);
  });
});

describe('PEP 440 alias spellings', () => {
  // c, pre and preview all mean rc; alpha means a; beta means b; r and rev
  // mean post. Comparing the raw marker text instead of the canonical phase
  // ranked these alphabetically ("c" < "rc" always, regardless of the number),
  // so a fix spelled one way and an installed version spelled the other never
  // compared as the same release.
  for (const [x, y] of [
    ['1.0rc1', '1.0c1'],
    ['1.0rc1', '1.0pre1'],
    ['1.0rc1', '1.0preview1'],
    ['1.0alpha1', '1.0a1'],
    ['1.0beta1', '1.0b1'],
    ['1.0post1', '1.0r1'],
    ['1.0post1', '1.0rev1'],
  ]) {
    it(`treats ${x} and ${y} as the same release`, () => {
      strictEqual(compare(x, y), 0, `${x} vs ${y}`);
      strictEqual(compare(y, x), 0, `${y} vs ${x}`);
    });
  }

  it('still orders the alias pair by number once the phase is canonicalized', () => {
    // 1.0.rc1 sorted alphabetically-above 1.0c1 before the fix (marker "rc" >
    // marker "c" as text), independent of the trailing number; canonicalizing
    // both to "rc" restores the numeric comparison PEP 440 actually specifies.
    ok(compare('1.0pre2', '1.0rc1') > 0, '1.0pre2 > 1.0rc1: both are rc-phase, and 2 > 1');
    ok(compare('1.0rc1', '1.0pre2') < 0);
  });

  it('the bumpTarget consequence: a fix spelled with the short alias must not look older than an already-cleared installed version', () => {
    // 1.0a5 is 1.0alpha5 under canonicalization. Before the fix, comparing the
    // raw marker text ranked "a" < "alpha" (a string-prefix comparison)
    // regardless of the trailing number, so an installed 1.0a5 compared as
    // BELOW a fix of 1.0alpha2 even though alpha5 is the later release —
    // gte() returned false and bumpTarget would have recommended downgrading
    // to an older spelling of a release the project had already cleared.
    ok(gte('1.0a5', '1.0alpha2'), 'installed alpha5 already clears a fix pinned to alpha2');
    ok(!gte('1.0a1', '1.0alpha2'), 'and alpha1 genuinely has not');
  });

  it('strips an upper-case V prefix like the lower-case one', () => {
    strictEqual(compare('V1.2.3', '1.2.3'), 0);
    strictEqual(compare('V1.2.3', 'v1.2.3'), 0);
  });
});

describe('rpm version-release ordering', () => {
  // rpm's NEVRA glues a second ordered field onto the version with a hyphen:
  // "1.2.3-4" is release 4 of version 1.2.3, not a semver prerelease "4" of
  // "1.2.3". Reading it as semver's hyphen sorts every "1.2.3-N" BELOW plain
  // "1.2.3" — installed 1.2.3-4.el9 against a fix of 1.2.3 read as a
  // downgrade, when it is actually already at or past the fix.
  it('a version-release is at or above its bare version, not below it', () => {
    ok(gte('1.2.3-4', '1.2.3', 'rpm'), 'a release qualifier must not read as a prerelease');
    ok(!gte('1.2.3-4', '1.2.3', undefined), 'without rpm ecosystem, the old (semver) reading still applies');
  });

  it('compares the release field numerically once the version fields tie', () => {
    ok(compare('1.2.3-4', '1.2.3-10', 'rpm') < 0, '4 < 10 numerically, not lexically');
    ok(compare('1.2.3-4', '1.2.3-4', 'rpm') === 0);
  });

  it('lets the version field win over the release field', () => {
    ok(compare('1.2.3-4', '1.2.4-1', 'rpm') < 0);
  });

  it('ranks a missing release below any present release of the same version', () => {
    ok(gte('1.2.3-0', '1.2.3', 'rpm'));
    ok(!gte('1.2.3', '1.2.3-0', 'rpm'));
  });

  it('keeps the release qualifier suffix (e.g. .el9) as a tiebreak, not a parse failure', () => {
    ok(compare('1.2.3-4.el9', '1.2.3-4.el8', 'rpm') > 0);
  });
});

describe('rpm rpmvercmp-style segment comparison', () => {
  // A plain numeric/lexical comparison of the version and release strings is
  // not what rpm actually does: rpm tokenizes into alternating digit/letter
  // runs (so "el9" < "el10" compares the trailing numbers as numbers, not as
  // strings), treats "~" as sorting below everything including the end of
  // the string, and orders the epoch ahead of both.
  it('a tilde pre-release marker sorts below the plain release it precedes', () => {
    ok(compare('1.2.3~rc1-1', '1.2.3-1', 'rpm') < 0);
    ok(compare('1.2.3-1', '1.2.3~rc1-1', 'rpm') > 0);
  });

  it('compares a numeric run numerically, not lexically, inside a release qualifier', () => {
    ok(compare('1.2.3-4.el9', '1.2.3-4.el10', 'rpm') < 0, 'el9 < el10 — a string compare would say the opposite');
  });

  it('compares the epoch prefix numerically, ahead of version and release', () => {
    ok(compare('2:1.2.3-1', '10:1.2.3-1', 'rpm') < 0, '2 < 10 numerically, not "2" > "10" lexically');
  });

  it('a release with an extra trailing segment is newer than the release it extends', () => {
    ok(compare('1.2.3-4.el9', '1.2.3-4.el9.1', 'rpm') < 0);
  });

  it('trailing alphabetic content with no tilde is newer, not a tiebreak toward equal', () => {
    ok(compare('1.0-1', '1.0a-1', 'rpm') < 0);
  });

  it('the bumpTarget consequence: a tilde pre-release must still clear a plain-release fix', () => {
    ok(gte('1.2.3-1', '1.2.3~rc1-1', 'rpm'), 'the real release clears its own pre-release');
    ok(!gte('1.2.3~rc1-1', '1.2.3-1', 'rpm'), 'and the pre-release has not reached the real release yet');
  });
});
