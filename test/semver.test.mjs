import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { describe, it } from 'node:test';

import { compare, gte, maxVersion } from '../dist/semver.js';
import { parsePep440 } from '../dist/pep440.js';
import { isExactVersion } from '../dist/vuln.js';

describe('compare with PEP 440 epochs (pypi)', () => {
  // Every expectation below was confirmed with packaging 26.3
  // (packaging.version.Version) before being written down.
  const vectors = [
    ['1!1.0', '2.0', 1],
    ['0!1.0', '1.0', 0],
    ['1!1.0', '1!1.0.post1', -1],
    ['2!0.1', '1!9.9', 1],
    ['1!1.0rc1', '1!1.0', -1],
    ['1!1.0.dev1', '1!1.0a1', -1],
    ['1!0.1', '99.0', 1],
    ['2.0', '1!1.0.dev0', -1],
    ['10!1.0', '9!5.0', 1],
    ['1!2.0', '1!10.0', -1],
  ];
  for (const [a, b, want] of vectors) {
    it(`orders ${a} against ${b} as ${want}`, () => {
      strictEqual(compare(a, b, 'pypi'), want);
      strictEqual(compare(b, a, 'pypi'), want === 0 ? 0 : -want);
    });
  }

  // Also confirmed with packaging 26.3: compound tails, local labels, and
  // spellings that packaging folds together.
  const fullVectors = [
    ['1.0rc1.post1', '1.0rc1', 1],
    ['1.0.post1.dev0', '1.0.post1', -1],
    ['1.0.post1.dev0', '1.0', 1],
    ['1.0a1.dev1', '1.0a1', -1],
    ['1.0a1.dev1', '1.0.dev9', 1],
    ['1.0.dev1', '1.0a0', -1],
    ['1.0.post1', '1.0rc1.post9', 1],
    ['1.0', '1.0+ubuntu1', -1],
    ['1.0+5', '1.0+abc', 1],
    ['1.0+abc.1', '1.0+abc', 1],
    ['1.0+2', '1.0+10', -1],
    ['1.0+a', '1.0+b', -1],
    ['1.0a', '1.0a0', 0],
    ['1.0-1', '1.0.post1', 0],
    ['1.0alpha1', '1.0a1', 0],
    ['1.0c1', '1.0RC1', 0],
    ['v1.0.0', '1.0', 0],
    ['1.0_beta_2', '1.0b2', 0],
    ['1.0.rev3', '1.0-r3', 0],
    ['1.0+1.2', '1.0+1-2', 0],
    ['1.0.dev', '1.0.dev0', 0],
    ['1.0+007', '1.0+7', 0],
    ['1!1.0+x', '2.0', 1],
  ];
  for (const [a, b, want] of fullVectors) {
    it(`full PEP 440: ${a} against ${b} is ${want}`, () => {
      strictEqual(compare(a, b, 'pypi'), want);
      strictEqual(compare(b, a, 'pypi'), want === 0 ? 0 : -want);
    });
  }

  it('leaves the other ecosystems on the generic path', () => {
    // Under semver rules a "+" tail is build metadata and "1.0.post1.dev0"
    // has no PEP 440 meaning; these results are the pre-change behaviour.
    strictEqual(compare('1.0', '1.0+ubuntu1', 'npm'), 0);
    strictEqual(compare('1.0', '1.0+ubuntu1'), 0);
    strictEqual(compare('1.0-1', '1.0', 'cargo'), -1);
    strictEqual(compare('1.0.0', '1.0', 'npm'), 0);
  });

  it('falls back to the generic path for a pypi string that is not PEP 440', () => {
    ok(compare('1.2.3-beta.2', '1.2.3-beta.10', 'pypi') < 0);
  });

  it('lets the epoch outrank a later release in gte and maxVersion', () => {
    ok(gte('1!1.0', '2.0', 'pypi'));
    strictEqual(maxVersion(['2.0', '1!1.0', '3.0'], 'pypi'), '1!1.0');
  });

  it('does not parse an epoch for other ecosystems', () => {
    strictEqual(compare('1!1.0', '1!1.0', 'npm'), 0);
    strictEqual(compare('1!1.0', '1!1.0'), 0);
    // No epoch split: "1!1" stays a lexical release segment, as before.
    ok(compare('1!1.0', '2.0', 'cargo') < 0);
  });

  it('accepts an epoch-carrying version as an exact pypi version', () => {
    ok(isExactVersion('pypi', '1!1.0'));
    ok(!isExactVersion('pypi', '!=1.0'));
  });
});

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

describe('rpm tilde and caret markers (rpm tests/rpmvercmp.at)', () => {
  // [a, b, expected sign of compare(a, b)]
  const vectors = [
    ['1.0~rc1', '1.0~rc1', 0],
    ['1.0~rc1', '1.0', -1],
    ['1.0', '1.0~rc1', 1],
    ['1.0~rc1', '1.0~rc2', -1],
    ['1.0~rc1~git123', '1.0~rc1~git123', 0],
    ['1.0~rc1~git123', '1.0~rc1', -1],
    ['1.0^', '1.0^', 0],
    ['1.0^', '1.0', 1],
    ['1.0', '1.0^', -1],
    ['1.0^git1', '1.0^git1', 0],
    ['1.0^git1', '1.0', 1],
    ['1.0^git1', '1.0^git2', -1],
    ['1.0^git1', '1.01', -1],
    ['1.0^20160101', '1.0.1', -1],
    ['1.0^20160101^git1', '1.0^20160101', 1],
    ['1.0^20160102', '1.0^20160101^git1', 1],
    ['1.0~rc1^git1', '1.0~rc1', 1],
    ['1.0^git1~pre', '1.0^git1', -1],
    ['1.0^git1', '1.0~rc1', 1],
    ['1.0~rc1^git1', '1.0', -1],
    ['1.0.~rc1', '1.0', -1],
  ];
  for (const [a, b, want] of vectors) {
    it(`${a} ${want < 0 ? '<' : want > 0 ? '>' : '=='} ${b}`, () => {
      strictEqual(Math.sign(compare(a, b, 'rpm')), want);
    });
  }
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

describe('maven ComparableVersion ordering', () => {
  // Every expectation below was confirmed against Maven 3.9.16's own
  // org.apache.maven.artifact.versioning.ComparableVersion (maven-artifact-3.9.16.jar,
  // maven:3.9-eclipse-temurin-21), not derived from the documentation.
  const vectors = [
    ['1.0-sp1', '1.0', 1],
    ['1.0.Final', '1.0', 0],
    ['2.0.0.RELEASE', '2.0.0', 0],
    ['5.6.15.Final', '5.6.15', 0],
    ['1.0-ga', '1.0', 0],
    ['1.0.0', '1', 0],
    ['1.0-SNAPSHOT', '1.0', -1],
    ['1.0-SNAPSHOT', '1.0-rc1', 1],
    ['1.0-rc1', '1.0-cr1', 0],
    ['1.0-alpha1', '1.0-beta1', -1],
    ['1.0-beta1', '1.0-milestone1', -1],
    ['1.0-milestone1', '1.0-rc1', -1],
    ['1.0-sp1', '1.0-sp2', -1],
    ['1.0.SP1', '1.0.Final', 1],
    ['1.0a1', '1.0-alpha-1', 0],
    ['1.0b2', '1.0-beta-2', 0],
    ['1.0m3', '1.0-milestone-3', 0],
    ['1.0-a', '1.0-alpha', 1],
    ['1.0.0.M1', '1.0.0', -1],
    ['3.0.0-RC2', '3.0.0', -1],
    ['1.0-foo', '1.0-sp1', 1],
    ['1.0-jre', '1.0', 1],
    ['1.0-FOO', '1.0-foo', 0],
    ['1.0-bar', '1.0-foo', -1],
    ['1.0-1', '1.0-sp1', 1],
    ['1.0.1', '1.0-sp1', 1],
    ['1.0.0.X1', '1.0.0-X2', -1],
    ['1.10', '1.9', 1],
    ['2.0.0.RELEASE', '2.0.1.RELEASE', -1],
  ];

  for (const [a, b, expected] of vectors) {
    it(`${a} vs ${b} is ${expected}`, () => {
      strictEqual(compare(a, b, 'maven'), expected);
      strictEqual(compare(b, a, 'maven'), expected === 0 ? 0 : -expected);
    });
  }

  it('a post-release or release-spelled fix is cleared by the installed version', () => {
    ok(gte('1.0-sp1', '1.0', 'maven'));
    ok(gte('2.0.0.RELEASE', '2.0.0', 'maven'));
    ok(!gte('1.0-rc1', '1.0.Final', 'maven'));
    strictEqual(maxVersion(['1.0', '1.0-sp1', '1.0.Final'], 'maven'), '1.0-sp1');
  });

  it('leaves other ecosystems on the generic parser', () => {
    ok(compare('1.0.Final', '1.0', undefined) > 0);
    // Not PEP 440, so it ranks below the valid 1.0 rather than above it as maven would.
    ok(compare('1.0.Final', '1.0', 'pypi') < 0);
  });

  it('still treats qualifier versions as exact, but not a bare release tag', () => {
    for (const v of ['1.0-sp1', '1.0.Final', '2.0.0.RELEASE', '1.0-SNAPSHOT', '5.6.15.Final']) {
      ok(isExactVersion('maven', v), v);
    }
    ok(!isExactVersion('maven', 'release'));
    ok(!isExactVersion('maven', '[1.0,2.0)'));
  });
});
describe('pypi strips the whitespace packaging strips', () => {
  it('treats U+001C and U+0085 at the ends as space, and U+FEFF as part of the string', () => {
    strictEqual(compare('1.0\u001c', '1.0', 'pypi'), 0);
    strictEqual(compare('\u00851.0', '1.0', 'pypi'), 0);
    strictEqual(compare('\u30001.0\u3000', '1.0', 'pypi'), 0);
    // packaging rejects a leading BOM as invalid PEP 440, and so does the parser.
    strictEqual(parsePep440('\ufeff1.0'), null);
  });
});

describe('apk version ordering', () => {
  it('orders an empty version as apk does (confirmed with apk version -t on Alpine 3.22)', () => {
    strictEqual(compare('', '1', 'apk'), -1);
    strictEqual(compare('1', '', 'apk'), 1);
    strictEqual(compare('', '', 'apk'), 0);
    strictEqual(compare('', '_rc1', 'apk'), 1);
    strictEqual(compare('_rc1', '', 'apk'), -1);
  });

  // Every expectation below was confirmed against `apk version -t A B` from
  // apk-tools 2.14.10 on Alpine 3.22.5. apk's `-rN` is a package revision and
  // `_rc`/`_alpha`/... are suffixes with a fixed rank, none of which the generic
  // semver / PEP 440 parsing understands.
  const vectors = [
    ['1.2.3-r4', '>', '1.2.3'],
    ['1.2.3', '<', '1.2.3-r4'],
    ['1.2.3-r4', '<', '1.2.3-r10'],
    ['1.2.3-r10', '>', '1.2.3-r4'],
    ['1.2.3-r4', '=', '1.2.3-r04'],
    ['1.2.3_rc1-r0', '<', '1.2.3-r0'],
    ['1.2.3_rc1', '<', '1.2.3_rc2'],
    ['1.2.3_alpha', '<', '1.2.3_beta'],
    ['1.2.3_beta', '<', '1.2.3_pre'],
    ['1.2.3_pre', '<', '1.2.3_rc'],
    ['1.2.3_rc9', '<', '1.2.3'],
    ['1.2.3_p1', '>', '1.2.3'],
    ['1.2.3_cvs', '<', '1.2.3_svn'],
    ['1.2.3_svn', '<', '1.2.3_git'],
    ['1.2.3_git', '<', '1.2.3_hg'],
    ['1.2.3_hg', '<', '1.2.3_p'],
    ['1.2.3_p1-r1', '>', '1.2.3_p1'],
    ['1.2.3a', '>', '1.2.3'],
    ['1.2.3b', '>', '1.2.3a'],
    ['1.2.3a', '<', '1.2.4'],
    ['1.10', '>', '1.9'],
    ['1.01', '<', '1.1'],
    ['1.00', '<', '1.0'],
    ['1.0.0', '>', '1.0'],
    ['2.0_rc1-r0', '>', '1.9.9-r5'],
    ['3.1.4_p20240101', '>', '3.1.4_p3'],
    ['1.2.3_git20240101-r2', '>', '1.2.3-r2'],
    // Invalid input orders as apk orders it: never a throw.
    ['1.2.3_foo', '<', '1.2.3'],
    ['1.2.3_foo', '=', '1.2.3_bar'],
    ['1.2.3-rx', '>', '1.2.3'],
    ['1.2.3', '=', '1.2.3'],
  ];
  const expected = { '<': -1, '=': 0, '>': 1 };

  for (const [a, op, b] of vectors) {
    it(`${a} ${op} ${b}`, () => {
      strictEqual(compare(a, b, 'apk'), expected[op]);
      strictEqual(compare(b, a, 'apk'), expected[op] === 0 ? 0 : -expected[op]);
    });
  }

  it('leaves the generic ordering alone for other ecosystems', () => {
    ok(compare('1.2.3-r4', '1.2.3') < 0, 'semver still reads -r4 as a prerelease without the apk ecosystem');
  });

  it('feeds gte and maxVersion: a revision clears its bare fix, the newest revision wins', () => {
    ok(gte('1.2.3-r4', '1.2.3', 'apk'));
    ok(!gte('1.2.3_rc1-r0', '1.2.3-r0', 'apk'));
    strictEqual(maxVersion(['1.2.3-r4', '1.2.3-r10', '1.2.3-r9'], 'apk'), '1.2.3-r10');
  });
});

describe('compare: NuGet prerelease labels are case-insensitive', () => {
  // Confirmed against NuGet.Versioning 6.11.1 VersionComparer.Default. npm semver
  // 7.8.5, the Rust semver crate and Elixir 1.17 Version compare the same labels
  // as ASCII, so the case folding is NuGet-only.
  const vectors = [
    ['1.0.0-beta2', '1.0.0-RC1', -1],
    ['1.0.0-RC1', '1.0.0-beta1', 1],
    ['1.0.0-ALPHA', '1.0.0-alpha', 0],
    ['1.0.0-A', '1.0.0-a', 0],
    ['1.0.0-Preview.2', '1.0.0-preview.10', -1],
    ['1.0.0-RC1', '1.0.0', -1],
    // NuGet reads an identifier as a number only while it fits an Int32; past
    // that it is text, so these compare as text rather than by value.
    ['1.0.0-2147483647', '1.0.0-2147483648', -1],
    ['1.0.0-2147483648', '1.0.0-a', -1],
    ['1.0.0-9007199254740992', '1.0.0-A', -1],
    ['1.0.0-20230101000000', '1.0.0-5', 1],
    ['1.0.0-4000000000', '1.0.0-3000000000', 1],
    // Each of these differs under SemVer's numeric rule, so they pin NuGet's.
    ['1.0.0-2147483648', '1.0.0--', 1],
    // int.TryParse reads an optional sign: -1 is the number below 0.
    ['1.0.0--1', '1.0.0-0', -1],
    ['1.0.0--0', '1.0.0-0', 0],
    ['1.0.0--1', '1.0.0-a', -1],
    ['1.0.0--2147483649', '1.0.0--2147483648', 1],
    // `--1` does not parse, so it is text, and text ranks above the number -1.
    ['1.0.0---1', '1.0.0--1', 1],
  ];

  for (const [a, b, expected] of vectors) {
    it(`${a} vs ${b} is ${expected} for nuget`, () => {
      strictEqual(compare(a, b, 'nuget'), expected);
      strictEqual(compare(b, a, 'nuget'), expected === 0 ? 0 : -expected);
    });
  }

  it('keeps other ecosystems case-sensitive', () => {
    for (const eco of ['npm', 'cargo', 'hex', 'golang', undefined]) {
      ok(compare('1.0.0-beta2', '1.0.0-RC1', eco) > 0, String(eco));
      ok(compare('1.0.0-ALPHA', '1.0.0-alpha', eco) < 0, String(eco));
    }
  });

  it('does not report a vulnerable beta as already fixed by an RC', () => {
    ok(!gte('1.0.0-beta2', '1.0.0-RC1', 'nuget'));
    ok(gte('1.0.0-RC1', '1.0.0-beta2', 'nuget'));
    strictEqual(maxVersion(['1.0.0-beta2', '1.0.0-RC1'], 'nuget'), '1.0.0-RC1');
  });
});

describe('compare: SemVer prerelease identifiers', () => {
  // Every expected value below was confirmed against npm semver 7.8.5, the Rust
  // semver crate 1.x (precedence), Elixir 1.17 Version.compare and
  // NuGet.Versioning 6.11.1 VersionComparer.Default, which agree with each
  // other. Where npm differs it is noted: npm rounds identifiers above 2^53
  // through Number() and reports them equal; SemVer says they differ.
  const vectors = [
    // A numeric identifier ranks below an alphanumeric one (SemVer 11.4.3).
    ['2.9.0-beta.A.-', '2.9.0-beta.A.0', 1],
    ['3.10.2-a.2.10a', '3.10.2-a.2.3', 1],
    ['1.0.0-1', '1.0.0-alpha', -1],
    ['1.0.0-alpha.1', '1.0.0-alpha.beta', -1],
    ['0.0.0-20230101000000-abcdef123456', '0.0.0-0.20230101000000-abcdef123456', 1],
    // Only 0 or digits with no leading zero are numeric; 1e2, 0x10 and 0b1 are text.
    ['1.0.0-1e2', '1.0.0-100', 1],
    ['1.0.0-1e3', '1.0.0-2', 1],
    ['1.0.0-0x10', '1.0.0-9', 1],
    ['1.0.0-0b1', '1.0.0-1', 1],
    // Numeric identifiers compare by value, not as text.
    ['1.0.0-2', '1.0.0-10', -1],
    // A longer chain outranks its own prefix; a prerelease is below its release.
    ['1.0.0-1.2.3', '1.0.0-1.2', 1],
    ['1.0.0-alpha', '1.0.0-alpha.1', -1],
    ['1.0.0-rc.1', '1.0.0', -1],
    // Uppercase sorts below lowercase in ASCII, outside NuGet.
    ['1.0.0-A', '1.0.0-a', -1],
    ['1.0.0-beta2', '1.0.0-RC1', 1],
  ];

  for (const [a, b, expected] of vectors) {
    it(`${a} vs ${b} is ${expected}`, () => {
      for (const eco of ['npm', 'cargo', 'hex']) {
        strictEqual(compare(a, b, eco), expected, eco);
        strictEqual(compare(b, a, eco), -expected, eco);
      }
    });
  }

  // Cargo, Hex and NuGet.Versioning order these; npm semver reports 0 for all three.
  const wide = [
    ['1.0.0-9007199254740992', '1.0.0-9007199254740993', -1],
    ['1.0.0-alpha.9007199254740993', '1.0.0-alpha.9007199254740992', 1],
    ['1.0.0-123456789012345678901234567890', '1.0.0-123456789012345678901234567891', -1],
  ];

  for (const [a, b, expected] of wide) {
    it(`keeps precision past 2^53: ${a} vs ${b}`, () => {
      strictEqual(compare(a, b, 'cargo'), expected);
      strictEqual(compare(b, a, 'hex'), -expected);
    });
  }

  it('keeps precision in release numbers past 2^53 (Cargo and Hex agree)', () => {
    strictEqual(compare('9007199254740993.0.0', '9007199254740992.0.0', 'cargo'), 1);
    strictEqual(compare('1.9007199254740993.0', '1.9007199254740992.0', 'hex'), 1);
    strictEqual(compare('1.9007199254740992.0', '1.9007199254740992.0', 'hex'), 0);
  });

  it('still treats leading zeros in a release number as the same value', () => {
    strictEqual(compare('1.02.0', '1.2.0'), 0);
    ok(compare('1.10.0', '1.9.0') > 0);
  });

  it('lets an alphanumeric prerelease fix clear a numeric one, not the reverse', () => {
    ok(gte('1.0.0-alpha', '1.0.0-1'));
    ok(!gte('1.0.0-1', '1.0.0-alpha'));
  });
});

describe('version input bounds and comparator consistency', () => {
  it('parses a very long whitespace run in linear time', () => {
    const started = performance.now();
    strictEqual(parsePep440('1' + ' '.repeat(100000) + 'x'), null);
    ok(parsePep440(' '.repeat(100000) + '1.0' + ' '.repeat(100000)) !== null);
    ok(performance.now() - started < 200, 'whitespace stripping must not backtrack');
  });

  it('trims surrounding whitespace for apk and maven like the other comparators', () => {
    strictEqual(compare(' 1.0-r1', '1.0-r0', 'apk'), 1);
    strictEqual(compare('1.0-r1 ', '1.0-r1', 'apk'), 0);
    strictEqual(compare('1.0.0', '1.0.0 ', 'maven'), 0);
    strictEqual(compare(' 1.0.0', '1.0.0', 'maven'), 0);
    strictEqual(gte('1.0.0 ', '1.0.0', 'maven'), true);
  });

  it('ranks a version PEP 440 rejects below every valid one, in any input order', () => {
    const triple = ['1.0.0-SNAPSHOT', '1.0-1', '1.0'];
    const orders = [triple, [...triple].reverse(), [triple[1], triple[0], triple[2]], [triple[2], triple[0], triple[1]]];
    const winners = new Set(orders.map((order) => maxVersion(order, 'pypi')));
    strictEqual(winners.size, 1);
    ok(!winners.has('1.0.0-SNAPSHOT'));
    strictEqual(compare('1.0.0-SNAPSHOT', '1.0', 'pypi'), -1);
    strictEqual(compare('1.0', '1.0.0-SNAPSHOT', 'pypi'), 1);
    strictEqual(compare('1.0.0-SNAPSHOT', '1.0-1', 'pypi'), -1);
  });

  it('compares a PEP 440 prerelease number by value even with leading zeros', () => {
    strictEqual(compare('1.0rc01', '1.0rc2', 'npm'), -1);
    strictEqual(compare('1.0rc2', '1.0rc01', 'npm'), 1);
    strictEqual(compare('1.0rc01', '1.0rc1', 'npm'), 0);
    strictEqual(compare('1.0rc00', '1.0rc0', 'npm'), 0);
  });

  it('does not throw on a deeply nested maven version', () => {
    const deep = '1' + 'a1'.repeat(3000);
    strictEqual(compare(deep, deep + 'z', 'maven'), -1);
    strictEqual(compare(deep, deep, 'maven'), 0);
    strictEqual(compare(deep + 'z', deep, 'maven'), 1);
  });
});
