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
