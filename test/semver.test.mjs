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
