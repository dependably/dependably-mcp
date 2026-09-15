/**
 * Minimal version ordering, sufficient for comparing an installed version
 * against an advisory's fixed version.
 *
 * Deliberately not a full semver implementation: advisory `fixedVersion` values
 * and lockfile versions are concrete releases, never ranges, so all this needs
 * is a total order over dotted numeric releases with an optional prerelease
 * tail. Prereleases sort below their release (1.2.3-rc.1 < 1.2.3), matching
 * semver, and build metadata is ignored. A segment that is not a number sorts
 * lexically, so unusual-but-real versions (e.g. "0.0.33") still order sanely.
 */

type Parsed = { release: number[]; prerelease: string[] };

function parse(version: string): Parsed {
  const cleaned = version.trim().replace(/^v/, '').split('+')[0];
  const [releasePart, ...preParts] = cleaned.split('-');
  const release = releasePart.split('.').map((s) => {
    const n = Number(s);
    return Number.isFinite(n) ? n : Number.NaN;
  });
  const prerelease = preParts.length ? preParts.join('-').split('.') : [];
  return { release, prerelease };
}

function compareSegments(a: string[], b: string[]): number {
  // An empty prerelease list means "is a release", which outranks any prerelease.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = Number(x);
    const ny = Number(y);
    const bothNumeric = Number.isFinite(nx) && Number.isFinite(ny);
    if (bothNumeric) {
      if (nx !== ny) return nx < ny ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** -1 if a < b, 0 if equal, 1 if a > b. */
export function compare(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < len; i++) {
    const x = pa.release[i] ?? 0;
    const y = pb.release[i] ?? 0;
    // NaN means a non-numeric segment; fall back to string comparison for it.
    if (Number.isNaN(x) || Number.isNaN(y)) {
      const sx = String(x);
      const sy = String(y);
      if (sx !== sy) return sx < sy ? -1 : 1;
      continue;
    }
    if (x !== y) return x < y ? -1 : 1;
  }
  return compareSegments(pa.prerelease, pb.prerelease);
}

export function gte(a: string, b: string): boolean {
  return compare(a, b) >= 0;
}

/** The highest of the given versions, or undefined for an empty list. */
export function maxVersion(versions: readonly string[]): string | undefined {
  let best: string | undefined;
  for (const v of versions) {
    if (!v) continue;
    if (best === undefined || compare(v, best) > 0) best = v;
  }
  return best;
}
