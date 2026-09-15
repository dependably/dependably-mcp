/**
 * Minimal version ordering, sufficient for comparing an installed version
 * against an advisory's fixed version.
 *
 * Deliberately not a full semver implementation: advisory `fixedVersion` values
 * and lockfile versions are concrete releases, never ranges, so all this needs
 * is a total order over dotted releases with an optional prerelease tail.
 * Prereleases sort below their release (1.2.3-rc.1 < 1.2.3), matching semver,
 * and build metadata is ignored. Segments are compared numerically when both
 * sides are numeric and lexically otherwise, so an unusual-but-real version
 * still yields a stable order instead of comparing equal.
 */

type Parsed = { release: string[]; prerelease: string[] };

function parse(version: string): Parsed {
  const cleaned = version.trim().replace(/^v/, '').split('+')[0];
  const [releasePart, ...preParts] = cleaned.split('-');
  return {
    release: releasePart.split('.'),
    prerelease: preParts.length ? preParts.join('-').split('.') : [],
  };
}

/**
 * Compare one dotted segment. Numeric on both sides compares as numbers, so
 * 9 < 10; anything else compares as text. Segments are kept as strings rather
 * than coerced up front, because coercing a non-numeric segment to NaN loses
 * the only information that distinguishes it from any other non-numeric one.
 */
function compareSegment(a: string, b: string): number {
  const na = Number(a);
  const nb = Number(b);
  if (a !== '' && b !== '' && Number.isFinite(na) && Number.isFinite(nb)) {
    return sign(na, nb);
  }
  return sign(a, b);
}

/** -1, 0 or 1 for two values of the same comparable type. */
function sign<T extends number | string>(a: T, b: T): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function compareRelease(a: readonly string[], b: readonly string[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    // A missing segment is zero, so 1.2 and 1.2.0 are the same release.
    const cmp = compareSegment(a[i] ?? '0', b[i] ?? '0');
    if (cmp !== 0) return cmp;
  }
  return 0;
}

function comparePrerelease(a: readonly string[], b: readonly string[]): number {
  // An empty prerelease list means "is a release", which outranks any prerelease.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i];
    const y = b[i];
    // A shorter identifier chain sorts first when the shared prefix is equal.
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const cmp = compareSegment(x, y);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

/** -1 if a < b, 0 if equal, 1 if a > b. */
export function compare(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  return compareRelease(pa.release, pb.release) || comparePrerelease(pa.prerelease, pb.prerelease);
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
