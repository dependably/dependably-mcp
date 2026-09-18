/**
 * Minimal version ordering, sufficient for comparing an installed version
 * against an advisory's fixed version.
 *
 * Deliberately not a full semver or PEP 440 implementation: advisory
 * `fixedVersion` values and lockfile versions are concrete releases, never
 * ranges, so all this needs is a total order over dotted releases with an
 * optional pre/post tail. Prereleases sort below their release
 * (1.2.3-rc.1 < 1.2.3), matching semver, and build metadata is ignored.
 * Segments are compared numerically when both sides are numeric and lexically
 * otherwise, so an unusual-but-real version still yields a stable order instead
 * of comparing equal.
 *
 * Python spells a prerelease without the hyphen semver requires — `2.0.0rc1`,
 * `1.0a1`, `1.0.dev1`, `1.0.post1`. Splitting only on `-` left the marker glued
 * to the last release segment, where `"0rc1"` compared lexically *above* `"0"`
 * and put 2.0.0rc1 ahead of 2.0.0. `bumpTarget` returns null once the installed
 * version is at or above the ceiling, so a project pinned to an RC was told the
 * advisory needed no action.
 *
 * Not modelled, because neither an advisory nor a lockfile has been observed to
 * carry one: PEP 440 epochs (`1!1.0`) and local version labels (`1.0+ubuntu1`,
 * whose `+` tail is dropped as build metadata).
 */

/** dev < pre < release < post, per PEP 440. */
const DEV = -2;
const PRE = -1;
const RELEASE = 0;
const POST = 1;

type Parsed = { release: string[]; phase: number; prerelease: string[] };

/**
 * A PEP 440 pre/post/dev tail, with or without a separator, anchored to the end:
 * `rc1`, `.dev1`, `-beta2`, `_post3`. The marker may carry no number (`1.0rc`).
 */
const PEP440_TAIL = /[.\-_]?(dev|alpha|beta|pre|preview|post|rev|a|b|c|rc|r)[.\-_]?(\d*)$/i;

function phaseOf(marker: string): number {
  const m = marker.toLowerCase();
  if (m === 'dev') return DEV;
  if (m === 'post' || m === 'rev' || m === 'r') return POST;
  return PRE;
}

function parse(version: string): Parsed {
  const cleaned = version.trim().replace(/^v/, '').split('+')[0];

  // A hyphenated tail is semver's spelling and is already a prerelease; keep that
  // path exactly as it was so existing orderings do not shift underneath callers.
  const hyphen = cleaned.indexOf('-');
  if (hyphen !== -1) {
    return {
      release: cleaned.slice(0, hyphen).split('.'),
      phase: PRE,
      prerelease: cleaned.slice(hyphen + 1).split('.'),
    };
  }

  const tail = PEP440_TAIL.exec(cleaned);
  if (tail) {
    const head = cleaned.slice(0, tail.index);
    // Guard against eating a release that merely ends in a marker letter, and
    // against a bare marker with no release in front of it.
    if (head.length > 0 && /[0-9]$/.test(head)) {
      return {
        release: head.split('.'),
        phase: phaseOf(tail[1]),
        prerelease: [tail[1].toLowerCase(), ...(tail[2] ? [tail[2]] : [])],
      };
    }
  }

  return { release: cleaned.split('.'), phase: RELEASE, prerelease: [] };
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
  return (
    compareRelease(pa.release, pb.release) ||
    sign(pa.phase, pb.phase) ||
    comparePrerelease(pa.prerelease, pb.prerelease)
  );
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
