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
 *
 * PEP 440 also permits several spellings of the same phase — `c`, `pre` and
 * `preview` all mean `rc`; `a` means `alpha`; `b` means `beta`; `r` and `rev`
 * mean `post` — and treats them as equal. Comparing the raw marker text (as
 * this module used to) instead ranks them alphabetically, which is a real but
 * different order (`"c" < "rc"` always, regardless of the number after it), so
 * a fix spelled `2.0.0c1` and an installed version spelled `2.0.0rc1` compared
 * as different releases instead of the same one — occasionally recommending a
 * bump to a spelling that was already superseded. Every marker is canonicalized
 * before it enters `prerelease` so the two spellings compare as one phase.
 *
 * `compare`/`gte`/`maxVersion` take an optional `ecosystem`: for `'rpm'` they
 * switch to `rpmSegmentCompare` (defined below, with its own doc comment),
 * a real rpmvercmp-style segment comparison over epoch, version and release —
 * NOT the PEP 440 / semver parsing above, which reads an rpm NEVRA's
 * `version-release` hyphen as a prerelease and gets the ordering backwards.
 * Modelled: epochs (`2:1.2.3-1`), alternating digit/letter run comparison
 * (`el9` < `el10`), `~` (tilde) pre-release markers and rpm 4.15's `^`
 * (caret) post-release markers.
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

/** PEP 440's alias spellings, folded onto the one form each phase compares as. */
const PEP440_ALIASES: Record<string, string> = {
  c: 'rc',
  pre: 'rc',
  preview: 'rc',
  a: 'alpha',
  b: 'beta',
  r: 'post',
  rev: 'post',
};

function canonicalMarker(marker: string): string {
  const m = marker.toLowerCase();
  return PEP440_ALIASES[m] ?? m;
}

function phaseOf(marker: string): number {
  if (marker === 'dev') return DEV;
  if (marker === 'post') return POST;
  return PRE;
}

function parse(version: string): Parsed {
  const cleaned = version.trim().replace(/^[vV]/, '').split('+')[0];

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
    if (head.length > 0 && /\d$/.test(head)) {
      const marker = canonicalMarker(tail[1]);
      return {
        release: head.split('.'),
        phase: phaseOf(marker),
        prerelease: [marker, ...(tail[2] ? [tail[2]] : [])],
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

/**
 * rpm's NEVRA packs an epoch, a version and a release into one ordering:
 * `2:1.2.3-1` outranks `10:1.2.3-1` on epoch alone (2 < 10, compared
 * numerically, before version or release is even looked at), and `1.2.3-4`
 * is release `4` of version `1.2.3`, not a semver prerelease `4` of `1.2.3`
 * (semver's reading, which this module otherwise uses for the hyphen, sorts
 * `1.2.3-4` *below* `1.2.3` — an every-rpm-package downgrade). Split on the
 * LAST hyphen — a release qualifier such as `4.el9` can itself contain dots
 * but rpm reserves the hyphen for the version/release boundary — and compare
 * both halves with `rpmSegmentCompare`, rpm's actual algorithm.
 *
 * `rpmSegmentCompare` walks each string as alternating runs of digits and
 * letters; anything else (`.`, `_`, ...) is just a separator and orders
 * nothing on its own. Two digit runs compare numerically, so `el9` < `el10`
 * (a plain string compare would get that backwards); a digit run always
 * outranks a letter run at the same position; and `~` sorts below
 * everything, including the end of the string, so `1.2.3~rc1` is older than
 * plain `1.2.3` and, symmetrically, `1.0` is older than `1.0a` (trailing
 * content with no `~` is newer, not a tiebreak). A missing release ranks
 * below any present one, the same way a missing segment does not.
 *
 * `^` (caret, rpm 4.15) is the opposite of `~`: a post-release marker, so
 * `1.0^git1` is newer than `1.0` but older than `1.0.1` or `1.0a`. Both are
 * found before separators are skipped, as rpmvercmp does, so `1.0.~rc1` keeps
 * its tilde.
 */
function rpmSegmentCompare(a: string, b: string): number {
  let ai = 0;
  let bi = 0;

  for (;;) {
    ai = skipSeparators(a, ai);
    bi = skipSeparators(b, bi);
    const marker = compareMarkers(a[ai], b[bi]);
    if (marker === 'both') {
      ai++;
      bi++;
      continue;
    }
    if (marker !== 0) return marker;
    if (a[ai] === undefined || b[bi] === undefined) break;

    const run = compareRuns(a, ai, b, bi);
    if (run.cmp !== 0) return run.cmp;
    ai = run.ai;
    bi = run.bi;
  }

  // Whichever side still has a run is newer.
  if (a[ai] === undefined && b[bi] === undefined) return 0;
  return a[ai] === undefined ? -1 : 1;
}

/**
 * rpmvercmp's `~` and `^` rules at one position. `~` sorts before anything,
 * even the end of the string. `^` sorts after the end of the string but before
 * any further run. 'both' means each side has the same marker, to be skipped.
 */
function compareMarkers(a: string | undefined, b: string | undefined): number | 'both' {
  if (a === '~' || b === '~') {
    if (a !== '~') return 1;
    if (b !== '~') return -1;
    return 'both';
  }
  if (a === '^' || b === '^') {
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    if (a !== '^') return 1;
    if (b !== '^') return -1;
    return 'both';
  }
  return 0;
}

const isDigit = (c: string | undefined): c is string => c !== undefined && /\d/.test(c);
const isAlpha = (c: string | undefined): c is string => c !== undefined && /[A-Za-z]/.test(c);
const isAlnum = (c: string | undefined): c is string => isDigit(c) || isAlpha(c);

/** Skips everything but a run or a `~` / `^` marker. */
function skipSeparators(s: string, i: number): number {
  while (s[i] !== undefined && !isAlnum(s[i]) && s[i] !== '~' && s[i] !== '^') i++;
  return i;
}

function skipWhile(s: string, i: number, pred: (c: string | undefined) => boolean): number {
  while (pred(s[i])) i++;
  return i;
}

/** Compares the digit-or-letter run at each offset, reporting where each run ended. */
function compareRuns(
  a: string,
  ai: number,
  b: string,
  bi: number,
): { cmp: number; ai: number; bi: number } {
  const numeric = isDigit(a[ai]);
  // A digit run always outranks a letter run at the same position.
  if (numeric !== isDigit(b[bi])) return { cmp: numeric ? 1 : -1, ai, bi };
  const pred = numeric ? isDigit : isAlpha;
  const aEnd = skipWhile(a, ai, pred);
  const bEnd = skipWhile(b, bi, pred);
  const aRun = a.slice(ai, aEnd);
  const bRun = b.slice(bi, bEnd);
  const cmp = numeric ? compareDigitRuns(aRun, bRun) : compareWords(aRun, bRun);
  return { cmp, ai: aEnd, bi: bEnd };
}

function compareDigitRuns(a: string, b: string): number {
  const aNum = a.replace(/^0+/, '') || '0';
  const bNum = b.replace(/^0+/, '') || '0';
  if (aNum.length !== bNum.length) return aNum.length < bNum.length ? -1 : 1;
  if (aNum !== bNum) return aNum < bNum ? -1 : 1;
  return 0;
}

function compareWords(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function splitRpm(version: string): [string, string | undefined] {
  const trimmed = version.trim();
  const idx = trimmed.lastIndexOf('-');
  if (idx === -1) return [trimmed, undefined];
  return [trimmed.slice(0, idx), trimmed.slice(idx + 1)];
}

function compareRpmRelease(a: string | undefined, b: string | undefined): number {
  if (a === undefined && b === undefined) return 0;
  if (a === undefined) return -1;
  if (b === undefined) return 1;
  return rpmSegmentCompare(a, b);
}

/** A leading `N:` epoch, compared numerically ahead of everything else. */
function splitEpoch(version: string): [number, string] {
  const m = /^(\d+):/.exec(version);
  return m ? [Number(m[1]), version.slice(m[0].length)] : [0, version];
}

function compareRpm(a: string, b: string): number {
  const [aEpoch, aRest] = splitEpoch(a.trim());
  const [bEpoch, bRest] = splitEpoch(b.trim());
  if (aEpoch !== bEpoch) return aEpoch < bEpoch ? -1 : 1;
  const [av, ar] = splitRpm(aRest);
  const [bv, br] = splitRpm(bRest);
  return rpmSegmentCompare(av, bv) || compareRpmRelease(ar, br);
}

/** -1 if a < b, 0 if equal, 1 if a > b. */
export function compare(a: string, b: string, ecosystem?: string): number {
  if (ecosystem === 'rpm') return compareRpm(a, b);
  const pa = parse(a);
  const pb = parse(b);
  return (
    compareRelease(pa.release, pb.release) ||
    sign(pa.phase, pb.phase) ||
    comparePrerelease(pa.prerelease, pb.prerelease)
  );
}

export function gte(a: string, b: string, ecosystem?: string): boolean {
  return compare(a, b, ecosystem) >= 0;
}

/** The highest of the given versions, or undefined for an empty list. */
export function maxVersion(versions: readonly string[], ecosystem?: string): string | undefined {
  let best: string | undefined;
  for (const v of versions) {
    if (!v) continue;
    if (best === undefined || compare(v, best, ecosystem) > 0) best = v;
  }
  return best;
}
