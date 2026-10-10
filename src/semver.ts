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

/**
 * Maven orders versions with `ComparableVersion` (maven-artifact, 3.9.x), which
 * the semver / PEP 440 parsing above gets wrong in both directions: `1.0-sp1`
 * is NEWER than `1.0` (`sp` is a post-release qualifier), while `1.0.Final`,
 * `1.0-ga` and `2.0.0.RELEASE` are EQUAL to `1.0` and `2.0.0` (Spring and
 * Hibernate/JBoss releases carry them). `compareMaven` ports that algorithm.
 *
 * The version is lower-cased and tokenized on `.` and `-` and on every
 * digit/letter transition (`1.0alpha1` reads as `1.0-alpha-1`). A token is a
 * number or a string qualifier; a `-` (or a transition) opens a nested list,
 * so `1-sp1` is `[1, [sp, [1]]]`. Trailing "null" items (zero, the empty
 * qualifier and its aliases `final`/`ga`/`release`, empty lists) are trimmed
 * from every list, which is what makes `1.0.0` equal `1`.
 *
 * Qualifiers order alpha < beta < milestone < rc (= cr) < snapshot < "" (=
 * final = ga = release) < sp, and the single letters a, b and m mean alpha,
 * beta and milestone only when a digit follows directly (`1.0a1`, not
 * `1.0-a`). A qualifier outside that list sorts after `sp`, compared
 * case-insensitively as text. A number outranks a qualifier, and a nested list
 * outranks a number but not a qualifier. Numbers of up to nine digits, of up
 * to eighteen, and longer fall in three width classes that compare in that
 * order before their values do, as Maven's Int/Long/BigInteger items do. Width
 * ignores leading zeros except in an all-zero token, which keeps its length
 * (`1.0000000000` outranks `1.999999999`, a quirk the oracle confirms).
 *
 * Not modelled: non-ASCII digits, which Java's `Character.isDigit` accepts.
 */
type MavenItem = MavenNumber | MavenQualifier | MavenList;
type MavenNumber = { kind: 'number'; value: bigint; width: number };
type MavenQualifier = { kind: 'qualifier'; value: string };
type MavenList = { kind: 'list'; items: MavenItem[] };

const MAVEN_QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const MAVEN_RELEASE_KEY = String(MAVEN_QUALIFIERS.indexOf(''));
const MAVEN_ALIASES: Record<string, string> = { ga: '', final: '', release: '', cr: 'rc' };
const MAVEN_SHORT_QUALIFIERS: Record<string, string> = { a: 'alpha', b: 'beta', m: 'milestone' };

function mavenNumber(digits: string): MavenNumber {
  const stripped = digits.replace(/^0+/, '') || digits;
  const width = stripped.length <= 9 ? 0 : stripped.length <= 18 ? 1 : 2;
  return { kind: 'number', value: BigInt(stripped), width };
}

function mavenQualifier(text: string, followedByDigit: boolean): MavenQualifier {
  const expanded = followedByDigit ? (MAVEN_SHORT_QUALIFIERS[text] ?? text) : text;
  return { kind: 'qualifier', value: MAVEN_ALIASES[expanded] ?? expanded };
}

/** Unknown qualifiers get a key above every known one, then compare as text. */
function mavenQualifierKey(value: string): string {
  const index = MAVEN_QUALIFIERS.indexOf(value);
  return index === -1 ? `${MAVEN_QUALIFIERS.length}-${value}` : String(index);
}

function mavenIsNull(item: MavenItem): boolean {
  if (item.kind === 'number') return item.value === 0n;
  if (item.kind === 'qualifier') return mavenQualifierKey(item.value) === MAVEN_RELEASE_KEY;
  return item.items.length === 0;
}

function mavenNormalize(list: MavenList): void {
  for (let i = list.items.length - 1; i >= 0; i--) {
    const last = list.items[i];
    if (mavenIsNull(last)) list.items.splice(i, 1);
    else if (last.kind !== 'list') break;
  }
}

type MavenParse = { text: string; stack: MavenList[]; list: MavenList; start: number; digit: boolean };

function mavenToken(state: MavenParse, end: number): MavenItem {
  const token = state.text.slice(state.start, end);
  return state.digit ? mavenNumber(token) : mavenQualifier(token, false);
}

function mavenOpenList(state: MavenParse): void {
  const child: MavenList = { kind: 'list', items: [] };
  state.list.items.push(child);
  state.list = child;
  state.stack.push(child);
}

/** `.X` reads as `-X` for a qualifier X, so a qualifier after other items starts its own list. */
function mavenOpenQualifierList(state: MavenParse): void {
  if (state.list.items.length > 0) mavenOpenList(state);
}

function mavenSeparator(state: MavenParse, i: number): void {
  state.list.items.push(i === state.start ? mavenNumber('0') : mavenToken(state, i));
  state.start = i + 1;
  if (state.text[i] === '-') mavenOpenList(state);
}

function mavenDigit(state: MavenParse, i: number): void {
  if (!state.digit && i > state.start) {
    mavenOpenQualifierList(state);
    state.list.items.push(mavenQualifier(state.text.slice(state.start, i), true));
    state.start = i;
    mavenOpenList(state);
  }
  state.digit = true;
}

function mavenLetter(state: MavenParse, i: number): void {
  if (state.digit && i > state.start) {
    state.list.items.push(mavenToken(state, i));
    state.start = i;
    mavenOpenList(state);
  }
  state.digit = false;
}

function parseMaven(version: string): MavenList {
  const root: MavenList = { kind: 'list', items: [] };
  const state: MavenParse = { text: version.toLowerCase(), stack: [root], list: root, start: 0, digit: false };
  for (let i = 0; i < state.text.length; i++) {
    const c = state.text[i];
    if (c === '.' || c === '-') mavenSeparator(state, i);
    else if (c >= '0' && c <= '9') mavenDigit(state, i);
    else mavenLetter(state, i);
  }
  if (state.text.length > state.start) {
    if (!state.digit) mavenOpenQualifierList(state);
    state.list.items.push(mavenToken(state, state.text.length));
  }
  for (let list = state.stack.pop(); list !== undefined; list = state.stack.pop()) mavenNormalize(list);
  return root;
}

/** `item` against `other`; a null `other` is the absent side of a shorter list. */
function mavenItemCompare(item: MavenItem, other: MavenItem | null): number {
  if (item.kind === 'number') return mavenCompareNumber(item, other);
  if (item.kind === 'qualifier') return mavenCompareQualifier(item, other);
  return mavenCompareList(item, other);
}

function mavenCompareNumber(item: MavenNumber, other: MavenItem | null): number {
  if (other === null) return item.value === 0n ? 0 : 1;
  if (other.kind !== 'number') return 1;
  if (item.width !== other.width) return sign(item.width, other.width);
  return item.value === other.value ? 0 : item.value < other.value ? -1 : 1;
}

function mavenCompareQualifier(item: MavenQualifier, other: MavenItem | null): number {
  if (other === null) return sign(mavenQualifierKey(item.value), MAVEN_RELEASE_KEY);
  if (other.kind === 'qualifier') return sign(mavenQualifierKey(item.value), mavenQualifierKey(other.value));
  return -1;
}

/** A list against nothing: the first item that is not itself null decides (not just item 0). */
function mavenFirstNonZero(items: readonly MavenItem[]): number {
  for (const entry of items) {
    const result = mavenItemCompare(entry, null);
    if (result !== 0) return result;
  }
  return 0;
}

function mavenCompareList(item: MavenList, other: MavenItem | null): number {
  if (other === null) return mavenFirstNonZero(item.items);
  if (other.kind === 'number') return -1;
  if (other.kind === 'qualifier') return 1;
  const length = Math.max(item.items.length, other.items.length);
  for (let i = 0; i < length; i++) {
    const result = mavenCompareSlot(item.items[i] ?? null, other.items[i] ?? null);
    if (result !== 0) return result;
  }
  return 0;
}

function mavenCompareSlot(left: MavenItem | null, right: MavenItem | null): number {
  if (left !== null) return mavenItemCompare(left, right);
  return right === null ? 0 : -mavenItemCompare(right, left);
}

function compareMaven(a: string, b: string): number {
  return mavenCompareList(parseMaven(a), parseMaven(b));
}

/** -1 if a < b, 0 if equal, 1 if a > b. */
export function compare(a: string, b: string, ecosystem?: string): number {
  if (ecosystem === 'rpm') return compareRpm(a, b);
  if (ecosystem === 'maven') return compareMaven(a, b);
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
