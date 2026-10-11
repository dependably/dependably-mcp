/**
 * PEP 440 ordering for the `pypi` ecosystem, a port of `packaging.version`'s
 * parser and `_cmpkey`.
 *
 * A version is the tuple (epoch, release with trailing zeros stripped, pre,
 * post, dev, local), compared left to right. `packaging` makes the optional
 * parts sort correctly with sentinels instead of special cases:
 *   - pre: a dev-only version (`1.0.dev1`) is -inf, so it sorts below every
 *     prerelease of 1.0; no pre at all is +inf, so a final release outranks
 *     its prereleases;
 *   - post: absent is -inf, so `1.0` < `1.0.post0`;
 *   - dev: absent is +inf, so `1.0.dev1` < `1.0`;
 *   - local: absent is -inf, so `1.0` < `1.0+x`; numeric segments compare as
 *     numbers and rank above string segments, and a shorter label sorts first.
 *
 * Spellings are folded as `packaging` does: alpha→a, beta→b, c/pre/preview→rc,
 * rev/r→post, a missing number is 0, `1.0-1` is `1.0.post1`, `-`/`_`/`.` are
 * interchangeable separators, input is case-insensitive and may start with `v`.
 *
 * Numbers are kept as digit strings and compared by length then text, so a
 * release component beyond 2^53 still orders correctly.
 */

/** -inf / a real value / +inf, for the segments packaging gives sentinels. */
type Slot = { inf: -1 | 0 | 1; tag: string; n: string };

type LocalPart = { numeric: boolean; value: string };

export type Pep440Key = {
  epoch: string;
  release: string[];
  pre: Slot;
  post: Slot;
  dev: Slot;
  local: LocalPart[] | null;
};

/**
 * packaging's VERSION_PATTERN, one segment at a time, in order: `v`, epoch,
 * release, pre, post, dev, local. Each is a sticky match at the end of the
 * last, so no segment's pattern needs the others'; a missing optional segment
 * contributes undefined groups, and the whole string must be consumed.
 */
type Segment = { re: RegExp; groups: number; optional: boolean };

const SEGMENTS: readonly Segment[] = [
  { re: /v?/iy, groups: 0, optional: true },
  { re: /(\d+)!/y, groups: 1, optional: true },
  { re: /(\d+(?:\.\d+)*)/y, groups: 1, optional: false },
  { re: /[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?/iy, groups: 2, optional: true },
  { re: /-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?/iy, groups: 3, optional: true },
  { re: /[-_.]?(dev)[-_.]?(\d+)?/iy, groups: 2, optional: true },
  { re: /\+([a-z0-9]+(?:[-_.][a-z0-9]+)*)/iy, groups: 1, optional: true },
];

/** The capture groups of a full PEP 440 match, or null when it does not match. */
function matchPep440(version: string): Array<string | undefined> | null {
  const groups: Array<string | undefined> = [version];
  let at = 0;
  for (const { re, groups: n, optional } of SEGMENTS) {
    re.lastIndex = at;
    const m = re.exec(version);
    if (m) {
      at = re.lastIndex;
      groups.push(...m.slice(1));
    } else if (optional) {
      groups.push(...new Array<undefined>(n).fill(undefined));
    } else {
      return null;
    }
  }
  return at === version.length ? groups : null;
}

const PRE_SPELLING: Record<string, string> = {
  alpha: 'a',
  a: 'a',
  beta: 'b',
  b: 'b',
  c: 'rc',
  pre: 'rc',
  preview: 'rc',
  rc: 'rc',
};

const NEG_INF: Slot = { inf: -1, tag: '', n: '0' };
const POS_INF: Slot = { inf: 1, tag: '', n: '0' };

/** Digits without leading zeros, so equal numbers are equal strings. */
function digits(s: string | undefined): string {
  return (s ?? '0').replace(/^0+(?=\d)/, '');
}

function compareDigits(a: string, b: string): number {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function stripTrailingZeros(release: string[]): string[] {
  const out = release.map(digits);
  while (out.length > 1 && out[out.length - 1] === '0') out.pop();
  return out;
}

function localParts(label: string | undefined): LocalPart[] | null {
  if (label === undefined) return null;
  return label
    .toLowerCase()
    .split(/[-_.]/)
    .map((value) => (/^\d+$/.test(value) ? { numeric: true, value: digits(value) } : { numeric: false, value }));
}

/** The pre slot: dev-only is -inf, no pre is +inf, otherwise the normalized phase. */
function preSlot(letter: string | undefined, n: string | undefined, hasPost: boolean, hasDev: boolean): Slot {
  if (letter !== undefined) return { inf: 0, tag: PRE_SPELLING[letter.toLowerCase()], n: digits(n) };
  return hasDev && !hasPost ? NEG_INF : POS_INF;
}

/** The post number from either spelling (`-1` or `.post1`), or null when absent. */
function postNumber(implicit: string | undefined, letter: string | undefined, n: string | undefined): string | null {
  if (implicit !== undefined) return digits(implicit);
  return letter === undefined ? null : digits(n);
}

/**
 * Python's str.isspace set, which packaging's `^\s*…\s*$` strips: unlike JS
 * `trim()` it includes U+001C–U+001F and U+0085, and excludes U+FEFF.
 */
const PY_SPACE = new Set<number>([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** Strips Python whitespace from both ends in one linear pass (a regex here backtracks quadratically). */
function stripPythonSpace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && PY_SPACE.has(value.charCodeAt(start))) start++;
  while (end > start && PY_SPACE.has(value.charCodeAt(end - 1))) end--;
  return value.slice(start, end);
}

/** Parses a PEP 440 version, or returns null when it is not one. */
export function parsePep440(version: string): Pep440Key | null {
  const m = matchPep440(stripPythonSpace(version));
  if (!m) return null;
  const [, epoch, release, preLetter, preN, postImplicit, postLetter, postN, devLetter, devN, local] = m;
  if (release === undefined) return null;
  const post = postNumber(postImplicit, postLetter, postN);
  return {
    epoch: digits(epoch),
    release: stripTrailingZeros(release.split('.')),
    pre: preSlot(preLetter, preN, post !== null, devLetter !== undefined),
    post: post === null ? NEG_INF : { inf: 0, tag: '', n: post },
    dev: devLetter === undefined ? POS_INF : { inf: 0, tag: '', n: digits(devN) },
    local: localParts(local),
  };
}

function compareSlot(a: Slot, b: Slot): number {
  if (a.inf !== b.inf) return a.inf < b.inf ? -1 : 1;
  return compareText(a.tag, b.tag) || compareDigits(a.n, b.n);
}

function compareLocalPart(a: LocalPart, b: LocalPart): number {
  if (a.numeric !== b.numeric) return a.numeric ? 1 : -1;
  return a.numeric ? compareDigits(a.value, b.value) : compareText(a.value, b.value);
}

function compareLength(a: number, b: number): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function compareSequence<T>(a: readonly T[], b: readonly T[], cmp: (x: T, y: T) => number): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const c = cmp(a[i], b[i]);
    if (c !== 0) return c;
  }
  return compareLength(a.length, b.length);
}

function compareLocal(a: LocalPart[] | null, b: LocalPart[] | null): number {
  if (a === null) return b === null ? 0 : -1;
  if (b === null) return 1;
  return compareSequence(a, b, compareLocalPart);
}

export function comparePep440(a: Pep440Key, b: Pep440Key): number {
  return (
    compareDigits(a.epoch, b.epoch) ||
    compareSequence(a.release, b.release, compareDigits) ||
    compareSlot(a.pre, b.pre) ||
    compareSlot(a.post, b.post) ||
    compareSlot(a.dev, b.dev) ||
    compareLocal(a.local, b.local)
  );
}

/**
 * A spelling-independent string for a valid PEP 440 version, or null when the
 * input is not one: equal versions (`1.0`, `1.0.0`, `0!1.0`, `1.0.0-0`,
 * `1.0.POST0`) give the same string. Used as a join key, not for display.
 */
export function canonicalPep440(version: string): string | null {
  const k = parsePep440(version);
  if (!k) return null;
  const epoch = k.epoch === '0' ? '' : `${k.epoch}!`;
  const pre = k.pre.inf === 0 ? `${k.pre.tag}${k.pre.n}` : '';
  const post = k.post.inf === 0 ? `.post${k.post.n}` : '';
  const dev = k.dev.inf === 0 ? `.dev${k.dev.n}` : '';
  const local = k.local ? `+${k.local.map((p) => p.value).join('.')}` : '';
  return `${epoch}${k.release.join('.')}${pre}${post}${dev}${local}`;
}
