import type { DependablyClient } from './client.js';
import { gte, maxVersion } from './semver.js';

/**
 * Client-side vulnerability scoping and remediation enrichment.
 *
 * The Dependably API reports vulnerabilities per *org* (`GET /api/v1/vuln-report`
 * returns every affected package any project has published), and its items carry
 * no fixed version — that lives on the per-advisory endpoint. Answering the
 * question people actually ask ("what is wrong with *my* project, and what do I
 * bump to?") therefore takes a whole-report fetch, a local join against the
 * caller's dependency list, and one detail call per distinct advisory.
 *
 * Doing that here rather than in each caller keeps it consistent and costs one
 * tool call instead of dozens. The server-side changes that would let this
 * collapse into a single request are tracked as asks against the API, not here.
 */

export type InputPackage = { name: string; version: string; dev?: boolean };

/** One row of `GET /api/v1/vuln-report`, as far as this module relies on it. */
export type ReportItem = {
  packageName: string;
  version: string;
  osvId: string;
  severity?: string;
  cvssScore?: number | null;
  epssScore?: number | null;
  isKev?: boolean | null;
  isKevRansomware?: boolean | null;
  summary?: string;
  ecosystem?: string;
  [k: string]: unknown;
};

export type Advisory = {
  osvId: string;
  severity: string;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  summary: string;
  fixedVersion: string | null;
  cwes?: string[];
  owasp?: string[];
  skills?: string[];
  /** Other ids for this same flaw (a PYSEC record of a GHSA, the CVE), folded into this entry. */
  aliases?: string[];
};

export type Finding = {
  package: string;
  installed: string;
  dev: boolean;
  bumpTo: string | null;
  /** True when some advisory's fixed version was not looked up (the lookup cap), so bumpTo may be too low. */
  bumpToPartial?: boolean;
  advisories: Advisory[];
};

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  MODERATE: 2,
  LOW: 1,
  NONE: 0,
  UNKNOWN: 0,
};

function severityRank(s: string | undefined): number {
  return SEVERITY_RANK[String(s ?? '').toUpperCase()] ?? 0;
}

function normalizeSeverity(s: string | undefined): string {
  const up = String(s ?? 'UNKNOWN').toUpperCase();
  return up === 'MODERATE' ? 'MEDIUM' : up;
}

/**
 * Fetch every page of the vulnerability report.
 *
 * The endpoint pages at 50 by default and reports a `total`; `pageSize` is sent
 * explicitly so a large org does not turn into dozens of round trips. `maxItems`
 * is a stop so a misbehaving or unexpectedly huge report cannot hang the tool.
 */
export async function fetchReport(
  client: DependablyClient,
  opts: { ecosystem?: string; pageSize?: number; maxItems?: number } = {},
): Promise<{ items: ReportItem[]; total: number; truncated: boolean }> {
  const pageSize = opts.pageSize ?? 200;
  const maxItems = opts.maxItems ?? 5000;
  const items: ReportItem[] = [];
  // `total` is only trustworthy once a response has actually carried it: a
  // response that omits the field is not "a report of length batch.length",
  // it is a report whose length is unknown, and stopping on that guess (as
  // this used to) truncated every report the server didn't paginate.
  let total: number | undefined;

  for (let page = 1; ; page++) {
    const res = (await client.get('/api/v1/vuln-report', {
      ecosystem: opts.ecosystem,
      limit: pageSize,
      page,
    })) as { items?: ReportItem[]; total?: number } | null;

    const batch = res?.items ?? [];
    if (typeof res?.total === 'number') total = res.total;
    items.push(...batch);

    if (batch.length === 0) break;
    if (total !== undefined && items.length >= total) break;
    if (items.length >= maxItems) {
      // The cap is enforced on the returned array, not just the loop: without
      // the slice, a page that pushed the running count past maxItems still
      // shipped its whole page, so maxItems: 500 with pageSize: 200 returned
      // 600 items — one whole page more than the cap promised.
      return { items: items.slice(0, maxItems), total: total ?? items.length, truncated: true };
    }
  }

  return { items, total: total ?? items.length, truncated: false };
}

/**
 * Fold a package name to the form both sides of the join must agree on.
 *
 * The report stores canonical, lower-case names; a lockfile carries whatever the
 * author wrote — `Newtonsoft.Json` in a NuGet `packages.lock.json`, `Typing-Extensions`
 * from a `pip freeze`. Joining those raw makes a vulnerable package report as
 * `clean: true`, which is the one answer this tool must never get wrong, so both
 * sides pass through here before a key is built.
 *
 * pypi additionally collapses runs of `.`, `-` and `_` to a single `-`: PEP 503
 * makes `typing_extensions` and `typing-extensions` the same distribution, so
 * folding them together is the correct comparison, not a lenient one.
 */
export function foldName(ecosystem: string | undefined, name: string): string {
  const lower = name.toLowerCase();
  return ecosystem === 'pypi' ? lower.replace(/[-_.]+/g, '-') : lower;
}

/** Ecosystems whose registry omits a trailing `.0` release segment more often than a lockfile does. */
const TRAILING_ZERO_ECOSYSTEMS = new Set(['pypi', 'nuget', 'maven']);

/**
 * Fold a version to the form both sides of the join must agree on.
 *
 * A raw string match misses versions that are the same release under a
 * different spelling: a NuGet pin of `4.5` against a registry row of `4.5.0`,
 * or a PyPI requirement of `1.0` against `1.0.0`. Conservative on purpose —
 * this only strips a leading `v`/`V` and lower-cases everywhere, and only
 * strips trailing `.0` segments on ecosystems where that spelling is common
 * (pypi, nuget, maven); npm, cargo and golang keep every segment, since a
 * dropped patch digit there is far more likely to be a real different release
 * than an equivalent spelling of the same one.
 */
export function canonicalVersion(ecosystem: string | undefined, v: string): string {
  let s = v.trim().replace(/^[vV]/, '').toLowerCase();
  if (TRAILING_ZERO_ECOSYSTEMS.has(String(ecosystem))) {
    const parts = s.split('.');
    while (parts.length > 1 && /^0+$/.test(parts[parts.length - 1])) parts.pop();
    s = parts.join('.');
  }
  return s;
}

/**
 * Join report rows onto the caller's dependency list by folded name @ version.
 *
 * The name side folds per `foldName`; the version side folds per
 * `canonicalVersion`, conservatively, so an equivalent spelling of the same
 * release still joins without risking a match against a version the project
 * does not actually have installed.
 */
export function matchPackages(
  report: readonly ReportItem[],
  packages: readonly InputPackage[],
  ecosystem?: string,
): { hits: ReportItem[]; devOf: Map<string, boolean> } {
  const devOf = new Map<string, boolean>();
  for (const p of packages) {
    const key = `${foldName(ecosystem, p.name)}@${canonicalVersion(ecosystem, p.version)}`;
    // A package present both as a dev and a prod dependency is prod: the
    // stricter classification wins, since it ships.
    const prior = devOf.get(key);
    const isDev = p.dev === true;
    devOf.set(key, prior === undefined ? isDev : prior && isDev);
  }
  const hits = report.filter((r) =>
    devOf.has(`${foldName(ecosystem, r.packageName)}@${canonicalVersion(ecosystem, r.version)}`),
  );
  return { hits, devOf };
}

/** Run `fn` over `items` with at most `limit` in flight. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Most advisory-detail lookups one check_dependencies call makes for fixed versions. */
export const MAX_REMEDIATION_LOOKUPS = 200;

/**
 * The (advisory, version) pairs to resolve, most severe first, capped. Past the
 * cap a finding keeps its advisory but reports no fixed version, which the
 * summary counts under `withoutFixedVersion`; the cap keeps a large tree from
 * turning one tool call into thousands of requests.
 */
export function remediationPairs(
  hits: readonly ReportItem[],
  cap = MAX_REMEDIATION_LOOKUPS,
): { pairs: Array<{ osvId: string; version: string }>; skipped: number } {
  const distinct = new Map<string, ReportItem>();
  for (const h of hits) {
    const key = `${h.osvId}@@${h.version}`;
    if (!distinct.has(key)) distinct.set(key, h);
  }
  const ordered = [...distinct.values()].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.cvssScore ?? 0) - (a.cvssScore ?? 0),
  );
  return {
    pairs: ordered.slice(0, cap).map((h) => ({ osvId: h.osvId, version: h.version })),
    skipped: Math.max(0, ordered.length - cap),
  };
}

export type RemediationLookup = {
  fixedVersion: string | null;
  cwes: string[];
  owasp: string[];
  skills: string[];
  severity?: string;
  summary?: string;
  /** The advisory's OSV `aliases`, used to fold duplicate records of one flaw. */
  aliases?: string[];
};

/**
 * Fetch the remediation block for each (advisory, installed version) pair.
 *
 * The installed version is passed through because the endpoint is release-line
 * aware: for `@hono/node-server` 1.19.14 it answers 1.19.15 rather than the 2.x
 * fix. Results are cached per pair, so N affected versions of one package cost
 * one call each rather than one per finding, and a failed lookup degrades to a
 * null fixed version rather than failing the whole scan.
 */
export async function fetchRemediations(
  client: DependablyClient,
  pairs: ReadonlyArray<{ osvId: string; version?: string }>,
  concurrency = 8,
): Promise<Map<string, RemediationLookup>> {
  const seen = new Map<string, { osvId: string; version?: string }>();
  for (const p of pairs) seen.set(`${p.osvId}@@${p.version ?? ''}`, p);
  const unique = [...seen.entries()];

  const results = await mapLimit(unique, concurrency, async ([, p]) => {
    try {
      const detail = (await client.get(`/api/v1/vulnerabilities/${encodeURIComponent(p.osvId)}`, {
        version: p.version,
      })) as Record<string, unknown> | null;
      return summarizeRemediation(detail);
    } catch {
      // A detail lookup can 404 when the advisory does not touch the org, or
      // fail transiently. Neither should sink the scan: report the finding
      // without a fixed version and let the caller see it as unresolved.
      return { fixedVersion: null, cwes: [], owasp: [], skills: [] } satisfies RemediationLookup;
    }
  });

  const out = new Map<string, RemediationLookup>();
  unique.forEach(([key], i) => out.set(key, results[i]));
  return out;
}

export function summarizeRemediation(detail: Record<string, unknown> | null): RemediationLookup {
  const remediation = (detail?.remediation ?? {}) as Record<string, unknown>;
  const entries = Array.isArray(remediation.entries) ? (remediation.entries as Record<string, unknown>[]) : [];
  const dbSpecific = (detail?.databaseSpecific ?? {}) as Record<string, unknown>;
  const fixed = remediation.fixedVersion;
  return {
    fixedVersion: typeof fixed === 'string' && fixed.length > 0 ? fixed : null,
    cwes: Array.isArray(remediation.cweIds) ? (remediation.cweIds as string[]) : [],
    owasp: [...new Set(entries.map((e) => e.owaspId).filter((v): v is string => typeof v === 'string'))],
    skills: [...new Set(entries.map((e) => e.skillId).filter((v): v is string => typeof v === 'string'))],
    // Normalized here, not passed through: the detail endpoint serves GHSA's raw
    // `database_specific` vocabulary ("MODERATE") while the report endpoint serves
    // the normalized one ("MEDIUM"). Two spellings of one severity across sibling
    // tools is a filter that silently misses findings.
    severity: typeof dbSpecific.severity === 'string' ? normalizeSeverity(dbSpecific.severity) : undefined,
    summary: typeof detail?.summary === 'string' ? detail.summary : undefined,
    aliases: Array.isArray(detail?.aliases)
      ? (detail.aliases as unknown[]).filter((v): v is string => typeof v === 'string' && v.length > 0)
      : [],
  };
}

/** Turn one report row plus its remediation into the advisory we report. */
function toAdvisory(hit: ReportItem, rem: RemediationLookup | undefined): Advisory {
  return {
    osvId: hit.osvId,
    severity: normalizeSeverity(hit.severity),
    cvss: hit.cvssScore ?? null,
    epss: hit.epssScore ?? null,
    kev: hit.isKev === true,
    summary: hit.summary ?? '',
    fixedVersion: rem?.fixedVersion ?? null,
    ...(rem?.cwes.length ? { cwes: rem.cwes } : {}),
    ...(rem?.owasp.length ? { owasp: rem.owasp } : {}),
    ...(rem?.skills.length ? { skills: rem.skills } : {}),
  };
}

/**
 * The version to bump to: the highest fixed version across the package's
 * advisories, or null when the installed version already clears them all.
 * The ceiling matters because several advisories are explicit incomplete-fix
 * follow-ups, where the lowest fix leaves the rest open.
 */
function bumpTarget(installed: string, advisories: readonly Advisory[], ecosystem?: string): string | null {
  const fixes = advisories.map((a) => a.fixedVersion).filter((v): v is string => !!v);
  const ceiling = maxVersion(fixes, ecosystem);
  if (!ceiling) return null;
  return gte(installed, ceiling, ecosystem) ? null : ceiling;
}

function bySeverityThenScore(a: Advisory, b: Advisory): number {
  return severityRank(b.severity) - severityRank(a.severity) || (b.cvss ?? 0) - (a.cvss ?? 0);
}

function byWorstAdvisory(a: Finding, b: Finding): number {
  return (
    severityRank(b.advisories[0]?.severity) - severityRank(a.advisories[0]?.severity) ||
    b.advisories.length - a.advisories.length ||
    a.package.localeCompare(b.package)
  );
}

/**
 * Group matched rows into one finding per package, with a single bump target.
 *
 * The grouping key must be built the same way `matchPackages` built `devOf`'s
 * keys — folded name, canonicalized version — or a report row whose raw
 * spelling differs from the caller's lockfile (a different case, a different
 * PEP 503 separator run) looks up a `devOf` entry that was never written for
 * it and silently falls back to "runtime", regardless of what the caller
 * actually said. `ecosystem` is threaded through for both the fold and the
 * rpm-aware bump-target ordering (see `semver.ts`).
 */
export function buildFindings(
  hits: readonly ReportItem[],
  devOf: ReadonlyMap<string, boolean>,
  remediations: ReadonlyMap<string, RemediationLookup>,
  ecosystem?: string,
): Finding[] {
  const byPackage = new Map<string, Finding>();
  const aliasesById = new Map<string, readonly string[]>();

  for (const hit of hits) {
    const key = `${foldName(ecosystem, hit.packageName)}@${canonicalVersion(ecosystem, hit.version)}`;
    const finding = byPackage.get(key) ?? {
      package: hit.packageName,
      installed: hit.version,
      dev: devOf.get(key) === true,
      bumpTo: null,
      advisories: [],
    };
    const rem = remediations.get(`${hit.osvId}@@${hit.version}`);
    // Newer servers list each report row's OSV aliases; the advisory detail
    // carries them too, but its lookup can 404 for an advisory the org's
    // registry does not record.
    const reported = Array.isArray(hit.aliases)
      ? hit.aliases.filter((v): v is string => typeof v === 'string' && v.length > 0)
      : [];
    const aliases = [...new Set([...(aliasesById.get(hit.osvId) ?? []), ...reported, ...(rem?.aliases ?? [])])];
    if (aliases.length) aliasesById.set(hit.osvId, aliases);
    finding.advisories.push(toAdvisory(hit, rem));
    byPackage.set(key, finding);
  }

  for (const finding of byPackage.values()) {
    finding.advisories = collapseAliases(
      finding.advisories,
      (osvId) => aliasesById.get(osvId) ?? [],
      ecosystem,
    );
    finding.advisories.sort(bySeverityThenScore);
    finding.bumpTo = bumpTarget(finding.installed, finding.advisories, ecosystem);
  }

  return [...byPackage.values()].sort(byWorstAdvisory);
}

/**
 * Fold the records of one flaw into one advisory.
 *
 * OSV publishes the same PyPI flaw as a GHSA and as a PYSEC record, and the
 * report lists both, so counting rows counted the flaw twice — and the PYSEC
 * copy usually carries no severity, so it also inflated "unknown". Two
 * advisories are the same flaw when one names the other, or both name the same
 * id (typically the CVE), in their OSV `aliases`.
 *
 * Only records from different databases fold together. A database does not
 * publish one flaw twice, but an incomplete-fix follow-up does list its
 * predecessor as an alias (lodash's GHSA-r5fr-rjxr-66jc names
 * GHSA-35jh-r3h4-6jhm and CVE-2021-23337), and folding those would report two
 * flaws, with different fixes, as one.
 *
 * The kept entry is the most informative record (highest severity, then one
 * with a summary, then a GHSA); the rest are listed in its `aliases`, and the
 * scores and fix are the most severe and highest of the group so no folded
 * record's facts are lost.
 */
export function collapseAliases(
  advisories: readonly Advisory[],
  aliasesOf: (osvId: string) => readonly string[],
  ecosystem?: string,
): Advisory[] {
  // Union-find over the advisory ids only. Two advisories are joined when one
  // names the other, or both name a shared id (a CVE), and the two groups hold
  // no advisory from the same database.
  const ids = [...new Set(advisories.map((a) => a.osvId))];
  const parent = new Map<string, string>(ids.map((id) => [id, id]));
  const databases = new Map<string, Set<string>>(ids.map((id) => [id, new Set([databaseOf(id)])]));
  const find = (x: string): string => {
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root)!;
    parent.set(x, root);
    return root;
  };
  const union = (a: string, b: string): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra === rb) return;
    const da = databases.get(ra)!;
    const db = databases.get(rb)!;
    if ([...da].some((d) => db.has(d))) return;
    parent.set(ra, rb);
    databases.set(rb, new Set([...da, ...db]));
  };

  const named = new Map<string, Set<string>>();
  for (const a of advisories) {
    const names = new Set([a.osvId, ...(a.aliases ?? []), ...aliasesOf(a.osvId)]);
    named.set(a.osvId, new Set([...(named.get(a.osvId) ?? []), ...names]));
  }
  // Direct mentions are joined before shared ids, so a PYSEC record that names
  // one GHSA attaches to that GHSA whatever order the advisories arrive in,
  // rather than to whichever GHSA sharing its CVE happened to come first.
  const pairs = (linked: (ni: Set<string>, nj: Set<string>, i: string, j: string) => boolean): void => {
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        if (linked(named.get(ids[i])!, named.get(ids[j])!, ids[i], ids[j])) union(ids[i], ids[j]);
      }
    }
  };
  // Each pass ties two records only when the link is unambiguous: each is the
  // other's sole candidate in the other's database. Union-find over every
  // candidate would let input order decide which twin a third record joined.
  const mentions = (i: string, j: string): boolean => named.get(i)!.has(j) || named.get(j)!.has(i);
  const sole = (link: (i: string, j: string) => boolean) => (i: string, j: string): boolean => {
    if (!link(i, j)) return false;
    const ci = ids.filter((k) => k !== i && databaseOf(k) === databaseOf(j) && link(i, k));
    const cj = ids.filter((k) => k !== j && databaseOf(k) === databaseOf(i) && link(j, k));
    return ci.length === 1 && cj.length === 1;
  };
  pairs((_ni, _nj, i, j) => sole(mentions)(i, j));
  // A record naming another advisory of its own database is an incomplete-fix
  // follow-up, and it lists its predecessor's ids (the old CVE) beside its own.
  // Only the ids it does not inherit can tie it to another record; when a
  // predecessor is not in this set its ids are unknown, so a shared id ties
  // the follow-up to nothing. Counting one flaw twice is the safe direction.
  const shareable = new Map<string, Set<string> | null>();
  for (const id of ids) {
    const names = named.get(id)!;
    const predecessors = [...names].filter((n) => n !== id && databaseOf(n) === databaseOf(id) && databaseOf(n) !== 'CVE');
    if (predecessors.length === 0) {
      shareable.set(id, names);
    } else if (predecessors.some((p) => !named.has(p))) {
      shareable.set(id, null);
    } else {
      const inherited = new Set(predecessors.flatMap((p) => [...named.get(p)!]));
      shareable.set(id, new Set([...names].filter((n) => !inherited.has(n))));
    }
  }
  const shares = (i: string, j: string): boolean => {
    const si = shareable.get(i);
    const sj = shareable.get(j);
    return !!si && !!sj && [...si].some((n) => n !== i && n !== j && sj.has(n));
  };
  pairs((_ni, _nj, i, j) => sole(shares)(i, j));

  const groups = new Map<string, Advisory[]>();
  for (const a of advisories) {
    const root = find(a.osvId);
    const group = groups.get(root) ?? [];
    // The same id reached twice (registry report and live check) is one record.
    if (!group.some((g) => g.osvId === a.osvId)) group.push(a);
    groups.set(root, group);
  }

  return [...groups.values()].map((group) => (group.length === 1 ? group[0] : mergeGroup(group, ecosystem)));
}

/** The database an advisory id comes from: its prefix (GHSA, PYSEC, CVE, MAL, …). */
function databaseOf(id: string): string {
  return id.split('-')[0].toUpperCase();
}

function informativeness(a: Advisory): number {
  return severityRank(a.severity) * 4 + (a.summary ? 2 : 0) + (a.osvId.startsWith('GHSA-') ? 1 : 0);
}

function mergeGroup(group: readonly Advisory[], ecosystem?: string): Advisory {
  const [primary, ...rest] = [...group].sort((x, y) => informativeness(y) - informativeness(x));
  const max = (values: Array<number | null>): number | null => {
    const known = values.filter((v): v is number => typeof v === 'number');
    return known.length ? Math.max(...known) : null;
  };
  const union = (pick: (a: Advisory) => string[] | undefined): string[] | undefined => {
    const all = [...new Set(group.flatMap((a) => pick(a) ?? []))];
    return all.length ? all : undefined;
  };
  const fixes = group.map((a) => a.fixedVersion).filter((v): v is string => !!v);
  const merged: Advisory = {
    ...primary,
    cvss: max(group.map((a) => a.cvss)),
    epss: max(group.map((a) => a.epss)),
    kev: group.some((a) => a.kev),
    summary: primary.summary || rest.find((a) => a.summary)?.summary || '',
    fixedVersion: maxVersion(fixes, ecosystem) ?? null,
    aliases: [...new Set(rest.map((a) => a.osvId).concat(primary.aliases ?? []))].sort(),
  };
  const cwes = union((a) => a.cwes);
  const owasp = union((a) => a.owasp);
  const skills = union((a) => a.skills);
  if (cwes) merged.cwes = cwes; else delete merged.cwes;
  if (owasp) merged.owasp = owasp; else delete merged.owasp;
  if (skills) merged.skills = skills; else delete merged.skills;
  return merged;
}

type SeverityCounts = { critical: number; high: number; medium: number; low: number; unknown: number };

const SEVERITY_BUCKET: Record<string, keyof SeverityCounts> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

export function summarize(findings: readonly Finding[], checked: number) {
  const bySeverity: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let advisories = 0;
  let kev = 0;
  let runtime = 0;
  let devOnly = 0;
  let withoutFixedVersion = 0;

  for (const finding of findings) {
    for (const advisory of finding.advisories) {
      advisories++;
      bySeverity[SEVERITY_BUCKET[advisory.severity] ?? 'unknown']++;
      if (advisory.kev) kev++;
      if (!advisory.fixedVersion) withoutFixedVersion++;
      if (finding.dev) devOnly++;
      else runtime++;
    }
  }

  return {
    packagesChecked: checked,
    packagesAffected: findings.length,
    advisories,
    bySeverity,
    kev,
    runtime,
    devOnly,
    withoutFixedVersion,
  };
}

/** Drop the redundant and rarely-actionable fields from a raw report row. */
export function compactReportItem(item: ReportItem): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: item.packageName,
    version: item.version,
    osvId: item.osvId,
    severity: normalizeSeverity(item.severity),
  };
  if (item.cvssScore !== undefined && item.cvssScore !== null) out.cvss = item.cvssScore;
  if (item.epssScore !== undefined && item.epssScore !== null) out.epss = item.epssScore;
  if (item.isKev) out.kev = true;
  if (item.isKevRansomware) out.kevRansomware = true;
  if (item.summary) out.summary = item.summary;
  return out;
}

/**
 * Extract `{ name, version, dev }` from an npm `package-lock.json` (v2/v3).
 *
 * Exported for callers assembling the `packages` argument to `check_dependencies`,
 * which reads no files itself — see the design note in tools/vuln.ts. v1 lockfiles
 * have no `packages` map; they are refused with a message that names the fix rather
 * than silently scanning nothing.
 */
export function parseNpmLockfile(text: string): InputPackage[] {
  let lock: { packages?: Record<string, { name?: string; version?: string; dev?: boolean; link?: boolean }> };
  try {
    lock = JSON.parse(text);
  } catch {
    // Deliberately does not echo the underlying JSON error: V8 embeds the offending
    // bytes in it, which would turn this into a read oracle if the input ever came
    // from a path rather than from the caller's own memory.
    throw new Error('Could not parse lockfile: not valid JSON.');
  }
  if (!lock.packages) {
    throw new Error(
      'This looks like a lockfileVersion 1 package-lock.json, which has no "packages" map. Run `npm install` with npm 7+ to upgrade it, or pass the dependency list via the packages argument.',
    );
  }

  const out: InputPackage[] = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    // "" is the project itself; link entries point at a workspace already listed.
    if (!path || entry.link) continue;
    const name = entry.name ?? path.split('node_modules/').pop();
    if (!name || !entry.version) continue;
    out.push({ name, version: entry.version, dev: entry.dev === true });
  }
  return out;
}

/** A dependency no source could vouch for, so the scan cannot call it clean. */
export type Unverified = { name: string; version: string; reason: string };

export type LiveCheck = { hits: ReportItem[]; unverified: Unverified[]; checked: number };

/** Most dependencies a non-npm scan checks one by one against `/api/v1/lookup`. */
export const MAX_LIVE_LOOKUPS = 100;

/** npm's advisory severity vocabulary, mapped onto the report's. */
const NPM_SEVERITY: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
  info: 'UNKNOWN',
};

/** The first sentence of an error, so one unreachable advisory source does not flood the result. */
function shortReason(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  return message.split(/(?<=\.)\s/)[0].slice(0, 200);
}

/** npm's exact-version shape, the one the server's npm version parser accepts. */
const NPM_EXACT_VERSION = /^[vV]?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** Cargo, Hex and Terraform lockfiles pin a full SemVer `x.y.z`; a shorter form is a requirement. */
const SEMVER_EXACT_VERSION = /^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** A Go module version: `v` + SemVer, which covers pseudo-versions and `+incompatible`. A branch or commit is not one. */
const GO_EXACT_VERSION = /^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\+incompatible)?$/;

/** The server parses each numeric part as a 32-bit int; a larger one is unparseable there. */
const INT32_MAX = 2_147_483_647;

/**
 * rpm and apk versions use `~` (sorts before a release) and `^` (a snapshot),
 * so only whitespace, comparison operators, list separators and URL or
 * source-spec prefixes mark a non-version there.
 */
const NOT_A_DISTRO_VERSION = /[\s<>=|,]|:\/\/|^(git|file|link):/i;

/**
 * Range operators, wildcards, dist-tags, source specs, Maven/NuGet bracket
 * ranges and Gradle dynamic versions: none names one release. When the
 * instance is air-gapped, lookup accepts any explicit version without
 * resolving it upstream, so these must be caught here rather than come back
 * "found, no advisories".
 */
const RANGE_SYNTAX = /[\s^~*<>=|,[\]()]|\.\+$|^\+$/;
const DIST_TAG = /^(latest|next|release|x)$|^latest\./i;
const SOURCE_SPEC = /:\/\/|^(git|git\+[a-z]+|file|link|npm|workspace|github|portal):/i;

function isNotAVersion(version: string): boolean {
  return RANGE_SYNTAX.test(version) || DIST_TAG.test(version) || SOURCE_SPEC.test(version);
}

function numericPartsFit(match: RegExpExecArray | null): boolean {
  return !!match && [match[1], match[2], match[3]].every((n) => n.length <= 10 && Number(n) <= INT32_MAX);
}

/** True when `version` names one release that an advisory source can match exactly. */
export function isExactVersion(ecosystem: string, version: string): boolean {
  switch (ecosystem) {
    case 'npm':
      return numericPartsFit(NPM_EXACT_VERSION.exec(version));
    case 'cargo':
    case 'hex':
    case 'terraform':
      return numericPartsFit(SEMVER_EXACT_VERSION.exec(version));
    case 'golang':
      return numericPartsFit(GO_EXACT_VERSION.exec(version));
    case 'rpm':
    case 'apk':
      return !NOT_A_DISTRO_VERSION.test(version);
    default:
      return !isNotAVersion(version);
  }
}

export function uniquePackages(packages: readonly InputPackage[], ecosystem: string): InputPackage[] {
  const seen = new Map<string, InputPackage>();
  for (const p of packages) {
    const key = `${foldName(ecosystem, p.name)}@${canonicalVersion(ecosystem, p.version)}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  return [...seen.values()];
}

/**
 * What the npm bulk-advisory endpoint will look at. It skips, without saying
 * so, a name over npm's 214-character limit, a version over 256, and either
 * with a control character (dependably-community NpmAuditHandler.IsUsableName
 * / IsUsableVersion). A skipped pair comes back with no advisories, which reads
 * as clean, so such a pair is reported unverified and never sent. Within these
 * limits a round of 5000 pairs is under 2.5 MB, below the endpoint's 4 MiB
 * body cap, so one request per round always fits.
 */
const NPM_MAX_NAME = 214;
const NPM_MAX_VERSION = 256;
/** C0, DEL and C1, the characters .NET's char.IsControl matches. */
function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

function npmUnusable(p: InputPackage): string | null {
  if (p.name.length > NPM_MAX_NAME) return `npm package names are at most ${NPM_MAX_NAME} characters; the advisory endpoint skips longer ones`;
  if (p.version.length > NPM_MAX_VERSION) return `versions over ${NPM_MAX_VERSION} characters are skipped by the advisory endpoint`;
  if (hasControlChar(p.name) || hasControlChar(p.version)) return 'a control character in the name or version; the advisory endpoint skips it';
  return null;
}

/**
 * Check every npm dependency against live OSV data through the instance's npm
 * bulk-advisory endpoint (the one `npm audit` calls). Unlike the registry
 * report, this covers versions the registry has never served.
 *
 * The endpoint lists an advisory under a name only when it affects one of the
 * versions requested for that name, and its `vulnerable_versions` is usually a
 * semver range rather than the requested version. So each request carries one
 * version per name: everything listed under a name then applies to exactly that
 * version, with no range matching on this side. A lockfile holding several
 * versions of one package costs one extra request per extra version.
 *
 * The endpoint answers 503 rather than a partial list when it cannot vouch for
 * the whole tree, so a failed round leaves that round's dependencies unverified.
 */
export async function liveCheckNpm(client: DependablyClient, packages: readonly InputPackage[]): Promise<LiveCheck> {
  const unverified: Unverified[] = [];
  const byName = new Map<string, string[]>();
  for (const p of packages) {
    const unusable = npmUnusable(p);
    if (unusable) {
      unverified.push({ name: p.name, version: p.version, reason: unusable });
      continue;
    }
    const versions = byName.get(p.name) ?? [];
    if (!versions.includes(p.version)) versions.push(p.version);
    byName.set(p.name, versions);
  }
  const rounds: Array<Map<string, string>> = [];
  for (const [name, versions] of byName) {
    for (const [i, version] of versions.entries()) {
      if (i === rounds.length) rounds.push(new Map());
      rounds[i].set(name, version);
    }
  }

  const hits: ReportItem[] = [];
  let checked = 0;
  for (const round of rounds) {
    const failed = (reason: string) => {
      for (const [name, version] of round) unverified.push({ name, version, reason });
    };
    let res: unknown;
    try {
      res = await client.post(
        '/npm/-/npm/v1/security/advisories/bulk',
        Object.fromEntries([...round].map(([name, version]) => [name, [version]])),
      );
    } catch (e) {
      failed(`live npm advisory check failed: ${shortReason(e)}`);
      continue;
    }
    if (res === null || typeof res !== 'object' || Array.isArray(res)) {
      failed('live npm advisory check returned an unexpected body');
      continue;
    }
    const idless = new Set<string>();
    for (const [name, advisories] of Object.entries(res as Record<string, unknown>)) {
      const version = round.get(name);
      if (version === undefined || !Array.isArray(advisories)) continue;
      for (const raw of advisories as Record<string, unknown>[]) {
        if (typeof raw?.id !== 'string') {
          if (!idless.has(name)) unverified.push({ name, version, reason: 'live npm advisory check returned an advisory without an id' });
          idless.add(name);
          continue;
        }
        const cvss = (raw.cvss as { score?: unknown } | undefined)?.score;
        hits.push({
          packageName: name,
          version,
          osvId: raw.id,
          severity: NPM_SEVERITY[String(raw.severity)] ?? 'UNKNOWN',
          cvssScore: typeof cvss === 'number' ? cvss : null,
          summary: typeof raw.title === 'string' ? raw.title : '',
        });
      }
    }
    checked += round.size - idless.size;
  }
  return { hits, unverified, checked };
}

type LookupAdvisory = { id?: unknown; severity?: unknown; cvssScore?: unknown; epss?: unknown; isKev?: unknown; summary?: unknown };

/**
 * Check dependencies one at a time against `/api/v1/lookup`, which resolves a
 * version against live OSV data without ingesting anything. Bounded: past
 * `cap` dependencies, the rest are reported unverified rather than making the
 * call run for minutes.
 */
export async function liveCheckByLookup(
  client: DependablyClient,
  ecosystem: string,
  packages: readonly InputPackage[],
  cap = MAX_LIVE_LOOKUPS,
): Promise<LiveCheck> {
  const toCheck = packages.slice(0, cap);
  const unverified: Unverified[] = packages.slice(cap).map((p) => ({
    name: p.name,
    version: p.version,
    reason: `over the ${cap}-dependency live-check limit for one call; check the rest in a second call`,
  }));
  const hits: ReportItem[] = [];
  let checked = 0;

  const results = await mapLimit(toCheck, 8, async (p) => {
    try {
      return { p, res: (await client.get('/api/v1/lookup', { ecosystem, name: p.name, version: p.version })) as Record<string, unknown> | null };
    } catch (e) {
      return { p, error: shortReason(e) };
    }
  });

  for (const r of results) {
    if ('error' in r) {
      unverified.push({ name: r.p.name, version: r.p.version, reason: `live lookup failed: ${r.error}` });
      continue;
    }
    const vulns = (r.res?.vulnerabilities ?? null) as { scored?: unknown; unscored?: unknown; available?: unknown } | null;
    if (r.res?.found === false) {
      unverified.push({ name: r.p.name, version: r.p.version, reason: 'not found upstream' });
      continue;
    }
    if (!vulns || vulns.available === false) {
      unverified.push({ name: r.p.name, version: r.p.version, reason: 'the advisory source was unavailable' });
      continue;
    }
    checked++;
    // Lookup reports malware apart from vulnerabilities: MAL- ids appear only
    // under malware.advisoryIds, never in scored or unscored.
    const malware = (r.res?.malware ?? null) as { advisoryIds?: unknown } | null;
    for (const id of Array.isArray(malware?.advisoryIds) ? malware.advisoryIds : []) {
      if (typeof id !== 'string') continue;
      hits.push({
        packageName: r.p.name,
        version: r.p.version,
        osvId: id,
        severity: 'CRITICAL',
        cvssScore: null,
        summary: 'Malicious package: an OpenSSF malicious-packages advisory names this version.',
      });
    }
    const all = [
      ...(Array.isArray(vulns.scored) ? vulns.scored : []),
      ...(Array.isArray(vulns.unscored) ? vulns.unscored : []),
    ] as LookupAdvisory[];
    for (const a of all) {
      if (typeof a?.id !== 'string') continue;
      hits.push({
        packageName: r.p.name,
        version: r.p.version,
        osvId: a.id,
        severity: typeof a.severity === 'string' ? a.severity : 'UNKNOWN',
        cvssScore: typeof a.cvssScore === 'number' ? a.cvssScore : null,
        epssScore: typeof a.epss === 'number' ? a.epss : null,
        isKev: a.isKev === true,
        summary: typeof a.summary === 'string' ? a.summary : '',
      });
    }
  }
  return { hits, unverified, checked };
}

/**
 * Cover what the registry report cannot see.
 *
 * The report lists only versions the registry has uploaded or proxied, so a
 * dependency it has never served is simply absent from it, and joining against
 * the report alone answered "clean" for a vulnerable version. npm is checked in
 * full through the bulk endpoint; other ecosystems check, one by one, each
 * dependency the report had nothing on; ecosystems with no live source are
 * unverified. Returns live hits not already in `reportHits`.
 */
export async function liveCoverage(
  client: DependablyClient,
  ecosystem: string,
  packages: readonly InputPackage[],
  reportHits: readonly ReportItem[],
  lookupEcosystems: readonly string[],
): Promise<LiveCheck> {
  const all = uniquePackages(packages, ecosystem);
  // A range, tag or git/file/alias spec cannot be checked: the server matches
  // advisories against one exact version, and answers a string it cannot parse
  // with "no advisories", which would read as clean.
  const inexact = all.filter((p) => !isExactVersion(ecosystem, p.version));
  const unique = all.filter((p) => isExactVersion(ecosystem, p.version));
  const inexactUnverified: Unverified[] = inexact.map((p) => ({
    name: p.name,
    version: p.version,
    reason: 'not an exact version (a range, tag, or git/file/alias spec); pass the resolved version from the lockfile',
  }));
  const keyOf = (name: string, version: string) => `${foldName(ecosystem, name)}@${canonicalVersion(ecosystem, version)}`;
  const reported = new Set(reportHits.map((h) => keyOf(h.packageName, h.version)));

  let live: LiveCheck;
  if (ecosystem === 'npm') {
    live = await liveCheckNpm(client, unique);
  } else if (lookupEcosystems.includes(ecosystem)) {
    live = await liveCheckByLookup(client, ecosystem, unique.filter((p) => !reported.has(keyOf(p.name, p.version))));
  } else {
    const reason = `no live advisory source for ${ecosystem}; only versions this registry has served are covered`;
    live = {
      hits: [],
      unverified: unique.filter((p) => !reported.has(keyOf(p.name, p.version))).map((p) => ({ name: p.name, version: p.version, reason })),
      checked: 0,
    };
  }

  const seen = new Set(reportHits.map((h) => `${keyOf(h.packageName, h.version)}#${h.osvId}`));
  const fresh = live.hits.filter((h) => !seen.has(`${keyOf(h.packageName, h.version)}#${h.osvId}`));
  return { ...live, hits: fresh, unverified: [...inexactUnverified, ...live.unverified] };
}

/** Most explicit affected versions compact output lists for an entry that has no ranges. */
const MAX_COMPACT_VERSIONS = 50;

/**
 * Shape an advisory detail (`GET /api/v1/vulnerabilities/{osvId}`) for reading.
 *
 * The raw OSV record lists every affected version as a string — over four
 * hundred for one Django advisory — which costs thousands of tokens and says no
 * more than the ranges beside it. Compact keeps the ranges as
 * `introduced`/`fixed`/`lastAffected` pairs, the references as URLs, and every
 * field that carries a judgement (severity, CWE, remediation, KEV, EPSS).
 */
export function compactVulnerability(detail: Record<string, unknown>): Record<string, unknown> {
  const { affected, references, databaseSpecific, schemaVersion: _schema, credits: _credits, related: _related, ...rest } = detail;
  const out: Record<string, unknown> = { ...rest };

  if (Array.isArray(affected)) {
    out.affected = (affected as Record<string, unknown>[]).map((a) => {
      const pkg = (a?.package ?? {}) as Record<string, unknown>;
      const ranges = Array.isArray(a?.ranges) ? (a.ranges as Record<string, unknown>[]) : [];
      const versions = Array.isArray(a?.versions) ? (a.versions as unknown[]) : [];
      const entry: Record<string, unknown> = {
        package: { ecosystem: pkg.ecosystem, name: pkg.name },
        ranges: ranges.map((r) => ({
          type: r?.type,
          ...(typeof r?.repo === 'string' && r.repo ? { repo: r.repo } : {}),
          ...collapseEvents(r?.events),
        })),
        versionCount: versions.length,
      };
      // With no range to read, the explicit list is the only record of what is affected.
      if (ranges.length === 0 && versions.length > 0) {
        entry.versions = versions.slice(0, MAX_COMPACT_VERSIONS);
        if (versions.length > MAX_COMPACT_VERSIONS) entry.versionsTruncated = true;
      }
      return entry;
    });
  }
  if (Array.isArray(references)) {
    out.references = (references as Record<string, unknown>[])
      .map((r) => r?.url)
      .filter((u): u is string => typeof u === 'string');
  }
  if (databaseSpecific && typeof databaseSpecific === 'object') {
    const ds = databaseSpecific as Record<string, unknown>;
    const kept = Object.fromEntries(
      Object.entries({ severity: ds.severity, cwe_ids: ds.cwe_ids }).filter(([, v]) => v !== undefined),
    );
    if (Object.keys(kept).length) out.databaseSpecific = kept;
  }
  return out;
}

/** OSV range events (`[{introduced}, {fixed}]`, null-padded) folded into one introduced/fixed list. */
function collapseEvents(events: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (!Array.isArray(events)) return out;
  for (const e of events as Record<string, unknown>[]) {
    for (const key of ['introduced', 'fixed', 'lastAffected', 'limit']) {
      const v = e?.[key];
      if (typeof v !== 'string' || v.length === 0) continue;
      const values = out[key] ?? [];
      values.push(v);
      out[key] = values;
    }
  }
  return out;
}
