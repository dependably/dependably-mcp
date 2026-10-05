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
    if (rem?.aliases?.length) aliasesById.set(hit.osvId, rem.aliases);
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
 * id (typically the CVE), in their OSV `aliases`. The kept entry is the most
 * informative record (highest severity, then one with a summary, then a GHSA);
 * the rest are listed in its `aliases`, and the scores and fix are the most
 * severe and highest of the group so no folded record's facts are lost.
 */
export function collapseAliases(
  advisories: readonly Advisory[],
  aliasesOf: (osvId: string) => readonly string[],
  ecosystem?: string,
): Advisory[] {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while (parent.has(root) && parent.get(root) !== root) root = parent.get(root)!;
    parent.set(x, root);
    return root;
  };
  const union = (a: string, b: string): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  for (const a of advisories) {
    parent.set(a.osvId, find(a.osvId));
    for (const alias of [...(a.aliases ?? []), ...aliasesOf(a.osvId)]) union(a.osvId, alias);
  }

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

function uniquePackages(packages: readonly InputPackage[], ecosystem: string): InputPackage[] {
  const seen = new Map<string, InputPackage>();
  for (const p of packages) {
    const key = `${foldName(ecosystem, p.name)}@${canonicalVersion(ecosystem, p.version)}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  return [...seen.values()];
}

/**
 * Check every npm dependency against live OSV data in one request, through the
 * instance's npm bulk-advisory endpoint (the one `npm audit` calls). Unlike the
 * registry report, this covers versions the registry has never served. The
 * endpoint answers 503 rather than a partial list when it cannot vouch for the
 * whole tree, so any failure leaves every dependency unverified.
 */
export async function liveCheckNpm(client: DependablyClient, packages: readonly InputPackage[]): Promise<LiveCheck> {
  const requested = new Map<string, Set<string>>();
  for (const p of packages) {
    const versions = requested.get(p.name) ?? new Set<string>();
    versions.add(p.version);
    requested.set(p.name, versions);
  }
  const body = Object.fromEntries([...requested].map(([name, versions]) => [name, [...versions]]));

  let res: unknown;
  try {
    res = await client.post('/npm/-/npm/v1/security/advisories/bulk', body);
  } catch (e) {
    const reason = `live npm advisory check failed: ${shortReason(e)}`;
    return { hits: [], unverified: packages.map((p) => ({ name: p.name, version: p.version, reason })), checked: 0 };
  }
  if (res === null || typeof res !== 'object' || Array.isArray(res)) {
    const reason = 'live npm advisory check returned an unexpected body';
    return { hits: [], unverified: packages.map((p) => ({ name: p.name, version: p.version, reason })), checked: 0 };
  }

  const hits: ReportItem[] = [];
  for (const [name, advisories] of Object.entries(res as Record<string, unknown>)) {
    const versions = requested.get(name);
    if (!versions || !Array.isArray(advisories)) continue;
    for (const raw of advisories as Record<string, unknown>[]) {
      if (typeof raw?.id !== 'string') continue;
      const range = typeof raw.vulnerable_versions === 'string' ? raw.vulnerable_versions : '*';
      const affected = range === '*' ? null : new Set(range.split('||').map((v) => v.trim()));
      const cvss = (raw.cvss as { score?: unknown } | undefined)?.score;
      for (const version of versions) {
        if (affected && !affected.has(version)) continue;
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
  }
  return { hits, unverified: [], checked: packages.length };
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
  const unique = uniquePackages(packages, ecosystem);
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
  return { ...live, hits: fresh };
}

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
      return {
        package: { ecosystem: pkg.ecosystem, name: pkg.name },
        ranges: ranges.map((r) => ({ type: r?.type, ...collapseEvents(r?.events) })),
        versionCount: Array.isArray(a?.versions) ? a.versions.length : 0,
      };
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
      if (typeof v === 'string' && v.length > 0) (out[key] ??= []).push(v);
    }
  }
  return out;
}
