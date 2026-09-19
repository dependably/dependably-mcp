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
  let total = 0;

  for (let page = 1; ; page++) {
    const res = (await client.get('/api/v1/vuln-report', {
      ecosystem: opts.ecosystem,
      limit: pageSize,
      page,
    })) as { items?: ReportItem[]; total?: number } | null;

    const batch = res?.items ?? [];
    total = res?.total ?? batch.length;
    items.push(...batch);

    if (batch.length === 0) break;
    if (items.length >= total) break;
    if (items.length >= maxItems) return { items, total, truncated: true };
  }

  return { items, total, truncated: false };
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

/**
 * Join report rows onto the caller's dependency list by folded name @ version.
 *
 * Versions stay exact. A lockfile pin and an advisory's affected version are both
 * concrete releases, and folding them would risk matching a version the project
 * does not actually have installed.
 */
export function matchPackages(
  report: readonly ReportItem[],
  packages: readonly InputPackage[],
  ecosystem?: string,
): { hits: ReportItem[]; devOf: Map<string, boolean> } {
  const devOf = new Map<string, boolean>();
  for (const p of packages) {
    const key = `${foldName(ecosystem, p.name)}@${p.version}`;
    // A package present both as a dev and a prod dependency is prod: the
    // stricter classification wins, since it ships.
    const prior = devOf.get(key);
    const isDev = p.dev === true;
    devOf.set(key, prior === undefined ? isDev : prior && isDev);
  }
  const hits = report.filter((r) => devOf.has(`${foldName(ecosystem, r.packageName)}@${r.version}`));
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
function bumpTarget(installed: string, advisories: readonly Advisory[]): string | null {
  const fixes = advisories.map((a) => a.fixedVersion).filter((v): v is string => !!v);
  const ceiling = maxVersion(fixes);
  if (!ceiling) return null;
  return gte(installed, ceiling) ? null : ceiling;
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

/** Group matched rows into one finding per package, with a single bump target. */
export function buildFindings(
  hits: readonly ReportItem[],
  devOf: ReadonlyMap<string, boolean>,
  remediations: ReadonlyMap<string, RemediationLookup>,
): Finding[] {
  const byPackage = new Map<string, Finding>();

  for (const hit of hits) {
    const key = `${hit.packageName}@${hit.version}`;
    const finding = byPackage.get(key) ?? {
      package: hit.packageName,
      installed: hit.version,
      dev: devOf.get(key) === true,
      bumpTo: null,
      advisories: [],
    };
    finding.advisories.push(toAdvisory(hit, remediations.get(`${hit.osvId}@@${hit.version}`)));
    byPackage.set(key, finding);
  }

  for (const finding of byPackage.values()) {
    finding.advisories.sort(bySeverityThenScore);
    finding.bumpTo = bumpTarget(finding.installed, finding.advisories);
  }

  return [...byPackage.values()].sort(byWorstAdvisory);
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
