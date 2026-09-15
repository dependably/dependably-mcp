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
 * tool call instead of dozens. See docs/api-asks.md for the server-side changes
 * that would let this collapse into a single request.
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

/** Join report rows onto the caller's dependency list by exact name@version. */
export function matchPackages(
  report: readonly ReportItem[],
  packages: readonly InputPackage[],
): { hits: ReportItem[]; devOf: Map<string, boolean> } {
  const devOf = new Map<string, boolean>();
  for (const p of packages) {
    const key = `${p.name}@${p.version}`;
    // A package present both as a dev and a prod dependency is prod: the
    // stricter classification wins, since it ships.
    const prior = devOf.get(key);
    const isDev = p.dev === true;
    devOf.set(key, prior === undefined ? isDev : prior && isDev);
  }
  const hits = report.filter((r) => devOf.has(`${r.packageName}@${r.version}`));
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
    severity: typeof dbSpecific.severity === 'string' ? dbSpecific.severity : undefined,
    summary: typeof detail?.summary === 'string' ? detail.summary : undefined,
  };
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
    const rem = remediations.get(`${hit.osvId}@@${hit.version}`);
    let finding = byPackage.get(key);
    if (!finding) {
      finding = {
        package: hit.packageName,
        installed: hit.version,
        dev: devOf.get(key) === true,
        bumpTo: null,
        advisories: [],
      };
      byPackage.set(key, finding);
    }
    finding.advisories.push({
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
    });
  }

  for (const finding of byPackage.values()) {
    // The bump target is the highest fixed version across the package's
    // advisories: several of these advisories are explicit incomplete-fix
    // follow-ups, so the lowest fix does not clear the rest.
    const fixes = finding.advisories.map((a) => a.fixedVersion).filter((v): v is string => !!v);
    const ceiling = maxVersion(fixes);
    finding.bumpTo = ceiling && !gte(finding.installed, ceiling) ? ceiling : null;
    finding.advisories.sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.cvss ?? 0) - (a.cvss ?? 0),
    );
  }

  return [...byPackage.values()].sort((a, b) => {
    const as = severityRank(a.advisories[0]?.severity);
    const bs = severityRank(b.advisories[0]?.severity);
    return bs - as || b.advisories.length - a.advisories.length || a.package.localeCompare(b.package);
  });
}

export function summarize(findings: readonly Finding[], checked: number) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let advisories = 0;
  let kev = 0;
  let prod = 0;
  let dev = 0;
  let unfixable = 0;

  for (const f of findings) {
    for (const a of f.advisories) {
      advisories++;
      if (a.kev) kev++;
      if (f.dev) dev++;
      else prod++;
      if (!a.fixedVersion) unfixable++;
      switch (a.severity) {
        case 'CRITICAL':
          counts.critical++;
          break;
        case 'HIGH':
          counts.high++;
          break;
        case 'MEDIUM':
          counts.medium++;
          break;
        case 'LOW':
          counts.low++;
          break;
        default:
          counts.unknown++;
      }
    }
  }

  return {
    packagesChecked: checked,
    packagesAffected: findings.length,
    advisories,
    bySeverity: counts,
    kev,
    runtime: prod,
    devOnly: dev,
    withoutFixedVersion: unfixable,
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
