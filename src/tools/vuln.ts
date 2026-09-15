import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';
import {
  buildFindings,
  fetchRemediations,
  fetchReport,
  matchPackages,
  summarize,
  summarizeRemediation,
  mapLimit,
} from '../vuln.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo']);

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

/**
 * Design note — why this tool takes a dependency list rather than a path.
 *
 * Reading the caller's lockfile would be more convenient, and an earlier draft did
 * exactly that behind a DEPENDABLY_PROJECT_ROOT opt-in. It was removed: only the
 * import tools read local files, and keeping that the whole rule is worth more than
 * the convenience. Two concrete reasons, beyond the general principle:
 *
 *  - Every host that could configure such a root (Claude Code, a CLI launcher) is one
 *    where the agent can already read the file itself, and the one host where it would
 *    genuinely help — Claude Desktop, where the agent may have no filesystem access —
 *    would have needed a further extension-manifest field to reach it.
 *  - Reporting a parse failure usefully means surfacing the JSON error, and V8 embeds
 *    the offending bytes in that message. That turns any path under the root into a
 *    few-bytes-at-a-time read oracle, which is precisely the shape the file-read
 *    restriction exists to prevent.
 *
 * `parseNpmLockfile` in ../vuln.ts stays exported and tested so a caller can do the
 * extraction in one JSON.parse and a map.
 */
export function registerVulnTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'check_dependencies',
    {
      title: "Check a project's dependencies",
      description:
        "Scope the org-wide vulnerability report to ONE project's dependency list and return only what affects it, each package annotated with the version to bump to. Prefer this over list_vulnerabilities whenever the question is about a specific project or lockfile — read the lockfile yourself and pass the resolved dependencies as `packages`. For an npm package-lock.json (v2/v3) that is every entry of its `packages` map: `{ name, version, dev }`. Also answers \"is this clean now?\" after a fix: `clean` is true when nothing matched. Requires read:packages capability.",
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.default('npm').describe('Ecosystem of the dependency list. Default npm.'),
        packages: z
          .array(
            z.object({
              name: z.string().min(1).describe('Package name, e.g. "hono" or "@scope/pkg".'),
              version: z.string().min(1).describe('Exact installed version.'),
              dev: z
                .boolean()
                .optional()
                .describe('True for a dev-only dependency. Affects the runtime/dev split in the summary only.'),
            }),
          )
          .min(1)
          .max(5000)
          .describe("The project's resolved dependencies."),
        includeAdvisoryDetail: z
          .boolean()
          .optional()
          .describe('Include CWE / OWASP / remediation-skill ids per advisory. Default false.'),
      },
    },
    async (args) =>
      run(async () => {
        const { items, total, truncated } = await fetchReport(client, { ecosystem: args.ecosystem });
        const { hits, devOf } = matchPackages(items, args.packages);

        const remediations = await fetchRemediations(
          client,
          hits.map((h) => ({ osvId: h.osvId, version: h.version })),
        );
        const findings = buildFindings(hits, devOf, remediations);

        if (!args.includeAdvisoryDetail) {
          for (const f of findings) {
            for (const a of f.advisories) {
              delete a.cwes;
              delete a.owasp;
              delete a.skills;
            }
          }
        }

        return json({
          ecosystem: args.ecosystem,
          clean: findings.length === 0,
          summary: summarize(findings, args.packages.length),
          reportSize: total,
          ...(truncated ? { truncated: true, note: 'Report exceeded the fetch cap; results may be incomplete.' } : {}),
          findings,
        });
      }),
  );

  server.registerTool(
    'get_remediation',
    {
      title: 'Get remediation for advisories',
      description:
        'Fixed version (plus CWE / OWASP / remediation-skill ids) for one or more advisories, without the full advisory prose. Pass the installed version alongside each id to get the fix for that release line — for @hono/node-server 1.19.14 that is 1.19.15, not the 2.x fix. Use get_vulnerability instead when you need the write-up, PoC, or workarounds. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        advisories: z
          .array(
            z.object({
              osvId: z.string().min(1).describe('Advisory id, e.g. "GHSA-xxxx-..." or "CVE-2024-...".'),
              version: z.string().optional().describe('Your installed version, so the fix names the right release line.'),
            }),
          )
          .min(1)
          .max(200)
          .describe('Advisories to resolve, up to 200.'),
      },
    },
    async (args) =>
      run(async () => {
        const results = await mapLimit(args.advisories, 8, async (a) => {
          try {
            const detail = (await client.get(`/api/v1/vulnerabilities/${encodeURIComponent(a.osvId)}`, {
              version: a.version,
            })) as Record<string, unknown> | null;
            const rem = summarizeRemediation(detail);
            return {
              osvId: a.osvId,
              ...(a.version ? { installed: a.version } : {}),
              fixedVersion: rem.fixedVersion,
              severity: rem.severity ?? null,
              summary: rem.summary ?? null,
              ...(rem.cwes.length ? { cwes: rem.cwes } : {}),
              ...(rem.owasp.length ? { owasp: rem.owasp } : {}),
              ...(rem.skills.length ? { skills: rem.skills } : {}),
            };
          } catch (e) {
            return { osvId: a.osvId, error: e instanceof Error ? e.message : String(e) };
          }
        });
        return json({ advisories: results });
      }),
  );
}
