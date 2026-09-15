import { readFile } from 'node:fs/promises';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import type { Config } from '../config.js';
import { json, run } from '../format.js';
import { resolveWithinRoot } from '../paths.js';
import {
  buildFindings,
  fetchRemediations,
  fetchReport,
  matchPackages,
  parseNpmLockfile,
  summarize,
  summarizeRemediation,
  mapLimit,
  type InputPackage,
} from '../vuln.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo']);

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const packageList = z
  .array(
    z.object({
      name: z.string().min(1).describe('Package name, e.g. "hono" or "@scope/pkg".'),
      version: z.string().min(1).describe('Exact installed version.'),
      dev: z.boolean().optional().describe('True for a dev-only dependency; affects the runtime/dev split only.'),
    }),
  )
  .min(1)
  .max(5000);

export function registerVulnTools(server: McpServer, client: DependablyClient, cfg: Config): void {
  const projectRoot = cfg.projectRoot;

  server.registerTool(
    'check_dependencies',
    {
      title: 'Check a project\'s dependencies',
      description:
        "Scope the org-wide vulnerability report to ONE project's dependency list and return only what affects it, each package annotated with the version to bump to. Prefer this over list_vulnerabilities whenever the question is about a specific project or lockfile. Pass the dependency list via `packages`" +
        (projectRoot
          ? ', or a `lockfile` path (npm package-lock.json v2/v3) that resolves inside DEPENDABLY_PROJECT_ROOT'
          : '') +
        '. Also answers "is this clean now?" after a fix: `clean` is true when nothing matched. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.default('npm').describe('Ecosystem of the dependency list. Default npm.'),
        packages: packageList
          .optional()
          .describe('The project\'s resolved dependencies as {name, version, dev}. Required unless `lockfile` is given.'),
        ...(projectRoot
          ? {
              lockfile: z
                .string()
                .min(1)
                .optional()
                .describe(
                  'Path to an npm package-lock.json on the machine running this MCP server; must resolve inside DEPENDABLY_PROJECT_ROOT. Mutually exclusive with `packages`.',
                ),
            }
          : {}),
        includeAdvisoryDetail: z
          .boolean()
          .optional()
          .describe('Include CWE / OWASP / remediation-skill ids per advisory. Default false.'),
      },
    },
    async (args) =>
      run(async () => {
        const lockfile = (args as { lockfile?: string }).lockfile;
        if (lockfile && args.packages) {
          throw new Error('Pass either `packages` or `lockfile`, not both.');
        }

        let packages: InputPackage[];
        if (lockfile) {
          if (!projectRoot) {
            throw new Error(
              'Reading a lockfile from disk requires DEPENDABLY_PROJECT_ROOT to be set on the MCP server. Pass the dependency list via `packages` instead.',
            );
          }
          const real = await resolveWithinRoot(projectRoot, lockfile, 'DEPENDABLY_PROJECT_ROOT');
          packages = parseNpmLockfile(await readFile(real, 'utf8'));
          if (args.ecosystem !== 'npm') {
            throw new Error(
              `lockfile parsing is implemented for npm only; got ecosystem "${args.ecosystem}". Pass \`packages\` for other ecosystems.`,
            );
          }
        } else if (args.packages) {
          packages = args.packages;
        } else {
          throw new Error('Provide `packages` (an array of {name, version})' + (projectRoot ? ' or `lockfile`' : '') + '.');
        }

        const { items, total, truncated } = await fetchReport(client, { ecosystem: args.ecosystem });
        const { hits, devOf } = matchPackages(items, packages);

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
          summary: summarize(findings, packages.length),
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
