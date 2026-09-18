import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';
import { compactReportItem, type ReportItem } from '../vuln.js';
import { LOOKUP_ECOSYSTEMS, REGISTRY_ECOSYSTEMS } from '../ecosystems.js';

const ecosystem = z.enum(REGISTRY_ECOSYSTEMS);
// /api/v1/lookup enforces its own, narrower set and 422s anything outside it.
const lookupEcosystem = z.enum(LOOKUP_ECOSYSTEMS);

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerReadTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'list_packages',
    {
      title: 'List packages',
      description:
        'List packages in the registry, paginated (GET /api/v1/packages). Returns { items, total, limit, offset }. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.optional().describe('Filter to one ecosystem.'),
        search: z.string().optional().describe('Substring filter on package name.'),
        limit: z.number().int().positive().max(200).optional().describe('Page size, 1–200, default 50.'),
        page: z.number().int().positive().optional().describe('1-based page number, default 1.'),
        sortBy: z.string().optional().describe('Sort column, default "created".'),
        sortDir: z.enum(['asc', 'desc']).optional().describe('Sort direction, default asc.'),
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/packages', {
            ecosystem: args.ecosystem,
            search: args.search,
            limit: args.limit,
            page: args.page,
            sortBy: args.sortBy,
            sortDir: args.sortDir,
          }),
        ),
      ),
  );

  server.registerTool(
    'get_package',
    {
      title: 'Get package',
      description:
        'Full detail for one package: versions, per-version SPDX licenses, vulnerability links (GET /api/v1/packages/{ecosystem}/{name}). Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.describe('Package ecosystem.'),
        name: z.string().describe('Package name, e.g. "left-pad" or "@scope/pkg" (encoding is handled).'),
      },
    },
    async (args) =>
      run(async () =>
        json(await client.get(`/api/v1/packages/${args.ecosystem}/${encodeURIComponent(args.name)}`)),
      ),
  );

  server.registerTool(
    'search_packages',
    {
      title: 'Search packages',
      description:
        'Quick search across the registry by name (GET /api/v1/search). Queries shorter than 2 characters return empty groups. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        q: z.string().min(2).describe('Search query, minimum 2 characters.'),
        limit: z.number().int().positive().max(25).optional().describe('Max results, 1–25, default 8.'),
      },
    },
    async (args) => run(async () => json(await client.get('/api/v1/search', { q: args.q, limit: args.limit }))),
  );

  server.registerTool(
    'list_vulnerabilities',
    {
      title: 'List vulnerabilities',
      description:
        'Org-wide vulnerability report: every package in the registry affected by a known advisory, paginated (GET /api/v1/vuln-report). Returns { items, total, limit, offset }. This is the whole org, NOT one project — to scope it to a project\'s dependencies and get bump targets, use check_dependencies. Items are compact by default; pass verbosity "full" for the raw server fields. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.optional().describe('Filter to one ecosystem.'),
        name: z.string().optional().describe('Filter to one package name.'),
        limit: z.number().int().positive().optional().describe('Page size, default 50.'),
        page: z.number().int().positive().optional().describe('1-based page number, default 1.'),
        sort: z.string().optional().describe('Sort column.'),
        dir: z.enum(['asc', 'desc']).optional().describe('Sort direction.'),
        verbosity: z
          .enum(['compact', 'full'])
          .default('compact')
          .describe(
            'compact (default) keeps name, version, osvId, severity, cvss, epss, kev and summary — roughly half the bytes. full returns every server field (purl, orgSlug, revokedAt, timestamps).',
          ),
      },
    },
    async (args) =>
      run(async () => {
        const res = (await client.get('/api/v1/vuln-report', {
          ecosystem: args.ecosystem,
          name: args.name,
          limit: args.limit,
          page: args.page,
          sort: args.sort,
          dir: args.dir,
        })) as { items?: ReportItem[] } | null;
        if (args.verbosity === 'full' || !res?.items) return json(res);
        return json({ ...res, items: res.items.map(compactReportItem) });
      }),
  );

  server.registerTool(
    'get_vulnerability',
    {
      title: 'Get vulnerability',
      description:
        'Rich detail for one advisory affecting the registry (GET /api/v1/vulnerabilities/{osvId}). 404 if the advisory does not touch any package in your org. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        osvId: z.string().describe('Advisory id, e.g. "GHSA-xxxx-..." or "CVE-2024-...".'),
        version: z
          .string()
          .optional()
          .describe('Your installed version — when set, remediation guidance names the fixed version for it.'),
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get(`/api/v1/vulnerabilities/${encodeURIComponent(args.osvId)}`, {
            version: args.version,
          }),
        ),
      ),
  );

  server.registerTool(
    'list_activity',
    {
      title: 'List activity',
      description:
        'Org activity feed: publishes, yanks, imports, policy changes, etc., paginated (GET /api/v1/activity). Requires read:audit capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        limit: z.number().int().positive().optional().describe('Page size, default 50.'),
        page: z.number().int().positive().optional().describe('1-based page number, default 1.'),
        event_type: z.string().optional().describe('Filter to one event type.'),
        search: z.string().optional().describe('Substring filter on event detail.'),
        since: z.enum(['24h', '7d', '30d', '90d']).optional().describe('Time window to look back over.'),
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/activity', {
            limit: args.limit,
            page: args.page,
            event_type: args.event_type,
            search: args.search,
            since: args.since,
          }),
        ),
      ),
  );

  server.registerTool(
    'get_license_policy',
    {
      title: 'Get license policy',
      description:
        'The org\'s license policy: enforcement mode (off/warn/block) plus the SPDX allowlist and blocklist (GET /api/v1/license-policy) — answers "which licenses are approved here". Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/license-policy'))),
  );

  server.registerTool(
    'lookup_package',
    {
      title: 'Look up a candidate package',
      description:
        'Pre-adoption check of a package NOT necessarily in the registry: upstream metadata, OSV advisories, and the org-policy verdict, without ingesting anything (GET /api/v1/lookup). Use before adding a new dependency. Requires read:packages capability.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: lookupEcosystem.describe(
          'Package ecosystem. Narrower than the registry tools: a pre-adoption verdict needs an upstream to resolve against, so rpm, oci, apk and terraform are not offered here.',
        ),
        name: z.string().describe('Package name to evaluate. Maven takes a "groupId:artifactId" coordinate.'),
        version: z
          .string()
          .optional()
          .describe('Specific version to evaluate; some ecosystems require it (the server says so).'),
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/lookup', {
            ecosystem: args.ecosystem,
            name: args.name,
            version: args.version,
          }),
        ),
      ),
  );
}
