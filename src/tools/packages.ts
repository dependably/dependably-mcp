import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, structured, paginationSchema } from '../format.js';

const ecosystem = z
  .enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci'])
  .describe('Package ecosystem.');

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const packageSummary = z.object({
  id: z.string().optional(),
  name: z.string(),
  ecosystem: z.string(),
  purl_name: z.string().optional(),
  created_at: z.string().optional(),
}).passthrough();

const packageVersion = z.object({
  id: z.string().optional(),
  version: z.string(),
  purl: z.string().optional(),
  size_bytes: z.number().nullable().optional(),
  checksum_sha256: z.string().nullable().optional(),
  yanked: z.boolean().optional(),
  origin: z.string().nullable().optional(),
  status: z.string().optional(),
  max_osv_score: z.number().nullable().optional(),
  licenses: z.array(z.string()).optional(),
  created_at: z.string().optional(),
  vuln_checked_at: z.string().nullable().optional(),
  published_at: z.string().nullable().optional(),
}).passthrough();

export function registerPackagesTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'list_packages',
    {
      title: 'List packages',
      description: 'List packages in the caller\'s org. Filter by ecosystem and free-text search; paginated.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.optional(),
        search: z.string().optional().describe('Free-text search across package names.'),
        sortBy: z.enum(['created', 'name', 'ecosystem']).optional().describe('Sort field. Server default: created.'),
        sortDir: z.enum(['asc', 'desc']).optional(),
        ...paginationSchema,
      },
      outputSchema: {
        items: z.array(packageSummary),
        total: z.number().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
        page: z.number().optional(),
      },
    },
    async (args) =>
      run(async () =>
        structured(
          await client.get('/api/v1/packages', {
            ecosystem: args.ecosystem,
            search: args.search,
            sortBy: args.sortBy,
            sortDir: args.sortDir,
            page: args.page,
            limit: args.limit,
          }),
        ),
      ),
  );

  server.registerTool(
    'get_package',
    {
      title: 'Get package',
      description: 'Get one package and all its versions, licenses, max OSV score, and per-version status.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem,
        name: z.string().describe('Package name (canonical for the ecosystem).'),
      },
      outputSchema: {
        package: packageSummary.optional(),
        versions: z.array(packageVersion).optional(),
      },
    },
    async (args) =>
      run(async () =>
        structured(await client.get(`/api/v1/packages/${args.ecosystem}/${encodeURIComponent(args.name)}`)),
      ),
  );

  server.registerTool(
    'get_org_stats',
    {
      title: 'Org stats',
      description: 'Return org-level analytics (package counts, storage, recent activity).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        total_packages: z.number().optional(),
        total_versions: z.number().optional(),
        total_size_bytes: z.number().optional(),
        by_ecosystem: z.record(z.string(), z.unknown()).optional(),
      },
    },
    async () => run(async () => structured(await client.get('/api/v1/stats'))),
  );
}
