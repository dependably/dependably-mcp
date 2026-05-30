import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, paginationSchema } from '../format.js';

const ecosystem = z
  .enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci'])
  .describe('Package ecosystem.');

export function registerPackagesTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_packages',
    'List packages in the caller\'s org. Filter by ecosystem and free-text search; paginated.',
    {
      ecosystem: ecosystem.optional(),
      search: z.string().optional().describe('Free-text search across package names.'),
      sortBy: z.enum(['created']).optional().describe('Sort field. Server default: created.'),
      sortDir: z.enum(['asc', 'desc']).optional(),
      ...paginationSchema,
    },
    async (args) =>
      run(async () =>
        json(
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

  server.tool(
    'get_package',
    'Get one package and all its versions, licenses, max OSV score, and per-version status.',
    {
      ecosystem,
      name: z.string().describe('Package name (canonical for the ecosystem).'),
    },
    async (args) =>
      run(async () => json(await client.get(`/api/v1/packages/${args.ecosystem}/${encodeURIComponent(args.name)}`))),
  );

  server.tool(
    'get_org_stats',
    'Return org-level analytics (package counts, storage, recent activity).',
    {},
    async () => run(async () => json(await client.get('/api/v1/stats'))),
  );
}
