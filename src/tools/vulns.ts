import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary, paginationSchema } from '../format.js';

const ecosystem = z
  .enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci'])
  .describe('Package ecosystem.');

const versionTarget = {
  ecosystem,
  name: z.string().describe('Package name.'),
  version: z.string().describe('Package version (ecosystem-canonical form).'),
};

function versionPath(args: { ecosystem: string; name: string; version: string }): string {
  return `/api/v1/packages/${args.ecosystem}/${encodeURIComponent(args.name)}/${encodeURIComponent(args.version)}`;
}

export function registerVulnsTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_vulnerabilities',
    'List affected packages and severities from the OSV scan results, optionally narrowed by ecosystem or name.',
    {
      ecosystem: ecosystem.optional(),
      name: z.string().optional().describe('Filter to a single package name.'),
      sort: z.string().optional().describe('Sort field (server default).'),
      dir: z.enum(['asc', 'desc']).optional(),
      ...paginationSchema,
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/vuln-report', {
            ecosystem: args.ecosystem,
            name: args.name,
            sort: args.sort,
            dir: args.dir,
            page: args.page,
            limit: args.limit,
          }),
        ),
      ),
  );

  server.tool(
    'rescan_version',
    'Force an immediate OSV rescan of a specific version. 1-hour cooldown enforced server-side (returns 429).',
    versionTarget,
    async (args) =>
      run(async () => withSummary(`Rescan requested for ${args.ecosystem}/${args.name}@${args.version}.`, await client.post(`${versionPath(args)}/rescan`))),
  );

  server.tool(
    'block_version',
    'Manually block a specific version. Subsequent fetches return 403 until unblocked.',
    versionTarget,
    async (args) =>
      run(async () => withSummary(`Blocked ${args.ecosystem}/${args.name}@${args.version}.`, await client.post(`${versionPath(args)}/block`))),
  );

  server.tool(
    'unblock_version',
    'Lift a manual block on a version (also overrides any auto-block).',
    versionTarget,
    async (args) =>
      run(async () => withSummary(`Unblocked ${args.ecosystem}/${args.name}@${args.version}.`, await client.post(`${versionPath(args)}/unblock`))),
  );

  server.tool(
    'yank_version',
    'Yank (delete) a specific package version from the org. Destructive — requires the yank:{ecosystem} capability.',
    versionTarget,
    async (args) =>
      run(async () => withSummary(`Yanked ${args.ecosystem}/${args.name}@${args.version}.`, await client.del(versionPath(args)))),
  );
}
