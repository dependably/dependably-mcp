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

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

const REVERSIBLE_BLOCK = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const DESTRUCTIVE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
} as const;

function versionPath(args: { ecosystem: string; name: string; version: string }): string {
  return `/api/v1/packages/${args.ecosystem}/${encodeURIComponent(args.name)}/${encodeURIComponent(args.version)}`;
}

export function registerVulnsTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'list_vulnerabilities',
    {
      title: 'List vulnerabilities',
      description: 'List affected packages and severities from the OSV scan results, optionally narrowed by ecosystem or name.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        ecosystem: ecosystem.optional(),
        name: z.string().optional().describe('Filter to a single package name.'),
        sort: z.string().optional().describe('Sort field (server default).'),
        dir: z.enum(['asc', 'desc']).optional(),
        ...paginationSchema,
      },
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

  server.registerTool(
    'rescan_version',
    {
      title: 'Rescan version',
      description: 'Force an immediate OSV rescan of a specific version. 1-hour cooldown enforced server-side (returns 429).',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: versionTarget,
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Rescan requested for ${args.ecosystem}/${args.name}@${args.version}.`,
          await client.post(`${versionPath(args)}/rescan`),
        ),
      ),
  );

  server.registerTool(
    'block_version',
    {
      title: 'Block version',
      description: 'Manually block a specific version. Subsequent fetches return 403 until unblocked.',
      annotations: REVERSIBLE_BLOCK,
      inputSchema: versionTarget,
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Blocked ${args.ecosystem}/${args.name}@${args.version}.`,
          await client.post(`${versionPath(args)}/block`),
        ),
      ),
  );

  server.registerTool(
    'unblock_version',
    {
      title: 'Unblock version',
      description: 'Lift a manual block on a version (also overrides any auto-block).',
      annotations: REVERSIBLE_BLOCK,
      inputSchema: versionTarget,
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Unblocked ${args.ecosystem}/${args.name}@${args.version}.`,
          await client.post(`${versionPath(args)}/unblock`),
        ),
      ),
  );

  server.registerTool(
    'yank_version',
    {
      title: 'Yank version',
      description: 'Yank (delete) a specific package version from the org. Destructive — requires the yank:{ecosystem} capability.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: versionTarget,
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Yanked ${args.ecosystem}/${args.name}@${args.version}.`,
          await client.del(versionPath(args)),
        ),
      ),
  );
}
