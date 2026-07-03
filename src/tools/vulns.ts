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
