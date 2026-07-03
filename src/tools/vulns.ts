import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, withSummary } from '../format.js';

const ecosystem = z
  .enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo'])
  .describe('Package ecosystem.');

const versionTarget = {
  ecosystem,
  name: z.string().describe('Package name.'),
  version: z.string().describe('Package version (ecosystem-canonical form).'),
};

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
