import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary } from '../format.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci']);
const claimState = z
  .enum(['unclaimed', 'mixed', 'local_only'])
  .describe('Claim state machine: unclaimed → mixed → local_only (one-way).');

function claimPath(eco: string, name: string): string {
  return `/api/v1/admin/claims/${eco}/${encodeURIComponent(name)}`;
}

export function registerClaimsTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_claims',
    'List package-name claims (namespace ownership for supply-chain trust). Filter by ecosystem, state, or search term.',
    {
      ecosystem: ecosystem.optional(),
      state: claimState.optional(),
      search: z.string().optional(),
      limit: z.number().int().positive().max(500).optional(),
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/admin/claims', {
            ecosystem: args.ecosystem,
            state: args.state,
            search: args.search,
            limit: args.limit,
          }),
        ),
      ),
  );

  server.tool(
    'get_claim',
    'Get a single claim plus its effective state.',
    { ecosystem, name: z.string() },
    async (args) => run(async () => json(await client.get(claimPath(args.ecosystem, args.name)))),
  );

  server.tool(
    'create_claim',
    'Claim a previously-unclaimed package name. Creating with state=local_only triggers a proxy-version purge.',
    {
      ecosystem,
      name: z.string(),
      state: claimState.optional().describe('Default: mixed.'),
      reason: z.string().describe('Required justification (audit trail).'),
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Created claim for ${args.ecosystem}/${args.name}${args.state ? ` (state=${args.state})` : ''}.`,
          await client.post('/api/v1/admin/claims', args),
        ),
      ),
  );

  server.tool(
    'transition_claim',
    'Move a claim along its state machine. mixed→local_only PURGES every proxy version + its blob first.',
    {
      ecosystem,
      name: z.string(),
      state: claimState,
      reason: z.string(),
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Transitioned ${args.ecosystem}/${args.name} to ${args.state}.`,
          await client.patch(claimPath(args.ecosystem, args.name), { state: args.state, reason: args.reason }),
        ),
      ),
  );

  server.tool(
    'release_claim',
    'Release a claim back to unclaimed. Fails if local versions still exist (delete those first).',
    {
      ecosystem,
      name: z.string(),
      reason: z.string(),
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Released claim for ${args.ecosystem}/${args.name}.`,
          await client.del(claimPath(args.ecosystem, args.name), { reason: args.reason }),
        ),
      ),
  );
}
