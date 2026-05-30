import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary } from '../format.js';

const role = z.enum(['member', 'admin', 'owner', 'auditor']);

export function registerUsersTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_org_users',
    'List members of the caller\'s org. Requires tenant:configure.',
    {},
    async () => run(async () => json(await client.get('/api/v1/users'))),
  );

  server.tool(
    'change_user_role',
    'Change a member\'s role. Only owners can touch owners or grant the owner role. Last-owner demotion is rejected.',
    {
      userId: z.string().describe('User id from list_org_users.'),
      role,
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Set user ${args.userId} role to ${args.role}.`,
          await client.patch(`/api/v1/users/${encodeURIComponent(args.userId)}/role`, { role: args.role }),
        ),
      ),
  );

  server.tool(
    'remove_user',
    'Remove a member from the org. Same two-tier gate as change_user_role.',
    { userId: z.string() },
    async (args) =>
      run(async () =>
        withSummary(`Removed user ${args.userId}.`, await client.del(`/api/v1/users/${encodeURIComponent(args.userId)}`)),
      ),
  );

  server.tool(
    'list_invites',
    'List pending invites for the org.',
    {},
    async () => run(async () => json(await client.get('/api/v1/invites'))),
  );

  server.tool(
    'create_invite',
    'Invite a user by email. Inviting at owner level requires owner role. Returns the invite link if SMTP is not configured.',
    {
      email: z.string().email(),
      role: role.optional().describe('Default: member.'),
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Invited ${args.email}${args.role ? ` as ${args.role}` : ''}.`,
          await client.post('/api/v1/invites', { email: args.email, role: args.role }),
        ),
      ),
  );

  server.tool(
    'cancel_invite',
    'Cancel a pending invite by id.',
    { id: z.string() },
    async (args) =>
      run(async () =>
        withSummary(`Cancelled invite ${args.id}.`, await client.del(`/api/v1/invites/${encodeURIComponent(args.id)}`)),
      ),
  );
}
