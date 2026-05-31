import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { DependablyApiError, type DependablyClient } from '../client.js';
import { err, json, run, structured, withSummary } from '../format.js';

const role = z.enum(['member', 'admin', 'owner', 'auditor']);

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

const PATCH_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const DESTRUCTIVE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerUsersTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'whoami',
    {
      title: 'Whoami',
      description: 'Return the calling identity: user id, org, role, and language. Tries /api/v1/auth/me (JWT) first; falls back to a minimal response if the endpoint rejects the API token auth scheme.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        user_id: z.string().nullable().optional(),
        org_id: z.string().nullable().optional(),
        role: z.string().nullable().optional(),
        must_change_password: z.boolean().optional(),
        language: z.string().optional(),
        auth_scheme: z.string().optional(),
        note: z.string().optional(),
      },
    },
    async () => {
      try {
        const me = await client.get('/api/v1/auth/me');
        return structured(me);
      } catch (e) {
        if (e instanceof DependablyApiError && e.status === 401) {
          return structured({
            auth_scheme: 'api-token',
            note: 'Authenticated via API token. /api/v1/auth/me is JWT-only and rejected this token; identity details are unavailable through this endpoint.',
          });
        }
        return err(e instanceof Error ? e.message : String(e));
      }
    },
  );

  server.registerTool(
    'list_org_users',
    {
      title: 'List org users',
      description: 'List members of the caller\'s org. Requires tenant:configure.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/users'))),
  );

  server.registerTool(
    'change_user_role',
    {
      title: 'Change user role',
      description: 'Change a member\'s role. Only owners can touch owners or grant the owner role. Last-owner demotion is rejected.',
      annotations: PATCH_ANNOTATIONS,
      inputSchema: {
        userId: z.string().describe('User id from list_org_users.'),
        role,
      },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Set user ${args.userId} role to ${args.role}.`,
          await client.patch(`/api/v1/users/${encodeURIComponent(args.userId)}/role`, { role: args.role }),
        ),
      ),
  );

  server.registerTool(
    'remove_user',
    {
      title: 'Remove user',
      description: 'Remove a member from the org. Same two-tier gate as change_user_role.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { userId: z.string() },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed user ${args.userId}.`,
          await client.del(`/api/v1/users/${encodeURIComponent(args.userId)}`),
        ),
      ),
  );

  server.registerTool(
    'list_invites',
    {
      title: 'List invites',
      description: 'List pending invites for the org.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/invites'))),
  );

  server.registerTool(
    'create_invite',
    {
      title: 'Create invite',
      description: 'Invite a user by email. Inviting at owner level requires owner role. Returns the invite link if SMTP is not configured.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        email: z.string().email(),
        role: role.optional().describe('Default: member.'),
      },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Invited ${args.email}${args.role ? ` as ${args.role}` : ''}.`,
          await client.post('/api/v1/invites', { email: args.email, role: args.role }),
        ),
      ),
  );

  server.registerTool(
    'cancel_invite',
    {
      title: 'Cancel invite',
      description: 'Cancel a pending invite by id.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { id: z.string() },
    },
    async (args) =>
      run(async () =>
        withSummary(`Cancelled invite ${args.id}.`, await client.del(`/api/v1/invites/${encodeURIComponent(args.id)}`)),
      ),
  );
}
