import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { DependablyApiError, type DependablyClient } from '../client.js';
import { err, structured } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
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
}
