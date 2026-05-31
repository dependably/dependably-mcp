import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary } from '../format.js';

const capabilities = z
  .array(z.string())
  .optional()
  .describe('Capability strings (e.g. "publish:npm", "read:*"). Capped at the caller\'s role grants.');

const expiresAt = z
  .string()
  .optional()
  .describe('ISO-8601 expiry timestamp. Omit for no expiry.');

const description = z
  .string()
  .max(200)
  .optional()
  .describe('Free-text label, up to 200 characters.');

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

const DESTRUCTIVE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerTokensTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'list_tokens',
    {
      title: 'List user tokens',
      description: 'List the caller\'s own user tokens (id, capabilities, expiry — never plaintext).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/tokens'))),
  );

  server.registerTool(
    'create_token',
    {
      title: 'Create user token',
      description: 'Mint a new user token. The plaintext token is returned ONCE in the response — surface it to the user immediately.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: { capabilities, expiresAt, description },
    },
    async (args) =>
      run(async () =>
        withSummary(
          'New user token created. The plaintext value is shown only once below — copy it now.',
          await client.post('/api/v1/tokens', {
            capabilities: args.capabilities,
            expiresAt: args.expiresAt,
            description: args.description,
          }),
        ),
      ),
  );

  server.registerTool(
    'revoke_token',
    {
      title: 'Revoke user token',
      description: 'Revoke one of the caller\'s user tokens by id. Admins may revoke any user token in the org.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { id: z.string().describe('Token id (from list_tokens).') },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Revoked token ${args.id}.`,
          await client.del(`/api/v1/tokens/${encodeURIComponent(args.id)}`),
        ),
      ),
  );

  server.registerTool(
    'list_service_tokens',
    {
      title: 'List service tokens',
      description: 'List the org\'s named service (M2M) tokens. Requires tenant:configure (admin+).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/service-tokens'))),
  );

  server.registerTool(
    'create_service_token',
    {
      title: 'Create service token',
      description: 'Create a named service (M2M) token. Plaintext returned once. Requires tenant:configure.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        name: z.string().describe('Human-readable service token name (e.g. "ci-publisher").'),
        capabilities,
        expiresAt,
        description,
      },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Service token "${args.name}" created. The plaintext value is shown only once below — copy it now.`,
          await client.post('/api/v1/service-tokens', {
            name: args.name,
            capabilities: args.capabilities,
            expiresAt: args.expiresAt,
            description: args.description,
          }),
        ),
      ),
  );

  server.registerTool(
    'revoke_service_token',
    {
      title: 'Revoke service token',
      description: 'Revoke a service token by id. Requires tenant:configure.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { id: z.string().describe('Service token id (from list_service_tokens).') },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Revoked service token ${args.id}.`,
          await client.del(`/api/v1/service-tokens/${encodeURIComponent(args.id)}`),
        ),
      ),
  );
}
