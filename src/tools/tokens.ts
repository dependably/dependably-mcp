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

export function registerTokensTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_tokens',
    'List the caller\'s own user tokens (id, capabilities, expiry — never plaintext).',
    {},
    async () => run(async () => json(await client.get('/api/v1/tokens'))),
  );

  server.tool(
    'create_token',
    'Mint a new user token. The plaintext token is returned ONCE in the response — surface it to the user immediately.',
    { capabilities, expiresAt, description },
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

  server.tool(
    'revoke_token',
    'Revoke one of the caller\'s user tokens by id. Admins may revoke any user token in the org.',
    { id: z.string().describe('Token id (from list_tokens).') },
    async (args) =>
      run(async () => withSummary(`Revoked token ${args.id}.`, await client.del(`/api/v1/tokens/${encodeURIComponent(args.id)}`))),
  );

  server.tool(
    'list_service_tokens',
    'List the org\'s named service (M2M) tokens. Requires tenant:configure (admin+).',
    {},
    async () => run(async () => json(await client.get('/api/v1/service-tokens'))),
  );

  server.tool(
    'create_service_token',
    'Create a named service (M2M) token. Plaintext returned once. Requires tenant:configure.',
    {
      name: z.string().describe('Human-readable service token name (e.g. "ci-publisher").'),
      capabilities,
      expiresAt,
      description,
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

  server.tool(
    'revoke_service_token',
    'Revoke a service token by id. Requires tenant:configure.',
    { id: z.string().describe('Service token id (from list_service_tokens).') },
    async (args) =>
      run(async () =>
        withSummary(`Revoked service token ${args.id}.`, await client.del(`/api/v1/service-tokens/${encodeURIComponent(args.id)}`)),
      ),
  );
}
