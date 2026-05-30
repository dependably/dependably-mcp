import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary } from '../format.js';

export function registerListsTools(server: McpServer, client: DependablyClient): void {
  // --- Allowlist (PURL prefix patterns) ---
  server.tool(
    'list_allowlist',
    'List org allowlist entries (PURL prefix patterns). When the org runs in allowlist mode, only matching packages can be fetched/pushed.',
    {},
    async () => run(async () => json(await client.get('/api/v1/allowlist'))),
  );

  server.tool(
    'add_allowlist',
    'Add a PURL prefix pattern to the allowlist. Requires tenant:configure.',
    {
      purlPattern: z
        .string()
        .describe('PURL prefix pattern, e.g. "pkg:npm/@acme/" or "pkg:pypi/django".'),
    },
    async (args) =>
      run(async () =>
        withSummary(`Added allowlist entry "${args.purlPattern}".`, await client.post('/api/v1/allowlist', { purlPattern: args.purlPattern })),
      ),
  );

  server.tool(
    'remove_allowlist',
    'Remove an allowlist entry by id. Requires tenant:configure.',
    { id: z.string().describe('Allowlist entry id (from list_allowlist).') },
    async (args) =>
      run(async () =>
        withSummary(`Removed allowlist entry ${args.id}.`, await client.del(`/api/v1/allowlist/${encodeURIComponent(args.id)}`)),
      ),
  );

  // --- Blocklist (regex on package name, with server-side ReDoS guards) ---
  server.tool(
    'list_blocklist',
    'List org blocklist entries (regex patterns on package name).',
    {},
    async () => run(async () => json(await client.get('/api/v1/blocklist'))),
  );

  server.tool(
    'add_blocklist',
    'Add a regex pattern to the blocklist (max 512 chars, server checks for ReDoS).',
    {
      pattern: z
        .string()
        .max(512)
        .describe('Regex matched against package name. Server rejects patterns that take >2s to compile.'),
    },
    async (args) =>
      run(async () =>
        withSummary(`Added blocklist entry "${args.pattern}".`, await client.post('/api/v1/blocklist', { pattern: args.pattern })),
      ),
  );

  server.tool(
    'remove_blocklist',
    'Remove a blocklist entry by id.',
    { id: z.string().describe('Blocklist entry id (from list_blocklist).') },
    async (args) =>
      run(async () =>
        withSummary(`Removed blocklist entry ${args.id}.`, await client.del(`/api/v1/blocklist/${encodeURIComponent(args.id)}`)),
      ),
  );

  // --- License policy ---
  server.tool(
    'get_license_policy',
    'Get current license policy: mode + SPDX allowlist + SPDX blocklist.',
    {},
    async () => run(async () => json(await client.get('/api/v1/license-policy'))),
  );

  server.tool(
    'set_license_policy_mode',
    'Set license policy mode. "off" = ignore, "review" = surface unknowns, "enforce" = block non-allowed.',
    { mode: z.enum(['off', 'review', 'enforce']) },
    async (args) =>
      run(async () =>
        withSummary(`License policy mode set to "${args.mode}".`, await client.put('/api/v1/license-policy/mode', { mode: args.mode })),
      ),
  );

  server.tool(
    'list_license_policy_review',
    'List licenses seen on packages that are not yet on the allowlist or blocklist. Admin-only.',
    {},
    async () => run(async () => json(await client.get('/api/v1/license-policy/review'))),
  );

  server.tool(
    'add_license_allowlist',
    'Add an SPDX identifier to the license allowlist (e.g. "MIT", "Apache-2.0").',
    { spdx: z.string().describe('SPDX license identifier.') },
    async (args) =>
      run(async () =>
        withSummary(`Allowed license "${args.spdx}".`, await client.post('/api/v1/license-policy/allowlist', { spdx: args.spdx })),
      ),
  );

  server.tool(
    'remove_license_allowlist',
    'Remove an SPDX identifier from the license allowlist.',
    { spdx: z.string() },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed "${args.spdx}" from license allowlist.`,
          await client.del(`/api/v1/license-policy/allowlist/${encodeURIComponent(args.spdx)}`),
        ),
      ),
  );

  server.tool(
    'add_license_blocklist',
    'Add an SPDX identifier to the license blocklist (e.g. "AGPL-3.0-only").',
    { spdx: z.string() },
    async (args) =>
      run(async () =>
        withSummary(`Blocked license "${args.spdx}".`, await client.post('/api/v1/license-policy/blocklist', { spdx: args.spdx })),
      ),
  );

  server.tool(
    'remove_license_blocklist',
    'Remove an SPDX identifier from the license blocklist.',
    { spdx: z.string() },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed "${args.spdx}" from license blocklist.`,
          await client.del(`/api/v1/license-policy/blocklist/${encodeURIComponent(args.spdx)}`),
        ),
      ),
  );
}
