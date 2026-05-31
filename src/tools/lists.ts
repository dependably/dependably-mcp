import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, structured, withSummary } from '../format.js';

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

const PUT_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const allowlistEntry = z.object({
  id: z.string().optional(),
  purl_pattern: z.string().optional(),
  created_at: z.string().optional(),
}).passthrough();

const blocklistEntry = z.object({
  id: z.string().optional(),
  pattern: z.string().optional(),
  created_at: z.string().optional(),
}).passthrough();

const licenseEntry = z.object({
  id: z.string().optional(),
  license_spdx: z.string().optional(),
  spdx: z.string().optional(),
  created_at: z.string().optional(),
}).passthrough();

const reviewEntry = z.object({
  license_spdx: z.string().optional(),
  spdx: z.string().optional(),
  version_count: z.number().optional(),
  first_seen: z.string().optional(),
  is_deprecated: z.boolean().optional(),
}).passthrough();

export function registerListsTools(server: McpServer, client: DependablyClient): void {
  // --- Allowlist (PURL prefix patterns) ---
  server.registerTool(
    'list_allowlist',
    {
      title: 'List allowlist',
      description: 'List org allowlist entries (PURL prefix patterns). When the org runs in allowlist mode, only matching packages can be fetched/pushed.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: { entries: z.array(allowlistEntry) },
    },
    async () =>
      run(async () => structured(await client.get('/api/v1/allowlist'), 'entries')),
  );

  server.registerTool(
    'add_allowlist',
    {
      title: 'Add allowlist entry',
      description: 'Add a PURL prefix pattern to the allowlist. Requires tenant:configure.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        purlPattern: z.string().describe('PURL prefix pattern, e.g. "pkg:npm/@acme/" or "pkg:pypi/django".'),
      },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Added allowlist entry "${args.purlPattern}".`,
          await client.post('/api/v1/allowlist', { purlPattern: args.purlPattern }),
        ),
      ),
  );

  server.registerTool(
    'remove_allowlist',
    {
      title: 'Remove allowlist entry',
      description: 'Remove an allowlist entry by id. Requires tenant:configure.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { id: z.string().describe('Allowlist entry id (from list_allowlist).') },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed allowlist entry ${args.id}.`,
          await client.del(`/api/v1/allowlist/${encodeURIComponent(args.id)}`),
        ),
      ),
  );

  // --- Blocklist (regex on package name, with server-side ReDoS guards) ---
  server.registerTool(
    'list_blocklist',
    {
      title: 'List blocklist',
      description: 'List org blocklist entries (regex patterns on package name).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: { entries: z.array(blocklistEntry) },
    },
    async () =>
      run(async () => structured(await client.get('/api/v1/blocklist'), 'entries')),
  );

  server.registerTool(
    'add_blocklist',
    {
      title: 'Add blocklist entry',
      description: 'Add a regex pattern to the blocklist (max 512 chars, server checks for ReDoS).',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        pattern: z
          .string()
          .max(512)
          .describe('Regex matched against package name. Server rejects patterns that take >2s to compile.'),
      },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Added blocklist entry "${args.pattern}".`,
          await client.post('/api/v1/blocklist', { pattern: args.pattern }),
        ),
      ),
  );

  server.registerTool(
    'remove_blocklist',
    {
      title: 'Remove blocklist entry',
      description: 'Remove a blocklist entry by id.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { id: z.string().describe('Blocklist entry id (from list_blocklist).') },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed blocklist entry ${args.id}.`,
          await client.del(`/api/v1/blocklist/${encodeURIComponent(args.id)}`),
        ),
      ),
  );

  // --- License policy ---
  server.registerTool(
    'get_license_policy',
    {
      title: 'License policy',
      description: 'Get current license policy: mode + SPDX allowlist + SPDX blocklist.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        mode: z.string().optional(),
        allowlist: z.array(licenseEntry).optional(),
        blocklist: z.array(licenseEntry).optional(),
      },
    },
    async () => run(async () => structured(await client.get('/api/v1/license-policy'))),
  );

  server.registerTool(
    'set_license_policy_mode',
    {
      title: 'Set license policy mode',
      description: 'Set license policy mode. "off" = ignore, "review" = surface unknowns, "enforce" = block non-allowed.',
      annotations: PUT_ANNOTATIONS,
      inputSchema: { mode: z.enum(['off', 'review', 'enforce']) },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `License policy mode set to "${args.mode}".`,
          await client.put('/api/v1/license-policy/mode', { mode: args.mode }),
        ),
      ),
  );

  server.registerTool(
    'list_license_policy_review',
    {
      title: 'License review queue',
      description: 'List licenses seen on packages that are not yet on the allowlist or blocklist. Admin-only.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        includeDeprecated: z
          .boolean()
          .optional()
          .describe('Include SPDX-deprecated license identifiers. Default false.'),
      },
      outputSchema: { entries: z.array(reviewEntry) },
    },
    async (args) =>
      run(async () =>
        structured(
          await client.get('/api/v1/license-policy/review', { includeDeprecated: args.includeDeprecated }),
          'entries',
        ),
      ),
  );

  server.registerTool(
    'add_license_allowlist',
    {
      title: 'Allow license',
      description: 'Add an SPDX identifier to the license allowlist (e.g. "MIT", "Apache-2.0").',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: { spdx: z.string().describe('SPDX license identifier.') },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Allowed license "${args.spdx}".`,
          await client.post('/api/v1/license-policy/allowlist', { spdx: args.spdx }),
        ),
      ),
  );

  server.registerTool(
    'remove_license_allowlist',
    {
      title: 'Remove license allowlist entry',
      description: 'Remove an SPDX identifier from the license allowlist.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { spdx: z.string() },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed "${args.spdx}" from license allowlist.`,
          await client.del(`/api/v1/license-policy/allowlist/${encodeURIComponent(args.spdx)}`),
        ),
      ),
  );

  server.registerTool(
    'add_license_blocklist',
    {
      title: 'Block license',
      description: 'Add an SPDX identifier to the license blocklist (e.g. "AGPL-3.0-only").',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: { spdx: z.string() },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Blocked license "${args.spdx}".`,
          await client.post('/api/v1/license-policy/blocklist', { spdx: args.spdx }),
        ),
      ),
  );

  server.registerTool(
    'remove_license_blocklist',
    {
      title: 'Remove license blocklist entry',
      description: 'Remove an SPDX identifier from the license blocklist.',
      annotations: DESTRUCTIVE_ANNOTATIONS,
      inputSchema: { spdx: z.string() },
    },
    async (args) =>
      run(async () =>
        withSummary(
          `Removed "${args.spdx}" from license blocklist.`,
          await client.del(`/api/v1/license-policy/blocklist/${encodeURIComponent(args.spdx)}`),
        ),
      ),
  );
}
