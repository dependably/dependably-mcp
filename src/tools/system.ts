import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, paginationSchema } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

// All tools here require a system-admin JWT/token at the apex host. If your token
// isn't system-scoped, every call returns 401/403 from upstream.
export function registerSystemTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'system_list_tenants',
    {
      title: 'System: list tenants',
      description: 'List all tenants (orgs) on the instance, with member and storage counts. Requires a system-admin token at the apex host.',
      annotations: READ_ANNOTATIONS,
      inputSchema: { ...paginationSchema },
    },
    async (args) =>
      run(async () =>
        json(await client.get('/api/v1/system/tenants', { page: args.page, limit: args.limit })),
      ),
  );

  server.registerTool(
    'system_dashboard',
    {
      title: 'System: dashboard',
      description: 'System dashboard snapshot: tenant counts by status, admin counts, recent job runs.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/system/dashboard'))),
  );

  server.registerTool(
    'system_list_background_jobs',
    {
      title: 'System: background jobs',
      description: 'List background job runs (vuln scans, rescans, retention, GC). Filter by outcome="server_error" to find failed runs during incident investigation. Valid outcomes: success | server_error | cancelled.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        jobName: z.string().optional().describe('Use system_list_background_job_facets to discover valid names.'),
        outcome: z.enum(['success', 'server_error', 'cancelled']).optional(),
        search: z.string().optional(),
        sortBy: z.enum(['startedAt', 'jobName', 'durationMs', 'outcome']).optional(),
        sortDir: z.enum(['asc', 'desc']).optional(),
        ...paginationSchema,
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/system/background-jobs', {
            jobName: args.jobName,
            outcome: args.outcome,
            search: args.search,
            sortBy: args.sortBy,
            sortDir: args.sortDir,
            page: args.page,
            limit: args.limit,
          }),
        ),
      ),
  );

  server.registerTool(
    'system_list_audit',
    {
      title: 'System: audit log',
      description: 'System-scope audit log (control-plane events, not tenant events).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        action: z.string().optional(),
        search: z.string().optional(),
        sortBy: z.enum(['createdAt', 'action']).optional(),
        sortDir: z.enum(['asc', 'desc']).optional(),
        ...paginationSchema,
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/system/audit', {
            action: args.action,
            search: args.search,
            sortBy: args.sortBy,
            sortDir: args.sortDir,
            page: args.page,
            limit: args.limit,
          }),
        ),
      ),
  );

  server.registerTool(
    'system_list_background_job_facets',
    {
      title: 'System: job facets',
      description: 'Return the vocabulary for filtering background jobs: { jobNames: [...], outcomes: ["success","server_error","cancelled"] }.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/system/background-jobs/facets'))),
  );

  server.registerTool(
    'system_get_instance_settings',
    {
      title: 'System: instance settings',
      description: 'Read instance-wide settings (upload limits, GC schedule, SIEM lookback).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/system/settings'))),
  );

  server.registerTool(
    'system_set_tenant_storage_quota',
    {
      title: 'System: set tenant quota',
      description: 'Set or clear the storage quota cap for a tenant (PATCH /api/v1/system/tenants/{slug}/storage-quota). Pass quotaBytes=null to clear.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        slug: z.string().describe('Tenant slug from system_list_tenants.'),
        quotaBytes: z.number().int().nonnegative().nullable().describe('New quota in bytes, or null to clear.'),
      },
    },
    async (args) =>
      run(async () =>
        json(
          await client.patch(`/api/v1/system/tenants/${encodeURIComponent(args.slug)}/storage-quota`, {
            quotaBytes: args.quotaBytes,
          }),
        ),
      ),
  );
}
