import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, paginationSchema } from '../format.js';

// All tools here require a system-admin JWT/token at the apex host. If your token
// isn't system-scoped, every call returns 401/403 from upstream.
export function registerSystemTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'system_list_tenants',
    'List all tenants (orgs) on the instance, with member and storage counts. Requires a system-admin token at the apex host.',
    { ...paginationSchema },
    async (args) =>
      run(async () => json(await client.get('/api/v1/system/tenants', { page: args.page, limit: args.limit }))),
  );

  server.tool(
    'system_dashboard',
    'System dashboard snapshot: tenant counts by status, admin counts, recent job runs.',
    {},
    async () => run(async () => json(await client.get('/api/v1/system/dashboard'))),
  );

  server.tool(
    'system_list_background_jobs',
    'List background job runs (vuln scans, rescans, retention, GC). Filter by outcome="server_error" to find failed runs during incident investigation. Valid outcomes: success | server_error | cancelled.',
    {
      jobName: z.string().optional().describe('Use system_list_background_job_facets to discover valid names.'),
      outcome: z.enum(['success', 'server_error', 'cancelled']).optional(),
      search: z.string().optional(),
      sortBy: z.enum(['startedAt', 'jobName', 'durationMs', 'outcome']).optional(),
      sortDir: z.enum(['asc', 'desc']).optional(),
      ...paginationSchema,
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

  server.tool(
    'system_list_audit',
    'System-scope audit log (control-plane events, not tenant events).',
    {
      action: z.string().optional(),
      search: z.string().optional(),
      sortBy: z.enum(['createdAt', 'action']).optional(),
      sortDir: z.enum(['asc', 'desc']).optional(),
      ...paginationSchema,
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

  server.tool(
    'system_list_background_job_facets',
    'Return the vocabulary for filtering background jobs: { jobNames: [...], outcomes: ["success","server_error","cancelled"] }.',
    {},
    async () => run(async () => json(await client.get('/api/v1/system/background-jobs/facets'))),
  );

  server.tool(
    'system_get_instance_settings',
    'Read instance-wide settings (upload limits, GC schedule, SIEM lookback).',
    {},
    async () => run(async () => json(await client.get('/api/v1/system/settings'))),
  );

  server.tool(
    'system_set_tenant_storage_quota',
    'Set or clear the storage quota cap for a tenant (PATCH /api/v1/system/tenants/{slug}/storage-quota). Pass quotaBytes=null to clear.',
    {
      slug: z.string().describe('Tenant slug from system_list_tenants.'),
      quotaBytes: z.number().int().nonnegative().nullable().describe('New quota in bytes, or null to clear.'),
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
