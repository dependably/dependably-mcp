import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, structured, paginationSchema } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const activityEvent = z.object({
  id: z.string().optional(),
  event_type: z.string().optional(),
  ecosystem: z.string().nullable().optional(),
  purl: z.string().nullable().optional(),
  actor_email: z.string().nullable().optional(),
  source_ip: z.string().nullable().optional(),
  detail: z.string().nullable().optional(),
  created_at: z.string().optional(),
}).passthrough();

const auditEntry = z.object({
  id: z.string().optional(),
  action: z.string().optional(),
  actor_email: z.string().nullable().optional(),
  ecosystem: z.string().nullable().optional(),
  purl: z.string().nullable().optional(),
  detail: z.string().nullable().optional(),
  created_at: z.string().optional(),
}).passthrough();

export function registerAuditTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'list_activity',
    {
      title: 'List activity',
      description: [
        'Package-operation activity feed for the caller\'s org. Filter by event_type for incident investigation.',
        'Known event_type values:',
        '  blocking: blocked, blocked_manual, blocked_vuln_score, blocked_release_age',
        '  allow/block lists: allowlist_added, allowlist_removed, blocklist_added, blocklist_removed',
        '  license policy: license_allowlist_added, license_allowlist_removed, license_blocklist_added, license_blocklist_removed, license_policy_mode_changed',
        '  registry I/O: first_fetch, download, push, pull, blob.get, manifest.get',
        '  membership: member_role_changed, member_removed',
        '  claims: claim.create, claim.release, claim.transition',
        '  settings: org_settings_updated, proxy_settings_updated, retention_updated, saml.config_deleted',
      ].join('\n'),
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        event_type: z.string().optional().describe('One of the documented event_type values.'),
        ...paginationSchema,
      },
      outputSchema: {
        items: z.array(activityEvent),
        total: z.number().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
        page: z.number().optional(),
      },
    },
    async (args) =>
      run(async () =>
        structured(
          await client.get('/api/v1/activity', {
            event_type: args.event_type,
            page: args.page,
            limit: args.limit,
            format: 'json',
          }),
        ),
      ),
  );

  server.registerTool(
    'list_audit_log',
    {
      title: 'List audit log',
      description: 'Config-mutation audit log (membership, settings, tokens, allowlists, etc.). Filter by action.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {
        action: z.string().optional().describe('Filter to a specific action (server-defined vocabulary).'),
        ...paginationSchema,
      },
      outputSchema: {
        items: z.array(auditEntry),
        total: z.number().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
        page: z.number().optional(),
      },
    },
    async (args) =>
      run(async () =>
        structured(
          await client.get('/api/v1/audit', {
            action: args.action,
            page: args.page,
            limit: args.limit,
            format: 'json',
          }),
        ),
      ),
  );
}
