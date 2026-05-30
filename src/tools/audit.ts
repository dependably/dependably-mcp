import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, paginationSchema } from '../format.js';

export function registerAuditTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'list_activity',
    [
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
    {
      event_type: z.string().optional().describe('One of the documented event_type values.'),
      ...paginationSchema,
    },
    async (args) =>
      run(async () =>
        json(
          await client.get('/api/v1/activity', {
            event_type: args.event_type,
            page: args.page,
            limit: args.limit,
            format: 'json',
          }),
        ),
      ),
  );

  server.tool(
    'list_audit_log',
    'Config-mutation audit log (membership, settings, tokens, allowlists, etc.). Filter by action.',
    {
      action: z.string().optional().describe('Filter to a specific action (server-defined vocabulary).'),
      ...paginationSchema,
    },
    async (args) =>
      run(async () =>
        json(
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
