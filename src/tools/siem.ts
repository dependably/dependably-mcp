import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci']);

// Known action prefixes for siem_list_auth_events (server filters by prefix match):
//   login.success | login.failure | login.locked
//   lockout.triggered
//   token.created | token.revoked
//   rbac.role_changed | rbac.member_added | rbac.member_removed
// Default server-side prefix set: login. / lockout. / token. / rbac.
const authActionPrefix = z
  .string()
  .describe(
    'Auth-event action prefix. Examples: "login.failure", "login.locked", "lockout.triggered", "token.revoked", "rbac.member_removed". Repeat the param to OR multiple prefixes.',
  );

export function registerSiemTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'siem_list_auth_events',
    'Stream auth events from the audit log (GET /api/v1/siem/events/auth) — login successes/failures, lockouts, token mints/revocations, role changes. Default lookback 24h, capped at SIEM_MAX_LOOKBACK_DAYS (default 90). Requires read:audit capability or a system-admin token.',
    {
      since: z.string().optional().describe('Lower bound as ISO-8601 timestamp. Default: 24h ago.'),
      until: z.string().optional().describe('Upper bound as ISO-8601 timestamp. Default: now.'),
      org: z.string().optional().describe('Org slug filter (system-admin tokens only — others are scoped to their own org).'),
      action: z.array(authActionPrefix).optional().describe('Filter to these action prefixes. Omit for the server-default set (login./lockout./token./rbac.).'),
      limit: z.number().int().positive().max(500).optional().describe('Page size, 1–500, default 100.'),
      cursor: z.string().optional().describe('Opaque cursor from a previous page\'s response.'),
    },
    async (args) =>
      run(async () => {
        const path = new URL(`http://x/api/v1/siem/events/auth`);
        if (args.since) path.searchParams.set('since', args.since);
        if (args.until) path.searchParams.set('until', args.until);
        if (args.org) path.searchParams.set('org', args.org);
        if (args.limit) path.searchParams.set('limit', String(args.limit));
        if (args.cursor) path.searchParams.set('cursor', args.cursor);
        for (const a of args.action ?? []) path.searchParams.append('action', a);
        const qs = path.search; // "?…" or ""
        return json(await client.get(`/api/v1/siem/events/auth${qs}`));
      }),
  );

  server.tool(
    'siem_vulnerabilities_summary',
    'Severity-bucketed vulnerability summary across packages (GET /api/v1/siem/vulnerabilities/summary). Returns { by_ecosystem: { ecosystem: { severity: count } }, packages_total, packages_affected }.',
    {
      org: z.string().optional().describe('Org slug filter (system-admin tokens only).'),
      ecosystem: ecosystem.optional(),
    },
    async (args) =>
      run(async () => json(await client.get('/api/v1/siem/vulnerabilities/summary', { org: args.org, ecosystem: args.ecosystem }))),
  );
}
