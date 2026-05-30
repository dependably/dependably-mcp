import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';

// Health / metrics / observability snapshot. Use these to triage incidents:
//   - readiness_check       → which subsystem reports degraded?
//   - get_observability_snapshot → blob sizes, last-success age per background job, since-startup counters, /metrics scrape diagnostics
//   - get_prometheus_metrics → raw Prometheus text (IP-allowlisted server-side; bearer token is ignored)
export function registerObservabilityTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'health_check',
    'Liveness probe (GET /health). Returns 200 with { status: "ok" } as long as the process is running.',
    {},
    async () => run(async () => json(await client.get('/health'))),
  );

  server.tool(
    'readiness_check',
    'Readiness probe (GET /ready). Returns { status: "ready"|"degraded", checks, errors }. 503 with details when a subsystem (DB, blob store, etc.) is failing — use this first when investigating an incident.',
    {},
    async () => run(async () => json(await client.get('/ready'))),
  );

  server.tool(
    'get_version',
    'Server build version (GET /version).',
    {},
    async () => run(async () => json(await client.get('/version'))),
  );

  server.tool(
    'get_prometheus_metrics',
    'Raw Prometheus exposition (GET /metrics). The endpoint is gated by an IP allowlist server-side — if your MCP host isn\'t in the allowlist this returns 403. Output is text, not JSON.',
    {},
    async () => run(async () => json(await client.get('/metrics'))),
  );

  server.tool(
    'get_observability_snapshot',
    'Operator dashboard snapshot (GET /api/v1/system/observability). Includes blob store sizes per tier, last-success age per background job, since-startup counters (publishes, proxy fetches, cache hits/misses), recent /metrics scrape attempts. Requires a system-admin token.',
    {},
    async () => run(async () => json(await client.get('/api/v1/system/observability'))),
  );

  server.tool(
    'get_metrics_access_config',
    'Current /metrics IP allowlist + enable flag (GET /api/v1/system/metrics-access). Requires a system-admin token.',
    {},
    async () => run(async () => json(await client.get('/api/v1/system/metrics-access'))),
  );
}
