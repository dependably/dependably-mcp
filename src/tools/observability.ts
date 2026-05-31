import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

// Health / metrics / observability snapshot. Use these to triage incidents:
//   - readiness_check       → which subsystem reports degraded?
//   - get_observability_snapshot → blob sizes, last-success age per background job, since-startup counters, /metrics scrape diagnostics
//   - get_prometheus_metrics → raw Prometheus text (IP-allowlisted server-side; bearer token is ignored)
export function registerObservabilityTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'health_check',
    {
      title: 'Health check',
      description: 'Liveness probe (GET /health). Returns 200 with { status: "ok" } as long as the process is running.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/health'))),
  );

  server.registerTool(
    'readiness_check',
    {
      title: 'Readiness check',
      description: 'Readiness probe (GET /ready). Returns { status: "ready"|"degraded", checks, errors }. 503 with details when a subsystem (DB, blob store, etc.) is failing — use this first when investigating an incident.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/ready'))),
  );

  server.registerTool(
    'get_version',
    {
      title: 'Server version',
      description: 'Server build version (GET /version).',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/version'))),
  );

  server.registerTool(
    'get_prometheus_metrics',
    {
      title: 'Prometheus metrics',
      description: 'Raw Prometheus exposition (GET /metrics). The endpoint is gated by an IP allowlist server-side — if your MCP host isn\'t in the allowlist this returns 403. Output is text, not JSON.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/metrics'))),
  );

  server.registerTool(
    'get_observability_snapshot',
    {
      title: 'Observability snapshot',
      description: 'Operator dashboard snapshot (GET /api/v1/system/observability). Includes blob store sizes per tier, last-success age per background job, since-startup counters (publishes, proxy fetches, cache hits/misses), recent /metrics scrape attempts. Requires a system-admin token.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/system/observability'))),
  );

  server.registerTool(
    'get_metrics_access_config',
    {
      title: 'Metrics access config',
      description: 'Current /metrics IP allowlist + enable flag (GET /api/v1/system/metrics-access). Requires a system-admin token.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
    },
    async () => run(async () => json(await client.get('/api/v1/system/metrics-access'))),
  );
}
