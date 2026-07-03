import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

// Health / metrics probes. Use these to triage incidents:
//   - readiness_check       → which subsystem reports degraded?
//   - get_prometheus_metrics → raw Prometheus text (IP-allowlisted server-side; bearer token is ignored)
// These endpoints are anonymous / IP-allowlisted, so they work without a PAT
// (subject to the /metrics IP allowlist).
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
}
