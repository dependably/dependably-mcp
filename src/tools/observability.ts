import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

// Health probes. Use readiness_check first when triaging an incident: it names the
// subsystem reporting degraded. Both endpoints are anonymous, so they work without a PAT
// and from any host.
//
// /version and /metrics are deliberately not wrapped: the server allowlists both to its own
// host, so a tool for either would fail for every client that is not running on it.
export function registerObservabilityTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'health_check',
    {
      title: 'Health check',
      description: 'Liveness probe (GET /health). Returns 200 with { status: "ok" } as long as the process is running.',
      annotations: READ_ANNOTATIONS,
      inputSchema: z.object({}).strict(),
    },
    async () => run(async () => json(await client.get('/health'))),
  );

  server.registerTool(
    'readiness_check',
    {
      title: 'Readiness check',
      description: 'Readiness probe (GET /ready). Returns { status: "ready"|"degraded", checks, errors }. 503 with details when a subsystem (DB, blob store, etc.) is failing — use this first when investigating an incident.',
      annotations: READ_ANNOTATIONS,
      inputSchema: z.object({}).strict(),
    },
    async () => run(async () => json(await client.get('/ready'))),
  );
}
