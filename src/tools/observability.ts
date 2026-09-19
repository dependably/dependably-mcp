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
// subsystem reporting degraded. The endpoint is anonymous, so it works without a PAT and from
// any host — which is what makes it the first call in the install-verification sequence: it
// separates "the base URL is wrong" from "the token is wrong", the only tool on the surface
// that can.
//
// /health is deliberately not wrapped alongside it. Liveness is a strict subset of readiness:
// if /ready answers, /health adds nothing, and if it does not, /health will not either. A
// developer never needs both, and this surface carries only what a developer needs.
//
// /version and /metrics are not wrapped either — a live instance answers /metrics with more
// Prometheus text than most model context windows hold, so no agent can usefully read it.
export function registerObservabilityTools(server: McpServer, client: DependablyClient): void {
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
