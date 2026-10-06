import type { McpServer, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { DependablyApiError } from '../client.js';
import { json, run, withSummary } from '../format.js';

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
export function registerObservabilityTools(server: McpServer, client: DependablyClient): RegisteredTool[] {
  const tools: RegisteredTool[] = [];

  tools.push(server.registerTool(
    'readiness_check',
    {
      title: 'Readiness check',
      description: 'Readiness probe (GET /ready). Returns { status, strict, checks, required, degraded }: status is "ready" (every dependency up), "degraded" (a non-required dependency is down but the instance still serves), "unready" (a required dependency is down) or "draining" (shutting down); `checks` maps each dependency to its state and `degraded` names the failing ones. Use this first when investigating an incident. Needs no token.',
      annotations: READ_ANNOTATIONS,
      inputSchema: z.object({}).strict(),
    },
    async () =>
      run(async () => {
        try {
          return json(await client.get('/ready'));
        } catch (e) {
          // /ready answers 503 with the same body when a required dependency is
          // down or the instance is draining; that body is the answer, not an error.
          if (!(e instanceof DependablyApiError) || e.status !== 503 || !e.body) throw e;
          let body: unknown;
          try {
            body = JSON.parse(e.body);
          } catch {
            throw e;
          }
          return withSummary('The instance answered 503: it is not ready to serve.', body);
        }
      }),
  ));

  return tools;
}
