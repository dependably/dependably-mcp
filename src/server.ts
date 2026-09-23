import { createRequire } from 'node:module';

import { McpServer, type RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { FALLBACK_PLANES, type EcosystemPlanes } from './ecosystems.js';
import { registerReadTools } from './tools/read.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerProjectTools } from './tools/projects.js';
import { registerSetupTools } from './tools/setup.js';
import { registerVulnTools } from './tools/vuln.js';

// The compiled file lives at dist/server.js, one level below the package root,
// and package.json is always present in the published tarball.
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

/**
 * Every tool here is reachable with a **Pull** token — the preset any member can
 * mint. Nothing in the surface requires a capability that only an admin or owner
 * can grant, which is what keeps the install instruction to one sentence.
 */
export function buildServer(client: DependablyClient, cfg: Config, planes: EcosystemPlanes = FALLBACK_PLANES): McpServer {
  return createServer(client, cfg, planes).server;
}

/**
 * {@link buildServer}, plus a way to swap the ecosystem vocabulary after the
 * server is connected. The vocabulary is baked into each tool's advertised
 * input schema, so a change means re-registering the tools; the client learns
 * of it through one debounced `notifications/tools/list_changed`.
 */
export function createServer(
  client: DependablyClient,
  cfg: Config,
  planes: EcosystemPlanes = FALLBACK_PLANES,
): { server: McpServer; replacePlanes(planes: EcosystemPlanes): void } {
  const server = new McpServer(
    {
      name: 'dependably-mcp',
      version,
    },
    { debouncedNotificationMethods: ['notifications/tools/list_changed'] },
  );

  let tools = registerTools(server, client, cfg, planes);

  return {
    server,
    // Synchronous from the first remove to the last register, so no tool call
    // can land while a tool is missing.
    replacePlanes(next) {
      for (const tool of tools) tool.remove();
      tools = registerTools(server, client, cfg, next);
    },
  };
}

function registerTools(server: McpServer, client: DependablyClient, cfg: Config, planes: EcosystemPlanes): RegisteredTool[] {
  return [
    ...registerReadTools(server, client, planes),
    // Project-scoped vulnerability tools take the dependency list as an argument;
    // no tool in this server reads a local file.
    ...registerVulnTools(server, client, planes),
    ...registerProjectTools(server, client),
    ...registerObservabilityTools(server, client),
    ...registerSetupTools(server, cfg, planes),
  ];
}
