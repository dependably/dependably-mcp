import { createRequire } from 'node:module';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerReadTools } from './tools/read.js';
import { registerSiemTools } from './tools/siem.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerSetupTools } from './tools/setup.js';
import { registerVulnTools } from './tools/vuln.js';

// The compiled file lives at dist/server.js, one level below the package root,
// and package.json is always present in the published tarball.
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

export function buildServer(client: DependablyClient, cfg: Config): McpServer {
  const server = new McpServer({
    name: 'dependably-mcp',
    version,
  });

  registerReadTools(server, client);
  // Project-scoped vulnerability tools take the dependency list as an argument;
  // no tool in this server reads a local file.
  registerVulnTools(server, client);
  registerSiemTools(server, client);
  registerObservabilityTools(server, client);
  registerSetupTools(server, cfg);

  return server;
}
