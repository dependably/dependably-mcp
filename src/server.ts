import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerVulnsTools } from './tools/vulns.js';
import { registerSiemTools } from './tools/siem.js';
import { registerImportTools } from './tools/import.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerSetupTools } from './tools/setup.js';

export function buildServer(client: DependablyClient, cfg: Config): McpServer {
  const server = new McpServer({
    name: 'dependably-mcp',
    version: '0.1.0',
  });

  registerVulnsTools(server, client);
  registerSiemTools(server, client);
  registerImportTools(server, client, cfg);
  registerObservabilityTools(server, client);
  registerSetupTools(server, cfg);

  return server;
}
