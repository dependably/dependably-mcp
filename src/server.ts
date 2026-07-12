import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerYankTools } from './tools/yank.js';
import { registerSiemTools } from './tools/siem.js';
import { registerImportTools } from './tools/import.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerSetupTools } from './tools/setup.js';

export function buildServer(client: DependablyClient, cfg: Config): McpServer {
  const server = new McpServer({
    name: 'dependably-mcp',
    version: '0.1.0',
  });

  registerYankTools(server, client);
  registerSiemTools(server, client);
  // The import tools read local files and upload them, so they are opt-in:
  // registered only when DEPENDABLY_IMPORT_ROOT scopes what they may read.
  if (cfg.importRoot) {
    registerImportTools(server, cfg);
  }
  registerObservabilityTools(server, client);
  registerSetupTools(server, cfg);

  return server;
}
