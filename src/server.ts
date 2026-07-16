import { createRequire } from 'node:module';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerYankTools } from './tools/yank.js';
import { registerSiemTools } from './tools/siem.js';
import { registerImportTools } from './tools/import.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerSetupTools } from './tools/setup.js';

// The compiled file lives at dist/server.js, one level below the package root,
// and package.json is always present in the published tarball.
const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

export function buildServer(client: DependablyClient, cfg: Config): McpServer {
  const server = new McpServer({
    name: 'dependably-mcp',
    version,
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
