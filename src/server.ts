import { createRequire } from 'node:module';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerYankTools } from './tools/yank.js';
import { registerReadTools } from './tools/read.js';
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

  registerReadTools(server, client);
  registerYankTools(server, client);
  registerSiemTools(server, client);
  // The import tools read local files and upload them, so they are opt-in:
  // registered only when DEPENDABLY_IMPORT_ROOT scopes what they may read.
  if (cfg.importRoot) {
    registerImportTools(server, cfg);
  }
  // /version and /metrics are IP-allowlisted to loopback on the server, so a
  // client that is not on the Dependably host itself gets a 403 from both.
  // `remote` leaves them out rather than shipping tools that can never succeed.
  registerObservabilityTools(server, client, { loopbackProbes: cfg.toolset !== 'remote' });
  registerSetupTools(server, cfg);

  return server;
}
