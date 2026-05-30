import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { DependablyClient } from './client.js';
import type { Config } from './config.js';
import { registerPackagesTools } from './tools/packages.js';
import { registerVulnsTools } from './tools/vulns.js';
import { registerAuditTools } from './tools/audit.js';
import { registerTokensTools } from './tools/tokens.js';
import { registerListsTools } from './tools/lists.js';
import { registerSettingsTools } from './tools/settings.js';
import { registerUsersTools } from './tools/users.js';
import { registerClaimsTools } from './tools/claims.js';
import { registerObservabilityTools } from './tools/observability.js';
import { registerSetupTools } from './tools/setup.js';
import { registerSiemTools } from './tools/siem.js';
import { registerSystemTools } from './tools/system.js';

export function buildServer(client: DependablyClient, cfg: Config): McpServer {
  const server = new McpServer({
    name: 'dependably-mcp',
    version: '0.1.0',
  });

  registerPackagesTools(server, client);
  registerVulnsTools(server, client);
  registerAuditTools(server, client);
  registerTokensTools(server, client);
  registerListsTools(server, client);
  registerSettingsTools(server, client);
  registerUsersTools(server, client);
  registerClaimsTools(server, client);
  registerSetupTools(server, client, cfg);
  registerObservabilityTools(server, client);
  registerSiemTools(server, client);
  registerSystemTools(server, client);

  return server;
}
