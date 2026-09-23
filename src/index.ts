#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { DependablyClient } from './client.js';
import { loadConfig } from './config.js';
import { fetchEcosystems, retryEcosystems } from './ecosystems.js';
import { createServer } from './server.js';

async function main(): Promise<void> {
  const cfg = loadConfig();
  const client = new DependablyClient(cfg);
  const eco = await fetchEcosystems(client);
  if (eco.source === 'fallback') {
    process.stderr.write(`dependably-mcp: using the built-in ecosystem list; /api/v1/ecosystems ${eco.reason}\n`);
  }
  const { server, replacePlanes } = createServer(client, cfg, eco.planes);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  if (eco.source === 'fallback' && eco.retryable) {
    retryEcosystems(client, replacePlanes, (line) => process.stderr.write(`dependably-mcp: ${line}\n`));
  }
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`dependably-mcp: ${msg}\n`);
  process.exit(1);
});
