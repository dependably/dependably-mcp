#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { DependablyClient } from './client.js';
import { loadConfig } from './config.js';
import { buildServer } from './server.js';

async function main(): Promise<void> {
  const cfg = loadConfig();
  const client = new DependablyClient(cfg);
  const server = buildServer(client, cfg);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`dependably-mcp: ${msg}\n`);
  process.exit(1);
});
