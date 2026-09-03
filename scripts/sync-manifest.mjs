// Keeps manifest.json (the Claude Desktop extension manifest) in step with the
// server it describes. The tool list is generated from the real server over an
// in-memory transport, so the manifest can never drift from what the bundle
// actually exposes.
//
//   node scripts/sync-manifest.mjs          rewrite manifest.json in place
//   node scripts/sync-manifest.mjs --check  exit 1 if manifest.json is stale
//
// Only the default surface is listed (no import root). The two import tools
// are runtime opt-ins, which is what `tools_generated: true` signals.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = join(root, 'manifest.json');
const check = process.argv.includes('--check');

const cfg = { baseUrl: 'https://dependably.example.com', token: 'sync', timeoutMs: 1000 };
const server = buildServer(new DependablyClient(cfg), cfg);
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: 'sync-manifest', version: '0.0.0' });
await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
const { tools } = await client.listTools();
await client.close();
await server.close();

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const next = {
  ...manifest,
  version: pkg.version,
  tools: tools
    .map((t) => ({ name: t.name, description: t.description ?? '' }))
    .sort((a, b) => a.name.localeCompare(b.name)),
};

const current = JSON.stringify(manifest, null, 2) + '\n';
const rendered = JSON.stringify(next, null, 2) + '\n';

if (check) {
  if (current !== rendered) {
    process.stderr.write(
      'manifest.json is stale (version or tool list differs from the server). Run `npm run manifest:sync`.\n',
    );
    process.exit(1);
  }
  console.log(`manifest OK: version ${next.version}, ${next.tools.length} tools`);
} else {
  writeFileSync(manifestPath, rendered);
  console.log(`manifest.json updated: version ${next.version}, ${next.tools.length} tools`);
}
