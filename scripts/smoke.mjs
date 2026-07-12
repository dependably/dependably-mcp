// Smoke test: boot the server in-process over an in-memory transport and
// assert the registered tool surface. No network, no Dependably instance.
// Run with `npm test` (builds first via pretest).
import { deepStrictEqual, ok } from 'node:assert';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';

async function toolNames(cfg) {
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'smoke', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const { tools } = await client.listTools();
  await client.close();
  await server.close();
  return tools.map((t) => t.name).sort();
}

const base = {
  baseUrl: 'https://dependably.example.com',
  token: 'dpb_smoke',
  timeoutMs: 1000,
};

const CORE_TOOLS = [
  'get_install_command',
  'get_prometheus_metrics',
  'get_publish_command',
  'get_version',
  'health_check',
  'readiness_check',
  'siem_list_auth_events',
  'siem_vulnerabilities_summary',
  'yank_version',
].sort();

const IMPORT_TOOLS = ['admin_upload', 'import_manifest'];

deepStrictEqual(await toolNames(base), CORE_TOOLS, 'default surface (no import root)');
deepStrictEqual(
  await toolNames({ ...base, importRoot: process.cwd() }),
  [...CORE_TOOLS, ...IMPORT_TOOLS].sort(),
  'surface with DEPENDABLY_IMPORT_ROOT set',
);

// Containment: a path outside the import root must be refused before any network I/O.
{
  const cfg = { ...base, importRoot: process.cwd() };
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'smoke', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const res = await client.callTool({ name: 'admin_upload', arguments: { files: ['/etc/hosts'] } });
  ok(res.isError, 'admin_upload must refuse files outside DEPENDABLY_IMPORT_ROOT');
  ok(
    res.content[0].text.includes('DEPENDABLY_IMPORT_ROOT'),
    `refusal should name DEPENDABLY_IMPORT_ROOT, got: ${res.content[0].text}`,
  );
  await client.close();
  await server.close();
}

console.log(`smoke OK: ${CORE_TOOLS.length} core tools, +${IMPORT_TOOLS.length} import tools when opted in, containment enforced`);
