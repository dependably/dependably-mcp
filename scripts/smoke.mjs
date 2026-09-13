// Smoke test: boot the server in-process over an in-memory transport and
// assert the registered tool surface. No network, no Dependably instance.
// Run with `npm test` (builds first via pretest).
import { deepStrictEqual, ok } from 'node:assert';
import { createServer } from 'node:net';

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
  toolset: 'full',
};

const CORE_TOOLS = [
  'get_install_command',
  'get_license_policy',
  'get_package',
  'get_prometheus_metrics',
  'get_publish_command',
  'get_version',
  'get_vulnerability',
  'health_check',
  'list_activity',
  'list_packages',
  'list_vulnerabilities',
  'lookup_package',
  'readiness_check',
  'search_packages',
  'siem_list_auth_events',
  'siem_vulnerabilities_summary',
  'whoami',
  'yank_version',
].sort();

const IMPORT_TOOLS = ['admin_upload', 'import_manifest'];
// Loopback-only on the server (IP allowlist); DEPENDABLY_TOOLSET=remote leaves them out.
const LOOPBACK_TOOLS = ['get_prometheus_metrics', 'get_version'];
const REMOTE_TOOLS = CORE_TOOLS.filter((t) => !LOOPBACK_TOOLS.includes(t));

deepStrictEqual(await toolNames(base), CORE_TOOLS, 'default surface (no import root)');
deepStrictEqual(await toolNames({ ...base, toolset: 'remote' }), REMOTE_TOOLS, 'remote toolset drops the loopback probes');
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

// Reachability: a transport failure must name the setting to fix, not a bare "fetch failed".
// Bind an ephemeral port and release it, then connect to it: refused immediately, so this
// needs no network and no instance. (undici rejects well-known ports like 9 before dialling.)
{
  const port = await new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
  const cfg = { ...base, baseUrl: `http://127.0.0.1:${port}` };
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'smoke', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const res = await client.callTool({ name: 'health_check', arguments: {} });
  ok(res.isError, 'health_check against a closed port must report an error');
  const text = res.content[0].text;
  ok(text.includes('DEPENDABLY_BASE_URL'), `unreachable-instance error should name DEPENDABLY_BASE_URL, got: ${text}`);
  ok(text.includes('ECONNREFUSED'), `error should carry the underlying cause code, got: ${text}`);
  ok(text.includes('Nothing is listening'), `error should explain a refused connection, got: ${text}`);
  await client.close();
  await server.close();
}

console.log(
  `smoke OK: ${CORE_TOOLS.length} core tools, ${REMOTE_TOOLS.length} with DEPENDABLY_TOOLSET=remote, +${IMPORT_TOOLS.length} import tools when opted in, containment enforced, unreachable-instance errors actionable`,
);
