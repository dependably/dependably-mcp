// Smoke test: boot the server in-process over an in-memory transport and
// assert the registered tool surface. No network, no Dependably instance.
// Run with `npm test` (builds first via pretest).
import { deepStrictEqual, ok } from 'node:assert';
import { createServer } from 'node:net';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { compare, gte, maxVersion } from '../dist/semver.js';
import { buildFindings, parseNpmLockfile } from '../dist/vuln.js';
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

async function withClient(cfg, fn) {
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'smoke', version: '0.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

async function toolSchema(cfg, name) {
  return withClient(cfg, async (client) => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === name);
    ok(tool, `tool ${name} should be registered`);
    return tool.inputSchema ?? {};
  });
}

async function callTool(cfg, name, args) {
  return withClient(cfg, (client) => client.callTool({ name, arguments: args }));
}

const base = {
  baseUrl: 'https://dependably.example.com',
  token: 'dpb_smoke',
  timeoutMs: 1000,
  toolset: 'full',
};

const CORE_TOOLS = [
  'check_dependencies',
  'get_install_command',
  'get_license_policy',
  'get_package',
  'get_prometheus_metrics',
  'get_publish_command',
  'get_remediation',
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

// Version ordering: bumpTo is only as good as this comparator.
{
  ok(compare('3.1.3', '3.1.6') < 0, '3.1.3 < 3.1.6');
  ok(compare('0.0.33', '0.2.6') < 0, '0.0.33 < 0.2.6 (0.x lines still order numerically)');
  ok(compare('4.13.7', '4.13.5') > 0, '4.13.7 > 4.13.5');
  ok(compare('10.7.0', '10.3.1') > 0, '10.7.0 > 10.3.1 (numeric, not lexical)');
  ok(compare('1.19.14', '2.0.5') < 0, 'major dominates');
  ok(compare('1.2.3', '1.2.3') === 0, 'equal versions compare equal');
  ok(compare('1.2.3-rc.1', '1.2.3') < 0, 'a prerelease sorts below its release');
  ok(compare('1.2.3+build', '1.2.3') === 0, 'build metadata is ignored');
  ok(gte('7.5.22', '7.5.21') && !gte('7.5.20', '7.5.21'), 'gte boundary');
  // The ceiling matters: several advisories are incomplete-fix follow-ups, so the
  // lowest fixed version does not clear the rest.
  deepStrictEqual(maxVersion(['3.1.4', '3.1.6', '3.1.5']), '3.1.6', 'ceiling across fixes');
  deepStrictEqual(maxVersion([]), undefined, 'empty list has no ceiling');
}

// buildFindings: ceiling per package, and no bump suggested when already clear.
{
  const hits = [
    { packageName: 'fast-uri', version: '3.1.3', osvId: 'A', severity: 'HIGH', cvssScore: 7.5 },
    { packageName: 'fast-uri', version: '3.1.3', osvId: 'B', severity: 'HIGH', cvssScore: 7.5 },
  ];
  const devOf = new Map([['fast-uri@3.1.3', false]]);
  const rem = new Map([
    ['A@@3.1.3', { fixedVersion: '3.1.4', cwes: [], owasp: [], skills: [] }],
    ['B@@3.1.3', { fixedVersion: '3.1.6', cwes: [], owasp: [], skills: [] }],
  ]);
  const [finding] = buildFindings(hits, devOf, rem);
  deepStrictEqual(finding.bumpTo, '3.1.6', 'bumpTo takes the highest fix, not the first');
  deepStrictEqual(finding.advisories.length, 2, 'advisories grouped under one package');

  const already = buildFindings(
    [{ packageName: 'x', version: '2.0.0', osvId: 'C', severity: 'LOW' }],
    new Map([['x@2.0.0', true]]),
    new Map([['C@@2.0.0', { fixedVersion: '1.9.0', cwes: [], owasp: [], skills: [] }]]),
  );
  deepStrictEqual(already[0].bumpTo, null, 'no bump when installed already exceeds the fix');
}

// Lockfile parsing: dev marker carried through, project root entry skipped.
{
  const pkgs = parseNpmLockfile(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/b': { version: '2.0.0', dev: true },
        'node_modules/c': { version: '3.0.0', link: true },
      },
    }),
  );
  deepStrictEqual(
    pkgs.sort((x, y) => x.name.localeCompare(y.name)),
    [
      { name: 'a', version: '1.0.0', dev: false },
      { name: 'b', version: '2.0.0', dev: true },
    ],
    'lockfile parse skips the root and link entries, keeps the dev marker',
  );

  let threw = '';
  try {
    parseNpmLockfile(JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
  } catch (e) {
    threw = e.message;
  }
  ok(threw.includes('lockfileVersion 1'), `v1 lockfile should be refused by name, got: ${threw}`);
}

// check_dependencies is on the default surface, but its lockfile parameter is not:
// reading a local file stays gated behind DEPENDABLY_PROJECT_ROOT.
{
  const withoutRoot = await toolSchema(base, 'check_dependencies');
  ok(!('lockfile' in (withoutRoot.properties ?? {})), 'lockfile must not be offered without DEPENDABLY_PROJECT_ROOT');
  ok('packages' in (withoutRoot.properties ?? {}), 'packages must always be offered');

  const withRoot = await toolSchema({ ...base, projectRoot: process.cwd() }, 'check_dependencies');
  ok('lockfile' in (withRoot.properties ?? {}), 'lockfile must be offered once DEPENDABLY_PROJECT_ROOT is set');
}

// Containment: the same rule the import tools enforce applies to lockfile reads.
{
  const cfg = { ...base, projectRoot: process.cwd() };
  const res = await callTool(cfg, 'check_dependencies', { ecosystem: 'npm', lockfile: '/etc/hosts' });
  ok(res.isError, 'check_dependencies must refuse a lockfile outside DEPENDABLY_PROJECT_ROOT');
  ok(
    res.content[0].text.includes('DEPENDABLY_PROJECT_ROOT'),
    `refusal should name DEPENDABLY_PROJECT_ROOT, got: ${res.content[0].text}`,
  );
}

// Argument validation happens before any network I/O, so these fail fast with a
// usable message rather than a transport error against the unreachable example host.
{
  const res = await callTool(base, 'check_dependencies', { ecosystem: 'npm' });
  ok(res.isError, 'check_dependencies with neither packages nor lockfile must error');
  ok(res.content[0].text.includes('packages'), `error should name the packages argument, got: ${res.content[0].text}`);
}
{
  const cfg = { ...base, projectRoot: process.cwd() };
  const res = await callTool(cfg, 'check_dependencies', {
    ecosystem: 'npm',
    lockfile: 'package-lock.json',
    packages: [{ name: 'x', version: '1.0.0' }],
  });
  ok(res.isError, 'check_dependencies must refuse both packages and lockfile');
  ok(res.content[0].text.includes('not both'), `error should say not both, got: ${res.content[0].text}`);
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
  `smoke OK: ${CORE_TOOLS.length} core tools, ${REMOTE_TOOLS.length} with DEPENDABLY_TOOLSET=remote, +${IMPORT_TOOLS.length} import tools when opted in, version ordering + lockfile parsing checked, import + project containment enforced, unreachable-instance errors actionable`,
);
