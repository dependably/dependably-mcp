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
import { LOOKUP_ECOSYSTEMS, REGISTRY_ECOSYSTEMS, SETUP_ECOSYSTEMS } from '../dist/ecosystems.js';
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

const base = {
  baseUrl: 'https://dependably.example.com',
  token: 'dpb_smoke',
  timeoutMs: 1000,
};

const CORE_TOOLS = [
  'check_dependencies',
  'get_install_command',
  'get_license_policy',
  'get_package',
  'get_publish_command',
  'get_remediation',
  'get_remediation_skill',
  'get_vulnerability',
  'health_check',
  'list_activity',
  'list_packages',
  'list_remediation_skills',
  'list_vulnerabilities',
  'lookup_package',
  'readiness_check',
  'search_packages',
  'siem_list_auth_events',
  'siem_vulnerabilities_summary',
].sort();

deepStrictEqual(await toolNames(base), CORE_TOOLS, 'the whole tool surface');


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

// check_dependencies is on the default surface and takes its input as an argument:
// it must expose no way to name a local file. Only the import tools read from disk.
{
  const schema = await toolSchema(base, 'check_dependencies');
  const props = Object.keys(schema.properties ?? {});
  ok(props.includes('packages'), 'packages must be offered');
  for (const forbidden of ['lockfile', 'path', 'file', 'dir']) {
    ok(!props.includes(forbidden), `check_dependencies must not accept a ${forbidden} argument`);
  }
  deepStrictEqual(
    (schema.required ?? []).includes('packages'),
    true,
    'packages must be required, so there is no path-shaped fallback',
  );
}

// The lockfile parser stays available to callers, but must never echo input bytes
// back in an error: V8 embeds the offending content in JSON parse messages.
{
  let msg = '';
  try {
    parseNpmLockfile('root:x:0:0:SECRET-CONTENT:/root:/bin/bash');
  } catch (e) {
    msg = e.message;
  }
  ok(msg.includes('not valid JSON'), `parse failure should be reported, got: ${msg}`);
  ok(!msg.includes('SECRET-CONTENT'), `parse failure must not echo input, got: ${msg}`);
  ok(!msg.includes('root:x'), `parse failure must not echo input, got: ${msg}`);
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

// The ecosystem vocabularies are a wire contract, and they are NOT the same across
// planes. A single shared enum was wrong in both directions at once: it offered rpm
// and oci to lookup_package (422 from the server) and withheld apk, terraform and hex
// from the registry tools, which serve them. Pin each plane's set as it reaches the
// client, not just the constant it came from.
{
  const enumOf = async (tool, field) => (await toolSchema(base, tool)).properties?.[field]?.enum;

  for (const tool of ['list_packages', 'get_package', 'list_vulnerabilities']) {
    deepStrictEqual(await enumOf(tool, 'ecosystem'), [...REGISTRY_ECOSYSTEMS], `${tool} offers the registry set`);
  }
  deepStrictEqual(
    await enumOf('check_dependencies', 'ecosystem'),
    [...REGISTRY_ECOSYSTEMS],
    'check_dependencies offers the registry set',
  );
  deepStrictEqual(
    await enumOf('lookup_package', 'ecosystem'),
    [...LOOKUP_ECOSYSTEMS],
    'lookup_package offers only what /api/v1/lookup accepts',
  );
  for (const tool of ['get_install_command', 'get_publish_command']) {
    deepStrictEqual(await enumOf(tool, 'ecosystem'), [...SETUP_ECOSYSTEMS], `${tool} offers only what it can spell`);
  }

  // The specific regressions, stated as behaviour rather than as list membership.
  for (const eco of ['apk', 'terraform', 'hex']) {
    ok(REGISTRY_ECOSYSTEMS.includes(eco), `registry tools must reach ${eco} — the instance serves packages there`);
  }
  for (const eco of ['rpm', 'oci', 'apk', 'terraform']) {
    ok(!LOOKUP_ECOSYSTEMS.includes(eco), `lookup_package must not offer ${eco} — the server answers 422`);
  }
  ok(LOOKUP_ECOSYSTEMS.includes('hex'), 'lookup_package must offer hex — the server accepts it');
  ok(!REGISTRY_ECOSYSTEMS.includes('go'), 'the Go ecosystem is spelled "golang"; "go" filters to nothing');
}

// Every tool advertises `additionalProperties: false`. That was a claim the runtime
// did not keep: the SDK builds a non-strict object from a raw shape, so an unknown
// property was silently dropped. A dropped `version` on lookup_package changes which
// package is being judged, so the advertised contract has to be the real one.
{
  await withClient(base, async (client) => {
    const { tools } = await client.listTools();
    for (const tool of tools) {
      deepStrictEqual(
        tool.inputSchema?.additionalProperties,
        false,
        `${tool.name} should advertise additionalProperties:false`,
      );
      const res = await client
        .callTool({ name: tool.name, arguments: { __unknown_probe__: 1 } })
        .catch((err) => ({ isError: true, content: [{ text: String(err) }] }));
      ok(res.isError, `${tool.name} must reject an unknown property, not ignore it`);
      ok(
        /unrecognized|unknown|not allowed/i.test(res.content[0].text),
        `${tool.name} should say the property was unrecognized, got: ${res.content[0].text.slice(0, 120)}`,
      );
    }
  });
}

console.log(
  `smoke OK: ${CORE_TOOLS.length} tools, no local-file surface, version ordering + lockfile parsing checked, no file-path surface on check_dependencies, unreachable-instance errors actionable`,
);
