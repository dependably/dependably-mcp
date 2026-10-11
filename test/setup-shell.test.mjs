import { deepStrictEqual, ok } from 'node:assert';
import { afterEach, describe, it } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';

const base = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000 };
const v6 = { baseUrl: 'http://[::1]:8443', token: 'tok', timeoutMs: 5000 };
const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

async function call(cfg, name, args) {
  globalThis.fetch = async () => {
    throw new Error('setup tools must not touch the network');
  };
  const server = buildServer(new DependablyClient(cfg), cfg);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'unit', version: '0.0.0' });
  await Promise.all([server.connect(st), client.connect(ct)]);
  try {
    return await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
    await server.close();
  }
}

const install = async (cfg, ecosystem, pkg, version) =>
  (await call(cfg, 'get_install_command', { ecosystem, package: pkg, version })).content[0].text;
const publish = async (cfg, ecosystem, artifact_path) =>
  (await call(cfg, 'get_publish_command', { ecosystem, artifact_path })).content[0].text;

/** Every line of every bash fence: what a user would paste into a terminal. */
const shellLines = (text) =>
  [...text.matchAll(/```bash\n([\s\S]*?)\n```/g)].flatMap((m) => m[1].split('\n'));
/** A line with its quoted spans removed: what zsh and bash would still glob. */
const unquoted = (line) => line.replace(/'[^']*'/g, '').replace(/"[^"]*"/g, '');

const pkgFor = { golang: 'example.com/pkg', maven: 'g:a', terraform: 'hashicorp/aws', oci: 'library/nginx' };
const ecosystems = ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo', 'apk', 'terraform', 'hex'];
const artifactFor = (eco) => (eco === 'cargo' || eco === 'hex' ? './crate' : './dist/a.bin');

describe('setup tools — IPv6 base URL is quoted wherever it reaches a shell', () => {
  it('leaves no [ or ] outside quotes on any shell line, for every ecosystem, install and publish', async () => {
    let checked = 0;
    for (const eco of ecosystems) {
      for (const text of [await install(v6, eco, pkgFor[eco] ?? 'pkg', '1.0.0'), await publish(v6, eco, artifactFor(eco))]) {
        for (const line of shellLines(text)) {
          checked++;
          ok(!/[[\]]/.test(unquoted(line)), `${eco}: unquoted bracket in: ${line}`);
        }
      }
    }
    ok(checked > 15, `only ${checked} shell lines were checked`);
  });

  it('quotes each registry, proxy, host and upload URL it interpolates', async () => {
    ok((await install(v6, 'npm', 'left-pad')).includes(`npm install --registry='http://[::1]:8443/npm/' 'left-pad'`));
    const oci = await install(v6, 'oci', 'library/nginx', '1');
    ok(oci.includes(`docker login '[::1]:8443'\n`), oci);
    ok(oci.includes(`docker pull '[::1]:8443'/'library/nginx':'1'`), oci);
    ok((await install(v6, 'golang', 'example.com/pkg')).includes(`GOPROXY='http://[::1]:8443/go' go get`));
    ok((await install(v6, 'nuget', 'Pkg')).includes(`--source 'http://[::1]:8443/nuget/v3/index.json'`));
    ok((await install(v6, 'pypi', 'requests')).includes(`PIP_INDEX_URL="http://user:\${PIP_TOKEN}@[::1]:8443/simple/"`));
    ok((await publish(v6, 'npm', './a.tgz')).includes(`npm publish --registry='http://[::1]:8443/npm/' './a.tgz'`));
    ok((await publish(v6, 'pypi', './a.tgz')).includes(`--repository-url 'http://[::1]:8443/pypi/legacy/'`));
    ok((await publish(v6, 'rpm', './a.rpm')).includes(`'http://[::1]:8443/rpm/upload'`));
    ok((await publish(v6, 'maven', './a.jar')).includes(`-Durl='http://[::1]:8443/maven/'`));
    ok((await publish(v6, 'hex', './crate')).includes(`HEX_API_URL='http://[::1]:8443/hex/api'`));
    const ociPublish = await publish(v6, 'oci', './image.tar');
    ok(ociPublish.includes(`docker tag <name>:<tag> '[::1]:8443'/<image>:<tag>`), ociPublish);
  });

  it('leaves an ordinary DNS base unquoted', async () => {
    ok((await install(base, 'npm', 'left-pad')).includes('npm install --registry=https://dep.example.com/npm/ '));
  });
});

describe('setup tools — npm scope registry', () => {
  it('names the scope of a scoped install so a user @scope:registry cannot redirect it', async () => {
    deepStrictEqual(shellLines(await install(base, 'npm', '@acme/widget', '2.0.0')), [
      `npm install --registry=https://dep.example.com/npm/ --@acme:registry=https://dep.example.com/npm/ '@acme/widget@2.0.0'`,
    ]);
  });

  it('quotes the scope flag too for an IPv6 base', async () => {
    deepStrictEqual(shellLines(await install(v6, 'npm', '@acme/widget')), [
      `npm install --registry='http://[::1]:8443/npm/' --@acme:registry='http://[::1]:8443/npm/' '@acme/widget'`,
    ]);
  });

  it('adds no scope flag for an unscoped install', async () => {
    ok(!(await install(base, 'npm', 'left-pad')).includes(':registry='));
  });

  it('warns publishers, outside the command block, that scoped packages need --@scope:registry', async () => {
    const text = await publish(base, 'npm', './a.tgz');
    const prose = text.replace(/```[\s\S]*?```/g, '');
    ok(prose.includes('--@scope:registry=https://dep.example.com/npm/'), prose);
    ok(prose.includes('publishConfig'), prose);
    ok(!shellLines(text).join('\n').includes('@scope'), 'the unknown scope is not invented inside the command');
  });
});

describe('setup tools — what a user pastes runs in interactive zsh', () => {
  it('puts every explanation outside the shell fences', async () => {
    for (const eco of ecosystems) {
      for (const text of [await install(base, eco, pkgFor[eco] ?? 'pkg', '1.0.0'), await publish(base, eco, artifactFor(eco)), await publish(base, eco, './x.crate')]) {
        for (const line of shellLines(text)) ok(!/(^|\s)#/.test(unquoted(line)), `${eco}: comment in a shell fence: ${line}`);
      }
    }
  });

  it('keeps a token read on one subshell line, never beside another command that could swallow it', async () => {
    const lines = [];
    for (const eco of ecosystems) {
      lines.push(...shellLines(await install(v6, eco, pkgFor[eco] ?? 'pkg')), ...shellLines(await publish(v6, eco, artifactFor(eco))));
    }
    const reads = lines.filter((l) => l.includes('read -rs'));
    ok(reads.length >= 5, `found only ${reads.length} reads`);
    for (const line of reads) ok(/^\( read -rs \w+ && .* \)$/.test(line), line);
  });
});
