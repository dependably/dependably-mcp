import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
const publish = async (cfg, ecosystem, artifact_path, extra = {}) =>
  (await call(cfg, 'get_publish_command', { ecosystem, artifact_path, ...extra })).content[0].text;
const publishRaw = (cfg, ecosystem, artifact_path, extra = {}) => call(cfg, 'get_publish_command', { ecosystem, artifact_path, ...extra });
const mavenIds = { groupId: 'com.acme', artifactId: 'widget', version: '1.2.3' };
const ociIds = { image: 'team/app', tag: '1.0.0' };
const extraFor = (eco) => (eco === 'maven' ? mavenIds : eco === 'oci' ? ociIds : {});

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
      for (const text of [await install(v6, eco, pkgFor[eco] ?? 'pkg', '1.0.0'), await publish(v6, eco, artifactFor(eco), extraFor(eco))]) {
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
    ok((await publish(v6, 'maven', './a.jar', mavenIds)).includes(`-Durl='http://[::1]:8443/maven/'`));
    ok((await publish(v6, 'hex', './crate')).includes(`HEX_API_URL='http://[::1]:8443/hex/api'`));
    const ociPublish = await publish(v6, 'oci', './image.tar', ociIds);
    ok(ociPublish.includes(`docker tag "$IMG" '[::1]:8443'/'team/app':'1.0.0'`), ociPublish);
    ok(ociPublish.includes(`docker push '[::1]:8443'/'team/app':'1.0.0'`), ociPublish);
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
      for (const text of [await install(base, eco, pkgFor[eco] ?? 'pkg', '1.0.0'), await publish(base, eco, artifactFor(eco), extraFor(eco)), await publish(base, eco, './x.crate', extraFor(eco)), await publish(base, eco, artifactFor(eco))]) {
        for (const line of shellLines(text)) ok(!/(^|\s)#/.test(unquoted(line)), `${eco}: comment in a shell fence: ${line}`);
      }
    }
  });

  it('keeps a token read on one subshell line, never beside another command that could swallow it', async () => {
    const lines = [];
    for (const eco of ecosystems) {
      lines.push(...shellLines(await install(v6, eco, pkgFor[eco] ?? 'pkg')), ...shellLines(await publish(v6, eco, artifactFor(eco), extraFor(eco))));
    }
    const reads = lines.filter((l) => l.includes('read -rs'));
    ok(reads.length >= 5, `found only ${reads.length} reads`);
    for (const line of reads) ok(/^\( read -rs \w+ && .* \)$/.test(line), line);
  });
});

describe('setup tools — publish fences paste cleanly', () => {
  it('holds no <placeholder> in any shell fence, with or without the optional inputs', async () => {
    let checked = 0;
    for (const eco of ecosystems) {
      const texts = [
        await install(base, eco, pkgFor[eco] ?? 'pkg', '1.0.0'),
        await install(base, eco, pkgFor[eco] ?? 'pkg'),
        await publish(base, eco, artifactFor(eco)),
        await publish(base, eco, artifactFor(eco), extraFor(eco)),
        await publish(base, eco, './x.crate', extraFor(eco)),
      ];
      for (const text of texts) {
        for (const line of shellLines(text)) {
          checked++;
          ok(!/[<>]/.test(unquoted(line)), `${eco}: placeholder or redirect in: ${line}`);
          ok(!/<[A-Za-z][^>]*>/.test(line), `${eco}: placeholder in: ${line}`);
        }
      }
    }
    ok(checked > 20, `only ${checked} shell lines were checked`);
  });

  it('emits a complete maven command from the supplied coordinates', async () => {
    deepStrictEqual(shellLines(await publish(base, 'maven', './a.jar', mavenIds)), [
      'mvn deploy:deploy-file -Dfile=\'./a.jar\' -Durl=https://dep.example.com/maven/ -DrepositoryId=dependably -DgroupId=com.acme -DartifactId=widget -Dversion=1.2.3',
    ]);
  });

  it('emits a complete oci command that captures the loaded reference and refuses an empty one', async () => {
    const text = await publish(base, 'oci', './image.tar', ociIds);
    deepStrictEqual(shellLines(text), [
      'docker login dep.example.com',
      `( IMG=$(docker load -i './image.tar' | sed -n 's/^Loaded image\\( ID\\)\\{0,1\\}: //p' | head -n 1) && test -n "$IMG" && docker tag "$IMG" dep.example.com/'team/app':'1.0.0' && docker push dep.example.com/'team/app':'1.0.0' )`,
    ]);
    const fences = [...text.matchAll(/```bash\n([\s\S]*?)\n```/g)].map((m) => m[1]);
    ok(fences[0] === 'docker login dep.example.com', 'the prompting login is alone in its fence');
  });

  it('runs the oci command: tags and pushes for a named or an ID load, and pushes nothing for an empty one', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oci-'));
    try {
      writeFileSync(
        join(dir, 'docker'),
        '#!/bin/sh\ncase "$1" in\nload) printf "%s\\n" "$FAKE_LOAD" ;;\n*) echo "$@" >> "$FAKE_LOG" ;;\nesac\n',
        { mode: 0o755 },
      );
      const body = shellLines(await publish(base, 'oci', './image.tar', ociIds)).find((l) => l.includes('docker load'));
      const run = (load) => {
        const log = join(dir, 'log');
        writeFileSync(log, '');
        spawnSync('bash', ['-c', body], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, FAKE_LOAD: load, FAKE_LOG: log } });
        return readFileSync(log, 'utf8');
      };
      strictEqual(run('Loaded image: app:dev'), "tag app:dev dep.example.com/team/app:1.0.0\npush dep.example.com/team/app:1.0.0\n");
      strictEqual(run('Loaded image ID: sha256:abc'), "tag sha256:abc dep.example.com/team/app:1.0.0\npush dep.example.com/team/app:1.0.0\n");
      strictEqual(run('Loaded image: a:1\nLoaded image: b:2'), "tag a:1 dep.example.com/team/app:1.0.0\npush dep.example.com/team/app:1.0.0\n");
      strictEqual(run('error: nothing'), '');
      strictEqual(run(''), '');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('names the missing inputs in prose, with no command to run, when maven coordinates are absent', async () => {
    const text = await publish(base, 'maven', './a.jar', { groupId: 'com.acme' });
    ok(!text.includes('```'), text);
    ok(text.includes('Missing: artifactId, version'), text);
    ok(text.includes('Call get_publish_command again with artifactId, version'), text);
    ok((await publish(base, 'maven', './a.jar')).includes('Missing: groupId, artifactId, version.'));
  });

  it('keeps the login fence but names the missing inputs for oci', async () => {
    const text = await publish(base, 'oci', './image.tar', { image: 'team/app' });
    deepStrictEqual(shellLines(text), ['docker login dep.example.com']);
    ok(text.includes('Missing: tag.'), text);
    ok(text.includes('Call get_publish_command again with tag'), text);
    ok((await publish(base, 'oci', './image.tar')).includes('Missing: image, tag.'));
  });

  it('treats empty strings as not supplied', async () => {
    const text = await publish(base, 'maven', './a.jar', { ...mavenIds, version: '  ' });
    ok(text.includes('Missing: version.'), text);
  });

  it('rejects malformed coordinates, repositories and tags', async () => {
    const bad = [
      ['maven', { ...mavenIds, groupId: 'com.acme;rm -rf' }],
      ['maven', { ...mavenIds, groupId: 'a'.repeat(129) }],
      ['maven', { ...mavenIds, artifactId: 'a b' }],
      ['maven', { ...mavenIds, artifactId: 'x:y' }],
      ['maven', { ...mavenIds, version: '-1' }],
      ['maven', { ...mavenIds, version: '1$(id)' }],
      ['maven', { ...mavenIds, version: '1'.repeat(257) }],
      ['oci', { ...ociIds, image: 'Team/App' }],
      ['oci', { ...ociIds, image: 'team/../app' }],
      ['oci', { ...ociIds, image: "team/app'; id" }],
      ['oci', { ...ociIds, image: 'a'.repeat(256) }],
      ['oci', { ...ociIds, tag: '.hidden' }],
      ['oci', { ...ociIds, tag: '-x' }],
      ['oci', { ...ociIds, tag: 'a:b' }],
      ['oci', { ...ociIds, tag: 'a'.repeat(129) }],
    ];
    for (const [eco, extra] of bad) {
      const res = await publishRaw(base, eco, './x', extra);
      ok(res.isError, `${eco} ${JSON.stringify(extra)} should be rejected: ${res.content[0].text}`);
    }
    const edge = await publishRaw(base, 'oci', './x', { image: 'a'.repeat(255), tag: 'a'.repeat(128) });
    ok(!edge.isError, edge.content[0].text);
  });

  it('rejects inputs that belong to another ecosystem', async () => {
    for (const [eco, extra] of [
      ['npm', { groupId: 'g' }],
      ['oci', { version: '1.0.0' }],
      ['oci', mavenIds],
      ['maven', { image: 'team/app' }],
      ['maven', { tag: '1' }],
      ['pypi', { tag: '1' }],
    ]) {
      const res = await publishRaw(base, eco, './x', extra);
      ok(res.isError, `${eco} ${JSON.stringify(extra)} should be rejected`);
      ok(res.content[0].text.includes('do not apply'), res.content[0].text);
    }
  });
});
