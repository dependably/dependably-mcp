// Builds the Claude Desktop extension bundle (dependably-<version>.mcpb).
//
// The bundle is assembled in build/mcpb/ rather than in the working tree so
// the dev dependencies here are never pruned: only dist/, the lockfile-pinned
// production node_modules, manifest.json, the icons and the licence go in.
//
//   node scripts/bundle.mjs            build dist-mcpb/dependably-<version>.mcpb + .sha256
//   node scripts/bundle.mjs --verify   also unpack the bundle and boot the server from it
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const stage = join(root, 'build', 'mcpb');
const out = join(root, 'dist-mcpb');
const verify = process.argv.includes('--verify');

function run(cmd, args, cwd = root, extraEnv = {}) {
  const res = spawnSync(cmd, args, { cwd, stdio: 'inherit', env: { ...process.env, ...extraEnv } });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed with exit code ${res.status}`);
  }
}

// The CLI is a pinned devDependency staged by the lockfile; never fetch it
// from the network at build time. A `npx --yes` fallback would download and
// execute a package outside the lockfile's integrity pin on every cold build,
// which is exactly the supply-chain exposure this project audits others for.
function mcpb(args) {
  const local = join(root, 'node_modules', '.bin', 'mcpb');
  if (!existsSync(local)) {
    throw new Error(`${local} not found; run npm ci first`);
  }
  return run(local, args);
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
if (manifest.version !== pkg.version) {
  throw new Error(
    `manifest.json version ${manifest.version} != package.json version ${pkg.version}; run npm run manifest:sync`,
  );
}
if (!existsSync(join(root, 'dist', 'index.js'))) {
  throw new Error('dist/index.js missing; run npm run build first');
}

// 1. Stage exactly what ships.
rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
for (const entry of ['dist', 'assets', 'manifest.json', 'package.json', 'package-lock.json', 'LICENSE', 'README.md']) {
  cpSync(join(root, entry), join(stage, entry), { recursive: true });
}

// 2. Production dependencies only. The installed node_modules is copied and
//    pruned against the lockfile rather than reinstalled, so the bundle needs
//    no network and matches what `npm ci` produced at the repo root. No
//    lifecycle scripts (husky's `prepare` would otherwise run in the stage).
cpSync(join(root, 'node_modules'), join(stage, 'node_modules'), { recursive: true });
run('npm', ['prune', '--omit=dev', '--ignore-scripts', '--no-fund', '--no-audit'], stage);

// 3. Validate and pack.
const bundleName = `${manifest.name}-${manifest.version}.mcpb`;
mkdirSync(out, { recursive: true });
const bundlePath = join(out, bundleName);
rmSync(bundlePath, { force: true });
mcpb(['validate', join(stage, 'manifest.json')]);
mcpb(['pack', stage, bundlePath]);

// 4. Checksum beside the bundle (the bundle ships unsigned; the distribution plan covers why).
const sha256 = createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
writeFileSync(`${bundlePath}.sha256`, `${sha256}  ${bundleName}\n`);
console.log(`bundle: ${bundlePath}\nsha256: ${sha256}`);

// 5. Optional: unpack and boot the server from the bundle to prove it is self-contained.
if (verify) {
  const unpacked = join(root, 'build', 'mcpb-verify');
  rmSync(unpacked, { recursive: true, force: true });
  // A .mcpb is a zip; the CLI has no unpack command. bsdtar (macOS, Windows)
  // and unzip (Linux, macOS) both read it.
  mkdirSync(unpacked, { recursive: true });
  const unzip = spawnSync('unzip', ['-q', bundlePath, '-d', unpacked], { stdio: 'inherit' });
  if (unzip.status !== 0) run('tar', ['-xf', bundlePath, '-C', unpacked]);
  // Launch the server the way Claude Desktop would: the manifest's mcp_config,
  // with the required user_config fields filled in and every optional one left
  // blank (Desktop substitutes an empty string for a field the user skipped).
  const sample = { base_url: 'https://dependably.example.com', token: 'verify' };
  const substitute = (value) =>
    String(value)
      .replaceAll('${__dirname}', unpacked)
      .replace(/\$\{user_config\.([a-z_]+)\}/g, (_, key) => sample[key] ?? '');
  const mcp = manifest.server.mcp_config;
  const command = substitute(mcp.command) === 'node' ? process.execPath : substitute(mcp.command);
  const args = (mcp.args ?? []).map(substitute);
  const env = Object.fromEntries(Object.entries(mcp.env ?? {}).map(([k, v]) => [k, substitute(v)]));
  const expected = manifest.tools.map((t) => t.name).sort();
  const probe = `
    import { Client } from '@modelcontextprotocol/sdk/client/index.js';
    import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
    const transport = new StdioClientTransport({
      command: ${JSON.stringify(command)},
      args: ${JSON.stringify(args)},
      env: { ...process.env, ...${JSON.stringify(env)} },
    });
    const client = new Client({ name: 'bundle-verify', version: '0.0.0' });
    await client.connect(transport);
    const { tools } = await client.listTools();
    await client.close();
    const got = tools.map((t) => t.name).sort();
    const expected = ${JSON.stringify(expected)};
    if (JSON.stringify(got) !== JSON.stringify(expected)) {
      throw new Error('bundle exposes ' + JSON.stringify(got) + ' but manifest.json lists ' + JSON.stringify(expected));
    }
    for (const t of tools) {
      if (!t.title || !t.annotations || typeof t.annotations.readOnlyHint !== 'boolean' || typeof t.annotations.destructiveHint !== 'boolean') {
        throw new Error('tool ' + t.name + ' is missing title or readOnlyHint/destructiveHint annotations (directory review requires them)');
      }
    }
    console.log('bundle verify OK: launched from the unpacked bundle via the manifest mcp_config; exposes exactly the ' + got.length + ' listed tools, all titled and annotated');
  `;
  run(process.execPath, ['--input-type=module', '-e', probe], root);
}
