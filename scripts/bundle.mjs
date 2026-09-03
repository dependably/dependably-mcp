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

// The CLI is a pinned devDependency; fall back to a pinned npx fetch when the
// dev tree is not installed (e.g. a release job that only ran `npm ci --omit=dev`).
const MCPB_VERSION = '2.1.2';
function mcpb(args) {
  const local = join(root, 'node_modules', '.bin', 'mcpb');
  if (existsSync(local)) return run(local, args);
  return run('npx', ['--yes', `@anthropic-ai/mcpb@${MCPB_VERSION}`, ...args]);
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

// 4. Checksum beside the bundle (the bundle ships unsigned; see docs/distribution-plan.md).
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
  const probe = `
    import { Client } from '@modelcontextprotocol/sdk/client/index.js';
    import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [${JSON.stringify(join(unpacked, 'dist', 'index.js'))}],
      env: { ...process.env, DEPENDABLY_BASE_URL: 'https://dependably.example.com', DEPENDABLY_TOKEN: 'verify', DEPENDABLY_IMPORT_ROOT: '' },
    });
    const client = new Client({ name: 'bundle-verify', version: '0.0.0' });
    await client.connect(transport);
    const { tools } = await client.listTools();
    await client.close();
    if (tools.length === 0) throw new Error('bundle server exposed no tools');
    console.log('bundle verify OK: server booted from the unpacked bundle with ' + tools.length + ' tools');
  `;
  run(process.execPath, ['--input-type=module', '-e', probe], root);
}
