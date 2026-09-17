// Rewrites package-lock.json's `resolved` URLs in place so `npm ci` can run
// against the public npm registry in GitHub CI.
//
// We dogfood a private Dependably instance, so the committed lockfile
// resolves tarballs at Dependably's own proxy path:
//   https://dependably.northwardlabs.ca/npm/tarballs/<pkg>/<file>.tgz
// That shape is specific to Dependably's pull-through cache, not the npm
// registry protocol's `<registry>/<pkg>/-/<file>.tgz` convention — so
// `npm ci --replace-registry-host`, which only swaps the host, produces a
// 404 on the public registry. This script does the full rewrite instead.
//
// Only ever run against a throwaway checkout (CI); never commit the result.
import { readFileSync, writeFileSync } from 'node:fs';

const PRIVATE_PREFIX = 'https://dependably.northwardlabs.ca/npm/tarballs/';
const publicRegistry = (process.env.PUBLIC_REGISTRY ?? 'https://registry.npmjs.org/').replace(/\/+$/, '');

const path = 'package-lock.json';
const lockfile = JSON.parse(readFileSync(path, 'utf8'));

let rewritten = 0;
for (const pkg of Object.values(lockfile.packages ?? {})) {
  if (!pkg.resolved?.startsWith(PRIVATE_PREFIX)) continue;
  const rest = pkg.resolved.slice(PRIVATE_PREFIX.length);
  const lastSlash = rest.lastIndexOf('/');
  const pkgPath = rest.slice(0, lastSlash);
  const filename = rest.slice(lastSlash + 1);
  pkg.resolved = `${publicRegistry}/${pkgPath}/-/${filename}`;
  rewritten++;
}

writeFileSync(path, `${JSON.stringify(lockfile, null, 2)}\n`);
console.log(`Rewrote ${rewritten} resolved URL(s) to ${publicRegistry}/`);
