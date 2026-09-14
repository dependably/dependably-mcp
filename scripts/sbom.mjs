// Generates cyclonedx-sbom.json (CycloneDX 1.6) with cyclonedx-npm, then makes
// the dev/prod declaration explicit on every component.
//
// Named distinctly from sbom.json (sbom-reach's own generate-mode output, see
// .gitlab-ci.yml's `sbom` job) — CI runs both generators in that one job, and
// this one is uploaded to Dependency-Track as a SEPARATE project
// (dependably-mcp-cyclonedx-npm, see `sbom-publish-cyclonedx-npm`) purely so
// the two generators' output can be compared side by side in the same
// Dependency-Track instance: this file carries no vulnerabilities[] at all
// and lets Dependency-Track run its own NVD/OSS-Index scan against a bare
// component list, independent of whatever sbom-reach's OSV-sourced SBOM
// already asserts.
//
// cyclonedx-npm writes the CycloneDX taxonomy property
// `cdx:npm:package:development=true` on dev dependencies and simply omits it
// on production ones. Consumers that read the property as a tri-state (true /
// false / not stated) — Dependably does, mapping "not stated" to an `unknown`
// dependency scope — therefore see every production dependency as unknown.
// Writing `false` where the generator stayed silent turns that into the
// `runtime` (prod) label without changing anything the generator did assert.
//
//   node scripts/sbom.mjs            → cyclonedx-sbom.json in the repo root
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'cyclonedx-sbom.json');
const DEV_PROPERTY = 'cdx:npm:package:development';

const gen = spawnSync(
  join(root, 'node_modules', '.bin', 'cyclonedx-npm'),
  ['--output-format', 'json', '--output-file', out],
  { cwd: root, stdio: 'inherit' },
);
if (gen.status !== 0) {
  throw new Error(`cyclonedx-npm failed with exit code ${gen.status}`);
}

const bom = JSON.parse(readFileSync(out, 'utf8'));
let dev = 0;
let prod = 0;

// Components may nest (components[].components[]) unless flattened; walk them all.
// metadata.component is the project itself, not a dependency, so it is left alone.
function mark(components) {
  for (const c of components ?? []) {
    const props = (c.properties ??= []);
    const existing = props.find((p) => p.name === DEV_PROPERTY);
    if (existing) {
      if (existing.value === 'true') dev += 1;
      else prod += 1;
    } else {
      props.push({ name: DEV_PROPERTY, value: 'false' });
      prod += 1;
    }
    mark(c.components);
  }
}
mark(bom.components);

writeFileSync(out, JSON.stringify(bom, null, 2) + '\n');
console.log(`cyclonedx-sbom.json: ${dev + prod} components, ${prod} runtime (prod), ${dev} development; dev marker explicit on every component`);
