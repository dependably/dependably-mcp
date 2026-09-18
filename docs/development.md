# Development

Building, testing and extending the server. For install and configuration see the
[README](../README.md); for the tool surface see [tools.md](tools.md).

## Getting set up

Node 22 or later is required.

```bash
git clone https://github.com/dependably/dependably-mcp.git
cd dependably-mcp
npm install
npm run dev   # tsc --watch
npm run build # tsc once
npm test      # build, unit tests with coverage, smoke test, manifest freshness check
npm run test:unit  # just the unit tests; writes coverage/lcov.info
npm run sbom  # local CycloneDX SBOM (cyclonedx-npm) into cyclonedx-sbom.json
```

CI runs `npm run sbom` alongside sbom-reach's generate mode and uploads both to
Dependency-Track as separate projects, so the two generators can be compared. See
`.gitlab-ci.yml`.

## A note on the lockfile

We dogfood a private Dependably instance as our npm registry, so the committed
`package-lock.json` and `.npmrc` resolve against it, at Dependably's own pull-through tarball
path rather than the npm registry protocol's shape. You do not need access to build. Every
dependency is also on the public registry, so point npm back at it for your clone and install
from there:

```bash
echo 'registry=https://registry.npmjs.org/' > .npmrc
node scripts/public-lockfile.mjs
npm ci
```

That is what our public CI does. `public-lockfile.mjs` rewrites `resolved` to the public
registry's URL shape; the lockfile's integrity hashes still pin the same bytes.

## Source layout

```
src/
├── index.ts           # entry: load config, start stdio
├── config.ts          # env parsing (PAT-only)
├── client.ts          # fetch wrapper (bearer auth, timeout, RFC 7807 errors)
├── server.ts          # registers the 5 tool modules
├── format.ts          # tool-result helpers (json/withSummary/err/run)
└── tools/
    ├── read.ts         # list/get/search packages, vulns, licence policy, lookup
    ├── vuln.ts         # check_dependencies, get_remediation
    ├── observability.ts# health_check, readiness_check
    └── setup.ts        # get_install_command, get_publish_command

test/                  # node:test unit tests, run against dist/ with source maps
├── semver.test.mjs    # version ordering (what bumpTo depends on)
├── vuln.test.mjs      # report paging, scoping, findings, lockfile parsing
├── client.test.mjs    # url building and the full error-message surface
├── config.test.mjs    # env validation
└── tools.test.mjs     # every tool handler, via an in-memory MCP client + stubbed fetch
```

Five modules register tools, grouped into the four groups shown in [tools.md](tools.md):
`vuln.ts` holds four tools that belong to the read group.

## Adding a tool

Import `server` and `client`, then call `server.registerTool(name, config, handler)`. Wrap the
handler body in the `run()` helper from `format.ts` so HTTP errors become readable text. Keep
the surface reachable by a personal access token: do not add JWT-only or `scope=system`
endpoints.

Run `npm run manifest:sync` after adding or changing a tool. `manifest.json` at the repo root
is the Claude Desktop extension manifest and its tool list is generated from the server;
`npm test` fails when it is stale.

## Coverage

`npm run test:unit` uses Node's built-in test runner and V8 coverage, with no c8 and no nyc. It
fails below 90% lines and 85% branches.

`--enable-source-maps` is load-bearing. Without it V8 reports coverage against `dist/*.js`,
which `sonar.sources=src` excludes, and SonarQube reads the project as 0% covered. CI publishes
`coverage/lcov.info` from the `test` job and `sonarqube-check` consumes it via `needs:`.

## Building the Claude Desktop bundle

```bash
npm ci
npm run bundle:verify    # builds dist-mcpb/dependably-<version>.mcpb and .sha256,
                         # then boots the server from the unpacked bundle
```

The bundle is unsigned. `docs/distribution-plan.md` covers why, and the plan to list it
in Anthropic's directory. The listing pack and pre-submission checklist are in
[listing.md](listing.md); the manual install runbook is [desktop-e2e.md](desktop-e2e.md).
