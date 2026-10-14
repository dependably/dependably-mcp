# Contributing

Building, testing and extending the server. For install, configuration and the tool surface, see
the [README](README.md).

## Getting set up

Node 22 or later is required.

The committed `package-lock.json` and `.npmrc` resolve against our private Dependably instance.
You don't need access to it: every dependency is also on the public registry. Clone, then point
your clone there before installing:

```bash
git clone https://github.com/dependably/dependably-mcp.git
cd dependably-mcp
echo 'registry=https://registry.npmjs.org/' > .npmrc
node scripts/public-lockfile.mjs
npm ci
```

`public-lockfile.mjs` rewrites each `resolved` URL to the public registry; the integrity hashes
still pin the same bytes. The public CI does the same. Don't commit the rewritten files; restore
them with `git checkout -- .npmrc package-lock.json` before you pull or commit.

Day to day:

- `npm run dev` runs `tsc --watch`; `npm run build` compiles once.
- `npm test` builds, runs the unit tests with coverage, then the smoke test and the manifest
  freshness check. `npm run test:unit` runs just the unit tests and writes `coverage/lcov.info`.
- `npm run sbom` writes a local CycloneDX SBOM (cyclonedx-npm) to `cyclonedx-sbom.json`.

CI also generates an SBOM with sbom-reach and uploads each to Dependency-Track as its own
project, so the generators can be compared.

## Source layout

```
src/
├── index.ts           # entry: load config, start stdio
├── config.ts          # env parsing (PAT-only)
├── client.ts          # fetch wrapper (bearer auth, timeout, RFC 7807 errors)
├── server.ts          # registers the 5 tool modules
├── format.ts          # tool-result helpers (json/withSummary/err/run)
├── ecosystems.ts      # ecosystem vocabularies, read from the instance with a built-in fallback
├── semver.ts          # version ordering, for comparing against a fix
├── vuln.ts            # dependency checks, live coverage, alias folding, remediation
└── tools/
    ├── read.ts           # packages, vulnerabilities, policies, lookup
    ├── vuln.ts           # check_dependencies, get_remediation, remediation skills
    ├── projects.ts       # list_projects, get_project, get_project_version
    ├── observability.ts  # readiness_check
    └── setup.ts          # get_install_command, get_publish_command

test/                  # node:test unit tests, run against dist/ with source maps
├── client.test.mjs    # URL building and error messages
├── config.test.mjs    # environment validation
├── ecosystems.test.mjs  # the instance vocabulary, fallback and retry
├── semver.test.mjs    # version ordering
├── server.test.mjs    # stdio startup in a child process, and every tool's annotations
├── tools.test.mjs     # every tool handler, through an in-memory MCP client and stubbed fetch
└── vuln.test.mjs      # report paging, matching, findings, lockfile parsing
```

The tools are listed in the README's [Tools](README.md#tools) table.

## Adding a tool

Register it with `server.registerTool(name, config, handler)` in the matching module under
`src/tools/`, give it a `title` and read-only `annotations`, and wrap the handler body in
`run()` from `format.ts` so HTTP errors become readable text. Use only endpoints a personal
access token can reach.

Then run `npm run manifest:sync`. The tool list in `manifest.json`, the Claude Desktop extension
manifest, is generated from the server, and `npm test` fails when it is stale. `scripts/smoke.mjs`
pins each tool's required arguments, so update it when those change.

## Coverage

`npm run test:unit` uses Node's built-in test runner and V8 coverage, with no c8 and no nyc. It
fails below 90% lines and 85% branches.

Keep `--enable-source-maps`: without it coverage is reported against `dist/*.js`, which
SonarQube excludes, and the project reads as 0% covered.

## Building the Claude Desktop bundle

```bash
npm ci
npm run bundle:verify    # builds dist-mcpb/dependably-<version>.mcpb and .sha256,
                         # then boots the server from the unpacked bundle
```

The bundle is unsigned.
