# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A Python prerelease sorted above its own release, so `bumpTo` went silent.** Python spells a
  prerelease without semver's hyphen (`2.0.0rc1`, `1.0a1`, `1.0.dev1`), and the parser split only
  on `-` — leaving the marker glued to the last release segment, where `"0rc1"` compared lexically
  *above* `"0"`. `bumpTarget` returns null once `gte(installed, ceiling)` holds, so a project
  pinned to `2.0.0rc1` with a fix at `2.0.0` was told nothing needed bumping. Pre, post and dev
  tails are now parsed and ordered `dev < pre < release < post`. Epochs (`1!1.0`) and local
  version labels remain unmodelled, and the module says so.

- **Tool schemas advertised `additionalProperties: false` and did not enforce it.** The SDK builds
  a non-strict object from a raw shape, so an unknown property was silently dropped and the call
  proceeded. A typo'd `version` on `lookup_package` meant the package was evaluated *unpinned* —
  a different question — and the verdict came back attributed to a version that was never sent.
  Every tool now registers `z.object({…}).strict()`, and the smoke test asserts, for every
  registered tool, that an unknown property is rejected rather than ignored.

- **The ecosystem enum was wrong in both directions.** One shared list of eight values backed every
  tool, but the planes differ. It offered `rpm` and `oci` to `lookup_package`, which the server
  rejects with `422 Must be one of: npm, pypi, nuget, maven, golang, cargo, hex`; and it withheld
  `apk`, `terraform` and `hex` from the registry tools, which serve them — 104 packages on the
  dogfood instance that no tool could reach (`hex` 45, `apk` 54, `terraform` 5). The sets are now
  per-plane in `src/ecosystems.ts`, and the smoke test pins each one as it reaches the client.

- **Error messages named a capability that does not exist.** `extractCapability` read only the
  token *after* the word "capability", but Dependably's dominant phrasing puts the name before it
  (`"read:tenant capability required."` — `AuthController`, `SiemController`, `CargoController`,
  `HexController` and friends). Every one of those rendered as `Your token lacks the "required"
  capability`, sending the reader after a grant that does not exist. Both positions are now read,
  and the capture must match the `verb:leaf` shape of a real capability, so prose can never be
  reported as one. The test that covered this used `requires capability "read:packages"`, a
  phrasing the server never emits; the real wordings are pinned now.
- **A 401 blamed the token's expiry when the cause could equally be a missing capability.**
  Dependably sends one body for "no token" and for "valid token, missing capability", so the
  message now names the capability and states both causes instead of picking one.
- **A 5xx told the reader to check `DEPENDABLY_BASE_URL`.** The instance answered, so the URL
  demonstrably resolves — `/lookup` in particular returns 503 when an *upstream* registry is
  unreachable, a fault beyond the instance. The hint now says so. A detail ending in a full stop
  no longer renders a doubled period.

- **`check_dependencies` reported a vulnerable package as `clean`.** Report rows were joined onto
  the caller's dependency list by exact `name@version`, but the report stores canonical lower-case
  names while a lockfile carries whatever the author wrote. Against a live instance,
  `starlette@0.47.2` returned 12 advisories and `Starlette@0.47.2` returned `clean: true` — and a
  NuGet `packages.lock.json` spells it `Newtonsoft.Json`, which is exactly the input the tool
  description tells the caller to paste. Both sides of the join now fold through `foldName`:
  lower-case everywhere, plus PEP 503 separator folding on pypi, where `typing_extensions` and
  `typing-extensions` are the same distribution. Versions stay exact.
- **`get_remediation` reported a severity its sibling tools did not use.** The advisory detail
  endpoint serves GHSA's raw `database_specific` vocabulary (`MODERATE`) while the report endpoint
  serves the normalized one (`MEDIUM`), so one advisory had two spellings depending on which tool
  you asked. `summarizeRemediation` now normalizes, and an advisory carrying no severity stays
  `undefined` rather than becoming `UNKNOWN`.

### Removed

- **`get_version` and `get_prometheus_metrics`, and the `DEPENDABLY_TOOLSET` switch with them.**
  Both tools wrapped endpoints Dependably allowlists to its own host, so they returned `403` for
  every client not running on the server. `DEPENDABLY_TOOLSET=remote` existed only to hide them,
  which made the default (`full`) wrong for almost every install. Read `/version` and `/metrics`
  on the host, or scrape `/metrics` with Prometheus.
- **`yank_version`.** The last write in the surface, and the only destructive tool. It needed
  `yank:*` or a per-ecosystem leaf, which sits in the publisher set and so cannot be minted by an
  ordinary member, and it had no token preset. Yank a version from the Dependably web UI instead.
- **`whoami`.** It was the only tool needing `read:tenant`, which drags the Admin preset into
  an install that otherwise runs on Pull. It answered with opaque ids rather than names — `orgId`
  is a hex string, not the org slug — and the two identity facts worth having are already on the
  Pull surface: `list_packages` returns `orgId` per item, and `list_vulnerabilities` at
  `verbosity: "full"` returns `orgSlug`. What was left unique to it (`role`, MFA flags, locale)
  gates nothing in a read-only surface.
- **`import_manifest`, `admin_upload` and `DEPENDABLY_IMPORT_ROOT`.** The two import tools were
  the only ones that read the local filesystem, and they needed an admin-grade token carrying
  `import:*` and `tenant:configure`, which an ordinary member cannot mint. `DEPENDABLY_IMPORT_ROOT`
  existed to contain those reads; with the tools gone the containment has nothing left to guard.
  No tool in this server now touches the filesystem or runs a command.

The surface is a flat **18 tools in 4 groups**, registered unconditionally and **entirely
read-only**: no tool writes to the instance, deletes anything, reads a local file, or runs a
command. The two environment variables that gated tool registration are no longer read, and
`manifest.json` drops the matching `user_config` fields.

### Added

- **Unit tests and coverage reporting.** 129 tests across `test/`, covering the pure logic
  (version ordering, report scoping, lockfile parsing, remediation extraction), the HTTP
  client's URL building and its whole error-message surface, config validation, and every
  tool's handler through an in-memory MCP client with a stubbed `fetch`. 97.78% lines /
  94.19% branches / 99.10% functions; `npm run test:unit` fails below 90/85.
- Coverage is wired into SonarQube. The project previously reported **0%** — not because
  nothing was tested, but because nothing produced an lcov file and
  `sonar.javascript.lcov.reportPaths` was never set. Node's V8 coverage also names
  `dist/*.js`, which `sonar.sources=src` excludes, so the fix is `--enable-source-maps`,
  which remaps each `SF:` line onto the `src/*.ts` file Sonar actually analyses. Verified on
  `node:22`, the CI image. No new dependencies: this is Node's built-in test runner and
  coverage, not c8 or nyc.
- CI: the `test` job publishes `coverage/lcov.info` and `sonarqube-check` now `needs` it,
  failing fast with a named reason if the artefact is missing rather than silently scanning
  with no coverage and failing the quality gate for the wrong reason.

### Changed

- `manifest.json` declares `compatibility.runtimes.node` as `>=22.0.0`, matching
  `engines.node` in `package.json` and the `node:22` image CI builds and tests on. It
  previously advertised `>=18.0.0`, which promised Claude Desktop a runtime floor the
  package itself does not support.

- **Cleared the SonarQube quality gate's 1 security hotspot and 12 code smells**, read from the
  API rather than guessed at.
  - `typescript:S5852` (hotspot, `src/config.ts`): the base-URL normalizer trimmed trailing
    slashes with `/\/+$/`, which backtracks super-linearly on a long run of slashes. Replaced
    with a loop. The input comes from the environment rather than a request, so this was not
    exploitable, but the pattern is worth not having.
  - `typescript:S3776` (cognitive complexity, 8 sites): `loadConfig`, `describeFetchError`,
    `formatHttpError`, `installCommand`'s handler, both vuln tool handlers, `buildFindings` and
    `summarize` are each split into named helpers. `formatHttpError` was the worst at 27; its
    per-status branches are now one function each, and the transport-failure hints in
    `describeFetchError` are a code lookup rather than an if/else chain.
  - `typescript:S4624` (nested template literals, 3 sites in `src/client.ts`): the conditional
    fragments are computed into named variables first.
  - `typescript:S3358` (nested ternaries, `src/semver.ts`): two sites introduced by this
    branch's own `compare` rewrite, caught by scanning before merge rather than after.
  - Behaviour is unchanged throughout — the 129 tests added alongside were written against the
    previous shapes and all still pass, and the 16 generated install commands were diffed
    byte-for-byte across all eight ecosystems, pinned and unpinned.
  - Verified by running the scanner against a throwaway project key (Community Edition has no
    branch analysis, so scanning under the real key would have overwritten `main`'s results):
    0 issues, 0 hotspots, 97.0% coverage, quality gate **OK**. The throwaway project was
    deleted afterwards.

### Fixed

- `compare` in `src/semver.ts` returned 0 for any two versions with non-numeric release
  segments (`1.a.0` vs `1.b.0`), because both coerced to `NaN` and then stringified to the
  same `"NaN"`. The doc comment claimed lexical ordering, which was never true. Segments are
  now kept as strings and compared numerically only when both sides are numeric. Inert for
  real lockfile and advisory versions, which are numeric — found by the new tests.

### Added

- **`check_dependencies` — scope the vulnerability report to one project.** The Dependably
  API reports per *org*, so answering "what is wrong with this project?" previously meant
  fetching every page and joining against a lockfile by hand. This tool does the join and
  returns one finding per affected package, each annotated with `bumpTo`: the highest fixed
  version across that package's advisories, because several are explicit incomplete-fix
  follow-ups where the lowest fix does not clear the rest. `clean: true` when nothing
  matched, so the same call answers "did my fix land?". Measured on this repo's own tree:
  one call, ~150 ms, replacing roughly 30 calls of manual cross-referencing.
  - The dependency list is passed as `packages`; the tool reads no files. An earlier draft
    accepted a lockfile path behind a `DEPENDABLY_PROJECT_ROOT` opt-in and it was removed
    before merge: every host that could set such a root is one where the agent can already
    read the file, and reporting a parse failure usefully means surfacing the JSON error,
    which V8 fills with the offending bytes — turning any path under the root into a
    read oracle. The file-read rule stays one sentence: only the two import tools read
    local files. `parseNpmLockfile` remains exported and tested for callers assembling the
    argument.
  - Taking the dev marker from the lockfile rather than by eye also fixes a real
    misclassification: `fast-uri` reads as dev-only from `npm ls`, which shows one path per
    package, but is in the production tree via `@modelcontextprotocol/sdk` → `ajv`.
- **`get_remediation` — fixed versions in bulk.** Up to 200 advisories per call, returning
  the fixed version plus CWE / OWASP / remediation-skill ids and nothing else. The
  per-advisory endpoint returns the full write-up — PoC code, reproduction tables — which is
  the right thing when you want the analysis and enormously wasteful when you want a version
  string. Installed versions are passed through, so the answer stays release-line aware:
  `@hono/node-server` 1.19.14 resolves to 1.19.15, not the 2.x fix.

### Changed

- **`list_vulnerabilities` items are compact by default**, dropping the fields that are
  redundant (`purl` alongside `packageName`/`version`/`ecosystem`) or rarely actionable
  (`orgSlug`, `revokedAt`, `firstSeenAt`, `vulnCheckedAt`). Measured 54% smaller on a
  50-item page. Pass `verbosity: "full"` for the raw server response.
- **`list_vulnerabilities` now says it is org-wide** and points at `check_dependencies` for
  project-scoped questions. The old description read as though it reported on your project.

### Docs

- `docs/api-asks.md`: the server-side changes that would let the MCP delete this client-side
  work — `fixedVersion`, a dev marker and reachability on each report item, and a `purls`
  filter. Each ask is written against measured cost from a real session.

### Security

- **Cleared all 26 known advisories in the dependency tree** (9 packages), verified against the
  Dependably registry's vulnerability report. Every one was transitive; neither direct dependency
  was itself affected.
  - `@modelcontextprotocol/sdk` 1.29.0 -> 1.30.0, whose refreshed ranges carry `hono` 4.12.27 ->
    4.13.7, `@hono/node-server` 1.19.14 -> 2.1.1, `qs` 6.15.3 -> 6.16.0, `ip-address` 10.2.0 ->
    10.7.0 and `fast-uri` (via `ajv`) 3.1.3 -> 3.1.7 — 19 advisories, including six HIGH
    host-confusion/SSRF issues in `fast-uri` and `ip-address`'s octal-octet SSRF bypass
    (`GHSA-mwp4-54f8-5fhr`, CVSS 7.7).
  - Dev tooling: `js-yaml` 4.3.0 -> 4.3.2, `brace-expansion` 2.1.2 -> 2.1.4, `tar` 7.5.20 ->
    7.5.22 — 5 advisories, all DoS.
  - `tmp` 0.0.33 -> 0.2.7 via a pinned `overrides` entry, since `external-editor` pins
    `tmp@^0.0.33` and cannot reach the 0.2.6 fix for `GHSA-ph9p-34f9-6g65`. That call site uses
    only `tmpNameSync({ postfix })`, unchanged in 0.2.x, so the forced bump is compatible. Drop
    the override once `@anthropic-ai/mcpb` ships a newer `@inquirer/prompts`.
  - None were reachable at runtime: the server instantiates only `StdioServerTransport`, so the
    SDK's HTTP path (Express/Hono, `qs` body parsing, `express-rate-limit`'s `ip-address`) is
    never loaded. They shipped on disk in the `.mcpb` bundle regardless, which is why they are
    fixed rather than waived.

### Fixed

- CI: `publish:github` pulled bare `alpine/git:latest`, which is not a Docker Hub official
  image and so is not reliably warm in the org's OCI pull-through cache; a cold pull fails on
  this network (Docker Hub's CDN does not resolve). It now pulls
  `${DEP_IMAGE_REGISTRY}/alpine/git:latest` with its entrypoint cleared, matching
  dependably-documentation's job of the same name.

### Added

- **Claude Desktop extension bundle.** `manifest.json` (MCPB manifest 0.3) at the repo root maps
  the extension's config dialog — instance URL, keychain-stored token, timeout, optional import
  folder — onto the existing `DEPENDABLY_*` environment variables, so the bundle is `dist/` plus
  production dependencies with no new code path. `npm run bundle` builds
  `dist-mcpb/dependably-<version>.mcpb` with a SHA-256 beside it; `npm run bundle:verify` also
  boots the server from the unpacked bundle. `npm run manifest:sync` regenerates the manifest's
  tool list from the running server, and `npm test` now fails when the manifest is stale.
- `docs/distribution-plan.md`: the plan for the extension, the Anthropic directory listing, and
  the other MCP harnesses.
- **`DEPENDABLY_TOOLSET`** (`full` | `remote`, default `full`). `remote` leaves out `get_version`
  and `get_prometheus_metrics`, whose endpoints Dependably allowlists to loopback, so any client
  not running on the Dependably host would only ever see a `403` from them. The extension
  manifest sets `remote`, and `npm run manifest:sync` boots the server with the toolset the
  manifest declares, so the listed tools are exactly what a Desktop install exposes (16).
- Extension config dialog: an optional **private CA bundle** file, mapped onto Node's standard
  `NODE_EXTRA_CA_CERTS`, for instances behind an internal certificate authority. There is no
  option to disable certificate verification.
- CI: the GitLab `build` job and a new GitHub `release-bundle` job build and verify the `.mcpb`
  on every tagged release and attach it, with its `.sha256`, to the GitLab and GitHub releases.
- CI: the `sbom` job now runs our own sbom-reach in generate mode. It builds the CycloneDX SBOM
  from the lockfile with the dev/runtime marker explicit on every component, embeds OSV.dev
  advisories, and writes a reachability SARIF. Until sbom-reach has a published release the job
  installs the tarball its own `pack-verify` job packs on every `main` push.
- CI: `sbom-publish-dependably` uploads the SBOM (`PUT /api/v1/sbom`) and then the reachability
  SARIF (`PUT /api/v1/sarif`) to the Dependably instance's own Projects on `main`, alongside the
  existing Dependency-Track upload. It authenticates with `DEPENDABLY_SBOM_TOKEN`, a token minted
  with the `sbom:upload` capability.
- CI: `sonarqube-check` (advisory SonarQube scan on `main`, `sonar-project.properties`) and a
  manual `publish:github` job that mirrors `main` or a release tag to
  `github.com/dependably/dependably-mcp`, whose workflow publishes to public npm.
- `docs/listing.md` (directory listing pack and pre-submission checklist) and
  `docs/desktop-e2e.md` (manual Claude Desktop install runbook, macOS and Windows).

### Changed

- `npm run sbom` now runs `scripts/sbom.mjs`, which wraps cyclonedx-npm and writes an explicit
  `cdx:npm:package:development=false` on every component the generator left unmarked. Consumers
  that read the marker as a tri-state (Dependably maps an absent marker to an `unknown` dependency
  scope) now see production dependencies as runtime instead of unknown.
- Transport failures now say what to check instead of Node's bare `fetch failed`: an unresolvable
  host, a refused connection, a TLS chain the runtime does not trust (with the
  `NODE_EXTRA_CA_CERTS` remedy), or a dropped connection, each with the underlying error code.
  The smoke test asserts this against a refused loopback port.
- Optional settings that arrive as an unexpanded `${…}` placeholder from a host that skipped
  substitution are treated as unset rather than as a URL or directory.
- Extension manifest: the support link points at <https://dependably.ca/contact>.

## [0.2.0] - 2026-07-16

The developer read surface.

### Added

- **read** group — 9 read-only tools authenticated with the same PAT:
  `list_packages`, `get_package`, `search_packages`, `list_vulnerabilities`,
  `get_vulnerability`, `lookup_package` (pre-adoption check of a package not yet
  in the registry), `get_license_policy` (enforcement mode + SPDX allow/blocklist),
  `list_activity`, and `whoami`.

### Notes

- Requires a Dependably server **≥ v0.3.0** (PAT auth on read endpoints);
  `get_license_policy` and `lookup_package` need the release after v0.3.1.
  Against an older server the read tools return `401`.
- Capabilities: `read:packages` drives the package/vulnerability/license tools,
  `read:audit` drives `list_activity`, `read:tenant` drives `whoami` — or mint
  `read:*` for all of them. Service/CI tokens work on the read surface too.

## [0.1.0] - 2026-07-15

First public release — the PAT-only v1 surface.

### Added

- 11 tools across 5 groups, authenticated with a Dependably Personal Access Token:
  - **yank** — `yank_version`
  - **siem** — `siem_list_auth_events`, `siem_vulnerabilities_summary`
  - **import** (opt-in via `DEPENDABLY_IMPORT_ROOT`) — `import_manifest`, `admin_upload`
  - **observability** — `health_check`, `readiness_check`, `get_version`, `get_prometheus_metrics`
  - **setup** (local, no server call) — `get_install_command`, `get_publish_command`
- Import-root sandboxing: the two import tools are only registered when
  `DEPENDABLY_IMPORT_ROOT` is set and refuse to read any path (symlinks included)
  that resolves outside it.
- RFC 7807-aware error formatting with actionable 401/403/429/5xx messages.
- In-memory smoke test asserting the tool surface and import-root containment.

### Notes

- The read/browse surface (package inventory, vulnerability list, audit logs, org
  settings, whoami, search) is deferred to v2, pending server-side PAT support on
  read endpoints (dependably-community#343).
