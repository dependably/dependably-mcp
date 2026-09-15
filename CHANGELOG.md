# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
