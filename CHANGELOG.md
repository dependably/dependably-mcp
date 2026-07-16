# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
