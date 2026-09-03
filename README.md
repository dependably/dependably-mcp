# dependably-mcp

An MCP (Model Context Protocol) server that lets an LLM client — Claude Desktop, Claude Code, Cursor, anything that speaks MCP — run supply-chain automation and incident triage against a [Dependably](https://github.com/dependably/dependably-community) instance over stdio.

Dependably is a self-hosted private artifact repository for npm, PyPI, NuGet, Maven, RPM, OCI, Go, and Cargo. This MCP server wraps the slice of its management API that a **static API token (PAT)** can reach today.

## PAT-only, read + ops

The server authenticates **only** with a Dependably Personal Access Token (`DEPENDABLY_TOKEN`) sent as a bearer token — 20 tools across 6 groups (18 by default; the 2 import tools are opt-in, see below).

Dependably's management API accepts PATs on endpoints that opt into the `ApiToken` auth scheme. Since Dependably **v0.3.0** that includes the whole read-only management surface, which is what the read group below talks to; yank, admin import, and SIEM opted in earlier, and the health/readiness/version/metrics probes are anonymous / IP-allowlisted. The install/publish command builders run entirely locally and never call the server.

> **Minimum server version:** the read tools need Dependably **≥ v0.3.0**; `get_license_policy` and `lookup_package` need the release after v0.3.1. Against an older server the read tools return `401`.

### The 20 tools

| Tool | Group | Capability the PAT needs |
|---|---|---|
| `list_packages` — paginated package inventory with ecosystem/search filters | read | `read:packages` |
| `get_package` — one package: versions, SPDX licenses, vulnerability links | read | `read:packages` |
| `search_packages` — quick name search across the registry | read | `read:packages` |
| `list_vulnerabilities` — paginated report of affected packages | read | `read:packages` |
| `get_vulnerability` — rich advisory detail incl. remediation guidance | read | `read:packages` |
| `lookup_package` — pre-adoption verdict on a package **not yet** in the registry (upstream metadata + OSV + org policy, ingests nothing) | read | `read:packages` |
| `get_license_policy` — enforcement mode + SPDX allowlist/blocklist ("which licenses are approved") | read | `read:packages` |
| `list_activity` — org activity feed (publishes, yanks, policy changes) | read | `read:audit` |
| `whoami` — identity behind the configured token | read | `read:tenant` |
| `yank_version` — destructive delete of a published version | yank | `yank:{ecosystem}` |
| `siem_list_auth_events` — login/lockout/token/rbac auth events with ISO-8601 since/until + prefix filters | siem | `read:audit` |
| `siem_vulnerabilities_summary` — severity-bucketed vuln counts by ecosystem | siem | `read:audit` |
| `import_manifest` — manifest-driven, all-or-nothing bulk import (lockfile + referenced artefacts) | import† | `import:*` + `tenant:configure` (admin-grade token) |
| `admin_upload` — air-gapped bulk upload of N local artefact files (ecosystem auto-detected) | import† | `import:*` + `tenant:configure` (admin-grade token) |
| `health_check` — liveness (`GET /health`) | observability | none (anonymous) |
| `readiness_check` — readiness + per-subsystem checks (`GET /ready`) | observability | none (anonymous) |
| `get_version` — server build version (`GET /version`) | observability | none (anonymous / IP-allowlisted) |
| `get_prometheus_metrics` — raw `/metrics` text | observability | none (IP-allowlisted server-side) |
| `get_install_command` — build the install shell command (does **not** execute) | setup | none (local, no server call) |
| `get_publish_command` — build the publish shell command (does **not** execute) | setup | none (local, no server call) |

† **The two import tools are opt-in.** They read local files and upload them, so they only appear when `DEPENDABLY_IMPORT_ROOT` is set — and they refuse to read anything that resolves outside that directory (symlinks included). Without it you get the 18-tool surface, which performs no local file reads at all.

`get_install_command` / `get_publish_command` cover all eight ecosystems (npm, pypi, nuget, maven, rpm, oci, golang, cargo). Go is proxy-only: it has an install command but no hosted publish endpoint, so `get_publish_command` returns guidance to push a VCS tag instead.

### What scope should the token have?

Mint the token with only the capabilities for the tools you intend to use. **The server never needs `publish:*`** — publishing and pulling packages are done by your package manager with its own token. Pick from:

| You want to… | Capability to grant | Unlocks |
|---|---|---|
| Browse packages, search, vulnerabilities, licenses *(recommended minimal — read-only)* | `read:packages` | `list_packages`, `get_package`, `search_packages`, `list_vulnerabilities`, `get_vulnerability`, `lookup_package`, `get_license_policy` |
| Activity feed + audit/vuln posture | `read:audit` | `list_activity`, `siem_list_auth_events`, `siem_vulnerabilities_summary` |
| Identity check | `read:tenant` | `whoami` |
| Everything read-only above in one grant | `read:*` *(owner/admin-mintable)* | all read + siem tools |
| Yank a bad published version | `yank:*` (or per-ecosystem `yank:npm`, …) | `yank_version` |
| Bulk / air-gapped import | `import:*` **and** `tenant:configure` *(admin-grade)* | `import_manifest`, `admin_upload` |
| Health / readiness / version / metrics, and the local command builders | *nothing* — anonymous / IP-allowlisted / local | the 6 observability + setup tools |

A **read-only token** (`read:packages`, or `read:*` for full coverage) is the safe default: it drives the developer read surface while carrying no write power — a `yank`/`import` attempt returns a clean `403`, and a tool whose capability the token lacks returns a `403` naming the missing capability. Add `yank:*` or `import:*`+`tenant:configure` only if you need those actions. Since Dependably v0.3.0 **service/CI tokens work too** on read endpoints, provided they carry explicit capabilities.

### Known limits

- **On Dependably servers older than v0.3.0**: the read tools return `401`, service / machine (M2M) tokens `404` on capability-gated endpoints, and in **MFA-required orgs** a token principal may get **`403 mfa_enrollment_required`**. All three are fixed server-side in v0.3.0 — upgrade the instance.
- Admin **import** (`import_manifest`, `admin_upload`) requires an **admin-grade token** carrying `import:*` and `tenant:configure`; a plain read PAT will be rejected. The tools are also **absent unless `DEPENDABLY_IMPORT_ROOT` is set** (see [Configure](#configure)).

## Roadmap

The core read surface shipped in **0.2.0**. Endpoints that are PAT-reachable server-side but not yet exposed as tools here:

- org stats (`get_org_stats`), full audit log (`list_audit_log`)
- org posture (`get_org_settings`, `get_proxy_settings`, `get_retention`), quarantine list
- the client-config `get_setup_snippet` fetch
- license risk drill-down (`GET /api/v1/risk/license`)

## Install

The package is published to npm as [`dependably-mcp`](https://www.npmjs.com/package/dependably-mcp):

```bash
npm install -g dependably-mcp
```

Or skip the install entirely — the MCP client configs below run it with `npx`, which fetches it on first use.

## Configure

The server is configured entirely through environment variables, supplied by your MCP client.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DEPENDABLY_BASE_URL` | yes | — | Base URL of your Dependably instance (e.g. `https://dependably.example.com`). Tenancy is resolved from the host — no org slug needed. |
| `DEPENDABLY_TOKEN` | yes | — | A Dependably **Personal Access Token (PAT)**. Mint one from the web UI under *Tokens*. Sent as a bearer token. Use a **user-owned** PAT (service/M2M tokens currently `404` on gated endpoints). |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request HTTP timeout. |
| `DEPENDABLY_IMPORT_ROOT` | no | *(unset)* | Opt-in for the two import tools. Set it to the directory holding your artefact files; `import_manifest` / `admin_upload` are only registered when it is set, and refuse to read files outside it. |

The PAT's **capabilities** determine which tools succeed — see the capability column in [the 20 tools](#the-20-tools).

### Claude Code

```bash
claude mcp add dependably \
  --env DEPENDABLY_BASE_URL=https://dependably.example.com \
  --env DEPENDABLY_TOKEN=dpb_xxx \
  -- npx -y dependably-mcp
```

Or edit `~/.claude.json` (or your project `.mcp.json`) directly:

```jsonc
{
  "mcpServers": {
    "dependably": {
      "command": "npx",
      "args": ["-y", "dependably-mcp"],
      "env": {
        "DEPENDABLY_BASE_URL": "https://dependably.example.com",
        "DEPENDABLY_TOKEN": "dpb_xxx"
      }
    }
  }
}
```

(With a global install, `"command": "dependably-mcp"` with no args works too. If you built from source, point `command`/`args` at `node /path/to/dependably-mcp/dist/index.js` instead.)

### Claude Desktop

Install the extension bundle instead of editing JSON. Download `dependably-<version>.mcpb` from the
release page (verify it against the `.sha256` beside it), then either double-click it or drag it onto
**Settings → Extensions** in Claude Desktop. The install dialog asks for your Dependably URL and a
personal access token; the token is stored in your operating system's keychain, and the optional
import folder enables the two air-gapped import tools scoped to that folder.

To build the bundle from source:

```bash
npm ci
npm run bundle:verify    # → dist-mcpb/dependably-<version>.mcpb + .sha256, then boots the server from the unpacked bundle
```

`manifest.json` at the repo root is the extension manifest. Its tool list is generated from the
server by `npm run manifest:sync`, and `npm test` fails when it is stale. The bundle is unsigned for
now; see `docs/distribution-plan.md` for why, and for the plan to list it in Anthropic's directory.

If you would rather keep a hand-written config, edit
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your
OS with the same shape as the Claude Code example above.

## Investigating logs / metrics / incidents

| Signal | Where to look |
|---|---|
| **Liveness / readiness** | `readiness_check` first — it reports per-subsystem degradation (DB, blob store, …). |
| **Live metrics** | `get_prometheus_metrics` for raw counters (IP-allowlisted server-side). |
| **Auth incidents** (brute force, lockouts, stolen tokens) | `siem_list_auth_events` filtered to `login.failure`, `login.locked`, `lockout.triggered`, `token.revoked`. |
| **Vulnerability sprawl** | `siem_vulnerabilities_summary` for an instance-wide, severity-bucketed view. |

**What we cannot surface over HTTP** (inherent to Dependably, not omissions in this server):

- **Application logs (Serilog)** are written to stdout only. Read them with `docker logs dependably`, your container platform's log aggregator, or by piping stdout to a log sink. There is no HTTP log-query endpoint.
- **Distributed traces** are exported via OTLP push when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Query them from your tracing backend (Jaeger / Tempo / Datadog / …), not from this MCP server.

## What this server doesn't do

- **No JWT/session login.** PAT-only, on purpose (see [PAT-only, read + ops](#pat-only-read--ops)).
- **No package install/publish from inside the MCP server.** The setup-helper tools return command strings; the LLM shows them to you and you run them. This keeps the MCP server from shelling out to `npm`/`pip`/`dotnet` with your network and FS access.
- **No policy-mutation, membership, token, or claim tools** — writes beyond yank/import stay JWT-session-only server-side, and a few reads aren't exposed as tools yet (see [Roadmap](#roadmap)).

## Development

```bash
git clone https://github.com/dependably/dependably-mcp.git
cd dependably-mcp
npm install
npm run dev   # tsc --watch
npm run build # tsc once
npm test      # build + smoke test (boots the server in-memory, asserts the tool surface)
```

> **Note on the lockfile:** we dogfood a private Dependably instance as our npm registry, so the committed `package-lock.json` and `.npmrc` resolve against it. You don't need access to build: every dependency is also on the public registry, so point npm back at it for your clone (`echo 'registry=https://registry.npmjs.org/' > .npmrc` — it's what our public CI does) and install with `npm ci --replace-registry-host=always`. The lockfile's integrity hashes still pin the exact same bytes.

Source layout:

```
src/
├── index.ts           # entry: load config, start stdio
├── config.ts          # env parsing (PAT-only)
├── client.ts          # fetch wrapper (bearer auth, timeout, RFC 7807 errors)
├── server.ts          # registers the 6 tool modules
├── format.ts          # tool-result helpers (json/withSummary/err/run)
└── tools/
    ├── read.ts         # list/get/search packages, vulns, activity, whoami, license policy, lookup
    ├── yank.ts         # yank_version
    ├── siem.ts         # siem_list_auth_events, siem_vulnerabilities_summary
    ├── import.ts       # import_manifest, admin_upload (opt-in via DEPENDABLY_IMPORT_ROOT)
    ├── observability.ts# health_check, readiness_check, get_version, get_prometheus_metrics
    └── setup.ts        # get_install_command, get_publish_command
```

Adding a tool: import `server` and `client`, call `server.registerTool(name, config, handler)`. Wrap the handler body in the `run()` helper from `format.ts` so HTTP errors become readable text. Keep the surface PAT-reachable — do not add JWT-only or `scope=system` endpoints.

## License

Apache-2.0.
