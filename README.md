# dependably-mcp

An MCP (Model Context Protocol) server that lets an LLM client — Claude Desktop, Claude Code, Cursor, anything that speaks MCP — run supply-chain automation and incident triage against a [Dependably](https://github.com/dependably/dependably) instance over stdio.

Dependably is a self-hosted private artifact repository for npm, PyPI, NuGet, Maven, RPM, OCI, Go, and Cargo. This MCP server wraps the slice of its management API that a **static API token (PAT)** can reach today.

## v1 — PAT-only, works today

This is **v1**. It authenticates **only** with a Dependably Personal Access Token (`DEPENDABLY_TOKEN`) sent as a bearer token, and it ships **only the tools that actually function with a PAT today** — 11 tools across 5 groups.

Dependably's management API is JWT-session-first: the default auth scheme reads the session JWT from the `dependably_session` cookie and never looks at the `Authorization` header. A PAT therefore only works on endpoints that explicitly opt into the `ApiToken` auth scheme (yank, admin import, SIEM) plus anonymous / IP-allowlisted probes (health, readiness, version, metrics). The install/publish command builders run entirely locally and never call the server. Everything else — the read surface — returns `401` to a PAT until a separate server change lands (see [Roadmap / v2](#roadmap--v2)), so it is **not** in v1.

### The 11 tools

| Tool | Group | Capability the PAT needs |
|---|---|---|
| `yank_version` — destructive delete of a published version | vulns | `yank:{ecosystem}` |
| `siem_list_auth_events` — login/lockout/token/rbac auth events with ISO-8601 since/until + prefix filters | siem | `read:audit` |
| `siem_vulnerabilities_summary` — severity-bucketed vuln counts by ecosystem | siem | `read:audit` |
| `import_manifest` — manifest-driven, all-or-nothing bulk import (lockfile + referenced artefacts) | import | `import:*` + `tenant:configure` (admin-grade token) |
| `admin_upload` — air-gapped bulk upload of N local artefact files (ecosystem auto-detected) | import | `import:*` + `tenant:configure` (admin-grade token) |
| `health_check` — liveness (`GET /health`) | observability | none (anonymous) |
| `readiness_check` — readiness + per-subsystem checks (`GET /ready`) | observability | none (anonymous) |
| `get_version` — server build version (`GET /version`) | observability | none (anonymous / IP-allowlisted) |
| `get_prometheus_metrics` — raw `/metrics` text | observability | none (IP-allowlisted server-side) |
| `get_install_command` — build the install shell command (does **not** execute) | setup | none (local, no server call) |
| `get_publish_command` — build the publish shell command (does **not** execute) | setup | none (local, no server call) |

`get_install_command` / `get_publish_command` cover all eight ecosystems (npm, pypi, nuget, maven, rpm, oci, golang, cargo). Go is proxy-only: it has an install command but no hosted publish endpoint, so `get_publish_command` returns guidance to push a VCS tag instead.

### What scope should the token have?

Mint the token with only the capabilities for the tools you intend to use. **v1 needs neither `push` (`publish:*`) nor `pull` (`read:packages`)** — publishing and pulling packages are done by your package manager with its own token, and the read/browse tools are deferred to v2 (see [Roadmap / v2](#roadmap--v2)). Pick from:

| You want to… | Capability to grant | Unlocks |
|---|---|---|
| Monitor audit + vulnerability posture *(recommended minimal — read-only)* | `read:audit` | `siem_list_auth_events`, `siem_vulnerabilities_summary` |
| Yank a bad published version | `yank:*` (or per-ecosystem `yank:npm`, …) | `yank_version` |
| Bulk / air-gapped import | `import:*` **and** `tenant:configure` *(admin-grade)* | `import_manifest`, `admin_upload` |
| Health / readiness / version / metrics, and the local command builders | *nothing* — anonymous / IP-allowlisted / local | the 6 observability + setup tools |

A **`read:audit`-only** token is the safe default: it drives both SIEM tools (and, with them, every anonymous/local tool) while carrying no write power — a `yank`/`import` attempt returns a clean `403`. Add `yank:*` or `import:*`+`tenant:configure` only if you need those actions. Always use a **user-owned PAT** (service/M2M tokens `404` on gated endpoints).

### Known limits

- **Service / machine (M2M) tokens currently `404`** on capability-gated endpoints — including `yank` and `import`. Use a **user-owned PAT**.
- In **MFA-required orgs**, a token principal may get **`403 mfa_enrollment_required`** on gated endpoints even with the right capability.
- Admin **import** (`import_manifest`, `admin_upload`) requires an **admin-grade token** carrying `import:*` and `tenant:configure`; a plain read PAT will be rejected.

## Roadmap / v2

The **read surface is deferred to v2**. These tools depend on a server-side change to accept PATs on read endpoints that has **not shipped yet** — tracked as **dependably-community#343**. Until it lands they return `401` to a PAT, so v1 does not expose them:

- package inventory (`list_packages`, `get_package`, `get_org_stats`)
- vulnerability list (`list_vulnerabilities`)
- audit/activity logs (`list_activity`, `list_audit_log`)
- org posture (`get_org_settings`, `get_proxy_settings`, `get_retention`)
- identity (`whoami`), package search, quarantine list
- the client-config `get_setup_snippet` fetch

When #343 ships, these return in v2.

## Install

```bash
git clone https://github.com/<you>/dependably-mcp.git
cd dependably-mcp
npm install
npm run build
```

That produces `dist/index.js`, the stdio entry point.

## Configure

The server is configured entirely through environment variables, supplied by your MCP client.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DEPENDABLY_BASE_URL` | yes | — | Base URL of your Dependably instance (e.g. `https://dependably.example.com`). Tenancy is resolved from the host — no org slug needed. |
| `DEPENDABLY_TOKEN` | yes | — | A Dependably **Personal Access Token (PAT)**. Mint one from the web UI under *Tokens*. Sent as a bearer token. Use a **user-owned** PAT (service/M2M tokens currently `404` on gated endpoints). |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request HTTP timeout. |

The PAT's **capabilities** determine which tools succeed — see the capability column in [the 11 tools](#the-11-tools).

### Claude Code

```bash
claude mcp add dependably node /absolute/path/to/dependably-mcp/dist/index.js \
  --env DEPENDABLY_BASE_URL=https://dependably.example.com \
  --env DEPENDABLY_TOKEN=dpb_xxx
```

Or edit `~/.claude.json` (or your project `.mcp.json`) directly:

```jsonc
{
  "mcpServers": {
    "dependably": {
      "command": "node",
      "args": ["/absolute/path/to/dependably-mcp/dist/index.js"],
      "env": {
        "DEPENDABLY_BASE_URL": "https://dependably.example.com",
        "DEPENDABLY_TOKEN": "dpb_xxx"
      }
    }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS, same shape as above.

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

- **No JWT/session login.** PAT-only, on purpose (see [v1 — PAT-only](#v1--pat-only-works-today)).
- **No package install/publish from inside the MCP server.** The setup-helper tools return command strings; the LLM shows them to you and you run them. This keeps the MCP server from shelling out to `npm`/`pip`/`dotnet` with your network and FS access.
- **No read/browse, policy, membership, token, claim, or settings tools yet** — those are JWT-session-only today and deferred to v2 (see [Roadmap / v2](#roadmap--v2)).

## Development

```bash
npm run dev   # tsc --watch
npm run build # tsc once
```

Source layout:

```
src/
├── index.ts           # entry: load config, start stdio
├── config.ts          # env parsing (PAT-only)
├── client.ts          # fetch wrapper (bearer auth, timeout, RFC 7807 errors)
├── server.ts          # registers the 5 tool modules
├── format.ts          # tool-result helpers + shared pagination schema
└── tools/
    ├── vulns.ts        # yank_version
    ├── siem.ts         # siem_list_auth_events, siem_vulnerabilities_summary
    ├── import.ts       # import_manifest, admin_upload
    ├── observability.ts# health_check, readiness_check, get_version, get_prometheus_metrics
    └── setup.ts        # get_install_command, get_publish_command
```

Adding a tool: import `server` and `client`, call `server.registerTool(name, config, handler)`. Wrap the handler body in the `run()` helper from `format.ts` so HTTP errors become readable text. Keep the surface PAT-reachable — do not add JWT-only or `scope=system` endpoints.

## License

Apache-2.0.
