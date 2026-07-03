# dependably-mcp

An MCP (Model Context Protocol) server that lets an LLM client — Claude Desktop, Claude Code, Cursor, anything that speaks MCP — inspect and run supply-chain automation against a [Dependably](https://github.com/dependably/dependably) instance over stdio.

Dependably is a self-hosted private artifact repository for npm, PyPI, NuGet, Maven, RPM, and OCI. This MCP server wraps the slice of its management API that a **static API token (PAT)** can reach, so you can ask questions like *"which versions of left-pad are in our cache and which have OSV findings?"* or run *"yank this compromised version"* from inside your editor.

## PAT-only surface

This server authenticates **only** with a Dependably Personal Access Token (`DEPENDABLY_TOKEN`) sent as a bearer token. It does **not** do JWT/session login, and that is intentional.

Dependably's management API is JWT-session-first: the default auth scheme reads the session JWT from the `dependably_session` cookie and never looks at the `Authorization` header. A PAT therefore only works on endpoints that explicitly opt into the `ApiToken` auth scheme (today: yank, import, SIEM) plus anonymous / IP-allowlisted probes (health, readiness, version, metrics). Everything else returns `401` to a PAT.

So this server deliberately exposes a **read + supply-chain-automation** surface:

- **Reads** — package inventory, vulnerability reports, activity/audit logs, org/proxy/retention posture, and identity (`whoami`).
- **Supply-chain automation** — `yank_version` (destructive removal of a bad artifact).
- **Anonymous ops probes** — health, readiness, version, Prometheus metrics.
- **Local command builders** — `get_install_command` / `get_publish_command` build shell snippets locally and never call the server.

Tools that a PAT cannot reach — token/identity admin, allow/block/license policy writes, claim admin, membership/invite management, org/proxy/retention **writes**, tenant rescan/block, and the system/tenant control plane — have been removed rather than left in to fail with `401`.

> [!IMPORTANT]
> ### What works today vs. what needs a server change
>
> Most of the **read** tools depend on a server-side change to accept PATs that has **not shipped yet** (tracked as **dependably-community#343**). Until it lands they will return **`401`** even with a valid PAT:
>
> - `list_packages`, `get_package`, `get_org_stats`
> - `list_vulnerabilities`
> - `list_activity`, `list_audit_log`
> - `get_org_settings`, `get_proxy_settings`, `get_retention`
> - `whoami`
> - `get_setup_snippet`
>
> **Works today with a PAT:**
>
> - `yank_version`
> - `siem_list_auth_events`, `siem_vulnerabilities_summary`
> - `health_check`, `readiness_check`, `get_version`, `get_prometheus_metrics` (anonymous / IP-allowlisted — `get_prometheus_metrics` is gated by a server-side IP allowlist, not the token)
> - `get_install_command`, `get_publish_command` (built locally, no server call)
>
> Admin **import** (bulk manifest ingest) is another `ApiToken`-scheme endpoint that works with a PAT, but this server does not expose an import tool yet.

### Token limitations (from the server review)

- **Service / machine (M2M) tokens currently `404`** on capability-gated endpoints — including `yank` and `import`. Use a **user-owned PAT** until dependably-community#343 addresses M2M principals.
- In **MFA-required orgs**, a token principal may get **`403 mfa_enrollment_required`** on gated endpoints even with the right capability.

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
| `DEPENDABLY_BASE_URL` | yes | — | Base URL of your Dependably instance (e.g. `https://dependably.example.com`). |
| `DEPENDABLY_TOKEN` | yes | — | A Dependably **Personal Access Token (PAT)**. Mint one from the web UI under *Tokens*. Sent as a bearer token. Use a **user-owned** PAT (service/M2M tokens currently `404` on gated endpoints). |
| `DEPENDABLY_ORG_SLUG` | no | `default` | Used by the local install/publish command-generator tools to template URLs. |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request HTTP timeout. |

The PAT's **capabilities** determine which tools succeed — see the per-tool capability notes below.

### Claude Code

```bash
claude mcp add dependably node /absolute/path/to/dependably-mcp/dist/index.js \
  --env DEPENDABLY_BASE_URL=https://dependably.example.com \
  --env DEPENDABLY_TOKEN=dpb_xxx \
  --env DEPENDABLY_ORG_SLUG=my-org
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
        "DEPENDABLY_TOKEN": "dpb_xxx",
        "DEPENDABLY_ORG_SLUG": "my-org"
      }
    }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS, same shape as above.

## Tools

All tools take JSON arguments and return JSON (or a fenced shell command, for the command-generator tools). The **Capability** column is the PAT capability the underlying endpoint requires. Tools marked **#343** currently return `401` to a PAT until dependably-community#343 ships (see the note above).

### Browsing (reads)
| Tool | Capability | Status |
|---|---|---|
| `list_packages` — packages in your org, filterable by ecosystem/search | `read:packages` | #343 |
| `get_package` — version list + licenses + max OSV score for a package | `read:packages` | #343 |
| `get_org_stats` — org-level analytics | `read:packages` | #343 |

### Vulnerabilities
| Tool | Capability | Status |
|---|---|---|
| `list_vulnerabilities` — affected packages from OSV scans | `read:packages` | #343 |
| `yank_version` — destructive delete of a published version | `yank:{ecosystem}` | **works today** |

### Audit (reads)
| Tool | Capability | Status |
|---|---|---|
| `list_activity` — package-operation events (publish, yank, …) | `read:audit` | #343 |
| `list_audit_log` — config-mutation events (settings, membership, …) | `read:audit` | #343 |

### Org posture (reads)
| Tool | Capability | Status |
|---|---|---|
| `get_org_settings` — anonymous-pull, allowlist mode, upload limits, upstreams | `read:tenant` | #343 |
| `get_proxy_settings` — passthrough flag, OSV score tolerance, min release age | `read:tenant` | #343 |
| `get_retention` — keep_versions / keep_days / activity retention | `read:tenant` | #343 |

### Identity
| Tool | Capability | Status |
|---|---|---|
| `whoami` — calling identity (falls back to a minimal reply on `401`) | `read:metadata` | #343 |

### Setup helpers
| Tool | Capability | Status |
|---|---|---|
| `get_setup_snippet` — fetch the canonical client-config snippet (`.npmrc`, `pip.conf`, …) from Dependably | `read:metadata` | #343 |
| `get_install_command` — build the install shell command (does **not** execute) | none (local) | **works today** |
| `get_publish_command` — build the publish shell command (does **not** execute) | none (local) | **works today** |

### Observability / incident triage (anonymous)
| Tool | Capability | Status |
|---|---|---|
| `health_check` — liveness (`GET /health`) | none (anonymous) | **works today** |
| `readiness_check` — readiness + subsystem checks (`GET /ready`, 503 + details when degraded) | none (anonymous) | **works today** |
| `get_version` — server build version | none (anonymous) | **works today** |
| `get_prometheus_metrics` — raw `/metrics` text | none (IP-allowlisted server-side) | **works today** |

### SIEM / auth-event log
| Tool | Capability | Status |
|---|---|---|
| `siem_list_auth_events` — `login.failure`, `login.locked`, `lockout.triggered`, `token.*`, `rbac.*` with ISO-8601 since/until and prefix filters | `read:audit` | **works today** |
| `siem_vulnerabilities_summary` — severity-bucketed counts by ecosystem | `read:audit` | **works today** |

## Investigating logs / metrics / traces / incidents

| Signal | Where to look |
|---|---|
| **Liveness / readiness** | `readiness_check` first — it reports per-subsystem degradation (DB, blob store, …). |
| **Live metrics** | `get_prometheus_metrics` for raw counters (IP-allowlisted server-side). |
| **Auth incidents** (brute force, lockouts, stolen tokens) | `siem_list_auth_events` filtered to `login.failure`, `login.locked`, `lockout.triggered`, `token.revoked`. |
| **Blocked package fetches** | `list_activity` with `event_type` in `{blocked, blocked_manual, blocked_vuln_score, blocked_release_age}`. |
| **Vulnerability sprawl** | `siem_vulnerabilities_summary` for an instance-wide view; `list_vulnerabilities` for the org-scoped detail. |
| **Config drift / policy changes** | `list_audit_log`. |

**What we cannot surface over HTTP** (inherent to Dependably, not omissions in this server):

- **Application logs (Serilog)** are written to stdout only. Read them with `docker logs dependably`, your container platform's log aggregator, or by piping stdout to a log sink. There is no HTTP log-query endpoint.
- **Distributed traces** are exported via OTLP push when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Query them from your tracing backend (Jaeger / Tempo / Datadog / …), not from this MCP server.
- **No rate-limit query endpoint and no last-N-exceptions endpoint** — those signals live in logs/metrics.
- **The operator dashboard / metrics-access config** (`/api/v1/system/*`) is `scope=system` and structurally unreachable by a PAT, so those tools are not exposed here.

## What this server doesn't do

- **No JWT/session login.** PAT-only, on purpose (see *PAT-only surface* above).
- **No package install/publish from inside the MCP server.** The setup-helper tools return command strings; the LLM shows them to you and you run them. This keeps the MCP server from shelling out to `npm`/`pip`/`dotnet` with your network and FS access.
- **No policy, membership, token, claim, or settings writes**, and no system/tenant control plane — those endpoints are JWT-session-only or `scope=system`, so a PAT cannot reach them.

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
├── server.ts          # registers the surviving tool modules
├── format.ts          # tool-result helpers + shared pagination schema
└── tools/
    ├── packages.ts    ├── vulns.ts    ├── audit.ts
    ├── settings.ts    ├── users.ts    ├── setup.ts
    ├── observability.ts ├── siem.ts
```

Adding a tool: import `server` and `client`, call `server.registerTool(name, config, handler)`. Wrap the handler body in the `run()` helper from `format.ts` so HTTP errors become readable text. Keep the surface PAT-reachable — do not add JWT-only or `scope=system` endpoints.

## License

Apache-2.0.
