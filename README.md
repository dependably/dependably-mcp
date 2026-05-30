# dependably-mcp

An MCP (Model Context Protocol) server that lets an LLM client — Claude Desktop, Claude Code, Cursor, anything that speaks MCP — browse and manage a [Dependably](https://github.com/dependably/dependably) instance over stdio.

Dependably is a self-hosted private artifact repository for npm, PyPI, NuGet, Maven, RPM, and OCI. This MCP server wraps its management API so you can ask questions like *"which versions of left-pad are in our cache and which have OSV findings?"* or *"create a service token for our CI named ci-publisher with publish:npm capability"* from inside your editor.

## Install

Clone and build:

```bash
git clone https://github.com/<you>/dependably-mcp.git
cd dependably-mcp
npm install
npm run build
```

That produces `dist/index.js` which is the stdio entry point.

## Configure

The server is configured entirely through environment variables, supplied by your MCP client.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DEPENDABLY_BASE_URL` | yes | — | Base URL of your Dependably instance (e.g. `https://dependably.example.com`). |
| `DEPENDABLY_TOKEN` | yes | — | A Dependably user or service token. Mint one from the web UI under *Tokens*. |
| `DEPENDABLY_ORG_SLUG` | no | `default` | Used by the install/publish command-generator tools to template URLs. |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request HTTP timeout. |

The token's capabilities determine which tools succeed. A read-only member token can browse; a `tenant:configure` admin token can mutate settings; a system-admin token at the apex host unlocks the `system_*` tools.

### Claude Code

Add the server with `claude mcp add`:

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

All tools take JSON arguments and return JSON (or a fenced shell command, for the command-generator tools).

### Browsing
- `list_packages` — list packages in your org, optionally filtered by ecosystem or search term
- `get_package` — full version list + licenses + max OSV score for a package
- `get_org_stats` — org-level analytics

### Vulnerabilities
- `list_vulnerabilities` — affected packages from OSV scans
- `rescan_version` — force an OSV rescan (1-hour cooldown)
- `block_version` / `unblock_version` — manual fetch block for a specific version
- `yank_version` — destructive delete of a published version

### Audit
- `list_activity` — package-operation events (publish, yank, …)
- `list_audit_log` — config-mutation events (settings, tokens, membership, …)

### Tokens
- `list_tokens` / `create_token` / `revoke_token` — your own user tokens
- `list_service_tokens` / `create_service_token` / `revoke_service_token` — M2M tokens (admin)

### Allowlist / Blocklist / License policy
- `list_allowlist` / `add_allowlist` / `remove_allowlist`
- `list_blocklist` / `add_blocklist` / `remove_blocklist`
- `get_license_policy` / `set_license_policy_mode` / `list_license_policy_review`
- `add_license_allowlist` / `remove_license_allowlist`
- `add_license_blocklist` / `remove_license_blocklist`

### Org settings
- `get_org_settings` / `update_org_settings`
- `get_retention` / `update_retention`
- `get_proxy_settings` / `update_proxy_settings`

### Members & invites
- `list_org_users` / `change_user_role` / `remove_user`
- `list_invites` / `create_invite` / `cancel_invite`

### Claims (namespace ownership)
- `list_claims` / `get_claim`
- `create_claim` / `transition_claim` / `release_claim`

### Setup helpers (command generators)
- `get_setup_snippet` — fetch the canonical client-config snippet (`.npmrc`, `pip.conf`, `nuget.config`, …) from Dependably itself
- `get_install_command` — return the shell command to install a package via Dependably (does **not** execute)
- `get_publish_command` — return the shell command to publish an artifact via Dependably (does **not** execute)

### Observability & incident triage
- `health_check` — liveness (`GET /health`, anonymous)
- `readiness_check` — readiness with subsystem checks (`GET /ready`, anonymous; returns 503 + details when degraded)
- `get_version` — server build version
- `get_prometheus_metrics` — raw `/metrics` text (IP-allowlisted server-side)
- `get_observability_snapshot` — blob sizes per tier, last-success age per background job, since-startup counters, recent `/metrics` scrape attempts (system admin)
- `get_metrics_access_config` — `/metrics` IP allowlist + enable flag (system admin)

### SIEM / auth-event log
- `siem_list_auth_events` — `login.failure`, `login.locked`, `lockout.triggered`, `token.created`, `token.revoked`, `rbac.*` events with ISO-8601 since/until and prefix filters
- `siem_vulnerabilities_summary` — severity-bucketed counts by ecosystem

### System admin (apex / system-admin token only)
- `system_list_tenants` / `system_dashboard`
- `system_list_background_jobs` (filter `outcome="server_error"` for failed runs) / `system_list_background_job_facets`
- `system_list_audit`
- `system_get_instance_settings`
- `system_set_tenant_storage_quota`

## Investigating logs / metrics / traces / incidents

| Signal | Where to look |
|---|---|
| **Liveness / readiness** | `readiness_check` first — it reports per-subsystem degradation (DB, blob store, …). |
| **Live metrics** | `get_prometheus_metrics` for raw counters; `get_observability_snapshot` for a curated dashboard view including blob-store sizes and last-success age per job. |
| **Failed background jobs** | `system_list_background_jobs` with `outcome="server_error"`. Use `system_list_background_job_facets` to discover valid `jobName` values. |
| **Auth incidents** (brute force, lockouts, stolen tokens) | `siem_list_auth_events` filtered to `login.failure`, `login.locked`, `lockout.triggered`, `token.revoked`. |
| **Blocked package fetches** | `list_activity` with `event_type` in `{blocked, blocked_manual, blocked_vuln_score, blocked_release_age}`. |
| **Vulnerability sprawl** | `siem_vulnerabilities_summary` for an instance-wide view; `list_vulnerabilities` for the org-scoped detail. |
| **Config drift / policy changes** | `list_audit_log` (org) and `system_list_audit` (instance). |
| **Storage near full** | `system_list_tenants` returns per-tenant `storageBytes` and `storageQuotaBytes`; `get_observability_snapshot` returns `blobStoreSizesByTier`. |

**What we cannot surface over HTTP** (these are inherent to Dependably, not omissions in this server):

- **Application logs (Serilog)** are written to stdout only. Read them with `docker logs dependably`, your container platform's log aggregator, or by piping stdout to a log sink. There is no HTTP log-query endpoint.
- **Distributed traces** are exported via OTLP push when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (`Program.cs` lines 500–559). Query them from your tracing backend (Jaeger / Tempo / Datadog / …), not from this MCP server.
- **No rate-limit query endpoint and no last-N-exceptions endpoint** — those signals live in logs/metrics.

## What this server doesn't do

- **No package install/publish from inside the MCP server.** The setup-helper tools return command strings; the LLM shows them to you and you run them. This keeps the MCP server from shelling out to `npm`/`pip`/`dotnet` with your network and FS access.
- **No bulk file upload** (`/api/v1/admin/upload`, `/api/v1/admin/import/manifest`). LLMs can't reliably hand over binary uploads — use the Dependably CLI or web UI for those.
- **No SAML config endpoints** — niche; ask if you want them added.

## Development

```bash
npm run dev   # tsc --watch
npm run build # tsc once
```

Source layout:

```
src/
├── index.ts           # entry: load config, start stdio
├── config.ts          # env parsing
├── client.ts          # fetch wrapper (auth, timeout, RFC 7807 errors)
├── server.ts          # registers all tool modules
├── format.ts          # tool-result helpers + shared pagination schema
└── tools/
    ├── packages.ts    ├── vulns.ts          ├── audit.ts
    ├── tokens.ts      ├── lists.ts          ├── settings.ts
    ├── users.ts       ├── claims.ts         ├── setup.ts
    ├── observability.ts ├── siem.ts
    └── system.ts
```

Adding a tool: import `server` and `client` from the module entry, call `server.tool(name, description, zodShape, handler)`. Wrap the handler body in the `run()` helper from `format.ts` so HTTP errors become readable text.

## License

Apache-2.0.
