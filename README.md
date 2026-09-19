# dependably-mcp

An MCP server that lets Claude Desktop, Claude Code, Cursor, or anything else that speaks the
Model Context Protocol query your [Dependably](https://github.com/dependably/dependably-community)
instance: package inventory, vulnerability reports, licence policy, audit events and incident
triage.

Dependably is a private artefact repository, self-hosted or as a hosted SaaS instance. This server
is read-only and runs over stdio through a single personal access token: no tool writes to your
instance or your filesystem, and none of them runs a command.

## Requirements

- **A current version of Node.** The floor is declared in `package.json` under `engines`, and
  npm refuses to install below it.
- **A Dependably instance,** and its base URL.
- **A personal access token**, created in that instance's web UI under Tokens. Choose the
  **Pull** preset: it is read-only, any member can create it, and it is the only preset this
  server needs — see [Choosing a token](#choosing-a-token).

## Install

### Claude Code

```bash
claude mcp add dependably \
  --env DEPENDABLY_BASE_URL=https://dependably.example.com \
  --env DEPENDABLY_TOKEN=dpb_xxx \
  -- npx -y dependably-mcp
```

`npx` fetches the package from npm on first use. To install it once instead, run
`npm install -g dependably-mcp` and use `dependably-mcp` in place of `npx -y dependably-mcp`.

Or edit `~/.claude.json`, or your project's `.mcp.json`, directly:

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

### Claude Desktop

Install the extension bundle rather than editing JSON. Download
`dependably-<version>.mcpb` from the project's releases and verify it against the `.sha256`
beside it. Then double-click it, or drag it onto the Extensions pane in Settings.

The install dialog asks for your Dependably URL and a personal access token, and stores the
token in your operating system's keychain. Two optional fields cover the request timeout and a
private certificate authority bundle.

To keep a hand-written config instead, edit
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or the equivalent on
your OS, using the same shape as the Claude Code example above.

## Verify

Restart your MCP client, then ask it to run these three, in order:

1. `readiness_check` needs no capability, so it answers as soon as the URL is right and the
   instance is reachable. It returns `{ status: "ready" | "degraded", checks, errors }`.
2. `list_packages` is the first call that uses your token. A result here confirms the Pull
   preset is granted and working.
3. `get_license_policy` confirms the same token reaches org policy, not just inventory.

Then ask a real question, such as *which of our packages have critical vulnerabilities?* Claude
answers that one with `list_vulnerabilities`.

## Configure

The server reads its whole configuration from environment variables supplied by your MCP client.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DEPENDABLY_BASE_URL` | yes | | Base URL of your instance, such as `https://dependably.example.com`. Tenancy comes from the host, so no org slug is needed. |
| `DEPENDABLY_TOKEN` | yes | | A Dependably personal access token, sent as a bearer token. |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request HTTP timeout. |
| `NODE_EXTRA_CA_CERTS` | no | unset | Path to a PEM bundle, for an instance behind a private or self-signed certificate. |

Self-hosting on your own network works two ways. Plain `http://` is accepted, so a LAN instance
needs no certificate at all. For HTTPS with a self-signed or internal CA certificate, point
`NODE_EXTRA_CA_CERTS` at that PEM and Node trusts it for this process alone. There is deliberately
no switch to turn verification off outright, because this server carries a token that can read
your whole registry. A TLS failure names both options and the host it could not verify.

## What it can do

15 tools in 3 groups. Every one is read-only, none reads a local file, and every one is reachable
with a **Pull** token — the preset any member can mint for themselves.

### Read

Package inventory, vulnerabilities and licence policy.

| Tool | What it does | Capability |
|---|---|---|
| `list_packages` | Paginated package inventory, with ecosystem and search filters. | `read:packages` |
| `get_package` | One package: versions, SPDX licence identifiers, vulnerability links. | `read:packages` |
| `search_packages` | Quick name search across the registry. | `read:packages` |
| `check_dependencies` | Scopes the org report to one project's dependency list and returns only what affects it, each package annotated with the version to bump to. | `read:packages` |
| `list_vulnerabilities` | Paginated org-wide report of affected packages, compact by default. | `read:packages` |
| `get_vulnerability` | Full advisory detail, including remediation guidance. | `read:packages` |
| `get_remediation` | Fixed versions for up to 200 advisories at once, without the advisory prose. | `read:packages` |
| `lookup_package` | Pre-adoption verdict on a package that is not in the registry: upstream metadata, OSV and org policy. Ingests nothing. Takes a narrower ecosystem set — see below. | `read:packages` |
| `get_license_policy` | Enforcement mode plus the SPDX allowlist and blocklist, so you can see which licences are approved. | `read:packages` |
| `list_remediation_skills` | Index of every curated remediation skill the instance ships — one per vulnerability class (vulnerable dependency, injection, XSS, path traversal, unsafe deserialization, SSRF, broken access control, weak cryptography, authentication failures). | none, anonymous |
| `get_remediation_skill` | Full how-to-fix guide for one or more skill ids, as markdown. Ids come from `list_remediation_skills` or from the `skills` field `get_remediation`/`check_dependencies` return. | none, anonymous |

### Observability

| Tool | What it does | Capability |
|---|---|---|
| `health_check` | Liveness (`GET /health`). | none, anonymous |
| `readiness_check` | Readiness plus per-subsystem checks (`GET /ready`). | none, anonymous |

Both answer without a token and from any machine. `readiness_check` is the one to reach for first
when triaging an incident: it names the subsystem reporting degraded.

`/version` and `/metrics` are deliberately not wrapped as tools. A live instance answers `/metrics`
with well over a megabyte of Prometheus text — larger than most model context windows, so no agent
can usefully read it, and truncating it would be worse than not offering it. Scrape it with
Prometheus, which is what it is for.

### Setup

Both build a shell command and return it as text. Neither executes anything, and neither calls the
server — which is what keeps this server from shelling out to `npm`, `pip` or `dotnet` with your
network and filesystem access.

| Tool | What it does | Capability |
|---|---|---|
| `get_install_command` | Builds the install command for an ecosystem. | none, runs locally |
| `get_publish_command` | Builds the publish command for an ecosystem. | none, runs locally |

Go is served through the standard module proxy protocol, so `get_install_command` works; modules
are published the Go way, by tagging a release in source, and `get_publish_command` returns that
guidance rather than a command.

### Ecosystems, and why the sets differ

| Plane | Ecosystems |
|---|---|
| Read tools | npm, pypi, nuget, maven, rpm, oci, golang, cargo, apk, terraform, hex |
| `lookup_package` | npm, pypi, nuget, maven, golang, cargo, hex |
| Setup tools | npm, pypi, nuget, maven, rpm, oci, golang, cargo |

The read tools take everything the registry plane serves. `lookup_package` is narrower because a
pre-adoption verdict has to resolve the candidate against an upstream, and rpm, oci, apk and
terraform have no single canonical upstream to ask — the server enforces that and answers anything
outside the set with `422 Must be one of: …`. The setup tools are bounded by the commands they know
how to write, not by what the registry holds.

Go is spelled **`golang`**, not `go`. The registry endpoints do not validate this parameter — they
treat it as a filter — so `go` comes back `200` with no results rather than as an error.

### Passing a dependency list to `check_dependencies`

Reach for this one when the question is about a project rather than the whole org. It takes the
dependency list as an argument, `packages`, an array of `{name, version, dev}`, and reads no files
itself. For an npm `package-lock.json` (v2 or v3) the argument is every entry of its `packages`
map: read the lockfile with whatever file access you already have and pass the result.

A `lockfileVersion` 1 lockfile has no `packages` map and is refused with a message naming the fix.
Run `npm install` with npm 7 or later to upgrade it, or build the list yourself.

### Choosing a token

One preset covers the whole server: **Pull** (`read:metadata`, `read:artifact`, `read:packages`).
Any member can mint it, including one with no admin rights.

That is the point of the surface being this size. A token never carries more than the role of the
person who minted it, so anything needing `read:audit` or `read:tenant` has to be issued by an admin
or owner — which turns "install the extension" into a request to somebody else. Every tool here
stays inside what a developer can grant themselves.

The 4 observability and setup tools need no token at all, and neither do the 2 remediation-skill
tools — they serve static, curated content that is identical for every tenant.

The audit surface (the org activity feed, auth events, SIEM vulnerability counts) is deliberately
**not** here. Those endpoints exist on the instance and an Audit token still reaches them; read them
in the web UI, or with your own client.

This server never needs `publish:*` or `yank:*`. It reads; publishing and pulling packages are done
by your package manager with its own token.

Any tool whose capability the token lacks returns a `403` naming what is missing.

## Privacy Policy

This server makes no network calls of its own beyond the Dependably instance you configure, using
the personal access token you provide; it has no other outbound destination, so tool results reach
Anthropic only as Claude's own response to your prompt, under Anthropic's policies. No telemetry,
analytics, or usage data is collected or transmitted. Your token is held in memory for the life of
the process and is never written to disk, logged, or cached by this server; when run as a Claude
Desktop extension, the token is instead stored in your operating system's keychain, managed by
Claude Desktop.

The full policy is published at <https://dependably.ca/privacy>. Contact
[support@dependably.ca](mailto:support@dependably.ca) with questions.
