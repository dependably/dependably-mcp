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
  server needs.

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
token in your operating system's keychain. One optional field takes a private certificate
authority bundle, for an instance whose certificate a public CA did not issue.

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

Then ask a real question. A few to start with are under [Example prompts](#example-prompts).

## Example prompts

Each of these works with a Pull token. The tool Claude reaches for is in brackets.

- *Which of our packages have critical vulnerabilities, and are any of them known to be exploited
  (CISA KEV)?* (`list_vulnerabilities`)
- *Here's my `package-lock.json`. Is anything in it vulnerable, and what should I bump each
  package to?* (`check_dependencies`, then `get_remediation` for a fix on your release line.)
  Claude reads the lockfile itself and passes the resolved versions; the server reads no files.
- *Before I add `log4j-core` 2.14.1 to this service, would our policy allow it?*
  (`lookup_package`, which checks the version against live advisory data and your org's policy
  without pulling it into the registry)
- *What's our policy for third-party packages?* (`get_policies`: licence rules, plus every
  vulnerability, release-age, install-script and signature control, with whether each warns or
  blocks)
- *Which of our projects are failing policy right now, and what's wrong with the latest build of
  the worst one?* (`list_projects`, then `get_project_version`)
- *Explain GHSA-frmv-pr5f-9mcr and how to fix it in our Django 5.0 app.* (`get_vulnerability`,
  then `get_remediation_skill` for the matching how-to-fix guide)
- *Give me the command to install `requests` 2.32.4 through our registry.*
  (`get_install_command`; the command comes back as text for you to run)

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

Every tool is read-only with a user-generated token with **Pull** permissions.

| Tool | What it does |
|---|---|
| `list_packages` | Paginated inventory, with ecosystem and search filters. |
| `get_package` | One package: versions, SPDX licences, vulnerability links. |
| `search_packages` | Quick name search across the registry. |
| `list_vulnerabilities` | Org-wide report of every affected package. |
| `get_vulnerability` | Advisory detail: affected ranges, severity, KEV and EPSS, and remediation guidance. |
| `check_dependencies` | Checks one project's dependency list and names the version to bump to. Versions the registry has never served are checked against live advisory data, and anything that could not be checked is listed as unverified rather than reported clean. |
| `get_remediation` | Fixed versions for a batch of advisories at once, without the prose. |
| `list_projects` | Projects and folders, paginated and searchable by name. |
| `get_project` | One project or folder: versions, ancestors, and a folder's children and subtree rollup. |
| `get_project_version` | A version's SBOM components with advisories and effective priority, plus a policy rollup. |
| `lookup_package` | Pre-adoption verdict on a package not in the registry. Ingests nothing. |
| `get_policies` | The whole package policy: licence rules plus every control that can refuse a download (malware, KEV, SSVC, CVSS, EPSS, release age, install scripts, signatures), with thresholds. Answers *what is our third-party package policy?* |
| `get_license_policy` | Licence rules only: enforcement mode, plus the SPDX allowlist and blocklist. |
| `list_remediation_skills`, `get_remediation_skill` | Curated how-to-fix guides, one per vulnerability class. |
| `readiness_check` | Readiness with per-subsystem detail; needs no token. |
| `get_install_command`, `get_publish_command` | Build an install or publish command, returned as text. |

The ecosystems each tool offers are read from your instance at startup; an instance without that endpoint gets the built-in list.

The setup tools return text for you to run, so this server never shells out to your package manager.
Nothing here needs `read:audit`, `read:tenant`, `publish:*` or `yank:*`.

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
