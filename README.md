# dependably-mcp

An MCP server that lets Claude Desktop, Claude Code, Cursor, or anything else that speaks the
Model Context Protocol query your [Dependably](https://github.com/dependably/dependably-community)
instance: packages, vulnerabilities, licence policy, and the install or publish command for each
ecosystem.

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

The first public npm release is 0.2.0; until it is published, install from a clone of this
repository instead: `npm ci && npm run build && npm install -g .`.

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

### Cursor

Edit `~/.cursor/mcp.json` (every project) or your project's `.cursor/mcp.json` (one project):

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

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

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

### VS Code

Edit your project's `.vscode/mcp.json`. Use an `inputs` prompt for the token instead of writing
it into the file, so it is not committed:

```jsonc
{
  "inputs": [
    {
      "type": "promptString",
      "id": "dependably-token",
      "description": "Dependably personal access token",
      "password": true
    }
  ],
  "servers": {
    "dependably": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "dependably-mcp"],
      "env": {
        "DEPENDABLY_BASE_URL": "https://dependably.example.com",
        "DEPENDABLY_TOKEN": "${input:dependably-token}"
      }
    }
  }
}
```

### Zed

Edit `settings.json` (`zed: open settings file`):

```jsonc
{
  "context_servers": {
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

### Codex CLI

Edit `~/.codex/config.toml`:

```toml
[mcp_servers.dependably]
command = "npx"
args = ["-y", "dependably-mcp"]

[mcp_servers.dependably.env]
DEPENDABLY_BASE_URL = "https://dependably.example.com"
DEPENDABLY_TOKEN = "dpb_xxx"
```

### Gemini CLI

Edit `~/.gemini/settings.json` (or your project's `.gemini/settings.json`):

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

14 tools. Every one is read-only, none reads a local file, and every one is reachable with a
**Pull** token — the preset any member can mint for themselves.

| Tool | What it does |
|---|---|
| `list_packages` | Paginated inventory, with ecosystem and search filters. |
| `get_package` | One package: versions, SPDX licences, vulnerability links. |
| `search_packages` | Quick name search across the registry. |
| `list_vulnerabilities` | Org-wide report of every affected package. |
| `get_vulnerability` | Full advisory detail, including remediation guidance. |
| `check_dependencies` | Scopes that report to one project's dependency list and names the version to bump to. |
| `get_remediation` | Fixed versions for up to 200 advisories at once, without the prose. |
| `lookup_package` | Pre-adoption verdict on a package not in the registry. Ingests nothing. |
| `get_license_policy` | Enforcement mode, plus the SPDX allowlist and blocklist. |
| `list_remediation_skills`, `get_remediation_skill` | Curated how-to-fix guides, one per vulnerability class. |
| `readiness_check` | Readiness with per-subsystem detail; needs no token. |
| `get_install_command`, `get_publish_command` | Build an install or publish command, returned as text. |

Ecosystems: npm, pypi, nuget, maven, rpm, oci, golang, cargo, apk, terraform, hex — `lookup_package`
and the two setup tools cover narrower sets, which their tool descriptions name.

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
