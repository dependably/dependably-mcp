# dependably-mcp

An MCP server that lets Claude, or any other Model Context Protocol client, query your
[Dependably](https://github.com/dependably/dependably-community) instance: package inventory,
vulnerabilities, projects, and package and licence policy.

Dependably is a private artefact repository, self-hosted or hosted. This server is read-only: it
runs over stdio with one personal access token, writes nothing to your instance or your
filesystem, and runs no commands.

## Requirements

- Node 22 or later.
- Dependably 0.12.2 or later. On 0.10.0 to 0.12.1 every tool works, but `get_policies` returns
  only the licence rules.
- A personal access token with the **Pull** preset, created in your instance under Tokens. Pull is
  read-only and any member can create it.

## Install

### Claude Code

```bash
claude mcp add dependably \
  --env DEPENDABLY_BASE_URL=https://dependably.example.com \
  --env DEPENDABLY_TOKEN=dpb_xxx \
  -- npx -y dependably-mcp
```

Or add it to `~/.claude.json` or your project's `.mcp.json`:

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

To install it once instead, run `npm install -g dependably-mcp` and use `dependably-mcp` as the
command in place of `npx -y dependably-mcp`.

### Claude Desktop

Download `dependably-<version>.mcpb` and its `.sha256` from the project's releases, and check
the bundle with `shasum -a 256 -c dependably-<version>.mcpb.sha256`. Double-click it, or drag it
onto **Settings > Extensions**.

The install dialog asks for your Dependably URL and token, and stores the token in your
operating system's keychain. An optional field takes a CA bundle for an instance whose
certificate comes from a private certificate authority.

## Verify

Restart your client and ask Claude to run:

1. `readiness_check`. It needs no token, so an answer confirms the URL and that the instance is
   reachable. `ready` or `degraded` means it can serve; `unready` names the failing dependency.
2. `list_packages`. Any result, even an empty list, confirms your token works.

If a call fails, the error names the setting to check: `DEPENDABLY_BASE_URL` when the instance
can't be reached, `DEPENDABLY_TOKEN` on a 401, and `NODE_EXTRA_CA_CERTS` when the certificate
can't be verified.

## Example prompts

Each works with a Pull token. The tool Claude uses is in brackets.

- *Which of our packages have critical vulnerabilities, and are any known to be exploited (CISA
  KEV)?* (`list_vulnerabilities`)
- *Here's my `package-lock.json`. Is anything vulnerable, and what should I bump to?*
  (`check_dependencies`, then `get_remediation`.) Claude reads the lockfile and passes the
  resolved versions; the server reads no files. A dependency listed as unverified was not
  checked: give its exact version, or ask Claude to check it with `lookup_package`.
- *Would our policy allow `log4j-core` 2.14.1?* (`lookup_package`, which checks a version
  against live advisory data and your policy without adding it to the registry)
- *What's our policy for third-party packages?* (`get_policies`)
- *Which projects are failing policy, and what's wrong with the latest build of the worst one?*
  (`list_projects`, then `get_project_version`)
- *Explain the most severe advisory affecting our Django packages, and how to fix it.*
  (`list_vulnerabilities`, `get_vulnerability`, then `get_remediation_skill`)
- *Give me the command to install `requests` 2.32.4 through our registry.*
  (`get_install_command`)

## Configure

The server reads its configuration from environment variables set by your MCP client.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DEPENDABLY_BASE_URL` | yes | | Base URL of your instance, such as `https://dependably.example.com`. Your organization comes from the host, so no org slug is needed. |
| `DEPENDABLY_TOKEN` | yes | | Personal access token, sent as a bearer token. |
| `DEPENDABLY_TIMEOUT_MS` | no | `30000` | Per-request timeout in milliseconds. The Claude Desktop extension always uses the default. |
| `NODE_EXTRA_CA_CERTS` | no | | Path to a PEM bundle, for an instance with a private or self-signed certificate. |

Plain `http://` works, for an instance on a network you trust; the token then travels
unencrypted. For HTTPS with a private certificate authority, set `NODE_EXTRA_CA_CERTS` (in Claude
Desktop, the CA bundle field). Certificate verification cannot be turned off.

## Tools

Every tool is read-only and works with a Pull token.

| Tool | What it does |
|---|---|
| `list_packages` | Paginated inventory, filtered by ecosystem or name. |
| `get_package` | One package: versions, SPDX licences, vulnerability links. |
| `search_packages` | Quick name search across the registry. |
| `list_vulnerabilities` | Every package in the registry affected by a known advisory. |
| `get_vulnerability` | One advisory: affected ranges, severity, KEV and EPSS, and how to fix it. |
| `check_dependencies` | Checks a project's resolved dependencies and names the version to bump to. Anything that could not be checked, such as a range instead of an exact version, is listed as unverified, never as clean. |
| `get_remediation` | Fixed versions for a batch of advisories. |
| `list_projects` | Projects and folders, searchable by name. |
| `get_project` | One project or folder: versions, ancestors, and a folder's children. |
| `get_project_version` | A version's SBOM components with their advisories and priority, plus the policy verdict. |
| `lookup_package` | Pre-adoption verdict on any package version, whether or not it is in the registry. Adds nothing to the registry. |
| `get_policies` | The whole package policy: licence rules plus every control that can refuse a download, with its setting. |
| `get_license_policy` | Licence rules only. |
| `list_remediation_skills`, `get_remediation_skill` | How-to-fix guides, one per vulnerability class. |
| `readiness_check` | Instance readiness, per dependency. Needs no token. |
| `get_install_command`, `get_publish_command` | An install or publish command for one package, returned as text for you to run. |

Each tool offers the ecosystems your instance reports at startup.

## Privacy Policy

This server connects only to the Dependably instance you configure, with the token you provide.
It collects no telemetry or usage data. It keeps your token in memory and never writes it to disk
or logs it. Claude Desktop stores the token in your operating system's keychain; with Claude
Code, the token sits in the config file you added it to, so keep it out of a project `.mcp.json`
you commit.

Tool results become part of your conversation with Claude and are handled under Anthropic's
policies. The full policy is at <https://dependably.ca/privacy>. Questions go to
[support@dependably.ca](mailto:support@dependably.ca).
