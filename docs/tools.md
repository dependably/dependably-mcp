# Tool reference

Every tool this server registers, the group it belongs to, and the capability your token needs
to call it. The [README](../README.md) covers install, configuration and troubleshooting.

19 tools in four groups. Every one is read-only, and none of them reads a local file.

## Read

Package inventory, vulnerabilities, licence policy and identity.

| Tool | What it does | Capability |
|---|---|---|
| `list_packages` | Paginated package inventory, with ecosystem and search filters. | `read:packages` |
| `get_package` | One package: versions, SPDX licence identifiers, vulnerability links. | `read:packages` |
| `search_packages` | Quick name search across the registry. | `read:packages` |
| `check_dependencies` | Scopes the org report to one project's dependency list and returns only what affects it, each package annotated with the version to bump to. | `read:packages` |
| `list_vulnerabilities` | Paginated org-wide report of affected packages, compact by default. | `read:packages` |
| `get_vulnerability` | Full advisory detail, including remediation guidance. | `read:packages` |
| `get_remediation` | Fixed versions for up to 200 advisories at once, without the advisory prose. | `read:packages` |
| `lookup_package` | Pre-adoption verdict on a package that is not in the registry: upstream metadata, OSV and org policy. Ingests nothing. | `read:packages` |
| `get_license_policy` | Enforcement mode plus the SPDX allowlist and blocklist, so you can see which licences are approved. | `read:packages` |
| `list_activity` | Org activity feed: publishes, yanks, policy changes. | `read:audit` |
| `whoami` | The identity behind the configured token. | `read:tenant` |
| `list_remediation_skills` | Index of every curated remediation skill the instance ships — one per vulnerability class (vulnerable dependency, injection, XSS, path traversal, unsafe deserialization, SSRF, broken access control, weak cryptography, authentication failures). | none, anonymous |
| `get_remediation_skill` | Full how-to-fix guide for one or more skill ids, as markdown. Ids come from `list_remediation_skills` or from the `skills` field `get_remediation`/`check_dependencies` return. | none, anonymous |

### Passing a dependency list to `check_dependencies`

Reach for this one when the question is about a project rather than the whole org. It takes the
dependency list as an argument, `packages`, an array of `{name, version, dev}`, and reads no
files itself. For an npm `package-lock.json` (v2 or v3) the argument is every entry of its
`packages` map: read the lockfile with whatever file access you already have and pass the result.

A `lockfileVersion` 1 lockfile has no `packages` map and is refused with a message naming the
fix. Run `npm install` with npm 7 or later to upgrade it, or build the list yourself.

## SIEM

| Tool | What it does | Capability |
|---|---|---|
| `siem_list_auth_events` | Login, lockout, token and RBAC auth events, with ISO-8601 since/until bounds and action-prefix filters. | `read:audit` |
| `siem_vulnerabilities_summary` | Severity-bucketed vulnerability counts by ecosystem. | `read:audit` |

## Observability

| Tool | What it does | Capability |
|---|---|---|
| `health_check` | Liveness (`GET /health`). | none, anonymous |
| `readiness_check` | Readiness plus per-subsystem checks (`GET /ready`). | none, anonymous |

Both are anonymous, so they answer without a token and from any machine. `readiness_check` is the
one to reach for first when triaging an incident: it names the subsystem reporting degraded.

The server's `/version` and `/metrics` endpoints are not wrapped as tools. Dependably allowlists
both to its own host, so a tool for either would fail for every client not running on it. Read
them directly on the host, or scrape `/metrics` with Prometheus.

## Setup

Both build a shell command and return it as text. Neither executes anything, and neither calls
the server, which keeps this server from shelling out to `npm`, `pip` or `dotnet` with your
network and filesystem access.

| Tool | What it does | Capability |
|---|---|---|
| `get_install_command` | Builds the install command for an ecosystem. | none, runs locally |
| `get_publish_command` | Builds the publish command for an ecosystem. | none, runs locally |

Both cover eight ecosystems: npm, PyPI, NuGet, Maven, RPM, OCI, Go and Cargo. Go is served
through the standard module proxy protocol, so `get_install_command` works and modules are
published the Go way, by tagging a release in source. `get_publish_command` returns that
guidance for Go rather than a command.

## Choosing capabilities for a token

The Tokens screen offers presets rather than raw capability strings. Three of them matter here:

| Preset | Capabilities it mints | Tools it covers | Who can mint it |
|---|---|---|---|
| Pull | `read:metadata`, `read:artifact`, `read:packages` | The 9 `read:packages` tools above | Anyone, including a member |
| Audit | `read:audit` | `list_activity`, `siem_list_auth_events`, `siem_vulnerabilities_summary` | An admin or owner |
| Admin | `tenant:configure`, `read:tenant` | `whoami` | An admin or owner |

**Pull is the one to start with.** It is read-only, any member can create it, and it drives the
whole developer read surface: inventory, search, package detail, vulnerability reports,
remediation versions, pre-adoption lookups and licence policy.

A token never carries more than the role of the person who minted it. A member's role tops out at
the read leaves above, so Audit and Admin tokens come from an admin or owner. Ask whoever
administers your instance if you need one, rather than looking for a checkbox that is not there.

The 4 observability and setup tools need no token at all, and neither do the 2 remediation-skill
tools — they serve static, curated content that is identical for every tenant.

This server never needs `publish:*` or `yank:*`. It reads; publishing and pulling packages are
done by your package manager with its own token.

Any tool whose capability the token lacks returns a `403` naming what is missing.
