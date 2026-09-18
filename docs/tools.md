# Tool reference

Every tool this server registers, the group it belongs to, and the capability your token needs
to call it. The [README](../README.md) covers install, configuration and troubleshooting.

15 tools in three groups. Every one is read-only, none reads a local file, and every one is
reachable with a **Pull** token — the preset any member can mint.

## Read

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
| `lookup_package` | Pre-adoption verdict on a package that is not in the registry: upstream metadata, OSV and org policy. Ingests nothing. Takes a narrower ecosystem set than the tools above — see below. | `read:packages` |
| `get_license_policy` | Enforcement mode plus the SPDX allowlist and blocklist, so you can see which licences are approved. | `read:packages` |
| `list_remediation_skills` | Index of every curated remediation skill the instance ships — one per vulnerability class (vulnerable dependency, injection, XSS, path traversal, unsafe deserialization, SSRF, broken access control, weak cryptography, authentication failures). | none, anonymous |
| `get_remediation_skill` | Full how-to-fix guide for one or more skill ids, as markdown. Ids come from `list_remediation_skills` or from the `skills` field `get_remediation`/`check_dependencies` return. | none, anonymous |

### Ecosystems, and why the sets differ

The registry tools — `list_packages`, `get_package`, `list_vulnerabilities` and
`check_dependencies` — take **npm, pypi, nuget, maven, rpm, oci, golang, cargo, apk, terraform,
hex**: everything the registry plane serves.

`lookup_package` takes a narrower set — **npm, pypi, nuget, maven, golang, cargo, hex**. A
pre-adoption verdict has to resolve the candidate against an upstream, and rpm, oci, apk and
terraform have no single canonical upstream to ask. The server enforces this and answers anything
outside the set with `422 Must be one of: …`.

Go is spelled **`golang`**, not `go`. The registry endpoints do not validate this parameter — they
treat it as a filter — so `go` would come back `200` with no results rather than as an error.

### Passing a dependency list to `check_dependencies`

Reach for this one when the question is about a project rather than the whole org. It takes the
dependency list as an argument, `packages`, an array of `{name, version, dev}`, and reads no
files itself. For an npm `package-lock.json` (v2 or v3) the argument is every entry of its
`packages` map: read the lockfile with whatever file access you already have and pass the result.

A `lockfileVersion` 1 lockfile has no `packages` map and is refused with a message naming the
fix. Run `npm install` with npm 7 or later to upgrade it, or build the list yourself.

## Observability

| Tool | What it does | Capability |
|---|---|---|
| `health_check` | Liveness (`GET /health`). | none, anonymous |
| `readiness_check` | Readiness plus per-subsystem checks (`GET /ready`). | none, anonymous |

Both are anonymous, so they answer without a token and from any machine. `readiness_check` is the
one to reach for first when triaging an incident: it names the subsystem reporting degraded.

The server's `/version` and `/metrics` endpoints are not wrapped as tools.

`/metrics` is the stronger reason: a live instance answers it with well over a megabyte of
Prometheus text, which is larger than most model context windows. No agent can usefully read it,
and returning it truncated would be worse than not offering it at all. Scrape it with Prometheus,
which is what it is for.

Both are also operator surfaces rather than agent surfaces, and `METRICS_ALLOWED_IPS` defaults to
loopback — so on a correctly configured instance a remote caller gets `403`. Treat that as the
intended posture rather than a guarantee: an instance behind a reverse proxy that forwards no
`X-Forwarded-For` presents every caller as the proxy's own address, and if that address is in the
allowlist the endpoint is open to anyone who can reach it. If you need to know, ask the endpoint
from off-network rather than assuming.

## Setup

Both build a shell command and return it as text. Neither executes anything, and neither calls
the server, which keeps this server from shelling out to `npm`, `pip` or `dotnet` with your
network and filesystem access.

| Tool | What it does | Capability |
|---|---|---|
| `get_install_command` | Builds the install command for an ecosystem. | none, runs locally |
| `get_publish_command` | Builds the publish command for an ecosystem. | none, runs locally |

Both cover eight ecosystems: npm, PyPI, NuGet, Maven, RPM, OCI, Go and Cargo — bounded by the
commands they know how to write, not by what the registry serves. Go is served
through the standard module proxy protocol, so `get_install_command` works and modules are
published the Go way, by tagging a release in source. `get_publish_command` returns that
guidance for Go rather than a command.

## Choosing capabilities for a token

One preset covers the whole server: **Pull** (`read:metadata`, `read:artifact`,
`read:packages`). Any member can mint it, including one with no admin rights.

That is the point of the surface being this size. A token never carries more than the role of the
person who minted it, so anything needing `read:audit` or `read:tenant` has to be issued by an
admin or owner — which turns "install the extension" into a request to somebody else. Every tool
here stays inside what a developer can grant themselves.

The 4 observability and setup tools need no token at all, and neither do the 2 remediation-skill
tools — they serve static, curated content that is identical for every tenant.

The audit surface (the org activity feed, auth events, SIEM vulnerability counts) is deliberately
**not** here. Those endpoints exist on the instance and are reachable with an Audit token; read
them in the web UI, or with your own client.

This server never needs `publish:*` or `yank:*`. It reads; publishing and pulling packages are
done by your package manager with its own token.

Any tool whose capability the token lacks returns a `403` naming what is missing.
