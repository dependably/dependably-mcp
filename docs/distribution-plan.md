# Distribution plan: Claude Desktop extension and other harnesses

Status: approved 2026-09-02. Supersedes the plan drafted in the (now redundant)
`dependably-claude-connector` directory; the connector lives in this repository.

Progress 2026-09-12: M1 steps 1 to 3 done and the bundle verifies; M2 steps 1 and 3 done
(actionable reachability errors, private-CA file setting); M3 step 1 done (bundle attached to
GitLab and GitHub releases). Open decision 1 resolved by dropping the two probes. What remains is
tracked in `docs/listing.md`, which is the pre-submission checklist.

Progress 2026-09-19: corrected §3's stale tool count (18 → 15) and manifest-spec claim, rewrote
§4's tool surface to the current 15 tools in three groups and dropped the prompts/resources/
roadmap bullets the 242e1de refactor rejected, dropped the unverifiable 150,000-character and
300 s numbers, and updated §7's open-source-clause and reviewer-test-account decisions to match
Anthropic's current review-criteria page (required and not waivable; a universal submission
requirement, not verified-tier only).

## 1. Goal

Let a Claude Desktop user open **Settings → Extensions**, find **Dependably**, install it, paste the
URL of their own Dependably instance plus a personal access token, and immediately ask Claude things
like "which of our npm packages have a critical vulnerability?" or "is `left-pad@1.3.0` safe to
adopt under our licence policy?". Then list the extension in Anthropic's Connectors Directory.

The same server must keep working, unchanged, in every other MCP harness: Claude Code, Cursor,
Windsurf, VS Code, Zed, Codex CLI, Gemini CLI, and anything else that speaks stdio MCP.

## 2. One server, several channels

`dependably-mcp` is the harness-neutral product. Nothing in `src/` knows which client is on the
other end of stdio, and that stays true. Each harness gets a packaging or an install snippet, never a
code path.

| Channel | Serves | Artefact | Status |
|---|---|---|---|
| **npm package** `dependably-mcp` | Every harness via `npx -y dependably-mcp` or a global install: Claude Code, Cursor, Windsurf, VS Code, Zed, Codex CLI, Gemini CLI, custom agents | npm tarball with provenance | Pipeline exists; the public npm publish has never actually run (README claims otherwise). M0 fixes that. |
| **Claude Desktop extension** | Claude Desktop users who want a config dialog and keychain-stored token instead of editing JSON | `dependably-<version>.mcpb` | This plan, M1 to M3 |
| **Official MCP Registry** (`registry.modelcontextprotocol.io`) | Harness-neutral discovery; Cursor, VS Code, Codex and others read it | `server.json` in the repo, published with `mcp-publisher` | M4 |
| **Per-harness install snippets** | Copy-paste config for each client, kept in the README | none | M2 (docs) |
| **Docker MCP catalogue / Cursor one-click deeplinks** | Convenience | Dockerfile or deeplink | Later, if asked for |

Rule of thumb: a channel may add files at the repo root (`manifest.json`, `server.json`,
`Dockerfile`) and scripts under `scripts/`, but never a `src/` branch on client identity. If a
client needs different behaviour, express it as a documented environment variable that any client
could set.

## 3. Facts that shape the plan

Verified 2026-09-02 against `dependably-community`, this repository, and Anthropic's connector
documentation.

**Dependably**

- Self-hosted or hosted SaaS (e.g. `dependably.ca`) — corrected 2026-09-16, this doc previously said
  "self-hosted only". Both deployment modes resolve tenancy from the Host header and use the same
  auth, so a client needs exactly one thing per user regardless of mode: a base URL.
- Not an OAuth provider. Auth is a 44-character opaque personal access token as
  `Authorization: Bearer`, plus SAML for browser SSO. This rules out Anthropic's remote-connector
  path without server-side work; see Appendix A.
- Management API is `/api/v1/*`, contract-tested against `tests/Contracts/openapi.contract.json` in
  `dependably-community`. The management OpenAPI document is loopback-and-JWT gated, so a token
  cannot fetch it at runtime.
- About 300 requests per minute per principal, immediate 429 with `Retry-After`.
- Nine OWASP-mapped remediation skills are served anonymously as Markdown at
  `GET /api/v1/remediation/skills`; nothing exposes them over MCP yet.
- Prose is Canadian English per `dependably-community/i18n/glossary.md`: `licence` the noun,
  `license` the verb, `artefact`, `behaviour`, but `-ize`. Machine-readable literals keep `license`.
  The product is capitalized **Dependably** in prose.

**This repository**

- TypeScript, ESM, `@modelcontextprotocol/sdk` 1.30, 15 tools in four modules, each with `title`
  and read-only annotations. Every tool is reachable with a Pull token. Stdio only. Four environment variables.
- Strong client layer: RFC 7807 parsing, capability-name extraction on 403, `Retry-After` on 429.
- No prompts or resources. One smoke test, no HTTP-mocked unit tests.
- `main` is one commit behind the unmerged `chore/npmrc-hygiene` branch.
- The server's `/version` and `/metrics` endpoints are allowlisted to the Dependably host, so
  they are not wrapped as tools.

**Anthropic**

- Bundles are `.mcpb` (renamed from `.dxt`; old files still open). Manifest spec 0.3 is current
  for a Node bundle; 0.4 only adds the `uv` runtime. CLI `@anthropic-ai/mcpb` 2.1.2. Node is the
  recommended runtime because Claude Desktop ships one.
  Platforms `darwin` and `win32`. Signing is optional, and `mcpb sign` currently produces bundles
  Desktop rejects (mcpb issue #278, open since 2026-06-12); ship unsigned with checksums.
- The directory lists remote servers, desktop extensions, and MCP Apps. Remote is preferred; MCPB
  is "the secondary distribution path" and is submitted through a Google Form
  (`clau.de/desktop-extention-submission`). The remote portal needs a Team or Enterprise org.
- Hard listing requirements: privacy-policy URL (missing means immediate rejection), verified
  support contact, public docs, three working example prompts, icon, one to five categories,
  tagline (55 chars) and description (2000 chars).
- Review criteria: `title` plus a read-only or destructive annotation on every tool; separate read
  and write tools; no catch-all request tool; descriptions that do not steer Claude; actionable
  errors, never a bare "Internal Server Error".
- Limits: not stated in current docs as fixed numbers — the guidance as of 2026-09-19 is
  qualitative ("keep responses reasonably sized for the task"); no resource subscriptions or
  sampling. MCP spec 2026-07-28 and SDK v2 exist, but which Claude surfaces run them is unstated,
  so this repository stays on SDK 1.x for now.

## 4. The extension

A `.mcpb` bundle built from this repository at the same commit as the npm release. The manifest
points at `dist/index.js`; `user_config` collects the base URL, a keychain-stored token, a timeout,
and maps them onto the remaining environment variables. No new
code path: the bundle is `npm ci --omit=dev` plus `dist/` plus `manifest.json` plus an icon.

`manifest.json` lives at the repo root because that is where `mcpb pack` expects it. Its `tools[]`
is generated from the running server by `scripts/sync-manifest.mjs`, and `npm test` fails when the
manifest is stale. `.mcpbignore` keeps `src/`, tests, docs and dev tooling out of the bundle; the
`files` whitelist in `package.json` keeps bundle assets out of the npm tarball.

### Tool surface

All 15 tools ship in the manifest and are static: none is generated at runtime, and
`tools_generated` is `false`.

| Group | Tools | Notes |
|---|---|---|
| Read | `list_packages`, `get_package`, `search_packages`, `lookup_package`, `list_vulnerabilities`, `get_vulnerability`, `get_license_policy`, `check_dependencies`, `get_remediation`, `list_remediation_skills`, `get_remediation_skill` | read-only |
| Observability | `health_check`, `readiness_check` | both anonymous, and they answer from any host |
| Setup | `get_install_command`, `get_publish_command` | local, never execute |

Prompts, resources, and the roadmap read tools once sketched here (org stats, audit log, org
settings, quarantine list, and similar) are not planned; the 242e1de refactor rejected them and
removed the audit- and admin-scoped tools that would have backed them. The surface stays the 15
tools above, all reachable with a Pull token.

## 5. Milestones

### M0 — Housekeeping (blocks submission, not the build)

1. Resolve `chore/npmrc-hygiene`: merge or drop, so the bundle work sits on `main`.
2. Run the public npm publish for real and fix the README's install claim.
3. `dependably-www`: publish `/privacy` and `/support`; confirm a monitored support address.
4. Decide the publisher identity (Moonlit Labs or Dependably) and the permanent `dependably` slug.

### M1 — Bundle builds and validates

1. `manifest.json`, `.mcpbignore`, `assets/` icons from the brand kit.
2. `scripts/sync-manifest.mjs` (generate and `--check`), wired into `npm test`.
3. `scripts/bundle.mjs`: stage `dist/`, `package.json`, lockfile, manifest, assets and licence into
   `build/mcpb/`, `npm ci --omit=dev --ignore-scripts` there, `mcpb validate`, `mcpb pack`, write a
   SHA-256 beside the bundle.
4. Install on this Mac by drag-and-drop against the local `demo.localhost:8080` instance; run
   `list_packages` and `list_vulnerabilities`.
5. Confirm how Desktop substitutes an unset optional `directory` field. `loadConfig` treats an empty
   string as unset; if Desktop passes the literal placeholder instead, add a guard.

Exit: a fresh Desktop install completes with only the config dialog; every read tool returns data.

### M2 — Review-readiness and docs for every harness

1. Walk Anthropic's review criteria tool by tool. Add a first-run reachability check that turns a
   bad base URL into "could not reach `<url>`: reason" instead of a stack trace.
2. Prompts, resources and roadmap read tools, with HTTP-mocked unit tests (`undici` `MockAgent`).
3. Self-signed TLS on internal hosts: a CA-bundle file setting or documented `NODE_EXTRA_CA_CERTS`,
   never a "disable verification" switch.
4. Windows pass: install, import-tool path handling, keychain storage of the token.
5. README: one install section per harness (Claude Desktop extension, Claude Code, Cursor,
   Windsurf, VS Code, Zed, Codex CLI, Gemini CLI), all using the same four environment variables.
   Mirror into `dependably-documentation/docs/en/integrations/claude.md` and dependably.ca.
6. Listing pack: three to five screenshots at 1000 px or wider, tagline, description, categories,
   three example prompts verified against a live instance.
7. Security pass: `@dependably/npm-check` audit, CycloneDX SBOM in CI, confirm the token is never
   logged, confirm the bundle contains no dev dependencies.

### M3 — Release and submit

1. Extend `.gitlab-ci.yml` and `.github/workflows/ci.yml`: the `build` job also runs `npm run bundle`
   and keeps the `.mcpb` and checksum as artefacts; the tag-driven release attaches them to the
   GitLab release and the public GitHub release alongside the npm publish.
2. Submit through the MCPB form with the listing pack; log the date, contact and reviewer
   correspondence in `docs/submission-log.md`.
3. Post-publish tool changes need no re-review; manifest or listing changes do. Each npm release
   ships a matching bundle from the same tag.

### M4 — Official MCP Registry

1. Add `server.json` (name `io.github.dependably/dependably-mcp` or the GitLab-namespaced form,
   packages entry pointing at the npm package with the four environment variables declared).
2. Publish with `mcp-publisher` from the release job so Cursor, VS Code and other registry-reading
   clients discover the server without an Anthropic listing.

## 6. Testing

| Layer | What | Where |
|---|---|---|
| Manifest | `mcpb validate`; `tools[]` matches the live server list | `scripts/sync-manifest.mjs --check` in `npm test` |
| Bundle | unpack the packed bundle, spawn `dist/index.js` with the env the manifest would produce, run initialize and tools/list | `scripts/bundle.mjs --verify` |
| Server | HTTP-mocked unit tests per tool, RFC 7807 paths, 429 with `Retry-After`, import path containment | `test/` (M2) |
| Contract | read tools against a real Dependably container in CI, diffed against the OpenAPI contract file | integration job (M2) |
| Desktop | manual runbook per release on macOS and Windows | `docs/desktop-e2e.md` (M1) |

## 7. Open decisions

1. **`get_version` and `get_prometheus_metrics`.** Resolved: both tools are removed, and the
   `DEPENDABLY_TOOLSET` switch that used to hide them with them. The endpoints they wrapped are
   allowlisted to the Dependably host, so the tools failed for every client not running on it.
   Read `/version` and `/metrics` on the host, or scrape `/metrics` with Prometheus.
2. **Reviewer access.** Test credentials are a universal submission requirement, not a
   verified-tier concern — every submission needs a fully populated test account for Anthropic to
   exercise every tool. A public demo instance with a scoped read-only token is the cleanest
   answer and also serves marketing.
3. **Community tier.** Community is the default label; escalation to verified is automatic and
   assessed by Anthropic, not a developer choice. MCPB listings may stay in the Community tier;
   org-scoped installs by Team and Enterprise admins do not depend on the tier.
4. **Open-source clause.** Relicensed from Apache-2.0 to MIT, which is on Anthropic's
   required-licence list for the submission form. The clause itself is required and not
   waivable: the GitHub mirror must be public before submission, not moot either way.
5. **Publisher identity and slug.** Permanent; decide before the first submission.
6. **Capability guidance.** The config dialog cannot validate token capabilities, and no tool
   reports which tools a token reaches — `read:packages` is the floor, and a missing capability
   surfaces only as a 403 on the tool that needed it.

## Appendix A — Notes for a future remote connector (not planned)

A remote listing would need, inside `dependably-community`: `/mcp` over Streamable HTTP; an OAuth
2.1 authorization server over existing tokens (authorization code + PKCE, RFC 9728 protected-resource
metadata with `resource` matching the URL exactly, RFC 8414 discovery, Client ID Metadata Document
support, refresh-token rotation, `aud` bound to the instance URL); a 401 with
`WWW-Authenticate: Bearer resource_metadata=…` on unauthenticated calls; discovery, registration and
token endpoints answering within 10 s. On Anthropic's side it would need the `custom_connection`
auth type (enabled per partner on request) and a Team or Enterprise org to submit through the
portal. A hosted middleman — anything other than Dependably itself sitting between the user and
their instance, holding tokens behind OAuth — was considered and rejected: it moves customer
registry credentials into a third party's hands. That reasoning holds regardless of self-hosted vs.
SaaS: the SaaS instance is not an OAuth provider either, so a remote listing needs the OAuth 2.1
work above built into `dependably-community` itself, not routed around it.
