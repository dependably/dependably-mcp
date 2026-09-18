# Directory listing pack: Dependably for Claude Desktop

The text, links and checks Anthropic asks for when a desktop extension is submitted to the
directory, kept here so a resubmission is a copy-and-paste and a review can be traced. Policy
source: the Anthropic Software Directory Policy (support.claude.com article 13145358) and the
desktop-extension submission notes (anthropic.com/engineering/desktop-extensions), re-read
2026-09-12. Spelling in user-facing text is Canadian English; tool names, SPDX fields and API
literals keep their exact spelling.

## 1. Listing fields

| Field | Value |
|---|---|
| Name | Dependably |
| Publisher | Moonlit Labs (author of record: Michael Hiland) — confirm before the first submission; the slug `dependably` is permanent |
| Tagline (55 characters max) | `Ask Claude about your Dependably package registry` (49) |
| Categories (one to five) | Developer Tools; Security; IT Operations — map to the nearest names the form offers |
| Icon | `assets/icon.png` (512 × 512, light) and `assets/icon-dark.png` (dark) |
| Bundle | `dist-mcpb/dependably-<version>.mcpb` from the tagged release, with `.sha256` |
| Privacy policy | <https://dependably.ca/privacy> (live) |
| Support | <https://dependably.ca/contact> (live) and `support@dependably.ca` (monitored) |
| Documentation | <https://github.com/dependably/dependably-mcp#readme> (see checklist: mirror not yet public) |
| Source | <https://github.com/dependably/dependably-mcp> (MIT) |
| Platforms tested | macOS (this Mac, Claude Desktop 1.49585.0); Windows pending (see checklist) |

### Description (2000 characters max)

> Dependably is a private artefact repository and pull-through proxy for npm, PyPI, NuGet, Maven,
> RPM, OCI, Go and Cargo, self-hosted or as a hosted SaaS instance. This extension connects Claude
> to your own Dependably instance using a personal access token you create in Dependably.
>
> With it, Claude can list and search your packages, explain a vulnerability and its remediation,
> check a package against your licence policy before you adopt it, review the org activity feed
> and authentication events, and produce the exact install or publish commands for each
> ecosystem. Every tool is read-only, so nothing the server offers can change or delete anything
> in your registry.
>
> All traffic goes directly from your machine to your Dependably instance. Nothing is sent
> anywhere else, and the token is stored in your operating system's keychain. Instances behind
> a private certificate authority are supported through an optional CA bundle setting; there is
> no option to disable certificate verification.
>
> Requires Dependably v0.3.0 or later and a token with `read:packages` (add `read:audit` for the
> activity and authentication tools).

That is 1,146 characters, matching `long_description` in `manifest.json` plus the last two
paragraphs. Keep the two in step.

## 2. Example prompts

The directory requires at least three working prompts. Each one below names the tools it drives
and the token capability it needs, so a reviewer with the test account can reproduce it.

| # | Prompt | Tools | Needs |
|---|---|---|---|
| 1 | "Which of our npm packages have a critical vulnerability, and what is the fix for the worst one?" | `list_vulnerabilities` → `get_vulnerability` | `read:packages` |
| 2 | "Is `lodash@4.17.21` acceptable under our licence policy? Do not add it, just check." | `lookup_package`, `get_license_policy` | `read:packages` |
| 3 | "Show me failed logins and lockouts in the last 24 hours." | `siem_list_auth_events` | `read:audit` |
| 4 | "Give me the pip install command for `requests` through our registry." | `get_install_command` | none (local) |
| 5 | "Is the registry healthy right now? Which subsystem is degraded, if any?" | `readiness_check`, `health_check` | none |

Verification status: the prompts are checked against the tool schemas and the smoke test. They
still have to be run once against a live instance through the installed extension, which is step
5 of `docs/desktop-e2e.md`; record the date and instance in §6 when done.

## 3. Test account for Anthropic

The policy requires "a standard testing account with sample data" so the reviewer can exercise
every tool. Plan:

1. A public demo instance of Dependably seeded with a few packages per ecosystem, at least one
   package with a known advisory, and a licence policy in `warn` mode. Reuse the marketing demo
   if one exists; otherwise a small instance under `demo.dependably.ca`.
2. A dedicated user in that org with a personal access token carrying `read:packages` and
   `read:audit`, which covers every tool the server registers.
3. Rotate the token after the review; note the rotation date in §6.
4. Give the reviewer: the instance URL, the token, and the five prompts above.

## 4. Screenshots (three to five, at least 1000 px wide)

Take them from the installed extension on macOS in light mode, then crop to the conversation.

1. The install dialog with the four settings visible (token field masked).
2. Prompt 1: the vulnerability list followed by the remediation for one advisory.
3. Prompt 2: the pre-adoption licence verdict.
4. Prompt 3: the authentication events table.
5. The tool list in Claude Desktop, showing all 18 tools marked read-only.

## 5. Pre-submission checklist

Status as of 2026-09-12. "Repo" items are done on branch `feat/mcpb-bundle`; "external" items
need something outside this repository.

| # | Item | Status | Where |
|---|---|---|---|
| 1 | Manifest validates (`mcpb validate`), bundle packs and boots (`npm run bundle:verify`) | done | `scripts/bundle.mjs` |
| 2 | Every tool has `title`, `readOnlyHint`, `destructiveHint`; read and write tools are separate; no catch-all tool | done | `src/tools/*.ts` |
| 3 | Tools that can never succeed off-host are not offered to Desktop users | done | the `/version` and `/metrics` probes are not registered at all; `src/tools/observability.ts` |
| 4 | Errors are actionable: 401/403/429/5xx wording, and transport failures name the URL, cause and setting | done | `src/client.ts`, asserted in `scripts/smoke.mjs` |
| 5 | Private-CA instances supported without disabling verification | done | `ca_bundle` → `NODE_EXTRA_CA_CERTS` |
| 6 | Privacy policy URL live | done | <https://dependably.ca/privacy> |
| 7 | Support URL live and address monitored | done | <https://dependably.ca/contact>, `support@dependably.ca` |
| 8 | Bundle and checksum attached to each tagged release | done (pipeline) | `.gitlab-ci.yml` `release`, `.github/workflows/ci.yml` `release-bundle` |
| 9 | GitHub mirror `dependably/dependably-mcp` is public | **external, blocking** (repo created 2026-09-13, private for now; `publish:github` in `.gitlab-ci.yml` pushes to it) | `repository` and `documentation` in `manifest.json` (and `repository`, `bugs`, `homepage` in `package.json`) return 404 today; the GitHub workflow and npm provenance also depend on it |
| 10 | Public npm publish of the current version has run | **external, blocking** | first `vX.Y.Z` tag on the mirror; the README's install section assumes it |
| 11 | Install on macOS through the dialog only; `list_packages`, `list_vulnerabilities` | pending, this Mac | `docs/desktop-e2e.md` steps 1 to 5 |
| 12 | Same on Windows, including the CA-bundle file picker and keychain storage | **external, blocking** | `docs/desktop-e2e.md` |
| 13 | Five prompts run through the installed extension against a live instance | pending | §2, §6 |
| 14 | Test account and demo instance for the reviewer | **external, blocking** | §3 |
| 15 | Screenshots | pending, after 11 | §4 |
| 16 | Publisher identity and slug confirmed | **decision** | §1 |
| 17 | Privacy policy mentions the extension explicitly (data stays between the user's machine and their instance; no telemetry) | recommended | `dependably-www/content/legal/privacy-policy.md` |
| 18 | Version bump and CHANGELOG release section, tag, pipeline green, `.mcpb` attached | pending | release day |

Submission goes through the desktop-extension form linked from
<https://www.anthropic.com/engineering/desktop-extensions>; questions to `mcp-review@anthropic.com`.
Later tool changes need no re-review; manifest or listing text changes do.

## 6. Submission log

| Date | Version | Bundle SHA-256 | Action | Contact / outcome |
|---|---|---|---|---|
| | | | | |
