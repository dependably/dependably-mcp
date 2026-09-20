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
| Tagline (55 characters max) | `Ask Claude about your Dependably registry` (41) |
| Categories (one to five) | Developer Tools; Security; IT Operations — map to the nearest names the form offers |
| Icon | `assets/icon.png` (512 × 512, light) and `assets/icon-dark.png` (dark) |
| Bundle | `dist-mcpb/dependably-<version>.mcpb` from the tagged release, with `.sha256` |
| Privacy policy | <https://dependably.ca/privacy> (live) |
| Support | <https://dependably.ca/contact> (live) and `support@dependably.ca` (monitored) |
| Documentation | <https://github.com/dependably/dependably-mcp#readme> (mirror is private until release day; this link 404s until then) |
| Source | <https://github.com/dependably/dependably-mcp> (MIT; private until release day, see §5 item 9) |
| Platforms tested | macOS pending, Windows pending (see checklist item 11 and 12) |

### Description (2000 characters max)

> Dependably is a private artefact repository and pull-through proxy for npm, PyPI, NuGet, Maven,
> RPM, OCI, Go and Cargo, self-hosted or run as a hosted SaaS instance. This extension connects
> Claude to your own instance with a personal access token you create there.
>
> With it, Claude can list and search your packages, look up a package before you adopt it, and
> explain an advisory and its fix. It can also scope your vulnerability report to one project's
> lockfile with the version to bump to, check a licence against your policy, and write the
> install or publish command for any of the eight ecosystems. Two more tools check whether the
> registry itself is up and healthy. Every tool is read-only: none of them can change or delete
> anything in your registry.
>
> All traffic goes straight from your machine to your own Dependably instance, and nowhere else.
> Your token stays in your operating system's keychain. Instances behind a private certificate
> authority are supported through an optional CA bundle setting; there is no option to disable
> certificate verification.
>
> Requires Dependably v0.3.0 or later and a token with `read:packages` — the Pull preset, which
> any member can create.

That is 1,182 characters, and is the exact text of `long_description` in `manifest.json`. Keep
the two in step.

## 2. Example prompts

The directory requires at least three working prompts. Each one below names the tools it drives
and the token capability it needs, so a reviewer with the test account can reproduce it.

| # | Prompt | Tools | Needs |
|---|---|---|---|
| 1 | "Which of our npm packages have a critical CVE right now, and what version fixes the worst one?" | `list_vulnerabilities` → `get_remediation` | `read:packages` |
| 2 | "Can we use lodash 4.17.21? Don't add it, just tell me if it clears our licence policy." | `lookup_package`, `get_license_policy` | `read:packages` |
| 3 | "Here's our package-lock.json. What in here has a known vuln, and what do I bump it to?" | `check_dependencies` | `read:packages` |
| 4 | "What's the pip install command for requests through our registry?" | `get_install_command` | none (local) |
| 5 | "Is the registry up? And if something's degraded, which part?" | `health_check`, `readiness_check` | none |

Verification status: the prompts are checked against the tool schemas and the smoke test. They
still have to be run once against a live instance through the installed extension, which is step
5 of `docs/desktop-e2e.md`; record the date and instance in §6 when done.

## 3. Test account for Anthropic

The policy requires "a standard testing account with sample data" so the reviewer can exercise
every tool. Plan:

1. A public demo instance of Dependably seeded with a few packages per ecosystem, at least one
   package with a known advisory, and a licence policy in `warn` mode. Reuse the marketing demo
   if one exists; otherwise a small instance under `demo.dependably.ca`.
2. A dedicated user in that org with a personal access token carrying `read:packages` — the Pull
   preset — which covers every tool the server registers.
3. Rotate the token after the review; note the rotation date in §6.
4. Give the reviewer: the instance URL, the token, and the five prompts above.

## 4. Screenshots (three to five, at least 1000 px wide)

Take them from the installed extension on macOS in light mode, then crop to the conversation.

1. The install dialog with the four settings visible (token field masked).
2. Prompt 1: the vulnerability list followed by the remediation for one advisory.
3. Prompt 2: the pre-adoption licence verdict.
4. Prompt 3: the `check_dependencies` result, the package-lock.json scoped vulnerability report.
5. The tool list in Claude Desktop, showing all 15 tools marked read-only.

## 5. Pre-submission checklist

Status as of 2026-09-19. "Repo" items are done on branch `feat/mcpb-bundle`; "external" items
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
| 9 | GitHub mirror `dependably/dependably-mcp` is public, and the repository stays open source | **external, blocking, required and not waivable** (repo created 2026-09-13, private for now; `publish:github` in `.gitlab-ci.yml` pushes to it). The MCPB open-source clause has no exception path — see [review criteria](https://claude.com/docs/connectors/building/review-criteria) | `repository` and `documentation` in `manifest.json` (and `repository`, `bugs`, `homepage` in `package.json`) return 404 today; the GitHub workflow and npm provenance also depend on it |
| 10 | Public npm publish of the current version has run | **external, blocking** | first `vX.Y.Z` tag on the mirror; the README's install section assumes it |
| 11 | Install on macOS through the dialog only; `list_packages`, `list_vulnerabilities` | pending, this Mac | `docs/desktop-e2e.md` steps 1 to 5 |
| 12 | Same on Windows, including the CA-bundle file picker and keychain storage | **external, blocking** | `docs/desktop-e2e.md` |
| 13 | Five prompts run through the installed extension against a live instance | pending | §2, §6 |
| 14 | Test account and demo instance for the reviewer — required for every submission, not just the verified tier | **external, blocking** | §3 |
| 15 | Screenshots | pending, after 11 | §4 |
| 16 | Publisher identity and slug confirmed | **decision** | §1 |
| 17 | Privacy policy mentions the extension explicitly (data stays between the user's machine and their instance; no telemetry) | recommended | `dependably-www/content/legal/privacy-policy.md` |
| 18 | Version bump and CHANGELOG release section, tag, pipeline green, `.mcpb` attached | pending | release day |
| 19 | Pre-submission checklist read against the current [review criteria](https://claude.com/docs/connectors/building/review-criteria) page | pending | this table |

Submission goes through the desktop-extension form linked from
<https://www.anthropic.com/engineering/desktop-extensions>, following the steps on
[Submitting to the Connectors Directory](https://claude.com/docs/connectors/building/submission);
questions to `mcp-review@anthropic.com`. Later tool changes need no re-review; manifest or
listing text changes do.

## 6. Submission log

| Date | Version | Bundle SHA-256 | Action | Contact / outcome |
|---|---|---|---|---|
| | | | | |
