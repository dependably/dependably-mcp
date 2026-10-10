# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **NuGet prerelease labels compare without regard to case.** `1.0.0-RC1` is now newer than
  `1.0.0-beta2`, as NuGet.Versioning orders them, and `1.0.0-ALPHA` equals `1.0.0-alpha`. Before,
  uppercase sorted below lowercase, so a project on `1.0.0-beta2` could read as already past a
  fix in `1.0.0-RC1` while still vulnerable. NuGet also reads a prerelease number as a number
  only up to Int32, so longer digit runs now compare as text. npm, Cargo, Hex and Go keep their
  case-sensitive order.
- **SemVer prerelease identifiers are ordered the way SemVer 2.0 orders them.** A numeric
  identifier now ranks below an alphanumeric one (`1.0.0-1` < `1.0.0-alpha`), `1e2`, `0x10` and
  `0b1` are text rather than numbers, and numbers above 2^53 keep their order in both prerelease
  identifiers and release numbers instead of comparing equal. Before, an installed prerelease could read as already
  fixed when it was not, or the reverse.
- **Maven versions are ordered the way Maven orders them.** `1.0-sp1` is now newer than `1.0`,
  and `1.0.Final`, `1.0-ga` and `2.0.0.RELEASE` equal `1.0` and `2.0.0`, so Spring and
  Hibernate releases no longer get a bump recommended for a version that is already fixed. The
  comparison follows Maven's `ComparableVersion` (qualifiers `alpha` < `beta` < `milestone` <
  `rc` < `snapshot` < release < `sp`, with unknown qualifiers after them).

### Added

- **`check_dependencies` and `lookup_package` cover apk, rpm, oci and Terraform, and take a
  `distro`.** When the instance can look these up (a newer Dependably), they are checked like any
  other ecosystem, so a clean apk, rpm or image dependency can now come back `clean`. apk and rpm
  take an optional `distro` (`v3.20`, `Rocky Linux:9`, `Red Hat:enterprise_linux:9::baseos`); the
  instance infers the release from its upstreams when they all name the same one. An image is
  checked by its digest, an rpm by its full version-release and an apk by its `-rN` revision, and
  anything else is listed as unverified with that reason instead of being sent. A dependency whose
  advisory source was not consulted (no release, unreachable, no coverage, an image without a
  complete scan) is unverified with the reason, and the server's own message is shown when it
  rejects a lookup. Terraform has no advisory database, so its modules appear in the new
  `coverage.notApplicable` list: they do not block `clean` and are not counted in
  `summary.packagesChecked`. An older instance behaves as before.
- **`get_install_command` covers apk, Terraform and Hex,** and `get_publish_command` covers Hex.
  For apk and Terraform, which Dependably proxies but does not host, it says there is nothing to
  publish.

### Changed

- **`check_dependencies` requires `ecosystem`.** A call without it now fails. A pip list sent
  without one used to be checked as npm and came back clean. A blank name or version is rejected,
  and `summary.packagesChecked` counts the distinct dependencies that were actually checked.
- **A base URL with shell metacharacters in its host or path stops the server at startup.**
  `DEPENDABLY_BASE_URL` is pasted into the setup commands the server returns, so a URL that would
  change what a shell runs is refused rather than passed through. An IPv6 literal such as
  `http://[::1]:8080` is accepted.
- **`get_vulnerability` is compact by default.** It gives each affected range as `introduced` and
  `fixed` versions instead of listing every affected version, which ran to hundreds for some
  advisories. `verbosity: "full"` returns the raw OSV record.
- The README is shorter and gains example prompts and the minimum Dependably version (0.12.2).
  It drops two inaccuracies: a request-timeout field in the Claude Desktop install dialog, and
  audit events, which no tool reads. Tool descriptions that return upstream or advisory text now
  label it as third-party data.

### Fixed

- **rpm versions order `^` and `~` as rpm does.** A `^` (caret) post-release such as
  `1.0^20230101` now sorts after `1.0` and before `1.0.1`, where it used to compare equal to
  `1.0`, so a caret build could be taken as already fixed. A `~` after a separator (`1.0.~rc1`)
  is no longer skipped as one.
- **PyPI version ordering now follows PEP 440 in full.** `1!1.0` used to sort below `2.0` because
  the `1!` prefix was read as part of the release, and a version combining pre-release, post and
  dev parts (`1.0rc1.post1`, `1.0.post1.dev0`) or carrying a local label (`1.0+ubuntu1`) mis-sorted
  too, which mis-stated "already fixed" and the suggested upgrade target. Ordering is now a port
  of `packaging.version`: epoch, release, pre, post, dev, then local label, with its spelling
  rules (`alpha`/`a`, `c`/`rc`, `-1`/`.post1`, implicit zeros, any separator). Equal spellings such
  as `1.0` and `1.0.0` or `0!1.0` also join as one version when matching a report to your
  dependencies. A pypi string that is not valid PEP 440 keeps the previous ordering, and other
  ecosystems are unaffected.
- **Alpine (apk) versions are now ordered the way apk orders them.** `compare`, `gte` and
  `maxVersion` read an apk version with the generic semver rules, so `1.2.3-r4` sorted below
  `1.2.3`, `1.2.3-r4` above `1.2.3-r10`, and `1.2.3_rc1-r0` above `1.2.3-r0`. That skewed the
  "already fixed" check and the suggested upgrade version in `check_dependencies` and
  `get_remediation`. They now follow apk-tools' own comparison: `-rN` revisions are numeric,
  `_alpha`, `_beta`, `_pre` and `_rc` sort before the release, and `_cvs`, `_svn`, `_git`, `_hg`
  and `_p` sort after it. Checked against `apk version -t` on Alpine 3.22.
- **`get_install_command` no longer suggests a `.netrc` line pip cannot match for an IPv6 host.**
  For a base URL such as `http://[::1]:8443`, requests looks the entry up by the text before the
  first colon, so the bracketed `machine [::1]` line never matched and pip failed to authenticate
  without a warning. The pypi command now reads the token with `read -rs` and passes it in the
  index URL's userinfo, through `PIP_INDEX_URL` for that one command so it stays off pip's
  command line, and unsets it afterwards. IPv4 and DNS hosts, and Go, are unchanged.
- **`check_dependencies` no longer reports an npm dependency clean when the advisory endpoint
  skipped it.** The endpoint ignores a name over npm's 214-character limit, a version over 256
  characters, or either with a control character, and answers with no advisories; a name or
  version that is not valid text would fail its whole request. Such a
  dependency is now listed in `coverage.unverified` with the reason. A name over 512 characters is
  rejected in every ecosystem, and a long npm list is split across requests so none passes the
  endpoint's 4 MiB limit.
- **Compact `get_vulnerability` keeps the affected versions of an advisory that has no ranges.**
  Such an entry used to show an empty `ranges` list and only a `versionCount`. It now lists
  `versions`, up to 50, with `versionsTruncated` set when the list was cut. GIT ranges also keep
  their `repo`.
- **`check_dependencies` checks every dependency, not only versions your registry has served.**
  It used to report a vulnerable version as clean when the registry had never cached it
  (`lodash@4.17.20`, with two HIGH advisories). npm dependencies are now checked through the
  instance's bulk advisory endpoint, and other ecosystems through `/api/v1/lookup`, up to 100 per
  call. A malicious version is a critical finding. A new `coverage` block lists anything that
  could not be checked, and `clean` is never true while that list has entries. When the server
  returns each advisory's aliases and fixed version with the live answer, these findings get a
  `bumpTo` and fold aliases like any other, with no extra request per advisory. An ecosystem the
  instance cannot look up (rpm, apk, oci and terraform on an older Dependably) has no live
  source, so its dependencies the report does not flag are listed as unverified and `clean` is
  never true for it; the tool description says so. A newer Dependably looks all four up (see
  Added).
- **A range, tag or source spec is reported as unverified, not clean.** Pass exact resolved
  versions, as a lockfile records them. `^4.17.20`, `latest`, a Go branch or commit, a Maven or
  NuGet bracket range, a Gradle dynamic version, a PEP 440 specifier, or a `git+`/`file:` spec
  now lands in `coverage.unverified` with the reason. rpm and apk versions keep their `~` and `^`
  (`2.0~rc1`), which are exact there.
- **One flaw is counted once.** A PyPI flaw published as both a GHSA and a PYSEC record is shown
  once, with the other id in `aliases`, so totals and the "unknown" severity count are no longer
  doubled. Two advisories from the same database are never merged, so an incomplete-fix
  follow-up stays separate from the flaw it follows up.
- **Fixed-version lookups are capped** at the 200 most severe advisories per call. Beyond that, a
  `remediationNote` says how many were skipped, and a finding whose bump target may be low is
  marked `bumpToPartial`.
- **`readiness_check` shows why an instance is not ready.** On a 503 it returns the readiness
  body, naming the failing dependencies, instead of a generic server error.
- **Publish commands no longer put your token on the command line**, where it would land in shell
  history. PyPI, NuGet and Hex read it with `read -rs`; RPM lets `curl` prompt for it. The token
  goes to the one publish command and is unset afterwards, never exported, so later commands in
  the shell don't inherit it. NuGet's push takes the key only as `--api-key`, so it is visible to
  `ps` on your machine while the push runs.
- **`get_publish_command` uses the path you give it.** OCI loads the image tarball with
  `docker load` before tagging, Maven uploads the file with `deploy:deploy-file`, and Cargo
  publishes from the crate's directory.
- **Cargo and Hex publish from a directory whose name holds a dot.** `target/package/foo-0.1.0`,
  where `cargo package` leaves a crate, was read as a file, so the command pointed at its parent
  directory and could publish a different package. Only `Cargo.toml` and `mix.exs` are now taken
  to be a file in the directory.
- **Go install commands no longer bypass the proxy.** `GOPROXY` has no `,direct` fallback, and the
  wrong `GONOSUMDB` advice is gone.
- **pip's `.netrc` line names the host without its port,** which is how pip matches it. Go's keeps
  the port, which is how Go matches it.
- **An artefact path with control characters is refused,** so setup output cannot differ from
  what a shell runs.
- **`lookup_package` and `get_policies` say how a `blockedReason` maps to a policy control,** the
  `controls` key `get_policies` uses. Older servers spell it in PascalCase (`VulnScore` for
  `vuln_score`).

## [1.1.0] - 2026-09-23

### Added

- **`get_policies` returns the org's whole package policy.** It reads `GET /api/v1/policies`,
  which a Pull token can call, and returns the licence rules plus every control that can refuse
  a download: malicious packages, KEV and KEV ransomware, SSVC exploitation, CVSS and EPSS
  ceilings, release age, deprecated and revoked versions, install scripts and per-ecosystem
  signature checks, each with its effect and threshold. Asked *what is our policy for
  third-party packages?*, Claude used to reach only the licence policy and then wrongly say
  nothing covered vulnerabilities, package age or signatures. The tool's description carries
  the glossary the server leaves out, so a control that is off is reported as off rather than
  missing, a control whose data isn't refreshing is reported as still enforcing, and a signature
  check set to block with no trust anchor is flagged. An older server without the endpoint gets
  the licence policy, with a note that other controls may still apply.

### Changed

- **`get_license_policy` now says it covers licences only** and points to `get_policies` for
  the full package policy. Its title reads "Get licence policy"; the tool name is unchanged.

### Removed

- **The Claude Desktop extension no longer asks for a request timeout.** Each request uses the
  30-second default. `DEPENDABLY_TIMEOUT_MS` still works when the server is configured through
  environment variables.

### Fixed

- **An unreachable host no longer reports "Nothing is listening".** `EHOSTUNREACH` and
  `ENETUNREACH` mean the host couldn't be reached at all, not that nothing answered on the
  port. The error now says so, and points macOS users at the Local Network permission, which
  blocks an app from reaching an instance on the local network until it is granted.
- **The ecosystem list recovers when the instance was out of reach at startup.** The list is
  fetched once when the server starts. A network error or 5xx at that moment (for example, a
  desktop app launching the server just after install, before macOS allows it onto the local
  network) used to pin the built-in list until the next restart. It is now retried in the
  background (after 10 s, 30 s, 60 s, then every 5 minutes) until the instance answers, and
  the tools are re-advertised with the live list.

## [1.0.0] - 2026-09-20

### Added

- **`list_projects` lists projects and folders, paginated and searchable.** A folder carries
  `subtreeProjectCount`; a project's row carries its latest version, component count, severity
  counts and policy status. Without `q` only the top level is returned, matching the tree view;
  passing `q` searches at any depth, so a project nested inside folders no longer needs a
  manual walk down the tree to find.
- **`get_project` returns one project or folder's detail:** its versions (newest first), its
  ancestor chain, and for a folder its direct children plus a rollup over the whole subtree. Use
  it to resolve a `versionId` for `get_project_version`, or pass `"latest"` directly.
- **`get_project_version` lists a version's SBOM components with their advisories and effective
  priority**, plus a policy rollup by severity, scope and priority. This is the tool for "which
  packages does project X ship right now and which are vulnerable" against a project already
  tracked in Dependably; `check_dependencies` remains the tool for a lockfile you have locally.
  Compact by default; pass `verbosity: "full"` for every server field.

- **Unit tests and coverage reporting.** 129 tests across `test/`, covering the pure logic
  (version ordering, report scoping, lockfile parsing, remediation extraction), the HTTP
  client's URL building and its whole error-message surface, config validation, and every
  tool's handler through an in-memory MCP client with a stubbed `fetch`. 97.78% lines /
  94.19% branches / 99.10% functions; `npm run test:unit` fails below 90/85.
- Coverage is wired into SonarQube. The project previously reported **0%** — not because
  nothing was tested, but because nothing produced an lcov file and
  `sonar.javascript.lcov.reportPaths` was never set. Node's V8 coverage also names
  `dist/*.js`, which `sonar.sources=src` excludes, so the fix is `--enable-source-maps`,
  which remaps each `SF:` line onto the `src/*.ts` file Sonar actually analyzes. Verified on
  `node:22`, the CI image. No new dependencies: this is Node's built-in test runner and
  coverage, not c8 or nyc.
- CI: the `test` job publishes `coverage/lcov.info` and `sonarqube-check` now `needs` it,
  failing fast with a named reason if the artefact is missing rather than silently scanning
  with no coverage and failing the quality gate for the wrong reason.

- **`check_dependencies` — scope the vulnerability report to one project.** The Dependably
  API reports per *org*, so answering "what is wrong with this project?" previously meant
  fetching every page and joining against a lockfile by hand. This tool does the join and
  returns one finding per affected package, each annotated with `bumpTo`: the highest fixed
  version across that package's advisories, because several are explicit incomplete-fix
  follow-ups where the lowest fix does not clear the rest. `clean: true` when nothing
  matched, so the same call answers "did my fix land?". Measured on this repo's own tree:
  one call, ~150 ms, replacing roughly 30 calls of manual cross-referencing.
  - The dependency list is passed as `packages`; the tool reads no files. An earlier draft
    accepted a lockfile path behind a `DEPENDABLY_PROJECT_ROOT` opt-in and it was removed
    before merge: every host that could set such a root is one where the agent can already
    read the file, and reporting a parse failure usefully means surfacing the JSON error,
    which V8 fills with the offending bytes — turning any path under the root into a
    read oracle. The file-read rule stays one sentence: only the two import tools read
    local files. `parseNpmLockfile` remains exported and tested for callers assembling the
    argument.
  - Taking the dev marker from the lockfile rather than by eye also fixes a real
    misclassification: `fast-uri` reads as dev-only from `npm ls`, which shows one path per
    package, but is in the production tree via `@modelcontextprotocol/sdk` → `ajv`.
- **`get_remediation` — fixed versions in bulk.** Up to 200 advisories per call, returning
  the fixed version plus CWE / OWASP / remediation-skill ids and nothing else. The
  per-advisory endpoint returns the full write-up — PoC code, reproduction tables — which is
  the right thing when you want the analysis and enormously wasteful when you want a version
  string. Installed versions are passed through, so the answer stays release-line aware:
  `@hono/node-server` 1.19.14 resolves to 1.19.15, not the 2.x fix.

- **Claude Desktop extension bundle.** `manifest.json` (MCPB manifest 0.3) at the repo root maps
  the extension's config dialog — instance URL, keychain-stored token, timeout, optional import
  folder — onto the existing `DEPENDABLY_*` environment variables, so the bundle is `dist/` plus
  production dependencies with no new code path. `npm run bundle` builds
  `dist-mcpb/dependably-<version>.mcpb` with a SHA-256 beside it; `npm run bundle:verify` also
  boots the server from the unpacked bundle. `npm run manifest:sync` regenerates the manifest's
  tool list from the running server, and `npm test` now fails when the manifest is stale.
- `docs/distribution-plan.md`: the plan for the extension, the Anthropic directory listing, and
  the other MCP harnesses.
- **`DEPENDABLY_TOOLSET`** (`full` | `remote`, default `full`). `remote` leaves out `get_version`
  and `get_prometheus_metrics`, whose endpoints Dependably allowlists to loopback, so any client
  not running on the Dependably host would only ever see a `403` from them. The extension
  manifest sets `remote`, and `npm run manifest:sync` boots the server with the toolset the
  manifest declares, so the listed tools are exactly what a Desktop install exposes (16).
- Extension config dialog: an optional **private CA bundle** file, mapped onto Node's standard
  `NODE_EXTRA_CA_CERTS`, for instances behind an internal certificate authority. There is no
  option to disable certificate verification.
- CI: the GitLab `build` job and a new GitHub `release-bundle` job build and verify the `.mcpb`
  on every tagged release and attach it, with its `.sha256`, to the GitLab and GitHub releases.
- CI: the `sbom` job now runs our own sbom-reach in generate mode. It builds the CycloneDX SBOM
  from the lockfile with the dev/runtime marker explicit on every component, embeds OSV.dev
  advisories, and writes a reachability SARIF. Until sbom-reach has a published release the job
  installs the tarball its own `pack-verify` job packs on every `main` push.
- CI: `sbom-publish-dependably` uploads the SBOM (`PUT /api/v1/sbom`) and then the reachability
  SARIF (`PUT /api/v1/sarif`) to the Dependably instance's own Projects on `main`, alongside the
  existing Dependency-Track upload. It authenticates with `DEPENDABLY_SBOM_TOKEN`, a token minted
  with the `sbom:upload` capability.
- CI: `sonarqube-check` (advisory SonarQube scan on `main`, `sonar-project.properties`) and a
  manual `publish:github` job that mirrors `main` or a release tag to
  `github.com/dependably/dependably-mcp`, whose workflow publishes to public npm.
- `docs/listing.md` (directory listing pack and pre-submission checklist) and
  `docs/desktop-e2e.md` (manual Claude Desktop install runbook, macOS and Windows).

### Changed

- **`list_vulnerabilities.limit` is capped at 200**, matching `list_packages` and the server's own
  clamp. **`get_remediation_skill` accepts at most 5 skill ids per call** (was 25); the documents
  are long.
- **`get_remediation` and `get_remediation_skill` return a tool-level error when every item in the
  batch failed**, instead of a quiet success whose every element carries an `error`.
- **Tool results are serialized compactly** rather than pretty-printed, roughly halving payload size.
- **Descriptions were reworded for the directory review.** The setup tools describe what they return
  instead of instructing the model; `lookup_package`, `get_vulnerability`, `list_vulnerabilities` and
  `get_remediation_skill` say that upstream metadata, advisory text and operator-written Markdown are
  third-party data, not instructions; `list_packages` points at `search_packages` for quick lookups.
- Removed the unused write verbs (`post`, `put`, `patch`, `del`) from the HTTP client, so the
  read-only server's client surface has no write methods to audit.
- **Ecosystem enums are now read from the instance, not hardcoded.** At startup the server calls
  `GET /api/v1/ecosystems` and builds each tool's ecosystem enum from the returned `planes`
  (registry/lookup/setup), so an ecosystem the instance adds reaches every tool without a client
  release. An instance that cannot answer — a server older than the endpoint (404), one that is
  unreachable, or one that answers with an unexpected shape — falls back to the previous built-in
  lists, and exactly one line is written to stderr naming which case it was
  (`dependably-mcp: using the built-in ecosystem list; /api/v1/ecosystems <reason>`).

- `manifest.json` declares `compatibility.runtimes.node` as `>=22.0.0`, matching
  `engines.node` in `package.json` and the `node:22` image CI builds and tests on. It
  previously advertised `>=18.0.0`, which promised Claude Desktop a runtime floor the
  package itself does not support.

- **Cleared the SonarQube quality gate's 1 security hotspot and 12 code smells**, read from the
  API rather than guessed at.
  - `typescript:S5852` (hotspot, `src/config.ts`): the base-URL normalizer trimmed trailing
    slashes with `/\/+$/`, which backtracks super-linearly on a long run of slashes. Replaced
    with a loop. The input comes from the environment rather than a request, so this was not
    exploitable, but the pattern is worth not having.
  - `typescript:S3776` (cognitive complexity, 8 sites): `loadConfig`, `describeFetchError`,
    `formatHttpError`, `installCommand`'s handler, both vuln tool handlers, `buildFindings` and
    `summarize` are each split into named helpers. `formatHttpError` was the worst at 27; its
    per-status branches are now one function each, and the transport-failure hints in
    `describeFetchError` are a code lookup rather than an if/else chain.
  - `typescript:S4624` (nested template literals, 3 sites in `src/client.ts`): the conditional
    fragments are computed into named variables first.
  - `typescript:S3358` (nested ternaries, `src/semver.ts`): two sites introduced by this
    branch's own `compare` rewrite, caught by scanning before merge rather than after.
  - Behaviour is unchanged throughout — the 129 tests added alongside were written against the
    previous shapes and all still pass, and the 16 generated install commands were diffed
    byte-for-byte across all eight ecosystems, pinned and unpinned.
  - Verified by running the scanner against a throwaway project key (Community Edition has no
    branch analysis, so scanning under the real key would have overwritten `main`'s results):
    0 issues, 0 hotspots, 97.0% coverage, quality gate **OK**. The throwaway project was
    deleted afterwards.

- **`list_vulnerabilities` items are compact by default**, dropping the fields that are
  redundant (`purl` alongside `packageName`/`version`/`ecosystem`) or rarely actionable
  (`orgSlug`, `revokedAt`, `firstSeenAt`, `vulnCheckedAt`). Measured 54% smaller on a
  50-item page. Pass `verbosity: "full"` for the raw server response.
- **`list_vulnerabilities` now says it is org-wide** and points at `check_dependencies` for
  project-scoped questions. The old description read as though it reported on your project.

- `npm run sbom` now runs `scripts/sbom.mjs`, which wraps cyclonedx-npm and writes an explicit
  `cdx:npm:package:development=false` on every component the generator left unmarked. Consumers
  that read the marker as a tri-state (Dependably maps an absent marker to an `unknown` dependency
  scope) now see production dependencies as runtime instead of unknown.
- Transport failures now say what to check instead of Node's bare `fetch failed`: an unresolvable
  host, a refused connection, a TLS chain the runtime does not trust (with the
  `NODE_EXTRA_CA_CERTS` remedy), or a dropped connection, each with the underlying error code.
  The smoke test asserts this against a refused loopback port.
- Optional settings that arrive as an unexpanded `${…}` placeholder from a host that skipped
  substitution are treated as unset rather than as a URL or directory.
- Extension manifest: the support link points at <https://dependably.ca/contact>.

### Removed

- **`health_check`.** Liveness is a strict subset of readiness: if `/ready` answers, `/health` adds
  nothing, and if it does not, `/health` will not either. A developer never needed both. What
  `readiness_check` is actually for on this surface is separating "the base URL is wrong" from "the
  token is wrong" — it is the only tool needing no capability, which is why it leads the
  install-verification sequence. That role is unaffected. 14 tools.


- **The `docs/` tree.** It shipped to nobody: `package.json` `files` is
  `dist, README.md, CHANGELOG.md, LICENSE`, and `.mcpbignore` excluded `docs/` from the extension
  bundle — so the README linked twice to a `docs/tools.md` that is absent from both the npm tarball
  and the `.mcpb`, dead for every consumer who did not browse the repo. It also diverged from the
  convention `dependably-community` adopted in 2026-08: prose lives in the documentation, enterprise
  and spec repos, split by audience.

  `docs/tools.md` is folded into the README, which is the only file that reaches a user.
  `docs/development.md` becomes `CONTRIBUTING.md` at the repo root. The four planning documents move
  to the tracker with their content preserved: distribution plan (#24), listing pack (#25), desktop
  E2E runbook (#26), API asks (#27). Those four carried live status — `pending, this Mac`,
  `external, blocking` — and a tool count that went stale three times in one day without anything
  catching it, which is what status in git looks like.


- **`list_activity`, `siem_list_auth_events` and `siem_vulnerabilities_summary`.** They were the
  only three tools needing `read:audit`, a capability a member cannot mint — so the install
  instruction was "get an admin to issue you a token" for three tools out of eighteen, and the
  other fifteen worked on a Pull token any developer can create for themselves. They were also
  the only three tools never verified against a live instance, precisely because the credential
  the server is built around cannot reach them.

  The surface is now **15 tools**, every one reachable with a Pull token, verified end-to-end:
  15/15 answered, 0 failed. The audit endpoints still exist on the instance and an Audit token
  still reaches them — read them in the web UI or with your own client.

- **`get_version` and `get_prometheus_metrics`, and the `DEPENDABLY_TOOLSET` switch with them.**
  Both wrapped operator endpoints rather than agent ones, and `get_prometheus_metrics` returned
  well over a megabyte of Prometheus text in a single tool result — larger than most model context
  windows. `DEPENDABLY_TOOLSET=remote` existed only to hide them, which made the default (`full`)
  wrong for almost every install. Read `/version` and `/metrics` on the host, or scrape `/metrics`
  with Prometheus.
- **`yank_version`.** The last write in the surface, and the only destructive tool. It needed
  `yank:*` or a per-ecosystem leaf, which sits in the publisher set and so cannot be minted by an
  ordinary member, and it had no token preset. Yank a version from the Dependably web UI instead.
- **`whoami`.** It was the only tool needing `read:tenant`, which drags the Admin preset into
  an install that otherwise runs on Pull. It answered with opaque ids rather than names — `orgId`
  is a hex string, not the org slug — and the two identity facts worth having are already on the
  Pull surface: `list_packages` returns `orgId` per item, and `list_vulnerabilities` at
  `verbosity: "full"` returns `orgSlug`. What was left unique to it (`role`, MFA flags, locale)
  gates nothing in a read-only surface.
- **`import_manifest`, `admin_upload` and `DEPENDABLY_IMPORT_ROOT`.** The two import tools were
  the only ones that read the local filesystem, and they needed an admin-grade token carrying
  `import:*` and `tenant:configure`, which an ordinary member cannot mint. `DEPENDABLY_IMPORT_ROOT`
  existed to contain those reads; with the tools gone the containment has nothing left to guard.
  No tool in this server now touches the filesystem or runs a command.

The surface is a flat **18 tools in 4 groups**, registered unconditionally and **entirely
read-only**: no tool writes to the instance, deletes anything, reads a local file, or runs a
command. The two environment variables that gated tool registration are no longer read, and
`manifest.json` drops the matching `user_config` fields.

### Fixed

- **`check_dependencies` could misfile or miss a package.** The dev/runtime flag was lost whenever
  the report spelled a name differently from the lockfile (case, or PyPI separators), so a dev-only
  hit was counted as runtime; `clean: true` was reported from a scan that had hit the fetch cap;
  the cap returned a whole extra page; a response without `total` stopped paging after one page;
  and a NuGet, PyPI or Maven pin that differed from the registry only by a trailing `.0` was never
  matched. All five are fixed and pinned by tests.
- **Version ordering.** PEP 440 alias spellings (`c`, `pre`, `preview` for `rc`; `alpha` and `beta`
  for `a` and `b`; `r` and `rev` for `post`) and an upper-case `V` prefix now compare as equal to
  their canonical forms, so a project on `2.0.0rc2` is no longer told to "bump" to `2.0.0c1`. For
  the `rpm` ecosystem a `version-release` string is ordered the way `rpmvercmp` does (epoch, then
  digit and letter runs, with `~` sorting below everything), instead of being read as a semver
  prerelease that sorts below its bare version and produces a downgrade recommendation.
- **`DEPENDABLY_TIMEOUT_MS` rejects fractional or oversized values at startup.** `1500.7` or
  `2147483648` previously passed validation and then broke or crippled every request, with an
  error that told the user to raise the value.
- **A body that could not be read after the headers arrived** now reports the method, URL and cause
  instead of a bare "terminated".
- **Setup commands.** An unpinned Maven install emitted an invalid `groupId:artifactId` coordinate
  (now `:LATEST` with a note); the Cargo config hint was invalid TOML; the pypi, NuGet, OCI and Go
  install commands omitted the credential step and would 401 against an authenticated instance;
  `docker login` and `GONOSUMDB` used the base URL's path prefix where only a host is valid; and an
  empty `version` is treated as unpinned rather than rejected.

- **A Python prerelease sorted above its own release, so `bumpTo` went silent.** Python spells a
  prerelease without semver's hyphen (`2.0.0rc1`, `1.0a1`, `1.0.dev1`), and the parser split only
  on `-` — leaving the marker glued to the last release segment, where `"0rc1"` compared lexically
  *above* `"0"`. `bumpTarget` returns null once `gte(installed, ceiling)` holds, so a project
  pinned to `2.0.0rc1` with a fix at `2.0.0` was told nothing needed bumping. Pre, post and dev
  tails are now parsed and ordered `dev < pre < release < post`. Epochs (`1!1.0`) and local
  version labels remain unmodelled, and the module says so.

- **Tool schemas advertised `additionalProperties: false` and did not enforce it.** The SDK builds
  a non-strict object from a raw shape, so an unknown property was silently dropped and the call
  proceeded. A typo'd `version` on `lookup_package` meant the package was evaluated *unpinned* —
  a different question — and the verdict came back attributed to a version that was never sent.
  Every tool now registers `z.object({…}).strict()`, and the smoke test asserts, for every
  registered tool, that an unknown property is rejected rather than ignored.

- **The ecosystem enum was wrong in both directions.** One shared list of eight values backed every
  tool, but the planes differ. It offered `rpm` and `oci` to `lookup_package`, which the server
  rejects with `422 Must be one of: npm, pypi, nuget, maven, golang, cargo, hex`; and it withheld
  `apk`, `terraform` and `hex` from the registry tools, which serve them — 104 packages on the
  dogfood instance that no tool could reach (`hex` 45, `apk` 54, `terraform` 5). The sets are now
  per-plane in `src/ecosystems.ts`, and the smoke test pins each one as it reaches the client.

- **Error messages named a capability that does not exist.** `extractCapability` read only the
  token *after* the word "capability", but Dependably's dominant phrasing puts the name before it
  (`"read:tenant capability required."` — `AuthController`, `SiemController`, `CargoController`,
  `HexController` and friends). Every one of those rendered as `Your token lacks the "required"
  capability`, sending the reader after a grant that does not exist. Both positions are now read,
  and the capture must match the `verb:leaf` shape of a real capability, so prose can never be
  reported as one. The test that covered this used `requires capability "read:packages"`, a
  phrasing the server never emits; the real wordings are pinned now.
- **A 401 blamed the token's expiry when the cause could equally be a missing capability.**
  Dependably sends one body for "no token" and for "valid token, missing capability", so the
  message now names the capability and states both causes instead of picking one.
- **A 5xx told the reader to check `DEPENDABLY_BASE_URL`.** The instance answered, so the URL
  demonstrably resolves — `/lookup` in particular returns 503 when an *upstream* registry is
  unreachable, a fault beyond the instance. The hint now says so. A detail ending in a full stop
  no longer renders a doubled period.

- **`check_dependencies` reported a vulnerable package as `clean`.** Report rows were joined onto
  the caller's dependency list by exact `name@version`, but the report stores canonical lower-case
  names while a lockfile carries whatever the author wrote. Against a live instance,
  `starlette@0.47.2` returned 12 advisories and `Starlette@0.47.2` returned `clean: true` — and a
  NuGet `packages.lock.json` spells it `Newtonsoft.Json`, which is exactly the input the tool
  description tells the caller to paste. Both sides of the join now fold through `foldName`:
  lower-case everywhere, plus PEP 503 separator folding on pypi, where `typing_extensions` and
  `typing-extensions` are the same distribution. Versions stay exact.
- **`get_remediation` reported a severity its sibling tools did not use.** The advisory detail
  endpoint serves GHSA's raw `database_specific` vocabulary (`MODERATE`) while the report endpoint
  serves the normalized one (`MEDIUM`), so one advisory had two spellings depending on which tool
  you asked. `summarizeRemediation` now normalizes, and an advisory carrying no severity stays
  `undefined` rather than becoming `UNKNOWN`.

- `compare` in `src/semver.ts` returned 0 for any two versions with non-numeric release
  segments (`1.a.0` vs `1.b.0`), because both coerced to `NaN` and then stringified to the
  same `"NaN"`. The doc comment claimed lexical ordering, which was never true. Segments are
  now kept as strings and compared numerically only when both sides are numeric. Inert for
  real lockfile and advisory versions, which are numeric — found by the new tests.

- CI: `publish:github` pulled bare `alpine/git:latest`, which is not a Docker Hub official
  image and so is not reliably warm in the org's OCI pull-through cache; a cold pull fails on
  this network (Docker Hub's CDN does not resolve). It now pulls
  `${DEP_IMAGE_REGISTRY}/alpine/git:latest` with its entrypoint cleared, matching
  dependably-documentation's job of the same name.

### Security

- **`get_install_command` and `get_publish_command` no longer pass their arguments into a shell
  command unchecked.** A package name, version or artefact path is now validated against the
  ecosystem's own naming rules before it is interpolated, and every interpolated field is
  single-quoted. Before this, a name taken from advisory prose or package metadata could append a
  second command, add a flag such as `--registry=http://evil.tld`, or point npm, pip or dnf at a
  remote tarball, in text the user is told to paste and run. Shell globs in `artifact_path` are
  rejected; name the file.
- **The client no longer follows HTTP redirects.** A 3xx response is rejected with a message naming
  the `Location` and pointing at `DEPENDABLY_BASE_URL`, rather than depending on the runtime to strip
  the bearer token when a redirect crosses origins.
- **Response bodies are capped at 8 MB** and tool results at 100,000 characters (with a truncation
  trailer that names the narrowing argument). `list_vulnerabilities` and `check_dependencies` could
  previously return 700 to 800 thousand characters, past what MCP hosts such as Claude Desktop will
  display; error results honour the same budget, so an oversized upstream `detail` cannot bypass it.
- **CI images that hold write tokens are digest-pinned** (`publish:github` and `release` in
  `.gitlab-ci.yml`), the public GitHub workflow runs `npm ci --ignore-scripts`, and
  `scripts/bundle.mjs` no longer falls back to fetching the `mcpb` CLI over the network at build time.

- **Cleared all 26 known advisories in the dependency tree** (9 packages), verified against the
  Dependably registry's vulnerability report. Every one was transitive; neither direct dependency
  was itself affected.
  - `@modelcontextprotocol/sdk` 1.29.0 -> 1.30.0, whose refreshed ranges carry `hono` 4.12.27 ->
    4.13.7, `@hono/node-server` 1.19.14 -> 2.1.1, `qs` 6.15.3 -> 6.16.0, `ip-address` 10.2.0 ->
    10.7.0 and `fast-uri` (via `ajv`) 3.1.3 -> 3.1.7 — 19 advisories, including six HIGH
    host-confusion/SSRF issues in `fast-uri` and `ip-address`'s octal-octet SSRF bypass
    (`GHSA-mwp4-54f8-5fhr`, CVSS 7.7).
  - Dev tooling: `js-yaml` 4.3.0 -> 4.3.2, `brace-expansion` 2.1.2 -> 2.1.4, `tar` 7.5.20 ->
    7.5.22 — 5 advisories, all DoS.
  - `tmp` 0.0.33 -> 0.2.7 via a pinned `overrides` entry, since `external-editor` pins
    `tmp@^0.0.33` and cannot reach the 0.2.6 fix for `GHSA-ph9p-34f9-6g65`. That call site uses
    only `tmpNameSync({ postfix })`, unchanged in 0.2.x, so the forced bump is compatible. Drop
    the override once `@anthropic-ai/mcpb` ships a newer `@inquirer/prompts`.
  - None were reachable at runtime: the server instantiates only `StdioServerTransport`, so the
    SDK's HTTP path (Express/Hono, `qs` body parsing, `express-rate-limit`'s `ip-address`) is
    never loaded. They shipped on disk in the `.mcpb` bundle regardless, which is why they are
    fixed rather than waived.

### Docs

- **The extension's directory card and token dialog no longer promise an audit trail or an
  activity-feed and authentication-events capability** that no tool provides; `tools_generated` is
  now `false`. Install instructions for every MCP client (Claude Desktop, Claude Code, Cursor,
  Windsurf, VS Code, Zed, Codex CLI, Gemini CLI) live in the documentation site's Integrations
  section, not in this README. `SECURITY.md` routes reports to `support@dependably.ca`. The
  submission checklist corrections found by the review (the MCPB open-source clause is required and
  not waivable; a populated test account is needed for every submission; screenshot 4 shows
  `check_dependencies`, not a table that no tool produces) belong to the listing pack in the
  tracker (#25), not to this repository.

- `docs/api-asks.md`: the server-side changes that would let the MCP delete this client-side
  work — `fixedVersion`, a dev marker and reachability on each report item, and a `purls`
  filter. Each ask is written against measured cost from a real session.

## [0.2.0] - 2026-07-16

The developer read surface.

### Added

- **read** group — 9 read-only tools authenticated with the same PAT:
  `list_packages`, `get_package`, `search_packages`, `list_vulnerabilities`,
  `get_vulnerability`, `lookup_package` (pre-adoption check of a package not yet
  in the registry), `get_license_policy` (enforcement mode + SPDX allow/blocklist),
  `list_activity`, and `whoami`.

### Notes

- Requires a Dependably server **≥ v0.3.0** (PAT auth on read endpoints);
  `get_license_policy` and `lookup_package` need the release after v0.3.1.
  Against an older server the read tools return `401`.
- Capabilities: `read:packages` drives the package/vulnerability/license tools,
  `read:audit` drives `list_activity`, `read:tenant` drives `whoami` — or mint
  `read:*` for all of them. Service/CI tokens work on the read surface too.

## [0.1.0] - 2026-07-15

First public release — the PAT-only v1 surface.

### Added

- 11 tools across 5 groups, authenticated with a Dependably Personal Access Token:
  - **yank** — `yank_version`
  - **siem** — `siem_list_auth_events`, `siem_vulnerabilities_summary`
  - **import** (opt-in via `DEPENDABLY_IMPORT_ROOT`) — `import_manifest`, `admin_upload`
  - **observability** — `health_check`, `readiness_check`, `get_version`, `get_prometheus_metrics`
  - **setup** (local, no server call) — `get_install_command`, `get_publish_command`
- Import-root sandboxing: the two import tools are only registered when
  `DEPENDABLY_IMPORT_ROOT` is set and refuse to read any path (symlinks included)
  that resolves outside it.
- RFC 7807-aware error formatting with actionable 401/403/429/5xx messages.
- In-memory smoke test asserting the tool surface and import-root containment.

### Notes

- The read/browse surface (package inventory, vulnerability list, audit logs, org
  settings, whoami, search) is deferred to v2, pending server-side PAT support on
  read endpoints (dependably-community#343).
