# API asks for dependably-community

Changes to the Dependably server that would let this MCP delete client-side work it
currently does to answer ordinary questions. Each one is written as "what the client
does today" → "what the server could return instead", with the cost that motivates it.

These are asks, not blockers: every item below is worked around in
`src/vuln.ts` today, and the MCP behaves correctly without any of them.

Written 2026-09-15, from a session that used the MCP to find and fix 26 advisories in
this repo's own dependency tree. The numbers are measured from that session.

---

## 1. `fixedVersion` on each `GET /api/v1/vuln-report` item

**Today.** The report says a package is affected but not what to upgrade to. The fixed
version lives only on `GET /api/v1/vulnerabilities/{osvId}`, so answering "what do I bump
to?" costs one extra request per distinct (advisory, version) pair. In the session that
prompted this, that was **24 extra calls**, each returning a full advisory — PoC code,
reproduction tables, remediation prose — to extract one string. One of them returned an
essay including `inotifywait` monitoring scripts to communicate the value `0.2.6`.

**Ask.** Add `fixedVersion` (string, nullable) to each report item, resolved for *that
item's* version — the same release-line-aware logic `/vulnerabilities/{osvId}?version=`
already implements. `@hono/node-server` 1.19.14 must yield `1.19.15`, not the 2.x fix.

**Impact.** `check_dependencies` drops from 1 + N requests to 1. It is the single
highest-value change on this list.

---

## 2. Dev/runtime marker on each report item

**Today.** The client recomputes dev-vs-prod from the caller's lockfile. Anyone who does
this by hand gets it wrong: in the source session, `fast-uri` was first reported as
dev-only when it is in the production tree via `@modelcontextprotocol/sdk` → `ajv`,
because `npm ls` shows only one path per package. That mistake moved six HIGH advisories
into the wrong tier.

**Ask.** Carry the SBOM's dev marker through to the report item as `dev` (bool, nullable).
The ingest side already has it — `fix(sbom): declare the dev marker explicitly on every
component` exists precisely because this field matters.

**Impact.** Removes a whole class of client-side misclassification, and lets callers that
do not have a lockfile to hand still get the split.

---

## 3. Reachability on each report item

**Today.** Not exposed at all. Reachability is what turns a report from alarming into
actionable — in the source session, all 26 advisories were unreachable, because the
server only ever instantiates `StdioServerTransport` and the SDK's HTTP path is never
loaded. Establishing that took reading the source by hand.

**Ask.** The CI pipeline already runs `sbom-reach` and uploads a reachability SARIF
(`sbom-publish` / `SBOM_REACH_VERSION`). Surface the result as `reachable`
(`true` | `false` | `null` for not-analyzed) per item, with `null` meaning no signal —
never conflate "not analyzed" with "not reachable".

**Impact.** Highest-value field after `fixedVersion`. It is the difference between
"26 advisories, patch now" and "26 advisories, none of which execute".

---

## 4. A `purls` (or `packages`) filter on the report

**Today.** The report is org-wide. Scoping it to one project means fetching every page
and joining locally: 138 items to answer a question about 296 packages, of which 9
matched. Every consumer will write that join, slightly differently, and some will get it
wrong.

**Ask.** Accept a repeated `purls=` query parameter (or a POST body for large sets) and
return only matching items. A few hundred purls per call is the realistic size.

**Impact.** Replaces a full-report download with one scoped request, and makes
"is this project clean now?" a cheap, obvious call rather than a re-download and re-join.

---

## 5. A compact representation

**Today.** Each item carries ~18 fields, including `purl` *and* `packageName` / `version` /
`ecosystem` separately, plus `orgSlug`, `revokedAt`, `isKevRansomware`, `firstSeenAt` and
`vulnCheckedAt`. Two calls in the source session exceeded the client's token budget and
spilled to disk: 61 KB at `limit=100`, 85 KB at `limit=300`. The MCP now strips these
client-side, which measures **54% smaller** on a 50-item page — bytes that were paid for
over the wire regardless.

**Ask.** Either a `fields=` selector or a `view=compact` mode that omits the redundant and
rarely-actionable fields.

**Impact.** Makes a whole report fit in one response for the common case.

---

## 6. Smaller things

- **Default page size.** `limit` defaults to 50 against a `total` in the hundreds, so the
  common case always paginates. A default of 200 would usually be one call.
- **`name=` filter semantics.** Filtering by name returns every version *in the registry*,
  including versions belonging to other projects — filtering for `hono` returned 4.12.27,
  4.13.0, 4.13.1 and 4.13.3. Useful sometimes; an opt-in `onlyAffected`-style narrowing
  would make the common case clearer.
- **`epssScore: null`.** Reads ambiguously as "no score published" versus "zero risk".
  Worth a distinct absent-vs-zero representation, or documenting which is meant.
- **Latest safe version.** There is no way to ask "what is the newest release of X that
  carries no known advisory". `lookup_package` is close but requires a candidate version.
  Callers currently fall back to `npm view`, which defeats the point of a private registry.
