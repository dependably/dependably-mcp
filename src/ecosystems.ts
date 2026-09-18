/**
 * The ecosystem vocabularies, one per server plane.
 *
 * These differ, and collapsing them into one list is what made the previous
 * single enum wrong in both directions at once: it offered `rpm` and `oci` to
 * `lookup_package`, which the server rejects with a 422, and withheld `apk`,
 * `terraform` and `hex` from the registry tools, which serve them — 104 packages
 * on the dogfood instance alone that no tool could reach.
 *
 * An enum is kept rather than a free string because the registry endpoints do
 * not validate this parameter at all: they treat it as a filter, so a typo comes
 * back as `200` with `total: 0`. An empty result that means "you misspelled the
 * ecosystem" is indistinguishable from one that means "nothing is affected",
 * which is the more dangerous reading for a tool that answers questions about
 * vulnerabilities.
 */

/**
 * Ecosystems the registry plane serves — inventory and vulnerability reports
 * (`/api/v1/packages`, `/vuln-report`).
 */
export const REGISTRY_ECOSYSTEMS = [
  'npm',
  'pypi',
  'nuget',
  'maven',
  'rpm',
  'oci',
  'golang',
  'cargo',
  'apk',
  'terraform',
  'hex',
] as const;

/**
 * Ecosystems `/api/v1/lookup` accepts. Narrower than the registry plane: a
 * pre-adoption verdict needs an upstream to resolve the candidate against, and
 * rpm, oci, apk and terraform have no single canonical upstream to ask. The
 * server enforces this set and answers a value outside it with
 * `422 Must be one of: …`.
 */
export const LOOKUP_ECOSYSTEMS = ['npm', 'pypi', 'nuget', 'maven', 'golang', 'cargo', 'hex'] as const;

/**
 * Ecosystems the install/publish command builders can write a command for.
 * Narrower again, and deliberately so: this list is bounded by what the builders
 * below actually know how to spell, not by what the server serves. Adding a name
 * here without a matching command arm would return an empty fence.
 */
export const SETUP_ECOSYSTEMS = ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo'] as const;
