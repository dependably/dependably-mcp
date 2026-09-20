import { z } from 'zod';

import { DependablyApiError, type DependablyClient } from './client.js';

/**
 * The ecosystem vocabularies, one per server plane.
 *
 * These differ, and collapsing them into one list is what made a single shared
 * enum wrong in both directions at once: it offered `rpm` and `oci` to
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
 *
 * The lists below are only the FALLBACK — used when the instance cannot answer
 * `GET /api/v1/ecosystems` (older server, unreachable at startup, or a malformed
 * response). When the instance answers, {@link fetchEcosystems} reads the live
 * vocabulary from it instead, so a newly-added ecosystem on the server reaches
 * every tool without a client release.
 */

/**
 * Fallback ecosystems the registry plane serves — inventory and vulnerability
 * reports (`/api/v1/packages`, `/vuln-report`).
 */
export const FALLBACK_REGISTRY_ECOSYSTEMS = [
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
 * Fallback ecosystems `/api/v1/lookup` accepts. Narrower than the registry
 * plane: a pre-adoption verdict needs an upstream to resolve the candidate
 * against, and rpm, oci, apk and terraform have no single canonical upstream to
 * ask. The server enforces this set and answers a value outside it with
 * `422 Must be one of: …`.
 */
export const FALLBACK_LOOKUP_ECOSYSTEMS = ['npm', 'pypi', 'nuget', 'maven', 'golang', 'cargo', 'hex'] as const;

/**
 * Fallback ecosystems the install/publish command builders can write a
 * command for. Narrower again, and deliberately so: this list is bounded by
 * what the builders in `tools/setup.ts` actually know how to spell, not by
 * what the server serves. Adding a name here without a matching command arm
 * would return an empty fence.
 */
export const FALLBACK_SETUP_ECOSYSTEMS = ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo'] as const;

/** The three ecosystem vocabularies a running server offers, one per plane. */
export type EcosystemPlanes = {
  registry: readonly string[];
  lookup: readonly string[];
  setup: readonly string[];
};

/** The vocabulary used when the instance cannot answer `GET /api/v1/ecosystems`. */
export const FALLBACK_PLANES: EcosystemPlanes = {
  registry: FALLBACK_REGISTRY_ECOSYSTEMS,
  lookup: FALLBACK_LOOKUP_ECOSYSTEMS,
  setup: FALLBACK_SETUP_ECOSYSTEMS,
};

/** `z.enum` needs a statically non-empty tuple; a fetched vocabulary is only known at runtime. */
export function enumOf(values: readonly string[], fallback: readonly string[]): z.ZodEnum<[string, ...string[]]> {
  const chosen = values.length > 0 ? values : fallback;
  return z.enum([...chosen] as [string, ...string[]]);
}

function isNonEmptyStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string' && v.length > 0);
}

function isSubset(subset: readonly string[], superset: readonly string[]): boolean {
  const set = new Set(superset);
  return subset.every((v) => set.has(v));
}

/**
 * Parse the `GET /api/v1/ecosystems` response body into {@link EcosystemPlanes}.
 *
 * Accepts the contract shape — `planes.registry`/`lookup`/`setup`, each a
 * non-empty array of non-empty strings, with `lookup` and `setup` each a
 * subset of `registry` — and returns `null` for anything else. Never throws:
 * a malformed or unexpected body is the caller's cue to fall back, not an
 * exception to handle.
 */
export function parsePlanes(body: unknown): EcosystemPlanes | null {
  if (body === null || typeof body !== 'object') return null;
  const planes = (body as Record<string, unknown>).planes;
  if (planes === null || typeof planes !== 'object') return null;
  const { registry, lookup, setup } = planes as Record<string, unknown>;
  if (!isNonEmptyStringArray(registry) || !isNonEmptyStringArray(lookup) || !isNonEmptyStringArray(setup)) {
    return null;
  }
  if (!isSubset(lookup, registry) || !isSubset(setup, registry)) return null;
  return { registry, lookup, setup };
}

/** A timeout of at most this many milliseconds is used for the startup ecosystems fetch. */
const ECOSYSTEMS_FETCH_TIMEOUT_CAP_MS = 5000;

/**
 * Read the ecosystem vocabulary from the instance (`GET /api/v1/ecosystems`),
 * falling back to the built-in lists when the instance cannot answer: any
 * HTTP status other than 200 (a server older than the endpoint answers 404;
 * an auth or server-side failure answers 401/500/…), the request is
 * unreachable at the transport level, or the body does not match the
 * contract shape.
 *
 * Never throws — every failure mode resolves to a `source: 'fallback'` result
 * with a short, single-line `reason`, so the caller can log exactly one line
 * and move on rather than fail startup over an instance detail the server can
 * serve without. The reason is never built from response bytes: an instance
 * (or a MITM sitting in front of one) answering with an oversized or
 * multi-line body — an HTML error page, a stack trace — cannot turn one
 * stderr line into several, or leak that body onto stderr at all.
 */
export async function fetchEcosystems(
  client: DependablyClient,
): Promise<{ planes: EcosystemPlanes; source: 'instance' } | { planes: EcosystemPlanes; source: 'fallback'; reason: string }> {
  const timeoutMs = Math.min(client.timeoutMs, ECOSYSTEMS_FETCH_TIMEOUT_CAP_MS);
  try {
    const body = await client.get('/api/v1/ecosystems', undefined, { timeoutMs });
    const planes = parsePlanes(body);
    if (!planes) return fallbackResult('answered with an unexpected shape');
    return { planes, source: 'instance' };
  } catch (e) {
    // The instance answered — with a status other than 2xx — so this is not
    // "unreachable"; and the reason is the status alone, never the response
    // body or DependablyApiError's formatted message, which can embed either.
    if (e instanceof DependablyApiError) return fallbackResult(`returned ${e.status}`);
    return fallbackResult(`was unreachable: ${transportReasonCause(e)}`);
  }
}

function fallbackResult(reason: string): { planes: EcosystemPlanes; source: 'fallback'; reason: string } {
  return { planes: FALLBACK_PLANES, source: 'fallback', reason: normalizeReason(reason) };
}

/**
 * Collapse whitespace (including newlines) to single spaces and cap the
 * length, so nothing that reaches this point — even a reason string this
 * module did not fully control the shape of — can turn the caller's one
 * `stderr.write` into more than one line, or an unbounded one.
 */
function normalizeReason(reason: string): string {
  return reason.replace(/\s+/g, ' ').trim().slice(0, 160);
}

/**
 * Reduce a transport failure (no HTTP response at all) to a short cause:
 * `ECONNREFUSED`, `timed out after 200ms`, `bad port` — never
 * {@link describeFetchError}'s full remediation sentence. In particular, a
 * timeout's own message says "Raise DEPENDABLY_TIMEOUT_MS if the instance is
 * just slow", which is the wrong advice here: this fetch is capped at
 * `min(cfg.timeoutMs, 5000)ms`, not the configured request timeout, so
 * raising the latter would not change this call's behaviour.
 */
function transportReasonCause(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  const timedOut = /timed out after \d+ms/.exec(message);
  if (timedOut) return timedOut[0];
  const code = /\(([A-Z][A-Z0-9_]*)\)/.exec(message);
  if (code) return code[1];
  const failed = /failed: ([^.]+)\./.exec(message);
  if (failed) return failed[1];
  return message;
}
