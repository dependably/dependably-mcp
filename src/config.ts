/**
 * Runtime configuration for the PAT-only Dependably MCP server.
 *
 * Authentication is a single static Personal Access Token (`DEPENDABLY_TOKEN`),
 * sent as a bearer token on every request. There is intentionally no JWT/session
 * login: a PAT reaches every endpoint that opts into the `ApiToken` auth scheme —
 * since Dependably v0.3.0 that includes the read-only management surface
 * (packages, search, vulnerabilities, activity, license policy, lookup) —
 * plus the anonymous health and readiness probes. Every tool is read-only and
 * reachable with a Pull token (`read:packages`): nothing in the surface writes,
 * deletes, or reads a local file.
 *
 * Against a Dependably server older than v0.3.0 the read tools return 401,
 * service/M2M tokens 404 on capability-gated endpoints, and MFA-required orgs
 * may return 403 mfa_enrollment_required — all fixed server-side in v0.3.0.
 *
 * Tenancy is resolved from the request host, so there is no org-slug config:
 * the install/publish command builders template URLs directly on the base URL.
 */
export interface Config {
  /** Normalized Dependably base URL (scheme://host[/path], no trailing slash). */
  baseUrl: string;
  /** Personal Access Token, sent as `Authorization: Bearer <token>`. */
  token: string;
  /** Per-request HTTP timeout in milliseconds. */
  timeoutMs: number;
}

/**
 * Reads an environment variable, treating an unset value, whitespace, or an
 * unexpanded `${…}` template as "not set". Desktop-extension hosts substitute
 * `${user_config.key}` for each field; an optional field the user left blank
 * arrives as an empty string, but a host that skips substitution would pass the
 * literal placeholder, which must never be mistaken for a URL or a directory.
 */
function envValue(name: string): string | undefined {
  const raw = process.env[name]?.trim();
  if (!raw || /^\$\{[^}]*\}$/.test(raw)) return undefined;
  return raw;
}

export function loadConfig(): Config {
  const baseUrl = parseBaseUrl(requireEnv('DEPENDABLY_BASE_URL', 'DEPENDABLY_BASE_URL is required (e.g. https://dependably.example.com)'));
  const token = requireEnv(
    'DEPENDABLY_TOKEN',
    'DEPENDABLY_TOKEN is required — a user-owned Personal Access Token minted in the Dependably UI',
  );

  return {
    baseUrl,
    token,
    timeoutMs: parseTimeout(envValue('DEPENDABLY_TIMEOUT_MS')),
  };
}

function requireEnv(name: string, message: string): string {
  const value = envValue(name);
  if (!value) throw new Error(message);
  return value;
}

/**
 * Normalize the instance URL to `scheme://host[/path]` with no trailing slash.
 *
 * The trailing slashes are trimmed with a loop rather than a `/\/+$/` replace:
 * that pattern backtracks super-linearly on a long run of slashes, which is a
 * denial-of-service shape even though this particular input comes from the
 * environment rather than a request.
 */
function parseBaseUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`DEPENDABLY_BASE_URL is not a valid URL: ${raw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`DEPENDABLY_BASE_URL must be http(s): ${raw}`);
  }
  const path = trimTrailingSlashes(parsed.pathname);
  // The base URL is pasted into the install and publish commands the setup
  // tools emit for the user to run, so a path segment a shell would interpret
  // is refused here rather than quoted at every call site.
  if (SHELL_SIGNIFICANT.test(path)) {
    throw new Error(`DEPENDABLY_BASE_URL must not contain shell metacharacters in its path: ${raw}`);
  }
  return `${parsed.protocol}//${parsed.host}${path}`;
}

const SHELL_SIGNIFICANT = /[;$()'"`!&|*?<>{}[\]\\\s]/;

function trimTrailingSlashes(path: string): string {
  let end = path.length;
  while (end > 0 && path[end - 1] === '/') end--;
  return path.slice(0, end);
}

/**
 * `AbortSignal.timeout()` hands the delay straight to Node's timer internals,
 * which require a 32-bit signed integer: a fractional value (`1500.7`) throws
 * "The value of \"delay\" is out of range" on every request, and a value above
 * `2147483647` (`TimeoutOverflowWarning`) silently clamps to a 1ms timeout —
 * the opposite of the raise-it-if-slow advice `describeFetchError` gives.
 * Validating the integer range at startup turns both into one actionable
 * message instead of a per-request failure.
 */
const MAX_TIMEOUT_MS = 2_147_483_647;

function parseTimeout(raw: string | undefined): number {
  if (!raw) return 30000;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > MAX_TIMEOUT_MS) {
    throw new Error(
      `DEPENDABLY_TIMEOUT_MS must be an integer between 1 and ${MAX_TIMEOUT_MS}: ${raw}`,
    );
  }
  return n;
}
