import { statSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Runtime configuration for the PAT-only Dependably MCP server.
 *
 * Authentication is a single static Personal Access Token (`DEPENDABLY_TOKEN`),
 * sent as a bearer token on every request. There is intentionally no JWT/session
 * login: a PAT reaches every endpoint that opts into the `ApiToken` auth scheme —
 * since Dependably v0.3.0 that includes the read-only management surface
 * (packages, search, vulnerabilities, activity, whoami, license policy, lookup)
 * alongside yank, import, and SIEM — plus anonymous / IP-allowlisted probes
 * (health, readiness, version, metrics). 18 tools by default, plus the 2 admin
 * import tools when `DEPENDABLY_IMPORT_ROOT` opts in, minus the 2 loopback-only
 * probes when `DEPENDABLY_TOOLSET=remote`.
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
  /**
   * Absolute directory the import tools may read artefact files from.
   * Unset ⇒ the import tools are not registered at all. This is the opt-in
   * that keeps the default tool surface free of local-file reads (an LLM
   * tricked into calling admin_upload cannot exfiltrate arbitrary files).
   */
  importRoot?: string;
  /**
   * Which tools to register. `full` (default) is everything. `remote` drops the
   * two probes Dependably allowlists to loopback (`get_version`,
   * `get_prometheus_metrics`), which always 403 from any machine other than the
   * Dependably host itself — the right setting for Claude Desktop, Cursor, and
   * any other client that is not running on the server.
   */
  toolset: Toolset;
}

export type Toolset = 'full' | 'remote';

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
    importRoot: readRoot('DEPENDABLY_IMPORT_ROOT'),
    toolset: parseToolset(envValue('DEPENDABLY_TOOLSET')),
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
  return `${parsed.protocol}//${parsed.host}${trimTrailingSlashes(parsed.pathname)}`;
}

function trimTrailingSlashes(path: string): string {
  let end = path.length;
  while (end > 0 && path[end - 1] === '/') end--;
  return path.slice(0, end);
}

function parseTimeout(raw: string | undefined): number {
  if (!raw) return 30000;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`DEPENDABLY_TIMEOUT_MS must be a positive number: ${raw}`);
  }
  return n;
}

function parseToolset(raw: string | undefined): Toolset {
  const value = raw ?? 'full';
  if (value !== 'full' && value !== 'remote') {
    throw new Error(`DEPENDABLY_TOOLSET must be "full" or "remote": ${value}`);
  }
  return value;
}

/**
 * Read an environment variable naming a directory the server may read from,
 * and require it to exist. Unset means the tools it gates are not registered.
 */
function readRoot(name: string): string | undefined {
  const raw = envValue(name);
  if (!raw) return undefined;
  const root = resolve(raw);
  let stat;
  try {
    stat = statSync(root);
  } catch {
    throw new Error(`${name} does not exist: ${root}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${name} must be a directory: ${root}`);
  }
  return root;
}
