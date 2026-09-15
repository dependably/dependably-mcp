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
 * (health, readiness, version, metrics). 20 tools by default, plus the 2 admin
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
   * Absolute directory `check_dependencies` may read a lockfile from.
   * Unset ⇒ that tool still works, but only via its `packages` argument; the
   * `lockfile` parameter is not offered. Same opt-in shape as `importRoot`:
   * no local-file read is reachable unless an operator scopes it.
   */
  projectRoot?: string;
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
  const baseUrlRaw = envValue('DEPENDABLY_BASE_URL');
  const token = envValue('DEPENDABLY_TOKEN');

  if (!baseUrlRaw) {
    throw new Error('DEPENDABLY_BASE_URL is required (e.g. https://dependably.example.com)');
  }
  if (!token) {
    throw new Error('DEPENDABLY_TOKEN is required — a user-owned Personal Access Token minted in the Dependably UI');
  }

  let parsed: URL;
  try {
    parsed = new URL(baseUrlRaw);
  } catch {
    throw new Error(`DEPENDABLY_BASE_URL is not a valid URL: ${baseUrlRaw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`DEPENDABLY_BASE_URL must be http(s): ${baseUrlRaw}`);
  }

  const baseUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '')}`;

  const timeoutRaw = envValue('DEPENDABLY_TIMEOUT_MS');
  let timeoutMs = 30000;
  if (timeoutRaw) {
    const n = Number(timeoutRaw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`DEPENDABLY_TIMEOUT_MS must be a positive number: ${timeoutRaw}`);
    }
    timeoutMs = n;
  }

  const importRoot = readRoot('DEPENDABLY_IMPORT_ROOT');
  const projectRoot = readRoot('DEPENDABLY_PROJECT_ROOT');

  const toolsetRaw = envValue('DEPENDABLY_TOOLSET') ?? 'full';
  if (toolsetRaw !== 'full' && toolsetRaw !== 'remote') {
    throw new Error(`DEPENDABLY_TOOLSET must be "full" or "remote": ${toolsetRaw}`);
  }

  return { baseUrl, token, timeoutMs, importRoot, projectRoot, toolset: toolsetRaw };
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
