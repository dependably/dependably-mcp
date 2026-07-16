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
 * import tools when `DEPENDABLY_IMPORT_ROOT` opts in.
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
}

export function loadConfig(): Config {
  const baseUrlRaw = process.env.DEPENDABLY_BASE_URL?.trim();
  const token = process.env.DEPENDABLY_TOKEN?.trim();

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

  const timeoutRaw = process.env.DEPENDABLY_TIMEOUT_MS?.trim();
  let timeoutMs = 30000;
  if (timeoutRaw) {
    const n = Number(timeoutRaw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`DEPENDABLY_TIMEOUT_MS must be a positive number: ${timeoutRaw}`);
    }
    timeoutMs = n;
  }

  const importRootRaw = process.env.DEPENDABLY_IMPORT_ROOT?.trim();
  let importRoot: string | undefined;
  if (importRootRaw) {
    importRoot = resolve(importRootRaw);
    let stat;
    try {
      stat = statSync(importRoot);
    } catch {
      throw new Error(`DEPENDABLY_IMPORT_ROOT does not exist: ${importRoot}`);
    }
    if (!stat.isDirectory()) {
      throw new Error(`DEPENDABLY_IMPORT_ROOT must be a directory: ${importRoot}`);
    }
  }

  return { baseUrl, token, timeoutMs, importRoot };
}
