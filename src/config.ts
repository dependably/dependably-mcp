/**
 * Runtime configuration for the PAT-only Dependably MCP server.
 *
 * Authentication is a single static Personal Access Token (`DEPENDABLY_TOKEN`),
 * sent as a bearer token on every request. There is intentionally no JWT/session
 * login: Dependably's management API reads the session JWT from the
 * `dependably_session` cookie and ignores the `Authorization` header, so a PAT
 * only reaches endpoints that opt into the `ApiToken` auth scheme (yank, import,
 * SIEM) plus anonymous / IP-allowlisted probes (health, readiness, version,
 * metrics). This server exposes only that PAT-reachable read + supply-chain-
 * automation surface.
 *
 * Use a user-owned PAT: service/M2M tokens currently 404 on capability-gated
 * endpoints (tracked as dependably-community#343), and most read tools also
 * require that server-side change before they stop returning 401 to a PAT.
 */
export interface Config {
  /** Normalized Dependably base URL (scheme://host[/path], no trailing slash). */
  baseUrl: string;
  /** Personal Access Token, sent as `Authorization: Bearer <token>`. */
  token: string;
  /** Org slug used only by the local install/publish command builders. */
  orgSlug: string;
  /** Per-request HTTP timeout in milliseconds. */
  timeoutMs: number;
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
  const orgSlug = process.env.DEPENDABLY_ORG_SLUG?.trim() || 'default';

  const timeoutRaw = process.env.DEPENDABLY_TIMEOUT_MS?.trim();
  let timeoutMs = 30000;
  if (timeoutRaw) {
    const n = Number(timeoutRaw);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`DEPENDABLY_TIMEOUT_MS must be a positive number: ${timeoutRaw}`);
    }
    timeoutMs = n;
  }

  return { baseUrl, token, orgSlug, timeoutMs };
}
