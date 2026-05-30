export interface Config {
  baseUrl: string;
  token: string;
  orgSlug: string;
  timeoutMs: number;
}

export function loadConfig(): Config {
  const baseUrlRaw = process.env.DEPENDABLY_BASE_URL?.trim();
  const token = process.env.DEPENDABLY_TOKEN?.trim();

  if (!baseUrlRaw) {
    throw new Error('DEPENDABLY_BASE_URL is required (e.g. https://dependably.example.com)');
  }
  if (!token) {
    throw new Error('DEPENDABLY_TOKEN is required (create one in the Dependably UI)');
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
