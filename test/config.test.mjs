import { ok, strictEqual, throws } from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, it } from 'node:test';

import { loadConfig } from '../dist/config.js';

const KEYS = [
  'DEPENDABLY_BASE_URL',
  'DEPENDABLY_TOKEN',
  'DEPENDABLY_TIMEOUT_MS',
];

/** Run loadConfig with exactly the given environment. */
function withEnv(env, fn) {
  const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, env);
  try {
    return fn();
  } finally {
    for (const k of KEYS) delete process.env[k];
    for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
  }
}

const minimal = { DEPENDABLY_BASE_URL: 'https://dep.example.com', DEPENDABLY_TOKEN: 'tok' };

describe('loadConfig required settings', () => {
  it('requires a base url and names the setting', () => {
    withEnv({ DEPENDABLY_TOKEN: 'tok' }, () => throws(loadConfig, /DEPENDABLY_BASE_URL is required/));
  });

  it('requires a token and says where to mint one', () => {
    withEnv({ DEPENDABLY_BASE_URL: 'https://x.example' }, () =>
      throws(loadConfig, /DEPENDABLY_TOKEN is required/),
    );
  });

  it('treats whitespace and an unexpanded ${…} placeholder as unset', () => {
    // Desktop hosts substitute ${user_config.key}; a host that does not must not
    // have the literal placeholder mistaken for a real value.
    withEnv({ DEPENDABLY_BASE_URL: '   ', DEPENDABLY_TOKEN: 'tok' }, () =>
      throws(loadConfig, /DEPENDABLY_BASE_URL is required/),
    );
    withEnv({ DEPENDABLY_BASE_URL: '${user_config.base_url}', DEPENDABLY_TOKEN: 'tok' }, () =>
      throws(loadConfig, /DEPENDABLY_BASE_URL is required/),
    );
  });
});

describe('loadConfig base url normalization', () => {
  it('rejects a malformed url', () => {
    withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'not a url' }, () =>
      throws(loadConfig, /not a valid URL/),
    );
  });

  it('rejects a non-http scheme', () => {
    for (const url of ['ftp://x.example', 'file:///etc']) {
      withEnv({ ...minimal, DEPENDABLY_BASE_URL: url }, () => throws(loadConfig, /must be http\(s\)/));
    }
  });

  it('strips trailing slashes but keeps a path prefix', () => {
    withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'https://x.example///' }, () =>
      strictEqual(loadConfig().baseUrl, 'https://x.example'),
    );
    withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'https://x.example/dep/' }, () =>
      strictEqual(loadConfig().baseUrl, 'https://x.example/dep'),
    );
  });

  it('keeps a non-default port', () => {
    withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'http://localhost:8080' }, () =>
      strictEqual(loadConfig().baseUrl, 'http://localhost:8080'),
    );
  });
});

describe('loadConfig timeout', () => {
  it('defaults to 30s', () => {
    withEnv(minimal, () => strictEqual(loadConfig().timeoutMs, 30000));
  });

  it('defaults to 30s when DEPENDABLY_TIMEOUT_MS is an empty string', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '' }, () => strictEqual(loadConfig().timeoutMs, 30000));
  });

  it('accepts a positive integer', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '1500' }, () =>
      strictEqual(loadConfig().timeoutMs, 1500),
    );
  });

  it('rejects zero, negative and non-numeric values', () => {
    for (const v of ['0', '-1', 'abc']) {
      withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: v }, () =>
        throws(loadConfig, /must be an integer between 1 and/),
      );
    }
  });

  it('rejects a fractional value, which breaks AbortSignal.timeout with a Node range error', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '1500.7' }, () =>
      throws(loadConfig, /DEPENDABLY_TIMEOUT_MS must be an integer between 1 and \d+: 1500\.7/),
    );
  });

  it('rejects a value above the 32-bit signed integer limit, which Node silently clamps to ~1ms', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '2147483648' }, () =>
      throws(loadConfig, /DEPENDABLY_TIMEOUT_MS must be an integer between 1 and 2147483647: 2147483648/),
    );
  });

  it('rejects a value far outside the safe integer range', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '1e21' }, () =>
      throws(loadConfig, /DEPENDABLY_TIMEOUT_MS must be an integer between 1 and \d+: 1e21/),
    );
  });

  it('accepts the maximum valid integer', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '2147483647' }, () =>
      strictEqual(loadConfig().timeoutMs, 2147483647),
    );
  });
});


afterEach(() => {
  for (const k of KEYS) delete process.env[k];
});

describe('loadConfig base URL path', () => {
  // The base URL is pasted into the commands the setup tools emit for the user to run.
  for (const path of ['/x;touch$(id)', "/a'b", '/a|b', '/a$HOME', '/a&b', '/a*', '/a!b']) {
    it(`refuses a shell metacharacter in the path: ${path}`, () => {
      throws(
        () => withEnv({ ...minimal, DEPENDABLY_BASE_URL: `https://dep.example.com${path}` }, loadConfig),
        /must not contain shell metacharacters/,
      );
    });
  }

  for (const url of ['https://a$(id).com', 'https://a;b.com/x', 'https://x`id`.com', "https://a'b.com"]) {
    it(`refuses a shell metacharacter in the host: ${url}`, () => {
      throws(() => withEnv({ ...minimal, DEPENDABLY_BASE_URL: url }, loadConfig), /must not contain shell metacharacters/);
    });
  }

  it('leaves a character the URL parser already percent-encodes harmless', () => {
    const cfg = withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'https://dep.example.com/a`id`' }, loadConfig);
    strictEqual(cfg.baseUrl, 'https://dep.example.com/a%60id%60');
  });

  for (const url of ['http://[::1]:8080', 'https://[fd00::5]/dependably']) {
    it(`accepts an IPv6 literal host: ${url}`, () => {
      const cfg = withEnv({ ...minimal, DEPENDABLY_BASE_URL: url }, loadConfig);
      ok(cfg.baseUrl.startsWith(url.replace(/\/$/, '')), cfg.baseUrl);
    });
  }

  it('accepts an ordinary path prefix and a port', () => {
    const cfg = withEnv({ ...minimal, DEPENDABLY_BASE_URL: 'https://dep.example.com:8443/dependably/' }, loadConfig);
    strictEqual(cfg.baseUrl, 'https://dep.example.com:8443/dependably');
  });
});
