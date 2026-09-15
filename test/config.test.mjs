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
  'DEPENDABLY_IMPORT_ROOT',
  'DEPENDABLY_TOOLSET',
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

  it('accepts a positive number', () => {
    withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: '1500' }, () =>
      strictEqual(loadConfig().timeoutMs, 1500),
    );
  });

  it('rejects zero, negative and non-numeric values', () => {
    for (const v of ['0', '-1', 'abc']) {
      withEnv({ ...minimal, DEPENDABLY_TIMEOUT_MS: v }, () =>
        throws(loadConfig, /must be a positive number/),
      );
    }
  });
});

describe('loadConfig toolset', () => {
  it('defaults to full', () => {
    withEnv(minimal, () => strictEqual(loadConfig().toolset, 'full'));
  });

  it('accepts remote', () => {
    withEnv({ ...minimal, DEPENDABLY_TOOLSET: 'remote' }, () =>
      strictEqual(loadConfig().toolset, 'remote'),
    );
  });

  it('rejects anything else', () => {
    withEnv({ ...minimal, DEPENDABLY_TOOLSET: 'partial' }, () =>
      throws(loadConfig, /must be "full" or "remote"/),
    );
  });
});

describe('loadConfig import root', () => {
  it('is undefined when unset, which is what leaves the import tools unregistered', () => {
    withEnv(minimal, () => strictEqual(loadConfig().importRoot, undefined));
  });

  it('resolves an existing directory to an absolute path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-cfg-'));
    withEnv({ ...minimal, DEPENDABLY_IMPORT_ROOT: dir }, () => {
      const root = loadConfig().importRoot;
      ok(root.startsWith('/'));
      ok(root.endsWith(dir.split('/').pop()));
    });
  });

  it('rejects a path that does not exist', () => {
    withEnv({ ...minimal, DEPENDABLY_IMPORT_ROOT: '/definitely/not/here/xyz' }, () =>
      throws(loadConfig, /does not exist/),
    );
  });

  it('rejects a file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dep-cfg-'));
    const file = join(dir, 'f.txt');
    writeFileSync(file, 'x');
    withEnv({ ...minimal, DEPENDABLY_IMPORT_ROOT: file }, () =>
      throws(loadConfig, /must be a directory/),
    );
  });
});

afterEach(() => {
  for (const k of KEYS) delete process.env[k];
});
