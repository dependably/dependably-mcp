import { deepStrictEqual, ok, strictEqual } from 'node:assert';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { DependablyClient } from '../dist/client.js';
import { buildServer } from '../dist/server.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const base = { baseUrl: 'https://dep.example.com', token: 'tok', timeoutMs: 5000 };

/**
 * Spawns `dist/index.js` as a real child process (no in-memory transport), the
 * way a Claude Desktop host actually launches this server: over stdio, against
 * an instance that is up but unreachable (127.0.0.1:9). This is the surface an
 * Anthropic reviewer would drive first, and it is the only place that would
 * catch a stray `console.log` or an unhandled rejection landing on stdout and
 * corrupting the JSON-RPC stream.
 */
function driveChildProcess() {
  const child = spawn('node', [join(root, 'dist/index.js')], {
    cwd: root,
    env: {
      ...process.env,
      DEPENDABLY_BASE_URL: 'http://127.0.0.1:9',
      DEPENDABLY_TOKEN: 'dpb_test',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderrBuf = '';
  child.stderr.on('data', (d) => {
    stderrBuf += d.toString();
  });

  const pending = new Map();
  let stdoutBuf = '';
  const rawStdoutLines = [];
  child.stdout.on('data', (d) => {
    stdoutBuf += d.toString();
    let i;
    while ((i = stdoutBuf.indexOf('\n')) >= 0) {
      const line = stdoutBuf.slice(0, i);
      stdoutBuf = stdoutBuf.slice(i + 1);
      if (!line.trim()) continue;
      rawStdoutLines.push(line);
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id !== undefined && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    }
  });

  let nextId = 1;
  function rpc(method, params) {
    const id = nextId++;
    const req = { jsonrpc: '2.0', id, method, ...(params ? { params } : {}) };
    return new Promise((resolve) => {
      const t = setTimeout(() => resolve({ id, TIMEOUT: true }), 15000);
      pending.set(id, (m) => {
        clearTimeout(t);
        resolve(m);
      });
      child.stdin.write(JSON.stringify(req) + '\n');
    });
  }
  function notify(method, params) {
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, ...(params ? { params } : {}) }) + '\n');
  }

  return { child, rpc, notify, rawStdoutLines, stderr: () => stderrBuf };
}

describe('server over a real child process (stdio)', () => {
  it('speaks clean JSON-RPC on stdout, reports serverInfo, logs exactly one fallback line to stderr, exits 0 on stdin close', async () => {
    const { child, rpc, notify, rawStdoutLines, stderr } = driveChildProcess();

    // A failing assertion below must not leave this process running: node:test
    // would otherwise hang waiting for the child's stdio pipes to close, timing
    // out the whole run instead of reporting the failure. SIGKILL after the
    // process has already exited (the success path) is a harmless no-op.
    try {
      const init = await rpc('initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'server-test', version: '0.0.1' },
      });
      notify('notifications/initialized');
      const list = await rpc('tools/list', {});

      ok(!init.TIMEOUT, 'initialize should not time out');
      ok(!list.TIMEOUT, 'tools/list should not time out');
      deepStrictEqual(init.result.serverInfo, { name: 'dependably-mcp', version: pkg.version });
      ok(
        typeof init.result.instructions === 'string' && init.result.instructions.includes('readiness_check'),
        'initialize result should carry instructions that point at readiness_check',
      );
      ok(Array.isArray(list.result.tools) && list.result.tools.length > 0, 'tools/list should return tools');

      for (const line of rawStdoutLines) {
        let parsed;
        try {
          parsed = JSON.parse(line);
        } catch (e) {
          throw new Error(`stdout line did not parse as JSON: ${line}\n${e.message}`);
        }
        ok(parsed.jsonrpc === '2.0', `every stdout line must be JSON-RPC 2.0: ${line}`);
      }

      // The instance at 127.0.0.1:9 is unreachable, so startup falls back to the
      // built-in ecosystem list and logs exactly one line naming why — never a
      // stray line, never silence about a fallback that changes tool schemas.
      assertOneFallbackLine(stderr());

      const listPackagesSchema = list.result.tools.find((t) => t.name === 'list_packages')?.inputSchema;
      deepStrictEqual(
        listPackagesSchema?.properties?.ecosystem?.enum,
        ['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo', 'apk', 'terraform', 'hex'],
        'tools/list still returns every tool with the fallback registry enum when the instance is unreachable',
      );

      const exitInfo = await new Promise((resolve) => {
        const t = setTimeout(() => resolve({ exited: false }), 5000);
        child.on('exit', (code, signal) => {
          clearTimeout(t);
          resolve({ exited: true, code, signal });
        });
        child.stdin.end();
      });

      if (!exitInfo.exited) {
        throw new Error('process did not exit within 5s of stdin closing');
      }
      strictEqual(exitInfo.code, 0, `process should exit 0 when stdin closes, got code=${exitInfo.code} signal=${exitInfo.signal}`);
      assertOneFallbackLine(stderr());
    } finally {
      child.kill('SIGKILL');
    }
  });
});

/**
 * Exactly one line matching the fallback-startup message, and nothing else —
 * a stray extra line (e.g. an unrelated warning) or silence (the fallback
 * happened but nothing was logged) both fail this. Also bounds the line's
 * length: the reason comes from `fetchEcosystems`, which never echoes a
 * response body, so nothing here should ever approach an unbounded size.
 */
function assertOneFallbackLine(stderrText) {
  const lines = stderrText.split('\n').filter((l) => l.length > 0);
  deepStrictEqual(lines.length, 1, `stderr should carry exactly one line, got: ${JSON.stringify(lines)}`);
  ok(
    /^dependably-mcp: using the built-in ecosystem list; /.test(lines[0]),
    `stderr line should report the ecosystem fallback, got: ${lines[0]}`,
  );
  ok(lines[0].length < 200, `stderr line should be short, got ${lines[0].length} chars: ${lines[0]}`);
}

describe('every registered tool advertises read-only annotations', () => {
  it('has a non-empty title, readOnlyHint true and destructiveHint false', async () => {
    const server = buildServer(new DependablyClient(base), base);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'server-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const { tools } = await client.listTools();
      ok(tools.length > 0, 'the server should register at least one tool');
      for (const tool of tools) {
        ok(typeof tool.title === 'string' && tool.title.length > 0, `${tool.name} must have a non-empty title`);
        ok(tool.annotations, `${tool.name} must declare annotations`);
        strictEqual(tool.annotations.readOnlyHint, true, `${tool.name} must be readOnlyHint: true`);
        strictEqual(tool.annotations.destructiveHint, false, `${tool.name} must be destructiveHint: false`);
      }
    } finally {
      await client.close();
      await server.close();
    }
  });
});
