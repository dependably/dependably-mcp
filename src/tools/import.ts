import { readFile, realpath } from 'node:fs/promises';
import { basename, resolve, sep } from 'node:path';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { DependablyApiError, describeFetchError, formatHttpError } from '../client.js';
import type { Config } from '../config.js';
import { run, withSummary } from '../format.js';

// Admin import writes new "uploaded" package versions. Non-destructive (it only adds
// versions; existing ones are deduped, never overwritten) but decidedly not read-only,
// and not idempotent (a second call re-imports / re-audits the same artefacts).
const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

// The controller detects each artefact's ecosystem from its *contents* (magic bytes +
// required manifest entry), so the tool never sends an ecosystem form field — a renamed
// file cannot lie and the caller does not have to declare a type. See ImportController
// class summary (ImportController.cs:15-31) and Upload (ImportController.cs:99).

const filePaths = z
  .array(z.string().min(1))
  .min(1)
  .describe('Paths to artefact files on the machine running this MCP server; every path must resolve inside DEPENDABLY_IMPORT_ROOT. Each file is read and streamed as a multipart part; the server auto-detects the ecosystem from the file contents.');

const dryRun = z
  .boolean()
  .optional()
  .describe('When true, the server validates every artefact and reports would_accept / would_reject without writing any blobs.');

/**
 * Design note — multipart over MCP.
 *
 * Both admin-import endpoints are multipart/form-data (the manifest endpoint parses a form,
 * not a JSON body — see ImportController.ImportManifest at ImportController.cs:284). The shared
 * JSON `DependablyClient` cannot express these requests, so this module issues a scoped raw
 * `fetch` that reuses the exact same base URL, bearer token and timeout the client uses,
 * keeping the JSON send path untouched. Files are addressed by local path: the MCP server
 * process reads them from disk. `fs.readFile` buffers each file fully into memory before it is
 * wrapped in a `Blob`; this is a deliberate simplification (see LIMITATIONS in the PR notes).
 * The server caps a batch at 1 GB total (ImportController.cs:73), which bounds worst-case usage.
 */
async function multipartPost(
  cfg: Config,
  path: string,
  form: FormData,
  query?: Record<string, string | number | boolean | undefined>,
): Promise<unknown> {
  const url = buildUrl(cfg.baseUrl, path, query);
  const headers: Record<string, string> = {
    // Identical auth to DependablyClient.request. Content-Type is intentionally omitted so
    // fetch derives the multipart boundary from the FormData body.
    Authorization: `Bearer ${cfg.token}`,
    Accept: 'application/json, application/problem+json',
  };

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers,
      body: form,
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
  } catch (err) {
    throw new Error(describeFetchError('POST', url, err, cfg.timeoutMs));
  }

  const text = await res.text();
  const ctype = res.headers.get('content-type') ?? '';

  if (!res.ok) {
    const message = formatHttpError('POST', url, res.status, ctype, text, res.headers);
    throw new DependablyApiError(message, res.status, 'POST', url, text);
  }

  if (res.status === 204 || text.length === 0) return null;
  if (ctype.includes('application/json') || ctype.includes('application/problem+json')) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

function buildUrl(
  baseUrl: string,
  path: string,
  query?: Record<string, string | number | boolean | undefined>,
): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(`${baseUrl}${p}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === '') continue;
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

/**
 * Resolve a user-supplied path and require it to live under the import root.
 * realpath both requires the file to exist and resolves symlinks, so a link
 * placed inside the root that points outside it is refused as well.
 */
async function resolveWithinRoot(root: string, path: string): Promise<string> {
  let real: string;
  try {
    real = await realpath(resolve(path));
  } catch {
    throw new Error(`File not found: ${path}`);
  }
  const rootReal = await realpath(root);
  if (real !== rootReal && !real.startsWith(rootReal + sep)) {
    throw new Error(
      `Refusing to read ${path}: it resolves outside DEPENDABLY_IMPORT_ROOT (${root}).`,
    );
  }
  return real;
}

async function appendFile(form: FormData, field: string, root: string, path: string): Promise<void> {
  const real = await resolveWithinRoot(root, path);
  const buf = await readFile(real);
  // new Uint8Array(buf) avoids a SharedArrayBuffer typing mismatch on Blob's BlobPart.
  form.append(field, new Blob([new Uint8Array(buf)]), basename(real));
}

function summarize(response: unknown): string {
  if (response && typeof response === 'object') {
    const r = response as Record<string, unknown>;
    const parts: string[] = [];
    if (typeof r.mode === 'string') parts.push(String(r.mode));
    if (typeof r.accepted === 'number') parts.push(`${r.accepted} accepted`);
    if (typeof r.rejected === 'number') parts.push(`${r.rejected} rejected`);
    if (typeof r.batch_id === 'string') parts.push(`batch ${r.batch_id}`);
    if (parts.length > 0) return `Import complete: ${parts.join(', ')}.`;
  }
  return 'Import complete.';
}

export function registerImportTools(server: McpServer, cfg: Config): void {
  const root = cfg.importRoot;
  if (!root) {
    throw new Error('registerImportTools requires cfg.importRoot (DEPENDABLY_IMPORT_ROOT)');
  }

  server.registerTool(
    'admin_upload',
    {
      title: 'Admin bulk upload',
      description:
        'Air-gapped bulk import: upload N local artefact files (any supported ecosystem) as "uploaded" package versions. POST /api/v1/admin/upload (multipart). The server detects each file\'s ecosystem from its contents — no ecosystem argument. One bad file is rejected per-file; the rest of the batch proceeds. Requires a token with the import-all capability. Files are read from the machine running this MCP server and must live under DEPENDABLY_IMPORT_ROOT.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        files: filePaths,
        dry_run: dryRun,
      },
    },
    async (args) =>
      run(async () => {
        const form = new FormData();
        for (const path of args.files) {
          // Field name "files"; the controller accepts any field except "sha256sums".
          await appendFile(form, 'files', root, path);
        }
        const response = await multipartPost(cfg, '/api/v1/admin/upload', form, {
          dryRun: args.dry_run,
        });
        return withSummary(summarize(response), response);
      }),
  );

  server.registerTool(
    'import_manifest',
    {
      title: 'Import from manifest',
      description:
        'Manifest-driven, all-or-nothing import: a lockfile (package-lock.json, requirements.txt, packages.lock.json, Pipfile.lock, or poetry.lock) plus every artefact it references. POST /api/v1/admin/import/manifest (multipart). The server pre-validates manifest↔artefact correspondence and hashes before writing anything; any mismatch rejects the entire batch with a 422 report. Requires a token with the import-all capability. All paths are read from the machine running this MCP server and must live under DEPENDABLY_IMPORT_ROOT.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        manifest_path: z
          .string()
          .min(1)
          .describe('Path to the lockfile (package-lock.json, requirements.txt, packages.lock.json, Pipfile.lock, or poetry.lock). Sent as the "manifest" multipart part.'),
        files: filePaths,
        dry_run: dryRun,
      },
    },
    async (args) =>
      run(async () => {
        const form = new FormData();
        await appendFile(form, 'manifest', root, args.manifest_path);
        for (const path of args.files) {
          await appendFile(form, 'files', root, path);
        }
        const response = await multipartPost(cfg, '/api/v1/admin/import/manifest', form, {
          dryRun: args.dry_run,
        });
        return withSummary(summarize(response), response);
      }),
  );
}
