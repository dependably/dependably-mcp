import { realpath } from 'node:fs/promises';
import { resolve, sep } from 'node:path';

/**
 * Resolve a caller-supplied path and require it to live under `root`.
 *
 * `realpath` both requires the target to exist and resolves symlinks, so a link
 * placed inside the root that points outside it is refused as well. `envName`
 * names the setting in the refusal so the message tells the user what to change.
 *
 * Shared by every tool that reads local files; each such tool is registered only
 * when its root is configured, which is what keeps arbitrary file reads off the
 * default tool surface.
 */
export async function resolveWithinRoot(root: string, path: string, envName: string): Promise<string> {
  let real: string;
  try {
    real = await realpath(resolve(path));
  } catch {
    throw new Error(`File not found: ${path}`);
  }
  const rootReal = await realpath(root);
  if (real !== rootReal && !real.startsWith(rootReal + sep)) {
    throw new Error(`Refusing to read ${path}: it resolves outside ${envName} (${root}).`);
  }
  return real;
}
