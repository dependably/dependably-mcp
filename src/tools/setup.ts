import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { Config } from '../config.js';
import type { ToolResult } from '../format.js';
import { SETUP_ECOSYSTEMS } from '../ecosystems.js';

const ecosystem = z.enum(SETUP_ECOSYSTEMS).describe('Package ecosystem the command targets.');

const LOCAL_READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/**
 * Field patterns for `package`, `version` and `artifact_path`.
 *
 * These commands are emitted into a fence the user is told to copy and paste
 * into a shell, so a value that survives validation is one keystroke away from
 * running. The patterns bound what an ecosystem name/version can legitimately
 * contain (npm scopes and OCI refs need `/` and `:`; SemVer-ish versions need
 * `.+-`); a leading `-` is rejected everywhere so a value can never be read as
 * a flag by the command it is interpolated into.
 */
const NAME_PATTERN = /^(?!-)[A-Za-z0-9@._+/:-]+$/;
const VERSION_PATTERN = /^(?!-)[A-Za-z0-9._+!~^-]+$/;
const ARTIFACT_PATH_PATTERN = /^(?!-)[^;|&$`<>()\s]+$/;

const packageName = z
  .string()
  .regex(NAME_PATTERN, 'Package name may only contain letters, digits, and @ . _ + - / : and must not start with -.')
  .describe('Package name (canonical for the ecosystem).');

const pinnedVersion = z
  .string()
  .regex(VERSION_PATTERN, 'Version may only contain letters, digits, and . _ + - ! ~ ^, no whitespace, and must not start with -.')
  .optional()
  .describe('Optional pinned version.');

const artifactPath = z
  .string()
  .regex(ARTIFACT_PATH_PATTERN, 'Artifact path must not contain shell metacharacters (; | & $ ` < > ( ) or whitespace) or start with -.')
  .describe('Path to the built artifact (e.g. ./dist/*, ./bin/Release/*.nupkg, package.tgz).');

/**
 * Single-quote a value so it cannot be read as more than one shell word, even
 * if it somehow passed the regex validation above. Defence in depth: the
 * schema is the primary control, this is the fallback that holds if it is not.
 */
function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function fenced(lang: string, body: string): ToolResult {
  return { content: [{ type: 'text', text: `\`\`\`${lang}\n${body}\n\`\`\`` }] };
}

export function registerSetupTools(server: McpServer, cfg: Config): void {
  server.registerTool(
    'get_install_command',
    {
      title: 'Install command',
      description: 'Build the shell command that installs a package through this Dependably instance. Returns the command as text only; nothing is executed. The output is for the user to review and run themselves.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: z.object({
        ecosystem,
        package: packageName,
        version: pinnedVersion,
      }).strict(),
    },
    async (args) => installCommand(cfg.baseUrl, args.ecosystem, args.package, args.version),
  );

  server.registerTool(
    'get_publish_command',
    {
      title: 'Publish command',
      description: 'Build the shell command that publishes an artefact through this Dependably instance. Returns the command as text only; nothing is executed. The placeholder <token> must be replaced by the user with a valid Dependably token.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: z.object({
        ecosystem,
        artifact_path: artifactPath,
      }).strict(),
    },
    async (args) => publishCommand(cfg.baseUrl, args.ecosystem, args.artifact_path),
  );
}

function stripScheme(url: string): string {
  return url.replace(/^https?:\/\//, '');
}

/** True when the base URL carries a path component beyond the host, e.g. `https://host/dependably`. */
function hasPathPrefix(base: string): boolean {
  return new URL(base).pathname !== '/';
}

/**
 * Build the install command for one ecosystem.
 *
 * Lifted out of the tool handler so the handler is a single delegation. The
 * branching is inherent — eight ecosystems, each with its own flag spelling and
 * version syntax — and reads better as one table-like switch than as a map of
 * closures that would hide the shape of each command.
 */
/**
 * Join a package name to an optional pinned version with the separator the
 * ecosystem uses (`@`, `==`, `:`, `-`). Unpinned yields the bare name. The
 * combined string is one shell word at every call site, so it is quoted as a
 * whole with {@link shq} rather than field-by-field.
 *
 * Each case used to do this inline with its own ternary; hoisting it keeps the
 * switch a flat table of command shapes, which is the part worth reading.
 */
function pinned(pkg: string, separator: string, ver: string | undefined): string {
  return ver ? `${pkg}${separator}${ver}` : pkg;
}

/** `<prefix><quoted ver>` when a version is pinned, otherwise the empty string. */
function flag(prefix: string, ver: string | undefined): string {
  return ver ? `${prefix}${shq(ver)}` : '';
}

function installCommand(base: string, ecosystem: string, pkg: string, ver: string | undefined): ToolResult {
  switch (ecosystem) {
    case 'npm':
      return fenced('bash', `npm install --registry=${base}/npm/ ${shq(pinned(pkg, '@', ver))}`);
    case 'pypi':
      return fenced(
        'bash',
        `# Put index-url = ${base}/simple/ with your token in ~/.pip/pip.conf (or ~/.netrc) first\npip install --index-url ${base}/simple/ ${shq(pinned(pkg, '==', ver))}`,
      );
    case 'nuget':
      return fenced(
        'bash',
        `# dotnet nuget add source ${base}/nuget/v3/index.json --name dependably --username user --password <token> first\ndotnet add package ${shq(pkg)}${flag(' --version ', ver)} --source ${base}/nuget/v3/index.json`,
      );
    case 'maven': {
      const artifact = ver ? `${pkg}:${ver}` : `${pkg}:LATEST`;
      const note = ver ? '' : '\n# pin a version in production';
      return fenced(
        'bash',
        `# Add ${base}/maven/ as a <repository> in your pom.xml or settings.xml, then:\nmvn dependency:get -Dartifact=${shq(artifact)}${note}`,
      );
    }
    case 'rpm':
      return fenced(
        'bash',
        `# Add ${base}/rpm/ as a dnf repo (baseurl) first, then:\ndnf install ${shq(pinned(pkg, '-', ver))}`,
      );
    case 'oci': {
      const host = stripScheme(base);
      const note = hasPathPrefix(base)
        ? '\n# Note: OCI registries cannot live under a URL path; use the instance host directly'
        : '';
      return fenced(
        'bash',
        `# docker login ${host} first\ndocker pull ${host}/${shq(pkg)}:${ver ? shq(ver) : 'latest'}${note}`,
      );
    }
    case 'golang': {
      const host = stripScheme(base);
      return fenced(
        'bash',
        `# Add ${host} credentials to ~/.netrc and set GONOSUMDB=${host} first\nGOPROXY=${base}/go,direct go get ${shq(pkg)}@${ver ? shq(ver) : 'latest'}`,
      );
    }
    case 'cargo':
      return fenced(
        'bash',
        `# In ~/.cargo/config.toml:\n#   [registries.dependably]\n#   index = "sparse+${base}/cargo/"\ncargo add ${shq(pinned(pkg, '@', ver))} --registry dependably`,
      );
    default:
      throw new Error(`Unsupported ecosystem: ${ecosystem}`);
  }
}

/**
 * Build the publish command for one ecosystem. Split from the tool handler for
 * the same reason as {@link installCommand}: the per-ecosystem branching is the
 * content, and it does not belong inline in a registration.
 */
function publishCommand(base: string, ecosystem: string, artifactPath: string): ToolResult {
  const p = shq(artifactPath);
  switch (ecosystem) {
    case 'npm':
      return fenced(
        'bash',
        `# Requires .npmrc with //${stripScheme(base)}/npm/:_authToken=<token>\nnpm publish --registry=${base}/npm/ ${p}`,
      );
    case 'pypi':
      return fenced(
        'bash',
        `twine upload --repository-url ${base}/pypi/legacy/ -u user -p <token> ${p}`,
      );
    case 'nuget':
      return fenced(
        'bash',
        `dotnet nuget push ${p} --source ${base}/nuget/v3/index.json --api-key <token>`,
      );
    case 'maven':
      return fenced(
        'bash',
        `# Configure ${base}/maven/ as a distributionManagement repo in pom.xml,\n# add server credentials (user / <token>) to settings.xml, then:\nmvn deploy`,
      );
    case 'rpm':
      return fenced('bash', `curl -u <user>:<token> --upload-file ${p} ${base}/rpm/upload`);
    case 'oci': {
      const host = stripScheme(base);
      return fenced(
        'bash',
        `docker login ${host}\ndocker tag ${p} ${host}/<image>:<tag>\ndocker push ${host}/<image>:<tag>`,
      );
    }
    case 'golang':
      // Informational, not an error: there is simply no publish command to return.
      return {
        content: [
          {
            type: 'text',
            text: 'Go is proxy-only — there is no hosted publish/upload endpoint. Publish by pushing a version tag to the module\'s VCS repo; the proxy fetches it on first request.',
          },
        ],
      };
    case 'cargo':
      return fenced(
        'bash',
        `# Requires [registries.dependably] in ~/.cargo/config.toml.\n# Run from the crate directory (${p}):\ncargo publish --registry dependably`,
      );
  }
  throw new Error(`Unsupported ecosystem: ${ecosystem}`);
}
