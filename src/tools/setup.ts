import type { McpServer, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { Config } from '../config.js';
import { err, type ToolResult } from '../format.js';
import { FALLBACK_SETUP_ECOSYSTEMS, enumOf, type EcosystemPlanes } from '../ecosystems.js';

type SetupEcosystem = (typeof FALLBACK_SETUP_ECOSYSTEMS)[number];

const LOCAL_READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/**
 * These commands are emitted into a fence the user is told to copy and paste
 * into a shell, so a value that survives validation is one keystroke away from
 * running. A single shared name pattern is not enough: each ecosystem's own
 * client reads a name that merely "looks plausible" as a source redirection —
 * npm installs a bare URL or a `host:path` git shorthand instead of resolving
 * against `--registry`, pip and dnf do the same for a URL, and a `../` segment
 * reads as a local path. So `package` is validated per ecosystem below, not
 * against one pattern loose enough to fit all eight. `version` and
 * `artifact_path` are not ecosystem-specific and keep one pattern each.
 * A leading `-` is rejected everywhere so a value can never be read as a flag
 * by the command it is interpolated into.
 */
function noDotDotOrScheme(name: string): boolean {
  return !name.includes('://') && !name.split('/').includes('..');
}

interface NameRule {
  test: (name: string) => boolean;
  message: string;
}

const NAME_RULES: Record<SetupEcosystem, NameRule> = {
  npm: {
    // Scopes are lowercase-only; the name part may carry upper-case letters,
    // which npm still serves for packages registered before 2017 (JSONStream).
    test: (n) => /^(@[a-z0-9][a-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/.test(n),
    message: 'npm package names are optionally scoped (@scope/name, lowercase scope) and made of letters, digits, . _ - only — no URL, no git shorthand.',
  },
  pypi: {
    test: (n) => /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(n),
    message: 'pypi package names (PEP 508) are letters, digits, . _ - only; extras and direct references (URLs, VCS refs) are not accepted.',
  },
  nuget: {
    test: (n) => /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(n),
    message: 'NuGet package ids are letters, digits, . _ - only; no / or :.',
  },
  maven: {
    test: (n) => /^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$/.test(n),
    message: 'Maven coordinates are exactly groupId:artifactId — one colon, no /.',
  },
  rpm: {
    test: (n) => /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(n),
    message: 'rpm package names are letters, digits, . _ + - only; no / or :.',
  },
  oci: {
    test: (n) => /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/.test(n) && noDotDotOrScheme(n),
    message: 'OCI repository names are lowercase path segments (e.g. library/nginx) — no scheme, no .. segment; the tag comes from version.',
  },
  golang: {
    test: (n) => /^[a-z0-9.-]+(\/[A-Za-z0-9._~-]+)+$/.test(n) && noDotDotOrScheme(n),
    message: 'Go module paths are a host-like first segment plus at least one path segment (e.g. github.com/org/repo) — no .. segment.',
  },
  cargo: {
    test: (n) => /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(n),
    message: 'Cargo crate names are letters, digits, _ - only.',
  },
};

/**
 * What the command builders below actually know how to spell — read from
 * {@link NAME_RULES}'s own keys rather than hand-listed again, so this set
 * cannot drift from the switches in {@link installCommand} and
 * {@link publishCommand}. `planes.setup` is intersected against this set: an
 * instance may advertise an ecosystem (e.g. `hex`) that no builder here knows,
 * and that ecosystem is withheld rather than offered with no command to give.
 */
const BUILDER_ECOSYSTEMS = new Set<string>(Object.keys(NAME_RULES));

/** `planes.setup`, narrowed to the ecosystems a builder here actually knows. */
function offeredSetupEcosystems(setupPlane: readonly string[]): string[] {
  return setupPlane.filter((eco) => BUILDER_ECOSYSTEMS.has(eco));
}

const VERSION_PATTERN = /^(?!-)[A-Za-z0-9._+!~^-]+$/;
const VERSION_MESSAGE = 'Version may only contain letters, digits, and . _ + - ! ~ ^, no whitespace, and must not start with -.';

/**
 * Glob characters are rejected outright rather than quoted: the tool's own
 * describe text used to invite `./dist/*`, but {@link shq} would have single
 * quoted that literally, silently turning a working glob into a no-op. Spaces
 * are allowed — shq() quotes them safely — so real paths like
 * `/Users/me/My Builds/out.rpm` still work; only shell metacharacters,
 * newlines, glob characters and a leading `-` are rejected.
 */
const ARTIFACT_PATH_PATTERN = /^(?!-)[^;|&$`<>()\n*?[\]{}]+$/;
const ARTIFACT_PATH_MESSAGE =
  'Artefact path must not contain shell metacharacters (; | & $ ` < > ( ) or newlines), shell glob characters (* ? [ ] { }), or start with -. Spaces are fine, but name one file — globs are not expanded.';

/** `""`/whitespace-only means "unpinned", the same as omitting the field entirely. */
const versionField = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? undefined : v))
  .refine((v) => v === undefined || VERSION_PATTERN.test(v), { message: VERSION_MESSAGE })
  .describe('Optional pinned version. An empty string is treated as unpinned.');

const artifactPath = z
  .string()
  .regex(ARTIFACT_PATH_PATTERN, ARTIFACT_PATH_MESSAGE)
  .describe('Path to one built artefact file (e.g. ./dist/package.tgz, ./bin/Release/My.Pkg.1.0.0.nupkg). Shell globs are not accepted; name the file.');

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

export function registerSetupTools(server: McpServer, cfg: Config, planes: EcosystemPlanes): RegisteredTool[] {
  const ecosystem = enumOf(offeredSetupEcosystems(planes.setup), FALLBACK_SETUP_ECOSYSTEMS).describe(
    'Package ecosystem the command targets.',
  );

  const tools: RegisteredTool[] = [];

  tools.push(server.registerTool(
    'get_install_command',
    {
      title: 'Install command',
      description: 'Build the shell command that installs a package through this Dependably instance. Returns the command as text only; nothing is executed. The output is for the user to review and run themselves.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: z
        .object({
          ecosystem,
          package: z
            .string()
            .describe('Package name (canonical for the ecosystem, e.g. a scoped npm name or a Maven groupId:artifactId coordinate). Validated per ecosystem.'),
          version: versionField,
        })
        .strict(),
    },
    // `package` is validated per ecosystem here rather than in the schema: a
    // schema-level object refinement (`.superRefine`/`z.discriminatedUnion`)
    // turns the whole inputSchema into a ZodEffects/union that the SDK's JSON
    // Schema converter cannot read a shape out of (it reports `properties: {}`
    // to the client, hiding every field). Keeping the schema a plain object
    // preserves the advertised schema; the per-ecosystem check still runs
    // before any command text is built.
    async (args) => {
      // `args.ecosystem` is drawn from `offeredSetupEcosystems`, which is
      // already filtered to keys of NAME_RULES — this lookup cannot actually
      // miss, but the enum built from a runtime vocabulary is typed as a
      // plain string, so TypeScript cannot see that on its own.
      const rule = NAME_RULES[args.ecosystem as SetupEcosystem];
      if (!rule) return err(`Unsupported ecosystem: ${args.ecosystem}`);
      if (!rule.test(args.package)) return err(rule.message);
      return installCommand(cfg.baseUrl, args.ecosystem, args.package, args.version);
    },
  ));

  tools.push(server.registerTool(
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
  ));

  return tools;
}

function stripScheme(url: string): string {
  return url.replace(/^https?:\/\//, '');
}

/** True when the base URL carries a path component beyond the host, e.g. `https://host/dependably`. */
function hasPathPrefix(base: string): boolean {
  return new URL(base).pathname !== '/';
}

/**
 * The bare `host[:port]`, with no scheme and no path prefix. Some destinations
 * — `docker login`, a `.netrc` `machine` entry, `GONOSUMDB` — parse their
 * argument as a hostname, not a URL; handing them a path-prefixed base (as
 * `stripScheme` would) makes them target the wrong thing. Places that expect
 * an actual URL (`GOPROXY`, `--index-url`, `--registry`) keep the full base.
 */
function hostOnly(base: string): string {
  return new URL(base).host;
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
    case 'pypi': {
      const host = hostOnly(base);
      return fenced(
        'bash',
        `# Put your token in ~/.netrc for ${host} (machine ${host} login user password <token>) first\npip install --index-url ${base}/simple/ ${shq(pinned(pkg, '==', ver))}`,
      );
    }
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
      const loginHost = hostOnly(base);
      const pullHost = stripScheme(base);
      const note = hasPathPrefix(base)
        ? '\n# Note: OCI registries cannot live under a URL path; use the instance host directly'
        : '';
      return fenced(
        'bash',
        `# docker login ${loginHost} first\ndocker pull ${pullHost}/${shq(pkg)}:${ver ? shq(ver) : 'latest'}${note}`,
      );
    }
    case 'golang': {
      const host = hostOnly(base);
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
      const loginHost = hostOnly(base);
      const refHost = stripScheme(base);
      return fenced(
        'bash',
        `docker login ${loginHost}\ndocker tag ${p} ${refHost}/<image>:<tag>\ndocker push ${refHost}/<image>:<tag>`,
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
