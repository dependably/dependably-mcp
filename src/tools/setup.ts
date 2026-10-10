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
 * against one pattern loose enough to fit them all. `version` and
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

const TERRAFORM_HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d+)?$/;
const TERRAFORM_PART = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;

/** `[hostname/]namespace/type`, each segment checked against its own grammar. */
function isTerraformSource(name: string): boolean {
  const segments = name.split('/');
  if (segments.length !== 2 && segments.length !== 3) return false;
  const host = segments.length === 3 ? segments[0] : undefined;
  const [namespace, type] = segments.slice(-2);
  if (host !== undefined && !TERRAFORM_HOST.test(host)) return false;
  return TERRAFORM_PART.test(namespace) && TERRAFORM_PART.test(type);
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
  apk: {
    test: (n) => /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(n),
    message: 'apk package names are letters, digits, . _ + - only; no / or =, and the version comes from version.',
  },
  terraform: {
    // A provider source address, [hostname/]namespace/type. It is interpolated
    // into an HCL string and its last segment becomes an HCL attribute name, so
    // nothing outside these characters may reach either position.
    // Namespace and type follow Terraform's own part grammar: letters, digits
    // and dashes, not starting or ending with a dash.
    test: isTerraformSource,
    message: 'Terraform provider sources are [hostname/]namespace/type (e.g. registry.terraform.io/hashicorp/aws): letters, digits and - only, no scheme.',
  },
  hex: {
    // The name becomes an Elixir atom literal (`{:name, …}`), so anything
    // beyond a plain lowercase atom would let it add options to the dependency.
    test: (n) => /^[a-z][a-z0-9_]*$/.test(n),
    message: 'Hex package names are lowercase letters, digits and _ only, starting with a letter.',
  },
};

/**
 * What the command builders below actually know how to spell — read from
 * {@link NAME_RULES}'s own keys rather than hand-listed again, so this set
 * cannot drift from the switches in {@link installCommand} and
 * {@link publishCommand}. `planes.setup` is intersected against this set: an
 * instance may advertise an ecosystem that no builder here knows,
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
const ARTIFACT_PATH_FORBIDDEN = new Set(';|&$`<>()*?[]{}');

function isSafeArtifactPath(path: string): boolean {
  if (path.length === 0 || path.startsWith('-')) return false;
  for (const ch of path) {
    const code = ch.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f || ARTIFACT_PATH_FORBIDDEN.has(ch)) return false;
  }
  return true;
}
const ARTIFACT_PATH_MESSAGE =
  'Artefact path must not contain shell metacharacters (; | & $ ` < > ( ) or newlines), control characters, shell glob characters (* ? [ ] { }), or start with -. Spaces are fine, but name one file — globs are not expanded.';

/** `""`/whitespace-only means "unpinned", the same as omitting the field entirely. */
const versionField = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? undefined : v))
  .refine((v) => v === undefined || VERSION_PATTERN.test(v), { message: VERSION_MESSAGE })
  .describe('Optional pinned version. An empty string is treated as unpinned.');

const artifactPath = z
  .string()
  .refine(isSafeArtifactPath, { message: ARTIFACT_PATH_MESSAGE })
  .describe('Path to one built artefact file (e.g. ./dist/package.tgz, ./bin/Release/My.Pkg.1.0.0.nupkg, an image tarball from docker save). For cargo and hex, which publish from source, the package directory. Shell globs are not accepted; name the file.');

/**
 * Single-quote a value so it cannot be read as more than one shell word, even
 * if it somehow passed the regex validation above. Defence in depth: the
 * schema is the primary control, this is the fallback that holds if it is not.
 */
function shq(value: string): string {
  const escaped = value.replace(/'/g, "'\\''");
  return `'${escaped}'`;
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
      description: 'Build the shell command that publishes an artefact through this Dependably instance. Returns the command as text only; nothing is executed. No command carries the token itself: it is read without echo (read -rs), prompted for, or kept in a config file the comments name.',
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

/** Informational, not an error: a proxy-only ecosystem simply has no publish command to return. */
function proxyOnly(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

/**
 * A line that reads a secret into an exported variable without echoing it or
 * leaving it in shell history, which a token typed into the command line would.
 */
function readSecret(variable: string): string {
  return `read -rs ${variable} && export ${variable}   # paste your token; it is not echoed or saved to history`;
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end--;
  return value.slice(0, end);
}

/**
 * The directory a source-built ecosystem publishes from. The path names the
 * directory itself or the ecosystem's manifest in it (Cargo.toml, mix.exs).
 * Only the manifest is taken to be a file: a directory name can hold a dot,
 * as `cargo package` leaves target/package/foo-0.1.0.
 */
function directoryOf(path: string, manifest: string): string {
  const trimmed = trimTrailingSlashes(path) || '/';
  const last = trimmed.split('/').pop() ?? '';
  if (last !== manifest) return trimmed;
  const parent = trimmed.slice(0, trimmed.length - last.length);
  if (parent === '') return '.';
  return trimTrailingSlashes(parent) || '/';
}

function stripScheme(url: string): string {
  return url.replace(/^https?:\/\//, '');
}

/** True when the base URL carries a path component beyond the host, e.g. `https://host/dependably`. */
function hasPathPrefix(base: string): boolean {
  return new URL(base).pathname !== '/';
}

/**
 * The hostname alone, for pip's `.netrc` `machine` entry: requests looks netrc
 * up by hostname without the port, so `host:8443` would never match and
 * authentication would silently fail. Go is the opposite (it matches
 * `host:port`), so its netrc line uses {@link hostOnly}.
 */
function netrcHost(base: string): string {
  return new URL(base).hostname;
}

/**
 * The bare `host[:port]`, with no scheme and no path prefix. Some destinations
 * — `docker login`, Go's `.netrc` `machine` entry — parse their argument as a
 * host, not a URL; handing them a path-prefixed base (as `stripScheme` would)
 * makes them target the wrong thing. Places that expect an actual URL
 * (`GOPROXY`, `--index-url`, `--registry`) keep the full base.
 */
function hostOnly(base: string): string {
  return new URL(base).host;
}

/**
 * Build the install command for one ecosystem.
 *
 * Lifted out of the tool handler so the handler is a single delegation. The
 * branching is inherent — each ecosystem has its own flag spelling and version
 * syntax — and reads better as one table-like switch than as a map of
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

/** The quoted pinned version, or the literal `latest` when none is pinned. */
function orLatest(ver: string | undefined): string {
  return ver ? shq(ver) : 'latest';
}

/**
 * Not a shell command: providers are declared in configuration and fetched
 * through a network mirror set once in the CLI config.
 */
function terraformInstall(base: string, pkg: string, ver: string | undefined): ToolResult {
  const localName = pkg.split('/').pop();
  const version = ver ? `\n      version = "${ver}"` : '';
  const mirror = `${new URL(base).protocol}//user:<token>@${stripScheme(base)}/terraform/`;
  const note = base.startsWith('http://')
    ? '\n# Note: Terraform refuses an http:// network mirror; serve this instance over HTTPS'
    : '';
  return fenced(
    'hcl',
    `# In ~/.terraformrc: provider_installation { network_mirror { url = "${mirror}" } }${note}\n# Then declare the provider and run terraform init:\nterraform {\n  required_providers {\n    ${localName} = {\n      source  = "${pkg}"${version}\n    }\n  }\n}`,
  );
}

function installCommand(base: string, ecosystem: string, pkg: string, ver: string | undefined): ToolResult {
  switch (ecosystem) {
    case 'npm':
      return fenced('bash', `npm install --registry=${base}/npm/ ${shq(pinned(pkg, '@', ver))}`);
    case 'pypi': {
      if (new URL(base).hostname.startsWith('[')) {
        // requests splits the netloc on ':' to find the netrc entry, which cuts a
        // bracketed IPv6 host to '[', so no machine line can match. Userinfo in the
        // index URL needs no netrc. PIP_INDEX_URL, set for the one command, keeps
        // the token out of pip's argv, and the variable is unset afterwards.
        const indexUrl = base.replace('://', '://user:${PIP_TOKEN}@');
        return fenced(
          'bash',
          `# pip cannot match a .netrc entry for an IPv6 host, so the token goes in the index URL instead.\n# It must be URL-safe (percent-encode any reserved characters).\nread -rs PIP_TOKEN\nPIP_INDEX_URL="${indexUrl}/simple/" pip install ${shq(pinned(pkg, '==', ver))}; unset PIP_TOKEN`,
        );
      }
      const host = netrcHost(base);
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
        `# docker login ${loginHost} first\ndocker pull ${pullHost}/${shq(pkg)}:${orLatest(ver)}${note}`,
      );
    }
    case 'golang': {
      // No `,direct` fallback: Go falls through to the origin on a 404 or 410,
      // which would fetch around the proxy and its policy. The checksum
      // database is proxied under /go/sumdb/, so GONOSUMDB is not needed.
      // Go matches a netrc machine on host:port, so the port stays.
      const host = hostOnly(base);
      return fenced(
        'bash',
        `# Add credentials to ~/.netrc first (machine ${host} login user password <token>), then, inside your module:\nGOPROXY=${base}/go go get ${shq(pkg)}@${orLatest(ver)}`,
      );
    }
    case 'cargo':
      return fenced(
        'bash',
        `# In ~/.cargo/config.toml:\n#   [registries.dependably]\n#   index = "sparse+${base}/cargo/"\ncargo add ${shq(pinned(pkg, '@', ver))} --registry dependably`,
      );
    case 'apk':
      // The repository line needs an Alpine release and repo (v3.22/main) that
      // only the user knows, so it is described rather than written out.
      return fenced(
        'bash',
        `# Add ${base}/apk/<release>/<repo> lines (e.g. v3.22/main) to /etc/apk/repositories,\n# with user:<token>@ in the URL, then:\napk update\napk add ${shq(pinned(pkg, '=', ver))}`,
      );
    case 'terraform':
      return terraformInstall(base, pkg, ver);
    case 'hex': {
      // The dependency names the repository, not a URL: the registry signs its
      // index under the name "dependably" and Hex refuses any other.
      const requirement = ver ? `~> ${ver}` : '>= 0.0.0';
      return fenced(
        'elixir',
        `# Register the repository once:\n#   curl -sSf ${base}/hex/public_key -o dependably-hex.pem\n#   mix hex.repo add dependably ${base}/hex --public-key dependably-hex.pem --auth-key <token>\n# Then add to deps in mix.exs and run mix deps.get:\n{:${pkg}, "${requirement}", repo: :dependably}`,
      );
    }
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
        `${readSecret('TWINE_PASSWORD')}\nTWINE_USERNAME=user twine upload --repository-url ${base}/pypi/legacy/ ${p}`,
      );
    case 'nuget':
      return fenced(
        'bash',
        `${readSecret('NUGET_API_KEY')}\ndotnet nuget push ${p} --source ${base}/nuget/v3/index.json --api-key "$NUGET_API_KEY"`,
      );
    case 'maven':
      return fenced(
        'bash',
        `# Add <server><id>dependably</id> with user / <token> to ~/.m2/settings.xml, then upload the file\n# (or run mvn deploy with ${base}/maven/ as the distributionManagement repository):\nmvn deploy:deploy-file -Dfile=${p} -Durl=${base}/maven/ -DrepositoryId=dependably -DgroupId=<groupId> -DartifactId=<artifactId> -Dversion=<version>`,
      );
    case 'rpm':
      // `-u user` with no password makes curl prompt for it.
      return fenced('bash', `# curl prompts for the password: paste your token\ncurl -u user --upload-file ${p} ${base}/rpm/upload`);
    case 'oci': {
      // The artefact is an image tarball (docker save); a path is not an image
      // reference, so it is loaded first and the loaded name is tagged.
      const loginHost = hostOnly(base);
      const refHost = stripScheme(base);
      return fenced(
        'bash',
        `docker login ${loginHost}\ndocker load -i ${p}   # prints "Loaded image: <name>:<tag>"\ndocker tag <name>:<tag> ${refHost}/<image>:<tag>\ndocker push ${refHost}/<image>:<tag>`,
      );
    }
    case 'golang':
      return proxyOnly('Go is proxy-only — there is no hosted publish/upload endpoint. Publish by pushing a version tag to the module\'s VCS repo; the proxy fetches it on first request.');
    case 'cargo': {
      // cargo publishes from source: the path names the crate's directory or
      // its Cargo.toml. A packaged .crate does not sit beside its source, so
      // no manifest path can be derived from one.
      const prereq = '# Requires [registries.dependably] in ~/.cargo/config.toml, and cargo login --registry dependably.';
      if (artifactPath.endsWith('.crate')) {
        return fenced('bash', `${prereq}\n# cargo publishes from source, not a packaged .crate: run this in the crate's own directory.\ncargo publish --registry dependably`);
      }
      const manifest = `${directoryOf(artifactPath, 'Cargo.toml').replace(/\/$/, '')}/Cargo.toml`;
      return fenced('bash', `${prereq}\ncargo publish --registry dependably --manifest-path ${shq(manifest)}`);
    }
    case 'apk':
      return proxyOnly('apk is proxy-only — there is no hosted publish/upload endpoint. Packages are fetched from the configured Alpine upstream on first request.');
    case 'terraform':
      return proxyOnly('Terraform is proxy-only — there is no hosted publish/upload endpoint. Providers are fetched from their upstream registry on first request.');
    case 'hex':
      return fenced(
        'bash',
        `# Requires the dependably repository registered with mix hex.repo add (see get_install_command).\n${readSecret('HEX_API_KEY')}\ncd ${shq(directoryOf(artifactPath, 'mix.exs'))} && HEX_API_URL=${base}/hex/api mix hex.publish`,
      );
  }
  throw new Error(`Unsupported ecosystem: ${ecosystem}`);
}
