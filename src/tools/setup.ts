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
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || isBidiControl(code) || ARTIFACT_PATH_FORBIDDEN.has(ch)) return false;
  }
  return true;
}

/** Bidi embeddings, overrides and isolates: they reorder how a pasted path is displayed, not what it is. */
function isBidiControl(code: number): boolean {
  return (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
}
const ARTIFACT_PATH_MESSAGE =
  'Artefact path must not contain shell metacharacters (; | & $ ` < > ( ) or newlines), control characters (including C1 controls and bidirectional overrides), shell glob characters (* ? [ ] { }), or start with -. Spaces are fine, but name one file — globs are not expanded.';

/** `""`/whitespace-only means "unpinned", the same as omitting the field entirely. */
const versionField = z
  .string()
  .optional()
  .transform((v) => (v === undefined || v.trim() === '' ? undefined : v))
  .refine((v) => v === undefined || VERSION_PATTERN.test(v), { message: VERSION_MESSAGE })
  .describe('Optional pinned version. An empty string is treated as unpinned.');

/** An optional publish input that is checked against `pattern`; an empty or whitespace-only string means "not supplied". */
function publishField(pattern: RegExp, message: string, max: number, description: string) {
  return z
    .string()
    .optional()
    .transform((v) => (v === undefined || v.trim() === '' ? undefined : v))
    .refine((v) => v === undefined || (v.length <= max && pattern.test(v)), { message })
    .describe(description);
}

const MAVEN_ID_PATTERN = /^[A-Za-z0-9_.-]+$/;
// The repository grammar Dependably's OCI routes accept, the same one
// NAME_RULES.oci enforces. It is a subset of the distribution spec's: the spec
// also allows `__` and a run of `-` between name parts, but the server answers
// those with NAME_INVALID (dependably-community#817), so they are refused here
// with a clear message rather than handed out as a command that fails later.
const OCI_REPOSITORY_PATTERN = /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/;
const OCI_TAG_PATTERN = /^\w[\w.-]{0,127}$/;
const MAVEN_ID_MESSAGE = 'Maven groupId and artifactId are letters, digits, . _ - only, at most 128 characters.';

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

/**
 * Quote a value for a shell word only when it needs it. A URL or host made of
 * the characters below passes through untouched, so ordinary output stays
 * readable; anything else, notably the `[...]` of an IPv6 literal, which zsh
 * and bash read as a glob (zsh aborts with "no matches found"), is
 * single-quoted by {@link shq}.
 */
function word(value: string): string {
  return /^[A-Za-z0-9_./:@%+,-]+$/.test(value) ? value : shq(value);
}

/** The base URL plus a path, as one shell word. */
function urlWord(base: string, path: string): string {
  return word(`${base}${path}`);
}

/**
 * A path as one shell word. A leading `~` is expanded by the shell only when it
 * is unquoted, and {@link shq} would make it a literal directory named `~`, so
 * `~` and `~/rest` become `"$HOME"` and `"$HOME"/'rest'`.
 */
function pathWord(path: string): string {
  if (path === '~') return '"$HOME"';
  if (path.startsWith('~/')) return `"$HOME"/${shq(path.slice(2))}`;
  return shq(path);
}

type Part = string | { lang: string; body: string };

/**
 * Prose and fences, in order, separated by blank lines. A shell fence holds
 * commands only. A `#` comment line is not safe in one: interactive zsh has
 * interactive_comments off by default, so it runs `#` as a command ("command
 * not found: #") or, trailing a command, hands the words to it as arguments.
 * Explanations are prose parts outside the fence. A command that waits for
 * typed input (a {@link withSecret} read, `docker login`) is the last line of
 * its fence, because a shell without bracketed paste would otherwise feed the
 * next pasted line to it as the answer.
 */
function render(parts: Part[]): ToolResult {
  const text = parts.map((p) => (typeof p === 'string' ? p : '```' + p.lang + '\n' + p.body + '\n```')).join('\n\n');
  return { content: [{ type: 'text', text }] };
}

function fenced(lang: string, body: string): ToolResult {
  return render([{ lang, body }]);
}

const SECRET_NOTE =
  'The command waits silently for your token: paste it and press Enter. It is not echoed, not saved to history and not left in your shell afterwards. Run it in bash or zsh (read -s is not POSIX sh).';

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
      description: 'Build the shell command that publishes an artefact through this Dependably instance. Returns the command as text only; nothing is executed. No command carries the token itself: it is read without echo (read -rs, in bash or zsh), prompted for, or kept in a config file the notes name. For maven (groupId, artifactId, version) and oci (image, tag) the command is complete only once those inputs are supplied; without them the reply names what is missing instead of a command with placeholders. Shell blocks hold commands only; explanations come as prose outside the code fence.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: z.object({
        ecosystem,
        artifact_path: artifactPath,
        groupId: publishField(MAVEN_ID_PATTERN, MAVEN_ID_MESSAGE, 128, 'maven only: the groupId to publish under. Required for a runnable maven command.'),
        artifactId: publishField(MAVEN_ID_PATTERN, MAVEN_ID_MESSAGE, 128, 'maven only: the artifactId to publish under. Required for a runnable maven command.'),
        version: publishField(VERSION_PATTERN, VERSION_MESSAGE, 256, 'maven only: the version to publish. Required for a runnable maven command. An empty string is treated as not supplied.'),
        image: publishField(
          OCI_REPOSITORY_PATTERN,
          'OCI repository names are lowercase path segments (e.g. team/app), at most 255 characters.',
          255,
          'oci only: the repository path to publish under on this instance (e.g. team/app). Required for a runnable oci command.',
        ),
        tag: publishField(OCI_TAG_PATTERN, 'OCI tags are letters, digits, _ . - only, at most 128 characters, and do not start with . or -.', 128, 'oci only: the tag to publish under (e.g. 1.0.0). Required for a runnable oci command.'),
      }).strict(),
    },
    // Which inputs apply is checked here, not in the schema, for the same
    // reason `package` is above: an object-level refinement would hide every
    // field from the advertised JSON Schema.
    async (args) => {
      const supplied: Array<[string, string, string | undefined]> = [
        ['maven', 'groupId', args.groupId],
        ['maven', 'artifactId', args.artifactId],
        ['maven', 'version', args.version],
        ['oci', 'image', args.image],
        ['oci', 'tag', args.tag],
      ];
      const misplaced = supplied.filter(([eco, , value]) => value !== undefined && eco !== args.ecosystem);
      if (misplaced.length > 0) {
        const detail = misplaced.map(([eco, name]) => `${name} (${eco} only)`).join(', ');
        return err(`These inputs do not apply to ${args.ecosystem}: ${detail}. Omit them.`);
      }
      return publishCommand(cfg.baseUrl, args.ecosystem, args.artifact_path, {
        groupId: args.groupId,
        artifactId: args.artifactId,
        version: args.version,
        image: args.image,
        tag: args.tag,
      });
    },
  ));

  return tools;
}

/** Informational, not an error: a proxy-only ecosystem simply has no publish command to return. */
function proxyOnly(text: string): ToolResult {
  return { content: [{ type: 'text', text }] };
}

/**
 * Reads a secret without echoing it and hands it to one command only, on a
 * single line run in a subshell. The variable lives and dies in the subshell,
 * so nothing needs unsetting and an interrupt (Ctrl-C) cannot leave it behind;
 * it is never exported, so later commands do not inherit it. One line, because
 * with `read` and the command on separate lines a shell without bracketed paste
 * (macOS /bin/bash 3.2) would feed the command line to `read` as the token and
 * then run the real token as a command, saving it to history. `command` must
 * not reference the variable itself when `inEnv` is set (the default): it
 * receives the secret in its environment. Pass `inEnv: false` when the command
 * line itself names the variable (`--password "$VAR"`), which is the only route
 * some clients offer. `after` runs between the read and the command (a `cd`), in the
 * same subshell. Nothing may run before the read: if a step ahead of it failed,
 * the subshell would exit without reading and the token the user then pastes
 * would run as a command and land in history.
 */
function withSecret(variable: string, command: string, opts: { after?: string; inEnv?: boolean } = {}): string {
  const { after = '', inEnv = true } = opts;
  const assignment = inEnv ? `${variable}="$${variable}" ` : '';
  return `( read -rs ${variable} && ${after}${assignment}${command} )`;
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
  const parts: Part[] = [
    'Set the network mirror once in ~/.terraformrc:',
    { lang: 'hcl', body: `provider_installation {\n  network_mirror {\n    url = "${mirror}"\n  }\n}` },
  ];
  if (base.startsWith('http://')) parts.push('Terraform refuses an http:// network mirror; serve this instance over HTTPS.');
  parts.push(
    'Then declare the provider and run terraform init:',
    { lang: 'hcl', body: `terraform {\n  required_providers {\n    ${localName} = {\n      source  = "${pkg}"${version}\n    }\n  }\n}` },
  );
  return render(parts);
}

function installCommand(base: string, ecosystem: string, pkg: string, ver: string | undefined): ToolResult {
  switch (ecosystem) {
    case 'npm': {
      // npm resolves a scoped package through `@scope:registry` ahead of
      // --registry, so a user's own scope mapping would send the install
      // elsewhere; naming the scope on the command line takes precedence.
      const registry = word(`${base}/npm/`);
      const scope = pkg.startsWith('@') ? pkg.slice(0, pkg.indexOf('/')) : undefined;
      const scoped = scope ? ` --${scope}:registry=${registry}` : '';
      return fenced('bash', `npm install --registry=${registry}${scoped} ${shq(pinned(pkg, '@', ver))}`);
    }
    case 'pypi': {
      if (new URL(base).hostname.startsWith('[')) {
        // requests splits the netloc on ':' to find the netrc entry, which cuts a
        // bracketed IPv6 host to '[', so no machine line can match. Userinfo in the
        // index URL needs no netrc. PIP_INDEX_URL, set for the one command, keeps
        // the token out of pip's argv.
        const indexUrl = base.replace('://', '://user:${PIP_TOKEN}@');
        return render([
          'pip cannot match a .netrc entry for an IPv6 host, so the token goes in the index URL instead. It must be URL-safe (percent-encode any reserved characters).',
          SECRET_NOTE,
          { lang: 'bash', body: withSecret('PIP_TOKEN', `PIP_INDEX_URL="${indexUrl}/simple/" pip install ${shq(pinned(pkg, '==', ver))}`) },
        ]);
      }
      const host = netrcHost(base);
      return render([
        `Put your token in ~/.netrc for ${host} first: machine ${host} login user password <token>`,
        { lang: 'bash', body: `pip install --index-url ${urlWord(base, '/simple/')} ${shq(pinned(pkg, '==', ver))}` },
      ]);
    }
    case 'nuget':
      // Off Windows NuGet refuses to store a source password without
      // --store-password-in-clear-text; it is on dotnet's argv while the command
      // runs, the same exposure as the publish side's --api-key.
      return render([
        'Add the authenticated source once. dotnet takes the password only as an argument, so it is visible to ps on this machine while the command runs, and off Windows it needs --store-password-in-clear-text, which writes the token to NuGet.Config in plain text (on Windows, drop that flag).',
        SECRET_NOTE,
        { lang: 'bash', body: withSecret('NUGET_TOKEN', `dotnet nuget add source ${urlWord(base, '/nuget/v3/index.json')} --name dependably --username user --password "$NUGET_TOKEN" --store-password-in-clear-text`, { inEnv: false }) },
        'Then add the package:',
        { lang: 'bash', body: `dotnet add package ${shq(pkg)}${flag(' --version ', ver)} --source ${urlWord(base, '/nuget/v3/index.json')}` },
      ]);
    case 'maven': {
      const artifact = ver ? `${pkg}:${ver}` : `${pkg}:LATEST`;
      return render([
        `Add ${base}/maven/ as a <repository> in your pom.xml or settings.xml, then run:`,
        { lang: 'bash', body: `mvn dependency:get -Dartifact=${shq(artifact)}` },
        ...(ver ? [] : ['No version was pinned, so this takes LATEST: pin a version in production.']),
      ]);
    }
    case 'rpm':
      return render([
        `Add ${base}/rpm/ as a dnf repo (baseurl) first, then run:`,
        { lang: 'bash', body: `dnf install ${shq(pinned(pkg, '-', ver))}` },
      ]);
    case 'oci': {
      const loginHost = hostOnly(base);
      const pullHost = stripScheme(base);
      return render([
        'Log in first; docker prompts for the username and password (paste your token as the password):',
        { lang: 'bash', body: `docker login ${word(loginHost)}` },
        ...(hasPathPrefix(base) ? ['Note: OCI registries cannot live under a URL path; use the instance host directly.'] : []),
        'Then pull:',
        { lang: 'bash', body: `docker pull ${word(pullHost)}/${shq(pkg)}:${orLatest(ver)}` },
      ]);
    }
    case 'golang': {
      // No `,direct` fallback: Go falls through to the origin on a 404 or 410,
      // which would fetch around the proxy and its policy. The checksum
      // database is proxied under /go/sumdb/, so GONOSUMDB is not needed.
      // Go matches a netrc machine on host:port, so the port stays.
      const host = hostOnly(base);
      return render([
        `Add credentials to ~/.netrc first: machine ${host} login user password <token>. Then, inside your module, run:`,
        { lang: 'bash', body: `GOPROXY=${urlWord(base, '/go')} go get ${shq(pkg)}@${orLatest(ver)}` },
      ]);
    }
    case 'cargo':
      return render([
        'Register the registry in ~/.cargo/config.toml:',
        { lang: 'toml', body: `[registries.dependably]\nindex = "sparse+${base}/cargo/"` },
        'Then add the crate:',
        { lang: 'bash', body: `cargo add ${shq(pinned(pkg, '@', ver))} --registry dependably` },
      ]);
    case 'apk':
      // The repository line needs an Alpine release and repo (v3.22/main) that
      // only the user knows, so it is described rather than written out.
      return render([
        `Add ${base}/apk/<release>/<repo> lines (e.g. v3.22/main) to /etc/apk/repositories, with user:<token>@ in the URL, then run:`,
        { lang: 'bash', body: `apk update\napk add ${shq(pinned(pkg, '=', ver))}` },
      ]);
    case 'terraform':
      return terraformInstall(base, pkg, ver);
    case 'hex': {
      // The dependency names the repository, not a URL: the registry signs its
      // index under the name "dependably" and Hex refuses any other.
      const requirement = ver ? `~> ${ver}` : '>= 0.0.0';
      const repoAdd = `mix hex.repo add dependably ${urlWord(base, '/hex')} --public-key dependably-hex.pem --auth-key "$HEX_AUTH_KEY"`;
      return render([
        'Register the repository once. mix takes the key only as an argument, so it is visible to ps on this machine while the command runs.',
        SECRET_NOTE,
        {
          lang: 'bash',
          body: `curl -sSf ${urlWord(base, '/hex/public_key')} -o dependably-hex.pem\n${withSecret('HEX_AUTH_KEY', repoAdd, { inEnv: false })}`,
        },
        'Then add to deps in mix.exs and run mix deps.get:',
        { lang: 'elixir', body: `{:${pkg}, "${requirement}", repo: :dependably}` },
      ]);
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
interface PublishInputs {
  groupId?: string;
  artifactId?: string;
  version?: string;
  image?: string;
  tag?: string;
}

function missingInputs(inputs: Array<[string, string | undefined]>): string[] {
  return inputs.filter(([, value]) => value === undefined).map(([name]) => name);
}

function publishCommand(base: string, ecosystem: string, artifactPath: string, inputs: PublishInputs = {}): ToolResult {
  const p = pathWord(artifactPath);
  switch (ecosystem) {
    case 'npm':
      return render([
        `Requires .npmrc with //${stripScheme(base)}/npm/:_authToken=<token>. For a scoped package (@scope/name), npm prefers an @scope:registry setting in your npm config, or a registry in the package's publishConfig, over --registry, so a scoped publish can go to the wrong registry unless you also pass --@scope:registry=${base}/npm/ with the package's own scope (or fix that setting).`,
        { lang: 'bash', body: `npm publish --registry=${urlWord(base, '/npm/')} ${p}` },
      ]);
    case 'pypi':
      return render([
        SECRET_NOTE,
        { lang: 'bash', body: withSecret('TWINE_PASSWORD', `TWINE_USERNAME=user twine upload --repository-url ${urlWord(base, '/pypi/legacy/')} ${p}`) },
      ]);
    case 'nuget':
      // dotnet nuget push takes the key only as --api-key, so it is on dotnet's
      // argv (visible to this machine's ps) while the push runs. The other route,
      // the source's stored credentials, needs a Basic challenge the server's 401
      // does not send, and stores the token in plaintext NuGet.Config off Windows.
      return render([
        'dotnet takes the key only as --api-key, so it is visible to ps on this machine while the push runs.',
        SECRET_NOTE,
        { lang: 'bash', body: withSecret('NUGET_API_KEY', `dotnet nuget push ${p} --source ${urlWord(base, '/nuget/v3/index.json')} --api-key "$NUGET_API_KEY"`, { inEnv: false }) },
      ]);
    case 'maven': {
      const settings = 'Add a <server> entry with <id>dependably</id>, your username and the token as the password to ~/.m2/settings.xml first.';
      const { groupId, artifactId, version } = inputs;
      if (groupId === undefined || artifactId === undefined || version === undefined) {
        const missing = missingInputs([['groupId', groupId], ['artifactId', artifactId], ['version', version]]).join(', ');
        return render([
          `${settings} The upload needs the artefact's coordinates, and no command is given without them. Missing: ${missing}. Call get_publish_command again with ${missing} for a command you can run as it is.`,
        ]);
      }
      return render([
        `${settings} The command uploads the file with mvn deploy:deploy-file. To deploy from a project instead, run mvn deploy with ${base}/maven/ as the distributionManagement repository.`,
        { lang: 'bash', body: `mvn deploy:deploy-file -Dfile=${p} -Durl=${urlWord(base, '/maven/')} -DrepositoryId=dependably -DgroupId=${word(groupId)} -DartifactId=${word(artifactId)} -Dversion=${word(version)}` },
      ]);
    }
    case 'rpm':
      // `-u user` with no password makes curl prompt for it.
      return render([
        'curl prompts for the password: paste your token.',
        { lang: 'bash', body: `curl -u user --upload-file ${p} ${urlWord(base, '/rpm/upload')}` },
      ]);
    case 'oci': {
      // The artefact is an image tarball (docker save); a path is not an image
      // reference, so it is loaded first and the loaded reference is tagged.
      const loginHost = hostOnly(base);
      const refHost = word(stripScheme(base));
      const login: Part[] = [
        'Log in first; docker prompts for the username and password (paste your token as the password):',
        { lang: 'bash', body: `docker login ${word(loginHost)}` },
      ];
      const { image, tag } = inputs;
      if (image === undefined || tag === undefined) {
        const missing = missingInputs([['image', image], ['tag', tag]]).join(', ');
        return render([
          ...login,
          `Publishing also needs the repository and tag to publish under, and no command is given without them. Missing: ${missing}. Call get_publish_command again with ${missing} for the load, tag and push commands.`,
        ]);
      }
      const target = `${refHost}/${shq(image)}:${shq(tag)}`;
      // docker load prints "Loaded image: name:tag", or "Loaded image ID: sha256:..." for an untagged image; docker tag
      // accepts both. An empty capture stops the chain before anything is tagged or pushed.
      const load = `IMG=$(docker load -i ${p} | sed -n 's/^Loaded image\\( ID\\)\\{0,1\\}: //p' | head -n 1)`;
      return render([
        ...login,
        `The next command loads the tarball, takes the first image reference docker load reports, and tags and pushes it as ${image}:${tag}. It runs in a subshell, and stops without pushing if no image was loaded. A tarball holding several images publishes only the first.`,
        { lang: 'bash', body: `( ${load} && test -n "$IMG" && docker tag "$IMG" ${target} && docker push ${target} )` },
      ]);
    }
    case 'golang':
      return proxyOnly('Go is proxy-only — there is no hosted publish/upload endpoint. Publish by pushing a version tag to the module\'s VCS repo; the proxy fetches it on first request.');
    case 'cargo': {
      // cargo publishes from source: the path names the crate's directory or
      // its Cargo.toml. A packaged .crate does not sit beside its source, so
      // no manifest path can be derived from one.
      const prereq = 'Requires [registries.dependably] in ~/.cargo/config.toml, and cargo login --registry dependably.';
      if (artifactPath.endsWith('.crate')) {
        return render([
          `${prereq} cargo publishes from source, not a packaged .crate: run this in the crate's own directory.`,
          { lang: 'bash', body: 'cargo publish --registry dependably' },
        ]);
      }
      const manifest = `${directoryOf(artifactPath, 'Cargo.toml').replace(/\/$/, '')}/Cargo.toml`;
      return render([prereq, { lang: 'bash', body: `cargo publish --registry dependably --manifest-path ${pathWord(manifest)}` }]);
    }
    case 'apk':
      return proxyOnly('apk is proxy-only — there is no hosted publish/upload endpoint. Packages are fetched from the configured Alpine upstream on first request.');
    case 'terraform':
      return proxyOnly('Terraform is proxy-only — there is no hosted publish/upload endpoint. Providers are fetched from their upstream registry on first request.');
    case 'hex': {
      // The cd happens inside the subshell, so the user's own directory is left alone.
      const publish = withSecret('HEX_API_KEY', `HEX_API_URL=${urlWord(base, '/hex/api')} mix hex.publish`, { after: `cd ${pathWord(directoryOf(artifactPath, 'mix.exs'))} && ` });
      return render([
        'Requires the dependably repository registered with mix hex.repo add (see get_install_command).',
        SECRET_NOTE,
        { lang: 'bash', body: publish },
      ]);
    }
  }
  throw new Error(`Unsupported ecosystem: ${ecosystem}`);
}
