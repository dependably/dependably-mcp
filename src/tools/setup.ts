import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { Config } from '../config.js';
import { err, type ToolResult } from '../format.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo']);

const LOCAL_READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

function fenced(lang: string, body: string): ToolResult {
  return { content: [{ type: 'text', text: `\`\`\`${lang}\n${body}\n\`\`\`` }] };
}

export function registerSetupTools(server: McpServer, cfg: Config): void {
  server.registerTool(
    'get_install_command',
    {
      title: 'Install command',
      description: 'Return the shell command to install a package through this Dependably instance. This tool DOES NOT execute — show the command to the user and let them run it.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: {
        ecosystem,
        package: z.string().describe('Package name (canonical for the ecosystem).'),
        version: z.string().optional().describe('Optional pinned version.'),
      },
    },
    async (args) => {
      const base = cfg.baseUrl;
      const pkg = args.package;
      const ver = args.version;
      switch (args.ecosystem) {
        case 'npm': {
          const spec = ver ? `${pkg}@${ver}` : pkg;
          return fenced('bash', `npm install --registry=${base}/npm/ ${spec}`);
        }
        case 'pypi': {
          const spec = ver ? `${pkg}==${ver}` : pkg;
          return fenced('bash', `pip install --index-url ${base}/simple/ ${spec}`);
        }
        case 'nuget': {
          const verFlag = ver ? ` --version ${ver}` : '';
          return fenced(
            'bash',
            `dotnet add package ${pkg}${verFlag} --source ${base}/nuget/v3/index.json`,
          );
        }
        case 'maven': {
          const coord = ver ? `${pkg}:${ver}` : pkg;
          return fenced(
            'bash',
            `# Add ${base}/maven/ as a <repository> in your pom.xml or settings.xml, then:\nmvn dependency:get -Dartifact=${coord}`,
          );
        }
        case 'rpm': {
          const spec = ver ? `${pkg}-${ver}` : pkg;
          return fenced(
            'bash',
            `# Add ${base}/rpm/ as a dnf repo (baseurl) first, then:\ndnf install ${spec}`,
          );
        }
        case 'oci': {
          const host = stripScheme(base);
          const ref = `${host}/${pkg}:${ver ?? 'latest'}`;
          return fenced('bash', `docker pull ${ref}`);
        }
        case 'golang': {
          const spec = ver ? `${pkg}@${ver}` : `${pkg}@latest`;
          return fenced('bash', `GOPROXY=${base}/go go get ${spec}`);
        }
        case 'cargo': {
          const spec = ver ? `${pkg}@${ver}` : pkg;
          return fenced(
            'bash',
            `# Requires [registries.dependably] = { index = "sparse+${base}/cargo/" } in ~/.cargo/config.toml, then:\ncargo add ${spec} --registry dependably`,
          );
        }
      }
    },
  );

  server.registerTool(
    'get_publish_command',
    {
      title: 'Publish command',
      description: 'Return the shell command to publish an artifact through this Dependably instance. This tool DOES NOT execute — show the command to the user and let them run it. Replace <token> with a valid Dependably token.',
      annotations: LOCAL_READ_ANNOTATIONS,
      inputSchema: {
        ecosystem,
        artifact_path: z.string().describe('Path to the built artifact (e.g. ./dist/*, ./bin/Release/*.nupkg, package.tgz).'),
      },
    },
    async (args) => {
      const base = cfg.baseUrl;
      const p = args.artifact_path;
      switch (args.ecosystem) {
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
          return err(
            'Go is proxy-only — there is no hosted publish/upload endpoint. Publish by pushing a version tag to the module\'s VCS repo; the proxy fetches it on first request.',
          );
        case 'cargo':
          return fenced(
            'bash',
            `# Requires [registries.dependably] in ~/.cargo/config.toml.\n# Run from the crate directory (${p}):\ncargo publish --registry dependably`,
          );
      }
    },
  );
}

function stripScheme(url: string): string {
  return url.replace(/^https?:\/\//, '');
}
