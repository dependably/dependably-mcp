import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import type { Config } from '../config.js';
import { run, structured, type ToolResult } from '../format.js';

const ecosystem = z.enum(['npm', 'pypi', 'nuget', 'maven']);

const REMOTE_READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const LOCAL_READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

function fenced(lang: string, body: string): ToolResult {
  return { content: [{ type: 'text', text: `\`\`\`${lang}\n${body}\n\`\`\`` }] };
}

export function registerSetupTools(server: McpServer, client: DependablyClient, cfg: Config): void {
  server.registerTool(
    'get_setup_snippet',
    {
      title: 'Setup snippet',
      description: 'Fetch the canonical Dependably-generated client config snippet for an ecosystem (.npmrc, pip.conf, nuget.config, settings.xml).',
      annotations: REMOTE_READ_ANNOTATIONS,
      inputSchema: { ecosystem },
      outputSchema: { snippet: z.string() },
    },
    async (args) =>
      run(async () => structured(await client.get(`/api/v1/setup/${args.ecosystem}`), 'snippet')),
  );

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
      const org = cfg.orgSlug;
      const pkg = args.package;
      const ver = args.version;
      switch (args.ecosystem) {
        case 'npm': {
          const spec = ver ? `${pkg}@${ver}` : pkg;
          return fenced('bash', `npm install --registry=${base}/o/${org}/npm/ ${spec}`);
        }
        case 'pypi': {
          const spec = ver ? `${pkg}==${ver}` : pkg;
          return fenced('bash', `pip install --index-url ${base}/o/${org}/simple/ ${spec}`);
        }
        case 'nuget': {
          const verFlag = ver ? ` --version ${ver}` : '';
          return fenced(
            'bash',
            `dotnet add package ${pkg}${verFlag} --source ${base}/o/${org}/nuget/v3/index.json`,
          );
        }
        case 'maven': {
          const coord = ver ? `${pkg}:${ver}` : pkg;
          return fenced(
            'bash',
            `# Add this repository to your pom.xml or settings.xml (see get_setup_snippet maven),\n# then:\nmvn dependency:get -Dartifact=${coord}`,
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
      const org = cfg.orgSlug;
      const p = args.artifact_path;
      switch (args.ecosystem) {
        case 'npm':
          return fenced(
            'bash',
            `# Requires .npmrc with //${stripScheme(base)}/o/${org}/npm/:_authToken=<token>\nnpm publish --registry=${base}/o/${org}/npm/ ${p}`,
          );
        case 'pypi':
          return fenced(
            'bash',
            `twine upload --repository-url ${base}/o/${org}/pypi/legacy/ -u user -p <token> ${p}`,
          );
        case 'nuget':
          return fenced(
            'bash',
            `dotnet nuget push ${p} --source ${base}/o/${org}/nuget/v3/index.json --api-key <token>`,
          );
        case 'maven':
          return fenced(
            'bash',
            `# Configure ${base}/o/${org}/maven/ as a distributionManagement repo in pom.xml,\n# add server credentials (user / <token>) to settings.xml, then:\nmvn deploy`,
          );
      }
    },
  );
}

function stripScheme(url: string): string {
  return url.replace(/^https?:\/\//, '');
}
