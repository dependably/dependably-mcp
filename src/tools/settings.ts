import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, structured } from '../format.js';

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

export function registerSettingsTools(server: McpServer, client: DependablyClient): void {
  server.registerTool(
    'get_org_settings',
    {
      title: 'Org settings',
      description: 'Read the caller org\'s settings: anonymous-pull, allowlist mode, upload limits, upstream URLs, default language, overwrite policy.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        anonymous_pull: z.boolean().nullable().optional(),
        allowlist_mode: z.string().nullable().optional(),
        max_upload_bytes: z.number().nullable().optional(),
        max_upload_bytes_pypi: z.number().nullable().optional(),
        max_upload_bytes_npm: z.number().nullable().optional(),
        max_upload_bytes_nuget: z.number().nullable().optional(),
        pypi_upstream: z.string().nullable().optional(),
        npm_upstream: z.string().nullable().optional(),
        nuget_upstream: z.string().nullable().optional(),
        default_language: z.string().nullable().optional(),
        allow_version_overwrite: z.boolean().nullable().optional(),
      },
    },
    async () => run(async () => structured(await client.get('/api/v1/settings'))),
  );

  server.registerTool(
    'get_retention',
    {
      title: 'Retention policy',
      description: 'Read retention policy: keep_versions, keep_days, activity_retention_days.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        keep_versions: z.number().nullable().optional(),
        keep_days: z.number().nullable().optional(),
        activity_retention_days: z.number().nullable().optional(),
      },
    },
    async () => run(async () => structured(await client.get('/api/v1/retention'))),
  );

  server.registerTool(
    'get_proxy_settings',
    {
      title: 'Proxy settings',
      description: 'Read proxy settings: passthrough-enabled, max OSV score tolerance, min release-age hours.',
      annotations: READ_ANNOTATIONS,
      inputSchema: {},
      outputSchema: {
        proxy_passthrough_enabled: z.boolean().optional(),
        max_osv_score_tolerance: z.number().optional(),
        min_release_age_hours: z.number().nullable().optional(),
      },
    },
    async () => run(async () => structured(await client.get('/api/v1/proxy-settings'))),
  );
}
