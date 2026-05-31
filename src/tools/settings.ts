import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { run, structured, withSummary } from '../format.js';

const optionalBool = z.boolean().optional();
const optionalNum = z.number().optional();
const optionalStr = z.string().optional();

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
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
    'update_org_settings',
    {
      title: 'Update org settings',
      description: 'Update org settings. Only the fields you pass are changed (others sent through unmodified). Requires tenant:configure.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        anonymousPull: optionalBool.describe('Allow unauthenticated package reads.'),
        allowlistMode: z
          .enum(['off', 'enforce'])
          .optional()
          .describe('When "enforce", only packages matching an allowlist entry can be fetched/pushed.'),
        maxUploadBytes: optionalNum.describe('Org-wide upload cap, bytes.'),
        maxUploadBytesPypi: optionalNum,
        maxUploadBytesNpm: optionalNum,
        maxUploadBytesNuget: optionalNum,
        pypiUpstream: optionalStr,
        npmUpstream: optionalStr,
        nugetUpstream: optionalStr,
        defaultLanguage: optionalStr,
        allowVersionOverwrite: optionalBool,
      },
    },
    async (args) =>
      run(async () => withSummary('Org settings updated.', await client.put('/api/v1/settings', args))),
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
    'update_retention',
    {
      title: 'Update retention',
      description: 'Update retention policy. Requires tenant:configure.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        keepVersions: optionalNum.describe('Max versions to keep per package (older pruned).'),
        keepDays: optionalNum.describe('Max age in days for kept versions.'),
        activityRetentionDays: optionalNum.describe('How long activity events are retained.'),
      },
    },
    async (args) =>
      run(async () => withSummary('Retention policy updated.', await client.put('/api/v1/retention', args))),
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

  server.registerTool(
    'update_proxy_settings',
    {
      title: 'Update proxy settings',
      description: 'Update proxy settings. Requires tenant:configure.',
      annotations: WRITE_ANNOTATIONS,
      inputSchema: {
        proxyPassthroughEnabled: optionalBool,
        maxOsvScoreTolerance: z.number().min(0).max(10).optional().describe('0.0–10.0 CVSS-style cap.'),
        minReleaseAgeHours: optionalNum.describe('Block versions newer than this many hours (typosquat shield).'),
      },
    },
    async (args) =>
      run(async () => withSummary('Proxy settings updated.', await client.put('/api/v1/proxy-settings', args))),
  );
}
