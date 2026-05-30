import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { DependablyClient } from '../client.js';
import { json, run, withSummary } from '../format.js';

const optionalBool = z.boolean().optional();
const optionalNum = z.number().optional();
const optionalStr = z.string().optional();

export function registerSettingsTools(server: McpServer, client: DependablyClient): void {
  server.tool(
    'get_org_settings',
    'Read the caller org\'s settings: anonymous-pull, allowlist mode, upload limits, upstream URLs, default language, overwrite policy.',
    {},
    async () => run(async () => json(await client.get('/api/v1/settings'))),
  );

  server.tool(
    'update_org_settings',
    'Update org settings. Only the fields you pass are changed (others sent through unmodified). Requires tenant:configure.',
    {
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
    async (args) =>
      run(async () => withSummary('Org settings updated.', await client.put('/api/v1/settings', args))),
  );

  server.tool(
    'get_retention',
    'Read retention policy: keep_versions, keep_days, activity_retention_days.',
    {},
    async () => run(async () => json(await client.get('/api/v1/retention'))),
  );

  server.tool(
    'update_retention',
    'Update retention policy. Requires tenant:configure.',
    {
      keepVersions: optionalNum.describe('Max versions to keep per package (older pruned).'),
      keepDays: optionalNum.describe('Max age in days for kept versions.'),
      activityRetentionDays: optionalNum.describe('How long activity events are retained.'),
    },
    async (args) =>
      run(async () => withSummary('Retention policy updated.', await client.put('/api/v1/retention', args))),
  );

  server.tool(
    'get_proxy_settings',
    'Read proxy settings: passthrough-enabled, max OSV score tolerance, min release-age hours.',
    {},
    async () => run(async () => json(await client.get('/api/v1/proxy-settings'))),
  );

  server.tool(
    'update_proxy_settings',
    'Update proxy settings. Requires tenant:configure.',
    {
      proxyPassthroughEnabled: optionalBool,
      maxOsvScoreTolerance: z.number().min(0).max(10).optional().describe('0.0–10.0 CVSS-style cap.'),
      minReleaseAgeHours: optionalNum.describe('Block versions newer than this many hours (typosquat shield).'),
    },
    async (args) =>
      run(async () => withSummary('Proxy settings updated.', await client.put('/api/v1/proxy-settings', args))),
  );
}
