import { z } from 'zod';

export const paginationSchema = {
  page: z.number().int().positive().optional().describe('Page number, 1-based. Default 1.'),
  limit: z.number().int().positive().max(500).optional().describe('Page size, default server-side (50).'),
};

export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

export function json(value: unknown): ToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function withSummary(summary: string, value: unknown): ToolResult {
  const body = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text: `${summary}\n\n${body}` }] };
}

export function err(message: string): ToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

export async function run(fn: () => Promise<ToolResult>): Promise<ToolResult> {
  try {
    return await fn();
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e));
  }
}
