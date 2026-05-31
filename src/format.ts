import { z } from 'zod';

export const paginationSchema = {
  page: z.number().int().positive().optional().describe('Page number, 1-based. Default 1.'),
  limit: z.number().int().positive().max(500).optional().describe('Page size, default server-side (50).'),
};

export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
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

/**
 * Tool result for read-only tools that declare an outputSchema.
 * The SDK validates structuredContent against the schema and requires
 * the value to be an object (record), not an array or primitive.
 *
 * Pass `wrap` when the server returns a non-object (e.g. an array or string);
 * the value is placed at that key in structuredContent.
 */
export function structured(value: unknown, wrap?: string): ToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const obj = wrap ? { [wrap]: value } : asRecord(value);
  return {
    content: [{ type: 'text', text }],
    structuredContent: obj,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return { value };
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
