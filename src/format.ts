export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

/**
 * Shared character budget for a tool result's text. Claude Desktop and other
 * MCP hosts impose their own caps on a single tool result; a compact,
 * unindented Dependably response can still run to hundreds of thousands of
 * characters for a large `list_vulnerabilities` or `check_dependencies` call.
 * Truncating here, with a trailer that names the fix, keeps every tool under
 * the host limit without each call site reimplementing the cap.
 */
export const RESULT_CHAR_BUDGET = 100_000;

const TRUNCATION_TRAILER = `\n[truncated: result exceeded ${RESULT_CHAR_BUDGET} characters; narrow the query (smaller limit, one ecosystem, fewer ids) and retry]`;

/** Truncate text to the shared budget, appending a machine-readable trailer if it was cut. */
function bounded(text: string): string {
  if (text.length <= RESULT_CHAR_BUDGET) return text;
  return text.slice(0, RESULT_CHAR_BUDGET) + TRUNCATION_TRAILER;
}

export function json(value: unknown): ToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return { content: [{ type: 'text', text: bounded(text) }] };
}

export function withSummary(summary: string, value: unknown): ToolResult {
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  return { content: [{ type: 'text', text: bounded(`${summary}\n\n${body}`) }] };
}

export function err(message: string): ToolResult {
  return { content: [{ type: 'text', text: bounded(message) }], isError: true };
}

export async function run(fn: () => Promise<ToolResult>): Promise<ToolResult> {
  try {
    return await fn();
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e));
  }
}
