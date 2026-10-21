/**
 * Request-size and tool-input limits.
 *
 * - CVE-2026-111768 / GHSA-46jr-4wx8-v453: memory exhaustion while validating
 *   deeply/widely nested tool input. `maxToolInputElements` is an McpServer-only
 *   option; this repo uses the low-level Server, so the cap is enforced here.
 * - GHSA-f897-62hf-6gxq: no request body / batch size cap.
 * - CVE-2026-111770 / GHSA-jm63-cq47-j5jp: SDK version floor (see package.json).
 *
 * Tracking: Linear WYREAI-454. Dependency-free on purpose.
 */

/** Maximum HTTP request body, in bytes (256 KiB). */
export const MAX_REQUEST_BODY_BYTES = 256 * 1024;

/** Maximum array elements + object keys, summed over all depths, in tool arguments. */
export const MAX_TOOL_INPUT_ELEMENTS = 10_000;

/**
 * Count every array element and own object key at every depth. Iterative (no
 * recursion, so depth cannot overflow the stack) and stops as soon as the
 * count exceeds `max`, returning that partial count (> max).
 */
export function countToolInputElements(value: unknown, max: number): number {
  let count = 0;
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || typeof current !== "object") continue;
    if (Array.isArray(current)) {
      count += current.length;
      if (count > max) return count;
      for (let i = 0; i < current.length; i++) stack.push(current[i]);
    } else {
      const keys = Object.keys(current);
      count += keys.length;
      if (count > max) return count;
      const record = current as Record<string, unknown>;
      for (const key of keys) stack.push(record[key]);
    }
  }
  return count;
}

/** True when `args` holds more than `max` array elements plus object keys, summed over all depths. */
export function toolInputTooLarge(args: unknown, max: number = MAX_TOOL_INPUT_ELEMENTS): boolean {
  return countToolInputElements(args, max) > max;
}

/**
 * Build the MCP error result for oversize tool input. The message is fixed on
 * purpose: it never echoes the caller-controlled tool name or arguments (CWE-209).
 */
export function toolInputTooLargeResult(max: number = MAX_TOOL_INPUT_ELEMENTS) {
  return {
    content: [
      {
        type: "text" as const,
        text: `Tool input exceeds the maximum of ${max} elements`,
      },
    ],
    isError: true as const,
  };
}
