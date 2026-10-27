import type { Tool } from "@modelcontextprotocol/sdk/types.js";

const DOCUMENTED_READ_ONLY_TOOLS = new Set([
  "get_customer_settings",
  "get_event_info",
  "get_event_process_tree",
  "get_scan_result",
  "get_skill_state",
  "generate_sysql",
  "list_runtime_events",
  "list_runtime_scan_results",
  "list_vulnerability_findings",
  "list_vulnerability_findings_by_image",
  "list_zones",
  "query_vulnerability_findings",
  "run_sysql",
  "test_posture_rego",
]);

/** Return known tools for startup discovery without initiating OAuth. */
export function getInitialReadOnlyTools(): Tool[] {
  return [...DOCUMENTED_READ_ONLY_TOOLS].map((name) => ({
    name,
    description: "Known Sysdig Secure tool; its current read-only status and schema are verified with Sysdig before execution.",
    inputSchema: { type: "object", additionalProperties: true },
  }));
}

/** Apply Raven's Sysdig read-only hint policy to one upstream tool. */
export function isReadOnlyTool(tool: Pick<Tool, "name" | "annotations">): boolean {
  if (tool.annotations?.readOnlyHint === false) return false;
  if (tool.annotations?.readOnlyHint === true) return true;
  return DOCUMENTED_READ_ONLY_TOOLS.has(tool.name);
}

/** Filter an upstream catalog to tools accepted by the current read-only policy. */
export function filterReadOnlyTools<T extends Pick<Tool, "name" | "annotations">>(
  tools: T[],
): T[] {
  return tools.filter(isReadOnlyTool);
}
