import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CompatibilityCallToolResult,
  type CallToolResult,
  type ListToolsResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { PiScrubber } from "@nrs/auth";
import { filterReadOnlyTools, getInitialReadOnlyTools } from "./read-only.js";

/** The upstream MCP client operations used by the local proxy. */
export interface SysdigUpstreamClient {
  listTools(params?: { cursor?: string }): Promise<ListToolsResult>;
  callTool(
    params: { name: string; arguments?: Record<string, unknown> },
  ): Promise<CallToolResult | CompatibilityCallToolResult>;
}

function scrubStringValues(value: unknown, scrubber: PiScrubber): unknown {
  if (typeof value === "string") return scrubber.scrubText(value);
  if (Array.isArray(value)) return value.map((item) => scrubStringValues(item, scrubber));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, scrubStringValues(item, scrubber)]),
    );
  }
  return value;
}

function normalizeToolResult(
  result: CallToolResult | CompatibilityCallToolResult,
): CallToolResult {
  if ("content" in result && Array.isArray(result.content)) return result as CallToolResult;
  if (!("toolResult" in result)) {
    throw new Error("Sysdig returned an unsupported tool result.");
  }
  const serialized = typeof result.toolResult === "string"
    ? result.toolResult
    : JSON.stringify(result.toolResult) ?? String(result.toolResult);
  return { content: [{ type: "text", text: serialized }] };
}

function scrubToolResult(result: CallToolResult, scrubber: PiScrubber): CallToolResult {
  const { structuredContent, ...unstructured } = result;
  const scrubbed = scrubStringValues(unstructured, scrubber) as CallToolResult;
  if (structuredContent === undefined) return scrubbed;

  const serialized = JSON.stringify(structuredContent);
  const scrubbedSerialized = scrubber.scrubText(serialized);
  try {
    return {
      ...scrubbed,
      structuredContent: JSON.parse(scrubbedSerialized) as Record<string, unknown>,
    };
  } catch {
    return {
      ...scrubbed,
      content: [
        ...scrubbed.content,
        { type: "text", text: scrubbedSerialized },
      ],
    };
  }
}

function safeErrorMessage(error: unknown, scrubber: PiScrubber): string {
  const message = error instanceof Error ? error.message : String(error);
  return scrubber.scrubText(message);
}

async function findReadOnlyTool(
  client: SysdigUpstreamClient,
  toolName: string,
): Promise<Tool | undefined> {
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageCount = 0; pageCount < 100; pageCount += 1) {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    const matchingTool = filterReadOnlyTools(page.tools).find((tool) => tool.name === toolName);
    if (matchingTool) return matchingTool;
    if (!page.nextCursor) return undefined;
    if (seenCursors.has(page.nextCursor)) {
      throw new Error("Sysdig returned a repeated tools-list cursor.");
    }
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error("Sysdig tool catalog exceeded the pagination safety limit.");
}

/** Create a local MCP server that proxies only Sysdig's read-only tools. */
export function createSysdigReadOnlyServer(
  getClient: () => Promise<SysdigUpstreamClient>,
  getCachedClient: () => SysdigUpstreamClient | undefined = () => undefined,
): Server {
  const server = new Server(
    { name: "Raven Sysdig Read-only MCP", version: "0.2.0" },
    { capabilities: { tools: { listChanged: true } } },
  );
  const scrubber = new PiScrubber();

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const upstream = getCachedClient();
    if (!upstream) return { tools: getInitialReadOnlyTools() };
    const result = await upstream.listTools(request.params);
    return {
      ...result,
      tools: filterReadOnlyTools(result.tools),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    let upstream: SysdigUpstreamClient;
    let tool: Tool | undefined;
    try {
      upstream = await getClient();
      tool = await findReadOnlyTool(upstream, request.params.name);
    } catch (error) {
      throw new McpError(ErrorCode.InternalError, safeErrorMessage(error, scrubber));
    }
    if (!tool) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Sysdig tool '${request.params.name}' is unavailable or is not approved as read-only.`,
      );
    }
    try {
      const result = normalizeToolResult(await upstream.callTool(request.params));
      return scrubToolResult(result, scrubber);
    } catch (error) {
      throw new McpError(ErrorCode.InternalError, safeErrorMessage(error, scrubber));
    }
  });

  return server;
}
