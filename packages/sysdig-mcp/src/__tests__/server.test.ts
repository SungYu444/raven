import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult, ListToolsResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSysdigReadOnlyServer, type SysdigUpstreamClient } from "../server.js";

describe("createSysdigReadOnlyServer", () => {
  let localServer: ReturnType<typeof createSysdigReadOnlyServer> | undefined;
  let localClient: Client | undefined;

  afterEach(async () => {
    await localClient?.close().catch(() => {});
    await localServer?.close().catch(() => {});
    localClient = undefined;
    localServer = undefined;
  });

  it("advertises and forwards only approved read-only tools", async () => {
    const callTool = vi.fn(async (): Promise<CallToolResult> => ({
      content: [{ type: "text", text: "Contact jane.smith@gov.bc.ca" }],
    }));
    const upstream: SysdigUpstreamClient = {
      listTools: async (): Promise<ListToolsResult> => ({
        tools: [
          { name: "list_runtime_events", inputSchema: { type: "object" } },
          { name: "save_skill_state", inputSchema: { type: "object" } },
          { name: "explicit_read", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
        ],
      }),
      callTool,
    };

    localServer = createSysdigReadOnlyServer(async () => upstream, () => upstream);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    const listed = await localClient.listTools();
    expect(listed.tools.map(({ name }) => name)).toEqual(["list_runtime_events", "explicit_read"]);

    const response = await localClient.callTool({ name: "list_runtime_events", arguments: {} });
    expect(callTool).toHaveBeenCalledOnce();
    expect(response.content).toEqual([
      { type: "text", text: "Contact [EMAIL]" },
    ]);
  });

  it("blocks a write-capable call even if a client invokes it directly", async () => {
    const callTool = vi.fn(async (): Promise<CallToolResult> => ({ content: [] }));
    const upstream: SysdigUpstreamClient = {
      listTools: async (): Promise<ListToolsResult> => ({
        tools: [
          { name: "save_skill_state", inputSchema: { type: "object" }, annotations: { readOnlyHint: false } },
        ],
      }),
      callTool,
    };

    localServer = createSysdigReadOnlyServer(async () => upstream, () => upstream);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    await expect(
      localClient.callTool({ name: "save_skill_state", arguments: {} }),
    ).rejects.toThrow(/not approved as read-only/);
    expect(callTool).not.toHaveBeenCalled();
  });

  it("normalizes the legacy upstream result shape and scrubs its strings", async () => {
    const upstream: SysdigUpstreamClient = {
      listTools: async (): Promise<ListToolsResult> => ({
        tools: [{ name: "legacy_read", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }],
      }),
      callTool: async () => ({ toolResult: { email: "jane.smith@gov.bc.ca" } }),
    };

    localServer = createSysdigReadOnlyServer(async () => upstream, () => upstream);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    const response = await localClient.callTool({ name: "legacy_read", arguments: {} });
    expect(response.content).toEqual([
      { type: "text", text: "{\"email\":\"[EMAIL]\"}" },
    ]);
  });

  it("lists local tools without initiating a connection or sign-in", async () => {
    const getClient = vi.fn(async (): Promise<SysdigUpstreamClient> => {
      throw new Error("should not connect for tools/list");
    });
    localServer = createSysdigReadOnlyServer(getClient);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    const listed = await localClient.listTools();
    expect(listed.tools.map(({ name }) => name)).toContain("list_runtime_events");
    expect(getClient).not.toHaveBeenCalled();
    expect(localClient.getServerCapabilities()?.tools?.listChanged).toBe(true);
    expect(listed.tools.every((tool) => tool.annotations?.readOnlyHint === undefined)).toBe(true);
  });

  it("scrubs key-labelled credentials in structured content as a whole", async () => {
    const upstream: SysdigUpstreamClient = {
      listTools: async (): Promise<ListToolsResult> => ({
        tools: [{ name: "list_runtime_events", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }],
      }),
      callTool: async () => ({
        content: [{ type: "text", text: "Finding details" }],
        structuredContent: {
          password: "hunter2",
          email: "jane.smith@gov.bc.ca",
          severity: "Critical",
        },
      }),
    };

    localServer = createSysdigReadOnlyServer(async () => upstream, () => upstream);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    const response = await localClient.callTool({ name: "list_runtime_events", arguments: {} });
    expect(JSON.stringify(response)).not.toContain("hunter2");
    expect(response.structuredContent).toBeUndefined();
    const blocks = Array.isArray(response.content) ? response.content : [];
    expect(blocks[1]).toMatchObject({ type: "text" });
    const fallback = blocks[1];
    if (typeof fallback === "object" && fallback !== null && "text" in fallback && typeof fallback.text === "string") {
      expect(fallback.text).toContain("[CREDENTIAL]");
      expect(fallback.text).toContain('"severity":"Critical"');
    }
  });

  it("scrubs upstream error messages before returning them", async () => {
    const upstream: SysdigUpstreamClient = {
      listTools: async (): Promise<ListToolsResult> => ({
        tools: [{ name: "list_runtime_events", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }],
      }),
      callTool: async () => {
        throw new Error("Upstream failed for jane.smith@gov.bc.ca with password=hunter2");
      },
    };

    localServer = createSysdigReadOnlyServer(async () => upstream, () => upstream);
    localClient = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      localServer.connect(serverTransport),
      localClient.connect(clientTransport),
    ]);

    await expect(
      localClient.callTool({ name: "list_runtime_events", arguments: {} }),
    ).rejects.toThrow("[EMAIL]");
    await expect(
      localClient.callTool({ name: "list_runtime_events", arguments: {} }),
    ).rejects.not.toThrow("hunter2");
  });
});
