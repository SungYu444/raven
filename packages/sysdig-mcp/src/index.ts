#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { OAuthError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { ListToolsResult } from "@modelcontextprotocol/sdk/types.js";
import { loadEnv } from "@nrs/auth";
import { resolveSysdigMcpUrl } from "./config.js";
import { connectSysdigClient, SysdigOAuthCallback } from "./oauth.js";
import { createSysdigReadOnlyServer, type SysdigUpstreamClient } from "./server.js";

loadEnv();
const sysdigUrl = resolveSysdigMcpUrl();
let connection: Awaited<ReturnType<typeof connectSysdigClient>> | undefined;
let connectionPromise: Promise<Awaited<ReturnType<typeof connectSysdigClient>>> | undefined;
let connectingCallback: SysdigOAuthCallback | undefined;
let retryAfter = 0;
let server: ReturnType<typeof createSysdigReadOnlyServer> | undefined;
const toolPages = new Map<string, ListToolsResult>();

const isAuthenticationError = (error: unknown): boolean =>
  error instanceof UnauthorizedError ||
  error instanceof OAuthError ||
  (error instanceof StreamableHTTPError && error.code === 401);

const loadToolCatalog = async (
  client: Awaited<ReturnType<typeof connectSysdigClient>>["client"],
): Promise<void> => {
  toolPages.clear();
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  for (let pageCount = 0; pageCount < 100; pageCount += 1) {
    const page = await client.listTools(cursor ? { cursor } : undefined);
    toolPages.set(cursor ?? "", page);
    if (!page.nextCursor) return;
    if (seenCursors.has(page.nextCursor)) {
      throw new Error("Sysdig returned a repeated tools-list cursor.");
    }
    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error("Sysdig tool catalog exceeded the pagination safety limit.");
};

const getConnection = async (): Promise<Awaited<ReturnType<typeof connectSysdigClient>>> => {
  if (!connectionPromise && Date.now() < retryAfter) {
    throw new Error("Sysdig sign-in recently failed. Try another Sysdig tool call later.");
  }
  connectionPromise ??= (async () => {
    const callback = new SysdigOAuthCallback();
    connectingCallback = callback;
    try {
      const connected = await connectSysdigClient(sysdigUrl, callback);
      connection = connected;
      await loadToolCatalog(connected.client);
      retryAfter = 0;
      void server?.sendToolListChanged().catch(() => {
        process.stderr.write("[sysdig-mcp] Could not notify the client that Sysdig tools are available.\n");
      });
      return connected;
    } catch (error) {
      await connection?.close().catch(() => {});
      connection = undefined;
      retryAfter = Date.now() + 60_000;
      throw error;
    } finally {
      if (connectingCallback === callback) connectingCallback = undefined;
    }
  })()
    .catch((error: unknown) => {
      connectionPromise = undefined;
      throw error;
    });
  return connectionPromise;
};

const withAuthenticationRecovery = async <T>(
  operation: (client: SysdigUpstreamClient) => Promise<T>,
): Promise<T> => {
  const connected = await getConnection();
  const client: SysdigUpstreamClient = {
    listTools: (params) => connected.client.listTools(params),
    callTool: (params) => connected.client.callTool(params),
  };
  try {
    return await operation(client);
  } catch (error) {
    if (!isAuthenticationError(error) || !connection) throw error;

    const expiredConnection = connection;
    connection = undefined;
    connectionPromise = undefined;
    await expiredConnection.close().catch(() => {});

    let replacement;
    try {
      replacement = await getConnection();
    } catch {
      retryAfter = Date.now() + 60_000;
      connection = undefined;
      connectionPromise = undefined;
      throw new Error("Sysdig session expired; sign-in did not complete. Retry a Sysdig tool call when ready.");
    }
    const replacementClient: SysdigUpstreamClient = {
      listTools: (params) => replacement.client.listTools(params),
      callTool: (params) => replacement.client.callTool(params),
    };
    try {
      return await operation(replacementClient);
    } catch (retryError) {
      if (!isAuthenticationError(retryError)) throw retryError;
      retryAfter = Date.now() + 60_000;
      await replacement.close().catch(() => {});
      connection = undefined;
      connectionPromise = undefined;
      throw new Error("Sysdig session expired; sign-in did not complete. Retry a Sysdig tool call when ready.");
    }
  }
};

const upstreamClient: SysdigUpstreamClient = {
  listTools: (params) =>
    withAuthenticationRecovery(async (client) => {
      const page = await client.listTools(params);
      toolPages.set(params?.cursor ?? "", page);
      return page;
    }),
  callTool: (params) => withAuthenticationRecovery((client) => client.callTool(params)),
};

const cachedCatalogClient: SysdigUpstreamClient = {
  listTools: async (params) => toolPages.get(params?.cursor ?? "") ?? { tools: [] },
  callTool: async () => {
    throw new Error("Cached Sysdig catalog client cannot call tools.");
  },
};

server = createSysdigReadOnlyServer(
  async () => upstreamClient,
  () => (connection ? cachedCatalogClient : undefined),
);
const transport = new StdioServerTransport();
await server.connect(transport);

let shutdownPromise: Promise<void> | undefined;
const shutdown = async () => {
  shutdownPromise ??= (async () => {
    await server?.close();
    await connectingCallback?.close().catch(() => {});
    await connectionPromise?.catch(() => {});
    await connection?.close();
  })();
  await shutdownPromise;
};
process.once("SIGINT", () => void shutdown().catch(() => process.exitCode = 1));
process.once("SIGTERM", () => void shutdown().catch(() => process.exitCode = 1));
