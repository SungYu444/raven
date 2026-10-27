import { execFile } from "node:child_process";
import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { promisify } from "node:util";
import type { OAuthClientProvider, OAuthDiscoveryState } from "@modelcontextprotocol/sdk/client/auth.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";

const execFileAsync = promisify(execFile);
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000;

interface PendingCallback {
  expectedState: string;
  resolve: (code: string) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

/** Owns the loopback listener used to receive a Sysdig OAuth callback. */
export class SysdigOAuthCallback {
  private server: HttpServer | undefined;
  private redirectUri: string | undefined;
  private pending: PendingCallback | undefined;

  async listen(): Promise<string> {
    if (this.server && this.redirectUri) return this.redirectUri;

    this.server = createServer((request, response) => {
      void this.handleRequest(request, response).catch(() => {
        if (response.headersSent) response.destroy();
        else {
          response.writeHead(500);
          response.end();
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(0, "127.0.0.1", () => {
        this.server!.off("error", reject);
        resolve();
      });
    });

    const address = this.server.address();
    if (!address || typeof address === "string") {
      throw new Error("Could not start the local Sysdig OAuth callback.");
    }
    this.redirectUri = `http://127.0.0.1:${address.port}/callback`;
    return this.redirectUri;
  }

  /** Wait for a state-validated authorization code from the local callback. */
  waitForCode(expectedState: string): Promise<string> {
    if (this.pending) throw new Error("A Sysdig OAuth callback is already pending.");
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending = undefined;
        reject(new Error("Sysdig OAuth authorization timed out."));
        void this.closeServer().catch(() => {
          process.stderr.write("[sysdig-mcp] Could not close the OAuth callback listener after timeout.\n");
        });
      }, CALLBACK_TIMEOUT_MS);
      timeout.unref();
      this.pending = { expectedState, resolve, reject, timeout };
    });
  }

  /** Close the local callback listener and reject any pending authorization. */
  async close(): Promise<void> {
    if (this.pending) {
      clearTimeout(this.pending.timeout);
      this.pending.reject(new Error("Sysdig OAuth callback server closed."));
      this.pending = undefined;
    }
    await this.closeServer();
  }

  private async closeServer(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    this.redirectUri = undefined;
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  }

  private async handleRequest(
    request: IncomingMessage,
    response: import("node:http").ServerResponse,
  ): Promise<void> {
    let requestUrl: URL;
    try {
      requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    } catch {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Malformed OAuth callback request.");
      return;
    }
    if (request.method !== "GET" || requestUrl.pathname !== "/callback" || !this.pending) {
      response.writeHead(404);
      response.end();
      return;
    }

    if (requestUrl.searchParams.get("state") !== this.pending.expectedState) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("OAuth state mismatch.");
      return;
    }

    const error = requestUrl.searchParams.get("error");
    if (error) {
      this.settlePending(new Error("Sysdig OAuth authorization was denied."));
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Authorization was not completed. Return to Raven for details.");
      await this.closeServer();
      return;
    }

    const code = requestUrl.searchParams.get("code");
    if (!code) {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Missing authorization code.");
      return;
    }

    this.settlePending(undefined, code);
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>Sysdig connected</title><p>Sysdig sign-in complete. You can close this tab.</p>");
    await this.closeServer();
  }

  private settlePending(error?: Error, code?: string): void {
    const pending = this.pending;
    if (!pending) return;
    clearTimeout(pending.timeout);
    this.pending = undefined;
    if (error) pending.reject(error);
    else if (code) pending.resolve(code);
  }
}

/** Supplies in-memory OAuth credentials and callback handling for Sysdig. */
export class EphemeralSysdigOAuthProvider implements OAuthClientProvider {
  private clientInfo: OAuthClientInformationMixed | undefined;
  private oauthTokens: OAuthTokens | undefined;
  private verifier: string | undefined;
  private discovery: OAuthDiscoveryState | undefined;
  private expectedState: string | undefined;
  private authorizationCode: Promise<string> | undefined;
  private connectionEstablished = false;

  constructor(
    private readonly callback: SysdigOAuthCallback,
    private readonly callbackUrl: string,
  ) {}

  get redirectUrl(): string {
    return this.callbackUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "Raven Sysdig Read-only MCP",
      redirect_uris: [this.callbackUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      // Sysdig documents role-based authorization, not a granular read-only OAuth scope.
    };
  }

  state(): string {
    this.expectedState = randomBytes(32).toString("base64url");
    return this.expectedState;
  }

  clientInformation(): OAuthClientInformationMixed | undefined {
    return this.clientInfo;
  }

  saveClientInformation(clientInformation: OAuthClientInformationMixed): void {
    this.clientInfo = clientInformation;
  }

  tokens(): OAuthTokens | undefined {
    return this.oauthTokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this.oauthTokens = tokens;
  }

  saveCodeVerifier(codeVerifier: string): void {
    this.verifier = codeVerifier;
  }

  codeVerifier(): string {
    if (!this.verifier) throw new Error("Sysdig OAuth code verifier is missing.");
    return this.verifier;
  }

  saveDiscoveryState(state: OAuthDiscoveryState): void {
    this.discovery = state;
  }

  discoveryState(): OAuthDiscoveryState | undefined {
    return this.discovery;
  }

  invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier" | "discovery"): void {
    if (scope === "all" || scope === "client") this.clientInfo = undefined;
    if (scope === "all" || scope === "tokens") this.oauthTokens = undefined;
    if (scope === "all" || scope === "verifier") this.verifier = undefined;
    if (scope === "all" || scope === "discovery") this.discovery = undefined;
    if (scope === "all") this.expectedState = undefined;
  }

  markConnectionEstablished(): void {
    this.connectionEstablished = true;
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.connectionEstablished) {
      throw new UnauthorizedError("Sysdig credentials expired; reconnect required.");
    }
    if (!this.expectedState) throw new Error("Sysdig OAuth state was not initialized.");
    validateAuthorizationUrl(authorizationUrl);
    this.authorizationCode = this.callback.waitForCode(this.expectedState);
    void this.authorizationCode.catch(() => {});
    process.stderr.write("[sysdig-mcp] Opening browser for Sysdig OAuth sign-in.\n");
    try {
      await openBrowser(authorizationUrl.toString());
    } catch {
      process.stderr.write(
        `[sysdig-mcp] Could not launch a browser automatically. Open this URL to authorize:\n${authorizationUrl.toString()}\n`,
      );
    }
  }

  waitForAuthorizationCode(): Promise<string> {
    if (!this.authorizationCode) throw new Error("Sysdig OAuth authorization did not start.");
    return this.authorizationCode;
  }

}

/** Only allow browser redirects to HTTPS authorization servers on Sysdig domains. */
export function validateAuthorizationUrl(authorizationUrl: URL): void {
  const hostname = authorizationUrl.hostname.toLowerCase();
  if (
    authorizationUrl.protocol !== "https:" ||
    (hostname !== "sysdig.com" && !hostname.endsWith(".sysdig.com")) ||
    authorizationUrl.username ||
    authorizationUrl.password
  ) {
    throw new Error("Sysdig OAuth authorization URL must use HTTPS on a sysdig.com host.");
  }
}

async function openBrowser(url: string): Promise<void> {
  const wsl = Boolean(process.env["WSL_DISTRO_NAME"]);
  const windowsRoot = process.env["SystemRoot"] ?? process.env["WINDIR"] ?? "C:\\Windows";
  const command =
    process.platform === "win32"
      ? join(windowsRoot, "System32", "rundll32.exe")
      : wsl
        ? "/mnt/c/Windows/System32/rundll32.exe"
      : process.platform === "darwin"
        ? "open"
        : "xdg-open";
  const args = process.platform === "win32" || wsl ? ["url.dll,FileProtocolHandler", url] : [url];
  await execFileAsync(command, args, { windowsHide: true });
}

/** An authenticated upstream client and its cleanup handle. */
export interface ConnectedSysdigClient {
  readonly client: Client;
  close(): Promise<void>;
}

/** Establish and manage an authenticated connection to Sysdig's hosted MCP. */
export async function connectSysdigClient(
  serverUrl: URL,
  callback = new SysdigOAuthCallback(),
): Promise<ConnectedSysdigClient> {
  let client: Client | undefined;
  try {
    const redirectUrl = await callback.listen();
    const authProvider = new EphemeralSysdigOAuthProvider(callback, redirectUrl);
    const createClient = () =>
      new Client({ name: "raven-sysdig-readonly-proxy", version: "0.2.0" }, { capabilities: {} });
    const createTransport = () => new StreamableHTTPClientTransport(serverUrl, { authProvider });
    client = createClient();
    let activeTransport = createTransport();

    try {
      await client.connect(activeTransport);
    } catch (error) {
      if (!(error instanceof UnauthorizedError)) throw error;
      const authorizationCode = await authProvider.waitForAuthorizationCode();
      await activeTransport.finishAuth(authorizationCode);
      activeTransport = createTransport();
      await client.connect(activeTransport);
    }

    authProvider.markConnectionEstablished();
    return {
      client,
      close: async () => {
        await client?.close();
        await callback.close();
      },
    };
  } catch (error) {
    await client?.close().catch(() => {});
    await callback.close().catch(() => {});
    throw error;
  }
}
