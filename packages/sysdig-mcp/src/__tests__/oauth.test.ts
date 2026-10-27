import { createConnection } from "node:net";
import type { OAuthClientInformationMixed, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  EphemeralSysdigOAuthProvider,
  SysdigOAuthCallback,
  validateAuthorizationUrl,
} from "../oauth.js";

function requestCallback(url: string, query: string): Promise<number> {
  const callbackUrl = new URL(url);
  callbackUrl.search = query;
  return new Promise((resolve, reject) => {
    const request = globalThis.fetch(callbackUrl);
    void request.then((response) => resolve(response.status), reject);
  });
}

function requestMalformedTarget(url: string): Promise<string> {
  const port = Number(new URL(url).port);
  return new Promise((resolve, reject) => {
    const socket = createConnection(port, "127.0.0.1");
    let response = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => {
      socket.write("GET // HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    });
    socket.on("data", (chunk) => {
      response += chunk;
    });
    socket.on("error", reject);
    socket.on("close", () => resolve(response));
  });
}

describe("Sysdig OAuth callback", () => {
  let callback: SysdigOAuthCallback | undefined;

  afterEach(async () => {
    await callback?.close();
    callback = undefined;
    vi.useRealTimers();
  });

  it("rejects a state mismatch without consuming the pending callback", async () => {
    callback = new SysdigOAuthCallback();
    const redirectUrl = await callback.listen();
    const code = callback.waitForCode("expected-state");

    expect(await requestCallback(redirectUrl, "?state=wrong&code=ignored")).toBe(400);
    expect(await requestCallback(redirectUrl, "?state=expected-state&code=valid-code")).toBe(200);
    await expect(code).resolves.toBe("valid-code");
  });

  it("allows only one pending callback", async () => {
    callback = new SysdigOAuthCallback();
    await callback.listen();
    const waiting = callback.waitForCode("state");
    expect(() => callback?.waitForCode("second-state")).toThrow(/already pending/);
    await callback.close();
    await expect(waiting).rejects.toThrow(/closed/);
  });

  it("returns HTTP 400 for a malformed callback request target", async () => {
    callback = new SysdigOAuthCallback();
    const redirectUrl = await callback.listen();
    const response = await requestMalformedTarget(redirectUrl);
    expect(response).toMatch(/^HTTP\/1\.1 400/m);
  });

  it("rejects an abandoned callback on timeout and closes the listener", async () => {
    vi.useFakeTimers();
    callback = new SysdigOAuthCallback();
    await callback.listen();
    const waiting = callback.waitForCode("state");
    const rejected = expect(waiting).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    await rejected;
    await callback.close();
  });
});

describe("Sysdig OAuth provider", () => {
  const makeProvider = () =>
    new EphemeralSysdigOAuthProvider(new SysdigOAuthCallback(), "http://127.0.0.1:1234/callback");

  it("invalidates only the requested credentials", () => {
    const provider = makeProvider();
    const client: OAuthClientInformationMixed = { client_id: "registered-client" };
    const tokens: OAuthTokens = {
      access_token: "access",
      refresh_token: "refresh",
      token_type: "Bearer",
    };
    provider.saveClientInformation(client);
    provider.saveTokens(tokens);

    provider.invalidateCredentials("tokens");
    expect(provider.tokens()).toBeUndefined();
    expect(provider.clientInformation()).toEqual(client);

    provider.saveTokens(tokens);
    provider.invalidateCredentials("all");
    expect(provider.tokens()).toBeUndefined();
    expect(provider.clientInformation()).toBeUndefined();
  });

  it("accepts HTTPS Sysdig authorization URLs and rejects other schemes or hosts", () => {
    expect(() => validateAuthorizationUrl(new URL("https://secure.sysdig.com/oauth/authorize"))).not.toThrow();
    expect(() => validateAuthorizationUrl(new URL("https://eu1.app.sysdig.com/oauth/authorize"))).not.toThrow();
    for (const value of [
      "http://secure.sysdig.com/oauth/authorize",
      "https://attacker.example/oauth/authorize",
      "https://sysdig.com.attacker.example/oauth/authorize",
      "file:///etc/passwd",
    ]) {
      expect(() => validateAuthorizationUrl(new URL(value))).toThrow(/HTTPS on a sysdig.com host/);
    }
  });

  it("requests a reconnect instead of opening another authorization tab after connection", async () => {
    const provider = makeProvider();
    provider.state();
    provider.markConnectionEstablished();
    await expect(
      provider.redirectToAuthorization(new URL("https://secure.sysdig.com/oauth/authorize")),
    ).rejects.toBeInstanceOf(UnauthorizedError);
  });
});
