import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { APIError as BetterAuthAPIError } from "@better-auth/core/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { oneTimeToken } from "better-auth/plugins";
import { APIError } from "better-call";
import fixture from "../../../tests/fixtures/one-time-token-expiry-1.7.6.json";

test("One Time Token expiry precedes custom hashing for HTTP generation and set-ott", async () => {
  const directory = mkdtempSync(join(tmpdir(), "better-auth-one-time-token-expiry-"));
  const output = join(directory, "capture.json");
  const capture = fileURLToPath(new URL("./one-time-token-expiry-capture.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", capture, output], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  writeFileSync(join(directory, "stdout.log"), stdout);
  writeFileSync(join(directory, "stderr.log"), stderr);
  expect({ status, stderr }, `Capture evidence: ${directory}`).toEqual({ status: 0, stderr: "" });
  const actual = JSON.parse(readFileSync(output, "utf8"));
  expect(actual, `Capture evidence: ${directory}`).toStrictEqual(fixture);
  rmSync(directory, { recursive: true });
}, 60_000);

const nativeErrors = [
  ["invalid-token", "Invalid token"],
  ["missing-session", "Session not found"],
  ["expired-session", "Session expired"],
  ["client-request-only", "Unauthorized"],
  ["client-disabled", "Client requests are disabled"],
] as const;

for (const [mode, message] of nativeErrors) {
  for (const http of [false, true]) {
    test(`One Time Token ${mode} retains error provenance and preceding writes HTTP=${http}`, async () => {
      const origin = "http://one-time-token-errors.test";
      const secret = "one-time-token-native-errors-secret-at-least-32-characters";
      const memory: Record<string, unknown[]> = { user: [], session: [], account: [], verification: [] };
      const generate = mode.startsWith("client-");
      let generated = 0;
      const auth = betterAuth({
        baseURL: origin, secret, database: memoryAdapter(memory),
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        session: { disableSessionRefresh: true, cookieCache: { enabled: false } },
        plugins: [oneTimeToken({
          disableClientRequest: generate,
          generateToken: async () => { generated++; return "unexpected-token"; },
        })],
      });
      const context = await auth.$context;
      const now = new Date();
      const token = "owner-session-token";
      await context.adapter.create({ model: "user", forceAllowId: true, data: {
        id: "owner", email: "owner@one-time-token-errors.test", emailVerified: true,
        name: "Owner", image: null, createdAt: now, updatedAt: now,
      } });
      await context.adapter.create({ model: "session", forceAllowId: true, data: {
        id: "owner-session", userId: "owner", token, createdAt: now, updatedAt: now,
        expiresAt: new Date(now.getTime() + (mode === "expired-session" ? -60_000 : 604_800_000)),
      } });
      if (mode === "missing-session" || mode === "expired-session") {
        await context.internalAdapter.createVerificationValue({
          identifier: "one-time-token:transfer-token",
          value: mode === "missing-session" ? "missing-session-token" : token,
          expiresAt: new Date(now.getTime() + 60_000),
        });
      }
      const before = structuredClone(memory);
      const signature = createHmac("sha256", secret).update(token).digest("base64");
      const cookie = `better-auth.session_token=${encodeURIComponent(`${token}.${signature}`)}`;
      const request = new Request(`${origin}/api/auth/one-time-token/${generate ? "generate" : "verify"}`, {
        method: generate ? "GET" : "POST",
        headers: { "content-type": "application/json", ...(generate ? { cookie } : {}) },
        ...(generate ? {} : { body: JSON.stringify({ token: "transfer-token" }) }),
      });
      let caught: APIError | undefined;
      let result: unknown;
      try {
        const options = {
          request, asResponse: http,
          ...(mode === "client-disabled" ? { headers: request.headers } : {}),
        };
        result = generate
          ? await auth.api.generateOneTimeToken(options)
          : await auth.api.verifyOneTimeToken({ ...options, body: { token: "transfer-token" } });
      } catch (error) {
        expect(error).toBeInstanceOf(APIError);
        caught = error as APIError;
      }
      const sessionGuard = mode === "client-request-only";
      const expected = { message, ...(sessionGuard ? { code: "UNAUTHORIZED" } : {}) };
      const status = sessionGuard ? 401 : 400;
      expect(Boolean(caught)).toBe(!http);
      if (caught) {
        expect(caught instanceof BetterAuthAPIError).toBe(sessionGuard);
        expect(caught.status).toBe(sessionGuard ? "UNAUTHORIZED" : "BAD_REQUEST");
        expect(caught.statusCode).toBe(status);
        expect(caught.body).toStrictEqual(expected);
        expect(Object.keys(caught.body!)).toStrictEqual(sessionGuard ? ["message", "code"] : ["message"]);
      } else {
        expect(result).toBeInstanceOf(Response);
        const response = result as Response;
        expect(response.status).toBe(status);
        expect(await response.clone().json()).toStrictEqual(expected);
        expect(await response.text()).toBe(JSON.stringify(expected));
        const cookies = response.headers.getSetCookie();
        expect(cookies.length).toBe(mode === "expired-session" ? 1 : 0);
        if (mode === "expired-session") expect(cookies[0].split(";")[0]).toBe(cookie);
      }
      expect(generated).toBe(0);
      expect(memory).toStrictEqual({ ...before, verification: [] });
    });
  }
}
