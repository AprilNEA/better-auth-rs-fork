import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { siwe } from "better-auth/plugins";
import { APIError, kAPIErrorHeaderSymbol } from "better-call";
import { APIError as BetterAuthAPIError } from "@better-auth/core/error";

const nonce = "native123";
const address = "0x0000000000000000000000000000000000000001";
const body = {
  message: `example.com wants you to sign in with your Ethereum account:\n${address}\n\nChain ID: 1\nNonce: ${nonce}`,
  signature: "verified-by-application",
};
const cases = [
  ["invalid-nonce", 500, { message: "SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.", status: 500, code: "SIWE_INVALID_NONCE" }],
  ["missing-nonce", 401, { message: "Unauthorized: Invalid or expired nonce", status: 401, code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" }],
  ["invalid-signature", 401, { message: "Unauthorized: Invalid SIWE signature", status: 401 }],
  ["api-error", 403, { code: "VERIFIER_REJECTED", message: "verifier rejected" }],
  ["runtime-error", 401, { message: "Something went wrong. Please try again later.", error: "verifier failed", status: 401 }],
  ["native-error", 401, { message: "Something went wrong. Please try again later.", error: "verifier failed", status: 401 }],
  ["native-syntax-error", 401, { message: "Something went wrong. Please try again later.", error: "JSON Parse error: Expected '}'", status: 401 }],
  ["database-error", 401, { message: "Something went wrong. Please try again later.", error: "driver failure", status: 401 }],
  ["renamed-native-error", 401, { message: "Something went wrong. Please try again later.", error: "verifier failed", status: 401 }],
  ["plain-error-shaped-object", 401, { message: "Something went wrong. Please try again later.", error: "Unknown error", status: 401 }],
] as const;

for (const [mode, status, expected] of cases) {
  for (const http of [false, true]) {
    test(`SIWE ${mode} preserves native APIError and nonce consumption HTTP=${http}`, async () => {
      const memory: Record<string, unknown[]> = { user: [], session: [], account: [], verification: [], walletAddress: [] };
      const calls: number[] = [];
      const auth = betterAuth({
        baseURL: "http://siwe-errors.test", secret: "siwe-error-contract-secret-at-least-32-characters",
        database: memoryAdapter(memory), logger: { disabled: true }, telemetry: { enabled: false },
        plugins: [siwe({
          domain: "example.com", getNonce: async () => "short",
          verifyMessage: async input => {
            calls.push(input.chainId);
            if (mode === "api-error") throw new APIError("FORBIDDEN", expected);
            if (mode === "runtime-error" || mode === "native-error") throw new Error("verifier failed");
            if (mode === "native-syntax-error") JSON.parse("{");
            if (mode === "database-error") throw Object.assign(new Error("driver failure"), { name: "error", code: "23505" });
            if (mode === "renamed-native-error") throw Object.assign(new Error("verifier failed"), { name: "RenamedError" });
            if (mode === "plain-error-shaped-object") throw { name: "Error", message: "must not be used" };
            return false;
          },
        })],
      });
      const context = await auth.$context;
      if (mode !== "invalid-nonce" && mode !== "missing-nonce") {
        await context.internalAdapter.createVerificationValue({ identifier: `siwe:${nonce}`, value: nonce, expiresAt: new Date(Date.now() + 300_000) });
      }
      const input = mode === "invalid-nonce" ? undefined : body;
      const path = mode === "invalid-nonce" ? "/siwe/nonce" : "/siwe/verify";
      const request = new Request(`http://siwe-errors.test/api/auth${path}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: input === undefined ? undefined : JSON.stringify(input),
      });
      let thrown: APIError | undefined;
      let result: unknown;
      try {
        const options = { request, asResponse: http, returnHeaders: true, returnStatus: true };
        result = mode === "invalid-nonce"
          ? await auth.api.getSiweNonce(options)
          : await auth.api.verifySiweMessage({ ...options, body });
      } catch (error) {
        expect(error).toBeInstanceOf(APIError);
        thrown = error as APIError;
      }
      expect(Boolean(thrown)).toBe(!http);
      if (http) {
        expect(result).toBeInstanceOf(Response);
        if (!(result instanceof Response)) throw new Error("Expected an HTTP Response");
        expect(result.status).toBe(status);
        expect(await result.clone().json()).toStrictEqual(expected);
        expect(await result.text()).toBe(JSON.stringify(expected));
        expect(Object.fromEntries(result.headers)).toStrictEqual({ "content-type": "application/json" });
      } else {
        expect(thrown instanceof BetterAuthAPIError).toBe(mode !== "api-error");
        expect(thrown!.status).toBe(mode === "invalid-nonce" ? "INTERNAL_SERVER_ERROR" : mode === "api-error" ? "FORBIDDEN" : "UNAUTHORIZED");
        expect(thrown!.statusCode).toBe(status);
        expect(thrown!.body).toStrictEqual(expected);
        expect(Object.keys(thrown!.body!)).toStrictEqual(Object.keys(expected));
        expect(Object.fromEntries(new Headers(thrown![kAPIErrorHeaderSymbol]))).toStrictEqual({});
      }
      expect(calls).toStrictEqual(mode === "invalid-nonce" || mode === "missing-nonce" ? [] : [1]);
      expect(memory).toStrictEqual({ user: [], session: [], account: [], verification: [], walletAddress: [] });
    });
  }
}
