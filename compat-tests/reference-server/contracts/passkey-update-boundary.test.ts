import { expect, test } from "bun:test";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { authenticator, type AuthenticationOptions, type RegistrationOptions } from "../../client-tests/tests/phase8/authenticator";
import { withRestoredSchema } from "./schema-isolation.mjs";

const origin = "http://passkey-null-update.test";
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

for (const operation of [
  "authentication", "rename", "stale-counter", "stale-counter-signature", "stale-counter-dynamic", "stale-counter-dynamic-signature",
  "stale-counter-flags", "stale-counter-flags-signature", "stale-counter-dynamic-flags", "stale-counter-dynamic-flags-signature",
  "valid-counter-flags", "valid-counter-flags-signature", "valid-counter-dynamic-flags", "valid-counter-dynamic-flags-signature",
  "stale-counter-flags-origin", "stale-counter-dynamic-flags-origin", "stale-counter-flags-rp", "stale-counter-dynamic-flags-rp",
] as const) {
  test(`Passkey preserves the ${operation} business boundary`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
      let remove = false;
      let deletions = 0;
      const logs: unknown[] = [];
      const updates: unknown[] = [];
      const conversions: string[] = [];
      const dynamic = operation.includes("dynamic");
      const invalidFlags = operation.includes("flags");
      const invalidOrigin = operation.endsWith("origin");
      const invalidRp = operation.endsWith("rp");
      const validCounter = operation.startsWith("valid-counter");
      const counterValue = {
        valueOf(...args: unknown[]) {
          expect(this).toBe(counterValue);
          expect(args).toStrictEqual([]);
          conversions.push("valueOf");
          return 2;
        },
        toString(...args: unknown[]) {
          expect(this).toBe(counterValue);
          expect(args).toStrictEqual([]);
          conversions.push("toString");
          return "projected counter";
        },
      };
      const auth = betterAuth({
        database: memoryAdapter(memory), baseURL: origin,
        secret: "passkey-null-update-contract-at-least-thirty-two",
        logger: { level: "error", log(...args) { logs.push(args); } },
        telemetry: { enabled: false }, rateLimit: { enabled: false },
        plugins: [passkey({
          rpID: "passkey-null-update.test", rpName: "Nullable passkey update", origin,
          authentication: { afterVerification({ verification }) {
            expect(verification.verified).toBe(true);
            expect(verification.authenticationInfo.newCounter).toBe(1);
            if (remove && operation === "authentication") {
              memory.passkey = [];
              deletions++;
            }
          } },
        }), testUtils(), {
          id: "passkey-rename-update-removal",
          schema: { passkey: { fields: { name: {
            type: "string", required: false,
            transform: { input(value: unknown) {
              if (remove && operation === "rename") {
                memory.passkey = [];
                deletions++;
              }
              return value;
            } },
          }, counter: {
            type: "number", required: true,
            transform: { output(value: unknown) { return remove && dynamic ? counterValue : value; } },
          } } } },
        }],
      });
      const request = (path: string, cookie?: string, body?: unknown) => {
        const headers = new Headers({ origin, accept: "application/json" });
        if (cookie) headers.set("cookie", cookie);
        if (body !== undefined) headers.set("content-type", "application/json");
        return auth.handler(new Request(`${origin}/api/auth/passkey/${path}`, {
          method: body === undefined ? "GET" : "POST", headers,
          body: body === undefined ? undefined : JSON.stringify(body),
        }));
      };
      const context = await auth.$context;
      const now = new Date();
      const owner = await context.adapter.create<{ id: string }>({ model: "user", forceAllowId: true, data: {
        id: "owner", name: "Owner", email: "owner@passkey-null-update.test", emailVerified: true,
        image: null, createdAt: now, updatedAt: now,
      } });
      const login = await context.test.login({ userId: owner.id });
      const loginCookie = login.headers.get("cookie")!;
      const key = authenticator(`null-update-${operation}`);
      const registerOptions = await request("generate-register-options", loginCookie);
      expect(registerOptions.status).toBe(200);
      const registration = await registerOptions.json() as RegistrationOptions;
      const registered = await request("verify-registration", `${loginCookie}; ${cookies(registerOptions)}`, {
        response: key.register(registration, origin, false), name: "Owner passkey",
      });
      expect(registered.status).toBe(200);
      expect(memory.passkey).toHaveLength(1);
      const stale = operation.startsWith("stale-counter");
      if (operation.includes("counter")) memory.passkey[0].counter = 2;
      const selected = structuredClone(memory.passkey[0]);
      const users = structuredClone(memory.user);
      const sessions = structuredClone(memory.session);
      const update = context.adapter.update.bind(context.adapter);
      context.adapter.update = async input => {
        const result = await update(input);
        updates.push({ input, result });
        return result;
      };
      remove = true;
      if (operation !== "rename") {
        const pending = await request("generate-authenticate-options");
        expect(pending.status).toBe(200);
        const options = await pending.json() as AuthenticationOptions;
        const assertion = key.authenticate(
          invalidRp ? { ...options, rpId: "wrong-rp.test" } : options,
          invalidOrigin ? "https://wrong-origin.test" : origin,
          validCounter ? 3 : dynamic ? 0 : 1,
          invalidFlags ? 0x15 : 0x01,
          registration.user.id,
        );
        if (operation.endsWith("signature")) {
          const signature = Buffer.from(assertion.response.signature, "base64url");
          signature[signature.length - 1] ^= 1;
          assertion.response.signature = signature.toString("base64url");
        }
        const result = await request("verify-authentication", cookies(pending), { response: assertion });
        if (stale || invalidFlags) {
          expect(result.status).toBe(400);
          expect(await result.json()).toStrictEqual({ code: "AUTHENTICATION_FAILED", message: "Authentication failed" });
          expect(result.headers.getSetCookie().some(value => value.startsWith(`${context.authCookies.sessionToken.name}=`))).toBe(false);
          expect(memory).toStrictEqual({ user: users, session: sessions, account: [], verification: [], passkey: [selected] });
          expect(updates).toStrictEqual([]);
          expect(deletions).toBe(0);
          expect(logs).toHaveLength(1);
          const [level, message, error] = logs[0] as [unknown, unknown, Error];
          expect([level, message]).toStrictEqual(["error", "Failed to verify authentication"]);
          expect(error).toBeInstanceOf(Error);
          expect(error.name).toBe(invalidRp ? "UnexpectedRPIDHash" : validCounter ? "InvalidBackupFlags" : "Error");
          expect(error.message).toBe(invalidOrigin
            ? `Unexpected authentication response origin "https://wrong-origin.test", expected "${origin}"`
            : invalidRp
              ? "Unexpected RP ID hash"
              : validCounter
                ? "Single-device credential indicated that it was backed up, which should be impossible."
                : dynamic
                  ? "Response counter value 0 was lower than expected projected counter"
                  : "Response counter value 1 was lower than expected 2");
          expect(Object.keys(error)).toStrictEqual(invalidRp || validCounter ? ["name"] : []);
          expect(conversions).toStrictEqual(!dynamic || invalidOrigin || invalidRp
            ? []
            : validCounter ? ["valueOf"] : ["valueOf", "valueOf", "toString"]);
          return;
        }
        expect(result.status).toBe(200);
        expect(memory.session).toHaveLength(sessions.length + 1);
        const created = memory.session.find(session => !sessions.some(old => old.id === session.id));
        expect(await result.json()).toStrictEqual(JSON.parse(JSON.stringify({ session: created, user: users[0] })));
        expect(result.headers.getSetCookie().some(value => value.startsWith(`${context.authCookies.sessionToken.name}=`))).toBe(true);
        expect(updates).toStrictEqual([{ input: {
          model: "passkey", where: [{ field: "id", value: selected.id }], update: { counter: 1 },
        }, result: null }]);
      } else {
        const result = await request("update-passkey", loginCookie, { id: selected.id, name: "Renamed" });
        expect(result.status).toBe(500);
        expect(await result.json()).toStrictEqual({ code: "FAILED_TO_UPDATE_PASSKEY", message: "Failed to update passkey" });
        expect(memory.session).toStrictEqual(sessions);
        expect(updates).toStrictEqual([{ input: {
          model: "passkey", where: [{ field: "id", value: selected.id }], update: { name: "Renamed" },
        }, result: null }]);
      }
      expect(deletions).toBe(1);
      expect(memory.passkey).toStrictEqual([]);
      expect(memory.user).toStrictEqual(users);
      expect(memory.account).toStrictEqual([]);
      expect(memory.verification).toStrictEqual([]);
      expect(logs).toStrictEqual([]);
    });
  });
}
