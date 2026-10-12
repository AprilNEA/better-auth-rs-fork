import { expect, test } from "bun:test";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { authenticator, type AuthenticationOptions, type RegistrationOptions } from "../../client-tests/tests/phase8/authenticator";
import { withRestoredSchema } from "./schema-isolation.mjs";

const origin = "http://passkey-null-update.test";
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");

for (const operation of ["authentication", "rename"] as const) {
  test(`a null Passkey update reaches the ${operation} business boundary`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const memory: Record<string, any[]> = { user: [], session: [], account: [], verification: [], passkey: [] };
      let remove = false;
      let deletions = 0;
      const logs: unknown[] = [];
      const updates: unknown[] = [];
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
      if (operation === "authentication") {
        const pending = await request("generate-authenticate-options");
        expect(pending.status).toBe(200);
        const options = await pending.json() as AuthenticationOptions;
        const result = await request("verify-authentication", cookies(pending), {
          response: key.authenticate(options, origin, 1, 0x01, registration.user.id),
        });
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
