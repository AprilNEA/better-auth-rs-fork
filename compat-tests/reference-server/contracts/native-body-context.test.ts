import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { anonymous } from "better-auth/plugins";

const origin = "http://native-body-context.test";
const secret = "native-body-context-secret-at-least-32-characters";
const inputs = { missing: undefined, null: null, false: false, number: 7, array: [1, 2], object: { label: "original" } };

for (const http of [false, true]) for (const apiKeyHook of [false, true]) for (const [name, specimen] of Object.entries(inputs)) {
  test(`native body survives hooks and ${apiKeyHook ? "API Key" : "Anonymous"} callbacks: ${name}, http=${http}`, async () => {
    const input = name === "object" ? { label: "original" } : specimen;
    const database = { user: [], session: [], account: [], verification: [], apikey: [] };
    const events: string[] = [];
    const failure = new APIError("CONFLICT", { message: "body observed" });
    const shared = { ownUndefined: undefined, date: new Date(1_893_456_000_000), get unread(): never { throw new Error("Body must not be enumerated"); } };
    let captured: any;
    const check = (body: any, phase: string) => {
      events.push(phase);
      expect(body).toBe(captured);
      if (name === "object") {
        expect(body.label).toBe("changed");
        expect(body.shared).toBe(shared);
        expect(body.alias).toBe(shared);
        expect(body.self).toBe(body);
        expect(Object.hasOwn(body.shared, "ownUndefined")).toBe(true);
        expect(body.shared.ownUndefined).toBeUndefined();
        expect(body.shared.date).toBe(shared.date);
      } else expect(body).toStrictEqual(input);
    };
    const auth = betterAuth({
      baseURL: origin, secret, database: memoryAdapter(database),
      logger: { disabled: true }, telemetry: { enabled: false },
      hooks: {
        before: createAuthMiddleware(async ctx => {
          if (ctx.path !== "/sign-in/anonymous") return;
          events.push("before");
          captured = ctx.body;
          if (name === "object") Object.assign(captured, { label: "changed", shared, alias: shared, self: captured });
        }),
        after: createAuthMiddleware(async ctx => {
          if (ctx.path !== "/sign-in/anonymous") return;
          check(ctx.body, "after");
          expect(ctx.context.returned).toBe(failure);
          expect(ctx.context.newSession).toBeNull();
        }),
      },
      plugins: [
        {
          id: "body-observer",
          hooks: { before: [{ matcher: ctx => ctx.path === "/sign-in/anonymous", handler: createAuthMiddleware(async ctx => { check(ctx.body, "plugin-before"); }) }] },
        },
        ...(apiKeyHook ? [apiKey({
          enableSessionForAPIKeys: true,
          customAPIKeyGetter(ctx) { check(ctx.body, "key-getter"); return "x".repeat(64); },
          async customAPIKeyValidator({ ctx }) { check(ctx.body, "key-validator"); throw failure; },
        })] : []),
        anonymous({
          generateRandomEmail() { events.push("email"); return "body@anonymous.test"; },
          generateName(ctx) { check(ctx.body, "name"); throw failure; },
        }),
      ],
    });
    try {
      if (http) {
        const response = await auth.handler(new Request(`${origin}/api/auth/sign-in/anonymous`, {
          method: "POST", headers: { "content-type": "application/json" },
          ...(input === undefined ? {} : { body: JSON.stringify(input) }),
        }));
        expect(response.status).toBe(409);
        expect(response.headers.get("set-cookie")).toBeNull();
        expect(await response.text()).toBe('{"message":"body observed"}');
      } else {
        let caught: unknown;
        try { await auth.api.signInAnonymous({ ...(input === undefined ? {} : { body: input as any }) }); }
        catch (error) { caught = error; }
        expect(caught).toBe(failure);
      }
      expect(events).toStrictEqual(apiKeyHook
        ? ["before", "plugin-before", "key-getter", "key-getter", "key-validator"]
        : ["before", "plugin-before", "email", "name", "after"]);
      expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [], apikey: [] });
    } finally {
      if (name === "object" && captured) delete captured.self;
    }
  });
}

for (const [method, field, body] of [
  ["createApiKey", "name", { userId: "owner", name: "original" }],
  ["updateApiKey", "keyId", { userId: "owner", keyId: "original" }],
  ["verifyApiKey", "key", { key: "original" }],
] as const) {
  test(`API Key getter mutations reach ${method} validation`, async () => {
    const database = { user: [], session: [], account: [], verification: [], apikey: [] };
    let calls = 0;
    const auth = betterAuth({
      baseURL: origin, secret, database: memoryAdapter(database),
      logger: { disabled: true }, telemetry: { enabled: false },
      plugins: [apiKey({ enableSessionForAPIKeys: true, customAPIKeyGetter(ctx) {
        calls++;
        ctx.body[field] = 7;
        return null;
      } })],
    });
    let caught: any;
    try { await auth.api[method]({ body: { ...body } } as any); }
    catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(APIError);
    expect(caught.status).toBe("BAD_REQUEST");
    expect(caught.body).toStrictEqual({ code: "VALIDATION_ERROR", message: `[body.${field}] Invalid input: expected string, received number` });
    expect(calls).toBe(1);
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [], apikey: [] });
  });
}

test("API Key schema retains native metadata until the permission callback", async () => {
  const database = { user: [], session: [], account: [], verification: [], apikey: [] };
  const failure = new APIError("CONFLICT", { message: "metadata observed" });
  const metadata = { ownUndefined: undefined, date: new Date(1_893_456_000_000), get unread(): never { throw new Error("Metadata must not be enumerated"); } };
  const events: string[] = [];
  let raw: any;
  const auth = betterAuth({
    baseURL: origin, secret, database: memoryAdapter(database),
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [apiKey({
      enableSessionForAPIKeys: true, enableMetadata: true,
      customAPIKeyGetter(ctx) { events.push("getter"); raw = ctx.body; ctx.body.metadata = metadata; return null; },
      customKeyGenerator() { events.push("generator"); return "x".repeat(64); },
      permissions: { defaultPermissions(referenceId, ctx) {
        events.push("permissions");
        expect(referenceId).toBe("owner");
        expect(ctx.body).not.toBe(raw);
        expect(ctx.body.metadata).toBe(metadata);
        expect(Object.hasOwn(ctx.body.metadata, "ownUndefined")).toBe(true);
        expect(ctx.body.metadata.date).toBe(metadata.date);
        expect(Object.keys(ctx.body)).toStrictEqual(["expiresIn", "remaining", "metadata", "userId"]);
        throw failure;
      } },
    })],
  });
  let caught: unknown;
  try { await auth.api.createApiKey({ body: { userId: "owner" } }); }
  catch (error) { caught = error; }
  expect(caught).toBe(failure);
  expect(events).toStrictEqual(["getter", "generator", "permissions"]);
  expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [], apikey: [] });
});
