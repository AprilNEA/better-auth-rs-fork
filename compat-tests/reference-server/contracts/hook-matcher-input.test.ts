import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { anonymous, phoneNumber } from "better-auth/plugins";

const baseURL = "http://hook-matcher.test";
const secret = "hook-matcher-input-secret-at-least-32-characters";
const matcherMessage = "An error occurred during hook matcher execution. Check the logs for more details.";

for (const name of ["missing", "null", "false", "number", "string", "array", "empty", "phone-null", "phone-undefined", "phone-value", "unread", "has-throw", "get-throw"] as const) {
  test(`PhoneNumber matcher retains native input semantics: ${name}`, async () => {
    const database = { user: [], session: [], account: [], verification: [] };
    const events: string[] = [];
    const logs: { level: string; message: string; args: unknown[] }[] = [];
    const sentinel = new APIError("CONFLICT", { message: "matcher sentinel" });
    const blocker = new APIError("CONFLICT", { message: "following hook" });
    const input = (() => {
      switch (name) {
        case "missing": return undefined;
        case "null": return null;
        case "false": return false;
        case "number": return 7;
        case "string": return "text";
        case "array": return [];
        case "empty": return {};
        case "phone-null": return { phoneNumber: null };
        case "phone-undefined": return { phoneNumber: undefined };
        case "phone-value": return { phoneNumber: "+15550000001" };
        case "unread": return { get unread(): never { throw sentinel; } };
        default: return new Proxy({}, {
          has(_, field) { events.push(`has:${String(field)}`); if (name === "has-throw") throw sentinel; return true; },
          get(_, field) { events.push(`get:${String(field)}`); throw sentinel; },
        });
      }
    })();
    const auth = betterAuth({
      baseURL, secret, database: memoryAdapter(database), telemetry: { enabled: false },
      logger: { level: "debug", log(level, message, ...args) {
        if (message.includes("hook matcher execution:")) logs.push({ level, message, args });
      } },
      hooks: { after: createAuthMiddleware(async () => { events.push("after"); }) },
      plugins: [phoneNumber({ sendOTP() {} }), {
        id: "following-hook",
        hooks: { before: [{ matcher: ctx => ctx.path === "/update-user", handler: createAuthMiddleware(async ctx => {
          events.push("following");
          expect(ctx.body).toBe(input);
          throw blocker;
        }) }] },
      }],
    });
    let caught: any;
    try { await auth.api.updateUser({ body: input as any }); }
    catch (error) { caught = error; }
    if (["missing", "null", "false", "number", "string", "has-throw", "get-throw"].includes(name)) {
      expect(caught).toBeInstanceOf(APIError);
      expect(caught).not.toBe(sentinel);
      expect(caught.status).toBe("INTERNAL_SERVER_ERROR");
      expect(caught.statusCode).toBe(500);
      expect(caught.body).toStrictEqual({ message: matcherMessage });
      expect(Object.keys(caught.body)).toStrictEqual(["message"]);
      expect(logs).toHaveLength(1);
      expect(logs[0].level).toBe("error");
      expect(logs[0].message).toBe("An error occurred during plugin:phone-number hook matcher execution:");
      expect(logs[0].args).toHaveLength(1);
      if (name === "has-throw" || name === "get-throw") expect(logs[0].args[0]).toBe(sentinel);
      else {
        expect(logs[0].args[0]).toBeInstanceOf(TypeError);
        console.info("Hook matcher primitive error:", JSON.stringify({ scenario: name, message: (logs[0].args[0] as TypeError).message }));
      }
      expect(events).toStrictEqual(name === "has-throw" ? ["has:phoneNumber"] : name === "get-throw" ? ["has:phoneNumber", "get:phoneNumber"] : []);
    } else if (name === "phone-undefined" || name === "phone-value") {
      expect(caught).toBeInstanceOf(APIError);
      expect(caught.status).toBe("BAD_REQUEST");
      expect(caught.body).toStrictEqual({ message: "Phone number cannot be updated", code: "PHONE_NUMBER_CANNOT_BE_UPDATED" });
      expect(events).toStrictEqual([]);
      expect(logs).toStrictEqual([]);
    } else {
      expect(caught).toBe(blocker);
      expect(events).toStrictEqual(["following"]);
      expect(logs).toStrictEqual([]);
    }
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  });
}

for (const failureCall of [1, 2]) {
  test(`API Key wraps only its matcher getter, failure call ${failureCall}`, async () => {
    const database = { user: [], session: [], account: [], verification: [], apikey: [] };
    const sentinel = new APIError("CONFLICT", { message: "key getter failure" });
    const logs: unknown[][] = [];
    let calls = 0;
    const auth = betterAuth({
      baseURL, secret, database: memoryAdapter(database), telemetry: { enabled: false },
      logger: { level: "debug", log(level, message, ...args) {
        if (message.includes("hook matcher execution:")) logs.push([level, message, ...args]);
      } },
      plugins: [apiKey({ enableSessionForAPIKeys: true, customAPIKeyGetter() {
        if (++calls === failureCall) throw sentinel;
        return "x".repeat(64);
      } }), anonymous()],
    });
    let caught: any;
    try { await auth.api.signInAnonymous({}); }
    catch (error) { caught = error; }
    expect(calls).toBe(failureCall);
    if (failureCall === 1) {
      expect(caught).toBeInstanceOf(APIError);
      expect(caught).not.toBe(sentinel);
      expect(caught.status).toBe("INTERNAL_SERVER_ERROR");
      expect(caught.statusCode).toBe(500);
      expect(caught.body).toStrictEqual({ message: matcherMessage });
      expect(logs).toStrictEqual([["error", "An error occurred during plugin:api-key hook matcher execution:", sentinel]]);
      expect(logs[0][2]).toBe(sentinel);
    } else {
      expect(caught).toBe(sentinel);
      expect(logs).toStrictEqual([]);
    }
    expect(database).toStrictEqual({ user: [], session: [], account: [], verification: [], apikey: [] });
  });
}
