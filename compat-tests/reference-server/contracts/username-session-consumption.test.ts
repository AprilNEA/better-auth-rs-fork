import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint, createAuthMiddleware, sessionMiddleware } from "better-auth/api";
import { username } from "better-auth/plugins/username";

const cases = [
  "same-id", "other-id", "zero-id", "false-id", "null-id", "undefined-id", "missing-id",
  "false-user", "number-user", "string-user", "array-user", "null-user", "undefined-user",
  "getter-id", "getter-error", "getter-unused",
];
const date = () => new Date(1_893_456_000_000);
function nativeUser(scenario: string, events: string[], thrown: object): any {
  if (scenario === "false-user") return false;
  if (scenario === "number-user") return 7;
  if (scenario === "string-user") return "ab";
  if (scenario === "array-user") return [{}, {}];
  if (scenario === "null-user") return null;
  if (scenario === "undefined-user") return undefined;
  if (scenario === "missing-id") return {};
  if (scenario === "same-id") return { id: "7" };
  if (scenario === "other-id") return { id: "other" };
  if (scenario === "zero-id") return { id: 0 };
  if (scenario === "false-id") return { id: false };
  if (scenario === "null-id") return { id: null };
  if (scenario === "undefined-id") return { id: undefined };
  return {
    get id() {
      events.push("user.id");
      if (scenario !== "getter-id") throw thrown;
      return "7";
    },
    get unread() { throw new Error("Username validation must not enumerate the injected User"); },
  };
}

for (const scenario of cases) for (const fallback of [false, true]) {
  test(`Username database hook consumes ${scenario} only at validation with fallback ${fallback}`, async () => {
    const events: string[] = [];
    const thrown = { failure: scenario };
    const injected = {
      session: {
        id: "injected-token-id", expiresAt: new Date(4_102_444_800_000), token: "injected-token",
        createdAt: date(), updatedAt: date(), ipAddress: null, userAgent: null, userId: "snapshot-user",
      },
      user: nativeUser(scenario, events, thrown),
    };
    const original = {
      name: "Stored", email: "7@update-user.test", emailVerified: true, image: null,
      createdAt: date(), updatedAt: date(), marker: "old", private: true, id: "7",
      username: "same_user", displayUsername: "Same_User",
    };
    const database = { user: [structuredClone(original)], session: [], account: [], verification: [] };
    const patch = {
      name: "Changed", ...(scenario === "getter-unused" ? {} : { username: "SAME_USER" }),
      ...(fallback ? { id: "7" } : {}),
    };
    const auth = betterAuth({
      baseURL: "http://username-session.test", secret: "update-user-native-session-secret-at-least-32-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, database: memoryAdapter(database),
      user: { additionalFields: { updatedAt: { type: "date", onUpdate: date } } },
      hooks: { before: createAuthMiddleware(async ctx => {
        events.push("endpoint.before");
        ctx.context.session = injected;
      }) },
      plugins: [username(), { id: "username-session-consumer", endpoints: {
        usernameSession: createAuthEndpoint("/username-session", { method: "POST", use: [sessionMiddleware] },
          async ctx => ctx.json(await ctx.context.internalAdapter.updateUser("7", patch))),
      } }],
    });
    let returned: any;
    let caught: any;
    try { returned = await auth.api.usernameSession(); }
    catch (error) { caught = error; }
    const succeeds = ["getter-unused", "same-id", "getter-id"].includes(scenario)
      || (fallback && !["other-id", "getter-error"].includes(scenario));
    expect(events).toStrictEqual(["getter-id", "getter-error"].includes(scenario)
      ? ["endpoint.before", "user.id"] : ["endpoint.before"]);
    const stored = { ...original, ...(succeeds ? { name: "Changed" } : {}) };
    if (succeeds) {
      expect(caught).toBeUndefined();
      const { marker, private: privateField, ...projected } = stored;
      expect(returned).toStrictEqual(projected);
    } else {
      expect(returned).toBeUndefined();
      if (scenario === "getter-error") expect(caught).toBe(thrown);
      else {
        expect(caught).toBeInstanceOf(APIError);
        expect(caught.status).toBe("BAD_REQUEST");
        expect(caught.body).toStrictEqual({
          message: "Username is already taken. Please try another.", code: "USERNAME_IS_ALREADY_TAKEN",
        });
      }
    }
    expect(database).toStrictEqual({ user: [stored], session: [], account: [], verification: [] });
  });
}
