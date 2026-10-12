import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import { phoneNumber } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";

const secret = "update-user-native-session-secret-at-least-32-characters";
const origin = "http://update-user-session.test";
const expires = 4_102_444_800_000;
const date = () => new Date(1_893_456_000_000);
const cases = [
  "matched", "numeric-id", "missing-id", "null-id", "undefined-id", "false-user",
  "number-user", "string-user", "array-user", "null-user", "undefined-user", "cancel",
  "before-error", "after-error", "output-transform", "image-only", "null-name",
  "null-no-fields", "undefined-email", "getter-id", "getter-cancel", "getter-error",
  "getter-no-fields", "getter-email", "getter-fallback-error",
];
const user = (id: string) => ({
  name: "Stored", email: `${id}@update-user.test`, emailVerified: true, image: null,
  createdAt: date(), updatedAt: date(), marker: "old", private: true, id,
});
const session = (token: string, userId: string) => ({
  id: `${token}-id`, expiresAt: new Date(expires), token, createdAt: date(), updatedAt: date(),
  ipAddress: null, userAgent: null, userId,
});
const noFields = (scenario: string) => ["null-no-fields", "getter-no-fields"].includes(scenario);
const emailGuard = (scenario: string) => ["undefined-email", "getter-email"].includes(scenario);
const cancelled = (scenario: string) => ["cancel", "getter-cancel"].includes(scenario);
const matchesRow = (scenario: string) => [
  "matched", "cancel", "before-error", "after-error", "output-transform", "image-only",
  "null-name", "getter-id", "getter-cancel",
].includes(scenario);
const failed = (scenario: string) => [
  "null-user", "undefined-user", "before-error", "after-error", "getter-error", "getter-fallback-error",
].includes(scenario) || noFields(scenario) || emailGuard(scenario);
function body(scenario: string) {
  if (scenario === "image-only") return { image: null };
  if (scenario === "null-name") return { name: null };
  if (noFields(scenario)) return {};
  if (emailGuard(scenario)) return { email: "changed@update-user.test" };
  return { name: 17, marker: "next" };
}

for (const scenario of ["clear", "cancel", "missing", "patch", "blocked", "set"]) for (const endpoint of [false, true]) {
  if ((scenario === "blocked" && !endpoint) || (scenario === "set" && endpoint)) continue;
  test(`Phone clear hook preserves original input and fallback ${scenario}, endpoint=${endpoint}`, async () => {
    const phoneUser = () => {
      const { marker, private: privateField, id, ...fields } = user("7");
      return { ...fields, phoneNumber: "+15550000001", phoneNumberVerified: true, id };
    };
    const events: string[] = [];
    const inputs: any[] = [];
    const updates: any[] = [];
    const issued: any[] = [];
    const id = scenario === "missing" ? "missing" : "7";
    const injected = {
      session: session("injected-token", "snapshot-user"),
      user: { ...phoneUser(), name: "Snapshot", phoneNumber: "+15550000003", id },
    };
    const database = { user: [phoneUser()], session: [], account: [], verification: [] };
    const auth = betterAuth({
      database: memoryAdapter(database), baseURL: origin, secret,
      logger: { disabled: true }, telemetry: { enabled: false },
      user: { additionalFields: {
        updatedAt: { type: "date", onUpdate: date },
        ...(scenario === "blocked" ? { phoneNumber: { type: "string" as const, input: false } } : {}),
      } },
      plugins: [phoneNumber({ async sendOTP() { throw new Error("Update-user must not send OTP"); } })],
      hooks: {
        before: createAuthMiddleware(async ctx => { events.push("endpoint.before"); ctx.context.session = injected; }),
        after: createAuthMiddleware(async ctx => { events.push("endpoint.after"); issued.push(ctx.context.newSession); }),
      },
      databaseHooks: { user: { update: {
        async before(input) {
          events.push("db.before"); inputs.push(input);
          if (scenario === "cancel") return false;
          if (scenario === "patch") return { data: { phoneNumber: "+15550000002" } };
        },
        async after(value) { events.push("db.after"); updates.push(value); },
      } } },
    });
    const context = await auth.$context;
    const phone = scenario === "set" ? "+15550000004" : null;
    const input = { phoneNumber: phone };
    let returned: any;
    if (endpoint) {
      if (scenario === "blocked") {
        let caught: any;
        try { await auth.api.updateUser({ body: input }); } catch (error) { caught = error; }
        expect(caught).toBeInstanceOf(APIError);
        expect(caught.status).toBe("BAD_REQUEST");
        expect(caught.body).toStrictEqual({ message: "No fields to update" });
      } else expect(await auth.api.updateUser({ body: input })).toStrictEqual({ status: true });
    } else returned = await context.internalAdapter.updateUser(id, input);
    const wrote = !["cancel", "missing", "blocked"].includes(scenario);
    const stored = { ...phoneUser(), ...(wrote ? {
      phoneNumber: scenario === "patch" ? "+15550000002" : phone,
      ...(scenario === "set" ? {} : { phoneNumberVerified: false }),
    } : {}) };
    expect(database).toStrictEqual({ user: [stored], session: [], account: [], verification: [] });
    const expectedEvents = endpoint ? ["endpoint.before"] : [];
    if (scenario !== "blocked") {
      expectedEvents.push("db.before");
      expect(inputs.length).toBe(1);
      ordered(inputs[0], { ...(endpoint ? { name: undefined, image: undefined } : {}), ...input });
      if (scenario !== "cancel") expectedEvents.push("db.after");
      expect(updates).toStrictEqual(scenario === "cancel" ? [] : [wrote ? stored : null]);
    } else { expect(inputs).toStrictEqual([]); expect(updates).toStrictEqual([]); }
    if (endpoint) expectedEvents.push("endpoint.after");
    expect(events).toStrictEqual(expectedEvents);
    if (endpoint) {
      expect(issued.length).toBe(1);
      if (scenario === "blocked") expect(issued[0]).toBeNull();
      else {
        ordered(issued[0].user, wrote ? stored : { ...injected.user, phoneNumber: phone });
        expect(issued[0].session).toStrictEqual(injected.session);
      }
    } else expect(returned).toStrictEqual(wrote ? stored : null);
  });
}
function snapshotUser(scenario: string, shared: object): any {
  if (scenario === "false-user") return false;
  if (scenario === "number-user") return 7;
  if (scenario === "string-user") return "ab";
  if (scenario === "array-user") return [shared, shared];
  if (["null-user", "null-no-fields"].includes(scenario)) return null;
  if (["undefined-user", "undefined-email"].includes(scenario)) return undefined;
  const fields: Record<string, unknown> = {
    name: false, image: 9, email: null, emailVerified: "dynamic", private: false,
    ownUndefined: undefined, shared, alias: shared,
  };
  if (scenario !== "missing-id") {
    fields.id = scenario === "numeric-id" ? 7 : scenario === "null-id" ? null
      : ["undefined-id", "getter-fallback-error"].includes(scenario) ? undefined : "7";
  }
  if (["getter-id", "getter-fallback-error"].includes(scenario)) fields.unread = null;
  return fields;
}
function injectedUser(scenario: string, shared: object, events: string[], thrown: object) {
  const fields = snapshotUser(scenario, shared);
  if (!scenario.startsWith("getter-")) return fields;
  const id = fields.id;
  Object.defineProperty(fields, "id", {
    enumerable: true,
    get() {
      events.push("user.id");
      if (["getter-error", "getter-no-fields", "getter-email"].includes(scenario)) throw thrown;
      return id;
    },
  });
  if (Object.hasOwn(fields, "unread")) Object.defineProperty(fields, "unread", {
    enumerable: true,
    get() { events.push("user.unread"); throw thrown; },
  });
  return fields;
}
function expectedFields(scenario: string, fields: Record<string, any>) {
  return { ...fields, ...body(scenario) };
}
function ordered(actual: object, expected: object) {
  expect(Object.keys(actual)).toStrictEqual(Object.keys(expected));
  expect(actual).toStrictEqual(expected);
}

for (const scenario of cases) for (const signedCookie of [false, true]) {
  test(`update-user consumes ${scenario} native Session with signed cookie ${signedCookie}`, async () => {
    const shared = { value: undefined };
    const thrown = { failure: scenario };
    const events: string[] = [];
    const inputs: any[] = [];
    const updates: any[] = [];
    const versions: any[] = [];
    const issued: any[] = [];
    const injected = {
      session: session("injected-token", "snapshot-user"),
      user: injectedUser(scenario, shared, events, thrown),
    };
    const database = {
      user: [user("7"), user("cookie-owner")], session: [session("stored-token", "cookie-owner")],
      account: [], verification: [],
    };
    const initialCache = new Map([
      ["active-sessions-7", JSON.stringify([{ token: "cached-token", expiresAt: expires }])],
      ["cached-token", JSON.stringify({ session: session("cached-token", "7"), user: user("7") })],
    ]);
    const cache = new Map(initialCache);
    const auth = betterAuth({
      database: memoryAdapter(database), baseURL: origin, secret,
      logger: { disabled: true }, telemetry: { enabled: false },
      user: { additionalFields: {
        marker: { type: "string" }, private: { type: "boolean", returned: false },
        updatedAt: { type: "date", onUpdate: date },
        ...(scenario === "output-transform" ? { name: {
          type: "string" as const, transform: { output(value: unknown) { events.push("output"); return [value]; } },
        } } : {}),
      } },
      session: {
        storeSessionInDatabase: true,
        cookieCache: {
          enabled: true,
          version(session, user) { events.push("version"); versions.push({ session, user }); return "native-v1"; },
        },
      },
      secondaryStorage: {
        async get(key) { events.push(`cache.get:${key}`); return cache.get(key) ?? null; },
        async set(key, value, ttl) {
          const expected = (expires - Date.now()) / 1_000;
          expect(ttl).toBeGreaterThanOrEqual(expected - 1);
          expect(ttl).toBeLessThanOrEqual(expected + 1);
          events.push(`cache.set:${key}`);
          cache.set(key, value);
        },
        async delete() { throw new Error("Update-user must not delete cache entries"); },
      },
      hooks: {
        before: createAuthMiddleware(async ctx => {
          events.push("endpoint.before");
          ctx.context.session = injected;
        }),
        after: createAuthMiddleware(async ctx => {
          events.push("endpoint.after");
          issued.push(ctx.context.newSession);
        }),
      },
      databaseHooks: { user: { update: {
        async before(data) {
          events.push("db.before");
          inputs.push(data);
          if (cancelled(scenario)) return false;
          if (scenario === "before-error") throw thrown;
        },
        async after(data) {
          events.push("db.after");
          updates.push(data);
          if (scenario === "after-error") throw thrown;
        },
      } } },
    });
    await auth.$context;
    events.length = 0;
    const headers = new Headers();
    if (signedCookie) headers.set("cookie", (await serializeSignedCookie("better-auth.session_token", "stored-token", secret)).split(";")[0]);
    let returned: any;
    let caught: any;
    const started = Date.now();
    try { returned = await auth.api.updateUser({ body: body(scenario), headers, returnHeaders: true }); }
    catch (error) { caught = error; }
    const ended = Date.now();
    const wrote = matchesRow(scenario) && !cancelled(scenario) && scenario !== "before-error";
    const stored = wrote ? expectedFields(scenario, user("7")) : user("7");
    expect(database).toStrictEqual({
      user: [stored, user("cookie-owner")], session: [session("stored-token", "cookie-owner")],
      account: [], verification: [],
    });
    const updated = scenario === "output-transform" ? { ...stored, name: [17] } : stored;
    const refreshed = wrote && scenario !== "after-error";
    const expectedCache = new Map(initialCache);
    if (refreshed) expectedCache.set("cached-token", JSON.stringify({ session: session("cached-token", "7"), user: updated }));
    expect([...cache.keys()]).toStrictEqual([...expectedCache.keys()]);
    for (const [key, value] of expectedCache) expect(JSON.parse(cache.get(key)!)).toStrictEqual(JSON.parse(value));
    const expectedEvents = ["endpoint.before"];
    if (scenario.startsWith("getter-") && !noFields(scenario) && !emailGuard(scenario)) expectedEvents.push("user.id");
    if (!["null-user", "undefined-user", "getter-error"].includes(scenario) && !noFields(scenario) && !emailGuard(scenario)) {
      expectedEvents.push("db.before");
      const input = body(scenario) as Record<string, unknown>;
      const expectedInput = { name: input.name, image: input.image, ...(Object.hasOwn(input, "marker") ? { marker: input.marker } : {}) };
      expect(inputs.length).toBe(1);
      ordered(inputs[0], expectedInput);
      if (!cancelled(scenario) && scenario !== "before-error") {
        if (scenario === "output-transform") expectedEvents.push("output");
        expectedEvents.push("db.after");
        expect(updates).toStrictEqual([matchesRow(scenario) ? updated : null]);
      } else expect(updates).toStrictEqual([]);
    } else {
      expect(inputs).toStrictEqual([]);
      expect(updates).toStrictEqual([]);
    }
    if (refreshed) expectedEvents.push("cache.get:active-sessions-7", "cache.get:cached-token", "cache.set:cached-token");
    if (["getter-cancel", "getter-fallback-error"].includes(scenario)) expectedEvents.push("user.id");
    if (scenario === "getter-fallback-error") expectedEvents.push("user.unread");
    if (!failed(scenario)) expectedEvents.push("version");
    if (!failed(scenario) || noFields(scenario) || emailGuard(scenario)) expectedEvents.push("endpoint.after");
    expect(events).toStrictEqual(expectedEvents);
    if (failed(scenario)) {
      expect(returned).toBeUndefined();
      expect(versions).toStrictEqual([]);
      if (noFields(scenario) || emailGuard(scenario)) {
        expect(caught).toBeInstanceOf(APIError);
        expect(caught.status).toBe("BAD_REQUEST");
        expect(caught.body).toStrictEqual(noFields(scenario) ? { message: "No fields to update" }
          : { message: "Email can not be updated", code: "EMAIL_CAN_NOT_BE_UPDATED" });
        expect(issued).toStrictEqual([null]);
      } else {
        expect(issued).toStrictEqual([]);
        if (["before-error", "after-error", "getter-error", "getter-fallback-error"].includes(scenario)) expect(caught).toBe(thrown);
        else expect(caught).toBeInstanceOf(TypeError);
      }
      return;
    }
    expect(caught).toBeUndefined();
    expect(returned.response).toStrictEqual({ status: true });
    const expected = refreshed ? updated : expectedFields(scenario, snapshotUser(scenario, shared));
    expect(versions.length).toBe(1);
    expect(issued.length).toBe(1);
    expect(versions[0].user).toBe(issued[0].user);
    for (const snapshot of [versions[0], issued[0]]) {
      ordered(snapshot.user, expected);
      expect(snapshot.session).toStrictEqual(session("injected-token", "snapshot-user"));
      if (!refreshed && injected.user && !Array.isArray(injected.user) && typeof injected.user === "object") {
        expect(snapshot.user.shared).toBe(shared);
        expect(snapshot.user.alias).toBe(shared);
      }
      if (scenario === "array-user") {
        expect(snapshot.user[0]).toBe(shared);
        expect(snapshot.user[1]).toBe(shared);
      }
    }
    const cookies = returned.headers.getSetCookie().map((value: string) => value.split(";")[0]);
    expect(cookies.length).toBe(2);
    expect(cookies[0]).toBe((await serializeSignedCookie("better-auth.session_token", "injected-token", secret)).split(";")[0]);
    expect(cookies[1].startsWith("better-auth.session_data=")).toBe(true);
    const envelope = JSON.parse(Buffer.from(cookies[1].slice("better-auth.session_data=".length), "base64url").toString());
    const publicUser = { ...expected };
    delete publicUser.private;
    expect(envelope.session.updatedAt).toBeGreaterThanOrEqual(started);
    expect(envelope.session.updatedAt).toBeLessThanOrEqual(ended);
    expect(envelope.expiresAt).toBeGreaterThan(envelope.session.updatedAt);
    expect(typeof envelope.signature).toBe("string");
    expect(envelope.signature.length).toBeGreaterThan(0);
    expect(envelope).toStrictEqual({
      session: {
        user: JSON.parse(JSON.stringify(publicUser)), session: JSON.parse(JSON.stringify(session("injected-token", "snapshot-user"))),
        updatedAt: envelope.session.updatedAt, version: "native-v1",
      },
      expiresAt: envelope.expiresAt, signature: envelope.signature,
    });
  });
}
