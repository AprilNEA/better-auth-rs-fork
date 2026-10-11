import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { testUtils } from "better-auth/plugins";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { withRestoredSchema } from "./schema-isolation.mjs";

for (const reject of [false, true]) {
  test(`JSON getter traversal ${reject ? "retains the original child error" : "reads later properties after the child"}`, () => {
    const events = [];
    const failure = new Error("JSON getter original error");
    const state = { tail: "before", drop: true };
    const child = { get value() {
      events.push("child.value");
      if (reject) throw failure;
      state.tail = "after";
      delete outer.drop;
      outer.added = true;
      return 1;
    } };
    const outer = {
      get child() { events.push("outer.child"); return child; },
      get tail() { events.push("outer.tail"); return state.tail; },
      get drop() { events.push("outer.drop"); return state.drop; },
    };
    let actual;
    let caught;
    try { actual = JSON.stringify(outer); } catch (error) { caught = error; }
    if (reject) {
      expect(caught).toBe(failure);
      expect(actual).toBeUndefined();
      expect(events).toStrictEqual(["outer.child", "child.value"]);
      expect(Object.keys(outer)).toStrictEqual(["child", "tail", "drop"]);
      expect(state).toStrictEqual({ tail: "before", drop: true });
    } else {
      expect(caught).toBeUndefined();
      expect(actual).toBe('{"child":{"value":1},"tail":"after"}');
      expect(events).toStrictEqual(["outer.child", "child.value", "outer.tail"]);
      expect(Object.keys(outer)).toStrictEqual(["child", "tail", "added"]);
      expect(state).toStrictEqual({ tail: "after", drop: true });
      expect(outer.added).toBe(true);
    }
  });
}

test("JSON toJSON receives the original receiver and each root, property, or array key", () => {
  const events = [];
  const shared = { toJSON(key) { expect(this).toBe(shared); events.push(key); return key; } };
  expect(JSON.stringify(shared)).toBe('""');
  expect(JSON.stringify({ left: shared, right: shared, items: [shared, shared] }))
    .toBe('{"left":"left","right":"right","items":["0","1"]}');
  expect(events).toStrictEqual(["", "left", "right", "0", "1"]);
});

test("JSON prepares a method result once and omits undefined at the containing boundary", () => {
  const events = [];
  const date = new Date(0);
  date.toJSON = function () { events.push("returned-date-method"); return "unexpected"; };
  const returned = { toJSON() { events.push("returned-object-method"); return "unexpected"; }, value: 7 };
  const dateValue = { toJSON(key) { expect(this).toBe(dateValue); events.push(["date", key]); return date; } };
  const objectValue = { toJSON(key) { expect(this).toBe(objectValue); events.push(["object", key]); return returned; } };
  const omitted = { toJSON(key) { expect(this).toBe(omitted); events.push(["omit", key]); return undefined; } };
  expect(JSON.stringify({ date: dateValue, object: objectValue, omitted, items: [omitted] }))
    .toBe('{"date":{},"object":{"value":7},"items":[null]}');
  expect(JSON.stringify(omitted)).toBeUndefined();
  expect(events).toStrictEqual([["date", "date"], ["object", "object"], ["omit", "omitted"], ["omit", "0"], ["omit", ""]]);
  expect(JSON.stringify({ toJSON: 3, value: 7 })).toBe('{"toJSON":3,"value":7}');
});

for (const failAt of ["none", "getter", "method"]) {
  test(`JSON toJSON getter and method preserve mutation order and the original ${failAt} error`, () => {
    const events = [];
    const failure = new Error("original toJSON error");
    const outer = {};
    const child = {
      get toJSON() {
        events.push("get:toJSON");
        outer.tail = "after-getter";
        if (failAt === "getter") throw failure;
        return function (key) {
          expect(this).toBe(child);
          expect(key).toBe("child");
          events.push("call:toJSON");
          outer.tail = "after-method";
          delete outer.drop;
          outer.added = true;
          if (failAt === "method") throw failure;
          return { get value() { events.push("returned.value"); return 7; } };
        };
      },
    };
    Object.assign(outer, { child, tail: "before", drop: true });
    let result;
    let caught;
    try { result = JSON.stringify(outer); } catch (error) { caught = error; }
    if (failAt === "none") {
      expect(caught).toBeUndefined();
      expect(result).toBe('{"child":{"value":7},"tail":"after-method"}');
      expect(events).toStrictEqual(["get:toJSON", "call:toJSON", "returned.value"]);
    } else {
      expect(caught).toBe(failure);
      expect(result).toBeUndefined();
      expect(events).toStrictEqual(failAt === "getter" ? ["get:toJSON"] : ["get:toJSON", "call:toJSON"]);
    }
    expect(outer.tail).toBe(failAt === "getter" ? "after-getter" : "after-method");
    expect(Object.keys(outer)).toStrictEqual(failAt === "getter" ? ["child", "tail", "drop"] : ["child", "tail", "added"]);
  });
}

function responseJsonValue(mode, events, failure) {
  const bundle = {};
  const alias = { toJSON(key) {
    expect(this).toBe(alias);
    events.push(["alias", key]);
    bundle.tail = "after";
    delete bundle.drop;
    bundle.added = true;
    if (mode === "error") throw failure;
    return key;
  } };
  const omitted = { toJSON(key) { expect(this).toBe(omitted); events.push(["omit", key]); return undefined; } };
  const date = { toJSON(key) { expect(this).toBe(date); events.push(["date", key]); return new Date(0); } };
  Object.assign(bundle, { first: alias, omit: omitted, last: alias, date, tail: "before", drop: true });
  const value = { toJSON(key) {
    expect(this).toBe(value);
    events.push(["name", key]);
    return mode === "omit" ? undefined : bundle;
  } };
  return { value, bundle };
}

for (const model of ["apikey", "passkey"]) {
  for (const mode of ["nested", "omit", "error"]) {
    test(`${model} response retains toJSON identity before hooks and observes ${mode} only at HTTP encoding`, async () => {
      await withRestoredSchema(passkey().schema, async () => {
        const memory = { user: [], session: [], account: [], verification: [], apikey: [], passkey: [] };
        const events = [];
        const observed = [];
        const failure = new Error("original response toJSON error");
        const probe = responseJsonValue(mode, events, failure);
        let replacement;
        const path = model === "apikey" ? "/api-key/get" : "/passkey/list-user-passkeys";
        const auth = betterAuth({
          database: memoryAdapter(memory), baseURL: "http://response-json.test",
          secret: "response-json-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
          hooks: { after: createAuthMiddleware(async ctx => {
            if (ctx.path === path) observed.push(ctx.context.returned);
          }) },
          plugins: [apiKey(), passkey(), testUtils(), { id: "response-to-json", schema: {
            [model]: { fields: { name: { type: "string", required: false,
              transform: { output(value) { return replacement ?? value; } },
            } } },
          } }],
        });
        const context = await auth.$context;
        const now = new Date();
        const owner = await context.adapter.create({ model: "user", data: {
          name: "Owner", email: "owner@response-json.test", emailVerified: true, createdAt: now, updatedAt: now,
        } });
        const login = await context.test.login({ userId: owner.id });
        const headers = login.headers;
        const row = await context.adapter.create({ model, data: model === "apikey" ? {
          name: "Stored", key: "response-json-key", configId: "default", referenceId: owner.id,
          enabled: true, rateLimitEnabled: false, requestCount: 0, createdAt: now, updatedAt: now,
        } : {
          name: "Stored", publicKey: "ordinary-public-key", userId: owner.id, credentialID: "response-json-credential",
          counter: 0, deviceType: "singleDevice", backedUp: false, createdAt: now,
        } });
        const read = asResponse => model === "apikey"
          ? auth.api.getApiKey({ headers, query: { id: row.id }, asResponse })
          : auth.api.listPasskeys({ headers, asResponse });
        const resultRow = result => model === "apikey" ? result : result[0];
        const baseline = JSON.parse(JSON.stringify(await read(false)));
        const stored = structuredClone(memory[model]);
        observed.length = 0;
        replacement = probe.value;
        const native = await read(false);
        expect(resultRow(native).name).toBe(probe.value);
        expect(resultRow(observed[0]).name.toJSON).toBe(probe.value.toJSON);
        expect(events).toStrictEqual([]);
        let response;
        let caught;
        try { response = await read(true); } catch (error) { caught = error; }
        expect(observed).toHaveLength(2);
        expect(resultRow(observed[1]).name).toBe(probe.value);
        if (mode === "error") {
          expect(caught).toBe(failure);
          expect(response).toBeUndefined();
          expect(events).toStrictEqual([["name", "name"], ["alias", "first"]]);
        } else {
          expect(caught).toBeUndefined();
          expect(response.status).toBe(200);
          expect(response.headers.get("content-type")).toBe("application/json");
          if (mode === "omit") {
            delete resultRow(baseline).name;
            expect(events).toStrictEqual([["name", "name"]]);
          } else {
            resultRow(baseline).name = { first: "first", last: "last", date: {}, tail: "after" };
            expect(events).toStrictEqual([["name", "name"], ["alias", "first"], ["omit", "omit"], ["alias", "last"], ["date", "date"]]);
          }
          expect(await response.text()).toBe(JSON.stringify(baseline));
        }
        expect(memory[model]).toStrictEqual(stored);
        expect(probe.bundle.tail).toBe(mode === "omit" ? "before" : "after");
        expect(Object.hasOwn(probe.bundle, "drop")).toBe(mode === "omit");
        expect(Object.hasOwn(probe.bundle, "added")).toBe(mode !== "omit");
      });
    });
  }
}
