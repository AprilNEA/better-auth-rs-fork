import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, isAPIError } from "better-auth/api";
import { APIError as CoreAPIError } from "@better-auth/core/error";
import { withSpan } from "@better-auth/core/instrumentation";
import { trace } from "@opentelemetry/api";
import { APIError, kAPIErrorHeaderSymbol, toResponse } from "better-call";

for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, "1.7.6");
}

const origin = "http://raw-api-errors.test";
const completed = [];
const payload = { code: "RAW_API_ERROR", message: "raw failure" };

function getter(value, key, get) {
  Object.defineProperty(value, key, { configurable: true, enumerable: false, get });
}

function errorValue(events, names = ["APIError"]) {
  const owned = { "x-owned": "1", "set-cookie": "owned=1" };
  const value = { body: payload, status: "BAD_REQUEST", statusCode: 418, headers: owned };
  let reads = 0;
  getter(value, "name", () => {
    events.push(`name:${++reads}`);
    const current = names[Math.min(reads - 1, names.length - 1)];
    if (current instanceof Error) throw current;
    return current;
  });
  return { value, owned };
}

async function settle(operation) {
  try { return { rejected: false, result: await operation() }; }
  catch (error) { return { rejected: true, error }; }
}

function headerState(headers) {
  return { ordinary: [...headers].filter(([name]) => name !== "set-cookie"), cookies: headers.getSetCookie() };
}

function assertHeaders(headers, entries, cookies = []) {
  assert.deepEqual(headerState(headers), { ordinary: Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)), cookies });
}

async function assertHTTP(response, status, entries, cookies = [], bytes = JSON.stringify(payload), statusText = "BAD_REQUEST") {
  assert.equal(response.status, status);
  assert.equal(response.statusText, statusText);
  assert.equal(response.body === null, false);
  assertHeaders(response.headers, { "content-type": "application/json", ...entries }, cookies);
  assert.equal(await response.text(), bytes);
}

function build({ phase = "handler-return", value, events, status, after, debug = false, instrumentation = false }) {
  const retained = {};
  const emit = location => {
    if (phase !== `${location}-return` && phase !== `${location}-throw`) return undefined;
    if (phase.endsWith("throw")) throw value;
    return value;
  };
  const auth = betterAuth({
    baseURL: origin, secret: "raw-api-error-contract-at-least-thirty-two-characters",
    logger: { disabled: true, level: debug ? "debug" : "warn" },
    experimental: { instrumentation: { enabled: instrumentation } },
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    onAPIError: { onError(error) { events.push("on-error"); assert.equal(error, value); } },
    hooks: {
      before: createAuthMiddleware(async ctx => {
        events.push("before"); retained.before = ctx.responseHeaders;
        ctx.setHeader("x-before", "1");
        return emit("before");
      }),
      after: createAuthMiddleware(async ctx => {
        events.push("after"); retained.after = ctx.responseHeaders;
        retained.returned = ctx.context.returned;
        ctx.setHeader("x-after", "1");
        if (after) await after(ctx, retained);
        return emit("after");
      }),
    },
    plugins: [{ id: "raw-api-error", endpoints: {
      rawApiError: createAuthEndpoint("/raw-api-error", { method: "GET" }, async ctx => {
        events.push("handler"); retained.handler = ctx.responseHeaders;
        ctx.setHeader("x-handler", "1");
        if (status !== undefined) ctx.setStatus(status);
        return emit("handler") ?? { ok: true };
      }),
    }, hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
      events.push("plugin-after"); retained.final = ctx.context.returned;
      retained.finalHeaders = ctx.context.responseHeaders;
    }) }] } }],
  });
  return {
    retained,
    call: transport => settle(() => transport === "router"
      ? auth.handler(new Request(`${origin}/api/auth/raw-api-error`))
      : auth.api.rawApiError({ asResponse: transport === "http", returnHeaders: true, returnStatus: true })),
  };
}

async function phases() {
  const schedule = {
    "before-return": ["before"],
    "before-throw": ["before", "name:1", "name:2"],
    "handler-return": ["before", "handler", "after", "plugin-after", "name:1", "name:2"],
    "handler-throw": ["before", "handler", "name:1", "name:2", "name:3", "after", "plugin-after", "name:4", "name:5"],
    "after-return": ["before", "handler", "after", "plugin-after", "name:1", "name:2"],
    "after-throw": ["before", "handler", "after", "name:1", "name:2", "plugin-after", "name:3", "name:4"],
  };
  for (const [phase, baseline] of Object.entries(schedule)) for (const transport of ["native", "http"]) {
    const events = [];
    const { value, owned } = errorValue(events);
    const { call, retained } = build({ phase, value, events, status: 201 });
    const outcome = await call(transport);
    const before = phase.startsWith("before");
    const thrown = phase.endsWith("throw");
    const rejected = phase === "before-throw" || transport === "native" && !before;
    assert.equal(outcome.rejected, rejected, `${phase}/${transport}`);
    const expected = [...baseline];
    if (transport === "http" && !rejected) expected.push(`name:${baseline.filter(event => event.startsWith("name:")).length + 1}`);
    assert.deepEqual(events, expected);
    assert.equal(value.headers, owned);
    const descriptor = Object.getOwnPropertyDescriptor(value, kAPIErrorHeaderSymbol);
    if (phase === "before-return") {
      assert.equal(descriptor, undefined);
      if (transport === "native") {
        assert.deepEqual(Object.keys(outcome.result), ["headers", "response"]);
        assert.equal(outcome.result.response, value);
        assertHeaders(outcome.result.headers, { "x-before": "1" });
      } else await assertHTTP(outcome.result, 418, { "x-before": "1" });
    } else if (phase === "before-throw") {
      assert.equal(outcome.error, value);
      assert.deepEqual(Object.keys(descriptor), ["get", "set", "enumerable", "configurable"]);
      assert.equal(descriptor.enumerable, false); assert.equal(descriptor.configurable, true);
      assert.equal(descriptor.set, undefined); assert.equal(descriptor.get.call(value), retained.before);
    } else {
      assert.equal(retained.final, value);
      if (phase.startsWith("handler")) assert.equal(retained.returned, value);
      if (phase.startsWith("after")) assert.deepEqual(retained.returned, { ok: true });
      const ordinary = { "x-handler": "1", "x-after": "1", ...(thrown ? { "x-owned": "1" } : {}) };
      if (transport === "native") {
        assert.equal(outcome.error, value);
        assert.deepEqual(Object.keys(descriptor), ["value", "writable", "enumerable", "configurable"]);
        assert.equal(descriptor.value, retained.finalHeaders);
        assert.equal(descriptor.writable, false); assert.equal(descriptor.enumerable, false); assert.equal(descriptor.configurable, true);
        assertHeaders(descriptor.value, ordinary, thrown ? ["owned=1"] : []);
      } else await assertHTTP(outcome.result, phase === "handler-throw" ? 418 : 201, ordinary, thrown ? ["owned=1"] : []);
    }
  }
  const events = [];
  const { value } = errorValue(events);
  const { call } = build({ phase: "before-throw", value, events });
  const outcome = await call("router");
  assert.equal(outcome.rejected, false);
  assert.deepEqual(events, ["before", "name:1", "name:2", "name:3", "on-error", "name:4", "name:5"]);
  await assertHTTP(outcome.result, 418, { "x-owned": "1" }, ["owned=1"]);
}

async function classification() {
  {
    const events = [];
    const { value } = errorValue(events);
    for (const key of ["body", "statusCode", "status", "headers"]) getter(value, key, () => { throw new Error(`Native return must not read ${key}`); });
    const { call } = build({ value, events });
    const outcome = await call("native");
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, value);
    assert.deepEqual(events, ["before", "handler", "after", "plugin-after", "name:1", "name:2"]);
  }
  for (const [transport, names, rejected, encoded] of [
    ["native", ["APIError", "Other"], false, false],
    ["native", ["Other", "APIError"], true, false],
    ["http", ["Other", "Other", "APIError"], false, true],
    ["http", ["APIError", "APIError", "Other"], false, false],
  ]) {
    const events = [];
    const { value } = errorValue(events, names);
    const { call } = build({ value, events });
    const outcome = await call(transport);
    assert.equal(outcome.rejected, rejected);
    assert.deepEqual(events, ["before", "handler", "after", "plugin-after", ...names.map((_, index) => `name:${index + 1}`)]);
    if (rejected) assert.equal(outcome.error, value);
    else if (transport === "native") {
      assert.deepEqual(Object.keys(outcome.result), ["headers", "response", "status"]);
      assert.equal(outcome.result.status, undefined); assert.equal(outcome.result.response, value);
      assertHeaders(outcome.result.headers, { "x-handler": "1", "x-after": "1" });
    } else await assertHTTP(outcome.result, encoded ? 418 : 200, { "x-handler": "1", "x-after": "1" }, [], encoded ? JSON.stringify(payload) : JSON.stringify(value), encoded ? "BAD_REQUEST" : "");
  }
  for (const read of [1, 2, 3]) {
    const events = [];
    const failure = new Error(`original classifier ${read}`);
    const names = Array(read).fill("APIError"); names[read - 1] = failure;
    const { value } = errorValue(events, names);
    const { call } = build({ value, events });
    const outcome = await call(read === 3 ? "http" : "native");
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, failure);
    assert.deepEqual(events, ["before", "handler", "after", "plugin-after", ...names.map((_, index) => `name:${index + 1}`)]);
    assert.equal(Object.getOwnPropertyDescriptor(value, kAPIErrorHeaderSymbol), undefined);
  }
}

async function status() {
  for (const [initial, expectedReads, expectedStatus] of [[418, 1, 418], [null, 2, 409], [undefined, 2, 409]]) {
    const events = [];
    const { value } = errorValue(events);
    let current = initial; let reads = 0;
    getter(value, "statusCode", () => { events.push(`status:${++reads}`); return current; });
    const { call } = build({ phase: "handler-throw", value, events, after() { current = 409; } });
    const outcome = await call("http");
    assert.equal(outcome.rejected, false);
    assert.equal(reads, expectedReads);
    assert.deepEqual(events, ["before", "handler", "name:1", "name:2", "name:3", "status:1", "after", "plugin-after", "name:4", "name:5", "name:6", ...(expectedReads === 2 ? ["status:2"] : [])]);
    await assertHTTP(outcome.result, expectedStatus, { "x-handler": "1", "x-after": "1", "x-owned": "1" }, ["owned=1"]);
  }
  for (const phase of ["handler-return", "after-throw"]) {
    const events = [];
    const { value } = errorValue(events);
    getter(value, "statusCode", () => { throw new Error("A defined endpoint status suppresses statusCode"); });
    let number = 202;
    const dynamic = { valueOf() { events.push("number"); assert.equal(this, dynamic); return number; } };
    const { call } = build({ phase, value, events, status: dynamic, after() { number = 207; } });
    const outcome = await call("http");
    assert.equal(outcome.rejected, false);
    assert.equal(events.at(-1), "number"); assert.equal(events.filter(event => event === "number").length, 1);
    await assertHTTP(outcome.result, 207, { "x-handler": "1", "x-after": "1", ...(phase === "after-throw" ? { "x-owned": "1" } : {}) }, phase === "after-throw" ? ["owned=1"] : []);
  }
  const events = [];
  const { value } = errorValue(events);
  let number = 418;
  const dynamic = { valueOf() { events.push("number"); assert.equal(this, dynamic); return number; } };
  getter(value, "statusCode", () => { events.push("status"); return dynamic; });
  const { call } = build({ phase: "handler-throw", value, events, after() { number = 409; } });
  const outcome = await call("http");
  assert.equal(outcome.rejected, false);
  assert.equal(events.filter(event => event === "status").length, 1);
  assert.equal(events.at(-1), "number");
  await assertHTTP(outcome.result, 409, { "x-handler": "1", "x-after": "1", "x-owned": "1" }, ["owned=1"]);
}

async function headers() {
  for (const mode of ["falsey", "same", "distinct", "shifting"]) {
    const events = [];
    const { value } = errorValue(events);
    let captured; let reads = 0;
    const first = new Headers({ "x-ignored": "first" });
    const last = new Headers({ "x-final": "third", "set-cookie": "explicit=1" });
    getter(value, "headers", () => {
      events.push(`headers:${++reads}`);
      return mode === "falsey" ? null : mode === "same" ? captured : mode === "shifting" && reads < 3 ? first : last;
    });
    const auth = betterAuth({
      baseURL: origin, secret: "raw-api-error-contract-at-least-thirty-two-characters",
      logger: { disabled: true, level: "warn" }, experimental: { instrumentation: { enabled: false } },
      telemetry: { enabled: false }, rateLimit: { enabled: false },
      plugins: [{ id: "raw-headers", endpoints: { probe: createAuthEndpoint("/probe", { method: "GET" }, async ctx => {
        captured = ctx.responseHeaders; ctx.setHeader("x-handler", "1"); captured.append("set-cookie", "context=1"); throw value;
      }) } }],
    });
    const outcome = await settle(() => auth.api.probe());
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, value);
    const count = mode === "falsey" ? 1 : mode === "same" ? 2 : 3;
    assert.deepEqual(events, ["name:1", "name:2", "name:3", ...Array.from({ length: count }, (_, index) => `headers:${index + 1}`), "name:4", "name:5"]);
    const descriptor = Object.getOwnPropertyDescriptor(value, kAPIErrorHeaderSymbol);
    assert.notEqual(descriptor.value, captured);
    assertHeaders(descriptor.value, { "x-handler": "1", ...(count === 3 ? { "x-final": "third" } : {}) }, count === 3 ? ["context=1", "explicit=1"] : ["context=1"]);
    assertHeaders(captured, { "x-handler": "1" }, ["context=1"]);
  }
  for (const failedRead of [undefined, 1, 2, 3, "convert"]) {
    const events = [];
    const failure = new Error(`original headers ${failedRead}`);
    const { value } = errorValue(events);
    let reads = 0;
    const native = { "x-final": { toString() { events.push("convert"); if (failedRead === "convert") throw failure; return "third"; } } };
    getter(value, "headers", () => { events.push(`headers:${++reads}`); if (reads === failedRead) throw failure; return native; });
    const { call } = build({ phase: "handler-throw", value, events });
    const outcome = await call("native");
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, failedRead === undefined ? value : failure);
    const count = failedRead === "convert" || failedRead === undefined ? 3 : failedRead;
    assert.deepEqual(events, ["before", "handler", "name:1", "name:2", "name:3", ...Array.from({ length: count }, (_, index) => `headers:${index + 1}`), ...(failedRead === "convert" || failedRead === undefined ? ["convert"] : []), ...(failedRead === undefined ? ["after", "plugin-after", "name:4", "name:5"] : [])]);
    if (failedRead === undefined) assertHeaders(Object.getOwnPropertyDescriptor(value, kAPIErrorHeaderSymbol).value, { "x-handler": "1", "x-after": "1", "x-final": "third" });
  }
}

async function conversion() {
  const order = ["name", "body", "statusCode", "status", "method", "call", "headers", "serialize"];
  for (const failedAt of [undefined, ...order]) {
    const events = [];
    const failure = new Error(`original conversion ${failedAt}`);
    const observe = (name, result) => { events.push(name); if (name === failedAt) throw failure; return result; };
    const value = {};
    const body = { toJSON() { assert.equal(this, body); return observe("serialize", payload); } };
    const dynamic = {};
    getter(dynamic, "toString", () => observe("method", function (...args) { assert.equal(this, dynamic); assert.deepEqual(args, []); return observe("call", "DYNAMIC"); }));
    for (const [name, result] of [["name", "APIError"], ["body", body], ["statusCode", 418], ["status", dynamic], ["headers", { "x-error": "1" }]]) getter(value, name, () => observe(name, result));
    const outcome = await settle(() => toResponse(value));
    assert.equal(outcome.rejected, failedAt !== undefined);
    assert.deepEqual(events, failedAt === undefined ? order : order.slice(0, order.indexOf(failedAt) + 1));
    if (failedAt) assert.equal(outcome.error, failure);
    else await assertHTTP(outcome.result, 418, { "x-error": "1" }, [], JSON.stringify(payload), "DYNAMIC");
  }
  for (const status of [null, undefined, { toString: 1 }]) {
    const value = { name: "APIError", statusCode: 418, status, body: payload };
    const outcome = await settle(() => toResponse(value));
    assert.equal(outcome.rejected, true); assert.ok(outcome.error instanceof TypeError);
  }
  const events = [];
  const statusText = { toString() { events.push("statusText"); return "twice"; } };
  const value = { name: "APIError", statusCode: 418, body: payload, status: { toString() { events.push("status"); return statusText; } } };
  const response = toResponse(value);
  assert.deepEqual(events, ["status", "statusText"]);
  await assertHTTP(response, 418, {}, [], JSON.stringify(payload), "twice");
}

async function constructors() {
  for (const ErrorClass of [APIError, CoreAPIError]) {
    for (const body of [undefined, null, {}, { message: undefined }, { message: null }, { message: false }]) {
      const value = new ErrorClass(undefined, body);
      assert.equal(value.status, "INTERNAL_SERVER_ERROR"); assert.equal(value.statusCode, 500);
      assert.equal(value.body, body); assert.deepEqual(value.headers, {});
      assert.equal(Object.hasOwn(value, "message"), body?.message !== undefined);
      assert.equal(value.message, body?.message === undefined ? "" : String(body.message));
      assert.equal(Object.hasOwn(value, "cause"), false);
    }
    for (const firstCause of [undefined, null, false, 0, "", {}]) {
      const events = [];
      const cause = { identity: true };
      const message = { toString() { events.push("message.toString"); return "constructed"; } };
      const status = { toString() { events.push("status.toString"); return "CONFLICT"; } };
      const body = {};
      let reads = 0;
      getter(body, "message", () => { events.push("message"); return message; });
      getter(body, "cause", () => { events.push(`cause:${++reads}`); return reads === 1 ? firstCause : cause; });
      const headers = {};
      const value = new ErrorClass(status, body, headers);
      assert.deepEqual(events, ["status.toString", "message", "cause:1", ...(firstCause ? ["cause:2"] : []), "message.toString"]);
      assert.equal(value.status, status); assert.equal(value.statusCode, 409);
      assert.equal(value.body, body); assert.equal(value.headers, headers);
      assert.equal(value.message, "constructed");
      assert.equal(Object.hasOwn(value, "cause"), !!firstCause);
      if (firstCause) assert.equal(value.cause, cause);
      getter(body, "message", () => "mutated");
      assert.equal(value.message, "constructed");
    }
  }
  const order = ["status", "message", "cause:1", "cause:2", "string"];
  for (const failedAt of order) {
    const events = [];
    const failure = new Error(`original constructor ${failedAt}`);
    const observe = (name, result) => { events.push(name); if (name === failedAt) throw failure; return result; };
    const body = {}; let causes = 0;
    getter(body, "message", () => observe("message", { toString() { return observe("string", "constructed"); } }));
    getter(body, "cause", () => observe(`cause:${++causes}`, {}));
    const outcome = await settle(() => new APIError({ toString() { return observe("status", "CONFLICT"); } }, body));
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, failure);
    assert.deepEqual(events, order.slice(0, order.indexOf(failedAt) + 1));
  }
  const plain = { name: "APIError" };
  assert.equal(isAPIError(plain), true);
  assert.deepEqual(Object.keys(plain), ["name"]);
  for (const key of ["message", "cause", "status", "statusCode", "body", "headers"]) assert.equal(Object.hasOwn(plain, key), false);
}

async function instances() {
  for (const ErrorClass of [APIError, CoreAPIError]) for (const mode of ["renamed", "throwing-name"]) {
    const events = [];
    const value = new ErrorClass("BAD_REQUEST", payload);
    if (mode === "renamed") value.name = "Other";
    else getter(value, "name", () => { throw new Error("An APIError instance bypasses the name getter"); });
    assert.equal(isAPIError(value), true);
    const { call } = build({ value, events });
    const outcome = await call("native");
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, value);
    assert.deepEqual(events, ["before", "handler", "after", "plugin-after"]);
  }
}

async function debug() {
  for (const failedAt of [undefined, "get", "set"]) {
    const events = [];
    const failure = new Error(`original debug ${failedAt}`);
    const { value } = errorValue(events);
    const stack = { identity: true };
    getter(value, "errorStack", () => { events.push("get"); if (failedAt === "get") throw failure; return stack; });
    Object.defineProperty(value, "stack", { configurable: true, set(next) { events.push("set"); assert.equal(next, stack); if (failedAt === "set") throw failure; } });
    const { call } = build({ value, events, debug: true });
    const outcome = await call("native");
    assert.equal(outcome.rejected, true); assert.equal(outcome.error, failedAt ? failure : value);
    assert.deepEqual(events, ["before", "handler", "after", "plugin-after", "name:1", "get", ...(failedAt === "get" ? [] : ["set"]), ...(failedAt ? [] : ["name:2"])]);
  }
}

async function tracing() {
  let recording;
  let ready = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return { startActiveSpan(name, _, callback) {
    if (name === "raw-api-error-warmup") ready = true;
    const record = recording;
    return callback({
      setAttribute(name, value) { record?.push(["attribute", name, value]); },
      setStatus(value) { record?.push(["span-status", value]); },
      recordException(value) { record?.push(["exception", value]); },
      end() { record?.push(["end"]); },
    });
  } }; } }), true);
  try {
    for (let attempt = 0; attempt < 50 && !ready; attempt++) {
      await withSpan("raw-api-error-warmup", {}, async () => {});
      if (!ready) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(ready, true, "The trace recorder must be active before observing errors");
    for (const kind of ["redirect", "nonredirect", "renamed-instance"]) {
      const events = [];
      recording = events;
      const raw = kind === "renamed-instance" ? new APIError("FOUND", payload) : {};
      let reads = 0;
      const status = { valueOf() { events.push(["number"]); return kind === "redirect" ? 302 : 418; } };
      getter(raw, "name", () => { events.push(["name"]); return kind === "renamed-instance" ? "Other" : "APIError"; });
      getter(raw, "statusCode", () => { events.push(["status", ++reads]); return status; });
      getter(raw, "message", () => { events.push(["message"]); return { toString() { events.push(["message-string"]); return "traced"; } }; });
      const value = new Proxy(raw, { has(target, name) { events.push(["has", name]); return Reflect.has(target, name); } });
      const outcome = await settle(() => withSpan("raw-error", {}, async () => { throw value; }));
      assert.equal(outcome.rejected, true); assert.equal(outcome.error, value);
      const expected = [["has", "name"], ["name"]];
      if (kind !== "renamed-instance") expected.push(["has", "statusCode"], ["status", 1], ["number"], ["number"]);
      if (kind === "redirect") expected.push(["status", 2], ["attribute", "http.response.status_code", status], ["span-status", { code: 1 }], ["end"]);
      else expected.push(["exception", value], ["message"], ["message-string"], ["span-status", { code: 2, message: "traced" }], ["end"]);
      assert.deepEqual(events, expected);
      recording = undefined;
    }
    {
      const events = [];
      const { value } = errorValue(events);
      let messages = 0;
      getter(value, "message", () => { events.push(`message:${++messages}`); return "hook rejection"; });
      const { call, retained } = build({ phase: "before-throw", value, events, instrumentation: true });
      const outcome = await call("native");
      assert.equal(outcome.rejected, true); assert.equal(outcome.error, value);
      assert.deepEqual(events, ["before", "name:1", "name:2", "message:1", "name:3", "name:4", "message:2"]);
      const descriptor = Object.getOwnPropertyDescriptor(value, kAPIErrorHeaderSymbol);
      assert.equal(descriptor.get.call(value), retained.before);
      assertHeaders(retained.before, { "x-before": "1" });
    }
  } finally { recording = undefined; trace.disable(); }
}

for (const [name, run] of [["phases", phases], ["classification", classification], ["status", status], ["headers", headers], ["conversion", conversion], ["constructors", constructors], ["instances", instances], ["debug", debug], ["trace", tracing]]) {
  await run(); completed.push(name);
}
process.stdout.write(`${JSON.stringify({ version: "1.7.6", groups: completed })}\n`);
