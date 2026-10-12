import assert from "node:assert/strict";
import { readFileSync, writeSync } from "node:fs";
import { APIError } from "better-call/error";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { oAuthProxy } from "better-auth/plugins/oauth-proxy";
import { callbackCases } from "./oauth-proxy-callback-cases.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = "1.7.6";
const now = 2_000_000_000_123;
const origin = "https://oauth-proxy-callback.test";
const baseURL = `${origin}/api/auth`;
const errorURL = `${origin}/failure?kept=1`;
const secret = "oauth-proxy-callback-contract-secret-at-least-thirty-two-characters";
const state = "original-proxy-state";
const providerId = "fixture";
const symbolKey = Symbol("callback-extra");

function inputObservation(value, observer) {
  if (value === null || typeof value !== "object" && typeof value !== "function") return observer.observe(value);
  const prototype = Object.getPrototypeOf(value);
  const standard = [[Object.prototype, "Object.prototype"], [Array.prototype, "Array.prototype"], [Date.prototype, "Date.prototype"], [Function.prototype, "Function.prototype"]];
  const properties = Reflect.ownKeys(value).map(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    const flags = { enumerable: descriptor.enumerable, configurable: descriptor.configurable };
    return [observer.observe(key), "value" in descriptor
      ? { ...flags, writable: descriptor.writable, value: observer.observe(descriptor.value) }
      : { ...flags, get: observer.observe(descriptor.get), set: observer.observe(descriptor.set) }];
  });
  return {
    type: Array.isArray(value) ? "array" : value instanceof Date ? "date" : typeof value,
    prototype: prototype === null ? null : standard.find(([object]) => object === prototype)?.[1] ?? inputObservation(prototype, observer),
    properties,
  };
}

function errorObservation(value, observer, original) {
  return {
    ...observer.error(value), originalError: value === original,
    ...(value instanceof Error ? { stack: value.stack, ownKeys: Reflect.ownKeys(value).map(key => observer.observe(key)) } : {}),
    ...(value instanceof APIError ? {
      status: value.status, statusCode: value.statusCode,
      headers: value.headers ? [...new Headers(value.headers)] : [],
    } : {}),
  };
}

const descriptors = value => value !== null && (typeof value === "object" || typeof value === "function")
  ? Object.getOwnPropertyDescriptors(value) : undefined;

async function captureCase(scenario) {
  const observer = createProtectedFunctionObserver();
  const events = [];
  const logs = [];
  const globalLogs = [];
  const providerCalls = [];
  const storeCalls = [];
  const getterCalls = [];
  const marker = { ownUndefined: undefined, invalidDate: new Date(NaN), nan: NaN };
  const originalError = Object.assign(new Error("OAuth proxy callback original failure"), { code: "PROXY_CALLBACK_FAILURE", detail: marker });
  marker.toJSON = function () { events.push("unexpected:marker.toJSON"); throw originalError; };
  const markerDescriptors = Object.getOwnPropertyDescriptors(marker);
  const originalErrorDescriptors = Object.getOwnPropertyDescriptors(originalError);
  let keys = 0;
  const options = {
    get secret() {
      events.push(`key:${++keys}`);
      if (keys === scenario.keyFailure) throw originalError;
      return secret;
    },
  };
  const plugin = oAuthProxy(options);
  const hook = plugin.hooks.before.find(candidate => candidate.matcher({ path: "/callback/:id" }));
  assert.ok(hook);
  assert.equal(hook.matcher({ path: "/callback/fixture" }), false);
  const database = { user: [], session: [], account: [], verification: [] };
  const context = await betterAuth({
    baseURL: origin, secret, database: memoryAdapter(database), telemetry: { enabled: false },
    rateLimit: { enabled: false }, plugins: [plugin],
    logger: { level: "debug", log(level, message, ...args) {
      events.push(`log:${level}:${message}`);
      logs.push({ level, message, args });
    } },
  }).$context;
  const guardStore = (store, label) => new Proxy(store, { get(target, name, receiver) {
    const value = Reflect.get(target, name, receiver);
    if (typeof value !== "function") return value;
    return function (...args) {
      storeCalls.push({ store: label, method: String(name), args });
      events.push(`store:${label}.${String(name)}`);
      throw new Error(`Unexpected OAuth proxy callback store call: ${label}.${String(name)}`);
    };
  } });
  context.adapter = guardStore(context.adapter, "adapter");
  context.internalAdapter = guardStore(context.internalAdapter, "internalAdapter");
  context.socialProviders = scenario.input === "provider-missing" ? [] : [{
    id: providerId,
    async validateAuthorizationCode(input) {
      events.push("provider:validate");
      providerCalls.push({ method: "validate", input });
      if (scenario.providerMode === "validate-throws") throw originalError;
      if (scenario.providerMode === "user-throws" || scenario.providerMode === "no-user") return { accessToken: "callback-access", scopes: ["profile"] };
      return undefined;
    },
    async getUserInfo(input) {
      events.push("provider:user");
      providerCalls.push({ method: "user", input });
      if (scenario.providerMode === "user-throws") throw originalError;
      return undefined;
    },
  }];

  let stateData = {
    callbackURL: `${origin}/complete`, codeVerifier: "callback-verifier", errorURL,
    expiresAt: now + 600_000, oauthState: state,
  };
  if (scenario.unbound) delete stateData.oauthState;
  if (scenario.emptyState) stateData = {};
  if (scenario.verifierDate) stateData.codeVerifier = "2030-01-02T03:04:05.000Z";
  if (scenario.input === "binding-mismatch") stateData.oauthState = "different-state";
  if (scenario.input === "binding-numeric") stateData.oauthState = 7;
  if (scenario.input === "binding-string") stateData.oauthState = "7";
  if (scenario.input === "binding-object") stateData.oauthState = { value: 7 };
  const cookiePlaintext = scenario.input === "cookie-plaintext" ? scenario.plaintext : JSON.stringify(stateData);
  const cookieCiphertext = await symmetricEncrypt({ key: secret, data: cookiePlaintext });
  assert.equal(await symmetricDecrypt({ key: secret, data: cookieCiphertext }), cookiePlaintext);
  const packageData = { isOAuthProxy: true, state, stateCookie: cookieCiphertext };
  if (scenario.input === "package-field") {
    if (scenario.value === undefined) delete packageData[scenario.field];
    else packageData[scenario.field] = scenario.value;
  }
  if (scenario.invalidCookie) packageData.stateCookie = "invalid-ciphertext";
  if (["binding-numeric", "binding-string"].includes(scenario.input)) packageData.state = 7;
  if (scenario.input === "binding-object") packageData.state = { value: 7 };
  const packagePlaintext = scenario.input === "outer-plaintext" ? scenario.plaintext : JSON.stringify(packageData);
  const ciphertext = await symmetricEncrypt({ key: secret, data: packagePlaintext });
  assert.equal(await symmetricDecrypt({ key: secret, data: ciphertext }), packagePlaintext);
  const getter = (object, label, key, value, throws = false) => Object.defineProperty(object, key, {
    enumerable: true, configurable: true,
    get() {
      const name = `${label}.${typeof key === "symbol" ? "symbol" : key}`;
      events.push(`get:${name}`);
      getterCalls.push({ name, receiver: this, owner: object, value });
      if (throws) throw originalError;
      return value;
    },
  });
  let query = { state: ciphertext };
  let body;
  switch (scenario.input) {
    case "root": query = scenario.value; body = scenario.value; break;
    case "body": query = undefined; body = { state: ciphertext }; break;
    case "query-wins": body = { state: "invalid-ciphertext" }; break;
    case "query-state": query = { state: scenario.value }; body = { state: ciphertext }; break;
    case "query-error": query.error = scenario.value; body = { error: "body-error" }; break;
    case "empty-code": query.code = ""; body = { code: "body-code" }; break;
    case "nullish-fields": Object.assign(query, { code: undefined, error: null, user: undefined }); body = { code: "body-code", error: "body-error", user: "{}" }; break;
    case "getters": {
      query = {};
      getter(query, "query", "state", ciphertext);
      getter(query, "query", "code", null);
      getter(query, "query", "child", marker);
      body = {};
      getter(body, "body", "state", "invalid-ciphertext");
      getter(body, "body", "error", "body-error");
      getter(body, "body", "child", marker);
      break;
    }
    case "getter-error": {
      query = {};
      getter(query, "query", "state", ciphertext, scenario.throwGetter === "query.state");
      if (scenario.throwGetter === "query.unread") getter(query, "query", "unread", marker, true);
      body = {};
      getter(body, "body", "state", ciphertext, scenario.throwGetter === "body.state");
      if (scenario.throwGetter === "body.unread") getter(body, "body", "unread", marker, true);
      break;
    }
    case "getter-before-guard": query = { state: false }; body = {}; getter(body, "body", "unread", marker, true); break;
    case "query-symbol": getter(query, "query", symbolKey, marker, true); break;
    case "body-symbol": body = {}; getter(body, "body", symbolKey, marker, true); break;
    case "query-proto": query = Object.defineProperty({}, "__proto__", { enumerable: true, configurable: true, value: { state: ciphertext } }); break;
    case "body-proto": query = {}; body = Object.defineProperty({}, "__proto__", { enumerable: true, configurable: true, value: { state: ciphertext } }); break;
    case "outer-cipher": query = { state: "invalid-ciphertext", code: 7 }; break;
    case "invalid-query": body = scenario.invalidFields; break;
    case "binding-mismatch": query.error = "access_denied"; break;
    case "provider-error": query.error = "access_denied"; break;
    case "provider-missing": query.code = "callback-code"; break;
    case "provider": query.code = "callback-code"; if (scenario.invalidUser) query.user = "not JSON"; break;
  }

  const queryDescriptors = descriptors(query);
  const bodyDescriptors = descriptors(body);
  const queryPrototype = query !== null && typeof query === "object" ? Object.getPrototypeOf(query) : undefined;
  const bodyPrototype = body !== null && typeof body === "object" ? Object.getPrototypeOf(body) : undefined;
  const before = { query: inputObservation(query, observer), body: inputObservation(body, observer) };
  const request = { path: "/callback/:id", method: scenario.method ?? "POST", params: { id: providerId }, query, body, context };
  assert.equal(Object.hasOwn(request, "request"), false);
  events.length = 0;
  logs.length = 0;
  keys = 0;
  let result;
  let caught;
  const savedConsole = { error: console.error, warn: console.warn, log: console.log };
  for (const method of Object.keys(savedConsole)) {
    console[method] = (...args) => globalLogs.push({ method, args, eventIndex: events.length });
  }
  try { result = await hook.handler(request); } catch (error) { caught = error; }
  finally { Object.assign(console, savedConsole); }
  const observe = () => {
    const outcome = caught === undefined ? { kind: "returned", value: observer.observe(result) }
      : { kind: "thrown", error: errorObservation(caught, observer, originalError) };
    const observedLogs = logs.map(({ level, message, args }) => ({ level, message,
      arguments: args.map(value => value instanceof Error ? errorObservation(value, observer, originalError) : observer.observe(value)),
    }));
    const observedGlobalLogs = globalLogs.map(({ method, args, eventIndex }) => ({ method, eventIndex,
      arguments: args.map(value => value !== null && typeof value === "object" && !(value instanceof Error)
        ? Object.fromEntries(Object.entries(value).map(([key, field]) => [key,
          field instanceof Error ? errorObservation(field, observer, originalError) : observer.observe(field)]))
        : value instanceof Error ? errorObservation(value, observer, originalError) : observer.observe(value)),
    }));
    return {
      name: scenario.name, scope: scenario.scope ?? "callback-contract", version,
      method: request.method, hasOriginalRequest: Object.hasOwn(request, "request"),
      inputs: { before, after: { query: inputObservation(query, observer), body: inputObservation(body, observer) } },
      encryption: { packagePlaintext, ciphertext, cookiePlaintext, cookieCiphertext },
      outcome, events, logs: observedLogs, globalLogs: observedGlobalLogs,
      providerCalls: observer.observe(providerCalls), storeCalls: observer.observe(storeCalls),
      getterCalls: getterCalls.map(call => ({ name: call.name, sameReceiver: call.receiver === call.owner, sameMarker: call.value === marker })),
      originalError: errorObservation(originalError, observer, originalError),
      database, functions: observer.functions,
    };
  };
  try {
    for (const method of Object.keys(savedConsole)) assert.equal(console[method], savedConsole[method]);
    assert.equal(globalLogs.length, scenario.invalidUser ? 1 : 0);
    if (scenario.invalidUser) {
      const [{ method, args, eventIndex }] = globalLogs;
      assert.equal(method, "error");
      assert.equal(eventIndex, 3);
      assert.equal(args.length, 2);
      assert.equal(args[0], `${new Date(now).toISOString()} ERROR [Better Auth]: Error parsing JSON`);
      assert.deepEqual(Reflect.ownKeys(args[1]), ["error"]);
      assert.ok(args[1].error instanceof SyntaxError);
      assert.equal(args[1].error.name, "SyntaxError");
      assert.equal(args[1].error.message, 'JSON Parse error: Unexpected identifier "not"');
    }
    assert.equal(request.query, query);
    assert.equal(request.body, body);
    assert.deepEqual(descriptors(query), queryDescriptors);
    assert.deepEqual(descriptors(body), bodyDescriptors);
    if (queryPrototype !== undefined) assert.equal(Object.getPrototypeOf(query), queryPrototype);
    if (bodyPrototype !== undefined) assert.equal(Object.getPrototypeOf(body), bodyPrototype);
    assert.deepEqual(Object.getOwnPropertyDescriptors(originalError), originalErrorDescriptors);
    assert.deepEqual(Object.getOwnPropertyDescriptors(marker), markerDescriptors);
    for (const call of getterCalls) assert.equal(call.receiver, call.owner);
    assert.deepEqual(getterCalls.map(call => call.name), scenario.getters ?? []);
    assert.equal(keys, scenario.expected.keys);
    assert.deepEqual(storeCalls, []);
    assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
    assert.deepEqual(providerCalls.map(call => call.method), scenario.expected.provider ?? []);
    assert.deepEqual(logs.map(({ level, message }) => ({ level, message })), scenario.expected.logs.map(({ level, message }) => ({ level, message })));
    for (const [index, expected] of scenario.expected.logs.entries()) {
      const actual = logs[index];
      assert.equal(actual.args.length, expected.argument ? 1 : 0);
      if (expected.argument === "original-error") assert.equal(actual.args[0], originalError);
      if (expected.argument === "error") assert.ok(actual.args[0] instanceof Error);
      if (expected.argument === "issues") assert.deepEqual(actual.args[0].issues, scenario.issues);
      if (expected.argument === "provider-id") assert.deepEqual(actual.args[0], { providerId });
    }
    if (scenario.expected.kind === "returned") { assert.equal(caught, undefined); assert.equal(result, undefined); }
    else if (scenario.expected.kind === "original-error") assert.equal(caught, originalError);
    else if (scenario.expected.kind === "type-error") assert.ok(caught instanceof TypeError);
    else {
      assert.ok(caught instanceof APIError);
      assert.equal(caught.status, "FOUND");
      assert.equal(caught.statusCode, 302);
      assert.equal(caught.body, undefined);
      const target = scenario.defaultError || scenario.emptyState ? `${baseURL}/error` : errorURL;
      assert.deepEqual([...new Headers(caught.headers)], [["location", `${target}${target.includes("?") ? "&" : "?"}error=${scenario.expected.error}`]]);
    }
    if (providerCalls.length) {
      assert.deepEqual(providerCalls[0].input, {
        code: "callback-code", redirectURI: `${baseURL}/callback/${providerId}`,
        codeVerifier: scenario.emptyState ? undefined : scenario.verifierDate ? new Date("2030-01-02T03:04:05.000Z") : "callback-verifier",
      });
      if (scenario.verifierDate) assert.ok(providerCalls[0].input.codeVerifier instanceof Date);
      if (providerCalls.length === 2) assert.deepEqual(providerCalls[1].input, { accessToken: "callback-access", scopes: ["profile"], user: undefined });
    }
    const expectedEvents = [
      ...(scenario.getters ?? []).map(name => `get:${name}`),
      ...Array.from({ length: scenario.expected.keys }, (_, index) => `key:${index + 1}`),
      ...(scenario.expected.provider ?? []).map(name => `provider:${name}`),
      ...scenario.expected.logs.map(({ level, message }) => `log:${level}:${message}`),
    ];
    assert.deepEqual(events, expectedEvents);
  } catch (error) {
    writeSync(1, `${JSON.stringify({ contract: "oauth-proxy-callback-failed-assertion", observation: observe() })}\n`);
    throw error;
  }
  return { ...observe(), originalErrorUnchanged: true };
}

export async function captureOAuthProxyCallback(scenario) {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  return withClock(async setClock => { setClock(now); return captureCase(scenario); });
}

if (import.meta.main) {
  const selected = callbackCases().filter(scenario => !process.argv[2] || scenario.name === process.argv[2]);
  assert.ok(selected.length > 0, "Select an existing OAuth proxy callback scenario");
  const failures = [];
  for (const scenario of selected) {
    try { writeSync(1, `${JSON.stringify(await captureOAuthProxyCallback(scenario))}\n`); }
    catch (error) {
      failures.push(error);
      writeSync(1, `${JSON.stringify({ contract: "oauth-proxy-callback-case-failed", name: scenario.name, error: { name: error.name, message: error.message, stack: error.stack } })}\n`);
    }
  }
  // Capture each independent case, then fail the process if any assertion failed.
  if (failures.length) throw new AggregateError(failures, `${failures.length} OAuth proxy callback source cases failed`);
}
