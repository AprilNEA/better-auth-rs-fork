import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { nativeTokenCases } from "./oauth-native-token-cases.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

const version = "1.7.6";
const now = 2_000_000_000_123;
const origin = "https://oauth-native-token.test";
const date = "2030-01-02T03:04:05.000Z";

function inspect(value, observer) {
  if (value === null || typeof value !== "object" && typeof value !== "function") return observer.observe(value);
  return {
    type: value instanceof Date ? "date" : Array.isArray(value) ? "array" : typeof value,
    ...(value instanceof Date || typeof value === "function" ? { value: observer.observe(value) } : {}),
    properties: Reflect.ownKeys(value).map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      const flags = { enumerable: descriptor.enumerable, configurable: descriptor.configurable };
      return [observer.observe(key), "value" in descriptor
        ? { ...flags, writable: descriptor.writable, value: observer.observe(descriptor.value) }
        : { ...flags, get: observer.observe(descriptor.get), set: observer.observe(descriptor.set) }];
    }),
  };
}

function observedError(error, observer, original) {
  return {
    ...observer.error(error), originalError: error === original,
    ...(error instanceof Error ? { stack: error.stack, ownKeys: Reflect.ownKeys(error).map(key => observer.observe(key)) } : {}),
  };
}

function value(kind) {
  switch (kind) {
    case "omitted": case "undefined": return undefined;
    case "null": return null;
    case "false": return false;
    case "zero": return 0;
    case "nan": return NaN;
    case "empty": return "";
    case "string": return "native-string";
    case "true": return true;
    case "number": return 7;
    case "array": return ["first", undefined, { ownUndefined: undefined }];
    case "sparse-array": return ["first", , "last"];
    case "date": return new Date(date);
    case "invalid-date": return new Date(NaN);
    case "function": return function tokenResult() { return "token-function-result"; };
    case "object": return { accessToken: "access", ownUndefined: undefined };
    default: throw new Error(`Unknown native token value: ${kind}`);
  }
}

function expiryValue(kind) {
  switch (kind) {
    case undefined: case "absent": return undefined;
    case "default": return 30;
    case "zero": return 0;
    case "nan": return NaN;
    case "infinity": return Infinity;
    case "negative": return -1;
    case "fractional": return -0.0005;
    default: throw new Error(`Unknown native token expiry: ${kind}`);
  }
}

async function captureCase(scenario) {
  const observer = createProtectedFunctionObserver();
  const events = [];
  const logs = [];
  const database = { user: [], session: [], account: [], verification: [] };
  const original = Object.assign(new Error("Native token callback original failure"), {
    code: "NATIVE_TOKEN_FAILURE", detail: { ownUndefined: undefined, invalidDate: new Date(NaN), nan: NaN },
  });
  let token;
  let stored;
  if (scenario.result.startsWith("expiry-")) {
    token = { accessToken: "access", ownUndefined: undefined };
    stored = scenario.result === "expiry-getter-truthy" ? new Date(date) : undefined;
    if (scenario.result === "expiry-readonly" || scenario.result === "expiry-nonenumerable") {
      Object.defineProperty(token, "accessTokenExpiresAt", {
        value: stored, enumerable: scenario.result !== "expiry-nonenumerable",
        configurable: true, writable: scenario.result !== "expiry-readonly",
      });
    } else {
      Object.defineProperty(token, "accessTokenExpiresAt", {
        enumerable: true, configurable: true,
        get() {
          events.push({ kind: "get-expiry", sameReceiver: this === token });
          if (scenario.result === "expiry-getter-throws") throw original;
          return stored;
        },
        set(next) {
          events.push({ kind: "set-expiry", sameReceiver: this === token, value: observer.observe(next) });
          if (scenario.result === "expiry-setter-throws") throw original;
          stored = next;
        },
      });
    }
  } else {
    token = value(scenario.result === "callback-throws" ? "object" : scenario.result);
  }
  const verifier = value(scenario.verifier ?? "string");
  const input = { code: "native-code" };
  if (scenario.verifier !== "omitted") input.codeVerifier = verifier;
  input.deviceId = undefined;
  input.redirectURI = `${origin}/api/auth/callback/native`;
  const expiry = expiryValue(scenario.expiry);
  const context = await betterAuth({
    baseURL: origin, secret: "native-token-contract-secret-at-least-thirty-two-characters",
    database: memoryAdapter(database), telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "debug", log(level, message, ...args) { logs.push({ level, message, args: args.map(observer.observe) }); } },
    plugins: [genericOAuth({ config: [{
      providerId: "native", clientId: "client", clientSecret: "secret",
      authorizationUrl: `${origin}/authorize`, accessTokenExpiresIn: expiry,
      async getToken(data) {
        events.push({ kind: "get-token", sameInput: data === input, sameVerifier: data.codeVerifier === verifier, input: inspect(data, observer) });
        if (scenario.result === "callback-throws") throw original;
        return token;
      },
    }] })],
  }).$context;
  const provider = context.socialProviders.find(provider => provider.id === "native");
  assert.ok(provider);
  const before = { input: inspect(input, observer), token: inspect(token, observer), accessorValue: observer.observe(stored) };
  events.length = 0;
  logs.length = 0;
  let result;
  let error;
  try { result = await provider.validateAuthorizationCode(input); } catch (caught) { error = caught; }
  const record = {
    name: scenario.name, version, scenario, expiry: observer.observe(expiry), before,
    outcome: error === undefined ? { kind: "returned", sameOriginal: result === token, value: inspect(result, observer) }
      : { kind: "thrown", error: observedError(error, observer, original) },
    events, after: { input: inspect(input, observer), token: inspect(token, observer), accessorValue: observer.observe(stored) },
    originalError: observedError(original, observer, original), logs, database, functions: observer.functions,
  };
  await writeObservation(`${JSON.stringify(record)}\n`);
  assert.deepEqual(record.after.input, record.before.input);
  assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
  assert.deepEqual(logs, []);
  assert.equal(events.filter(event => event.kind === "get-token").length, 1);
  assert.equal(events[0].sameInput, true);
  assert.equal(events[0].sameVerifier, !Number.isNaN(verifier));
  const nullish = token === undefined || token === null;
  const primitive = token !== null && typeof token !== "object" && typeof token !== "function";
  const originalFailure = ["callback-throws", "expiry-getter-throws", "expiry-setter-throws"].includes(scenario.result);
  const typeFailure = nullish || primitive && !!expiry || scenario.result === "expiry-readonly";
  if (originalFailure) assert.equal(error, original);
  else if (typeFailure) assert.ok(error instanceof TypeError);
  else {
    assert.equal(error, undefined);
    assert.equal(result, token);
  }
}

if (import.meta.main) {
  for (const name of ["better-auth", "@better-auth/core"]) {
    assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
  }
  const failures = [];
  await withClock(async setClock => {
    setClock(now);
    for (const scenario of nativeTokenCases()) {
      try { await captureCase(scenario); }
      catch (error) {
        failures.push(error);
        await writeObservation(`${JSON.stringify({ contract: "oauth-native-token-failed", name: scenario.name, error: { name: error.name, message: error.message, stack: error.stack } })}\n`);
      }
    }
  });
  if (failures.length) throw new AggregateError(failures, `${failures.length} native token source cases failed`);
}
