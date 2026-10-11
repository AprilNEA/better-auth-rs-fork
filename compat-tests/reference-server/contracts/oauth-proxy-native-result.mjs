import assert from "node:assert/strict";
import { test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { memoryAdapter } from "better-auth/adapters/memory";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { oAuthProxy } from "better-auth/plugins";

// The Rust counterpart invokes the production after hook before HTTP serialization.
const origin = "http://preview.proxy-result.test";
const production = "http://production.proxy-result.test";
const secret = "oauth-proxy-native-result-secret-at-least-thirty-two-characters";
const state = "native-proxy-state";
const url = "https://provider.test/authorize?before=a%20b&state=native-proxy-state&state=discarded&after=~";
const plaintext = ' { "callbackURL": "http://preview.proxy-result.test/complete", "extra": 1 } \n';
const object = value => ({ url: value, kept: undefined });

async function fixture(options = {}) {
  const database = { user: [], session: [], account: [], verification: [] };
  const logs = [];
  let armed = false;
  let reads = 0;
  let value;
  let cookie;
  const proxyOptions = { currentURL: origin, productionURL: production };
  const auth = betterAuth({
    baseURL: origin, secret, database: memoryAdapter(database),
    telemetry: { enabled: false },
    logger: { log(level, message, ...arguments_) { logs.push({ level, message, arguments: arguments_ }); } },
    account: { storeStateStrategy: options.strategy ?? "database" },
    verification: { additionalFields: { value: { type: "string", transform: { output(input) {
      if (!armed) return input;
      reads += 1;
      if (options.failRead) throw new Error("proxy lookup original failure");
      return Object.hasOwn(options, "output") ? options.output : input;
    } } } } },
    hooks: { after: createAuthMiddleware(async ctx => {
      if (options.skipAfter === "header") ctx.request.headers.set("x-skip-oauth-proxy", "1");
      if (options.skipAfter === "origin") proxyOptions.currentURL = production;
    }) },
    plugins: [
      { id: "proxy-native-result-contract", endpoints: {
        signInSocial: createAuthEndpoint("/sign-in/social", { method: "POST" }, async ctx => {
          if (options.status !== undefined) ctx.setStatus(options.status);
          ctx.setHeader("x-proxy", "kept");
          if (cookie !== undefined) {
            for (const header of Array.isArray(cookie) ? cookie : [cookie]) ctx.responseHeaders.append("set-cookie", header);
          }
          if (options.apiError) throw ctx.error(400, value);
          return value;
        }),
      } },
      oAuthProxy(proxyOptions),
    ],
  });
  const context = await auth.$context;
  if (options.persisted !== false) await context.internalAdapter.createVerificationValue({
    identifier: state, value: plaintext, expiresAt: new Date(Date.now() + 300000),
  });
  armed = true;
  logs.length = 0;
  return {
    database, logs,
    get reads() { return reads; },
    async invoke(returned, stateCookie) {
      value = returned;
      cookie = stateCookie;
      return auth.api.signInSocial({
        request: new Request(`${origin}/api/auth/sign-in/social`, { method: "POST" }),
        asResponse: false,
        body: options.skipAfter ? { provider: "google" } : {},
        returnHeaders: true, returnStatus: true,
      });
    },
  };
}

async function assertPackage(response, expectedPlaintext) {
  const rewritten = new URL(response.url);
  const pairs = [...rewritten.searchParams];
  assert.deepEqual(pairs.map(([key]) => key), ["before", "state", "after"]);
  assert.equal(pairs[0][1], "a b");
  assert.equal(pairs[2][1], "~");
  const statePackage = JSON.parse(await symmetricDecrypt({ key: secret, data: rewritten.searchParams.get("state") }));
  assert.deepEqual(Object.keys(statePackage), ["state", "stateCookie", "isOAuthProxy"]);
  assert.equal(statePackage.state, state);
  assert.equal(statePackage.isOAuthProxy, true);
  assert.equal(await symmetricDecrypt({ key: secret, data: statePackage.stateCookie }), expectedPlaintext);
  assert.ok(response.url.includes("before=a+b&"));
  assert.ok(response.url.endsWith("&after=%7E"));
}

function assertLog(sample, error) {
  assert.equal(sample.logs.length, 1);
  assert.equal(sample.logs[0].level, error ? "error" : "warn");
  assert.equal(sample.logs[0].message, error ? "Failed to prepare OAuth proxy state:" : "No OAuth state found for proxy");
  assert.equal(sample.logs[0].arguments.length, error ? 1 : 0);
  if (error) assert.ok(sample.logs[0].arguments[0] instanceof Error);
}

test("native result shallow copy preserves values, order, identity and status", async () => {
  for (const status of [undefined, 201, 401]) {
    const sample = await fixture({ status });
    let calls = 0;
    const shared = {};
    shared.self = shared;
    const original = {
      9: "nine", url, 2: "two", left: shared, date: new Date(NaN), missing: undefined,
      nan: NaN, right: shared, toJSON() { calls += 1; throw new Error("proxy must not serialize returned fields"); },
    };
    const before = structuredClone(sample.database);
    const result = await sample.invoke(original);
    assert.notEqual(result.response, original);
    assert.deepEqual(Object.keys(result.response), ["2", "9", "url", "left", "date", "missing", "nan", "right", "toJSON"]);
    for (const name of ["left", "right", "date", "missing", "toJSON"]) assert.equal(result.response[name], original[name]);
    assert.ok(Number.isNaN(result.response.nan));
    assert.equal(original.url, url);
    assert.equal(calls, 0);
    assert.equal(result.status, status);
    assert.equal(result.headers.get("x-proxy"), "kept");
    assert.equal(sample.reads, 1);
    assert.deepEqual(sample.database, before);
    assert.deepEqual(sample.logs, []);
    await assertPackage(result.response, plaintext);
  }
});

test("native result guards skip without serialization or state lookup", async () => {
  const values = [undefined, null, false, 7, "text", {}, [], new Date(NaN), () => undefined, ...[
    undefined, null, 7, "", "https://provider.test/authorize",
    "https://provider.test/authorize?state=&state=native-proxy-state",
  ].map(object)];
  for (const original of values) {
    const sample = await fixture({ failRead: true });
    const result = await sample.invoke(original);
    assert.equal(result.response, original);
    assert.equal(sample.reads, 0);
    assert.deepEqual(sample.logs, []);
  }
});

test("native result URL errors escape before state try and UTF-16 uses USVString", async () => {
  const sample = await fixture();
  const original = object("not a URL");
  await assert.rejects(sample.invoke(original), TypeError);
  assert.equal(original.url, "not a URL");
  assert.equal(sample.reads, 0);
  assert.deepEqual(sample.logs, []);
  const result = await sample.invoke(object(`${url}#\ud800`));
  assert.ok(result.response.url.endsWith("#%EF%BF%BD"));
});

test("native result state truthiness and failures preserve original", async () => {
  const cases = [
    { persisted: false },
    ...[undefined, null, false, 0, NaN, ""].map(output => ({ output })),
    ...[7, {}].map(output => ({ output, error: true })),
    { failRead: true, error: true },
  ];
  for (const options of cases) {
    const sample = await fixture({ ...options, status: 403 });
    const original = object(url);
    const before = structuredClone(sample.database);
    const result = await sample.invoke(original);
    assert.equal(result.response, original);
    assert.equal(result.status, 403);
    assert.deepEqual(sample.database, before);
    assertLog(sample, options.error);
    if (options.failRead) assert.equal(sample.logs[0].arguments[0].message, "proxy lookup original failure");
  }
});

test("native result cookie state preserves plaintext and catches decryption errors", async () => {
  for (const payload of [undefined, "", plaintext, "invalid-ciphertext"]) {
    const sample = await fixture({ strategy: "cookie", persisted: false, status: 202 });
    const original = object(url);
    let cookie;
    if (payload !== undefined) {
      const encrypted = payload === "invalid-ciphertext" ? payload : await symmetricEncrypt({ key: secret, data: payload });
      cookie = `better-auth.oauth_state=${encodeURIComponent(encrypted)}; Path=/; HttpOnly`;
    }
    const result = await sample.invoke(original, cookie);
    assert.equal(result.headers.get("set-cookie"), cookie ?? null);
    assert.equal(sample.reads, 0);
    if (payload === plaintext) {
      await assertPackage(result.response, plaintext);
      assert.deepEqual(sample.logs, []);
    } else {
      assert.equal(result.response, original);
      assertLog(sample, payload === "invalid-ciphertext");
    }
  }
});

test("native result after hook rechecks skip and ignores explicit JSON bytes", async () => {
  for (const skipAfter of ["header", "origin"]) {
    const sample = await fixture({ skipAfter });
    const original = object(url);
    const result = await sample.invoke(original);
    assert.equal(result.response, original);
    assert.equal(sample.reads, 0);
    assert.deepEqual(sample.logs, []);
  }
  const sample = await fixture();
  const bytes = JSON.stringify({ url });
  const original = new Response(bytes, { status: 201, headers: { "x-proxy": "explicit" } });
  const result = await sample.invoke(original);
  assert.deepEqual(Object.keys(result), ["headers", "response", "status"]);
  assert.equal(result.status, undefined);
  const response = result.response;
  assert.equal(response, original);
  assert.equal(response.status, 201);
  assert.equal(await response.text(), bytes);
  assert.equal(response.headers.get("x-proxy"), "explicit");
  assert.equal(sample.reads, 0);
  assert.deepEqual(sample.logs, []);
});

test("native result cookie uses last value and decodes ciphertext", async () => {
  const sample = await fixture({ strategy: "cookie", persisted: false });
  const ciphertext = await symmetricEncrypt({ key: secret, data: plaintext });
  const encoded = [...ciphertext].map(character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`).join("");
  const cookies = ["better-auth.oauth_state=invalid-ciphertext; Path=/", `better-auth.oauth_state=${encoded}; Path=/`];
  const result = await sample.invoke(object(url), cookies);
  await assertPackage(result.response, plaintext);
  assert.deepEqual(result.headers.getSetCookie(), cookies);
  assert.deepEqual(sample.logs, []);
});

test("native API error body URL is not an error object URL", async () => {
  const sample = await fixture({ apiError: true });
  const original = object(url);
  const before = structuredClone(sample.database);
  await assert.rejects(sample.invoke(original), error => {
    assert.equal(error.body, original);
    assert.equal(error.statusCode, 400);
    return true;
  });
  assert.equal(sample.reads, 0);
  assert.deepEqual(sample.database, before);
  assert.deepEqual(sample.logs, []);
});
