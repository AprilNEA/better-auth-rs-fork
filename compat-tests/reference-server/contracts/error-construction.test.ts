import { expect, test } from "bun:test";
import { APIError, BetterAuthError } from "@better-auth/core/error";
import { APIError as EndpointAPIError, createEndpoint, createRouter, toResponse } from "better-call";
import { z } from "zod";
import { toZodSchema } from "better-auth/db";

test("BetterAuthError retains UTF-16 messages, hidden properties, and native identity", () => {
  for (const message of ["OAUTH_ACCOUNT_SUBJECT_INVALID", "", "\ud800", "\udc00", "😀", "\udc00A\ud800"]) {
    const error = new BetterAuthError(message);
    expect(error).toBeInstanceOf(BetterAuthError);
    expect(error).not.toBeInstanceOf(APIError);
    expect(error).not.toBeInstanceOf(EndpointAPIError);
    expect(error.name).toBe("BetterAuthError");
    expect(error.message).toBe(message);
    expect(error.stack).toBe("");
    for (const name of ["message", "stack"]) {
      expect(Object.getOwnPropertyDescriptor(error, name)?.enumerable).toBe(false);
    }
    expect(Object.keys(error)).toStrictEqual(["name"]);
    expect(JSON.stringify(error)).toBe('{"name":"BetterAuthError"}');
    expect(String(error)).toBe(message ? `BetterAuthError: ${message}` : "BetterAuthError");
    error.name = "APIError";
    expect(error).not.toBeInstanceOf(EndpointAPIError);
    expect(error.message).toBe(message);
  }
});

test("JWT mismatch retains the second algorithm read and UTF-16 BetterAuthError message", async () => {
  const { resolveSigningKey } = await import("../node_modules/better-auth/dist/plugins/jwt/sign.mjs");
  for (const actual of [null, undefined, "changed", "\ud800A\udc00"]) {
    const events: string[] = [];
    let reads = 0;
    const key = {
      lastRead: "",
      get id() { events.push("id"); return "selected"; },
      get alg() { events.push("alg"); this.lastRead = "alg"; return ++reads === 1 ? "RS256" : actual; },
      get privateKey() { throw new Error("Mismatch must not read privateKey"); },
    };
    let caught: unknown;
    try {
      await resolveSigningKey({ context: { adapter: {} } }, {
        adapter: { async getJwks() { events.push("read"); return [key]; } },
      }, { signingKeyId: "selected", signingAlgorithm: "EdDSA" });
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(BetterAuthError);
    const error = caught as BetterAuthError;
    expect(error.name).toBe("BetterAuthError");
    expect(error.stack).toBe("");
    expect(error.message).toBe(`signJWT: signingKeyId "selected" has alg "${actual ?? 'unset (inherits keyPairConfig.alg "EdDSA")'}" but signingAlgorithm was set to "EdDSA".`);
    expect(events).toStrictEqual(["read", "id", "alg", "alg"]);
    expect(reads).toBe(2);
    expect(key.lastRead).toBe("alg");
  }
});

test("JWT mismatch propagates original second-read and string-coercion failures", async () => {
  const { resolveSigningKey } = await import("../node_modules/better-auth/dist/plugins/jwt/sign.mjs");
  for (const boundary of ["getter", "coercion"]) {
    const events: string[] = [];
    const original = { boundary };
    const dynamic = { toString() {
      expect(this).toBe(dynamic);
      events.push("toString");
      key.progress = "coercion";
      throw original;
    } };
    let reads = 0;
    const key = {
      id: "selected", progress: "",
      get alg() {
        events.push("alg");
        if (++reads === 1) return "RS256";
        this.progress = "getter";
        if (boundary === "getter") throw original;
        return dynamic;
      },
    };
    let caught: unknown;
    try {
      await resolveSigningKey({ context: { adapter: {} } }, {
        adapter: { async getJwks() { events.push("read"); return [key]; } },
      }, { signingKeyId: "selected", signingAlgorithm: "EdDSA" });
    } catch (error) { caught = error; }
    expect(caught).toBe(original);
    expect(events).toStrictEqual(["read", "alg", "alg", ...(boundary === "coercion" ? ["toString"] : [])]);
    expect(key.progress).toBe(boundary);
  }
});

test("JWT configuration guards retain upstream BetterAuthError messages and precedence", async () => {
  const { jwt } = await import("better-auth/plugins/jwt");
  const sign = async () => "unused";
  for (const [options, cache, message] of [
    [{ jwt: { sign } }, false, "options.jwks.remoteUrl must be set when using options.jwt.sign"],
    [{ jwks: { remoteUrl: "https://remote.test/jwks" } }, false, "options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata"],
    ...["", "keys", "/../keys"].map((jwksPath) => [
      { jwks: { jwksPath } }, false, "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
    ]),
    [{ sessionCookieCache: true }, false, '`jwt({ sessionCookieCache: true })` requires `session.cookieCache.strategy = "jwt"`.'],
    [{ sessionCookieCache: true, jwt: { sign }, jwks: { remoteUrl: "https://remote.test/jwks", keyPairConfig: { alg: "EdDSA" } } }, true,
      "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`."],
  ]) {
    let caught: unknown;
    try {
      const plugin = Reflect.apply(jwt, undefined, [options]);
      await plugin.init({ options: { session: { cookieCache: { strategy: cache ? "jwt" : "compact" } } } });
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(BetterAuthError);
    expect((caught as BetterAuthError).message).toBe(message);
    expect((caught as BetterAuthError).stack).toBe("");
  }
});

test("JWT missing keys and unconfigured algorithms retain detailed BetterAuthError messages", async () => {
  const { resolveSigningKey } = await import("../node_modules/better-auth/dist/plugins/jwt/sign.mjs");
  for (const [overrides, configs, message] of [
    [{ signingKeyId: "missing" }, [], 'signJWT: signingKeyId "missing" not found in JWKS. The key must be provisioned before it can be referenced.'],
    ...[[], [{ alg: "PS256" }, { alg: "ES512" }]].map((keyPairConfigs) => [
      { signingAlgorithm: "RS256" }, keyPairConfigs,
      `signJWT: no key with alg "RS256" found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg="EdDSA"; additional algs configured via keyPairConfigs: ${keyPairConfigs.map((config) => config.alg).join(", ") || "none"}. Add "RS256" to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().`,
    ]),
  ]) {
    const events: string[] = [];
    let caught: unknown;
    try {
      await resolveSigningKey({ context: { adapter: {} } }, {
        jwks: { keyPairConfigs: configs },
        adapter: {
          async getJwks() { events.push("read"); return []; },
          async createJwk() { events.push("write"); throw new Error("A missing pinned key must not be created"); },
        },
      }, overrides);
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(BetterAuthError);
    expect((caught as BetterAuthError).message).toBe(message);
    expect(events).toStrictEqual(["read"]);
  }
});

async function observe(error: EndpointAPIError, status: number, keys: string[], bytes: string) {
  expect(error.statusCode).toBe(status);
  expect(Object.keys(error.body ?? {})).toStrictEqual(keys);
  const response = toResponse(error);
  expect(response.status).toBe(status);
  expect(await response.text()).toBe(bytes);
  return error.body;
}

test("coded errors and explicit message bodies have distinct contracts", async () => {
  const source = { code: "USER_NOT_FOUND", message: "User not found", extra: "discarded" };
  const coded = APIError.from("BAD_REQUEST", source);
  expect(coded.body).not.toBe(source);
  expect(await observe(coded, 400, ["message", "code"], '{"message":"User not found","code":"USER_NOT_FOUND"}'))
    .toStrictEqual({ message: "User not found", code: "USER_NOT_FOUND" });
  const body = { message: "User not found" };
  expect(await observe(APIError.fromStatus("BAD_REQUEST", body), 400, ["message"], '{"message":"User not found"}')).toBe(body);
});

for (const fromStatus of [true, false]) {
  test(`explicit ${fromStatus ? "fromStatus" : "constructor"} bodies retain order, extra properties and identity`, async () => {
    const body = { code: "CUSTOM", message: "initial", details: { reason: "retained" }, omitted: undefined };
    const error = fromStatus ? APIError.fromStatus("CONFLICT", body) : new APIError("CONFLICT", body);
    body.message = "User not found";
    expect(await observe(error, 409, ["code", "message", "details", "omitted"],
      '{"code":"CUSTOM","message":"User not found","details":{"reason":"retained"}}')).toBe(body);
    expect(Object.hasOwn(error.body!, "omitted")).toBe(true);
    expect(error.body!.omitted).toBeUndefined();
  });
}

test("absent and null error bodies remain distinct", async () => {
  expect(await observe(APIError.fromStatus("UNAUTHORIZED"), 401, [], "")).toBeUndefined();
  const error = Reflect.construct(APIError, ["UNAUTHORIZED", null]) as APIError;
  expect(await observe(error, 401, [], "null")).toBeNull();
});

test("custom coded field errors retain their explicit code", async () => {
  const error = APIError.from("BAD_REQUEST", { code: "CUSTOM_FIELD_FAILURE", message: "field rejected" });
  expect(error).toBeInstanceOf(APIError);
  expect(error).toBeInstanceOf(EndpointAPIError);
  expect(error.status).toBe("BAD_REQUEST");
  await observe(error,
    400, ["message", "code"], '{"message":"field rejected","code":"CUSTOM_FIELD_FAILURE"}');
});

for (const location of ["body", "query", "headers"] as const) {
  test(`${location} validation retains complete issues and native coded error bodies`, async () => {
    const events: unknown[] = [];
    const endpoint = createEndpoint("/schema", {
      method: "POST",
      ...(location === "body" ? { body: z.record(z.string(), z.unknown()) }
        : location === "query" ? { query: z.object({}).optional() } : { requireHeaders: true }),
      onValidationError(error) { events.push(error); },
    }, async () => { events.push("handler"); return null; });
    let caught: unknown;
    const context = location === "headers" ? { request: new Request("http://headers.test/source") } : { [location]: 42 };
    try { await Reflect.apply(endpoint, undefined, [context]); }
    catch (error) { caught = error; }
    const kind = location === "body" ? "record" : "object";
    const issue = `Invalid input: expected ${kind}, received number`;
    const message = location === "headers" ? "Headers is required" : `[${location}] ${issue}`;
    expect(events).toStrictEqual([{ message, issues: location === "headers" ? []
      : [{ expected: kind, code: "invalid_type", path: [], message: issue }] }]);
    expect(caught).toBeInstanceOf(EndpointAPIError);
    expect(caught).not.toBeInstanceOf(APIError);
    expect((caught as EndpointAPIError).status).toBe(400);
    await observe(caught as EndpointAPIError, 400, ["message", "code"], JSON.stringify({ message, code: "VALIDATION_ERROR" }));
  });
}

test("Organization issues retain request identity and declaration order", async () => {
  const endpoint = createEndpoint("/organization", {
    method: "POST",
    body: toZodSchema({ fields: { title: { type: "string" }, tags: { type: "string[]" } }, isClientSide: true }),
  }, async () => { throw new Error("Invalid input must not reach the handler"); });
  let caught: unknown;
  try { await Reflect.apply(endpoint, undefined, [{ body: { title: false, tags: [null, 3] } }]); }
  catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(EndpointAPIError);
  expect(caught).not.toBeInstanceOf(APIError);
  expect((caught as EndpointAPIError).status).toBe(400);
  await observe(caught as EndpointAPIError, 400, ["message", "code"],
    '{"message":"[body.title] Invalid input: expected string, received boolean; [body.tags.0] Invalid input: expected string, received null; [body.tags.1] Invalid input: expected string, received number","code":"VALIDATION_ERROR"}');
});

test("Organization field validation propagates original getter failures", () => {
  const fields = toZodSchema({ fields: {
    first: { type: "string" }, payload: { type: "json" }, later: { type: "string" },
  }, isClientSide: true });
  for (const failure of [
    APIError.from("CONFLICT", { code: "VALIDATION_ERROR", message: "getter rejected" }),
    APIError.from("BAD_REQUEST", { code: "CUSTOM_FIELD_FAILURE", message: "field getter rejected" }),
    new EndpointAPIError(400, { message: "field getter rejected", code: "VALIDATION_ERROR" }),
  ]) {
    const events: string[] = [];
    const payload = { get value() { events.push("value"); throw failure; } };
    let caught: unknown;
    try { fields.parse({ first: false, payload }); }
    catch (error) { caught = error; }
    expect(caught).toBe(failure);
    expect(events).toStrictEqual(["value"]);
  }
});

test("update-user preserves named builtin errors and complete explicit bodies", async () => {
  const { betterAuth } = await import("better-auth");
  const { serializeSignedCookie } = await import("better-call");
  const { memoryAdapter } = await import("better-auth/adapters/memory");
  const now = new Date();
  const user = { id: "owner", email: "owner@status.test", emailVerified: true, name: "Owner", createdAt: now, updatedAt: now };
  const session = { user, session: { id: "session", userId: "owner", token: "token", createdAt: now, updatedAt: now, expiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000) } };
  const database = { user: [user], session: [session.session], account: [], verification: [] };
  const stored = structuredClone(database);
  const secret = "status-contract-secret-at-least-32-characters";
  const cookie = (await serializeSignedCookie("better-auth.session_token", "token", secret)).split(";")[0];
  const auth = betterAuth({
    database: memoryAdapter(database), baseURL: "http://status-contract.test",
    secret,
    logger: { disabled: true }, telemetry: { enabled: false },
  });
  for (const [hasSession, body, status, code, expected] of [
    [false, {}, "UNAUTHORIZED", 401, { message: "Unauthorized", code: "UNAUTHORIZED" }],
    [true, { email: "changed@status.test" }, "BAD_REQUEST", 400, { message: "Email can not be updated", code: "EMAIL_CAN_NOT_BE_UPDATED" }],
    [true, {}, "BAD_REQUEST", 400, { message: "No fields to update" }],
  ] as const) {
    let caught: APIError | undefined;
    try { await auth.api.updateUser({ body, headers: new Headers(hasSession ? { cookie } : {}) }); }
    catch (error) { expect(error).toBeInstanceOf(APIError); caught = error as APIError; }
    expect(caught?.status).toBe(status);
    expect(await observe(caught!, code, Object.keys(expected), JSON.stringify(expected))).toStrictEqual(expected);
    expect(database).toStrictEqual(stored);
  }
});

for (const [name, contentType, input, status, code, message] of [
  ["missing-type", undefined, "{}", 415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type is required. Allowed types: application/json"],
  ["disallowed-type", "text/plain", "{}", 415, "UNSUPPORTED_MEDIA_TYPE", 'Content-Type "text/plain" is not allowed. Allowed types: application/json'],
  ["invalid-json", "application/json", "{", 400, "BAD_REQUEST", "Invalid JSON in request body"],
  ["empty-json", "application/json", "", 400, "BAD_REQUEST", "Invalid JSON in request body"],
] as const) {
  test(`HTTP body parser ${name} retains Better Call provenance before serialization`, async () => {
    let caught: unknown;
    let calls = 0;
    const router = createRouter({ body: createEndpoint("/body", {
      method: "POST", metadata: { allowedMediaTypes: ["application/json"] },
    }, async () => { calls++; return null; }) }, {
      openapi: { disabled: true },
      onError(error) { caught = error; },
    });
    const response = await router.handler(new Request("http://body-errors.test/body", {
      method: "POST",
      headers: contentType === undefined ? undefined : { "content-type": contentType },
      body: new TextEncoder().encode(input),
    }));
    expect(caught).toBeInstanceOf(EndpointAPIError);
    expect(caught).not.toBeInstanceOf(APIError);
    const error = caught as EndpointAPIError;
    expect(error.status).toBe(status);
    expect(error.statusCode).toBe(status);
    expect(error.body).toStrictEqual({ message, code });
    expect(Object.keys(error.body!)).toStrictEqual(["message", "code"]);
    expect(error.headers).toStrictEqual({});
    expect(response.status).toBe(status);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.text()).toBe(JSON.stringify({ message, code }));
    expect(calls).toBe(0);
  });
}
