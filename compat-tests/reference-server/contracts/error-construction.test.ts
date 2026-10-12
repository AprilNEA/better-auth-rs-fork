import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { APIError as EndpointAPIError, createEndpoint, createRouter, toResponse } from "better-call";
import { z } from "zod";
import { toZodSchema } from "better-auth/db";

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
