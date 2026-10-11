import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { APIError as EndpointAPIError, createEndpoint, toResponse } from "better-call";
import { z } from "zod";

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
  await observe(APIError.from("BAD_REQUEST", { code: "CUSTOM_FIELD_FAILURE", message: "field rejected" }),
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
    await observe(caught as EndpointAPIError, 400, ["message", "code"], JSON.stringify({ message, code: "VALIDATION_ERROR" }));
  });
}
