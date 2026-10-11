import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { toResponse } from "better-call";

async function observe(error: APIError, status: number, keys: string[], bytes: string) {
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
