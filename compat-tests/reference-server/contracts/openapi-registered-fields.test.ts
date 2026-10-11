import { expect, test } from "bun:test";
import { betterAuth } from "better-auth/minimal";
import { lastLoginMethod, openAPI, username } from "better-auth/plugins";
import expected from "../../../tests/fixtures/openapi-registered-fields-1.7.6.json";
import { captureOpenApiRegisteredFields } from "./openapi-registered-fields";

test("registered field policies reach complete OpenAPI components without callbacks", async () => {
  const actual = await captureOpenApiRegisteredFields();
  expect(actual).toStrictEqual(expected);
  expect(actual.cases.map(({ name }) => name)).toStrictEqual([
    "registered-only", "organization-before", "organization-after", "organization-disabled",
  ]);
  for (const { callbackCalls } of actual.cases) {
    expect(callbackCalls).toStrictEqual({ default: 0, input: 0, output: 0 });
  }
});

for (const displayUsername of [false, true]) for (const storeInDatabase of [false, true]) {
  test(`User components follow actual registration: displayUsername=${displayUsername}, storeInDatabase=${storeInDatabase}`, async () => {
    const options = {
      baseURL: "http://openapi-built-in-registration.test",
      secret: "openapi-built-in-registration-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
    };
    const baseline = (await betterAuth({ ...options, plugins: [openAPI()] }).api.generateOpenAPISchema()).components.schemas;
    const expectedSchemas = structuredClone(baseline);
    expectedSchemas.User.properties.username = { type: "string" };
    if (displayUsername) expectedSchemas.User.properties.displayUsername = { type: "string" };
    if (storeInDatabase) expectedSchemas.User.properties.lastLoginMethod = { type: "string", readOnly: true };
    const actual = (await betterAuth({ ...options, plugins: [
      username({ displayUsername }), lastLoginMethod({ storeInDatabase }), openAPI(),
    ] }).api.generateOpenAPISchema()).components.schemas;
    expect(actual).toStrictEqual(expectedSchemas);
    expect(Object.keys(actual)).toStrictEqual(Object.keys(expectedSchemas));
    expect(Object.keys(actual.User.properties)).toStrictEqual(Object.keys(expectedSchemas.User.properties));
  });
}
