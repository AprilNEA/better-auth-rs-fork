import { expect, test } from "bun:test";
import { APIError } from "@better-auth/core/error";
import { APIError as EndpointAPIError } from "better-call";
import { parseUserInput } from "better-auth/db";
import { admin, anonymous, phoneNumber, twoFactor } from "better-auth/plugins";

const fields = ["role", "banned", "banReason", "banExpires", "phoneNumberVerified", "isAnonymous", "twoFactorEnabled"];
const defaults = { banned: false, isAnonymous: false, twoFactorEnabled: false };
const native = () => [admin(), phoneNumber({ sendOTP: async () => {} }), anonymous(), twoFactor()];
const plain = (value: unknown) => Object.assign({}, value);

function policies(label: string, trace: string[], reject?: string, protectedInput = false) {
  return Object.fromEntries(fields.map(name => [name, {
    type: "string" as const, input: !protectedInput,
    ...(protectedInput ? { defaultValue: "replacement-default" } : {}),
    ...(name === "role" ? { validator: { input: { "~standard": {
      version: 1 as const, vendor: "user-input-policy",
      validate() {
        trace.push(`${label}:validate:${name}`);
        return reject === name ? { issues: [{ message: "validator denied" }] } : { value: `${label}:${name}` };
      },
    } } } } : {}),
    transform: { input() {
      trace.push(`${label}:transform:${name}`);
      if (reject === name) throw new Error("transform denied");
      return `${label}:${name}`;
    } },
  }]));
}

function denied(action: () => unknown, name: string) {
  let caught: any;
  try { action(); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(APIError);
  expect(caught).toBeInstanceOf(EndpointAPIError);
  expect(caught.status).toBe("BAD_REQUEST");
  expect(caught.statusCode).toBe(400);
  expect(Object.keys(caught.body)).toStrictEqual(["message", "code"]);
  expect(caught?.body).toStrictEqual({ code: "FIELD_NOT_ALLOWED", message: `${name} is not allowed to be set` });
}

test("native User input declarations preserve protection and creation defaults", () => {
  const options = { plugins: native() };
  expect(plain(parseUserInput(options, {}, "create"))).toStrictEqual(defaults);
  expect(plain(parseUserInput(options, {}, "update"))).toStrictEqual({});
  for (const name of fields) {
    const input = { [name]: true };
    if (name in defaults) expect(plain(parseUserInput(options, input, "create"))).toStrictEqual(defaults);
    else denied(() => parseUserInput(options, input, "create"), name);
    denied(() => parseUserInput(options, input, "update"), name);
    for (const value of [null, false, 0, ""]) {
      expect(plain(parseUserInput(options, { [name]: value }, "create"))).toStrictEqual(defaults);
      expect(plain(parseUserInput(options, { [name]: value }, "update"))).toStrictEqual({});
    }
  }
});

test("complete User declarations replace application and earlier plugin callbacks in plugin order", () => {
  for (const late of [false, true]) {
    for (const reject of [undefined, "role", "banReason"]) {
      const trace: string[] = [];
      const options = {
        user: { additionalFields: policies("application", trace) },
        plugins: [
          { id: "early-policy", schema: { user: { fields: policies("early", trace) } } },
          ...native(),
          ...(late ? [{ id: "late-policy", schema: { user: { fields: policies("late", trace, reject) } } }] : []),
        ],
      };
      const input = Object.fromEntries(fields.map(name => [name, true]));
      for (const action of ["create", "update"] as const) {
        if (!late) {
          denied(() => parseUserInput(options, input, action), "role");
          expect(trace.splice(0)).toStrictEqual([]);
        } else if (reject === "role") {
          let caught: any;
          try { parseUserInput(options, input, action); } catch (error) { caught = error; }
          expect(caught).toBeInstanceOf(APIError);
          expect(caught).toBeInstanceOf(EndpointAPIError);
          expect(caught.status).toBe("BAD_REQUEST");
          expect(caught.statusCode).toBe(400);
          expect(Object.keys(caught.body)).toStrictEqual(["message", "code"]);
          expect(caught?.body).toStrictEqual({ code: "VALIDATION_ERROR", message: "validator denied" });
          expect(trace.splice(0)).toStrictEqual(["late:validate:role"]);
        } else if (reject === "banReason") {
          expect(() => parseUserInput(options, input, action)).toThrow("transform denied");
          expect(trace.splice(0)).toStrictEqual(["late:validate:role", "late:transform:banned", "late:transform:banReason"]);
        } else {
          const parsed = parseUserInput(options, input, action);
          expect(Object.keys(parsed)).toStrictEqual(fields);
          expect(plain(parsed)).toStrictEqual(Object.fromEntries(fields.map(name => [name, `late:${name}`])));
          expect(trace.splice(0)).toStrictEqual(fields.map(name => `late:${name === "role" ? "validate" : "transform"}:${name}`));
        }
      }
      expect(plain(parseUserInput(options, {}, "create"))).toStrictEqual(late ? {} : defaults);
      expect(trace).toStrictEqual([]);
    }
  }
});

test("protected replacement defaults take precedence without invoking callbacks", () => {
  const trace: string[] = [];
  const options = { plugins: [...native(), {
    id: "protected-policy", schema: { user: { fields: policies("protected", trace, "role", true) } },
  }] };
  const expected = Object.fromEntries(fields.map(name => [name, "replacement-default"]));
  const input = Object.fromEntries(fields.map(name => [name, true]));
  expect(plain(parseUserInput(options, input, "create"))).toStrictEqual(expected);
  expect(plain(parseUserInput(options, {}, "create"))).toStrictEqual(expected);
  denied(() => parseUserInput(options, input, "update"), "role");
  expect(trace).toStrictEqual([]);
});

test("missing User fields retain named schema errors", () => {
  const options = { user: { additionalFields: { required: { type: "string" as const, required: true } } } };
  let caught: any;
  try { parseUserInput(options, {}, "create"); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(APIError);
  expect(caught).toBeInstanceOf(EndpointAPIError);
  expect(caught.status).toBe("BAD_REQUEST");
  expect(caught.statusCode).toBe(400);
  expect(Object.keys(caught.body)).toStrictEqual(["message", "code"]);
  expect(caught.body).toStrictEqual({ message: "required is required", code: "MISSING_FIELD" });
  expect(plain(parseUserInput(options, {}, "update"))).toStrictEqual({});
});

for (const factory of [false, true]) {
  test(`User ${factory ? "factory" : "transform"} propagates original failures`, () => {
    const events: string[] = [];
    const failure = APIError.from("CONFLICT", { code: "VALIDATION_ERROR", message: "callback rejected" });
    const rejected = () => { events.push(factory ? "factory" : "transform"); throw failure; };
    const options = { user: { additionalFields: {
      value: { type: "string" as const, ...(factory ? { defaultValue: rejected } : { transform: { input: rejected } }) },
      later: { type: "string" as const, defaultValue: () => { events.push("later"); return "later"; } },
    } } };
    let caught: unknown;
    try { parseUserInput(options, factory ? {} : { value: true }, "create"); }
    catch (error) { caught = error; }
    expect(caught).toBe(failure);
    expect(events).toStrictEqual([factory ? "factory" : "transform"]);
  });
}
