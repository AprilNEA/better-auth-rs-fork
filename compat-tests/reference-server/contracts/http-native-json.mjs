import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { APIError, toResponse } from "better-call";

function specimen(name) {
  const events = [];
  const failure = new Error("original HTTP JSON method error");
  let value;
  const method = (label, result) => ({ toJSON(key) {
    events.push([label, key]);
    expect(this).toBe(label === "root" ? value : value[label]);
    if (name === "method-error") throw failure;
    return result();
  } });
  switch (name) {
    case "object-self": value = {}; value.self = value; break;
    case "array-self": value = []; value.push(value); break;
    case "indirect": value = { child: {} }; value.child.root = value; break;
    case "aliases": {
      const shared = {}; shared.self = shared;
      value = { first: {}, a: shared, b: shared }; break;
    }
    case "ordinary-alias": { const shared = { leaf: 1 }; value = { a: shared, b: shared }; break; }
    case "returned-date": {
      const child = {}; child.self = child;
      value = { date: method("date", () => new Date(0)), child }; break;
    }
    case "toJSON-ancestor": value = { child: method("child", () => value) }; break;
    case "root-undefined": value = method("root", () => undefined); break;
    case "root-function": value = method("root", () => function omitted() {}); break;
    case "root-date": value = method("root", () => new Date(0)); break;
    case "root-returned-object": value = method("root", () => ({ toJSON() { throw new Error("prepared twice"); }, kept: 1 })); break;
    case "method-error": value = method("root", () => null); break;
    default: throw new Error(`Unknown HTTP JSON specimen: ${name}`);
  }
  return { value, events, failure };
}

const cases = [
  ["object-self", '{"self":"[Circular ref-0]"}', true, []],
  ["array-self", '["[Circular ref-0]"]', true, []],
  ["indirect", '{"child":{"root":"[Circular ref-0]"}}', true, []],
  ["aliases", '{"first":{},"a":{"self":"[Circular ref-2]"},"b":{"self":"[Circular ref-2]"}}', true, []],
  ["ordinary-alias", '{"a":{"leaf":1},"b":{"leaf":1}}', false, []],
  ["returned-date", '{"date":{},"child":{"self":"[Circular ref-2]"}}', true, [["date", "date"]]],
  ["toJSON-ancestor", '{"child":"[Circular ref-0]"}', true, [["child", "child"]]],
  ["root-undefined", undefined, false, [["root", ""]]],
  ["root-function", undefined, false, [["root", ""]]],
  ["root-date", '{}', false, [["root", ""]]],
  ["root-returned-object", '{"kept":1}', false, [["root", ""]]],
  ["method-error", undefined, false, [["root", ""]]],
];

for (const phase of ["before-raw", "before-json", "endpoint", "after-json"]) {
  test(`HTTP JSON ${phase} preserves native identity, encoding, and strict before-hook provenance`, async () => {
    for (const [name, bytes, circular, expectedEvents] of cases) {
      for (const transport of ["native", "asResponse", "router"]) {
        const { value, events, failure } = specimen(name);
        const observed = [];
        const errors = [];
        const before = phase.startsWith("before");
        const auth = betterAuth({
          baseURL: "http://http-json.test", secret: "http-json-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
          onAPIError: { onError(error) { errors.push(error); } },
          hooks: {
            before: createAuthMiddleware(async ctx => {
              if (before) {
                ctx.setHeader("x-before", "1");
                return phase === "before-json" ? ctx.json(value) : value;
              }
            }),
            after: createAuthMiddleware(async ctx => {
              observed.push(ctx.context.returned);
              if (phase === "after-json") return ctx.json(value);
            }),
          },
          plugins: [{ id: "http-json", endpoints: {
            httpJson: createAuthEndpoint("/http-json", { method: "GET" }, async ctx => {
              ctx.setStatus(201);
              return ctx.json(phase === "endpoint" ? value : { endpoint: true });
            }),
          }, hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
            observed.push(ctx.context.returned);
          }) }] } }],
        });
        let result;
        let thrown;
        try {
          result = transport === "router"
            ? await auth.handler(new Request("http://http-json.test/api/auth/http-json"))
            : await auth.api.httpJson({ asResponse: transport === "asResponse", returnHeaders: true, returnStatus: true });
        } catch (error) { thrown = error; }
        expect(observed.length, `${name}/${phase}/${transport}`).toBe(before ? 0 : 2);
        if (!before) {
          expect(observed[1]).toBe(value);
          if (phase === "endpoint") expect(observed[0]).toBe(value);
          else expect(observed[0]).toStrictEqual({ endpoint: true });
        }
        if (transport === "native") {
          expect(thrown).toBeUndefined();
          expect(result.response).toBe(value);
          expect(Object.hasOwn(result, "status")).toBe(!before);
          expect(result.status).toBe(before ? undefined : 201);
          expect(events).toStrictEqual([]);
          expect(errors).toStrictEqual([]);
          continue;
        }
        const failed = name === "method-error" || phase === "before-json" && circular;
        const caught = transport === "router" ? errors[0] : thrown;
        if (failed) {
          if (name === "method-error") expect(caught).toBe(failure);
          else expect(caught).toBeInstanceOf(TypeError);
          if (transport === "router") {
            expect(thrown).toBeUndefined();
            expect(errors.length).toBe(1);
            expect(result.status).toBe(500);
            expect(result.body).toBeNull();
            expect(await result.text()).toBe("");
          } else expect(result).toBeUndefined();
        } else {
          expect(caught).toBeUndefined();
          expect(errors).toStrictEqual([]);
          expect(result.status).toBe(before ? 200 : 201);
          expect(result.headers.get("content-type")).toBe("application/json");
          expect(result.body === null).toBe(bytes === undefined);
          expect(await result.text()).toBe(bytes ?? "");
        }
        expect(events).toStrictEqual(expectedEvents);
      }
    }
  });
}

test("HTTP before ctx.json wraps scalar values while native and raw scalar returns fall through", async () => {
  for (const value of [undefined, null, "", "text", false, 0]) {
    for (const wrap of [false, true]) {
      for (const http of [false, true]) {
        let calls = 0;
        const auth = betterAuth({
          baseURL: "http://http-json.test", secret: "http-json-contract-at-least-32-characters",
          logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
          hooks: { before: createAuthMiddleware(async ctx => wrap ? ctx.json(value) : value) },
          plugins: [{ id: "scalar-json", endpoints: {
            scalarJson: createAuthEndpoint("/scalar-json", { method: "GET" }, async ctx => {
              calls += 1; ctx.setStatus(201); return ctx.json({ endpoint: true });
            }),
          } }],
        });
        const result = await auth.api.scalarJson({ asResponse: http });
        const short = wrap && http;
        expect(calls).toBe(short ? 0 : 1);
        if (http) {
          expect(result.status).toBe(short ? 200 : 201);
          expect(result.body === null).toBe(short && value === undefined);
          expect(await result.text()).toBe(short ? JSON.stringify(value) ?? "" : '{"endpoint":true}');
        } else expect(result).toStrictEqual({ endpoint: true });
      }
    }
  }
});

test("HTTP JSON materializes before validating status and preserves explicit Response and APIError boundaries", async () => {
  for (const failed of [false, true]) {
    const { value, events, failure } = specimen(failed ? "method-error" : "root-date");
    let caught;
    try { toResponse(value, { status: 199 }); } catch (error) { caught = error; }
    expect(events).toStrictEqual([["root", ""]]);
    if (failed) expect(caught).toBe(failure);
    else {
      expect(caught).toBeInstanceOf(RangeError);
      expect(caught.message).toBe("The status provided (199) must be 101 or in the range of [200, 599]");
    }
  }
  const response = new Response("explicit", { status: 207 });
  response.toJSON = () => { throw new Error("Explicit Response must not serialize"); };
  expect(toResponse(response, { status: 199 })).toBe(response);
  expect(await response.text()).toBe("explicit");
  const { value } = specimen("object-self");
  const error = new APIError("BAD_REQUEST", value);
  const encoded = toResponse(error);
  expect(encoded.status).toBe(400);
  expect(await encoded.text()).toBe('{"self":"[Circular ref-0]"}');
});
