import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

const origin = "http://http-json-router.test";

test("HTTP JSON router preserves catch headers and response-hook order", async () => {
  for (const phase of ["before-raw", "before-json", "endpoint", "after-json"]) {
    for (const specimen of ["cycle", "method-error", "omitted"]) {
      const events = [];
      const errors = [];
      const failure = new Error("original HTTP JSON router method error");
      const before = phase.startsWith("before");
      const failed = specimen === "method-error" || phase === "before-json" && specimen === "cycle";
      const value = specimen === "cycle" ? {} : { toJSON(key) {
        expect(this).toBe(value);
        expect(key).toBe("");
        events.push("serialize");
        if (specimen === "method-error") throw failure;
        return undefined;
      } };
      if (specimen === "cycle") value.self = value;
      const expectedBody = failed || specimen === "omitted" ? "" : '{"self":"[Circular ref-0]"}';
      const expectedHeaders = failed ? {} : before
        ? { "content-type": "application/json", "x-before": "1" }
        : { "content-type": "application/json", "x-endpoint": "1", "x-after": "1" };
      async function assertHTTP(response) {
        expect(response.status).toBe(failed ? 500 : before ? 200 : 201);
        expect(response.body === null).toBe(failed || specimen === "omitted");
        expect(await response.clone().text()).toBe(expectedBody);
        expect([...response.headers].length).toBe(Object.keys(expectedHeaders).length);
        for (const [name, header] of Object.entries(expectedHeaders)) expect(response.headers.get(name)).toBe(header);
      }
      const auth = betterAuth({
        baseURL: origin, secret: "http-json-router-contract-at-least-32-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        onAPIError: { onError(error) {
          events.push("on-error");
          errors.push(error);
          if (specimen === "method-error") expect(error).toBe(failure);
          else expect(error).toBeInstanceOf(TypeError);
        } },
        hooks: {
          before: createAuthMiddleware(async ctx => {
            events.push("before");
            ctx.setHeader("x-before", "1");
            if (before) return phase === "before-json" ? ctx.json(value) : value;
          }),
          after: createAuthMiddleware(async ctx => {
            events.push("after");
            ctx.setHeader("x-after", "1");
            if (phase === "endpoint") expect(ctx.context.returned).toBe(value);
            else {
              expect(ctx.context.returned).toStrictEqual({ endpoint: true });
              return ctx.json(value);
            }
          }),
        },
        plugins: [{
          id: "http-json-router",
          endpoints: { httpJsonRouter: createAuthEndpoint("/http-json-router", { method: "GET" }, async ctx => {
            events.push("endpoint");
            ctx.setStatus(201);
            ctx.setHeader("x-endpoint", "1");
            return ctx.json(phase === "endpoint" ? value : { endpoint: true });
          }) },
          hooks: { after: [{ matcher: () => true, handler: createAuthMiddleware(async ctx => {
            events.push("plugin-after");
            expect(ctx.context.returned).toBe(value);
          }) }] },
          async onResponse(response) {
            events.push("on-response");
            await assertHTTP(response);
          },
        }],
      });
      const response = await auth.handler(new Request(`${origin}/api/auth/http-json-router`));
      await assertHTTP(response);
      const expected = ["before"];
      if (!before) expected.push("endpoint", "after", "plugin-after");
      if (specimen !== "cycle") expected.push("serialize");
      if (failed) expected.push("on-error");
      expected.push("on-response");
      expect(events).toStrictEqual(expected);
      expect(errors.length).toBe(failed ? 1 : 0);
    }
  }
});
