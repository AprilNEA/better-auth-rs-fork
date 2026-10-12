import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint } from "better-auth/api";

const origin = "https://original.routing.test";
const basePath = "/api/runtime";
const duringRequest = "http://during.routing.test/replaced";
const secret = "request-runtime-routing-secret-at-least-32-characters";
const emptyDatabase = () => ({ user: [], session: [], account: [], verification: [] });

for (const [name, assigned, requestPath] of [
  ["no-path", "https://next.routing.test", "/routing-probe"],
  ["dot-path", "https://next.routing.test/root/../auth/", "/auth/routing-probe"],
  ["query-fragment", "https://next.routing.test/auth?next=/wrong#ignored", "/auth/routing-probe"],
  ["query-without-path", "https://next.routing.test?next=/wrong#ignored", "/routing-probe"],
] as const) {
  test(`HTTP router captures the current root URL pathname: ${name}`, async () => {
    const database = emptyDatabase();
    const observations: unknown[] = [];
    const auth = betterAuth({
      baseURL: origin, basePath, secret, database: memoryAdapter(database),
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
      plugins: [{ id: "runtime-routing", async onRequest(request, context) {
        observations.push({ phase: "onRequest", baseURL: context.baseURL, requestURL: request.url });
        context.baseURL = duringRequest;
      }, async onResponse(_response, context) {
        observations.push({ phase: "onResponse", baseURL: context.baseURL });
      }, endpoints: {
        routingProbe: createAuthEndpoint("/routing-probe", { method: "GET" }, async ctx => {
          return ctx.json({ baseURL: ctx.context.baseURL, path: ctx.path, optionURL: ctx.context.options.baseURL, optionPath: ctx.context.options.basePath });
        }),
      } }],
    });
    const root = await auth.$context;
    root.baseURL = assigned;
    const requestURL = `${origin}${requestPath}`;
    const response = await auth.handler(new Request(requestURL));
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ baseURL: duringRequest, path: "/routing-probe", optionURL: origin, optionPath: basePath });
    expect(observations).toStrictEqual([
      { phase: "onRequest", baseURL: assigned, requestURL },
      { phase: "onResponse", baseURL: duringRequest },
    ]);
    expect(root.baseURL).toBe(assigned);
    expect(root.options.baseURL).toBe(origin);
    expect(root.options.basePath).toBe(basePath);
    expect(database).toStrictEqual(emptyDatabase());
  });
}

for (const assigned of ["", "/relative", "not a url", "https://[invalid"] as const) {
  test(`invalid root URL fails before HTTP hooks and router error handling: ${JSON.stringify(assigned)}`, async () => {
    const database = emptyDatabase();
    const events: string[] = [];
    const auth = betterAuth({
      baseURL: origin, basePath, secret, database: memoryAdapter(database),
      logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
      trustedOrigins(request) { events.push(`origins:${request ? "request" : "initial"}`); return []; },
      account: { accountLinking: { trustedProviders(request) { events.push(`providers:${request ? "request" : "initial"}`); return []; } } },
      onAPIError: { onError() { events.push("router-error"); } },
      plugins: [{ id: "runtime-routing-error", async onRequest() { events.push("onRequest"); },
        async onResponse() { events.push("onResponse"); }, endpoints: {
          routingProbe: createAuthEndpoint("/routing-probe", { method: "GET" }, async () => {
            events.push("handler");
            return { ok: true };
          }),
        },
      }],
    });
    const root = await auth.$context;
    expect(events).toStrictEqual(["origins:initial", "providers:initial"]);
    events.length = 0;
    // The native constructor supplies the runtime-specific message; the actual handler must propagate that error shape.
    let expected: unknown;
    try { new URL(assigned); } catch (error) { expected = error; }
    expect(expected).toBeInstanceOf(TypeError);
    root.baseURL = assigned;
    let caught: unknown;
    try { await auth.handler(new Request(`${origin}${basePath}/routing-probe`)); }
    catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).name).toBe((expected as Error).name);
    expect((caught as Error).message).toBe((expected as Error).message);
    expect(events).toStrictEqual(["origins:request", "providers:request"]);
    expect(root.baseURL).toBe(assigned);
    expect(root.options.baseURL).toBe(origin);
    expect(database).toStrictEqual(emptyDatabase());
    process.stdout.write(`${JSON.stringify({ case: "request-runtime-invalid-url", assigned, name: (caught as Error).name, message: (caught as Error).message, events })}\n`);
  });
}
