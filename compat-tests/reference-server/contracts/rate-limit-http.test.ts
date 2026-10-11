import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";

const { onRequestRateLimit } = await import(new URL("../node_modules/better-auth/dist/api/rate-limiter/index.mjs", import.meta.url).href);
const baseURL = "http://rate-http.test";
expect((await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json()).version).toBe("1.7.6");

test("direct limiter and auth.handler preserve explicit responses and skip endpoint callbacks", async () => {
  for (const outcome of [null, 0, 2.25, "allowed", "failed"] as const) {
    const events: unknown[] = [];
    const failure = new Error("rate storage failed");
    const auth = betterAuth({
      baseURL, secret: "rate-http-secret-at-least-thirty-two-characters", logger: { disabled: true },
      rateLimit: {
        enabled: true, window: 7.5, max: 3,
        customStorage: {
          async consume(key, rule) {
            events.push({ phase: "consume", key, ...rule });
            if (outcome === "failed") throw failure;
            return { allowed: outcome === "allowed", retryAfter: typeof outcome === "number" ? outcome : null };
          },
        },
      },
      plugins: [{
        id: "rate-limit-http-probe",
        onRequest: async () => { events.push({ phase: "http-request" }); },
        onResponse: async () => { events.push({ phase: "http-response" }); },
        hooks: {
          before: [{ matcher: () => true, handler: createAuthMiddleware(async () => { events.push({ phase: "before" }); }) }],
          after: [{ matcher: () => true, handler: createAuthMiddleware(async () => { events.push({ phase: "after" }); }) }],
        },
        endpoints: {
          rateHttp: createAuthEndpoint("/rate-http", { method: "GET" }, async ctx => {
            events.push({ phase: "endpoint" });
            return ctx.json({ accepted: true });
          }),
        },
      }],
    });
    const context = await auth.$context;
    for (const http of [false, true]) {
      events.length = 0;
      const request = new Request(`${baseURL}/api/auth/rate-http`, { headers: { "x-forwarded-for": "192.0.2.45" } });
      const result = http ? auth.handler(request) : onRequestRateLimit(request, context);
      if (outcome === "failed") {
        await expect(result).rejects.toBe(failure);
      } else {
        const response = await result;
        if (outcome === "allowed" && !http) {
          expect(response).toBeUndefined();
        } else {
          expect(response).toBeInstanceOf(Response);
          const allowed = outcome === "allowed";
          expect(response.status).toBe(allowed ? 200 : 429);
          if (!allowed) expect(response.statusText).toBe("Too Many Requests");
          expect([...response.headers]).toStrictEqual(allowed
            ? [["content-type", "application/json"]]
            : [["x-retry-after", String(outcome ?? 7.5)]]);
          const body = allowed ? '{"accepted":true}' : '{"message":"Too many requests. Please try again later."}';
          expect(new Uint8Array(await response.arrayBuffer())).toStrictEqual(new TextEncoder().encode(body));
        }
      }
      const expected: unknown[] = [{ phase: "consume", key: "192.0.2.45|/rate-http", window: 7.5, max: 3 }];
      if (http && outcome === "allowed") {
        expected.push(...["http-request", "before", "endpoint", "after", "http-response"].map(phase => ({ phase })));
      }
      expect(events).toStrictEqual(expected);
    }
  }
});
