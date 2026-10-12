import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withRestoredSchema } from "./schema-isolation.mjs";

for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}

const origin = "http://session-reference.test";
const secret = "x".repeat(64);
const requestIp = "203.0.113.9";
const createdAt = () => new Date(1_893_456_000_000);
const expiresAt = () => new Date(4_102_444_800_000);

for (const reference of [1, "001"]) {
  test(`API Key virtual Session retains reference ${JSON.stringify(reference)} before Serial User conversion`, async () => {
    await withRestoredSchema(apiKey().schema, async () => {
      const initialUser = {
        id: 1, name: "Owner", email: "owner@session-reference.test", emailVerified: true,
        image: null, createdAt: createdAt(), updatedAt: createdAt(),
      };
      const initialKey = {
        id: 1, name: "Machine", start: null, prefix: null, key: secret,
        referenceId: "1", configId: "default", refillInterval: null, refillAmount: null,
        lastRefillAt: null, enabled: true, rateLimitEnabled: false, rateLimitTimeWindow: 60000,
        rateLimitMax: 3, requestCount: 0, remaining: null, lastRequest: null,
        permissions: null, metadata: null, createdAt: createdAt(), updatedAt: createdAt(), expiresAt: expiresAt(),
      };
      const memory: Record<string, any[]> = {
        user: [structuredClone(initialUser)], apikey: [structuredClone(initialKey)],
        session: [], account: [], verification: [],
      };
      const events: unknown[] = [];
      const auth = betterAuth({
        database: memoryAdapter(memory), baseURL: origin,
        secret: "session-reference-secret-at-least-32-characters",
        advanced: { database: { generateId: "serial" } },
        logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
        user: { additionalFields: { name: {
          type: "string", required: false,
          transform: { output(value: unknown) { events.push(["name", value]); return "Projected owner"; } },
        } } },
        plugins: [apiKey({ enableSessionForAPIKeys: true, disableKeyHashing: true, deferUpdates: false }), {
          id: "api-key-session-reference",
          schema: { apikey: { fields: { referenceId: {
            type: "string", required: false,
            transform: { output(value: unknown) { events.push(["referenceId", value]); return reference; } },
          } } } },
        }],
      });
      for (const method of ["native", "GET", "POST"]) {
        events.length = 0;
        const start = Date.now();
        const headers = new Headers({ "x-api-key": secret, "x-forwarded-for": requestIp });
        const result = method === "native"
          ? await auth.api.getSession({ headers })
          : await auth.handler(new Request(`${origin}/api/auth/get-session`, { method, headers }));
        const end = Date.now();
        let actual: any = result;
        if (result instanceof Response) {
          expect(result.status).toBe(200);
          expect(result.headers.get("set-cookie")).toBeNull();
          actual = await result.json();
        }
        for (const value of [actual.session.createdAt, actual.session.updatedAt]) {
          if (method === "native") expect(value).toBeInstanceOf(Date);
          const time = new Date(value).getTime();
          expect(time).toBeGreaterThanOrEqual(start);
          expect(time).toBeLessThanOrEqual(end);
        }
        const expected = {
          user: { ...initialUser, id: "1", name: "Projected owner" },
          session: {
            id: "1", token: secret, userId: reference, userAgent: null, ipAddress: method === "native" ? null : requestIp,
            createdAt: actual.session.createdAt, updatedAt: actual.session.updatedAt, expiresAt: expiresAt(),
          },
        };
        expect(actual).toStrictEqual(method === "native" ? expected : JSON.parse(JSON.stringify(expected)));
        expect(events).toStrictEqual([
          ["referenceId", "1"], ["referenceId", "1"], ["referenceId", "1"], ["name", "Owner"],
        ]);
        expect(memory.user).toStrictEqual([initialUser]);
        expect(memory.apikey).toHaveLength(1);
        const stored = memory.apikey[0];
        for (const value of [stored.lastRequest, stored.updatedAt]) {
          expect(value).toBeInstanceOf(Date);
          expect(value.getTime()).toBeGreaterThanOrEqual(start);
          expect(value.getTime()).toBeLessThanOrEqual(end);
        }
        expect(memory).toStrictEqual({
          user: [initialUser], apikey: [{ ...initialKey, lastRequest: stored.lastRequest, updatedAt: stored.updatedAt }],
          session: [], account: [], verification: [],
        });
      }
    });
  });
}
