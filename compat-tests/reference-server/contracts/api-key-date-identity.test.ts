import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { withClock } from "./email-verification-duration-capture.mjs";
import { withRestoredSchema } from "./schema-isolation.mjs";

for (const name of ["better-auth", "@better-auth/core", "@better-auth/api-key"]) {
  expect(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version).toBe("1.7.6");
}

const epoch = 2_000_000_000_123;
const iso = new Date(epoch).toISOString();
const secret = "x".repeat(64);
const tables = ["user", "session", "account", "verification", "apikey"];
type Probe = { field: string; phase: string; value: unknown; ownMarker: boolean; constructed: boolean };

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of ["database", "secondary", "fallback"] as const) {
    test(`${backend}/${mode}: API Key creation retains separate native Date objects through field policies`, async () => {
      await withRestoredSchema(apiKey().schema, () => withClock(async setClock => {
        setClock(epoch);
        const database = backend === "sqlite" ? new Database(":memory:") : undefined;
        const memory: Record<string, any[]> = Object.fromEntries(tables.map(table => [table, []]));
        const cache = new Map<string, string>();
        const constructed: Date[] = [];
        const probes: Probe[] = [];
        const declaration = (field: "createdAt" | "updatedAt") => ({
          type: "date" as const, required: true,
          transform: {
            input(value: Date) {
              probes.push({ field, phase: "input", value, ownMarker: Object.hasOwn(value, "createdOnly"), constructed: constructed.includes(value) });
              if (field === "createdAt") Object.defineProperty(value, "createdOnly", { value: "marker", enumerable: true, configurable: true });
              return value;
            },
            output(value: unknown) {
              probes.push({ field, phase: "output", value, ownMarker: Object.hasOwn(value as object, "createdOnly"), constructed: constructed.includes(value as Date) });
              return value;
            },
          },
        });
        const options = {
          database: database ?? memoryAdapter(memory), baseURL: "http://date-identity.test",
          secret: "date-identity-contract-secret-at-least-32-characters",
          advanced: { database: { generateId: () => "date-key" } },
          logger: { disabled: true }, telemetry: { enabled: false }, rateLimit: { enabled: false },
          plugins: [apiKey({
            storage: mode === "database" ? "database" : "secondary-storage", fallbackToDatabase: mode === "fallback",
            customKeyGenerator: async () => secret, disableKeyHashing: true, deferUpdates: false,
            customStorage: {
              get: async (key: string) => cache.get(key) ?? null,
              set: async (key: string, value: string) => { cache.set(key, value); },
              delete: async (key: string) => { cache.delete(key); },
            },
          }), {
            id: "api-key-date-identity",
            schema: { apikey: { fields: { createdAt: declaration("createdAt"), updatedAt: declaration("updatedAt") } } },
          }],
        };
        try {
          if (database) await (await getMigrations(options)).runMigrations();
          const auth = betterAuth(options);
          await auth.$context;
          const FrozenDate = globalThis.Date;
          globalThis.Date = new Proxy(FrozenDate, {
            construct(target, args, newTarget) {
              const value = Reflect.construct(target, args, newTarget);
              if (args.length === 0) constructed.push(value);
              return value;
            },
          });
          let created: any;
          try {
            created = await auth.api.createApiKey({ body: {
              userId: "owner", name: "Date key", rateLimitEnabled: false, rateLimitTimeWindow: 60000, rateLimitMax: 3,
            } });
          } finally { globalThis.Date = FrozenDate; }

          const keepsNativeInput = backend === "memory" && mode !== "secondary";
          const expectedCreatedAt = new Date(epoch);
          if (keepsNativeInput) Object.defineProperty(expectedCreatedAt, "createdOnly", { value: "marker", enumerable: true, configurable: true });
          const expected = {
            id: "date-key", key: secret, configId: "default", name: "Date key", prefix: null, start: "xxxxxx",
            enabled: true, expiresAt: null, referenceId: "owner", lastRefillAt: null, lastRequest: null,
            metadata: null, rateLimitMax: 3, rateLimitTimeWindow: 60000, remaining: null,
            refillAmount: null, refillInterval: null, rateLimitEnabled: false, requestCount: 0,
            createdAt: expectedCreatedAt, updatedAt: new Date(epoch), permissions: null,
          };
          expect(created).toStrictEqual(expected);
          expect(JSON.parse(JSON.stringify(created))).toStrictEqual({ ...expected, createdAt: iso, updatedAt: iso });
          for (const field of ["createdAt", "updatedAt"] as const) {
            expect(created[field]).toBeInstanceOf(Date);
            expect(created[field].getTime()).toBe(epoch);
            expect(Object.getOwnPropertyDescriptors(created[field])).toStrictEqual(Object.getOwnPropertyDescriptors(expected[field]));
          }
          expect(created.createdAt).not.toBe(created.updatedAt);
          if (mode === "secondary") {
            expect(probes).toStrictEqual([]);
            expect(constructed).toContain(created.createdAt);
            expect(constructed).toContain(created.updatedAt);
          } else {
            expect(probes.map(({ value, ...probe }) => ({ ...probe, value: value instanceof Date ? value.getTime() : value }))).toStrictEqual([
              { field: "createdAt", phase: "input", value: epoch, ownMarker: false, constructed: true },
              { field: "updatedAt", phase: "input", value: epoch, ownMarker: false, constructed: true },
              { field: "createdAt", phase: "output", value: backend === "memory" ? epoch : iso, ownMarker: keepsNativeInput, constructed: keepsNativeInput },
              { field: "updatedAt", phase: "output", value: backend === "memory" ? epoch : iso, ownMarker: false, constructed: keepsNativeInput },
            ]);
            expect(probes[0].value).toBeInstanceOf(Date);
            expect(probes[1].value).toBeInstanceOf(Date);
            expect(probes[0].value).not.toBe(probes[1].value);
            for (const [index, field] of ["createdAt", "updatedAt"].entries()) {
              if (backend === "memory") {
                expect(created[field]).toBe(probes[index].value);
                expect(probes[index + 2].value).toBe(probes[index].value);
              } else {
                expect(created[field]).not.toBe(probes[index].value);
                expect(constructed).not.toContain(created[field]);
              }
            }
          }

          const stored: Record<string, unknown> = { ...expected, metadata: "null" };
          if (backend === "memory") delete stored.permissions;
          else Object.assign(stored, { enabled: 1, rateLimitEnabled: 0, createdAt: iso, updatedAt: iso });
          const expectedTables = Object.fromEntries(tables.map(table => [table, table === "apikey" && mode !== "secondary" ? [stored] : []]));
          const actualTables = database
            ? Object.fromEntries(tables.map(table => [table, database.query(`SELECT * FROM "${table}"`).all()]))
            : memory;
          expect(actualTables).toStrictEqual(expectedTables);
          if (keepsNativeInput) {
            expect(memory.apikey[0].createdAt).toBe(probes[0].value);
            expect(memory.apikey[0].updatedAt).toBe(probes[1].value);
          }

          const cached: Record<string, unknown> = { ...expected, createdAt: iso, updatedAt: iso };
          if (mode === "secondary" || backend === "memory") delete cached.permissions;
          const expectedCache = mode === "database" ? new Map() : new Map([
            [`api-key:${secret}`, cached], ["api-key:by-id:date-key", cached],
            ...(mode === "secondary" ? [["api-key:by-ref:owner", ["date-key"]] as const] : []),
          ]);
          expect(new Map([...cache].map(([key, value]) => [key, JSON.parse(value)]))).toStrictEqual(expectedCache);
        } finally { database?.close(); }
      }));
    });
  }
}
