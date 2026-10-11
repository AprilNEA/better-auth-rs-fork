import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";

const { onRequestRateLimit } = await import(new URL("../node_modules/better-auth/dist/api/rate-limiter/index.mjs", import.meta.url).href);
const { initGetDefaultModelName } = await import(new URL("../node_modules/@better-auth/core/dist/db/adapter/get-default-model-name.mjs", import.meta.url).href);
const baseURL = "http://rate-limit-declaration.test";
const secret = "rate-limit-declaration-secret-at-least-thirty-two-characters";
type Row = Record<string, unknown>;
expect((await Bun.file(new URL("../node_modules/better-auth/package.json", import.meta.url)).json()).version).toBe("1.7.6");

function plugins(events: string[], callbacks: string[], shared = true) {
  const fail = (phase: string) => () => {
    callbacks.push(phase);
    throw new Error(`Discarded RateLimit ${phase} ran`);
  };
  const fields = Object.fromEntries(["id", "count", "key", "label"].map(name => [name, {
    type: "string" as const, fieldName: `plugin_${name}`, required: false, returned: false, unique: false,
    defaultValue: fail("default"), onUpdate: fail("update"),
    transform: { input: fail("input"), output: fail("output") },
  }]));
  return [{
    id: "rate-limit-first", init() { events.push("first"); }, schema: {
      before: { modelName: shared ? "shared" : "before", fields: {} },
      rateLimit: { modelName: "first_counter", fields },
    },
  }, {
    id: "rate-limit-last", init() { events.push("last"); }, schema: {
      after: { modelName: shared ? "shared" : "after", fields: {} },
      rateLimit: { modelName: "plugin_counter", fields: {} },
    },
  }];
}

test("database RateLimit replaces the complete plugin declaration at its original position", async () => {
  for (const storage of ["database", "memory"] as const) for (const custom of [false, true]) {
    const events: string[] = [];
    const callbacks: string[] = [];
    const configured = custom ? { modelName: "configured_counter", fields: { key: "bucket", count: "hits", lastRequest: "touched" } } : {};
    const options: BetterAuthOptions = {
      baseURL, secret, logger: { disabled: true }, telemetry: { enabled: false }, plugins: plugins(events, callbacks),
      rateLimit: { storage, enabled: false, customStorage: { async get() { return null; }, async set() {} }, ...configured },
    };
    const schema = getAuthTables(options);
    expect(Object.keys(schema).slice(-3)).toStrictEqual(["before", "rateLimit", "after"]);
    const resolve = initGetDefaultModelName({ usePlural: false, schema });
    expect(resolve("shared")).toBe("before");
    if (storage === "memory") {
      expect(schema.rateLimit).toStrictEqual({
        fields: options.plugins![0]!.schema!.rateLimit!.fields,
        indexes: [], modelName: "plugin_counter", disableMigrations: undefined,
      });
      expect(Object.keys(schema.rateLimit!.fields)).toStrictEqual(["id", "count", "key", "label"]);
      expect(resolve("plugin_counter")).toBe("rateLimit");
    } else {
      const fieldName = (name: "key" | "count" | "lastRequest") => configured.fields?.[name] ?? name;
      expect(schema.rateLimit).toStrictEqual({ modelName: configured.modelName ?? "rateLimit", fields: {
        key: { type: "string", unique: true, required: true, fieldName: fieldName("key") },
        count: { type: "number", required: true, fieldName: fieldName("count") },
        lastRequest: { type: "number", bigint: true, required: true, fieldName: fieldName("lastRequest"), defaultValue: expect.any(Function) },
      } });
      expect(Object.keys(schema.rateLimit!.fields)).toStrictEqual(["key", "count", "lastRequest"]);
      expect(resolve(configured.modelName ?? "rateLimit")).toBe("rateLimit");
      expect(() => resolve("plugin_counter")).toThrow('Model "plugin_counter" not found in schema');
    }
    await betterAuth(options).$context;
    expect(events).toStrictEqual(["first", "last"]);
    expect(callbacks).toStrictEqual([]);
  }
});

for (const backend of ["memory", "sqlite"] as const) for (const custom of backend === "sqlite" ? [false, true] : [false]) {
  test(`${backend} ${custom ? "mapped" : "native"} RateLimit ignores replaced callbacks during atomic counter consumption`, async () => {
    const memory: Record<string, Row[]> = { user: [], session: [], account: [], verification: [], shared: [], rateLimit: [] };
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const events: string[] = [];
    const callbacks: string[] = [];
    const ids: string[] = [];
    const configured = custom ? { modelName: "configured_counter", fields: { key: "bucket", count: "hits", lastRequest: "touched" } } : {};
    const options: BetterAuthOptions = {
      database: database ?? memoryAdapter(memory), baseURL, secret,
      logger: { disabled: true }, telemetry: { enabled: false }, plugins: plugins(events, callbacks, false),
      advanced: { database: { generateId({ model }) { ids.push(model); return "counter"; } } },
      rateLimit: { enabled: true, storage: "database", window: 600, max: 2, ...configured },
    };
    const table = configured.modelName ?? "rateLimit";
    const field = (name: "key" | "count" | "lastRequest") => configured.fields?.[name] ?? name;
    const snapshot = () => structuredClone(database ? database.query(`SELECT * FROM "${table}"`).all() : memory[table]) as Row[];
    const request = () => new Request(`${baseURL}/api/auth/ordinary-counter`, { headers: { "x-forwarded-for": "192.0.2.17" } });
    const key = "192.0.2.17|/ordinary-counter";
    try {
      if (database) await (await getMigrations(options)).runMigrations();
      const context = await betterAuth(options).$context;
      expect(events).toStrictEqual(["first", "last"]);
      for (const count of [1, 2]) {
        const start = Date.now();
        expect(await onRequestRateLimit(request(), context)).toBeUndefined();
        const finish = Date.now();
        const rows = snapshot();
        expect(rows).toHaveLength(1);
        const last = rows[0]![field("lastRequest")];
        expect(typeof last).toBe("number");
        expect(last).toBeGreaterThanOrEqual(start);
        expect(last).toBeLessThanOrEqual(finish);
        expect(rows).toStrictEqual([{ id: "counter", [field("key")]: key, [field("count")]: count, [field("lastRequest")]: last }]);
      }
      const before = snapshot();
      const denied = await onRequestRateLimit(request(), context);
      expect(denied?.status).toBe(429);
      expect(await denied?.json()).toStrictEqual({ message: "Too many requests. Please try again later." });
      expect(Number(denied?.headers.get("x-retry-after"))).toBeGreaterThan(0);
      expect(Number(denied?.headers.get("x-retry-after"))).toBeLessThanOrEqual(600);
      expect(snapshot()).toStrictEqual(before);
      context.rateLimit.customRules = { "/ordinary-counter": { window: 0, max: 2 } };
      const start = Date.now();
      expect(await onRequestRateLimit(request(), context)).toBeUndefined();
      const finish = Date.now();
      const last = snapshot()[0]![field("lastRequest")];
      expect(last).toBeGreaterThanOrEqual(start);
      expect(last).toBeLessThanOrEqual(finish);
      expect(snapshot()).toStrictEqual([{ id: "counter", [field("key")]: key, [field("count")]: 1, [field("lastRequest")]: last }]);
      expect(ids).toStrictEqual(["rateLimit"]);
      expect(callbacks).toStrictEqual([]);
    } finally { database?.close(); }
  });
}
