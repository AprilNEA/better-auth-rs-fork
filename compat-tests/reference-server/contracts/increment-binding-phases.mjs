import assert from "node:assert/strict";
import { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { twoFactor } from "better-auth/plugins";
import { Kysely, MysqlDialect } from "kysely";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const createdAt = new Date("2030-01-01T00:00:00.000Z");
const at = new Date("2031-01-01T00:00:00.000Z");

function configuration(model, transform) {
  const field = model === "apikey" ? "remaining" : "backupCodes";
  return {
    baseURL: "http://increment-binding-phases.test",
    secret: "increment-binding-phases-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { generateId: false } },
    plugins: [model === "apikey" ? apiKey() : twoFactor(), {
      id: "increment-binding-phases", schema: { [model]: { fields: {
        [field]: { type: model === "apikey" ? "number" : "string", ...(transform ? { transform } : {}) },
      } } },
    }],
  };
}

async function seed(options, model) {
  const { adapter } = await betterAuth(options).$context;
  for (const id of ["target", "retained"]) {
    const data = model === "apikey" ? {
      id, key: `${id}-key`, referenceId: `${id}-owner`, configId: "default",
      enabled: true, rateLimitEnabled: false, remaining: 6, lastRefillAt: null,
      createdAt, updatedAt: createdAt,
    } : {
      id, secret: `${id}-secret`, userId: `${id}-owner`, backupCodes: "backup-before",
      verified: true, failedVerificationCount: 0, lockedUntil: null,
    };
    if (model === "twoFactor") {
      await adapter.create({ model: "user", forceAllowId: true, data: {
        id: data.userId, name: id, email: `${id}@increment-binding-phases.test`,
        emailVerified: true, createdAt, updatedAt: createdAt,
      } });
    }
    await adapter.create({ model, forceAllowId: true, data });
  }
}

async function check(backend, model, options, raw) {
  await seed(options, model);
  const before = await raw();
  assert.equal(before.length, 2);
  const events = [];
  const statements = [];
  const database = backend === "mysql" ? {
    type: "mysql",
    db: new Kysely({
      dialect: new MysqlDialect({ pool: options.database.pool }),
      log(event) {
        const sql = event.query.sql.toLowerCase();
        statements.push(sql);
        events.push(["begin", "commit", "rollback"].includes(sql) ? sql
          : sql.endsWith(" for update") ? "lock" : "unexpected-sql");
      },
    }),
  } : options.database;
  // The existing server harness owns the MySQL pool and closes the pool after this check.
  for (const scenario of ["where-parse", "where-driver", "missing", "stale", "matched"]) {
    if (backend === "mysql" && scenario === "where-driver") continue;
    const label = `${backend}/${model}/${scenario}`;
    const setError = new Error("increment-set-error");
    const whereError = new Error("increment-where-error");
    const set = () => { events.push("set"); throw setError; };
    const selector = scenario === "where-parse" ? () => { events.push("where"); throw whereError; }
      : scenario === "where-driver" ? { "driver-invalid": true }
      : scenario === "missing" ? "missing" : "target";
    const context = await betterAuth({ database, ...configuration(model, {
      input() { events.push("set-input"); return set; },
      output(value) { events.push("set-output"); return value; },
    }) }).$context;
    await context.checkSchema?.();
    const { adapter } = context;
    events.length = 0;
    statements.length = 0;
    const where = [{ field: "id", value: selector }, model === "apikey"
      ? { field: "lastRefillAt", value: scenario === "stale" ? at : null }
      : { field: "backupCodes", value: scenario === "stale" ? "stale" : "backup-before" }];
    let result;
    let caught;
    try {
      result = await adapter.incrementOne({ model, where, increment: {}, set: model === "apikey"
        ? { remaining: 7, lastRefillAt: at } : { backupCodes: "backup-after" } });
    } catch (error) { caught = error; }
    const expected = ["set-input"];
    if (backend === "mysql") {
      expected.push("begin");
      if (scenario !== "where-parse") expected.push("lock");
    }
    if (backend === "mysql" && ["missing", "stale"].includes(scenario)) {
      assert.equal(caught, undefined, label);
      assert.equal(result, null, label);
      expected.push("commit");
    } else {
      const phase = scenario === "where-parse" ? "where" : "set";
      assert.equal(caught, phase === "where" ? whereError : setError, label);
      assert.equal(result, undefined, label);
      expected.push(phase);
      if (backend === "mysql") expected.push("rollback");
    }
    assert.deepEqual(events, expected, JSON.stringify({ label, statements }));
    assert.deepEqual(await raw(), before, label);
  }
}

export async function checkIncrementBindingPhases(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend));
  for (const model of ["apikey", "twoFactor"]) {
    const options = configuration(model);
    if (backend === "sqlite") {
      const database = new Database(":memory:");
      try {
        const configured = { ...options, database };
        await (await getMigrations(configured)).runMigrations();
        await check(backend, model, configured, async () =>
          structuredClone(database.query(`SELECT * FROM "${model}" ORDER BY id`).all()));
      } finally { database.close(); }
    } else {
      await captureFreshServerCatalog(backend, [model], options, async ({ options, query }) => {
        const table = backend === "postgres" ? `"${model}"` : `\`${model}\``;
        await check(backend, model, options, async () =>
          structuredClone(await query(`SELECT * FROM ${table} ORDER BY id`)));
      });
    }
  }
}
