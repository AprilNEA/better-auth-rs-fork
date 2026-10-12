import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import {
  apiKeyCleanupConfiguration, apiKeyCleanupCurrent, apiKeyCleanupScenarios,
} from "./api-key-cleanup-fields-capture.mjs";
import { observeValue } from "./device-where-capture.mjs";
import { nativeInput } from "./native-plugin-replacements-capture.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";

const models = ["user", "session", "account", "verification", "apikey"];

function observeError(error) {
  if (error instanceof assert.AssertionError) throw error;
  assert.ok(error instanceof Error);
  const observer = createProtectedFunctionObserver();
  const identities = new WeakMap();
  let nextIdentity = 0;
  const observe = value => {
    if (value === null || typeof value !== "object" && typeof value !== "function") return observer.observe(value);
    if (identities.has(value)) return { reference: identities.get(value) };
    const identity = `object-${++nextIdentity}`;
    identities.set(value, identity);
    const ownKeys = Reflect.ownKeys(value);
    const properties = ownKeys.map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      const flags = { enumerable: descriptor.enumerable, configurable: descriptor.configurable };
      return [observer.observe(key), "value" in descriptor
        ? { ...flags, writable: descriptor.writable, value: observe(descriptor.value) }
        : { ...flags, get: observe(descriptor.get), set: observe(descriptor.set) }];
    });
    return {
      identity,
      type: value instanceof Error ? "error" : Array.isArray(value) ? "array" : value instanceof Date ? "date" : typeof value,
      ownKeys: ownKeys.map(key => observer.observe(key)), properties,
      ...(value instanceof Date || typeof value === "function" ? { value: observer.observe(value) } : {}),
      ...(value instanceof Error ? { error: {
        name: observe(value.name), message: observe(value.message),
        stack: observe(value.stack), cause: observe(value.cause),
      } } : {}),
    };
  };
  const raw = observe(error);
  // Raw descriptors retain host-specific stack paths and driver metadata for separate comparison.
  return {
    name: observer.observe(error.name), message: observer.observe(error.message),
    raw: { root: raw, functions: observer.functions },
  };
}

async function captureRows({ options, query, backend }, scenario, events) {
  const { adapter } = await betterAuth(options).$context;
  const quote = name => backend === "mysql" ? `\`${name}\`` : `"${name}"`;
  const stored = async () => Object.fromEntries(await Promise.all(models.map(async model => [
    model, observeValue(await query(`SELECT * FROM ${quote(model)} ORDER BY ${quote("id")}`, [])),
  ])));
  const observe = async (input, operation) => {
    const before = await stored();
    let outcome;
    try {
      outcome = { returned: true, result: observeValue(await operation()) };
    } catch (error) {
      outcome = { returned: false, error: observeError(error) };
    }
    return {
      input: observeValue(input), before, ...outcome,
      events: events.splice(0), after: await stored(),
    };
  };
  const setup = [];
  for (const [index, expiresAt] of [
    new Date("2030-01-02T03:04:05.000Z"), new Date("2032-01-02T03:04:05.000Z"), null,
  ].entries()) {
    const input = { model: "apikey", forceAllowId: true, data: {
      ...nativeInput("apikey"), id: String(index + 1), expiresAt,
    } };
    setup.push(await observe(input, () => adapter.create(input)));
  }
  const steps = [];
  for (const attempt of [1, 2]) {
    const input = { model: "apikey", where: [
      { field: "expiresAt", operator: "lt", value: apiKeyCleanupCurrent },
      { field: "expiresAt", operator: "ne", value: null },
    ] };
    steps.push({ attempt, method: "deleteMany", ...await observe(input, () => adapter.deleteMany(input)) });
  }
  assert.deepEqual(steps.map(step => step.events), [[], []]);
  return { scenario, setup, steps };
}

async function captureCase(backend, scenario) {
  const events = [];
  const configuration = apiKeyCleanupConfiguration(scenario, events);
  if (backend === "sqlite") {
    const database = new Database(":memory:");
    try {
      const options = { ...configuration, database };
      await (await getMigrations(options)).runMigrations();
      const catalog = observeSqliteCatalog(database, "apikey", "The cleanup table must exist");
      const captured = await captureRows({
        options, backend, query: async (sql, values) => database.query(sql).all(...values),
      }, scenario, events);
      return { ...captured, catalog };
    } finally {
      database.close();
    }
  }
  const captured = await captureFreshServerCatalog(backend, ["apikey"], configuration,
    context => captureRows(context, scenario, events));
  return {
    ...captured.observation,
    catalog: { columns: captured.columns, migration: captured.migration },
  };
}

export async function captureApiKeyCleanupSqlFields(backend) {
  assert.ok(["sqlite", "postgres", "mysql"].includes(backend));
  const cases = [];
  for (const scenario of apiKeyCleanupScenarios) cases.push(await captureCase(backend, scenario));
  return { version: "1.7.6", backend, current: observeValue(apiKeyCleanupCurrent), cases };
}

if (import.meta.main) {
  const [backend, output] = process.argv.slice(2);
  assert.ok(output, "Pass a backend and fixture output path");
  writeFileSync(output, `${JSON.stringify(await captureApiKeyCleanupSqlFields(backend), null, 2)}\n`);
}
