import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Database } from "bun:sqlite";
import { getAuthTables } from "@better-auth/core/db";
import { getMigrations } from "better-auth/db/migration";
import { admin, anonymous, lastLoginMethod, phoneNumber, twoFactor, username } from "better-auth/plugins";
import { captureFreshServerCatalog, observeServerIndexes } from "./server-catalog-shared.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";
import { writeObservation } from "./write-observation.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/user-plugin-catalog-config.json", import.meta.url), "utf8"));

function plugin(name, configuration) {
  const fields = configuration.user?.fields ?? {};
  const user = names => ({ fields: Object.fromEntries(names.filter(name => Object.hasOwn(fields, name)).map(name => [name, fields[name]])) });
  switch (name) {
    case "anonymous": return anonymous({ schema: { user: user(["isAnonymous"]) } });
    case "phone-number": return phoneNumber({ schema: { user: user(["phoneNumber", "phoneNumberVerified"]) } });
    case "username": return username({ schema: { user: user(["username", "displayUsername"]) } });
    case "last-login-method": return lastLoginMethod({ storeInDatabase: true, schema: { user: { lastLoginMethod: fields.lastLoginMethod } } });
    case "two-factor": return twoFactor({ schema: { user: user(["twoFactorEnabled"]) } });
    case "admin": return admin({ schema: {
      user: user(["role", "banned", "banReason", "banExpires"]),
      session: { fields: configuration.session?.fields ?? {} },
    } });
    default: assert.fail(`Unknown User plugin ${name}`);
  }
}

// Retain every enumerable declaration property, including callable defaults and transforms.
function declaration(value) {
  if (value === undefined) return { type: "undefined" };
  if (typeof value === "function") {
    return { type: "function", name: value.name, length: value.length, source: Function.prototype.toString.call(value) };
  }
  if (Array.isArray(value)) return value.map(declaration);
  if (value !== null && typeof value === "object") {
    return { keys: Object.keys(value), value: Object.fromEntries(Object.entries(value).map(([key, value]) => [key, declaration(value)])) };
  }
  return value;
}

async function captureSqlite(tableNames, configuration) {
  const database = new Database(":memory:");
  try {
    const options = { ...configuration, database };
    const initial = await getMigrations(options);
    const initialSql = await initial.compileMigrations();
    await initial.runMigrations();
    const catalog = {};
    const ddl = {};
    for (const [model, table] of Object.entries(tableNames)) {
      const observed = observeSqliteCatalog(database, table, `The generated ${model} table must exist`);
      catalog[model] = observed.catalog;
      ddl[model] = observed.ddl;
    }
    const repeated = await getMigrations(options);
    assert.equal(repeated.toBeCreated.length, 0);
    assert.equal(repeated.toBeAdded.length, 0);
    assert.equal(repeated.toBeAddedIndexes.length, 0);
    assert.equal(repeated.schemaProblems.length, 0);
    return { catalog, ddl, migration: { initialSql, repeatedSql: await repeated.compileMigrations() } };
  } finally {
    database.close();
  }
}

async function captureCase(backend, name) {
  const { plugins, configuration } = configurations[name];
  const options = {
    baseURL: "http://user-plugin-catalog.test",
    secret: "ordinary-user-plugin-catalog-secret-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    ...configuration,
    plugins: plugins.map(name => plugin(name, configuration)),
  };
  const schema = getAuthTables(options);
  const declarations = Object.fromEntries(["user", "session"].map(model => [model, declaration(schema[model])]));
  const tableNames = Object.fromEntries(["user", "session"].map(model => [model, schema[model].modelName]));
  const observed = backend === "sqlite"
    ? await captureSqlite(tableNames, options)
    : await captureFreshServerCatalog(backend, Object.values(tableNames), options, async context => {
      const observations = {};
      for (const [model, table] of Object.entries(tableNames)) observations[model] = await observeServerIndexes(context, table);
      return observations;
    });
  return { name, plugins, configuration, declarations, ...observed };
}

async function captureCatalog(backend) {
  const directory = await mkdtemp(join(tmpdir(), "better-auth-user-plugin-catalog-"));
  try {
    const cases = [];
    for (const name of Object.keys(configurations)) {
      const output = join(directory, `${name}.json`);
      // Upstream plugin mappings mutate shared declarations, so isolate each configuration.
      const child = Bun.spawn([process.execPath, "--no-install", fileURLToPath(import.meta.url), backend, output, name], {
        stdout: "inherit", stderr: "inherit",
      });
      assert.equal(await child.exited, 0, `${backend}/${name} catalog capture must succeed`);
      cases.push(JSON.parse(await readFile(output, "utf8")));
    }
    return { version, database: backend, cases };
  } finally {
    await rm(directory, { recursive: true });
  }
}

const [backend, output, name] = process.argv.slice(2);
assert.ok(["sqlite", "postgres", "mysql"].includes(backend), "Select sqlite, postgres or mysql");
assert.ok(output, "Pass the fixture output path as the second argument");
const observation = name === undefined ? await captureCatalog(backend) : await captureCase(backend, name);
writeFileSync(output, `${JSON.stringify(observation, null, 2)}\n`);
if (name === undefined) await writeObservation(`${JSON.stringify(observation)}\n`);
