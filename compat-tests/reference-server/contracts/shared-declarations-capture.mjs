import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { getAuthTables } from "@better-auth/core/db";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";
import { writeObservation } from "./write-observation.mjs";

const configuration = JSON.parse(readFileSync(new URL("../../schema-consumer/shared-declarations-schema.json", import.meta.url), "utf8"));
const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

export async function captureSharedDeclarations(organizationSource = "declarations") {
  assert.ok(organizationSource === "declarations" || organizationSource === "options");
  const database = new Database(":memory:");
  try {
    const coreModels = ["user", "session", "account", "verification"];
    const organizationModels = ["organization", "member", "invitation", "team", "organizationRole"];
    const organizationOptions = { teams: { enabled: true }, dynamicAccessControl: { enabled: true } };
    if (organizationSource === "options") {
      organizationOptions.schema = Object.fromEntries(organizationModels.map(name => [name, structuredClone(configuration[name])]));
    }
    const pluginDeclarations = Object.fromEntries(Object.entries(configuration)
      .filter(([name]) => !coreModels.includes(name)
        && !(organizationSource === "options" && organizationModels.includes(name)))
      .map(([name, model]) => [name, { fields: model.additionalFields }]));
    const options = {
      baseURL: "http://shared-declarations.test",
      secret: "shared-declaration-contract-secret-at-least-32-characters",
      database,
      telemetry: { enabled: false },
      ...Object.fromEntries(coreModels.map(name => [name, configuration[name]])),
      rateLimit: { storage: "database", fields: configuration.rateLimit.fields },
      plugins: [organization(organizationOptions), {
        id: "shared-declaration-replacements",
        schema: pluginDeclarations,
      }],
    };
    const schema = getAuthTables(options);
    await (await getMigrations(options)).runMigrations();
    const models = [];
    for (const name of Object.keys(configuration)) {
      const { catalog, ddl } = observeSqliteCatalog(database, schema[name].modelName, `The declared ${name} table must exist`);
      models.push({ model: name, fields: Object.keys(schema[name].fields), ...catalog, ddl });
    }
    assert.ok(!Object.hasOwn(schema.rateLimit.fields, "discardedField"));
    assert.equal(schema.rateLimit.fields.lastRequest.type, "number");
    assert.equal(schema.rateLimit.fields.lastRequest.fieldName, "stored_last_request");
    const observation = { version, database: "sqlite", configuration, models };
    if (organizationSource === "options") {
      observation.configurationBoundary = {
        core: "BetterAuthOptions.additionalFields",
        organization: "organization(options.schema).additionalFields",
        teamMember: "late plugin.schema fields; organization options have no additionalFields expansion",
        rateLimit: "database rateLimit options replace the late plugin.schema fields",
      };
    }
    return observation;
  } finally {
    database.close();
  }
}

if (import.meta.main) {
  const observation = await captureSharedDeclarations();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
