import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getAuthTables } from "@better-auth/core/db";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog.ts";
import { writeObservation } from "./write-observation.mjs";

const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}
const date = "2030-01-02T03:04:05.000Z";
const shared = "shared_value";
const targets = [
  ["user", "name", "image"],
  ["session", "ipAddress", "userAgent"],
  ["account", "accountId", "providerId"],
  ["verification", "identifier", "value"],
  ["organization", "name", "slug"],
  ["member", "role", "userId"],
  ["invitation", "status", "role"],
  ["team", "name", "organizationId"],
  ["teamMember", "teamId", "userId"],
  ["organizationRole", "role", "organizationId"],
];
const modes = ["native-native-string", "native-native-number", "native-additional"];
const coreModels = ["user", "session", "account", "verification"];

function input(model) {
  const createdAt = new Date(date);
  const updatedAt = new Date(date);
  return {
    user: { name: "Owner", image: null, email: "shared@columns.test", emailVerified: false, createdAt, updatedAt },
    session: { token: "shared-token", userId: "owner", expiresAt: new Date("2035-01-02T00:00:00.000Z"), createdAt, updatedAt, ipAddress: null, userAgent: null },
    account: { accountId: "account", providerId: "provider", userId: "owner", accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null, refreshTokenExpiresAt: null, scope: null, password: null, createdAt, updatedAt },
    verification: { identifier: "identifier", value: "verification", expiresAt: new Date("2035-01-02T00:00:00.000Z"), createdAt, updatedAt },
    organization: { name: "Workspace", slug: "workspace", logo: null, createdAt, metadata: null },
    member: { organizationId: "workspace", userId: "owner", role: "member", createdAt },
    invitation: { organizationId: "workspace", email: "invitee@columns.test", role: "member", status: "pending", expiresAt: new Date("2035-01-02T00:00:00.000Z"), inviterId: "owner", teamId: null, createdAt },
    team: { name: "Team", organizationId: "workspace", memberCount: 0, createdAt, updatedAt: null },
    teamMember: { teamId: "team", userId: "owner", createdAt },
    organizationRole: { organizationId: "workspace", role: "reader", permission: "{}", createdAt, updatedAt: null },
  }[model];
}

async function capture(backend, [model, first, nativeSecond], mode) {
  const second = mode === "native-additional" ? "shadow" : nativeSecond;
  const state = { events: [], discard: false, reject: false };
  const callbackError = new Error("shared column output rejected");
  const configuration = { [model]: { additionalFields: {
    [first]: { type: "string", required: false, fieldName: shared },
    [second]: { type: mode === "native-native-number" ? "number" : "string", required: false, fieldName: shared },
  } } };
  const additionalFields = Object.fromEntries(Object.entries(configuration[model].additionalFields).map(([name, declaration]) => [name, {
    ...declaration,
    transform: {
      input(value) {
        state.events.push({ phase: "input", field: name, value: observeValue(value) });
        return state.discard && name === second ? undefined : value;
      },
      output(value) {
        state.events.push({ phase: "output", field: name, value: observeValue(value) });
        if (state.reject && name === second) throw callbackError;
        return value;
      },
    },
  }]));
  const organizationOptions = { teams: { enabled: true }, dynamicAccessControl: { enabled: true } };
  if (!coreModels.includes(model) && model !== "teamMember") {
    organizationOptions.schema = { [model]: { additionalFields } };
  }
  const options = {
    baseURL: "http://shared-columns.test",
    secret: "shared-columns-contract-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, logger: { disabled: true },
    ...(coreModels.includes(model) ? { [model]: { additionalFields } } : {}),
    plugins: [organization(organizationOptions), ...(model === "teamMember" ? [{ id: "team-member-columns", schema: { teamMember: { fields: additionalFields } } }] : [])],
  };
  const schema = getAuthTables(options)[model];
  const memory = {};
  const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
  const database = sqlite ?? memoryAdapter(memory);
  try {
    if (sqlite) await (await getMigrations({ ...options, database })).runMigrations();
    const catalog = sqlite ? observeSqliteCatalog(sqlite, schema.modelName, "The shared column table must exist") : null;
    const adapter = (await betterAuth({ ...options, database }).$context).adapter;
    for (const [parent, id] of [["user", "owner"], ["organization", "workspace"], ["team", "team"]]) {
      if (parent === model) continue;
      if (parent !== "user" && coreModels.includes(model)) continue;
      if (parent === "team" && model !== "teamMember") continue;
      await adapter.create({ model: parent, forceAllowId: true, data: { id, ...input(parent) } });
    }
    assert.deepEqual(state.events, []);
    const stored = () => (sqlite
      ? sqlite.query(`SELECT * FROM "${schema.modelName}" ORDER BY "id"`).all()
      : memory[schema.modelName] ?? []).map(row => ({ keys: Object.keys(row), value: observeValue(row) }));
    const where = [{ field: "id", value: "shared-row" }];
    const observe = async (name, method, fields = {}) => {
      const parameters = method === "create"
        ? { model, forceAllowId: true, data: { id: "shared-row", ...input(model), ...fields } }
        : method === "update" ? { model, where, update: {
          ...(Object.hasOwn(schema.fields, "updatedAt") ? { updatedAt: new Date(date) } : {}), ...fields,
        } } : { model, where };
      let outcome;
      try {
        const value = await adapter[method](parameters);
        outcome = { returned: true, keys: value == null ? [] : Object.keys(value), value: observeValue(value) };
      } catch (error) {
        assert.ok(error instanceof Error);
        outcome = { returned: false, error: { name: error.name, message: error.message, sameCallbackError: error === callbackError, properties: observeValue(Object.fromEntries(Object.entries(error))) } };
      }
      return { name, method, input: observeValue(parameters), ...outcome, events: state.events.splice(0), stored: stored() };
    };
    const last = mode === "native-native-number" ? 27 : "last-writer";
    const operations = [
      await observe("create", "create", { [first]: "first-writer", [second]: last }),
      await observe("read-created", "findOne"),
      await observe("update-first", "update", { [first]: "accepted" }),
    ];
    state.discard = true;
    operations.push(await observe("update-undefined", "update", { [first]: "retained", [second]: last }));
    state.discard = false;
    state.reject = true;
    operations.push(await observe("update-output-error", "update", { [first]: "committed" }));
    state.reject = false;
    operations.push(await observe("read-after-error", "findOne"));
    operations.push(await observe("delete", "delete"));
    operations.push(await observe("read-deleted", "findOne"));
    return { model, first, second, mode, configuration, fields: Object.keys(schema.fields), catalog, operations };
  } finally {
    sqlite?.close();
  }
}

const [backend, output] = process.argv.slice(2);
assert.ok(["memory", "sqlite"].includes(backend));
assert.ok(output, "Pass a backend and output path");
const cases = [];
for (const target of targets) {
  for (const mode of modes) cases.push(await capture(backend, target, mode));
}
const observation = { version, backend, cases };
writeFileSync(output, `${JSON.stringify(observation, null, 2)}\n`);
await writeObservation(`${JSON.stringify(observation)}\n`);
