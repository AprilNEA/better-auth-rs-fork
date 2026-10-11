import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { withSpan } from "@better-auth/core/instrumentation";
import { organization } from "better-auth/plugins";
import { observeValue } from "./device-where-capture.mjs";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url));
const require = createRequire(new URL("../package.json", import.meta.url));
const { trace } = require("@opentelemetry/api");
const version = "1.7.6";
for (const name of ["better-auth", "@better-auth/core"]) {
  assert.equal(JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8")).version, version);
}

export const fullFallbackScenarios = [
  { name: "ordinary" },
  { name: "preceding-relations", dependencies: true },
  { name: "mapped-preceding-relations", dependencies: true, mapped: true },
  { name: "preceding-relation-error", dependencies: true, failure: "invitation.role" },
  { name: "source-alias-chain", sourceAlias: true },
  { name: "target-alias-chain", targetAlias: true },
  { name: "projected-owner-redirect", owner: "redirect" },
  { name: "projected-owner-null", owner: "null" },
  { name: "projected-owner-number", owner: "number" },
  { name: "duplicate-user-id-last-wins", duplicateUsers: true },
  ...["member", "invitation", "team"].flatMap(model => [
    { name: `${model}-singular-present`, singular: model },
    { name: `${model}-singular-empty`, singular: model, empty: model },
  ]),
  ...["member.role", "team.name", "user.name"].map(failure => ({ name: `${failure}-error`, failure })),
];

const date = new Date("2030-01-01T00:00:00.000Z");
const catalog = {
  linked_user: { id: "TEXT", name: "TEXT", email: "TEXT", emailVerified: "INTEGER", image: "TEXT", createdAt: "TEXT", updatedAt: "TEXT", linked_account: "TEXT" },
  organization: { id: "TEXT", name: "TEXT", slug: "TEXT", logo: "TEXT", metadata: "TEXT", createdAt: "TEXT", invitation: "TEXT", member: "TEXT", stored_invitation: "TEXT", stored_member: "TEXT", lookup: "TEXT", stored_lookup: "TEXT" },
  member: { id: "TEXT", organizationId: "TEXT", userId: "TEXT", role: "TEXT", createdAt: "TEXT", lookup: "TEXT", stored_lookup: "TEXT" },
  invitation: { id: "TEXT", organizationId: "TEXT", email: "TEXT", role: "TEXT", teamId: "TEXT", status: "TEXT", inviterId: "TEXT", createdAt: "TEXT", expiresAt: "TEXT" },
  team: { id: "TEXT", organizationId: "TEXT", name: "TEXT", memberCount: "INTEGER", createdAt: "TEXT", updatedAt: "TEXT" },
};

function seeds(scenario) {
  const owner = scenario.owner === "number" ? "7" : "owner";
  const user = (id, name) => ({ id, name, email: `${name.toLowerCase()}@full-fallback.test`, emailVerified: true,
    image: null, createdAt: date, updatedAt: date });
  return {
    linked_user: [user(owner, "Owner"), user(scenario.duplicateUsers ? owner : "redirect", "Redirect")],
    organization: [{ id: "organization", name: "Organization", slug: "organization", logo: null, metadata: null, createdAt: date,
      ...(scenario.dependencies ? { [scenario.mapped ? "stored_invitation" : "invitation"]: "stale-member-key",
        [scenario.mapped ? "stored_member" : "member"]: "stale-team-key" } : {}),
      ...(scenario.sourceAlias ? { lookup: "stale-member-key", stored_lookup: "organization" } : {}),
    }],
    member: scenario.empty === "member" ? [] : [{ id: "member", organizationId: scenario.dependencies ? "stale-member-key" : "organization",
      userId: owner, role: "member", createdAt: date,
      ...(scenario.targetAlias ? { lookup: "stale-member-key", stored_lookup: "organization" } : {}),
    }],
    invitation: scenario.empty === "invitation" ? [] : [{ id: "invitation", organizationId: "organization",
      email: "recipient@full-fallback.test", role: "member", teamId: null, status: "pending", inviterId: owner,
      createdAt: date, expiresAt: date }],
    team: scenario.empty === "team" ? [] : [{ id: "team", organizationId: scenario.dependencies ? "stale-team-key" : "organization",
      name: "Team", memberCount: 0, createdAt: date, updatedAt: null }],
  };
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

async function captureScenario(scenario, recorder) {
  const database = new Database(":memory:");
  const events = [];
  const failure = new TypeError(`full-fallback-output-rejected:${scenario.failure}`);
  const field = (name, declaration = {}) => ({ type: "string", ...declaration, transform: {
    input(value) { events.push(["unexpected-input", name, observeValue(value)]); return value; },
    output(value) {
      events.push(["output", name, observeValue(value)]);
      if (scenario.failure === name) throw failure;
      if (name === "member.userId") {
        if (scenario.owner === "redirect") return "redirect";
        if (scenario.owner === "null") return null;
        if (scenario.owner === "number") return 7;
      }
      return value;
    },
  } });
  const fields = {
    organization: { name: field("organization.name") },
    invitation: { role: field("invitation.role") },
    member: { userId: field("member.userId"), role: field("member.role") },
    team: { name: field("team.name") },
  };
  if (scenario.dependencies) {
    for (const name of ["invitation", "member"]) fields.organization[name] = field(`organization.${name}`,
      scenario.mapped ? { fieldName: `stored_${name}` } : {});
    fields.member.organizationId = { type: "string", references: { model: "organization", field: "invitation" } };
    fields.team.organizationId = { type: "string", references: { model: "organization", field: "member" } };
  }
  if (scenario.sourceAlias) {
    fields.organization.ownerRef = field("organization.ownerRef", { fieldName: "lookup" });
    fields.organization.lookup = field("organization.lookup", { fieldName: "stored_lookup" });
    fields.member.organizationId = { type: "string", references: { model: "organization", field: "ownerRef" } };
  }
  if (scenario.targetAlias) {
    fields.member.organizationId = { type: "string", fieldName: "lookup", references: { model: "organization", field: "id" } };
    fields.member.lookup = field("member.lookup", { fieldName: "stored_lookup" });
  }
  if (scenario.singular) fields[scenario.singular].organizationId = {
    type: "string", references: { model: "organization", field: "id" }, unique: true,
  };
  const pluginOptions = { teams: { enabled: true }, schema: Object.fromEntries(Object.entries(fields)
    .map(([model, additionalFields]) => [model, { additionalFields }])) };
  try {
    // A caller-supplied SQL catalog need not enforce uniqueness. Duplicate rows exercise Map last-wins behavior.
    for (const [table, columns] of Object.entries(catalog)) database.exec(`CREATE TABLE "${table}" (${Object.entries(columns)
      .map(([name, kind]) => `"${name}" ${kind}`).join(",")})`);
    for (const [table, rows] of Object.entries(seeds(scenario))) for (const row of rows) {
      const names = Object.keys(catalog[table]);
      const values = names.map(name => row[name] instanceof Date ? row[name].toISOString()
        : typeof row[name] === "boolean" ? Number(row[name]) : row[name] ?? null);
      database.query(`INSERT INTO "${table}" (${names.map(name => `"${name}"`).join(",")}) VALUES (${names.map(() => "?").join(",")})`).run(...values);
    }
    const stored = () => Object.fromEntries(Object.keys(catalog).map(table => [table,
      database.query(`SELECT * FROM "${table}" ORDER BY rowid`).all()]));
    const before = stored();
    const context = await betterAuth({
      database, baseURL: "http://full-fallback.test", secret: "full-fallback-contract-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins: false } },
      user: { modelName: "linked_user", additionalFields: { name: field("user.name") } },
      plugins: [organization(pluginOptions)],
    }).$context;
    recorder.events = events;
    let outcome;
    try {
      const result = await getOrgAdapter(context, pluginOptions).findFullOrganization({
        organizationId: "organization", includeTeams: true,
      });
      outcome = { returned: true, result: observeValue(result), json: JSON.parse(JSON.stringify(result)), keyOrder: keyOrder(result) };
    } catch (error) {
      assert.ok(error instanceof Error);
      outcome = { returned: false, error: { name: error.name, message: error.message,
        sameCallbackError: error === failure, properties: observeValue(Object.fromEntries(Object.entries(error))), keys: Object.keys(error) } };
    } finally { recorder.events = null; }
    const after = stored();
    assert.deepEqual(after, before, "Read projection and callback errors must preserve every physical field");
    assert.equal(events.some(event => event[0] === "unexpected-input"), false);
    return { scenario: scenario.name, before, events, ...outcome, after };
  } finally { recorder.events = null; database.close(); }
}

export async function captureOrganizationFullFallback() {
  const recorder = { events: null };
  let warmup = false;
  assert.equal(trace.setGlobalTracerProvider({ getTracer() { return {
    startActiveSpan(name, options, callback) {
      if (name === "full-fallback-warmup") warmup = true;
      const attributes = options.attributes;
      if (attributes["db.operation.name"] && attributes["db.collection.name"]) {
        recorder.events?.push(["query", attributes["db.operation.name"], attributes["db.collection.name"]]);
      }
      return callback({ end() {}, setAttribute() {}, setStatus() {}, recordException() {} });
    },
  }; } }), true);
  try {
    for (let attempt = 0; attempt < 50 && !warmup; attempt++) {
      await withSpan("full-fallback-warmup", {}, async () => {});
      if (!warmup) await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(warmup, true, "The query recorder must be active before sampling");
    const cases = [];
    for (const scenario of fullFallbackScenarios) cases.push(await captureScenario(scenario, recorder));
    return { version, backend: "sqlite", catalog, scenarios: fullFallbackScenarios, cases };
  } finally { trace.disable(); }
}

if (import.meta.main) {
  const serialized = `${JSON.stringify(await captureOrganizationFullFallback(), null, 2)}\n`;
  if (process.argv[2]) writeFileSync(process.argv[2], serialized);
  else process.stdout.write(serialized);
}
