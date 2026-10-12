import assert from "node:assert/strict";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";
import { getOrgAdapter } from "../node_modules/better-auth/dist/plugins/organization/adapter.mjs";
import { observeValue } from "./device-where-capture.mjs";

const date = new Date("2030-01-02T03:04:05.000Z");
const expiresAt = new Date("2100-01-02T03:04:05.000Z");
const pluginOptions = { teams: { enabled: true }, dynamicAccessControl: { enabled: true } };
const schema = getAuthTables({ plugins: [organization(pluginOptions)] });
const models = ["organization", "member", "invitation", "team", "organizationRole"];
const tables = ["user", "session", "account", "verification", ...models, "teamMember"];
const probe = model => ({ organization: "name", member: "role", invitation: "status", team: "name", organizationRole: "role" })[model];

export const organizationQueryIdAliasScenarios = [
  ...models.flatMap(model => ["find", "update", "delete"].map(operation => `${model}-${operation}`)),
  "member-user-fallback", "member-user-native",
  "invitation-atomic-retained-alias", "invitation-atomic-mutated-alias",
];

function user(id = "owner", name = "Owner") {
  return { id, name, email: `${id}@organization-query-id.test`, emailVerified: false, image: null, createdAt: date, updatedAt: date };
}

function row(model, id, label) {
  if (model === "organization") return { id, name: label, slug: label, logo: null, createdAt: date, metadata: "{}" };
  if (model === "member") return { id, organizationId: "parent", userId: "owner", role: label, createdAt: date };
  if (model === "invitation") return {
    id, organizationId: "parent", email: "recipient@organization-query-id.test", role: "member",
    status: label, teamId: null, expiresAt, createdAt: date, inviterId: "owner",
  };
  if (model === "team") return { id, name: label, memberCount: 0, organizationId: "parent", createdAt: date, updatedAt: null };
  assert.equal(model, "organizationRole");
  return { id, organizationId: "parent", role: label, permission: "{}", createdAt: date, updatedAt: null };
}

function storage() {
  return Object.fromEntries(tables.map(model => [model, []]));
}

function observedField(model, field, events, onInput) {
  assert.ok(schema[model]?.fields[field]);
  return { ...schema[model].fields[field], transform: {
    input(value) {
      events.push(["input", `${model}.${field}`, observeValue(value)]);
      onInput?.();
      return value;
    },
    output(value) {
      events.push(["output", `${model}.${field}`, observeValue(value)]);
      return value;
    },
  } };
}

async function context(memory, fields, joins = false, userFields = {}) {
  const plugin = {
    ...pluginOptions,
    schema: Object.fromEntries(Object.entries(fields).map(([model, additionalFields]) => [model, { additionalFields }])),
  };
  const current = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://organization-query-id.test",
    secret: "organization-query-id-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } }, user: { additionalFields: userFields },
    plugins: [organization(plugin)],
  }).$context;
  return { adapter: current.adapter, org: getOrgAdapter(current, plugin) };
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  return [{ path, keys: Object.keys(value) }, ...Object.entries(value).flatMap(([key, child]) => keyOrder(child, [...path, key]))];
}

async function observedStep(memory, events, input, action) {
  const before = observeValue(memory);
  let outcome;
  try {
    const result = await action();
    outcome = { returned: true, result: observeValue(result), keyOrder: keyOrder(result) };
  } catch (error) {
    assert.ok(error instanceof Error);
    outcome = { returned: false, error: {
      name: error.name, message: error.message, stack: error.stack,
      ownKeys: Reflect.ownKeys(error).map(String),
      properties: observeValue(Object.fromEntries(Reflect.ownKeys(error).map(key => [String(key), error[key]]))),
    } };
  }
  return { input: observeValue(input), before, ...outcome, events: events.splice(0), after: observeValue(memory) };
}

function request(model, operation, id) {
  if (operation === "find") {
    if (model === "organization") return ["getOrgAdapter.findOrganizationById", [id]];
    if (model === "member") return ["getOrgAdapter.findMemberById", [id]];
    if (model === "invitation") return ["getOrgAdapter.findInvitationById", [id]];
    if (model === "team") return ["getOrgAdapter.findTeamById", [{ teamId: id }]];
  }
  if (operation === "update") {
    if (model === "organization") return ["getOrgAdapter.updateOrganization", [id, { name: "accepted" }]];
    if (model === "member") return ["getOrgAdapter.updateMember", [id, "accepted"]];
    if (model === "invitation") return ["getOrgAdapter.updateInvitation", [{ invitationId: id, status: "accepted" }]];
    if (model === "team") return ["getOrgAdapter.updateTeam", [id, { name: "accepted" }]];
  }
  if (operation === "delete") {
    if (model === "organization") return ["getOrgAdapter.deleteOrganization", [id]];
    if (model === "member") return ["getOrgAdapter.deleteMember", [{ memberId: id, organizationId: "parent", userId: "owner" }]];
    if (model === "team") return ["getOrgAdapter.deleteTeam", [id]];
  }
  const method = operation === "find" ? "findOne" : operation;
  return [`adapter.${method}`, [{ model, where: [{ field: "id", value: id }],
    ...(operation === "update" ? { update: { [probe(model)]: "accepted" } } : {}),
  }]];
}

async function execute(current, [surface, args]) {
  const [owner, method] = surface.split(".");
  return current[owner === "getOrgAdapter" ? "org" : "adapter"][method](...args);
}

async function directCase(model, operation) {
  const memory = storage();
  memory.user.push(user());
  if (model !== "organization") memory.organization.push(row("organization", "parent", "Parent"));
  const canonical = `canonical-${model}`;
  const alias = `alias-${model}`;
  memory[model].push({ ...row(model, canonical, "selected"), lookup: alias });
  memory[model].push({ ...row(model, alias, "decoy"), lookup: "unrelated-alias" });
  const events = [];
  const current = await context(memory, { [model]: {
    id: { type: "string", fieldName: "lookup" },
    [probe(model)]: observedField(model, probe(model), events),
  } });
  const initial = request(model, operation, alias);
  const steps = [await observedStep(memory, events, initial, () => execute(current, initial))];
  if (operation !== "delete") {
    for (const id of [canonical, alias]) {
      const input = request(model, "find", id);
      steps.push(await observedStep(memory, events, input, () => execute(current, input)));
    }
  }
  return { scenario: `${model}-${operation}`, model, operation, surface: initial[0], canonical, alias, idFieldName: "lookup", steps };
}

async function joinedCase(joins, unique = false) {
  const memory = storage();
  memory.user.push({ ...user("canonical-user", "Alias owner"), lookup: "user-alias" });
  memory.user.push({ ...user("user-alias", "Decoy owner"), lookup: "unrelated-alias" });
  memory.member.push({ ...row("member", "member", "member"), userId: "user-alias" });
  const events = [];
  const current = await context(memory, { member: {
    role: observedField("member", "role", events),
    ...(unique ? { userId: { ...schema.member.fields.userId, unique: true } } : {}),
  } }, joins, {
    id: { type: "string", fieldName: "lookup" }, name: observedField("user", "name", events),
  });
  const input = { userId: "user-alias", organizationId: "parent" };
  const step = await observedStep(memory, events, input, () => current.org.findMemberByOrgId(input));
  return { scenario: `member-user-${joins ? "native" : "fallback"}${unique ? "-unique" : ""}`, joins, surface: "getOrgAdapter.findMemberByOrgId", steps: [step] };
}

async function atomicCase(mutate) {
  const memory = storage();
  const selected = { ...row("invitation", "canonical-invitation", "pending"), lookup: "invitation-alias" };
  memory.invitation.push(selected);
  memory.invitation.push({ ...row("invitation", "invitation-alias", "pending"), lookup: "unrelated-alias" });
  const events = [];
  const current = await context(memory, { invitation: {
    id: { type: "string", fieldName: "lookup" },
    status: observedField("invitation", "status", events, mutate ? () => {
      const before = observeValue(selected);
      selected.lookup = "changed-alias";
      events.push(["mutation", "invitation.lookup", before, observeValue(selected)]);
    } : undefined),
  } });
  const input = { invitationId: "invitation-alias", status: "accepted" };
  const step = await observedStep(memory, events, input, () => current.org.updateInvitation(input));
  return { scenario: `invitation-atomic-${mutate ? "mutated" : "retained"}-alias`, mutate, surface: "getOrgAdapter.updateInvitation", steps: [step] };
}

export async function captureOrganizationQueryIdAliases(onCase = () => {}) {
  const cases = [];
  const append = async captured => { cases.push(captured); await onCase(captured); };
  for (const model of models) {
    for (const operation of ["find", "update", "delete"]) await append(await directCase(model, operation));
  }
  for (const joins of [false, true]) await append(await joinedCase(joins));
  for (const mutate of [false, true]) await append(await atomicCase(mutate));
  return { version: "1.7.6", backend: "memory", cases };
}

export async function captureOrganizationUniqueIdAliasJoins(onCase = () => {}) {
  const cases = [];
  for (const joins of [false, true]) {
    const captured = await joinedCase(joins, true);
    cases.push(captured);
    await onCase(captured);
  }
  return { version: "1.7.6", backend: "memory", cases };
}

export async function captureInvitationClaimSelectorUpdates(onCase = () => {}) {
  const cases = [];
  for (const column of ["id", "lookup"]) {
    const memory = storage();
    const selected = { ...row("invitation", "canonical-invitation", "pending"), [column]: "invitation-alias" };
    memory.invitation.push(selected);
    const events = [];
    const current = await context(memory, { invitation: {
      id: { type: "string", fieldName: column },
      claimLookup: { type: "string", fieldName: column, onUpdate() {
        events.push(["onUpdate", "invitation.claimLookup", "claimed-alias"]);
        return "claimed-alias";
      } },
    } });
    const input = { invitationId: "invitation-alias", status: "accepted", fromStatus: "pending" };
    const step = await observedStep(memory, events, input, () => current.org.updateInvitation(input));
    const captured = { scenario: `invitation-own-selector-update-${column}`, column, surface: "getOrgAdapter.updateInvitation", steps: [step] };
    cases.push(captured);
    await onCase(captured);
  }
  return { version: "1.7.6", backend: "memory", cases };
}
