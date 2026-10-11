import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization, type OrganizationOptions } from "better-auth/plugins/organization";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
type Parent = "member" | "invitation";
type Backend = "memory" | "sqlite";
type Fields = Record<string, unknown>;
const cases = ["mapped-missing", "redirect", "many", "unique-duplicates", "null-projection", "fallback-key-redirect", "fallback-key-null", "no-refs", "no-refs-empty", "multiple-refs", "multiple-refs-empty", "many-empty-schema", "function-unfiltered", "function-hidden"] as const;
type Scenario = typeof cases[number];
const date = () => new Date("2030-01-01T00:00:00.000Z");
const reverse = (scenario: Scenario) => scenario === "many" || scenario === "unique-duplicates" || scenario === "many-empty-schema";
const many = (scenario: Scenario) => scenario === "many" || scenario === "many-empty-schema";
const functionName = (scenario: Scenario) => scenario === "function-unfiltered" || scenario === "function-hidden";
const fallbackKey = (scenario: Scenario) => scenario === "fallback-key-redirect" || scenario === "fallback-key-null";
function parentRoles(scenario: Scenario): string[] {
  if (scenario === "no-refs-empty" || scenario === "multiple-refs-empty") return [];
  if (scenario === "mapped-missing") return ["org-a", "missing"];
  if (many(scenario)) return ["linked", "missing"];
  if (scenario === "unique-duplicates") return ["linked"];
  if (scenario === "redirect" || scenario === "fallback-key-redirect") return ["slug-a"];
  return ["org-a"];
}
function schemaError(parent: Parent, scenario: Scenario) {
  if (scenario === "no-refs" || scenario === "no-refs-empty") return `No foreign key found for model organization and base model ${parent} while performing join operation.`;
  if (scenario === "multiple-refs" || scenario === "multiple-refs-empty") return `Multiple foreign keys found for model organization and base model ${parent} while performing join operation. Only one foreign key is supported.`;
}
function outputField(attributes: DBFieldAttribute, output: (value: unknown) => unknown): DBFieldAttribute {
  // Runtime plugins can return Function values outside the DBPrimitive declaration.
  Object.defineProperty(attributes, "transform", { enumerable: true, value: { output } });
  return attributes;
}
function policies(parent: Parent, scenario: Scenario, events: unknown[][], name: () => string) {
  const parentFields: Record<string, DBFieldAttribute> = {};
  if (!reverse(scenario)) {
    parentFields.organizationId = outputField({
      type: "string", fieldName: "role", unique: true,
      ...(scenario === "no-refs" || scenario === "no-refs-empty" ? {} : { references: { model: "organization", field: scenario === "redirect" || scenario === "fallback-key-redirect" ? "slug" : "id" } }),
    }, value => {
      events.push([`${parent}.organizationId`, value]);
      return scenario === "redirect" ? "slug-b" : scenario === "null-projection" ? null : value;
    });
  } else {
    parentFields.role = outputField({ type: "string" }, value => { events.push([`${parent}.role`, value]); return value; });
  }
  if (fallbackKey(scenario)) parentFields.role = outputField({ type: "string" }, value => {
    events.push([`${parent}.role`, value]);
    return scenario === "fallback-key-redirect" ? "slug-b" : null;
  });
  if (scenario === "multiple-refs" || scenario === "multiple-refs-empty") {
    parentFields.role = { type: "string", references: { model: "organization", field: "slug" } };
  }
  const organizationFields: Record<string, DBFieldAttribute> = {
    name: outputField({ type: "string" }, value => {
      events.push(["organization.name", value]);
      return functionName(scenario) ? name : `visible:${value}`;
    }),
  };
  if (reverse(scenario)) organizationFields.logo = { type: "string", unique: scenario === "unique-duplicates", references: { model: parent, field: "role" } };
  return { [parent]: { fields: parentFields }, organization: { fields: organizationFields } };
}
function publicOptions(scenario: Scenario): OrganizationOptions {
  if (scenario === "many-empty-schema") return { teams: { enabled: true }, schema: { organization: { additionalFields: {} } } };
  if (scenario === "function-hidden") return { teams: { enabled: true }, schema: { organization: { additionalFields: { name: { type: "string", returned: false } } } } };
  return { teams: { enabled: true } };
}

async function setup(backend: Backend, parent: Parent, scenario: Scenario, joins: boolean) {
  const models = ["user", "session", "account", "verification", "organization", "member", "invitation", "team", "teamMember"];
  const memory: Record<string, Fields[]> = Object.fromEntries(models.map(model => [model, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const organizationPlugin = organization({ teams: { enabled: true } });
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory), baseURL: "http://list-relations.test",
    secret: "organization-list-relations-secret-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } }, plugins: [organizationPlugin],
  };
  if (database) {
    // The read contract uses a compatible legacy column; required legacy columns have separate preflight negative coverage.
    const migrationOptions: BetterAuthOptions = reverse(scenario) ? options : {
      ...options,
      plugins: [organizationPlugin, { id: "organization-list-compatible-schema", schema: {
        [parent]: { fields: { organizationId: {
          ...organizationPlugin.schema[parent].fields.organizationId, required: false,
        } } },
      } }],
    };
    await (await getMigrations(migrationOptions)).runMigrations();
    const legacyColumn = database.query<{ notnull: number }, []>(`SELECT "notnull" FROM pragma_table_info('${parent}') WHERE name = 'organizationId'`).get();
    expect(legacyColumn).toStrictEqual({ notnull: reverse(scenario) ? 1 : 0 });
  }
  const writer = (await betterAuth(options).$context).adapter;
  const create = (model: string, data: Fields) => writer.create({ model, data, forceAllowId: true });
  await create("user", { id: "user", name: "Owner", email: "owner@list-relations.test", emailVerified: true, image: null, createdAt: date(), updatedAt: date() });
  for (const suffix of ["a", "b", "c"]) await create("organization", {
    id: `org-${suffix}`, name: `Organization ${suffix}`, slug: `slug-${suffix}`, logo: suffix === "c" ? "other" : "linked", createdAt: date(), metadata: null,
  });
  for (const [index, role] of parentRoles(scenario).entries()) await create(parent, {
    id: `parent-${index}`, organizationId: "org-a", role, createdAt: date(),
    ...(parent === "member" ? { userId: "user" } : { email: "owner@list-relations.test", teamId: null, status: "pending", expiresAt: date(), inviterId: "user" }),
  });
  await create("session", { id: "session", userId: "user", token: "list-relations-token", expiresAt: date(), createdAt: date(), updatedAt: date(), ipAddress: null, userAgent: null, activeOrganizationId: null, activeTeamId: null });
  return {
    options,
    snapshot: () => Object.fromEntries(models.map(model => [model, structuredClone(database
      ? database.query(`SELECT * FROM "${model}" ORDER BY id`).all()
      : memory[model].toSorted((left, right) => String(left.id).localeCompare(String(right.id))))])),
    close: () => database?.close(),
  };
}

function selected(backend: Backend, joins: boolean, scenario: Scenario, index: number) {
  if (index > 0 || scenario === "fallback-key-null" && !joins) return [];
  if (many(scenario)) return ["a", "b"];
  // The factory resolves the physical key "role" as its own declaration before checking aliases.
  if (scenario === "fallback-key-redirect" && !joins || scenario === "unique-duplicates" && backend === "sqlite" && joins) return ["b"];
  return ["a"];
}
function expectedOrganization(suffix: string, scenario: Scenario, name: () => string) {
  return { name: functionName(scenario) ? name : `visible:Organization ${suffix}`, slug: `slug-${suffix}`, logo: suffix === "c" ? "other" : "linked", createdAt: date(), metadata: null, id: `org-${suffix}` };
}
function expectedParent(parent: Parent, scenario: Scenario, index: number, role: string) {
  const organizationId = reverse(scenario) ? "org-a" : scenario === "redirect" ? "slug-b" : scenario === "null-projection" ? null : role;
  const projectedRole = scenario === "fallback-key-redirect" ? "slug-b" : scenario === "fallback-key-null" ? null : role;
  return parent === "member" ? { organizationId, userId: "user", role: projectedRole, createdAt: date(), id: `parent-${index}` }
    : { organizationId, email: "owner@list-relations.test", role: projectedRole, teamId: null, status: "pending", expiresAt: date(), createdAt: date(), inviterId: "user", id: `parent-${index}` };
}
function expectedResult(backend: Backend, joins: boolean, parent: Parent, scenario: Scenario, publicOutput: boolean, name: () => string) {
  return parentRoles(scenario).map((role, index) => {
    const selectedChildren = selected(backend, joins, scenario, index);
    const children = selectedChildren.map(suffix => expectedOrganization(suffix, scenario, name));
    const relation = many(scenario) ? publicOutput && parent === "member" && scenario === "many-empty-schema" ? Object.fromEntries(children.map((row, index) => [String(index), row])) : children : children[0] ?? null;
    if (parent === "member") return relation;
    return { ...expectedParent(parent, scenario, index, role), ...(publicOutput
      ? { organizationName: many(scenario) || selectedChildren.length === 0 ? undefined : functionName(scenario) ? name : `visible:Organization ${selectedChildren[0]}` }
      : { organization: relation }) };
  });
}
function expectedEvents(backend: Backend, joins: boolean, parent: Parent, scenario: Scenario) {
  if (schemaError(parent, scenario)) return [];
  return [
    ...parentRoles(scenario).map(role => [`${parent}.${reverse(scenario) ? "role" : "organizationId"}`, role]),
    ...(fallbackKey(scenario) ? parentRoles(scenario).map(role => [`${parent}.role`, role]) : []),
    ...parentRoles(scenario).flatMap((_, index) => selected(backend, joins, scenario, index).map(suffix => ["organization.name", `Organization ${suffix}`])),
  ];
}
function expectOrdered(actual: unknown, expected: unknown) {
  expect(actual).toStrictEqual(expected);
  if (typeof expected === "function") expect(actual).toBe(expected);
  if (expected === null || typeof expected !== "object" || expected instanceof Date) return;
  expect(Object.keys(actual as object)).toStrictEqual(Object.keys(expected));
  for (const [field, value] of Object.entries(expected)) expectOrdered(Reflect.get(actual as object, field), value);
}

for (const backend of ["memory", "sqlite"] as const) for (const joins of [false, true]) for (const parent of ["member", "invitation"] as const) for (const scenario of cases) {
  test(`${backend} ${parent} Organization list relation: ${scenario}, joins=${joins}`, async () => {
    const fixture = await setup(backend, parent, scenario, joins);
    try {
      const before = fixture.snapshot();
      const events: unknown[][] = [];
      const name = () => { events.push(["function-called", undefined]); return "called"; };
      const orgOptions = publicOptions(scenario);
      const auth = betterAuth({ ...fixture.options, plugins: [organization(orgOptions), { id: "organization-list-relation-fields", schema: policies(parent, scenario, events, name) }] });
      expect(await auth.api.ok()).toStrictEqual({ ok: true });
      const context = await auth.$context;
      const adapter = getOrgAdapter(context, orgOptions);
      for (const publicOutput of [false, true]) {
        const operation = async () => {
          if (publicOutput) return parent === "member" ? adapter.listOrganizations("user") : adapter.listUserInvitations("OWNER@LIST-RELATIONS.TEST");
          const rows = await context.adapter.findMany({ model: parent, where: [{ field: parent === "member" ? "userId" : "email", value: parent === "member" ? "user" : "owner@list-relations.test" }], join: { organization: true } });
          return parent === "member" ? rows.map(row => row.organization) : rows;
        };
        const error = schemaError(parent, scenario);
        if (error || publicOutput && parent === "member" && scenario === "function-hidden") {
          let caught: unknown;
          try { await operation(); } catch (error) { caught = error; }
          expect(caught).toBeInstanceOf(Error);
          expect({ name: (caught as Error).name, message: (caught as Error).message }).toStrictEqual(error
            ? { name: "BetterAuthError", message: error }
            : { name: "DataCloneError", message: "The object can not be cloned." });
        } else expectOrdered(await operation(), expectedResult(backend, joins, parent, scenario, publicOutput, name));
        expect(events.splice(0)).toStrictEqual(expectedEvents(backend, joins, parent, scenario));
        expect(fixture.snapshot()).toStrictEqual(before);
      }
    } finally { fixture.close(); }
  });
}
