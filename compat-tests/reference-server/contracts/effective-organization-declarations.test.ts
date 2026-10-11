import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { getAuthTables, type DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { observeSqliteCatalog } from "./sqlite-catalog";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);

type Row = Record<string, unknown>;
type Events = ["input" | "output", string, unknown][];
const tables = ["user", "session", "account", "verification", "team"];
const id = "mapping-row";
const date = new Date("2030-01-01T00:00:00.000Z");

async function setup(backend: "memory" | "sqlite", partial: boolean, minimalTable = false) {
  const events: Events = [];
  const state: { failure?: { phase: "input" | "output"; error: Error } } = {};
  const memory: Record<string, Row[]> = Object.fromEntries(tables.map(table => [table, []]));
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const field: DBFieldAttribute = {
    type: "string", required: true, fieldName: "name",
    transform: {
      input(value) {
        events.push(["input", "organizationId", value]);
        if (state.failure?.phase === "input") throw state.failure.error;
        return `stored:${value}`;
      },
      output(value) {
        events.push(["output", "organizationId", value]);
        if (state.failure?.phase === "output") throw state.failure.error;
        return `visible:${value}`;
      },
    },
  };
  const options: BetterAuthOptions = {
    database: database ?? memoryAdapter(memory),
    baseURL: "http://effective-organization-declarations.test",
    secret: "effective-organization-declarations-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [{ id: "explicit-team", schema: {
      team: { fields: partial ? { organizationId: field } : {} },
    } }],
  };
  if (database) {
    database.exec(minimalTable
      ? `CREATE TABLE team (id TEXT PRIMARY KEY NOT NULL${partial ? ", name TEXT" : ""})`
      : `CREATE TABLE team (
        id TEXT PRIMARY KEY NOT NULL, name TEXT, organization_id TEXT,
        created_at TEXT, updated_at TEXT, member_count INTEGER NOT NULL DEFAULT 0
      )`);
    await (await getMigrations(options)).runMigrations();
  }
  return {
    options, database, events, state,
    snapshot: () => Object.fromEntries(tables.map(table => [
      table, structuredClone(database ? database.query(`SELECT * FROM "${table}" ORDER BY id`).all() : memory[table]),
    ])),
    close() { database?.close(); },
  };
}

for (const partial of [false, true]) {
  test(`SQLite explicit ${partial ? "partial" : "empty"} Team declaration does not require undeclared native date columns`, async () => {
    const fixture = await setup("sqlite", partial);
    const database = fixture.database!;
    try {
      database.exec("ALTER TABLE team DROP COLUMN created_at");
      database.exec("ALTER TABLE team DROP COLUMN updated_at");
      const before = fixture.snapshot();
      const catalog = observeSqliteCatalog(database, "team", "The declared Team table must exist");
      expect(await betterAuth(fixture.options).api.ok()).toStrictEqual({ ok: true });
      expect(fixture.events).toStrictEqual([]);
      expect(fixture.snapshot()).toStrictEqual(before);
      expect(observeSqliteCatalog(database, "team", "Preflight must preserve the declared Team table")).toStrictEqual(catalog);
    } finally { fixture.close(); }
  });

  for (const [backend, minimalTable] of [["memory", false], ["sqlite", false], ["sqlite", true]] as const) {
    test(`${backend}${minimalTable ? " minimal table" : ""} explicit ${partial ? "partial" : "empty"} Team declaration controls complete adapter writes and reads`, async () => {
      const fixture = await setup(backend, partial, minimalTable);
      try {
        const { adapter } = await betterAuth(fixture.options).$context;
        expect(fixture.events).toStrictEqual([]);
        const before = fixture.snapshot();
        expect(before).toStrictEqual(Object.fromEntries(tables.map(table => [table, []])));
        const catalog = fixture.database && observeSqliteCatalog(fixture.database, "team", "The declared Team table must exist");
        const where = [{ field: "id", value: id }];
        const stages = partial ? ["create", "read", "update", "read"] as const : ["create", "read"] as const;
        let input = "source";
        for (const stage of stages) {
          if (stage === "update") input = "next";
          const actual = stage === "create"
            ? await adapter.create<Row>({ model: "team", forceAllowId: true, data: {
              id, name: "Team", organizationId: input, createdAt: date, updatedAt: date,
            } })
            : stage === "update"
              ? await adapter.update<Row>({ model: "team", where, update: { organizationId: input, updatedAt: date } })
              : await adapter.findOne<Row>({ model: "team", where });
          expect(actual).toStrictEqual(partial ? { organizationId: `visible:stored:${input}`, id } : { id });
          expect(Object.keys(actual!)).toStrictEqual(partial ? ["organizationId", "id"] : ["id"]);
          expect(fixture.events.splice(0)).toStrictEqual(partial ? [
            ...(stage === "read" ? [] : [["input", "organizationId", input]]),
            ["output", "organizationId", `stored:${input}`],
          ] : []);
          const stored = backend === "memory"
            ? partial ? { name: `stored:${input}`, id } : { id }
            : minimalTable
              ? partial ? { id, name: `stored:${input}` } : { id }
              : { id, name: partial ? `stored:${input}` : null, organization_id: null, created_at: null, updated_at: null, member_count: 0 };
          expect(fixture.snapshot()).toStrictEqual({ ...before, team: [stored] });
          if (fixture.database) {
            expect(observeSqliteCatalog(fixture.database, "team", "CRUD must preserve the declared Team table")).toStrictEqual(catalog);
          }
        }
      } finally { fixture.close(); }
    });
  }
}

for (const operation of ["create", "update"] as const) for (const phase of ["input", "output"] as const) {
  test(`memory partial Team ${operation} preserves persistence after ${phase} callback failure`, async () => {
    const fixture = await setup("memory", true);
    try {
      const { adapter } = await betterAuth(fixture.options).$context;
      const where = [{ field: "id", value: id }];
      const data = (organizationId: string) => ({ id, name: "Team", organizationId, createdAt: date, updatedAt: date });
      const expectedStorage = (input: string | undefined) => ({
        ...Object.fromEntries(tables.map(table => [table, []])),
        team: input === undefined ? [] : [{ name: `stored:${input}`, id }],
      });
      const visible = (input: string) => ({ organizationId: `visible:stored:${input}`, id });
      if (operation === "update") {
        expect(await adapter.create({ model: "team", forceAllowId: true, data: data("source") })).toStrictEqual(visible("source"));
        expect(fixture.events.splice(0)).toStrictEqual([["input", "organizationId", "source"], ["output", "organizationId", "stored:source"]]);
      }
      const before = operation === "update" ? "source" : undefined;
      expect(fixture.snapshot()).toStrictEqual(expectedStorage(before));
      const error = new Error(`partial-team-${phase}-failed`);
      fixture.state.failure = { phase, error };
      const result = operation === "create"
        ? adapter.create({ model: "team", forceAllowId: true, data: data("next") })
        : adapter.update({ model: "team", where, update: { organizationId: "next", updatedAt: date } });
      await expect(result).rejects.toBe(error);
      expect(fixture.events.splice(0)).toStrictEqual([
        ["input", "organizationId", "next"], ...(phase === "output" ? [["output", "organizationId", "stored:next"]] : []),
      ]);
      const stored = phase === "output" ? "next" : before;
      expect(fixture.snapshot()).toStrictEqual(expectedStorage(stored));
      delete fixture.state.failure;
      const observed = await adapter.findOne({ model: "team", where });
      expect(observed).toStrictEqual(stored === undefined ? null : visible(stored));
      if (observed) expect(Object.keys(observed)).toStrictEqual(["organizationId", "id"]);
      expect(fixture.events.splice(0)).toStrictEqual(stored === undefined ? [] : [["output", "organizationId", `stored:${stored}`]]);
      expect(fixture.snapshot()).toStrictEqual(expectedStorage(stored));
    } finally { fixture.close(); }
  });
}

test("Organization partial initialization changes only its own Role options before merging external declarations", () => {
  for (const enabled of [false, true]) {
    const events: unknown[] = [];
    const declaration = (): DBFieldAttribute => ({
      type: "string", required: true,
      transform: { output(value) { events.push(value); return value; } },
    });
    const externalBefore = declaration();
    const own = declaration();
    const externalAfter = declaration();
    const schema = getAuthTables({ plugins: [
      { id: "before-organization", schema: { organizationRole: { fields: { externalBefore } } } },
      organization({ dynamicAccessControl: { enabled }, schema: { organizationRole: { additionalFields: { own } } } }),
      { id: "after-organization", schema: { organizationRole: { fields: { externalAfter } } } },
    ] });
    const fields = schema.organizationRole!.fields;
    expect(Object.keys(fields)).toStrictEqual([
      "externalBefore", ...(enabled ? ["organizationId", "role", "permission", "createdAt", "updatedAt", "own"] : []), "externalAfter",
    ]);
    expect(fields.externalBefore).toBe(externalBefore);
    expect(fields.externalAfter).toBe(externalAfter);
    expect(externalBefore.required).toBe(true);
    expect(externalAfter.required).toBe(true);
    expect(own.required).toBe(false);
    if (enabled) expect(fields.own).toBe(own);
    else expect(Object.hasOwn(fields, "own")).toBe(false);
    expect(events).toStrictEqual([]);
  }
});

async function expectSchemaError(operation: Promise<unknown>, message: string) {
  let caught: unknown;
  try { await operation; } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(Error);
  const error = caught as Error;
  expect({ name: error.name, message: error.message, keys: Object.keys(error), properties: Object.fromEntries(Object.entries(error)) })
    .toStrictEqual({ name: "BetterAuthError", message, keys: ["name"], properties: { name: "BetterAuthError" } });
}

for (const backend of ["memory", "sqlite"] as const) for (const partial of [false, true]) for (const joins of [false, true]) {
  test(`${backend} explicit ${partial ? "partial" : "empty"} Member declaration rejects undeclared filters and user joins=${joins}`, async () => {
    const memberTables = ["user", "session", "account", "verification", "member"];
    const memory: Record<string, Row[]> = Object.fromEntries(memberTables.map(table => [table, []]));
    const database = backend === "sqlite" ? new Database(":memory:") : undefined;
    const events: Events = [];
    const options: BetterAuthOptions = {
      database: database ?? memoryAdapter(memory),
      baseURL: "http://effective-organization-declarations.test",
      secret: "effective-organization-declarations-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } },
      plugins: [{ id: "explicit-member", schema: { member: { fields: partial ? {
        organizationId: {
          type: "string", required: true, fieldName: "organization_id",
          transform: {
            input(value) { events.push(["input", "organizationId", value]); return `stored:${value}`; },
            output(value) { events.push(["output", "organizationId", value]); return `visible:${value}`; },
          },
        },
      } : {} } } }],
    };
    const snapshot = () => Object.fromEntries(memberTables.map(table => [
      table, structuredClone(database ? database.query(`SELECT * FROM "${table}" ORDER BY id`).all() : memory[table]),
    ]));
    try {
      if (database) {
        database.exec("CREATE TABLE member (id TEXT PRIMARY KEY NOT NULL, organization_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL)");
        await (await getMigrations(options)).runMigrations();
      }
      const before = snapshot();
      expect(before).toStrictEqual(Object.fromEntries(memberTables.map(table => [table, []])));
      const catalog = database && observeSqliteCatalog(database, "member", "The declared Member table must exist");
      const { adapter } = await betterAuth(options).$context;
      await expectSchemaError(adapter.findOne({
        model: "member", where: [{ field: "id", value: id }], join: { user: true },
      }), "No foreign key found for model user and base model member while performing join operation.");
      expect(events).toStrictEqual([]);
      expect(snapshot()).toStrictEqual(before);
      await expectSchemaError(adapter.findMany({ model: "member", where: [
        { field: "organizationId", value: "source" }, { field: "userId", value: "owner" },
      ] }), `Field ${partial ? "userId" : "organizationId"} not found in model member`);
      expect(events).toStrictEqual([]);
      expect(snapshot()).toStrictEqual(before);
      if (database) expect(observeSqliteCatalog(database, "member", "Rejected reads must preserve the declared Member table")).toStrictEqual(catalog);
    } finally { database?.close(); }
  });
}

async function deletionFixture(missingReference: boolean) {
  const memory: Record<string, Row[]> = {
    user: [], session: [], account: [], verification: [],
    organization: [], member: [], invitation: [], team: [], teamMember: [], organizationRole: [],
  };
  for (const organizationId of ["deleted", "retained"]) {
    memory.organization!.push({ id: organizationId, name: organizationId, slug: organizationId, createdAt: date });
    memory.member!.push({ id: `${organizationId}-member`, organizationId, userId: "owner", role: "member", createdAt: date });
    memory.invitation!.push({ id: `${organizationId}-invitation`, organizationId, email: "owner@delete.test", role: "member",
      status: "pending", inviterId: "owner", expiresAt: date, createdAt: date });
    memory.team!.push({ id: `${organizationId}-team`, organizationId, name: organizationId, memberCount: 1, createdAt: date });
    memory.teamMember!.push({ id: `${organizationId}-team-member`, teamId: `${organizationId}-team`, userId: "owner", createdAt: date });
    memory.organizationRole!.push({ id: `${organizationId}-role`, organizationId, role: "reader", permission: "{}", createdAt: date });
  }
  const context = await betterAuth({
    database: memoryAdapter(memory), baseURL: "http://effective-organization-declarations.test",
    secret: "effective-organization-declarations-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: missingReference ? [{ id: "explicit-delete-models", schema: {
      organization: { fields: {} }, member: { fields: { organizationId: { type: "string" } } }, invitation: { fields: {} },
    } }] : [organization({})],
  }).$context;
  return { memory, context, before: structuredClone(memory) };
}

test("Memory Organization deletion preserves disabled Team and Role storage", async () => {
  const { memory, context, before } = await deletionFixture(false);
  expect(await getOrgAdapter(context, {}).deleteOrganization("deleted")).toBe("deleted");
  expect(memory).toStrictEqual({
    ...before, organization: before.organization!.slice(1), member: before.member!.slice(1), invitation: before.invitation!.slice(1),
  });
});

for (const transactional of [false, true]) {
  test(`Memory Organization cleanup preserves the failure boundary: transaction=${transactional}`, async () => {
    const { memory, context, before } = await deletionFixture(true);
    const cleanup = async () => {
      const where = [{ field: "organizationId", value: "deleted" }];
      expect(await context.adapter.deleteMany({ model: "member", where })).toBe(1);
      await context.adapter.deleteMany({ model: "invitation", where });
      await context.adapter.delete({ model: "organization", where: [{ field: "id", value: "deleted" }] });
    };
    await expectSchemaError(transactional ? getOrgAdapter(context, {}).deleteOrganization("deleted") : cleanup(),
      "Field organizationId not found in model invitation");
    expect(memory).toStrictEqual(transactional ? before : { ...before, member: before.member!.slice(1) });
  });
}

for (const [model, table] of [["apikey", "api_keys"], ["passkey", "passkeys"]] as const) {
  test(`SQLite ${model} complete raw CRUD uses only declared physical columns`, async () => {
    const database = new Database(":memory:");
    const events: Events = [];
    const names = ["user", "session", "account", "verification", table];
    const options: BetterAuthOptions = {
      database, baseURL: "http://effective-organization-declarations.test",
      secret: "effective-organization-declarations-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      plugins: [{ id: `explicit-${model}`, schema: {
        [model]: { modelName: table, fields: {
          name: { type: "string", required: false, fieldName: "name", transform: {
            input(value) { events.push(["input", "name", value]); return `stored:${value}`; },
            output(value) { events.push(["output", "name", value]); return `visible:${value}`; },
          } },
        } },
      } }],
    };
    try {
      database.exec(`CREATE TABLE "${table}" (id TEXT PRIMARY KEY NOT NULL, name TEXT)`);
      await (await getMigrations(options)).runMigrations();
      const snapshot = () => Object.fromEntries(names.map(name => [
        name, database.query(`SELECT * FROM "${name}" ORDER BY id`).all(),
      ]));
      const before = snapshot();
      expect(before).toStrictEqual(Object.fromEntries(names.map(name => [name, []])));
      const catalog = observeSqliteCatalog(database, table, "The declared model table must exist");
      const { adapter } = await betterAuth(options).$context;
      expect(events).toStrictEqual([]);
      const where = [{ field: "id", value: id }];
      let input = "source";
      for (const stage of ["create", "read", "list", "update", "read", "delete", "missing"] as const) {
        if (stage === "update") input = "next";
        const actual = stage === "create"
          ? await adapter.create({ model, forceAllowId: true, data: { id, name: input } })
          : stage === "update"
            ? await adapter.update({ model, where, update: { name: input } })
            : stage === "list"
              ? await adapter.findMany({ model, where })
              : stage === "delete"
                ? await adapter.delete({ model, where })
                : await adapter.findOne({ model, where });
        const deleted = stage === "delete" || stage === "missing";
        const visible = { name: `visible:stored:${input}`, id };
        expect(actual).toStrictEqual(stage === "delete" ? undefined : stage === "missing" ? null : stage === "list" ? [visible] : visible);
        if (!deleted) {
          for (const record of stage === "list" ? actual as Row[] : [actual as Row]) {
            expect(Object.keys(record)).toStrictEqual(["name", "id"]);
          }
        }
        expect(events.splice(0)).toStrictEqual(deleted ? [] : [
          ...(stage === "create" || stage === "update" ? [["input", "name", input]] : []),
          ["output", "name", `stored:${input}`],
        ]);
        expect(snapshot()).toStrictEqual({ ...before, [table]: deleted ? [] : [{ id, name: `stored:${input}` }] });
        expect(observeSqliteCatalog(database, table, "CRUD must preserve the declared model table")).toStrictEqual(catalog);
      }
    } finally { database.close(); }
  });
}

test("PostgreSQL native enum labels reach complete JWK CRUD policies before record decoding", async () => {
  const events: Events = [];
  const failure = new Error("enum-output-stop");
  const names = ["user", "session", "account", "verification", "raw_enum_jwks"];
  await captureFreshServerCatalog("postgres", names, {
    plugins: [{ id: "explicit-enum-jwk", schema: { jwks: {
      modelName: "raw_enum_jwks", fields: {
        publicKey: { type: "string", required: false, fieldName: "stored_public_key", transform: {
          input(value: unknown) {
            events.push(["input", "publicKey", value]);
            return value === null ? null : `stored:${value}`;
          },
          output(value: unknown) {
            events.push(["output", "publicKey", value]);
            if (value === "stored:reject") throw failure;
            return value === null ? null : `visible:${value}`;
          },
        } },
      },
    } } }],
  }, async ({ options, query }: any) => {
    await query("CREATE TYPE raw_jwk_label AS ENUM ('stored:source','stored:next','stored:reject')");
    await query('ALTER TABLE raw_enum_jwks ALTER COLUMN stored_public_key TYPE raw_jwk_label USING stored_public_key::raw_jwk_label');
    const columns = async () => await query("SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'raw_enum_jwks' ORDER BY ordinal_position");
    const physicalColumns = await columns();
    expect(physicalColumns).toStrictEqual([{ column_name: "id" }, { column_name: "stored_public_key" }]);
    const snapshot = async () => {
      const rows: Record<string, Row[]> = {};
      for (const name of names) rows[name] = await query(`SELECT * FROM "${name}" ORDER BY id`);
      return rows;
    };
    const before = await snapshot();
    expect(before).toStrictEqual(Object.fromEntries(names.map(name => [name, []])));
    const { adapter } = await betterAuth(options).$context;
    expect(events).toStrictEqual([]);
    const where = [{ field: "id", value: id }];
    let stored: string | null | undefined;
    for (const stage of [
      "create", "read", "list", "update", "read-updated", "update-null", "read-null",
      "update-rejected", "read-rejected", "delete", "create-rejected", "read-create-rejected", "delete-rejected", "missing",
    ]) {
      const create = stage === "create" || stage === "create-rejected";
      const update = stage.startsWith("update");
      const remove = stage.startsWith("delete");
      const input = stage === "create" ? "source" : stage === "update-null" ? null : stage.endsWith("rejected") ? "reject" : "next";
      if (create || update) stored = input === null ? null : `stored:${input}`;
      if (remove) stored = undefined;
      const execute = () => create
        ? adapter.create({ model: "jwks", forceAllowId: true, data: { id, publicKey: input } })
        : update
          ? adapter.update({ model: "jwks", where, update: { publicKey: input } })
          : remove
            ? adapter.delete({ model: "jwks", where })
            : stage === "list"
              ? adapter.findMany({ model: "jwks", where })
              : adapter.findOne({ model: "jwks", where });
      if (stored === "stored:reject") {
        await expect(execute()).rejects.toBe(failure);
      } else {
        const actual = await execute();
        const visible = { publicKey: stored === null ? null : `visible:${stored}`, id };
        expect(actual).toStrictEqual(remove ? undefined : stored === undefined ? null : stage === "list" ? [visible] : visible);
        if (stored !== undefined) {
          for (const record of stage === "list" ? actual as Row[] : [actual as Row]) {
            expect(Object.keys(record)).toStrictEqual(["publicKey", "id"]);
          }
        }
      }
      expect(events.splice(0)).toStrictEqual(stored === undefined ? [] : [
        ...(create || update ? [["input", "publicKey", input]] : []),
        ["output", "publicKey", stored],
      ]);
      expect(await snapshot()).toStrictEqual({ ...before, raw_enum_jwks: stored === undefined ? [] : [{ id, stored_public_key: stored }] });
      expect(await columns()).toStrictEqual(physicalColumns);
    }
  });
}, 120_000);
