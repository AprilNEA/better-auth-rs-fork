import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { passkey } from "@better-auth/passkey";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { withRestoredSchema } from "./schema-isolation.mjs";
import { observeSqliteCatalog } from "./sqlite-catalog";

type Fields = Record<string, unknown>;
type Events = ["input" | "output", string, unknown][];
type ColumnMode = "required" | "nullable" | "default";
type IdMode = "missing-alias" | "both-columns" | "missing-primary-key";
const models = [
  ["user", "name", "image"],
  ["session", "token", "userAgent"],
  ["account", "accountId", "scope"],
  ["verification", "value", "identifier"],
  ["team", "organizationId", "name"],
  ["passkey", "publicKey", "name"],
] as const;
type Model = typeof models[number][0];
const tables = ["account", "invitation", "member", "organization", "passkey", "session", "team", "teamMember", "user", "verification"];
const date = new Date("2030-01-01T00:00:00.000Z");
const expiresAt = new Date("2100-01-01T00:00:00.000Z");
const dates = { createdAt: date, updatedAt: date };
const id = "mapping-row";

function base(database: Database): BetterAuthOptions {
  return {
    database, baseURL: "http://schema-preflight.test",
    secret: "native-mapping-schema-preflight-contract-at-least-32-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    plugins: [organization({ teams: { enabled: true } }), passkey()],
  };
}

function field(source: string, fieldName: string, events: Events) {
  return {
    type: "string" as const, required: true, fieldName,
    transform: {
      input(value: unknown) { events.push(["input", source, value]); return `stored:${value}`; },
      output(value: unknown) { events.push(["output", source, value]); return `visible:${value}`; },
    },
  };
}

function snapshot(database: Database) {
  return Object.fromEntries(tables.map(table => [table, database.query(`SELECT * FROM "${table}" ORDER BY id`).all()]));
}

function raw(value: Fields) {
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key, item instanceof Date ? item.toISOString() : typeof item === "boolean" ? Number(item) : item,
  ]));
}

function data(model: Model): Fields {
  switch (model) {
    case "user": return { id, name: "source", email: "mapping-row@schema-preflight.test", emailVerified: true, ...dates };
    case "session": return {
      id, token: "source", userId: "owner", expiresAt, ...dates,
      ipAddress: null, activeOrganizationId: null, activeTeamId: null,
    };
    case "account": return {
      id, accountId: "source", providerId: "password", userId: "owner",
      accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null,
      refreshTokenExpiresAt: null, password: null, ...dates,
    };
    case "verification": return { id, identifier: "subject", value: "source", expiresAt, ...dates };
    case "team": return { id, name: "Team", memberCount: 0, organizationId: "source", ...dates };
    case "passkey": return {
      id, userId: "owner", publicKey: "source", credentialID: "credential", counter: 0,
      deviceType: "singleDevice", backedUp: false, transports: null, createdAt: date, aaguid: null,
    };
  }
}

function seed(database: Database, model: Model) {
  if (["session", "account", "passkey"].includes(model)) {
    database.query('INSERT INTO "user" (id, name, email, emailVerified, image, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run("owner", "Owner", "owner@schema-preflight.test", 1, null, date.toISOString(), date.toISOString());
  }
  if (model === "team") {
    database.query('INSERT INTO organization (id, name, slug, logo, metadata, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run("legacy-default", "Legacy", "legacy-default", null, null, date.toISOString());
  }
}

async function outcome(auth: ReturnType<typeof betterAuth>) {
  try {
    return { result: await auth.api.ok() };
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    const mismatch = error as Error & { code: string; source: string; findings: unknown[] };
    return { error: {
      name: mismatch.name, message: mismatch.message, code: mismatch.code,
      source: mismatch.source, findings: mismatch.findings,
    } };
  }
}

function mismatch(model: string, column: string, kind: "unexpected-required-column" | "missing-column") {
  return { error: {
    name: "BetterAuthError", code: "SCHEMA_MISMATCH", source: "database",
    findings: [{ kind, table: model, column }],
    message: kind === "unexpected-required-column"
      ? `Database schema mismatch\n\n  Required columns Better Auth never writes\n    ${model}.${column}\n\n  Inserts into ${model} will fail.\n\n  help: Make the listed columns nullable, give them defaults, or remove them.`
      : `Database schema mismatch\n\n  Missing columns\n    ${model}.${column}\n\n  help: Run \`npx auth migrate\` to add the missing tables and columns.`,
  } };
}

for (const [model, source, destination] of models) {
  for (const mode of ["required", "nullable", "default"] as const satisfies readonly ColumnMode[]) {
    test(`SQLite ${model} mapping validates the ${mode} unused native column before complete CRUD`, async () => {
      await withRestoredSchema(passkey().schema, async () => {
        const database = new Database(":memory:");
        const events: Events = [];
        const options = base(database);
        options.plugins!.push({ id: "native-mapping-preflight", schema: {
          [model]: { fields: { [source]: field(source, destination, events) } },
        } });
        try {
          await (await getMigrations(options)).runMigrations();
          const before = observeSqliteCatalog(database, model, "The mapped table must exist");
          expect(before.catalog.columns.some(column => column.name === source)).toBe(false);
          const declaration = `"${source}" TEXT${mode === "nullable" ? "" : " NOT NULL"}${mode === "default" ? " DEFAULT 'legacy-default'" : ""}${model === "team" ? ' REFERENCES "organization" ("id")' : ""}`;
          database.exec(`ALTER TABLE "${model}" ADD COLUMN ${declaration}`);
          const catalog = observeSqliteCatalog(database, model, "The mapped table must retain its native column");
          expect(catalog.catalog).toStrictEqual({
            ...before.catalog,
            columns: [...before.catalog.columns, {
              cid: before.catalog.columns.length, name: source, type: "TEXT",
              notnull: mode === "nullable" ? 0 : 1, dflt_value: mode === "default" ? "'legacy-default'" : null, pk: 0,
            }],
            foreignKeys: model === "team" ? [{
              id: 0, seq: 0, table: "organization", from: source, to: "id",
              on_update: "NO ACTION", on_delete: "NO ACTION", match: "NONE",
            }] : before.catalog.foreignKeys,
          });
          expect(catalog.ddl.filter(row => row.type !== "table")).toStrictEqual(before.ddl.filter(row => row.type !== "table"));
          const empty = snapshot(database);
          expect(empty).toStrictEqual(Object.fromEntries(tables.map(table => [table, []])));
          const auth = betterAuth(options);
          expect(await outcome(auth)).toStrictEqual(mode === "required" ? mismatch(model, source, "unexpected-required-column") : { result: { ok: true } });
          expect(events).toStrictEqual([]);
          expect(snapshot(database)).toStrictEqual(empty);
          expect(observeSqliteCatalog(database, model, "Preflight must preserve the table")).toStrictEqual(catalog);
          if (mode === "required") return;

          seed(database, model);
          const initial = snapshot(database);
          const { adapter } = await auth.$context;
          const input = data(model);
          const visible = (value: string) => ({ ...input, [destination]: `stored:${value}`, [source]: `visible:stored:${value}` });
          const stored = (value: string) => raw({
            ...input, [destination]: `stored:${value}`, [source]: mode === "default" ? "legacy-default" : null,
          });
          const where = [{ field: "id", value: id }];
          const checkStorage = (value: string) => {
            expect(snapshot(database)).toStrictEqual({ ...initial, [model]: [stored(value)] });
            expect(observeSqliteCatalog(database, model, "CRUD must preserve the table")).toStrictEqual(catalog);
          };
          expect(await adapter.create({ model, forceAllowId: true, data: input })).toStrictEqual(visible("source"));
          expect(events).toStrictEqual([["input", source, "source"], ["output", source, "stored:source"]]);
          checkStorage("source");
          events.length = 0;
          expect(await adapter.findOne({ model, where })).toStrictEqual(visible("source"));
          expect(events).toStrictEqual([["output", source, "stored:source"]]);
          checkStorage("source");
          events.length = 0;
          expect(await adapter.update({ model, where, update: {
            [source]: "next", ...(model === "passkey" ? {} : { updatedAt: date }),
          } })).toStrictEqual(visible("next"));
          expect(events).toStrictEqual([["input", source, "next"], ["output", source, "stored:next"]]);
          checkStorage("next");
          events.length = 0;
          expect(await adapter.findMany({ model, where })).toStrictEqual([visible("next")]);
          expect(events).toStrictEqual([["output", source, "stored:next"]]);
          checkStorage("next");
          events.length = 0;
          expect(await adapter.delete({ model, where })).toBeUndefined();
          expect(await adapter.findOne({ model, where })).toBeNull();
          expect(events).toStrictEqual([]);
          expect(snapshot(database)).toStrictEqual(initial);
          expect(observeSqliteCatalog(database, model, "Deletion must preserve the table")).toStrictEqual(catalog);
        } finally { database.close(); }
      });
    });
  }
}

for (const mode of ["missing-alias", "both-columns", "missing-primary-key"] as const satisfies readonly IdMode[]) {
  test(`SQLite explicit ID mapping requires both physical columns: ${mode}`, async () => {
    await withRestoredSchema(passkey().schema, async () => {
      const database = new Database(":memory:");
      const events: Events = [];
      const options = base(database);
      try {
        await (await getMigrations(options)).runMigrations();
        const original = observeSqliteCatalog(database, "user", "The User table must exist");
        if (mode === "both-columns") database.exec('ALTER TABLE "user" ADD COLUMN "legacyId" TEXT');
        if (mode === "missing-primary-key") database.exec('ALTER TABLE "user" RENAME COLUMN "id" TO "legacyId"');
        const catalog = observeSqliteCatalog(database, "user", "The User table must remain present");
        const renamed = (column: { name: string | null }) => column.name === "id" ? { ...column, name: "legacyId" } : column;
        expect(catalog.catalog).toStrictEqual({
          ...original.catalog,
          columns: mode === "missing-primary-key" ? original.catalog.columns.map(renamed) : [
            ...original.catalog.columns,
            ...(mode === "both-columns" ? [{ cid: original.catalog.columns.length, name: "legacyId", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 }] : []),
          ],
          indexes: mode === "missing-primary-key" ? original.catalog.indexes.map(index => ({
            ...index, columns: index.columns.map(renamed), extendedColumns: index.extendedColumns.map(renamed),
          })) : original.catalog.indexes,
        });
        const empty = Object.fromEntries(tables.map(table => [table, database.query(`SELECT * FROM "${table}"`).all()]));
        expect(empty).toStrictEqual(Object.fromEntries(tables.map(table => [table, []])));
        // Adapter input and output replace the runtime ID declaration, so preflight must run before any CRUD.
        options.plugins!.push({ id: "explicit-id-preflight", schema: { user: { fields: { id: field("id", "legacyId", events) } } } });
        expect(await outcome(betterAuth(options))).toStrictEqual(mode === "both-columns"
          ? { result: { ok: true } }
          : mismatch("user", mode === "missing-alias" ? "legacyId" : "id", "missing-column"));
        expect(events).toStrictEqual([]);
        expect(Object.fromEntries(tables.map(table => [table, database.query(`SELECT * FROM "${table}"`).all()]))).toStrictEqual(empty);
        expect(observeSqliteCatalog(database, "user", "ID preflight must preserve the table")).toStrictEqual(catalog);
      } finally { database.close(); }
    });
  });
}
