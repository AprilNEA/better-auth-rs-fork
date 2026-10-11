import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute, Where } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import cases from "../../../tests/fixtures/sparse-native-join-cases.json";
import { observe, revive } from "./user-runtime-contract";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
type Row = Record<string, unknown>;
type Declaration = { fieldName?: string; references?: string };
type FixtureInput = {
  tables: { model: string; table: string; columns: Record<string, string | undefined>; rows: Record<string, string | number | null | undefined>[] }[];
  declarations: Record<string, Record<string, Declaration>>;
};

async function setup(joins: boolean, rejectAt?: string, input: FixtureInput = cases) {
  const database = new Database(":memory:");
  const events: unknown[][] = [];
  const failure = new Error("sparse-native-output-rejected");
  for (const table of input.tables) {
    const columns = Object.entries(table.columns).map(([name, kind]) => `"${name}" ${kind}`).join(", ");
    database.exec(`CREATE TABLE "${table.table}" (${columns})`);
    for (const row of table.rows) {
      const names = Object.keys(row).map(name => `"${name}"`).join(", ");
      const markers = Object.keys(row).map(() => "?").join(", ");
      database.query(`INSERT INTO "${table.table}" (${names}) VALUES (${markers})`).run(...Object.values(row));
    }
  }
  const field = (label: string, declaration: Declaration = {}): DBFieldAttribute => ({
    type: "string",
    ...(declaration.fieldName ? { fieldName: declaration.fieldName } : {}),
    ...(declaration.references ? { references: { model: declaration.references, field: "id" } } : {}),
    transform: { output(value) {
      events.push([label, observe(value)]);
      if (label === rejectAt) throw failure;
      if (label.endsWith(".name")) {
        expect(typeof value).toBe("number");
        return `visible:${value}`;
      }
      return value;
    } },
  });
  const schema = Object.fromEntries(Object.entries(input.declarations).map(([model, fields]) => [model, {
    modelName: input.tables.find(table => table.model === model)!.table,
    fields: Object.fromEntries(Object.entries(fields).map(([name, declaration]) => [name, field(`${model}.${name}`, declaration)])),
  }]));
  const context = await betterAuth({
    database,
    baseURL: "http://sparse-native.test",
    secret: "sparse-native-join-contract-at-least-thirty-two-characters",
    logger: { disabled: true }, telemetry: { enabled: false },
    advanced: { database: { joins } },
    user: {
      modelName: "users",
      fields: { emailVerified: "email_verified", createdAt: "created_at", updatedAt: "updated_at" },
      additionalFields: { name: field("user.name") },
    },
    plugins: [{ id: "sparse-native-fields", schema }],
  }).$context;
  const adapter = getOrgAdapter(context, { teams: { enabled: true } });
  const read = (path: string, selector: unknown = path === "full" ? "organization" : path) => path === "team"
    ? adapter.findTeamById({ teamId: selector, includeTeamMembers: true })
    : path === "member"
      ? adapter.findMemberById(selector)
      : adapter.findFullOrganization({ organizationId: selector, includeTeams: true });
  const snapshot = () => Object.fromEntries(input.tables.map(({ table }) => [table, {
    columns: database.query(`PRAGMA table_info("${table}")`).all().map(row => (row as { name: string }).name),
    rows: database.query(`SELECT * FROM "${table}" ORDER BY id`).all(),
  }]));
  return { database, events, failure, read, snapshot, internalAdapter: context.internalAdapter, adapter: context.adapter };
}

for (const query of cases.adapterCounts) {
  test(`SQLite adapter count excludes null IDs without output conversion: ${query.model}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const table = input.tables.find(table => table.model === query.model)!;
    table.columns.id = "TEXT";
    table.rows.push({ ...table.rows[0], id: null }, { ...table.rows[0], id: "excluded", [query.column]: "another-owner" });
    const fixture = await setup(false, undefined, input);
    try {
      const before = fixture.snapshot();
      const where = [{ field: query.field, value: query.value }];
      expect(await fixture.adapter.count({ model: query.model, where })).toStrictEqual(query.total);
      expect(fixture.events).toStrictEqual([]);
      expect(fixture.snapshot()).toStrictEqual(before);
      if (query.model === "apikey") {
        const actual = await fixture.adapter.findMany({ model: query.model, where });
        expect(actual).toStrictEqual(cases.nullableApiKey.result);
        assertKeys(actual, cases.nullableApiKey.result);
        expect(fixture.events).toStrictEqual(cases.nullableApiKey.events);
        expect(fixture.snapshot()).toStrictEqual(before);
      }
    } finally { fixture.database.close(); }
  });
}

for (const query of cases.nullableUser.queries) {
  test(`SQLite nullable User IDs preserve pages and literal id counts: ${query.name}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const table = input.tables.find(table => table.model === "user")!;
    table.columns.id = "TEXT";
    table.rows.push(cases.nullableUser.row);
    const fixture = await setup(false, undefined, input);
    try {
      const before = fixture.snapshot();
      const filter = "filter" in query ? query.filter : undefined;
      if (filter && filter.operator !== "eq") throw new Error("Nullable User count cases must use equality");
      const where: Where[] | undefined = filter ? [{ field: filter.field, operator: "eq", value: filter.value }] : undefined;
      const users = await fixture.internalAdapter.listUsers(query.limit, query.offset, { field: "name", direction: "asc" }, where);
      const total = await fixture.internalAdapter.countTotalUsers(where);
      const actual = { users, total };
      const expected = revive({ users: [cases.nullableUser.result], total: query.total });
      expect(actual).toStrictEqual(expected);
      assertKeys(actual, expected);
      expect(fixture.events).toStrictEqual(cases.nullableUser.events);
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

for (const joins of [false, true]) for (const populated of [false, true]) {
  test(`SQLite sparse child id=null joins=${joins} populated=${populated}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const table = input.tables.find(table => table.model === "teamMember")!;
    table.columns.id = "TEXT";
    table.rows = populated ? cases.nullableChildRows : [];
    const fixture = await setup(joins, undefined, input);
    try {
      const before = fixture.snapshot();
      const rows = populated ? cases.nullableChildRows : [];
      const expected = { ...cases.cases[0].result, members: rows.map(row => ({ teamId: row.team_id, id: row.id })) };
      const actual = await fixture.read("team");
      expect(actual).toStrictEqual(expected);
      assertKeys(actual, expected);
      expect(fixture.events).toStrictEqual([
        ...cases.cases[0].events.slice(0, 2),
        ...rows.map(() => cases.cases[0].events[2]),
      ]);
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

for (const joins of [false, true]) {
  test(`SQLite zero child IDs retain duplicates before ID conversion joins=${joins}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const table = input.tables.find(table => table.model === "teamMember")!;
    table.columns.id = "INTEGER";
    table.rows = cases.zeroChildRows;
    const fixture = await setup(joins, undefined, input);
    try {
      const before = fixture.snapshot();
      const expected = { ...cases.cases[0].result, members: [{ teamId: "team", id: "0" }, { teamId: "team", id: "0" }] };
      const actual = await fixture.read("team");
      expect(actual).toStrictEqual(expected);
      assertKeys(actual, expected);
      expect(fixture.events).toStrictEqual([...cases.cases[0].events, cases.cases[0].events[2]]);
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

for (const joins of [false, true]) for (const row of cases.falsyParentCases) {
  test(`SQLite falsy parent ${row.path} id=${JSON.stringify(row.id)} joins=${joins}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const table = input.tables.find(table => table.model === row.model)!;
    table.columns.id = row.idType;
    table.rows[0].id = row.id;
    const fixture = await setup(joins, undefined, input);
    try {
      const before = fixture.snapshot();
      const expected = joins ? null : row.result;
      const actual = await fixture.read(row.path, row.id);
      expect(actual).toStrictEqual(expected);
      assertKeys(actual, expected);
      expect(fixture.events).toStrictEqual(joins ? [] : row.events);
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

for (const column of [cases.aliasCollision.column, cases.aliasCollision.alternateColumn]) for (const joins of [false, true]) for (const populated of [false, true]) {
  test(`SQLite reserved child alias ${column} retains own undefined joins=${joins} populated=${populated}`, async () => {
    const input: FixtureInput = structuredClone(cases);
    const collision = cases.aliasCollision;
    const table = input.tables.find(table => table.model === "team")!;
    table.columns[column] = "TEXT";
    table.rows[0][column] = collision.value;
    if (!populated) input.tables.find(table => table.model === "teamMember")!.rows = [];
    input.declarations.team.shadow = { fieldName: column };
    const fixture = await setup(joins, undefined, input);
    try {
      const before = fixture.snapshot();
      const expected = revive(joins ? collision.nativeResult : collision.fallbackResult);
      const events = structuredClone(joins ? collision.nativeEvents : collision.fallbackEvents);
      if (!populated) { expected.members = []; events.pop(); }
      const actual = await fixture.read("team");
      expect(actual).toStrictEqual(expected);
      assertKeys(actual, expected);
      expect(fixture.events).toStrictEqual(events);
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

function assertKeys(actual: unknown, expected: unknown) {
  if (expected === null || typeof expected !== "object") return;
  expect(Object.keys(actual as object)).toStrictEqual(Object.keys(expected));
  for (const [name, value] of Object.entries(expected)) assertKeys((actual as Row)[name], value);
}

for (const joins of [false, true]) for (const row of cases.cases) for (const reject of [false, true]) {
  test(`SQLite sparse ${row.path} joins=${joins} reject=${reject}`, async () => {
    const fixture = await setup(joins, reject ? row.rejectAt : undefined);
    try {
      const before = fixture.snapshot();
      expect(fixture.events).toStrictEqual([]);
      const result = fixture.read(row.path);
      if (reject) await expect(result).rejects.toBe(fixture.failure);
      else {
        const actual = await result;
        expect(actual).toStrictEqual(row.result);
        assertKeys(actual, row.result);
      }
      const end = reject ? row.events.findIndex(event => event[0] === row.rejectAt) + 1 : row.events.length;
      expect(fixture.events).toStrictEqual(row.events.slice(0, end));
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}

for (const joins of [false, true]) {
  test(`SQLite missing declared child column preserves callback order joins=${joins}`, async () => {
    const fixture = await setup(joins);
    try {
      fixture.database.exec("ALTER TABLE team_member DROP COLUMN team_id");
      const before = fixture.snapshot();
      await expect(fixture.read("team")).rejects.toThrow("no such column");
      expect(fixture.events).toStrictEqual(joins ? [] : cases.cases[0].events.slice(0, 2));
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.database.close(); }
  });
}
