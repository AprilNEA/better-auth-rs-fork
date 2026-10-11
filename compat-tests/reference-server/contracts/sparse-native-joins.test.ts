import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import cases from "../../../tests/fixtures/sparse-native-join-cases.json";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
type Row = Record<string, unknown>;
type Declaration = { fieldName?: string; references?: string };

async function setup(joins: boolean, rejectAt?: string, nullableChildren?: boolean) {
  const database = new Database(":memory:");
  const events: unknown[][] = [];
  const failure = new Error("sparse-native-output-rejected");
  for (const table of cases.tables) {
    const columns = Object.entries(table.columns).map(([name, kind]) => `"${name}" ${
      nullableChildren !== undefined && table.model === "teamMember" && name === "id" ? "TEXT" : kind
    }`).join(", ");
    database.exec(`CREATE TABLE "${table.table}" (${columns})`);
    const rows = nullableChildren !== undefined && table.model === "teamMember"
      ? nullableChildren ? cases.nullableChildRows : []
      : table.rows;
    for (const row of rows) {
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
      events.push([label, value]);
      if (label === rejectAt) throw failure;
      if (label.endsWith(".name")) {
        expect(typeof value).toBe("number");
        return `visible:${value}`;
      }
      return value;
    } },
  });
  const schema = Object.fromEntries(Object.entries(cases.declarations).map(([model, fields]) => [model, {
    modelName: cases.tables.find(table => table.model === model)!.table,
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
  const read = (path: string) => path === "team"
    ? adapter.findTeamById({ teamId: "team", includeTeamMembers: true })
    : path === "member"
      ? adapter.findMemberById("member")
      : adapter.findFullOrganization({ organizationId: "organization", includeTeams: true });
  const snapshot = () => Object.fromEntries(cases.tables.map(({ table }) => [table, {
    columns: database.query(`PRAGMA table_info("${table}")`).all().map(row => (row as { name: string }).name),
    rows: database.query(`SELECT * FROM "${table}" ORDER BY id`).all(),
  }]));
  return { database, events, failure, read, snapshot };
}

for (const joins of [false, true]) for (const populated of [false, true]) {
  test(`SQLite sparse child id=null joins=${joins} populated=${populated}`, async () => {
    const fixture = await setup(joins, undefined, populated);
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
