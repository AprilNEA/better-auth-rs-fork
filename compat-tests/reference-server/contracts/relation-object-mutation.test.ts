import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import type { DBFieldAttribute } from "@better-auth/core/db";

type Row = Record<string, unknown>;
type Fields = Record<string, DBFieldAttribute>;
type Target = "user" | "account" | "team";
type Backend = "memory" | "sqlite";
const date = new Date("2030-01-01T00:00:00.000Z");
const collision = "stored-parent-property";
const user = (id: string, name: string): Row => ({
  id, name, email: `${id}@relation-object-mutation.test`, emailVerified: true,
  image: null, createdAt: date, updatedAt: date,
});
const account = (id: string, accessToken: string, userId: string): Row => ({
  id, accountId: id, providerId: "provider", userId, accessToken, refreshToken: "refresh",
  idToken: "id-token", accessTokenExpiresAt: date, refreshTokenExpiresAt: date,
  scope: "read", password: "password", createdAt: date, updatedAt: date,
});

async function check(backend: Backend, target: Target, joins: boolean, reject: boolean) {
  const many = target !== "account";
  const child = target === "team" ? "teamMember" : target === "user" ? "account" : "user";
  const physical = target === "team" ? "linked_team_member" : `linked_${child}`;
  const parentTable = `linked_${target}`;
  const changedField = child === "teamMember" ? "userId" : child === "account" ? "accessToken" : "name";
  const deletedField = child === "teamMember" ? "createdAt" : child === "account" ? "refreshToken" : "image";
  const memory: Record<string, Row[]> = { user: [], account: [], session: [], verification: [] };
  const database = backend === "sqlite" ? new Database(":memory:") : undefined;
  const baseFields: Fields = {
    [physical]: { type: "string" },
    relationMirror: { type: "string", fieldName: physical },
  };
  const configure = (parentFields: Fields, childFields: Fields, native: boolean): BetterAuthOptions => {
    const plugin = organization({ teams: { enabled: true } });
    const schema = { ...plugin.schema };
    if (target === "team") {
      schema.team = { ...schema.team, modelName: parentTable, fields: { ...schema.team.fields, ...parentFields } };
      schema.teamMember = { ...schema.teamMember, modelName: physical, fields: { ...schema.teamMember.fields, ...childFields } };
    }
    return {
      database: database ?? memoryAdapter(memory), baseURL: "http://relation-object-mutation.test",
      secret: "relation-object-mutation-secret-at-least-thirty-two-characters",
      logger: { disabled: true }, telemetry: { enabled: false },
      advanced: { database: { joins: native } },
      user: { modelName: "linked_user", additionalFields: target === "user" ? parentFields : target === "account" ? childFields : {} },
      account: { modelName: "linked_account", additionalFields: target === "account" ? parentFields : target === "user" ? childFields : {} },
      plugins: target === "team" ? [{ ...plugin, schema }] : [],
    };
  };
  try {
    const options = configure(baseFields, {}, false);
    if (database) {
      await (await getMigrations(options)).runMigrations();
      database.exec("PRAGMA foreign_keys = OFF");
    }
    const parent = {
      ...(target === "user" ? user("parent", "Parent") : target === "account" ? account("parent", "Parent", "child") : {
        id: "parent", name: "Parent", memberCount: 2, organizationId: "organization", createdAt: date, updatedAt: null,
      }),
      [physical]: collision,
    };
    const children = target === "user" ? [account("child", "Before", "parent"), account("second", "Second", "parent")]
      : target === "account" ? [user("child", "Before")]
      : ["Before", "Second"].map((userId, index) => ({ id: index ? "second" : "child", teamId: "parent", userId, membershipKey: `membership:${index}`, createdAt: date }));
    const stored = (row: Row): Row => Object.fromEntries(Object.entries(row).map(([name, value]) => [name,
      database ? value instanceof Date ? value.toISOString() : typeof value === "boolean" ? Number(value) : value : value,
    ]));
    const insert = (table: string, rows: Row[]) => {
      if (!database) { memory[table] = rows.map(row => structuredClone(row)); return; }
      for (const row of rows.map(stored)) {
        const names = Object.keys(row);
        database.query(`INSERT INTO "${table}" (${names.map(name => `"${name}"`).join(",")}) VALUES (${names.map(() => "?").join(",")})`).run(...Object.values(row) as (string | number | null)[]);
      }
    };
    insert(parentTable, [parent]);
    insert(physical, children);
    const storage = (table: string): Row[] => database
      ? database.query(`SELECT * FROM "${table}" ORDER BY rowid`).all() as Row[] : memory[table];
    const beforeParent = structuredClone(storage(parentTable));
    const beforeChildren = structuredClone(storage(physical));
    const rawKeys = backend === "memory" ? Object.keys(beforeChildren[0])
      : child === "user" ? ["name", "email", "emailVerified", "image", "createdAt", "updatedAt", "id"]
      : child === "account" ? ["accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt", "id"]
      : ["teamId", "userId", "membershipKey", "createdAt", "id"];
    const mutatedKeys = [...rawKeys.filter(key => key !== deletedField), "mutationOwn", "mutationTail"];
    const joined = (rows: Row[]) => many ? rows : rows[0];
    const where = [{ field: "id", value: "parent" }];
    const plain = (await betterAuth(options).$context).adapter;
    const baseline = await plain.findOne<Row>({ model: target, where, join: { [child]: true } });
    expect(baseline).not.toBeNull();
    const visibleBefore = many ? baseline![child] as Row[] : [baseline![child] as Row];
    const rawBefore = joins ? joined(beforeChildren) : collision;
    const changed = structuredClone(beforeChildren);
    if (joins) {
      changed[0].id = 9;
      changed[0][changedField] = 7;
      delete changed[0][deletedField];
      changed[0].mutationOwn = undefined;
      changed[0].mutationTail = "last";
    }
    const rawAfter = joins ? joined(changed) : collision;
    const events: unknown[][] = [];
    let captured: unknown;
    let capturedChild: Row | undefined;
    const failure = new TypeError("relation-object-mutation-rejected");
    const parentFields: Fields = {
      [physical]: { type: "string", transform: { output(value) {
        expect(value).toStrictEqual(rawBefore);
        captured = value;
        events.push(["collision", structuredClone(value)]);
        if (joins) {
          const object = (many ? (value as Row[])[0] : value) as Row;
          capturedChild = object;
          const keys = Object.keys(object);
          expect(keys).toStrictEqual(rawKeys);
          object.id = 9;
          object[changedField] = 7;
          expect(delete object[deletedField]).toBe(true);
          object.mutationTail = "first";
          object.mutationOwn = undefined;
          expect(delete object.mutationTail).toBe(true);
          object.mutationTail = "last";
          expect(Object.hasOwn(object, deletedField)).toBe(false);
          expect(Object.hasOwn(object, "mutationOwn")).toBe(true);
          expect(Object.keys(object)).toStrictEqual([...keys.filter(key => key !== deletedField), "mutationOwn", "mutationTail"]);
        }
        expect(value).toStrictEqual(rawAfter);
        events.push(["mutation", structuredClone(value)]);
        if (reject) throw failure;
        return value;
      } } },
      relationMirror: { type: "string", fieldName: physical, transform: { output(value) {
        expect(value).toBe(captured);
        expect(value).toStrictEqual(rawAfter);
        if (joins) expect(many ? (value as Row[])[0] : value).toBe(capturedChild);
        events.push(["mirror", structuredClone(value)]);
        return value;
      } } },
    };
    const childFields: Fields = {};
    for (const [index, name] of [changedField, deletedField].entries()) {
      childFields[name] = {
        type: name === "createdAt" ? "date" : "string",
        onUpdate() { events.push(["unexpected-onUpdate", name]); return undefined; },
        transform: {
          input(value) { events.push(["unexpected-input", name, value]); return value; },
          output(value) { events.push([index ? "deleted" : "value", value]); return value; },
        },
      };
    }
    const reader = (await betterAuth(configure(parentFields, childFields, joins)).$context).adapter;
    const operation = () => reader.findOne<Row>({ model: target, where, join: { [child]: true } });
    const expectedEvents: unknown[][] = [["collision", rawBefore], ["mutation", rawAfter]];
    if (reject) {
      let caught: unknown;
      try { await operation(); } catch (error) { caught = error; }
      expect(caught).toBe(failure);
    } else {
      const output = await operation();
      const visible = visibleBefore.map((row, index) => joins && index === 0
        ? { ...row, id: "9", [changedField]: 7, [deletedField]: undefined } : row);
      expectedEvents.push(["mirror", rawAfter]);
      for (const row of changed) expectedEvents.push(["value", row[changedField]], ["deleted", row[deletedField]]);
      expect(output).toStrictEqual({ ...baseline, [physical]: rawAfter, relationMirror: rawAfter, [child]: joined(visible) });
      expect(Object.keys(output!)).toStrictEqual(Object.keys(baseline!));
      expect(output![physical]).toBe(captured);
      expect(output!.relationMirror).toBe(captured);
      const first = (many ? (output![child] as Row[])[0] : output![child]) as Row;
      expect(Object.keys(first)).toStrictEqual(Object.keys(visibleBefore[0]));
      expect(Object.hasOwn(first, deletedField)).toBe(true);
      expect(Object.hasOwn(first, "mutationOwn")).toBe(false);
      if (joins) {
        expect(first).not.toBe(capturedChild);
        if (many) expect(output![child]).not.toBe(captured);
        if (backend === "memory" && target !== "team") expect(first.createdAt).toBe(capturedChild!.createdAt);
      }
    }
    expect(events).toStrictEqual(expectedEvents);
    expect(storage(parentTable)).toStrictEqual(beforeParent);
    expect(storage(physical)).toStrictEqual(backend === "memory" ? changed : beforeChildren);
    if (joins && backend === "memory") expect(storage(physical)[0]).toBe(capturedChild);
    if (joins) expect(Object.keys(capturedChild!)).toStrictEqual(mutatedKeys);
  } finally { database?.close(); }
}

for (const backend of ["memory", "sqlite"] as const) for (const target of ["user", "account", "team"] as const) {
  for (const joins of [false, true]) for (const reject of [false, true]) {
    test(`${backend} ${target} relation-object mutation joins=${joins}, reject=${reject}`, () => check(backend, target, joins, reject));
  }
}
