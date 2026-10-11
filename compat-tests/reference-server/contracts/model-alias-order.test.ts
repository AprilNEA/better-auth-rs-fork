import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);
const { initGetDefaultModelName } = await import(new URL("../node_modules/@better-auth/core/dist/db/adapter/get-default-model-name.mjs", import.meta.url).href);
const date = () => new Date("2030-01-01T00:00:00.000Z");
const membershipKey = createHash("sha256").update(JSON.stringify(["team-a", "user-a"])).digest("base64url");
type Fields = Record<string, unknown>;

for (const backend of ["memory", "sqlite"] as const) {
  for (const before of [true, false]) for (const reference of ["shared", "team"]) for (const joins of [false, true]) {
    test(`${backend} native and custom shared aliases follow ${before ? "custom-first" : "native-first"} registration with ${reference} reference and joins=${joins}`, async () => {
      let enabled = false;
      const events: unknown[][] = [];
      const output = (field: string) => (value: unknown) => {
        if (enabled) {
          events.push([field, value]);
          if (field === "team.name") return `Visible ${value}`;
        }
        return value;
      };
      const observed = (field: string): DBFieldAttribute => ({ type: "string", transform: { output: output(field) } });
      const badge = { id: "model-alias-badge", schema: {
        badge: { modelName: "shared", fields: { label: observed("badge.label") } },
      } };
      const own = organization({ teams: { enabled: true }, schema: { team: { modelName: "shared" } } });
      const policies = (target: string) => ({ id: "model-alias-policies", schema: {
        team: { modelName: "shared", fields: {
          name: observed("team.name"), updatedAt: { type: "date" as const, onUpdate: date },
        } },
        teamMember: { fields: {
          teamId: { ...observed("teamMember.teamId"), references: { model: target, field: "id" } },
          userId: observed("teamMember.userId"), membershipKey: observed("teamMember.membershipKey"),
          createdAt: { type: "date" as const, transform: { input: date, output: output("teamMember.createdAt") } },
        } },
      } });
      const memory: Record<string, Fields[]> = Object.fromEntries([
        "user", "session", "account", "verification", "organization", "member", "invitation", "shared", "teamMember",
      ].map(model => [model, []]));
      const sqlite = backend === "sqlite" ? new Database(":memory:") : undefined;
      const options: BetterAuthOptions = {
        database: sqlite ?? memoryAdapter(memory), baseURL: "http://model-alias-order.test",
        secret: "model-alias-order-contract-at-least-thirty-two-characters",
        logger: { disabled: true }, telemetry: { enabled: false }, advanced: { database: { joins } },
        plugins: [own, policies("team")],
      };
      const stored = (row: Fields) => Object.fromEntries(Object.entries(row).map(([name, value]) => [
        name, backend === "sqlite" && value instanceof Date ? value.toISOString() : value,
      ]));
      const team = { name: "Team A", memberCount: 1, organizationId: "organization", createdAt: date(), updatedAt: date(), id: "team-a" };
      const member = { teamId: "team-a", userId: "user-a", membershipKey, createdAt: date(), id: "member-a" };
      const snapshot = () => ({
        teams: structuredClone(sqlite ? sqlite.query("SELECT * FROM shared ORDER BY id").all() : memory.shared),
        members: structuredClone(sqlite ? sqlite.query("SELECT * FROM teamMember ORDER BY id").all() : memory.teamMember),
      });
      const expectedStorage = { teams: [stored(team)], members: [stored(member)] };
      try {
        if (sqlite) await (await getMigrations(options)).runMigrations();
        const writer = (await betterAuth(options).$context).adapter;
        await writer.create({ model: "user", forceAllowId: true, data: {
          id: "user-a", name: "User A", email: "user-a@model-alias-order.test", emailVerified: false,
          image: null, createdAt: date(), updatedAt: date(),
        } });
        await writer.create({ model: "organization", forceAllowId: true, data: {
          id: "organization", name: "Organization", slug: "organization", logo: null, metadata: "{}", createdAt: date(),
        } });
        await writer.create({ model: "team", forceAllowId: true, data: team });
        await writer.create({ model: "teamMember", forceAllowId: true, data: member });
        expect(snapshot()).toStrictEqual(expectedStorage);
        const reading = { ...options, plugins: before ? [badge, own, policies(reference)] : [own, badge, policies(reference)] };
        const tableNames = Object.keys(getAuthTables(reading));
        expect(tableNames.indexOf("badge") < tableNames.indexOf("team")).toBe(before);
        const context = await betterAuth(reading).$context;
        const org = getOrgAdapter(context, { teams: { enabled: true } });
        const publicTeam = { name: "Visible Team A", organizationId: "organization", createdAt: date(), updatedAt: date(), id: "team-a" };
        enabled = true;
        expect(await context.adapter.findOne({ model: "team", where: [{ field: "id", value: "team-a" }] }))
          .toStrictEqual({ ...team, name: "Visible Team A" });
        expect(events.splice(0)).toStrictEqual([["team.name", "Team A"]]);
        for (const userId of ["user-a", "missing"]) {
          if (before && reference === "shared") {
            let failure: unknown;
            try { await org.listTeamsByUser({ userId }); } catch (error) { failure = error; }
            expect(failure).toBeInstanceOf(Error);
            expect((failure as Error).name).toBe("BetterAuthError");
            expect((failure as Error).message).toBe("No foreign key found for model team and base model teamMember while performing join operation.");
            expect(Object.keys(failure as Error)).toStrictEqual(["name"]);
            expect(events.splice(0)).toStrictEqual([]);
          } else {
            expect(await org.listTeamsByUser({ userId })).toStrictEqual(userId === "missing" ? [] : [publicTeam]);
            expect(events.splice(0)).toStrictEqual(userId === "missing" ? [] : [
              ["teamMember.teamId", "team-a"], ["teamMember.userId", "user-a"],
              ["teamMember.membershipKey", membershipKey], ["teamMember.createdAt", backend === "sqlite" ? date().toISOString() : date()],
              ["team.name", "Team A"],
            ]);
          }
          expect(snapshot()).toStrictEqual(expectedStorage);
        }
      } finally { sqlite?.close(); }
    });
  }
}

test("native modelName omission and empty values replace aliases without changing the original schema position", () => {
  for (const modelName of [undefined, ""]) {
    const options: BetterAuthOptions = { plugins: [
      { id: "first", schema: { badge: { modelName: "shared", fields: {} } } },
      organization({ teams: { enabled: true }, schema: { team: { modelName: "shared" } } }),
      { id: "reset", schema: { team: { modelName, fields: {} } } },
    ] };
    const schema = getAuthTables(options);
    const resolve = initGetDefaultModelName({ usePlural: false, schema });
    expect(schema.team?.modelName).toBe("team");
    expect(resolve("shared")).toBe("badge");
    expect(resolve("team")).toBe("team");
    expect(Object.keys(schema).indexOf("badge") < Object.keys(schema).indexOf("team")).toBe(true);
  }
});

function expectModel(schema: ReturnType<typeof getAuthTables>, candidate: string, expected: string | null) {
  const resolve = initGetDefaultModelName({ usePlural: false, schema });
  if (expected !== null) {
    expect(resolve(candidate)).toBe(expected);
    return;
  }
  let failure: unknown;
  try { resolve(candidate); } catch (error) { failure = error; }
  expect(failure).toBeInstanceOf(Error);
  expect({ name: (failure as Error).name, message: (failure as Error).message, keys: Object.keys(failure as Error) })
    .toStrictEqual({ name: "BetterAuthError", message: `Model "${candidate}" not found in schema`, keys: ["name"] });
}

test("explicit native models and memory rateLimit retain logical names and aliases without matching plugins", () => {
  const events: unknown[] = [];
  const marker: DBFieldAttribute = { type: "string", transform: { output(value) { events.push(value); return value; } } };
  const schema = getAuthTables({ rateLimit: { storage: "memory" }, plugins: [{ id: "declarations", schema: {
    passkey: { modelName: "key_store", fields: { marker } },
    rateLimit: { modelName: "counter_store", fields: { marker } },
  } }] });
  expect(Object.keys(schema)).toStrictEqual(["user", "session", "account", "verification", "passkey", "rateLimit"]);
  for (const [name, alias] of [["passkey", "key_store"], ["rateLimit", "counter_store"]]) {
    expectModel(schema, name, name);
    expectModel(schema, alias, name);
    expect(schema[name].modelName).toBe(alias);
    expect(Object.keys(schema[name].fields)).toStrictEqual(["marker"]);
  }
  expect(events).toStrictEqual([]);
});

test("organizationRole visibility retains explicit declarations and declaration-order alias precedence", () => {
  for (const explicitBefore of [false, true]) for (const enabled of [false, true]) {
    const events: unknown[] = [];
    const marker: DBFieldAttribute = { type: "string", transform: { output(value) { events.push(value); return value; } } };
    const schema = getAuthTables({ plugins: [
      ...(explicitBefore ? [{ id: "explicit-role", schema: { organizationRole: { modelName: "shared", fields: { marker } } } }] : []),
      organization({ teams: { enabled: true }, dynamicAccessControl: { enabled } }),
      { id: "aliases", schema: {
        ...(enabled ? { organizationRole: { modelName: "shared", fields: {} } } : {}),
        team: { modelName: "shared", fields: {} },
      } },
    ] });
    expect(Object.keys(schema)).toStrictEqual([
      "user", "session", "account", "verification",
      ...(explicitBefore ? ["organizationRole"] : []), "organization",
      ...(enabled && !explicitBefore ? ["organizationRole"] : []),
      "team", "teamMember", "member", "invitation",
    ]);
    expect(Object.keys(schema.organizationRole?.fields ?? {})).toStrictEqual([
      ...(explicitBefore ? ["marker"] : []),
      ...(enabled ? ["organizationId", "role", "permission", "createdAt", "updatedAt"] : []),
    ]);
    expectModel(schema, "team", "team");
    expectModel(schema, "organizationRole", explicitBefore || enabled ? "organizationRole" : null);
    expectModel(schema, "shared", explicitBefore || enabled ? "organizationRole" : "team");
    expect(events).toStrictEqual([]);
  }
});

test("secondary storage hides explicitly declared session and verification until database persistence is enabled", () => {
  for (const storeCore of [false, true]) {
    const events: unknown[] = [];
    const marker: DBFieldAttribute = { type: "string", transform: { output(value) { events.push(value); return value; } } };
    const schema = getAuthTables({
      secondaryStorage: { async get() { return null; }, async set() {}, async delete() {} },
      session: { modelName: "session_store", storeSessionInDatabase: storeCore },
      verification: { modelName: "verification_store", storeInDatabase: storeCore },
      plugins: [{ id: "explicit-core", schema: { session: { fields: { marker } }, verification: { fields: { marker } } } }],
    });
    expect(Object.keys(schema)).toStrictEqual(storeCore ? ["user", "session", "account", "verification"] : ["user", "account"]);
    for (const [name, alias] of [["session", "session_store"], ["verification", "verification_store"]]) {
      expectModel(schema, name, storeCore ? name : null);
      expectModel(schema, alias, storeCore ? name : null);
    }
    expect(events).toStrictEqual([]);
  }
});

test("a matching plugin ID does not declare a native model but an explicit empty schema does", () => {
  for (const declared of [false, true]) {
    const schema = getAuthTables({ plugins: [{ id: "passkey", ...(declared ? { schema: { passkey: { fields: {} } } } : {}) }] });
    expect(Object.keys(schema)).toStrictEqual(["user", "session", "account", "verification", ...(declared ? ["passkey"] : [])]);
    expectModel(schema, "passkey", declared ? "passkey" : null);
  }
});
