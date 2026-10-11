import { expect, test } from "bun:test";
import { toResponse } from "better-call";
import { Database } from "bun:sqlite";
import { getAuthTables } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { organization } from "better-auth/plugins";
import { expectOrdered, setup } from "./organization-invitation-response-contract";
import { date, membershipKey, type Events, type Fields } from "./organization-team-member-contract";
import { observeSqliteCatalog } from "./sqlite-catalog";

type Mode = "mapped-owner" | "moved-owner" | "deleted-team" | "invitation-error" | "after-error" | "hidden-id" | "wrong-projected-owner";
const modes: Mode[] = ["mapped-owner", "moved-owner", "deleted-team", "invitation-error", "after-error", "hidden-id", "wrong-projected-owner"];
type Fixture = Awaited<ReturnType<typeof setup>>;
const teamIds = "target-team,retained-team";

async function makeOriginalOwnerNullable(fixture: Fixture) {
  const database = fixture.options.database;
  if (!(database instanceof Database)) throw new Error("The mapped Team owner fixture requires SQLite");
  const before = fixture.snapshot();
  expect(before.team).toStrictEqual([]);
  expect(before.teamMember).toStrictEqual([]);
  const { catalog } = observeSqliteCatalog(database, "team", "The original Team table must exist");
  const owner = getAuthTables(fixture.options).team.fields.organizationId;
  // The reader maps organizationId to name, so the unused physical owner must allow an omitted value.
  database.exec('DROP TABLE "team"');
  await (await getMigrations({
    ...fixture.options,
    plugins: [...fixture.options.plugins!, { id: "nullable-physical-team-owner", schema: {
      team: { fields: { organizationId: { ...owner, required: false } } },
    } }],
  })).runMigrations();
  const rebuilt = observeSqliteCatalog(database, "team", "The rebuilt Team table must exist").catalog;
  expect(rebuilt).toStrictEqual({
    ...catalog,
    columns: catalog.columns.map(column => column.name === "organizationId" ? { ...column, notnull: 0 } : column),
  });
  expect(fixture.snapshot()).toStrictEqual(before);
}

function invitation(id: string, organizationId: string, teamId: string, status = "pending") {
  return {
    id, organizationId, email: "user-b@fields.test", role: "member", teamId, status,
    expiresAt: new Date("2100-01-01T00:00:00.000Z"), createdAt: date(0), inviterId: "user-a",
  };
}

async function seed(fixture: Fixture, mode: Mode) {
  const { adapter } = fixture.context;
  await adapter.deleteMany({ model: "invitation", where: [] });
  await adapter.create({ model: "organization", forceAllowId: true, data: {
    id: "other", name: "Other", slug: "other", logo: null, metadata: "{}", createdAt: date(0),
  } });
  for (const [id, name, owner] of [
    ["target-team", mode === "mapped-owner" ? "organization" : "Target", mode === "mapped-owner" ? "other" : "organization"],
    ["retained-team", "Retained", "organization"],
  ]) {
    await adapter.create({ model: "team", forceAllowId: true, data: {
      id, name, organizationId: owner, memberCount: 1, createdAt: date(0), updatedAt: date(0),
    } });
    await adapter.create({ model: "teamMember", forceAllowId: true, data: {
      id: id === "target-team" ? "target-team-member" : "retained-team-member",
      teamId: id, userId: "user-b", membershipKey: membershipKey(id, "user-b"), createdAt: date(0),
    } });
  }
  for (const row of [
    invitation("invitation-a", "organization", mode === "deleted-team" ? "retained-team" : teamIds),
    invitation("invitation-other", "other", teamIds),
    invitation("invitation-accepted", "organization", "target-team", "accepted"),
  ]) await adapter.create({ model: "invitation", forceAllowId: true, data: row });
}

function expectedHook(mode: Mode) {
  return {
    team: {
      name: mode === "mapped-owner" ? "organization" : "Target", organizationId: "organization",
      createdAt: date(0), updatedAt: date(0), ...(mode === "hidden-id" ? {} : { id: "target-team" }),
    },
    user: undefined,
    organization: {
      name: "Organization", slug: "organization", logo: null, createdAt: date(0), metadata: "{}", id: "organization",
    },
  };
}

function expectedEvents(mode: Mode): Events {
  const events: Events = [["team.organizationId", "output", "organization"]];
  if (mode === "wrong-projected-owner") return events;
  events.push(["beforeDeleteTeam", "hook", expectedHook(mode)]);
  if (mode === "deleted-team") events.push(["invitation.teamId", "output", "retained-team"]);
  events.push(["invitation.teamId", "output", teamIds]);
  if (mode === "invitation-error") return events;
  if (mode !== "hidden-id") events.push(
    ["invitation.teamId", "input", "retained-team"],
    ["invitation.teamId", "output", "retained-team"],
  );
  events.push(["afterDeleteTeam", "hook", expectedHook(mode)]);
  return events;
}

function authFor(fixture: Fixture, mode: Mode, events: Events, failure: Error) {
  let originalTeam: unknown;
  let originalOrganization: unknown;
  return betterAuth({
    ...fixture.options,
    plugins: [organization({
      teams: { enabled: true, allowRemovingAllTeams: true },
      ...(mode === "hidden-id" ? { schema: { team: { additionalFields: { id: { type: "string", returned: false } } } } } : {}),
      organizationHooks: {
        async beforeDeleteTeam(data) {
          originalTeam = data.team;
          originalOrganization = data.organization;
          events.push(["beforeDeleteTeam", "hook", data]);
          const { adapter } = fixture.context;
          if (mode === "moved-owner" || mode === "invitation-error") {
            await adapter.update({ model: "team", where: [{ field: "id", value: "target-team" }], update: {
              organizationId: "other", updatedAt: date(0),
            } });
          } else if (mode === "deleted-team") {
            await adapter.deleteMany({ model: "teamMember", where: [{ field: "teamId", value: "target-team" }] });
            await adapter.delete({ model: "team", where: [{ field: "id", value: "target-team" }] });
            await adapter.create({ model: "invitation", forceAllowId: true, data: invitation("invitation-recreated", "organization", teamIds) });
          }
        },
        async afterDeleteTeam(data) {
          expect(data.team).toBe(originalTeam);
          expect(data.organization).toBe(originalOrganization);
          events.push(["afterDeleteTeam", "hook", data]);
          if (mode === "after-error") throw failure;
        },
      },
    }), { id: "team-delete-context-fields", schema: {
      team: { fields: {
        organizationId: { type: "string", ...(mode === "mapped-owner" ? { fieldName: "name" } : {}), transform: {
          output(value) {
            events.push(["team.organizationId", "output", value]);
            return mode === "wrong-projected-owner" ? "other" : value;
          },
        } },
      } },
      invitation: { fields: {
        teamId: { type: "string", required: false, transform: {
          input(value) { events.push(["invitation.teamId", "input", value]); return value; },
          output(value) {
            events.push(["invitation.teamId", "output", value]);
            if (mode === "invitation-error") throw failure;
            return value;
          },
        } },
      } },
    } }],
  });
}

function expectedStorage(fixture: Fixture, before: Record<string, Fields[]>, mode: Mode) {
  const after = structuredClone(before);
  if (mode === "hidden-id" || mode === "wrong-projected-owner") return after;
  if (mode === "invitation-error") {
    after.team = after.team.map(row => row.id === "target-team" ? { ...row, organizationId: "other" } : row);
    return after;
  }
  after.team = after.team.filter(row => row.id !== "target-team");
  after.teamMember = after.teamMember.filter(row => row.teamId !== "target-team");
  after.invitation = after.invitation.map(row => row.id === "invitation-a" ? { ...row, teamId: "retained-team" } : row);
  if (mode === "deleted-team") {
    after.invitation.push(fixture.stored(invitation("invitation-recreated", "organization", "retained-team")));
    after.invitation.sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }
  return after;
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of modes) {
    test(`${backend} trusted Team deletion preserves ${mode} operation context, callbacks and complete storage`, async () => {
      const fixture = await setup(backend, { name: mode, route: "cancel", deleteBefore: true });
      try {
        if (backend === "sqlite" && mode === "mapped-owner") await makeOriginalOwnerNullable(fixture);
        await seed(fixture, mode);
        const before = fixture.snapshot();
        if (mode === "mapped-owner") expect(before.team.find(row => row.id === "target-team")?.organizationId).toBe("other");
        const events: Events = [];
        const failure = new Error(mode === "after-error" ? "team-after-hook-failed" : "team-invitation-output-failed");
        const auth = authFor(fixture, mode, events, failure);
        let actual: unknown;
        let caught: unknown;
        try { actual = await auth.api.removeTeam({ body: { teamId: "target-team", organizationId: "organization" } }); }
        catch (error) { caught = error; }
        if (mode === "wrong-projected-owner") {
          expect(caught).toMatchObject({ name: "APIError", statusCode: 400 });
          expectOrdered(Reflect.get(caught as object, "body"), { message: "Team not found", code: "TEAM_NOT_FOUND" });
          expect(await toResponse(caught).text()).toBe('{"message":"Team not found","code":"TEAM_NOT_FOUND"}');
          expect(actual).toBeUndefined();
        } else if (mode === "invitation-error" || mode === "after-error") {
          expect(caught).toBe(failure);
          expect(actual).toBeUndefined();
        } else {
          expect(caught).toBeUndefined();
          expectOrdered(actual, { message: "Team removed successfully." });
        }
        expectOrdered(events, expectedEvents(mode));
        expect(fixture.snapshot()).toStrictEqual(expectedStorage(fixture, before, mode));
      } finally { fixture.close(); }
    });
  }
}
