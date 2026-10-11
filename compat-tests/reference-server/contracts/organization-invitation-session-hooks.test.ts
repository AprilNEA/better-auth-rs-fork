import { expect, test } from "bun:test";
import { getCurrentAdapter } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, setup } from "./organization-invitation-response-contract";
import { date, membershipKey, type Events } from "./organization-team-member-contract";

const modes = ["commit", "before", "output", "after", "external", "cancel-team", "cancel-organization"] as const;
type Mode = typeof modes[number];
const commits = (mode: Mode) => ["commit", "after", "external", "cancel-organization"].includes(mode);
const succeeds = (mode: Mode) => ["commit", "external", "cancel-organization"].includes(mode);
const hookUser = {
  id: "hook-user", name: "Created by Session hook", email: "hook@example.com", emailVerified: false,
  image: null, createdAt: date(0), updatedAt: date(0),
};
const response = {
  invitation: {
    organizationId: "organization", email: "user-b@team-member-fields.test", role: "member", teamId: "team-a",
    status: "accepted", expiresAt: date(30), createdAt: date(0), inviterId: "user-a", id: "invitation-a",
  },
  member: { organizationId: "organization", userId: "user-b", role: "member", createdAt: date(0), id: "member-a" },
};

function expectedEvents(mode: Mode): Events {
  const events: Events = [["before.accept"], ["before", "team"]];
  if (mode !== "cancel-team") {
    events.push(["output.ip", "team"], ["output.agent", "initial-agent"], ["before", "organization"]);
    if (mode !== "before" && mode !== "cancel-organization") {
      events.push(["output.ip", "organization"]);
      if (mode !== "output") events.push(["output.agent", "initial-agent"]);
    }
  }
  if (commits(mode)) {
    events.push(["after.user", "committed"], ["after.session", "team:projected"]);
    if (mode === "commit" || mode === "external") events.push(["after.session", "organization:projected"]);
  }
  if (succeeds(mode)) events.push(["after.accept"]);
  return events;
}

for (const mode of modes) for (const joins of [false, true]) for (const entry of ["native", "http"] as const) {
  test(`Memory invitation Session hooks ${mode} ${entry} joins=${joins} preserve transaction output and persistence`, async () => {
    const fixture = await setup("memory", { name: mode, route: "accept", joins, teamIds: "team-a" });
    try {
      await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }],
        update: { ipAddress: "initial", userAgent: "initial-agent", updatedAt: date(0) } });
      const before = fixture.snapshot();
      const events: Events = [];
      const failure = new TypeError(`${mode}-session`);
      let recording = false;
      let context: typeof fixture.context;
      const auth = betterAuth({
        ...fixture.options,
        advanced: { database: { ...fixture.options.advanced?.database,
          generateId: ({ model }) => model === "user" ? "hook-user" : `${model}-a`,
        } },
        databaseHooks: {
          user: { create: { after(user) {
            expect(user).toStrictEqual(hookUser);
            expect(fixture.snapshot().member).toHaveLength(2);
            expect(fixture.snapshot().user).toHaveLength(3);
            events.push(["after.user", "committed"]);
            return Promise.resolve();
          } } },
          session: { update: {
            async before(data) {
              const team = "activeTeamId" in data;
              const phase = team ? "team" : "organization";
              events.push(["before", phase]);
              const current = await getCurrentAdapter(context.adapter);
              expect(current).not.toBe(context.adapter);
              expect(fixture.snapshot().member).toHaveLength(1);
              expect(fixture.snapshot().user).toHaveLength(2);
              expect(fixture.snapshot().team.find(row => row.id === "team-a")?.memberCount).toBe(0);
              expect(await current.findOne({ model: "team", where: [{ field: "id", value: "team-a" }] }))
                .toMatchObject({ memberCount: 1 });
              expect(await current.count({ model: "member", where: [{ field: "organizationId", value: "organization" }] }))
                .toBe(team ? 1 : 2);
              if (team) expect(await context.internalAdapter.createUser(hookUser)).toStrictEqual(hookUser);
              if (mode === "before" && !team) throw failure;
              if (mode === "cancel-team" && team || mode === "cancel-organization" && !team) return false;
              return { data: { ipAddress: phase } };
            },
            after(session) {
              expect(fixture.snapshot().member).toHaveLength(2);
              expect(fixture.snapshot().teamMember).toHaveLength(1);
              expect(fixture.snapshot().invitation[0]?.status).toBe("accepted");
              events.push(["after.session", session?.ipAddress]);
              if (mode === "after") throw failure;
              return Promise.resolve();
            },
          } },
        },
        plugins: [organization({
          teams: { enabled: true, maximumMembersPerTeam: 1 },
          organizationHooks: {
            beforeAcceptInvitation() { recording = true; events.push(["before.accept"]); return Promise.resolve(); },
            afterAcceptInvitation() { events.push(["after.accept"]); return Promise.resolve(); },
          },
        }), { id: "invitation-session-transaction-fields", schema: {
          member: { fields: { createdAt: { type: "date", transform: { input: () => date(0) } } } },
          teamMember: { fields: { createdAt: { type: "date", transform: { input: () => date(0) } } } },
          session: { fields: {
            updatedAt: { type: "date", onUpdate: () => date(0) },
            ipAddress: { type: "string", transform: { async output(value) {
              if (!recording) return value;
              events.push(["output.ip", value]);
              if (mode === "output" && value === "organization") throw failure;
              if (mode === "external" && value === "team") {
                await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }],
                  update: { userAgent: "external-agent", updatedAt: date(1) } });
              }
              return `${value}:projected`;
            } } },
            userAgent: { type: "string", transform: { output(value) {
              if (recording) events.push(["output.agent", value]);
              return value;
            } } },
          } },
        } }],
      });
      context = await auth.$context;
      const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
      const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
      if (entry === "native") {
        if (succeeds(mode)) expectOrdered(await auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } }), response);
        else {
          let caught: unknown;
          try { await auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } }); } catch (error) { caught = error; }
          if (mode === "cancel-team") expect(caught).toMatchObject({ name: "TypeError", message: "null is not an object (evaluating 'session.session.token')" });
          else expect(caught).toBe(failure);
        }
      } else {
        const result = await auth.handler(new Request(`${baseURL}/api/auth/organization/accept-invitation`, {
          method: "POST", headers, body: JSON.stringify({ invitationId: "invitation-a" }),
        }));
        expect(result.status).toBe(succeeds(mode) ? 200 : 500);
        expect(await result.text()).toBe(succeeds(mode) ? JSON.stringify(response) : "");
      }
      expect(events).toStrictEqual(expectedEvents(mode));
      if (commits(mode)) {
        before.user.unshift(hookUser);
        before.member.unshift(member("member-a", "user-b", "member"));
        before.teamMember = [{ id: "teamMember-a", teamId: "team-a", userId: "user-b",
          membershipKey: membershipKey("team-a", "user-b"), createdAt: date(0) }];
        before.team = before.team.map(row => row.id === "team-a" ? { ...row, memberCount: 1 } : row);
        before.invitation = before.invitation.map(row => ({ ...row, status: mode === "after" ? "pending" : "accepted" }));
        before.session = before.session.map(row => ({ ...row, updatedAt: date(0), activeTeamId: "team-a",
          activeOrganizationId: mode === "cancel-organization" ? null : "organization",
          ipAddress: mode === "cancel-organization" ? "team" : "organization" }));
      }
      // Memory commits its transaction row over an external same-row write. Rust retains its explicit ownership conflict guard.
      expect(fixture.snapshot()).toStrictEqual(before);
    } finally { fixture.close(); }
  });
}
