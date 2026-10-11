import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import { date, membershipKey, storedDate, type Backend, type Events } from "./organization-team-member-contract";

type Scenario = "add-mismatch" | "accept-mismatch" | "add-hidden-id" | "accept-hidden-id" | "add-clone" | "accept-clone" | "many" | "second-clone" | "member-error";
const scenarios: Scenario[] = ["add-mismatch", "accept-mismatch", "add-hidden-id", "accept-hidden-id", "add-clone", "accept-clone", "many", "second-clone", "member-error"];
const isAdd = (scenario: Scenario) => scenario.startsWith("add-");
const isMismatch = (scenario: Scenario) => scenario.endsWith("mismatch");
const isMany = (scenario: Scenario) => scenario === "many" || scenario === "second-clone";
const teamIds = (scenario: Scenario) => isMany(scenario) ? "team-a,team-b" : "team-a";
const succeeds = (scenario: Scenario) => ["add-hidden-id", "accept-hidden-id", "many"].includes(scenario);
const clonesAt = (scenario: Scenario, name: unknown) => scenario === "add-clone" || scenario === "accept-clone" || scenario === "second-clone" && name === "Team B";

function timestamp(model: string, events: Events, failure?: Error): DBFieldAttribute {
  return { type: "date", transform: {
    input(value) {
      expect(value).toBeInstanceOf(Date);
      events.push([`${model}.createdAt`, "input", "native-date"]);
      if (failure) throw failure;
      return date(0);
    },
    output(value) { events.push([`${model}.createdAt`, "output", value]); return date(0); },
  } };
}

function transactionAuth(options: BetterAuthOptions, config: { scenario: Scenario; events: Events; failure: Error }) {
  const { scenario, events, failure } = config;
  let sequence = 0;
  const teamFunction = () => { events.push(["team.name", "called"]); return "called"; };
  return betterAuth({
    ...options,
    advanced: { database: { ...options.advanced?.database, generateId: ({ model }) => model === "teamMember" ? `teamMember-${++sequence}` : `${model}-a` } },
    plugins: [organization({
      teams: { enabled: true, maximumMembersPerTeam({ organizationId, teamId, session }) {
        events.push(["maximum", "callback", [organizationId, teamId, session.user.id]]);
        return 3;
      } },
      schema: { team: { additionalFields: { id: { type: "string", returned: false }, name: { type: "string", returned: false } } } },
    }), { id: "ordinary-team-transaction-projection", schema: {
      team: { fields: {
        name: outputField("team.name", events, value => clonesAt(scenario, value) ? teamFunction : value, { type: "string" }),
        organizationId: outputField("team.organizationId", events, value => value, { type: "string" }),
      } },
      teamMember: { fields: { createdAt: timestamp("teamMember", events) } },
      member: { fields: { createdAt: timestamp("member", events, scenario === "member-error" ? failure : undefined) } },
      invitation: { fields: { status: outputField("invitation.status", events, value => value, { type: "string" }) } },
      session: { fields: {
        updatedAt: { type: "date", onUpdate: () => date(0), transform: { input(value) {
          expect(value).toBeInstanceOf(Date);
          events.push(["session.updatedAt", "input", "native-date"]);
          return date(0);
        } } },
        activeOrganizationId: { type: "string", transform: { input(value) { events.push(["session.activeOrganizationId", "input", value]); return value; } } },
        activeTeamId: { type: "string", transform: { input(value) { events.push(["session.activeTeamId", "input", value]); return value; } } },
      } },
    } }],
  });
}

function expectedEvents(backend: Backend, scenario: Scenario): Events {
  const events: Events = isAdd(scenario) ? [] : [["invitation.status", "output", "pending"], ["invitation.status", "output", "accepted"]];
  const memberInput = ["member.createdAt", "input", "native-date"];
  const memberOutput = ["member.createdAt", "output", storedDate(backend, 0)];
  for (const [index, id] of teamIds(scenario).split(",").entries()) {
    if (isMismatch(scenario)) break;
    const name = id === "team-a" ? "Team A" : "Team B";
    const parent = [["team.name", "output", name], ["team.organizationId", "output", "organization"]];
    events.push(...parent);
    if (clonesAt(scenario, name)) break;
    if (isAdd(scenario)) events.push(memberInput, memberOutput);
    events.push(["maximum", "callback", ["organization", id, "user-b"]], ...parent,
      ["teamMember.createdAt", "input", "native-date"], ["teamMember.createdAt", "output", storedDate(backend, 0)]);
    if (index === 0 && !isMany(scenario) && !isAdd(scenario)) {
      events.push(["session.updatedAt", "input", "native-date"], ["session.activeTeamId", "input", id]);
    }
  }
  if (!isAdd(scenario) && !isMismatch(scenario) && scenario !== "accept-clone" && scenario !== "second-clone") {
    events.push(memberInput);
    if (scenario !== "member-error") events.push(memberOutput, ["session.updatedAt", "input", "native-date"], ["session.activeOrganizationId", "input", "organization"]);
  }
  if (!isAdd(scenario) && !succeeds(scenario)) events.push(["invitation.status", "output", "pending"]);
  return events;
}

function expectedResponse(scenario: Scenario) {
  const member = { organizationId: "organization", userId: "user-b", role: "member", createdAt: date(0), id: "member-a" };
  if (isAdd(scenario)) return member;
  return { invitation: {
    organizationId: "organization", email: "user-b@team-member-fields.test", role: "member", teamId: teamIds(scenario), status: "accepted",
    expiresAt: date(30), createdAt: date(0), inviterId: "user-a", id: "invitation-a",
  }, member };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const scenario of scenarios) {
    for (const joins of [false, true]) {
      for (const entry of (isAdd(scenario) ? ["native"] : ["native", "http"]) as ("native" | "http")[]) {
        test(`${backend} Team transaction ${scenario} ${entry} joins=${joins} preserves scope, projection, order and storage`, async () => {
          const fixture = await setup(backend, { name: scenario, route: "accept", joins, teamIds: teamIds(scenario) });
          try {
            if (isMismatch(scenario)) {
              await fixture.context.adapter.create({ model: "organization", forceAllowId: true, data: {
                id: "other", name: "Other", slug: "other", logo: null, metadata: "{}", createdAt: date(0),
              } });
              await fixture.context.adapter.update({ model: "team", where: [{ field: "id", value: "team-a" }], update: { organizationId: "other" } });
            }
            const before = fixture.snapshot();
            const events: Events = [];
            const failure = new Error("member-create-failed");
            const auth = transactionAuth(fixture.options, { scenario, events, failure });
            const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
            const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
            const expected = expectedResponse(scenario);
            const invoke = () => isAdd(scenario)
              ? auth.api.addMember({ headers, body: { organizationId: "organization", userId: "user-b", role: "member", teamId: "team-a" } })
              : auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } });
            if (entry === "native") {
              if (succeeds(scenario)) expectOrdered(await invoke(), expected);
              else {
                let caught: unknown;
                try { await invoke(); } catch (error) { caught = error; }
                if (isMismatch(scenario)) expect(caught).toMatchObject({ statusCode: 400, body: { code: "TEAM_NOT_FOUND", message: "Team not found" } });
                else if (scenario === "member-error") expect(caught).toBe(failure);
                else expect(caught).toMatchObject({ name: "DataCloneError", message: "The object can not be cloned." });
              }
            } else {
              const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/accept-invitation`, {
                method: "POST", headers, body: JSON.stringify({ invitationId: "invitation-a" }),
              }));
              expect(response.status).toBe(succeeds(scenario) ? 200 : isMismatch(scenario) ? 400 : 500);
              if (succeeds(scenario)) expect(await response.text()).toBe(JSON.stringify(expected));
              else if (isMismatch(scenario)) expect(await response.json()).toStrictEqual({ code: "TEAM_NOT_FOUND", message: "Team not found" });
              else expect(await response.text()).toBe("");
            }
            expect(events).toStrictEqual(expectedEvents(backend, scenario));
            if (succeeds(scenario)) {
              before.member.unshift(fixture.stored(member("member-a", "user-b", "member")));
              before.teamMember = teamIds(scenario).split(",").map((id, index) => fixture.stored({
                id: `teamMember-${index + 1}`, teamId: id, userId: "user-b", membershipKey: membershipKey(id, "user-b"), createdAt: date(0),
              }));
              before.team = before.team.map(row => teamIds(scenario).split(",").includes(String(row.id)) ? { ...row, memberCount: 1 } : row);
              if (!isAdd(scenario)) {
                before.invitation = before.invitation.map(row => ({ ...row, status: "accepted" }));
                before.session = before.session.map(row => ({ ...row, updatedAt: storedDate(backend, 0), activeOrganizationId: "organization", ...(!isMany(scenario) ? { activeTeamId: "team-a" } : {}) }));
              }
            }
            expect(fixture.snapshot()).toStrictEqual(before);
          } finally { fixture.close(); }
        });
      }
    }
  }
}
