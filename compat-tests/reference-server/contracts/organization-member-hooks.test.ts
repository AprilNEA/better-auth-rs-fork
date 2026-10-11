import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import { date, type Fields } from "./organization-team-member-contract";

type Case = "remove-email" | "remove-id" | "update-other" | "update-self";
type Failure = "none" | "before" | "after";
type Subject = { member: object; user: object; organization: object };
const cases: Case[] = ["remove-email", "remove-id", "update-other", "update-self"];
const failures = (scenario: Case): Failure[] => scenario === "remove-email" || scenario === "update-other"
  ? ["none", "before", "after"] : ["none"];
const removes = (scenario: Case) => scenario.startsWith("remove-");
const userId = (scenario: Case) => scenario === "update-self" ? "user-a" : "user-b";
const memberId = (scenario: Case) => scenario === "update-self" ? "owner-member" : "member-b";
const role = (scenario: Case, updated: boolean) => scenario === "update-self"
  ? updated ? "owner,admin" : "owner" : scenario === "update-other" && updated ? "admin" : "member";

function name(user: string, read: number, mutated = false) {
  return user === "user-a" ? user : { read, ...(mutated ? { touched: true } : {}) };
}

function summary(scenario: Case, mutated: boolean) {
  const id = userId(scenario);
  return {
    id, name: name(id, 1, mutated), email: `${id}@team-member-fields.test`, image: null,
    ...(mutated ? { hook: "before" } : {}),
  };
}

function visibleMember(scenario: Case, after: boolean, mutated: boolean) {
  const updated = after && !removes(scenario);
  const value: Fields = {
    organizationId: "organization", userId: userId(scenario), role: role(scenario, updated), createdAt: date(0),
  };
  if (scenario === "remove-email") value.user = summary(scenario, mutated);
  else if (updated) value.user = "declared-user";
  value.id = memberId(scenario);
  if (!removes(scenario) && !after) value.user = summary(scenario, mutated);
  return value;
}

function independentUser(scenario: Case) {
  const id = userId(scenario);
  return {
    id, name: name(id, 2), email: `${id}@team-member-fields.test`, emailVerified: true,
    image: null, createdAt: date(0), updatedAt: date(0),
  };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const joins of [false, true]) {
    for (const scenario of cases) {
      for (const entry of ["native", "http"] as const) {
        for (const failure of failures(scenario)) {
          test(`${backend} Member hooks joins=${joins} ${entry} preserve ${scenario} ${failure}`, async () => {
            const fixture = await setup(backend, { name: scenario, route: "cancel", joins });
            try {
              await fixture.context.adapter.create({
                model: "member", forceAllowId: true, data: member("member-b", "user-b", "member"),
              });
              const before = fixture.snapshot();
              let reads = 0;
              const calls: string[] = [];
              let originalMember: object | undefined;
              let originalSummary: object | undefined;
              let originalUser: object | undefined;
              const hookError = new Error(`member-${failure}-hook-failed`);
              const common = (event: Subject) => {
                expect(event.user).toStrictEqual(independentUser(scenario));
                expect(event.organization).toStrictEqual({
                  id: "organization", name: "Organization", slug: "organization", logo: null,
                  metadata: "{}", createdAt: date(0),
                });
              };
              const beforeHook = (hook: string, event: Subject) => {
                common(event);
                expectOrdered(event.member, visibleMember(scenario, false, false));
                calls.push(hook);
                originalMember = event.member;
                originalUser = event.user;
                if (scenario !== "remove-id") {
                  const user = Reflect.get(event.member, "user");
                  expect(typeof user).toBe("object");
                  expect(user).not.toBeNull();
                  user.hook = "before";
                  if (userId(scenario) === "user-b") user.name.touched = true;
                  originalSummary = user;
                  expectOrdered(user, summary(scenario, true));
                  common(event);
                }
                if (failure === "before") throw hookError;
              };
              const afterHook = (hook: string, event: Subject) => {
                common(event);
                expectOrdered(event.member, visibleMember(scenario, true, true));
                calls.push(hook);
                expect(event.user).toBe(originalUser);
                if (removes(scenario)) expect(event.member).toBe(originalMember);
                if (scenario === "remove-email") expect(Reflect.get(event.member, "user")).toBe(originalSummary);
                if (failure === "after") throw hookError;
              };
              const auth = betterAuth({
                ...fixture.options,
                session: { disableSessionRefresh: true },
                user: { additionalFields: { name: outputField("name", [], value =>
                  value === "user-b" ? name("user-b", ++reads) : value, { type: "string" }) } },
                plugins: [organization({
                  organizationHooks: {
                    beforeRemoveMember(event) { beforeHook("beforeRemoveMember", event); return Promise.resolve(); },
                    afterRemoveMember(event) { afterHook("afterRemoveMember", event); return Promise.resolve(); },
                    beforeUpdateMemberRole(event) {
                      expect(event.newRole).toBe(role(scenario, true));
                      beforeHook("beforeUpdateMemberRole", event);
                      return Promise.resolve();
                    },
                    afterUpdateMemberRole(event) {
                      expect(event.previousRole).toBe(role(scenario, false));
                      afterHook("afterUpdateMemberRole", event);
                      return Promise.resolve();
                    },
                  },
                }), { id: "member-hook-fields", schema: { member: { fields: {
                  user: outputField("user", [], () => "declared-user", { type: "string", fieldName: "role" }),
                } } } }],
              });
              const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
              const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
              const body = removes(scenario)
                ? { organizationId: "organization", memberIdOrEmail: scenario === "remove-email" ? "user-b@team-member-fields.test" : memberId(scenario) }
                : { organizationId: "organization", memberId: memberId(scenario), role: role(scenario, true) };
              const expectedMember = visibleMember(scenario, true, true);
              const expected = removes(scenario) ? { member: expectedMember } : expectedMember;
              if (entry === "native") {
                let actual: object | undefined;
                let caught: unknown;
                try {
                  actual = removes(scenario)
                    ? await auth.api.removeMember({ headers, body: body as { organizationId: string; memberIdOrEmail: string } })
                    : await auth.api.updateMemberRole({ headers, body: body as { organizationId: string; memberId: string; role: string } });
                } catch (error) { caught = error; }
                if (failure !== "none") expect(caught).toBe(hookError);
                else {
                  expect(caught).toBeUndefined();
                  expectOrdered(actual, expected);
                  if (scenario === "remove-email") expect(Reflect.get(Reflect.get(actual as object, "member"), "user")).toBe(originalSummary);
                }
              } else {
                const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/${removes(scenario) ? "remove-member" : "update-member-role"}`, {
                  method: "POST", headers, body: JSON.stringify(body),
                }));
                expect(response.status).toBe(failure === "none" ? 200 : 500);
                if (failure !== "none") expect(await response.text()).toBe("");
                else {
                  expect(response.headers.get("content-type")).toContain("application/json");
                  expect(await response.text()).toBe(JSON.stringify(expected));
                }
              }
              const expectedCalls = removes(scenario)
                ? ["beforeRemoveMember", "afterRemoveMember"] : ["beforeUpdateMemberRole", "afterUpdateMemberRole"];
              if (failure === "before") expectedCalls.length = 1;
              expect(calls).toStrictEqual(expectedCalls);
              expect(reads).toBe(scenario === "update-self" ? 0 : 2);
              if (failure !== "before") {
                if (removes(scenario)) before.member = before.member.filter(row => row.id !== memberId(scenario));
                else before.member.find(row => row.id === memberId(scenario))!.role = role(scenario, true);
              }
              expect(fixture.snapshot()).toStrictEqual(before);
            } finally { fixture.close(); }
          });
        }
      }
    }
  }
}
