import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import { date, type Backend, type Events, type Policies } from "./organization-team-member-contract";

type Route = "get" | "list" | "role" | "remove-id" | "remove-email" | "update" | "leave" | "add";
type RoleValue = "string" | "undefined" | "null" | "object" | "function";
type Entry = "native" | "http";

async function check(backend: Backend, route: Route, mode: RoleValue, entry: Entry) {
  const fixture = await setup(backend, { name: route, route: ["get", "role", "leave"].includes(route) ? "accept" : "cancel" });
  try {
    if (route !== "add") await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: member("member-b", "user-b", "member") });
    await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }], update: { activeOrganizationId: "organization" } });
    const before = fixture.snapshot();
    const events: Events = [];
    const functionValue = () => { throw new Error("Member output function must not run"); };
    const shared = { native: true };
    const nested = { id: "nested-id", userId: "nested-user", token: "nested-token", expiresAt: date(0), activeTeamId: shared };
    const extensions = {
      ownUndefined: undefined, ownNull: null, left: shared, right: shared,
      token: "member-token", expiresAt: date(0), activeTeamId: shared, session: nested,
    };
    const roleValue = (input: unknown) => mode === "undefined" ? undefined : mode === "null" ? null
      : mode === "object" ? shared : mode === "function" ? functionValue : input;
    const fields: Policies = {
      role: outputField("role", [], input => { events.push(["role", input]); return roleValue(input); }, { type: "string" }),
      createdAt: { type: "date", transform: { input(value) {
        expect(value).toBeInstanceOf(Date);
        events.push(["createdAt.input", "native-date"]);
        return date(0);
      } } },
    };
    Object.defineProperty(fields.createdAt.transform, "output", { value(input: unknown) {
      events.push(["createdAt", input]);
      return functionValue;
    } });
    for (const [name, value] of Object.entries(extensions)) fields[name] = outputField(name, [], input => {
      events.push([name, input]); return value;
    }, { type: "string", fieldName: "role" });
    let observed: unknown;
    const auth = betterAuth({ ...fixture.options,
      hooks: { after: createAuthMiddleware(async ctx => { observed = ctx.context.returned; }) },
      plugins: [organization(), { id: "native-member-fields", schema: {
        member: { fields }, session: { fields: { updatedAt: { type: "date", onUpdate: () => date(0) } } },
      } }],
    });
    const visible = (id: string, role: string, withUser: boolean) => ({
      organizationId: "organization", userId: "user-b", role, createdAt: functionValue,
      ...extensions, id, ...(withUser ? { user: { id: "user-b", name: "user-b", email: "user-b@team-member-fields.test", image: null } } : {}),
    });
    const expected = route === "role" ? { role: roleValue("member") }
      : route === "list" ? { members: [visible("member-b", "member", true)], total: 2 }
      : route === "remove-id" || route === "remove-email" ? { member: visible("member-b", "member", route === "remove-email") }
      : route === "update" ? visible("member-b", "admin", false)
      : route === "add" ? visible("member-a", "member", false) : visible("member-b", "member", true);
    const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
    const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
    const body = route === "remove-id" || route === "remove-email"
      ? { memberIdOrEmail: route === "remove-id" ? "member-b" : "user-b@team-member-fields.test", organizationId: "organization" }
      : route === "update" ? { memberId: "member-b", role: "admin", organizationId: "organization" }
      : route === "leave" ? { organizationId: "organization" } : undefined;
    let result: unknown;
    if (entry === "native") {
      switch (route) {
        case "get": result = await auth.api.getActiveMember({ headers }); break;
        case "list": result = await auth.api.listMembers({ headers, query: { limit: 1, sortBy: "id", sortDirection: "asc" } }); break;
        case "role": result = await auth.api.getActiveMemberRole({ headers }); break;
        case "remove-id": case "remove-email": result = await auth.api.removeMember({ headers, body: body as { memberIdOrEmail: string; organizationId: string } }); break;
        case "update": result = await auth.api.updateMemberRole({ headers, body: body as { memberId: string; role: string; organizationId: string } }); break;
        case "leave": result = await auth.api.leaveOrganization({ headers, body: { organizationId: "organization" } }); break;
        case "add": result = await auth.api.addMember({ headers, body: { userId: "user-b", organizationId: "organization", role: "member" } }); break;
      }
      expectOrdered(result, expected);
      expectOrdered(observed, expected);
      expect(result).toBe(observed);
      if (route !== "role") {
        const row = route === "list" ? Reflect.get(result as object, "members")[0]
          : route === "remove-id" || route === "remove-email" ? Reflect.get(result as object, "member") : result;
        for (const [name, value] of Object.entries(extensions)) expect(Reflect.get(row as object, name)).toBe(value);
      }
    } else {
      const path = route === "get" ? "get-active-member" : route === "list" ? "list-members?limit=1&sortBy=id&sortDirection=asc"
        : route === "role" ? "get-active-member-role" : route === "update" ? "update-member-role"
        : route === "leave" ? "leave" : "remove-member";
      const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/${path}`, {
        headers, ...(body ? { method: "POST", body: JSON.stringify(body) } : {}),
      }));
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("application/json");
      expect(await response.text()).toBe(JSON.stringify(expected));
    }
    const roles = route === "list" || route === "remove-id" || route === "remove-email" ? ["owner", "member"]
      : route === "update" ? ["owner", "member", "admin"] : ["member"];
    const expectedEvents: Events = route === "add" ? [["createdAt.input", "native-date"]] : [];
    for (const role of roles) expectedEvents.push(["role", role], ["createdAt", before.member[0].createdAt],
      ...Object.keys(extensions).map(name => [name, role]));
    expectOrdered(events, expectedEvents);
    const after = structuredClone(before);
    if (["remove-id", "remove-email", "leave"].includes(route)) after.member = after.member.filter(row => row.id !== "member-b");
    if (route === "update") after.member.find(row => row.id === "member-b")!.role = "admin";
    if (route === "add") after.member.unshift(fixture.stored(member("member-a", "user-b", "member")));
    if (route === "leave") after.session = after.session.map(row => ({ ...row, activeOrganizationId: null, ...fixture.stored({ updatedAt: date(0) }) }));
    expect(fixture.snapshot()).toStrictEqual(after);
  } finally { fixture.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const entry of ["native", "http"] as const) {
    for (const route of ["get", "list", "role", "remove-id", "remove-email", "update", "leave"] as const) {
      test(`${backend} Member ${route} ${entry} preserves native values and complete storage`, () => check(backend, route, "string", entry));
    }
    for (const mode of ["undefined", "null", "object", "function"] as const) {
      test(`${backend} Member role ${mode} ${entry} retains own properties`, () => check(backend, "role", mode, entry));
    }
  }
  test(`${backend} pathless addMember preserves native fields and identity`, () => check(backend, "add", "string", "native"));
}
