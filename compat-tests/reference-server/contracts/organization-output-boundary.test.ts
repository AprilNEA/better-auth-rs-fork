import { expect, test } from "bun:test";
import type { DBFieldAttribute } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, outputField, setup } from "./organization-invitation-response-contract";
import { date, type Events } from "./organization-team-member-contract";

type Route = "get-id" | "get-slug" | "active-id" | "active-slug" | "create" | "update" | "check-slug" | "members" | "role" | "delete" | "teams";
type Entry = "native" | "http";

function request(route: Route) {
  switch (route) {
    case "get-id": return { path: "get-organization", get: true, input: { organizationId: "organization" } };
    case "get-slug": return { path: "get-organization", get: true, input: { organizationSlug: "organization" } };
    case "active-id": return { path: "set-active", input: { organizationId: "organization" } };
    case "active-slug": return { path: "set-active", input: { organizationSlug: "organization" } };
    case "create": return { path: "create", input: { name: "Duplicate", slug: "organization" } };
    case "update": return { path: "update", input: { organizationId: "organization", data: { slug: "organization" } } };
    case "check-slug": return { path: "check-slug", input: { slug: "organization" } };
    case "members": return { path: "list-members", get: true, input: { organizationSlug: "organization" } };
    case "role": return { path: "get-active-member-role", get: true, input: { organizationSlug: "organization" } };
    case "delete": return { path: "delete", input: { organizationId: "organization" } };
    case "teams": return { path: "list-teams", get: true, input: { organizationId: "organization" } };
  }
}

function nativeCall(auth: ReturnType<typeof endpoint>, route: Route, headers: Headers) {
  switch (route) {
    case "get-id": return auth.api.getOrganization({ headers, query: { organizationId: "organization" } });
    case "get-slug": return auth.api.getOrganization({ headers, query: { organizationSlug: "organization" } });
    case "active-id": return auth.api.setActiveOrganization({ headers, body: { organizationId: "organization" } });
    case "active-slug": return auth.api.setActiveOrganization({ headers, body: { organizationSlug: "organization" } });
    case "create": return auth.api.createOrganization({ headers, body: { name: "Duplicate", slug: "organization" } });
    case "update": return auth.api.updateOrganization({ headers, body: { organizationId: "organization", data: { slug: "organization" } } });
    case "check-slug": return auth.api.checkOrganizationSlug({ headers, body: { slug: "organization" } });
    case "members": return auth.api.listMembers({ headers, query: { organizationSlug: "organization" } });
    case "role": return auth.api.getActiveMemberRole({ headers, query: { organizationSlug: "organization" } });
    case "delete": return auth.api.deleteOrganization({ headers, body: { organizationId: "organization" } });
    case "teams": return auth.api.listOrganizationTeams({ headers, query: { organizationId: "organization" } });
  }
}

function call(auth: ReturnType<typeof endpoint>, route: Route, headers: Headers, entry: Entry) {
  if (entry === "native") return nativeCall(auth, route, headers);
  const { path, input, get } = request(route);
  const url = new URL(`${baseURL}/api/auth/organization/${path}`);
  if (get) for (const [name, value] of Object.entries(input)) url.searchParams.set(name, String(value));
  return auth.handler(new Request(url, { headers, ...(get ? {} : { method: "POST", body: JSON.stringify(input) }) }));
}

async function headers(secret: string) {
  const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", secret)).split(";", 1)[0];
  return new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
}

function sessionField(events: Events): DBFieldAttribute {
  return { type: "date" as const, onUpdate() {
    events.push(["session.updatedAt", "onUpdate"]);
    return date(0);
  }, transform: { input(value) {
    events.push(["session.updatedAt", "input", value]);
    return value;
  } } };
}

const sessionEvents = () => [["session.updatedAt", "onUpdate"], ["session.updatedAt", "input", date(0)]];

function endpoint(options: Awaited<ReturnType<typeof setup>>["options"], events: Events) {
  return betterAuth({ ...options, plugins: [organization({
    schema: { organization: { additionalFields: { name: { type: "string", returned: false } } } },
  }), { id: "organization-output-boundary", schema: {
    organization: { fields: { name: outputField("organization.name", events, () => () => {
      throw new Error("Hidden output function must not run");
    }, { type: "string" }) } },
    member: { fields: { role: outputField("member.role", events, value => value, { type: "string" }) } },
    session: { fields: { updatedAt: sessionField(events) } },
  } }] });
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const route of ["get-id", "get-slug", "active-id", "active-slug", "create", "update", "check-slug", "members", "role", "delete"] as const) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Organization ${route} ${entry} projects before consumption and preserves failed storage`, async () => {
        const fixture = await setup(backend, { name: route, route: route === "create" ? "accept" : "cancel", deleteBefore: route === "delete" });
        const events: Events = [];
        try {
          await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }], update: { activeOrganizationId: "organization" } });
          const before = fixture.snapshot();
          const auth = endpoint(fixture.options, events);
          const requestHeaders = await headers(fixture.options.secret!);
          if (entry === "native") {
            let error: unknown;
            try { await call(auth, route, requestHeaders, entry); } catch (caught) { error = caught; }
            expect(error).toMatchObject({ name: "DataCloneError", message: "The object can not be cloned." });
          } else {
            const response = await call(auth, route, requestHeaders, entry) as Response;
            expect(response.status).toBe(500);
            expect(await response.text()).toBe("");
            expect(response.headers.get("set-cookie")).toBeNull();
          }
          const expected: Events = [];
          if (route === "active-id" || route === "update" || route === "delete") expected.push(["member.role", "output", "owner"]);
          if (route === "delete") {
            expected.push(...sessionEvents());
            before.session = before.session.map(row => ({ ...row, activeOrganizationId: null, updatedAt: fixture.stored({ updatedAt: date(0) }).updatedAt }));
          }
          expected.push(["organization.name", "output", "Organization"]);
          expectOrdered(events, expected);
          expect(fixture.snapshot()).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }

  for (const route of ["get-id", "teams"] as const) {
    for (const entry of ["native", "http"] as const) {
      for (const apiError of [false, true]) {
        test(`${backend} Organization ${route} ${entry} preserves the after hook ${apiError ? "APIError" : "replacement"}`, async () => {
          const fixture = await setup(backend, { name: "after-output", route: "cancel" });
          try {
            const before = fixture.snapshot();
            const item = { name: "after-hook", memberCount: 7, ownUndefined: undefined };
            const body = { message: "after-hook", name: "body-name", memberCount: 7 };
            const errorHeaders = { "x-output": "1" };
            const replacement = apiError ? new APIError("CREATED", body, errorHeaders) : route === "teams" ? [item] : item;
            const original = route === "teams"
              ? ["team-a", "team-b"].map(id => ({ organizationId: "organization", createdAt: date(0), updatedAt: date(0), id }))
              : { slug: "organization", logo: null, createdAt: date(0), metadata: "{}", id: "organization" };
            const auth = betterAuth({ ...fixture.options, hooks: { after: createAuthMiddleware(async ctx => {
              expectOrdered(ctx.context.returned, original);
              if (apiError) throw replacement;
              return ctx.json(replacement);
            }) }, plugins: [organization({
              teams: { enabled: true }, schema: {
                organization: { additionalFields: { name: { type: "string", returned: false } } },
                team: { additionalFields: { name: { type: "string", returned: false } } },
              },
            })] });
            const requestHeaders = await headers(fixture.options.secret!);
            if (entry === "native" && apiError) {
              let error: unknown;
              try { await call(auth, route, requestHeaders, entry); } catch (caught) { error = caught; }
              expect(error).toBe(replacement);
              expect(error).toBeInstanceOf(APIError);
              expect((error as APIError).statusCode).toBe(201);
              expectOrdered((error as APIError).body, body);
              expectOrdered((error as APIError).headers, errorHeaders);
            } else {
              const actual = await call(auth, route, requestHeaders, entry);
              if (entry === "native") {
                expect(actual).toBe(replacement);
                expectOrdered(actual, replacement);
              } else {
                expect((actual as Response).status).toBe(apiError ? 201 : 200);
                if (apiError) expect((actual as Response).headers.get("x-output")).toBe("1");
                expect(await (actual as Response).text()).toBe(JSON.stringify(apiError ? body : replacement));
              }
            }
            expect(fixture.snapshot()).toStrictEqual(before);
          } finally { fixture.close(); }
        });
      }
    }
  }

  for (const entry of ["native", "http"] as const) {
    test(`${backend} Organization delete ${entry} shares projected fields between hooks and result`, async () => {
      const fixture = await setup(backend, { name: "delete-output", route: "cancel", deleteBefore: true });
      const events: Events = [];
      const metadata = { nested: { value: "shared" } };
      let beforeHook: Record<string, unknown> | undefined;
      try {
        await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }], update: { activeOrganizationId: "organization" } });
        const before = fixture.snapshot();
        const auth = betterAuth({ ...fixture.options, plugins: [organization({
          schema: { organization: { additionalFields: { name: { type: "string", returned: false } } } },
          organizationHooks: {
            beforeDeleteOrganization({ organization }) {
              expect(Object.hasOwn(organization, "name")).toBe(false);
              beforeHook = organization;
              events.push(["beforeDeleteOrganization", organization]);
              return Promise.resolve();
            },
            afterDeleteOrganization({ organization }) {
              expect(organization).toBe(beforeHook);
              events.push(["afterDeleteOrganization", organization]);
              return Promise.resolve();
            },
          },
        }), { id: "organization-delete-output", schema: {
          organization: { fields: { metadata: outputField("metadata", events, () => metadata, { type: "string" }) } },
          session: { fields: { updatedAt: sessionField(events) } },
        } }] });
        const actual = await call(auth, "delete", await headers(fixture.options.secret!), entry);
        expect(beforeHook!.metadata).not.toBe(metadata);
        const expected = { slug: "organization", logo: null, createdAt: date(0), metadata: beforeHook!.metadata, id: "organization" };
        if (entry === "native") {
          expectOrdered(actual, expected);
          expect((actual as Record<string, unknown>).metadata).toBe(beforeHook!.metadata);
        } else {
          expect((actual as Response).status).toBe(200);
          expect(await (actual as Response).text()).toBe(JSON.stringify(expected));
        }
        expectOrdered(events, [...sessionEvents(), ["metadata", "output", "{}"], ["beforeDeleteOrganization", expected], ["afterDeleteOrganization", expected]]);
        for (const model of ["organization", "member", "invitation"]) before[model] = [];
        before.session = before.session.map(row => ({ ...row, activeOrganizationId: null, updatedAt: fixture.stored({ updatedAt: date(0) }).updatedAt }));
        expect(fixture.snapshot()).toStrictEqual(before);
      } finally { fixture.close(); }
    });
  }
}
