import { expect, test } from "bun:test";
import { serializeSignedCookie, toResponse } from "better-call";
import { baseURL, expectOrdered, outputField } from "./organization-invitation-response-contract";
import { build, fixture } from "./organization-live-source-contract";
import { type Events } from "./organization-team-member-contract";

const cases = [
  "team-session", "slug-session", "team-organization", "missing-team", "create-session", "remove-session",
  "remove-organization", "update-session", "update-organization", "invitation-organization",
] as const;
type Case = typeof cases[number];

function request(mode: Case) {
  switch (mode) {
    case "team-session": case "team-organization": return { path: "update-team", body: { teamId: "missing", data: { name: "Updated" } } };
    case "missing-team": return { path: "update-team", body: { teamId: "missing", data: { name: "Updated", organizationId: "organization" } } };
    case "slug-session": return { path: "check-slug", body: { slug: "available" } };
    case "create-session": return { path: "create-team", body: { name: "New", organizationId: "organization" } };
    case "remove-session": return { path: "remove-team", body: { teamId: "missing", organizationId: "organization" } };
    case "remove-organization": return { path: "remove-team", body: { teamId: "missing" } };
    case "update-session": case "update-organization": return { path: "update", body: { data: { name: "Updated" } } };
    case "invitation-organization": return { path: "list-invitations", body: undefined };
  }
}

function expected(mode: Case) {
  switch (mode) {
    case "team-session": case "slug-session": return { status: 401, body: { message: "Unauthorized", code: "UNAUTHORIZED" } };
    case "team-organization": case "remove-organization": return { status: 400, body: { message: "No active organization", code: "NO_ACTIVE_ORGANIZATION" } };
    case "missing-team": return { status: 400, body: { message: "Team not found", code: "TEAM_NOT_FOUND" } };
    case "create-session": case "remove-session": return { status: 401, body: undefined };
    case "update-session": return { status: 401, body: { message: "User not found" } };
    case "update-organization": return { status: 400, body: { message: "Organization not found", code: "ORGANIZATION_NOT_FOUND" } };
    case "invitation-organization": return { status: 400, body: { message: "Organization ID is required" } };
  }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const entry of ["native", "http"] as const) {
    for (const mode of cases) {
      test(`${backend} Organization ${entry} preserves ${mode} error construction and complete storage`, async () => {
        const source = await fixture(backend, `error-construction-${entry}-${mode}`);
        try {
          const before = source.snapshot();
          const events: Events = [];
          const reader = build(source.options, "team", { name: outputField("name", events, value => value, { type: "string" }) }, {
            organizationHooks: {
              beforeUpdateTeam() { events.push(["before"]); return Promise.resolve(); },
              afterUpdateTeam() { events.push(["after"]); return Promise.resolve(); },
            },
          });
          const headers = new Headers({ origin: baseURL, "content-type": "application/json" });
          if (["team-organization", "missing-team", "update-organization", "invitation-organization"].includes(mode)) {
            headers.set("cookie", (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", reader.options.secret!)).split(";", 1)[0]);
          }
          const { path, body } = request(mode);
          const { status, body: errorBody } = expected(mode);
          let response: Response;
          if (entry === "http") {
            response = await reader.handler(new Request(`${baseURL}/api/auth/organization/${path}`, {
              method: body === undefined ? "GET" : "POST", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            }));
          } else {
            let caught: unknown;
            try {
              switch (mode) {
                case "team-session": case "team-organization": await reader.api.updateTeam({ headers, body: { teamId: "missing", data: { name: "Updated" } } }); break;
                case "missing-team": await reader.api.updateTeam({ headers, body: { teamId: "missing", data: { name: "Updated", organizationId: "organization" } } }); break;
                case "slug-session": await reader.api.checkOrganizationSlug({ headers, body: { slug: "available" } }); break;
                case "create-session": await reader.api.createTeam({ headers, body: { name: "New", organizationId: "organization" } }); break;
                case "remove-session": await reader.api.removeTeam({ headers, body: { teamId: "missing", organizationId: "organization" } }); break;
                case "remove-organization": await reader.api.removeTeam({ headers, body: { teamId: "missing" } }); break;
                case "update-session": case "update-organization": await reader.api.updateOrganization({ headers, body: { data: { name: "Updated" } } }); break;
                case "invitation-organization": await reader.api.listInvitations({ headers }); break;
              }
            } catch (error) { caught = error; }
            expect(caught).toMatchObject({ name: "APIError", statusCode: status });
            expectOrdered(Reflect.get(caught as object, "body"), errorBody);
            response = toResponse(caught);
          }
          expect(response.status).toBe(status);
          expect(await response.text()).toBe(JSON.stringify(errorBody) ?? "");
          expect(events).toStrictEqual([]);
          expect(source.snapshot()).toStrictEqual(before);
        } finally { source.close(); }
      });
    }
  }
}
