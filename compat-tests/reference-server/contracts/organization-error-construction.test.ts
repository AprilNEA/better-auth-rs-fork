import { expect, test } from "bun:test";
import { serializeSignedCookie, toResponse } from "better-call";
import { baseURL, expectOrdered, outputField } from "./organization-invitation-response-contract";
import { build, fixture } from "./organization-live-source-contract";
import { date, type Events } from "./organization-team-member-contract";

const cases = [
  "team-session", "slug-session", "team-organization", "missing-team", "create-session", "remove-session",
  "remove-organization", "update-session", "update-organization", "invitation-organization",
  "organization-create-session", "organization-create-no-user", "organization-create-missing-user",
  "organization-create-denied", "organization-create-limit", "organization-create-duplicate", "slug-taken",
  "organization-update-member", "organization-update-denied", "organization-update-slug",
  "organization-delete-disabled", "organization-delete-disabled-session", "organization-delete-session",
  "organization-delete-empty", "organization-delete-member", "organization-delete-denied",
  "organization-get-missing", "organization-get-member", "organization-full-missing", "organization-full-member",
  "organization-active-missing", "organization-active-member", "organization-leave-member", "organization-leave-owner",
] as const;
type Case = typeof cases[number];

const clearsActive = (mode: Case) => ["organization-get-member", "organization-full-member", "organization-active-member"].includes(mode);
const headerless = (mode: Case) => ["organization-create-no-user", "organization-create-missing-user"].includes(mode);
const authenticated = (mode: Case) => ![
  "team-session", "slug-session", "create-session", "remove-session", "remove-organization", "update-session",
  "organization-create-session", "organization-create-no-user", "organization-create-missing-user",
  "organization-delete-session", "organization-delete-disabled-session",
].includes(mode);

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
    case "organization-create-session": case "organization-create-no-user":
    case "organization-create-denied": case "organization-create-limit":
      return { path: "create", body: { name: "New", slug: "available" } };
    case "organization-create-missing-user": return { path: "create", body: { name: "New", slug: "available", userId: "missing" } };
    case "organization-create-duplicate": return { path: "create", body: { name: "New", slug: "organization" } };
    case "slug-taken": return { path: "check-slug", body: { slug: "organization" } };
    case "organization-update-member": return { path: "update", body: { organizationId: "source-parent", data: { name: "Updated" } } };
    case "organization-update-denied": return { path: "update", body: { organizationId: "organization", data: { name: "Updated" } } };
    case "organization-update-slug": return { path: "update", body: { organizationId: "organization", data: { slug: "other" } } };
    case "organization-delete-disabled": case "organization-delete-disabled-session":
    case "organization-delete-session": case "organization-delete-denied":
      return { path: "delete", body: { organizationId: "organization" } };
    case "organization-delete-empty": return { path: "delete", body: { organizationId: "" } };
    case "organization-delete-member": return { path: "delete", body: { organizationId: "source-parent" } };
    case "organization-get-missing": case "organization-get-member": return { path: "get-organization", body: undefined };
    case "organization-full-missing": case "organization-full-member": return { path: "get-full-organization", body: undefined };
    case "organization-active-missing": return { path: "set-active", body: { organizationSlug: "missing" } };
    case "organization-active-member": return { path: "set-active", body: { organizationId: "source-parent" } };
    case "organization-leave-member": return { path: "leave", body: { organizationId: "source-parent" } };
    case "organization-leave-owner": return { path: "leave", body: { organizationId: "organization" } };
  }
}

function query(mode: Case) {
  switch (mode) {
    case "organization-get-missing": case "organization-full-missing": return { organizationId: "missing" };
    case "organization-get-member": case "organization-full-member": return { organizationId: "source-parent" };
    default: return undefined;
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
    case "organization-create-session": case "organization-create-no-user": case "organization-create-missing-user":
    case "organization-delete-session": return { status: 401, body: undefined };
    case "organization-create-denied": return { status: 403, body: { message: "You are not allowed to create a new organization", code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION" } };
    case "organization-create-limit": return { status: 403, body: { message: "You have reached the maximum number of organizations", code: "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS" } };
    case "organization-create-duplicate": return { status: 400, body: { message: "Organization already exists", code: "ORGANIZATION_ALREADY_EXISTS" } };
    case "slug-taken": case "organization-update-slug": return { status: 400, body: { message: "Organization slug already taken", code: "ORGANIZATION_SLUG_ALREADY_TAKEN" } };
    case "organization-update-member": case "organization-delete-member": return { status: 400, body: { message: "User is not a member of the organization", code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" } };
    case "organization-update-denied": return { status: 403, body: { message: "You are not allowed to update this organization", code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION" } };
    case "organization-delete-disabled": case "organization-delete-disabled-session": return { status: 404, body: { message: "Organization deletion is disabled", code: "ORGANIZATION_DELETION_DISABLED" } };
    case "organization-delete-denied": return { status: 403, body: { message: "You are not allowed to delete this organization", code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION" } };
    case "organization-delete-empty": case "organization-get-missing": case "organization-full-missing":
    case "organization-active-missing": return { status: 400, body: { message: "Organization not found", code: "ORGANIZATION_NOT_FOUND" } };
    case "organization-get-member": case "organization-full-member": case "organization-active-member":
      return { status: 403, body: { message: "User is not a member of the organization", code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" } };
    case "organization-leave-member": return { status: 400, body: { message: "Member not found", code: "MEMBER_NOT_FOUND" } };
    case "organization-leave-owner": return { status: 400, body: { message: "You cannot leave the organization as the only owner", code: "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER" } };
  }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const entry of ["native", "http"] as const) {
    for (const mode of cases) {
      test(`${backend} Organization ${entry} preserves ${mode} error construction and complete storage`, async () => {
        const source = await fixture(backend, `error-construction-${entry}-${mode}`);
        try {
          if (["organization-update-denied", "organization-delete-denied"].includes(mode)) {
            await source.writer.update({ model: "member", where: [{ field: "id", value: "owner-member" }], update: { role: "member" } });
          }
          if (clearsActive(mode)) {
            await source.writer.update({ model: "session", where: [{ field: "id", value: "session-a" }],
              update: { activeOrganizationId: "organization", updatedAt: date(0) } });
          }
          const before = source.snapshot();
          const events: Events = [];
          const reader = build({ ...source.options, ...(clearsActive(mode) ? { session: { additionalFields: {
            updatedAt: { type: "date", onUpdate() { events.push(["session.updatedAt", "onUpdate"]); return date(0); } },
          } } } : {}) }, "team", { name: outputField("name", events, value => value, { type: "string" }) }, {
            allowUserToCreateOrganization: mode !== "organization-create-denied",
            ...(mode === "organization-create-limit" ? { organizationLimit: 0 } : {}),
            disableOrganizationDeletion: ["organization-delete-disabled", "organization-delete-disabled-session"].includes(mode),
            organizationHooks: {
              beforeUpdateTeam() { events.push(["before"]); return Promise.resolve(); },
              afterUpdateTeam() { events.push(["after"]); return Promise.resolve(); },
              beforeCreateOrganization() { events.push(["beforeCreateOrganization"]); return Promise.resolve(); },
              afterCreateOrganization() { events.push(["afterCreateOrganization"]); return Promise.resolve(); },
              beforeUpdateOrganization() { events.push(["beforeUpdateOrganization"]); return Promise.resolve(); },
              afterUpdateOrganization() { events.push(["afterUpdateOrganization"]); return Promise.resolve(); },
              beforeDeleteOrganization() { events.push(["beforeDeleteOrganization"]); return Promise.resolve(); },
              afterDeleteOrganization() { events.push(["afterDeleteOrganization"]); return Promise.resolve(); },
            },
          });
          const headers = new Headers({ origin: baseURL, "content-type": "application/json" });
          if (authenticated(mode)) {
            headers.set("cookie", (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", reader.options.secret!)).split(";", 1)[0]);
          }
          const { path, body } = request(mode);
          const queryInput = query(mode);
          const { status, body: errorBody } = expected(mode);
          let response: Response;
          if (entry === "http") {
            const suffix = queryInput ? `?${new URLSearchParams(queryInput)}` : "";
            response = await reader.handler(new Request(`${baseURL}/api/auth/organization/${path}${suffix}`, {
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
                case "organization-create-session": case "organization-create-no-user": case "organization-create-denied":
                case "organization-create-limit": await reader.api.createOrganization({ ...(headerless(mode) ? {} : { headers }), body: { name: "New", slug: "available" } }); break;
                case "organization-create-missing-user": await reader.api.createOrganization({ body: { name: "New", slug: "available", userId: "missing" } }); break;
                case "organization-create-duplicate": await reader.api.createOrganization({ headers, body: { name: "New", slug: "organization" } }); break;
                case "slug-taken": await reader.api.checkOrganizationSlug({ headers, body: { slug: "organization" } }); break;
                case "organization-update-member": await reader.api.updateOrganization({ headers, body: { organizationId: "source-parent", data: { name: "Updated" } } }); break;
                case "organization-update-denied": await reader.api.updateOrganization({ headers, body: { organizationId: "organization", data: { name: "Updated" } } }); break;
                case "organization-update-slug": await reader.api.updateOrganization({ headers, body: { organizationId: "organization", data: { slug: "other" } } }); break;
                case "organization-delete-disabled": case "organization-delete-disabled-session": case "organization-delete-session":
                case "organization-delete-denied": await reader.api.deleteOrganization({ headers, body: { organizationId: "organization" } }); break;
                case "organization-delete-empty": await reader.api.deleteOrganization({ headers, body: { organizationId: "" } }); break;
                case "organization-delete-member": await reader.api.deleteOrganization({ headers, body: { organizationId: "source-parent" } }); break;
                case "organization-get-missing": case "organization-get-member": await reader.api.getOrganization({ headers, query: queryInput }); break;
                case "organization-full-missing": case "organization-full-member": await reader.api.getFullOrganization({ headers, query: queryInput }); break;
                case "organization-active-missing": await reader.api.setActiveOrganization({ headers, body: { organizationSlug: "missing" } }); break;
                case "organization-active-member": await reader.api.setActiveOrganization({ headers, body: { organizationId: "source-parent" } }); break;
                case "organization-leave-member": await reader.api.leaveOrganization({ headers, body: { organizationId: "source-parent" } }); break;
                case "organization-leave-owner": await reader.api.leaveOrganization({ headers, body: { organizationId: "organization" } }); break;
              }
            } catch (error) { caught = error; }
            expect(caught).toMatchObject({ name: "APIError", statusCode: status });
            expectOrdered(Reflect.get(caught as object, "body"), errorBody);
            response = toResponse(caught);
          }
          expect(response.status).toBe(status);
          expect(await response.text()).toBe(JSON.stringify(errorBody) ?? "");
          expect(events).toStrictEqual(clearsActive(mode) ? [["session.updatedAt", "onUpdate"]] : []);
          if (clearsActive(mode)) {
            const session = before.session.find(row => row.id === "session-a");
            if (!session) throw new Error("Expected complete stored Session");
            session.activeOrganizationId = null;
          }
          expect(source.snapshot()).toStrictEqual(before);
        } finally { source.close(); }
      });
    }
  }
}
