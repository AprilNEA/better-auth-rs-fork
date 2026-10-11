import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, outputField, setup } from "./organization-invitation-response-contract";
import { date, type Backend, type Events, type Policies } from "./organization-team-member-contract";

type Metadata = "parsed" | "undefined" | "omitted" | "final-parse-error";
const modes: Metadata[] = ["parsed", "undefined", "omitted", "final-parse-error"];
const changedMetadata = '{"source":"changed"}';
const initialMetadata = '{"source":"initial"}';
const permissionError = { message: "Invalid permissions for role custom" };

async function headers(secret: string) {
  const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", secret)).split(";", 1)[0];
  return new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
}

function fixedCreation(model: string, events: Events): Policies {
  return { createdAt: { type: "date", transform: { input(value) {
    expect(value).toBeInstanceOf(Date);
    events.push([`${model}.createdAt`, "input", "native-date"]);
    return date(0);
  } } } };
}

function visibleOrganization(backend: Backend, mode: Metadata) {
  const fields: Record<string, unknown> = {
    name: "Created", slug: "created", logo: null, createdAt: date(0),
  };
  if (mode !== "omitted") fields.metadata = mode === "parsed"
    ? { source: backend === "memory" ? "changed" : "initial" } : mode === "final-parse-error" ? "bad-json" : undefined;
  fields.id = "organization-a";
  if (mode === "omitted") fields.metadata = undefined;
  return fields;
}

const visibleMember = () => ({
  organizationId: "organization-a", userId: "user-a", role: "owner", createdAt: date(0), id: "member-a",
});

for (const backend of ["memory", "sqlite"] as const) {
  for (const mode of modes) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Organization create ${entry} consumes live metadata ${mode}`, async () => {
        const fixture = await setup(backend, { name: mode, route: "cancel", dynamicAccessControl: true });
        const events: Events = [];
        try {
          await fixture.context.adapter.delete({ model: "member", where: [{ field: "id", value: "owner-member" }] });
          const before = fixture.snapshot();
          const auth = betterAuth({ ...fixture.options, plugins: [organization({
            teams: { enabled: true, defaultTeam: { enabled: false } },
            dynamicAccessControl: { enabled: true },
            schema: { organization: { additionalFields: mode === "omitted" ? { metadata: { type: "json", returned: false } } : {} } },
            organizationHooks: {
              afterAddMember(data) { events.push(["afterAddMember", data.organization, data.member]); return Promise.resolve(); },
              afterCreateOrganization(data) { events.push(["afterCreateOrganization", data.organization, data.member]); return Promise.resolve(); },
            },
          }), { id: "live-organization-business-fields", schema: {
            organization: { fields: {
              ...fixedCreation("organization", events),
              name: { type: "string", transform: { async output(value) {
                events.push(["organization.name", "output", value]);
                await fixture.context.adapter.update({ model: "organization", where: [{ field: "id", value: "organization-a" }], update: { metadata: changedMetadata } });
                return value;
              } } },
              metadata: { type: "string", transform: { output(value) {
                events.push(["organization.metadata", "output", value]);
                return mode === "undefined" ? undefined : mode === "final-parse-error" ? '"bad-json"' : value;
              } } },
            } },
            member: { fields: fixedCreation("member", events) },
            session: { fields: { updatedAt: { type: "date", onUpdate() {
              events.push(["session.updatedAt", "onUpdate"]);
              return date(0);
            }, transform: { input(value) {
              expect(value).toBeInstanceOf(Date);
              events.push(["session.updatedAt", "input", "native-date"]);
              return date(0);
            } } } } },
          } }] });
          const fails = mode === "final-parse-error";
          const body = { name: "Created", slug: "created", logo: null, metadata: { source: "initial" }, keepCurrentActiveOrganization: !fails };
          const requestHeaders = await headers(fixture.options.secret!);
          const org = visibleOrganization(backend, mode);
          const hookOrg = { ...org };
          if (mode === "omitted") delete hookOrg.metadata;
          const member = visibleMember();
          const expected = { ...org, members: [member] };
          if (entry === "native") {
            if (fails) {
              let caught: unknown;
              try { await auth.api.createOrganization({ headers: requestHeaders, body }); } catch (error) { caught = error; }
              expect(caught).toBeInstanceOf(SyntaxError);
            } else expectOrdered(await auth.api.createOrganization({ headers: requestHeaders, body }), expected);
          }
          else {
            const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/create`, {
              method: "POST", headers: requestHeaders, body: JSON.stringify(body),
            }));
            expect(response.status).toBe(fails ? 500 : 200);
            expect(await response.text()).toBe(fails ? "" : JSON.stringify(expected));
          }
          expectOrdered(events, [
            ["organization.createdAt", "input", "native-date"],
            ["organization.name", "output", "Created"],
            ["organization.metadata", "output", backend === "memory" ? changedMetadata : initialMetadata],
            ["member.createdAt", "input", "native-date"],
            ["afterAddMember", hookOrg, member],
            ["afterCreateOrganization", hookOrg, member],
            ...(fails ? [["session.updatedAt", "onUpdate"], ["session.updatedAt", "input", "native-date"]] : []),
          ]);
          before.organization.push(fixture.stored({
            id: "organization-a", name: "Created", slug: "created", logo: null, createdAt: date(0), metadata: changedMetadata,
          }));
          before.member = [fixture.stored({ id: "member-a", organizationId: "organization-a", userId: "user-a", role: "owner", createdAt: date(0) })];
          if (fails) before.session = before.session.map(row => ({ ...row, activeOrganizationId: "organization-a", updatedAt: fixture.stored({ updatedAt: date(0) }).updatedAt }));
          expect(fixture.snapshot()).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }

  for (const mode of ["dynamic", "utf16"] as const) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} Organization update ${entry} retains ${mode} metadata until serialization`, async () => {
        const fixture = await setup(backend, { name: `update-${mode}`, route: "cancel", dynamicAccessControl: true });
        const events: Events = [];
        const source = mode === "dynamic" ? {
          undefined: undefined, infinity: Infinity, date: date(0),
          function() { events.push(["metadata.function", "called"]); return "called"; },
          nested: { value: "retained" },
        } : '{"units":"' + '\ud800' + '","date":"2030-01-01T00:00:00.000Z"}';
        const metadata = mode === "dynamic" ? source : { units: '\ud800', date: date(0) };
        let observed: unknown;
        try {
          const before = fixture.snapshot();
          const auth = betterAuth({ ...fixture.options, plugins: [organization({
            teams: { enabled: true }, dynamicAccessControl: { enabled: true },
            organizationHooks: { afterUpdateOrganization(data) {
              observed = data.organization.metadata;
              if (mode === "dynamic") expect(observed).toBe(source);
              events.push(["afterUpdateOrganization", data.organization]);
              return Promise.resolve();
            } },
          }), { id: "native-organization-update-fields", schema: { organization: { fields: {
            metadata: outputField("metadata", events, () => source, { type: "string" }),
          } } } }] });
          const requestHeaders = await headers(fixture.options.secret!);
          const body = { organizationId: "organization", data: { name: "Updated", metadata: { source: "written" } } };
          const expected = { name: "Updated", slug: "organization", logo: null, createdAt: date(0), metadata, id: "organization" };
          if (entry === "native") {
            const actual = await auth.api.updateOrganization({ headers: requestHeaders, body });
            expectOrdered(actual, expected);
            expect(actual!.metadata).toBe(observed);
          } else {
            const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/update`, {
              method: "POST", headers: requestHeaders, body: JSON.stringify(body),
            }));
            expect(response.status).toBe(200);
            expect(await response.text()).toBe(JSON.stringify(expected));
          }
          expectOrdered(events, [["metadata", "output", '{"source":"written"}'], ["afterUpdateOrganization", expected]]);
          before.organization = before.organization.map(row => row.id === "organization"
            ? { ...row, name: "Updated", metadata: '{"source":"written"}' } : row);
          expect(fixture.snapshot()).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }

  for (const malformed of [false, true]) {
    for (const entry of ["native", "http"] as const) {
      test(`${backend} OrganizationRole has-permission ${entry} consumes live ${malformed ? "invalid" : "grant"} permission`, async () => {
        const fixture = await setup(backend, { name: "role-permission", route: "cancel", dynamicAccessControl: true });
        const events: Events = [];
        const permission = JSON.stringify(malformed ? { team: true } : { team: ["create"] });
        try {
          await fixture.context.adapter.update({ model: "member", where: [{ field: "id", value: "owner-member" }], update: { role: "custom" } });
          await fixture.context.adapter.create({ model: "organizationRole", forceAllowId: true, data: {
            id: "organizationRole-a", organizationId: "organization", role: "custom", permission: "{}", createdAt: date(0), updatedAt: date(0),
          } });
          const before = fixture.snapshot();
          const writer = await betterAuth({ ...fixture.options, plugins: [organization({ dynamicAccessControl: { enabled: true } }), {
            id: "live-role-writer-date", schema: { organizationRole: { fields: { updatedAt: { type: "date", onUpdate: () => date(0) } } } },
          }] }).$context;
          const auth = betterAuth({ ...fixture.options, plugins: [organization({
            teams: { enabled: true }, dynamicAccessControl: { enabled: true }, ac: createAccessControl({ team: ["create"] }),
          }), { id: "live-role-business-fields", schema: { organizationRole: { fields: {
            organizationId: { type: "string", transform: { async output(value) {
              events.push(["organizationId", "output", value]);
              await writer.adapter.update({ model: "organizationRole", where: [{ field: "id", value: "organizationRole-a" }], update: { permission } });
              return value;
            } } },
            permission: { type: "string", transform: { output(value) { events.push(["permission", "output", value]); return value; } } },
          } } } }] });
          const requestHeaders = await headers(fixture.options.secret!);
          const body = { organizationId: "organization", permissions: { team: ["create"] } };
          const fails = backend === "memory" && malformed;
          const expected = { error: null, success: backend === "memory" };
          if (entry === "native") {
            if (fails) {
              let caught: unknown;
              try { await auth.api.hasPermission({ headers: requestHeaders, body }); } catch (error) { caught = error; }
              expect(caught).toBeInstanceOf(APIError);
              if (!(caught instanceof APIError)) throw new Error("Expected native invalid-permission APIError");
              expect(caught.status).toBe("INTERNAL_SERVER_ERROR");
              expectOrdered(caught.body, permissionError);
            } else expectOrdered(await auth.api.hasPermission({ headers: requestHeaders, body }), expected);
          } else {
            const response = await auth.handler(new Request(`${baseURL}/api/auth/organization/has-permission`, {
              method: "POST", headers: requestHeaders, body: JSON.stringify(body),
            }));
            expect(response.status).toBe(fails ? 500 : 200);
            expect(await response.text()).toBe(JSON.stringify(fails ? permissionError : expected));
          }
          expectOrdered(events, [["organizationId", "output", "organization"], ["permission", "output", backend === "memory" ? permission : "{}"]]);
          before.organizationRole = before.organizationRole.map(row => ({ ...row, permission }));
          expect(fixture.snapshot()).toStrictEqual(before);
        } finally { fixture.close(); }
      });
    }
  }
}
