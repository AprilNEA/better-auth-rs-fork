import { expect, test } from "bun:test";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, outputField } from "./organization-invitation-response-contract";
import { build, fixture, mutate, past, replace, visible } from "./organization-live-source-contract";
import { date, type Backend, type Events, type Fields } from "./organization-team-member-contract";

type Entry = "native" | "http";

async function call(auth: ReturnType<typeof build>, entry: Entry, team: boolean, denied: boolean) {
  const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", auth.options.secret!)).split(";", 1)[0];
  const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
  const body = { teamId: "source-a", data: { name: "Updated", organizationId: denied ? "other" : "organization" } };
  if (entry === "native") return team
    ? auth.api.updateTeam({ headers, body })
    : auth.api.getInvitation({ headers, query: { id: "source-a" } });
  const path = team ? "update-team" : "get-invitation?id=source-a";
  return auth.handler(new Request(`${baseURL}/api/auth/organization/${path}`, {
    method: team ? "POST" : "GET", headers, ...(team ? { body: JSON.stringify(body) } : {}),
  }));
}

async function response(operation: Promise<unknown>, entry: Entry, expected: Fields, status: number) {
  if (entry === "http") {
    const actual = await operation;
    expect(actual).toBeInstanceOf(Response);
    expect((actual as Response).status).toBe(status);
    expect(await (actual as Response).text()).toBe(JSON.stringify(expected));
  } else if (status === 200) {
    const actual = await operation;
    expectOrdered(actual, expected);
    expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
  } else {
    let caught: unknown;
    try { await operation; } catch (error) { caught = error; }
    expect(caught).toMatchObject({ name: "APIError", statusCode: status });
    expectOrdered(Reflect.get(caught as object, "body"), expected);
  }
}

async function invitation(backend: Backend, entry: Entry) {
  const source = await fixture(backend, `invitation-consumption-${entry}`);
  try {
    const row = { ...visible("invitation", "source-a", "First"), organizationId: "organization", email: "user-a@team-member-fields.test" };
    await source.writer.create({ model: "invitation", forceAllowId: true, data: row });
    const after = source.snapshot();
    const events: Events = [];
    const reader = build(source.options, "invitation", {
      organizationId: outputField("organizationId", [], async value => {
        events.push(["organizationId", value]);
        await mutate(source.writer, "invitation", "source-a");
        return value;
      }, { type: "string" }),
      expiresAt: outputField("expiresAt", [], value => { events.push(["expiresAt", value]); return value; }, { type: "date" }),
    });
    const expected = backend === "memory" ? { message: "Invitation not found!" } : {
      ...row, organizationName: "Organization", organizationSlug: "organization", inviterEmail: "user-a@team-member-fields.test",
    };
    await response(call(reader, entry, false, false), entry, expected, backend === "memory" ? 400 : 200);
    expectOrdered(events, [["organizationId", "organization"], ["expiresAt", source.stored({ value: backend === "memory" ? past() : date(0) }).value]]);
    replace(after, "invitation", "source-a", [source.stored({ ...row, expiresAt: past() })]);
    expect(source.snapshot()).toStrictEqual(after);
  } finally { source.close(); }
}

function publicTeam(name: string, organizationId: string) {
  const row = visible("team", "source-a", name);
  delete row.memberCount;
  return { ...row, organizationId };
}
const hook = (team: unknown, organizationId: unknown = "organization", userId: unknown = "user-a") => ({ team, organizationId, userId });

async function team(backend: Backend, entry: Entry, denied: boolean) {
  const source = await fixture(backend, `team-consumption-${entry}-${denied}`);
  try {
    await source.writer.create({ model: "team", forceAllowId: true, data: { ...visible("team", "source-a", "First"), organizationId: "organization" } });
    const after = source.snapshot();
    const events: Events = [];
    const reader = build(source.options, "team", {
      name: outputField("name", [], async value => {
        events.push(["name", value]);
        if (value === "Updated") await mutate(source.writer, "team", "source-a");
        return value;
      }, { type: "string" }),
      organizationId: outputField("organizationId", [], value => { events.push(["organizationId", value]); return value; }, { type: "string" }),
    }, { organizationHooks: {
      beforeUpdateTeam({ team, updates, organization, user }) {
        expectOrdered(updates, { name: "Updated" });
        events.push(["before", hook(team, organization.id, user.id)]);
        return Promise.resolve();
      },
      afterUpdateTeam({ team, organization, user }) {
        events.push(["after", hook(team, organization.id, user.id)]);
        return Promise.resolve();
      },
    } });
    if (denied) {
      await response(call(reader, entry, true, true), entry, {
        code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM", message: "You are not allowed to update this team",
      }, 403);
      expect(events).toStrictEqual([]);
    } else {
      const organizationId = backend === "memory" ? "other" : "organization";
      const expected = publicTeam("Updated", organizationId);
      await response(call(reader, entry, true, false), entry, expected, 200);
      expectOrdered(events, [
        ["name", "First"], ["organizationId", "organization"], ["before", hook(publicTeam("First", "organization"))],
        ["name", "Updated"], ["organizationId", organizationId], ["after", hook(expected)],
      ]);
      replace(after, "team", "source-a", [source.stored({ ...visible("team", "source-a", "Updated"), organizationId: "other" })]);
    }
    expect(source.snapshot()).toStrictEqual(after);
  } finally { source.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const entry of ["native", "http"] as const) {
    test(`${backend} Invitation ${entry} expires from the projected deadline`, () => invitation(backend, entry));
    for (const denied of [false, true]) {
      test(`${backend} Team ${entry} consumes projected scope after authorization: denied=${denied}`, () => team(backend, entry, denied));
    }
  }
}
