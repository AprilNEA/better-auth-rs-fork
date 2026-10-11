import { expect, spyOn, test } from "bun:test";
import { getCurrentAdapter } from "@better-auth/core/context";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import { date, membershipKey, type Backend, type Events, type Fields } from "./organization-team-member-contract";

type Mode = "commit" | "version" | "clone" | "signer" | "member";
type Storage = "database" | "cache-only" | "mirror";
type Entry = "native" | "http";
type CacheWrite = [string, string, number | undefined];
const token = "invitation-response-token";
const listKey = "active-sessions-user-b";
const marker = {
  id: "cookie-verification", identifier: "cookie-transaction", value: "signed-in-transaction",
  expiresAt: date(100), createdAt: date(0), updatedAt: date(0),
};
const response = {
  invitation: {
    organizationId: "organization", email: "user-b@team-member-fields.test", role: "member", teamId: "team-a",
    status: "accepted", expiresAt: date(30), createdAt: date(0), inviterId: "user-a", id: "invitation-a",
  },
  member: { organizationId: "organization", userId: "user-b", role: "member", createdAt: date(0), id: "member-a" },
};

function committedStorage(before: Record<string, Fields[]>, fixture: Awaited<ReturnType<typeof setup>>, storage: Storage) {
  const expected = structuredClone(before);
  expected.verification = [fixture.stored(marker)];
  expected.member.unshift(fixture.stored(member("member-a", "user-b", "member")));
  expected.teamMember = [fixture.stored({
    id: "teamMember-a", teamId: "team-a", userId: "user-b",
    membershipKey: membershipKey("team-a", "user-b"), createdAt: date(0),
  })];
  expected.team = expected.team.map(row => row.id === "team-a" ? { ...row, memberCount: 1 } : row);
  expected.invitation = expected.invitation.map(row => ({ ...row, status: "accepted" }));
  if (storage !== "cache-only") expected.session = expected.session.map(row => ({
    ...row, ...fixture.stored({ updatedAt: date(0) }),
    activeTeamId: "team-a", activeOrganizationId: "organization", ipAddress: "organization",
  }));
  return expected;
}

async function checkCookieTransaction(backend: Backend, mode: Mode, storage: Storage, entry: Entry) {
  const fixture = await setup(backend, { name: mode, route: "accept", teamIds: "team-a" });
  let now: ReturnType<typeof spyOn> | undefined;
  try {
    await fixture.context.adapter.update({ model: "session", where: [{ field: "id", value: "session-a" }],
      update: { ipAddress: "initial", userAgent: "initial-agent", updatedAt: date(0) } });
    const before = fixture.snapshot();
    const committed = committedStorage(before, fixture, storage);
    const seedSession = (await fixture.context.adapter.findOne<Fields>({ model: "session", where: [{ field: "id", value: "session-a" }] }))!;
    const seedUser = (await fixture.context.adapter.findOne<Fields>({ model: "user", where: [{ field: "id", value: "user-b" }] }))!;
    const seedOrganization = (await fixture.context.adapter.findOne<Fields>({ model: "organization", where: [{ field: "id", value: "organization" }] }))!;
    const entries = new Map<string, string>();
    const writes: CacheWrite[] = [];
    const events: Events = [];
    const failure = new TypeError(`${mode}-cookie-transaction`);
    const functionValue = () => "active-team-function";
    const cache = storage !== "database";
    const database = storage !== "cache-only";
    const cacheSession = (phase: "team" | "organization") => ({
      ...seedSession, activeTeamId: "team-a", activeOrganizationId: phase === "team" ? null : "organization", ipAddress: phase,
    });
    const outputSession = (phase: "team" | "organization") => ({
      ...cacheSession(phase), ipAddress: database ? `${phase}:projected` : phase,
    });
    const cookiePayload = { session: outputSession("team"), user: seedUser, updatedAt: date(0).getTime(), version: "invitation-version" };
    const ttl = (new Date("2100-01-01T00:00:00.000Z").getTime() - date(0).getTime()) / 1000;
    const cacheWrites = (phase: "team" | "organization"): CacheWrite[] => [
      [token, JSON.stringify({ session: cacheSession(phase), user: seedUser }), ttl],
      [listKey, JSON.stringify([{ token, expiresAt: new Date("2100-01-01T00:00:00.000Z").getTime() }]), ttl],
    ];
    if (cache) entries.set(token, JSON.stringify({ session: seedSession, user: seedUser }));
    let recording = false;
    let versionSession: object | undefined;
    let versionUser: object | undefined;
    let context: typeof fixture.context;
    const auth = betterAuth({
      ...fixture.options,
      verification: { storeInDatabase: true },
      ...(cache ? { secondaryStorage: {
        async get(key: string) { return entries.get(key) ?? null; },
        async set(key: string, value: string, seconds?: number) {
          writes.push([key, value, seconds]);
          events.push(["cache.set", key, value, seconds]);
          entries.set(key, value);
        },
        async delete(key: string) { events.push(["cache.delete", key]); entries.delete(key); },
      } } : {}),
      session: {
        storeSessionInDatabase: database,
        additionalFields: {},
        cookieCache: { enabled: true, strategy: "jwt", maxAge: 300, async version(session, user) {
          if (!recording) return "initial-version";
          versionSession = session;
          versionUser = user;
          expectOrdered(session, outputSession("team"));
          expectOrdered(user, seedUser);
          events.push(["version", session, user]);
          if (cache) expect(writes).toStrictEqual(cacheWrites("team"));
          if (mode === "version") throw failure;
          return "invitation-version";
        } },
      },
      databaseHooks: { session: { update: {
        before(data) {
          const phase = "activeTeamId" in data ? "team" : "organization";
          events.push(["before.session", phase, data]);
          return Promise.resolve({ data: { ipAddress: phase } });
        },
        after(session) {
          expect(fixture.snapshot()).toStrictEqual(committed);
          events.push(["after.session", session]);
          return Promise.resolve();
        },
      } } },
      plugins: [organization({
        teams: { enabled: true, maximumMembersPerTeam: 1 },
        organizationHooks: {
          beforeAcceptInvitation(data) {
            recording = true;
            expectOrdered(data, { invitation: { ...response.invitation, status: "pending" }, user: seedUser, organization: seedOrganization });
            events.push(["before.accept"]);
            return Promise.resolve();
          },
          afterAcceptInvitation(data) {
            expectOrdered(data, { ...response, user: seedUser, organization: seedOrganization });
            events.push(["after.accept"]);
            return Promise.resolve();
          },
        },
      }), { id: "invitation-cookie-transaction-fields", schema: {
        member: { fields: {
          role: { type: "string", transform: { async output(value) {
            if (recording) {
              events.push(["output.member", value]);
              const current = await getCurrentAdapter(context.adapter);
              expect(await current.count({ model: "member", where: [{ field: "organizationId", value: "organization" }] })).toBe(2);
              expect(await current.count({ model: "verification", where: [{ field: "id", value: marker.id }] })).toBe(1);
              if (mode === "member") throw failure;
            }
            return value;
          } } },
          createdAt: { type: "date", transform: { input: () => date(0) } },
        } },
        teamMember: { fields: { createdAt: { type: "date", transform: { input: () => date(0) } } } },
        session: { fields: {
          updatedAt: { type: "date", onUpdate: () => date(0) },
          ipAddress: { type: "string", transform: { output(value) {
            if (!recording) return value;
            events.push(["output.ip", value]);
            return `${value}:projected`;
          } } },
          userAgent: { type: "string", transform: { output(value) {
            if (recording) events.push(["output.agent", value]);
            return value;
          } } },
          activeTeamId: outputField("output.team", [], value => {
            if (!recording) return value;
            events.push(["output.team", value]);
            return mode === "clone" ? functionValue : value;
          }, { type: "string", required: false }),
        } },
      } }],
    });
    context = await auth.$context;
    context.sessionConfig.cookieCacheSigner = {
      async sign(_ctx, payload, expiresIn) {
        if (!recording) return "initial-cookie-signature";
        expectOrdered(payload, cookiePayload);
        expect(payload.session).not.toBe(versionSession);
        expect(payload.user).not.toBe(versionUser);
        expect(expiresIn).toBe(300);
        events.push(["signer", payload, expiresIn]);
        const current = await getCurrentAdapter(context.adapter);
        expect(current).not.toBe(context.adapter);
        expect(await current.count({ model: "teamMember", where: [{ field: "teamId", value: "team-a" }] })).toBe(1);
        expect(await current.count({ model: "member", where: [{ field: "organizationId", value: "organization" }] })).toBe(1);
        expect(await current.create({ model: "verification", data: marker, forceAllowId: true })).toStrictEqual(marker);
        if (cache) expect(writes).toStrictEqual(cacheWrites("team"));
        if (mode === "signer") throw failure;
        return "invitation-cookie-signature";
      },
      async verify() { throw new Error("Cookie signer verification is not part of this request"); },
    };
    const cookie = (await serializeSignedCookie("better-auth.session_token", token, fixture.options.secret!)).split(";", 1)[0];
    const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
    now = spyOn(Date, "now").mockReturnValue(date(0).getTime());
    if (entry === "native") {
      if (mode === "commit") expectOrdered(await auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } }), response);
      else {
        let caught: unknown;
        try { await auth.api.acceptInvitation({ headers, body: { invitationId: "invitation-a" } }); } catch (error) { caught = error; }
        if (mode === "clone") expect(caught).toMatchObject({ name: "DataCloneError", message: "The object can not be cloned." });
        else expect(caught).toBe(failure);
      }
    } else {
      const result = await auth.handler(new Request(`${baseURL}/api/auth/organization/accept-invitation`, {
        method: "POST", headers, body: JSON.stringify({ invitationId: "invitation-a" }),
      }));
      expect(result.status).toBe(mode === "commit" ? 200 : 500);
      expect(await result.text()).toBe(mode === "commit" ? JSON.stringify(response) : "");
    }
    const expected: Events = [["before.accept"], ["before.session", "team", { activeTeamId: "team-a" }]];
    const appendSessionWork = (phase: "team" | "organization") => {
      if (cache) expected.push(...cacheWrites(phase).map(write => ["cache.set", ...write]));
      if (database) expected.push(["output.ip", phase], ["output.agent", "initial-agent"], ["output.team", "team-a"]);
    };
    appendSessionWork("team");
    if (mode !== "clone") expected.push(["version", outputSession("team"), seedUser]);
    if (mode !== "clone" && mode !== "version") expected.push(["signer", cookiePayload, 300]);
    if (mode === "commit" || mode === "member") expected.push(["output.member", "member"]);
    if (mode === "commit") {
      expected.push(["before.session", "organization", { activeOrganizationId: "organization" }]);
      appendSessionWork("organization");
      expected.push(["after.session", outputSession("team")], ["after.session", outputSession("organization")], ["after.accept"]);
    }
    expectOrdered(events, expected);
    expect(fixture.snapshot()).toStrictEqual(mode === "commit" ? committed : before);
    const expectedWrites = cache ? [...cacheWrites("team"), ...(mode === "commit" ? cacheWrites("organization") : [])] : [];
    expect(writes).toStrictEqual(expectedWrites);
    expect([...entries]).toStrictEqual(cache ? cacheWrites(mode === "commit" ? "organization" : "team").map(([key, value]) => [key, value]) : []);
  } finally { now?.mockRestore(); fixture.close(); }
}

for (const backend of ["memory", "sqlite"] as const) for (const entry of ["native", "http"] as const) {
  for (const mode of ["commit", "version", "clone", "signer", "member"] as const) {
    test(`${backend} invitation Cookie transaction ${mode} ${entry} preserves callbacks and complete storage`, () =>
      checkCookieTransaction(backend, mode, "database", entry));
  }
  for (const storage of ["cache-only", "mirror"] as const) for (const mode of ["commit", "version", "member"] as const) {
    test(`${backend} invitation Cookie transaction ${storage} ${mode} ${entry} preserves immediate cache writes`, () =>
      checkCookieTransaction(backend, mode, storage, entry));
  }
}
