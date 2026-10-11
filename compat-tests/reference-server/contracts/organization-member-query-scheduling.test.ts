import { expect, test } from "bun:test";
import { getCurrentAuthEndpointContext, runWithEndpointContext } from "@better-auth/core/context";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { organization } from "better-auth/plugins";
import { serializeSignedCookie } from "better-call";
import { baseURL, expectOrdered, member, setup } from "./organization-invitation-response-contract";
import { date, type Events } from "./organization-team-member-contract";

const { getOrgAdapter } = await import(new URL("../node_modules/better-auth/dist/plugins/organization/adapter.mjs", import.meta.url).href);

const rows = [
  { ...member("member-z", "user-z", "selected"), createdAt: date(30) },
  { ...member("member-a", "user-a-query", "selected"), createdAt: date(10) },
  { ...member("member-m", "user-m", "selected"), createdAt: date(20) },
];
const cases = [
  { name: "insertion-order", query: {}, selected: [0, 1, 2], total: 3 },
  { name: "page-and-total", query: { limit: 1, offset: 1 }, selected: [1], total: 3 },
  { name: "explicit-sort", query: { sortBy: "createdAt", sortDirection: "asc" as const }, selected: [1, 2, 0], total: 3 },
  { name: "unknown-sort-empty", query: { sortBy: "unknown", filterField: "userId", filterValue: "absent" }, selected: [], total: 0 },
  { name: "unknown-sort-single", query: { sortBy: "unknown", filterField: "userId", filterValue: "user-a-query" }, selected: [1], total: 1 },
  { name: "unknown-sort-many", query: { sortBy: "unknown" }, selected: [0, 1, 2], total: 3 },
];

function adapterMember(row: typeof rows[number], role: string) {
  return {
    organizationId: row.organizationId, userId: row.userId, role, createdAt: row.createdAt, id: row.id,
  };
}

function visibleMember(row: typeof rows[number], role: string) {
  return {
    ...adapterMember(row, role),
    user: { id: row.userId, name: row.userId, email: `${row.userId}@team-member-fields.test`, image: null },
  };
}

function observeMemberReads(adapter: DBAdapter) {
  type Outcome = { value: unknown } | { error: unknown };
  const page = Promise.withResolvers<Outcome>();
  const count = Promise.withResolvers<Outcome>();
  const calls: string[] = [];
  const settled = { page: false, count: false };
  // Observe the real operations and return each original promise without changing its result.
  adapter.findMany = new Proxy(adapter.findMany, { apply(target, receiver, args) {
    calls.push(`findMany:${args[0].model}`);
    const pending: Promise<unknown> = Reflect.apply(target, receiver, args);
    if (args[0].model === "member") void pending.then(
      value => { settled.page = true; page.resolve({ value }); },
      error => { settled.page = true; page.resolve({ error }); },
    );
    return pending;
  } });
  adapter.count = new Proxy(adapter.count, { apply(target, receiver, args) {
    calls.push(`count:${args[0].model}`);
    const pending: Promise<unknown> = Reflect.apply(target, receiver, args);
    if (args[0].model === "member") void pending.then(
      value => { settled.count = true; count.resolve({ value }); },
      error => { settled.count = true; count.resolve({ error }); },
    );
    return pending;
  } });
  return { page: page.promise, count: count.promise, calls, settled };
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const scenario of cases) {
    test(`${backend} native Member independent page and count preserve ${scenario.name}`, async () => {
      const fixture = await setup(backend, { name: scenario.name, route: "cancel" });
      try {
        for (const row of rows) {
          await fixture.context.adapter.create({ model: "user", forceAllowId: true, data: {
            id: row.userId, name: row.userId, email: `${row.userId}@team-member-fields.test`, emailVerified: true,
            image: null, createdAt: date(0), updatedAt: date(0),
          } });
          await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: row });
        }
        const before = fixture.snapshot();
        const events: Events = [];
        const auth = betterAuth({ ...fixture.options, plugins: [organization({ teams: { enabled: true } }), {
          id: "member-query-fields", schema: { member: { fields: { role: { type: "string", transform: {
            input(value) { events.push(["role", "input", value]); throw new Error("query-input-must-not-run"); },
            output(value) { events.push(["role", "output", value]); return `${value}:visible`; },
          } } } } },
        }] });
        const cookie = (await serializeSignedCookie("better-auth.session_token", "invitation-response-token", fixture.options.secret!)).split(";", 1)[0];
        const headers = new Headers({ cookie, origin: baseURL, "content-type": "application/json" });
        let actual: unknown;
        let caught: unknown;
        try {
          actual = await auth.api.listMembers({ headers, query: {
            organizationId: "organization", filterField: "role", filterValue: "selected", ...scenario.query,
          } });
        } catch (error) { caught = error; }
        const fails = scenario.query.sortBy === "unknown" && (backend === "sqlite" || scenario.total > 1);
        if (fails) {
          expect(actual).toBeUndefined();
          expect(caught).toBeInstanceOf(Error);
          expect({ name: (caught as Error).name, message: (caught as Error).message }).toStrictEqual({
            name: "BetterAuthError", message: "Field unknown not found in model member",
          });
        } else {
          expect(caught).toBeUndefined();
          expectOrdered(actual, {
            members: scenario.selected.map(index => visibleMember(rows[index]!, "selected:visible")), total: scenario.total,
          });
        }
        expect(events).toStrictEqual([
          ["role", "output", "owner"], ...(fails ? [] : scenario.selected.map(() => ["role", "output", "selected"])),
        ]);
        expect(fixture.snapshot()).toStrictEqual(before);
      } finally { fixture.close(); }
    });
  }
}

for (const mode of ["success", "page-error", "count-error", "both-errors"] as const) {
  test(`Memory Member independent scans preserve ${mode} and the continuing peer context`, async () => {
    const fixture = await setup("memory", { name: mode, route: "cancel" });
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const finished = Promise.withResolvers<void>();
    try {
      await fixture.context.adapter.deleteMany({ model: "member", where: [{ field: "organizationId", value: "organization" }] });
      const row = member("schedule-member", "user-b", "z");
      await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: row });
      const before = fixture.snapshot();
      const events: string[] = [];
      const userReads: unknown[] = [];
      const headers = new Headers({ "x-contract": "member-query-peer" });
      const request = new Request(`${baseURL}/organization/list-members`, { headers });
      const assertContext = () => {
        const current = getCurrentAuthEndpointContext();
        expect(current.path).toBe("/organization/list-members");
        expect(current.headers?.get("x-contract")).toBe("member-query-peer");
        expect(current.request).toBe(request);
        expect(current.request?.headers.get("x-contract")).toBe("member-query-peer");
      };
      const context = await betterAuth({ ...fixture.options, plugins: [organization({ teams: { enabled: true } }), {
        id: "member-query-peer-fields", schema: {
          member: { fields: { role: { type: "string", transform: {
            input() { throw new Error("query-input-must-not-run"); },
            async output(value) {
              assertContext();
              expect(value).toBe("z");
              events.push("output-start");
              started.resolve();
              if (mode === "count-error") {
                await release.promise;
                assertContext();
                await fixture.context.adapter.update({ model: "member", where: [{ field: "id", value: "schedule-member" }],
                  update: { role: "after-error" } });
                assertContext();
              }
              events.push("output-end");
              finished.resolve();
              return `${value}:visible`;
            },
          } } } },
          user: { fields: { name: { type: "string", transform: { output(value) {
            assertContext();
            userReads.push(value);
            return value;
          } } } } },
        },
      }] }).$context;
      const pageError = new Error("member-page-original");
      const countError = new Error("member-count-original");
      let reads = 0;
      const operand = { get toString() {
        assertContext();
        const read = ++reads;
        events.push(`get-${read}`);
        if (read === 1 && (mode === "page-error" || mode === "both-errors")) throw pageError;
        if (read === 2 && (mode === "count-error" || mode === "both-errors")) throw countError;
        return Object.prototype.toString;
      } };
      const observed = observeMemberReads(context.adapter);
      // The HTTP filter schema rejects native objects. The adapter accepts this property getter.
      const pending = runWithEndpointContext({ context, path: "/organization/list-members", headers, request }, () =>
        getOrgAdapter(context, {}).listMembers({
          organizationId: "organization", filter: { field: "role", operator: "gt", value: operand },
        }),
      ).then(value => ({ value }), error => ({ error }));
      if (mode === "count-error") await started.promise;
      const outcome = await pending;
      const counted = await observed.count;
      if (mode === "count-error" || mode === "both-errors") {
        expect("error" in counted ? counted.error : undefined).toBe(countError);
      } else expectOrdered(counted, { value: 1 });
      if (mode === "success") {
        expect("error" in outcome).toBe(false);
        expectOrdered("value" in outcome ? outcome.value : undefined, {
          members: [visibleMember(row, "z:visible")], total: 1,
        });
        expect(events).toStrictEqual(["get-1", "get-2", "output-start", "output-end"]);
        expect(userReads).toStrictEqual(["user-b"]);
        expectOrdered(await observed.page, { value: [adapterMember(row, "z:visible")] });
      } else {
        expect("value" in outcome).toBe(false);
        expect("error" in outcome ? outcome.error : undefined).toBe(mode === "count-error" ? countError : pageError);
        expect(events).toStrictEqual(mode === "count-error" ? ["get-1", "get-2", "output-start"] : ["get-1", "get-2"]);
        expect(userReads).toStrictEqual([]);
        if (mode === "count-error") expect(observed.settled.page).toBe(false);
        else {
          const paged = await observed.page;
          expect("error" in paged ? paged.error : undefined).toBe(pageError);
        }
      }
      expect(observed.calls).toStrictEqual(["findMany:member", "count:member", ...(mode === "success" ? ["findMany:user"] : [])]);
      expect(fixture.snapshot()).toStrictEqual(before);
      if (mode === "count-error") {
        release.resolve();
        await finished.promise;
        expectOrdered(await observed.page, { value: [adapterMember(row, "z:visible")] });
        expect(events).toStrictEqual(["get-1", "get-2", "output-start", "output-end"]);
        expect(userReads).toStrictEqual([]);
        expect(observed.calls).toStrictEqual(["findMany:member", "count:member"]);
        const after = structuredClone(before);
        after.member.find(value => value.id === "schedule-member")!.role = "after-error";
        expect(fixture.snapshot()).toStrictEqual(after);
      }
    } finally {
      release.resolve();
      fixture.close();
    }
  });
}

test("Memory Member scans read a later row after the operand getter changes that row", async () => {
  const fixture = await setup("memory", { name: "live-query-row", route: "cancel" });
  try {
    const memory = fixture.snapshot();
    memory.member = [];
    const options = { ...fixture.options, database: memoryAdapter(memory) };
    const writer = await betterAuth(options).$context;
    await writer.adapter.create({ model: "user", forceAllowId: true, data: {
      id: "user-following", name: "user-following", email: "user-following@team-member-fields.test", emailVerified: true,
      image: null, createdAt: date(0), updatedAt: date(0),
    } });
    const queryRows = [member("schedule-member", "user-b", "z"), member("following-member", "user-following", "A")];
    for (const row of queryRows) await writer.adapter.create({ model: "member", forceAllowId: true, data: row });
    const before = structuredClone(memory);
    const events: string[] = [];
    const headers = new Headers({ "x-contract": "member-query-peer" });
    const request = new Request(`${baseURL}/organization/list-members`, { headers });
    const assertContext = () => {
      const current = getCurrentAuthEndpointContext();
      expect(current.path).toBe("/organization/list-members");
      expect(current.headers?.get("x-contract")).toBe("member-query-peer");
      expect(current.request).toBe(request);
    };
    const context = await betterAuth({ ...options, plugins: [organization({ teams: { enabled: true } }), {
      id: "member-live-query-fields", schema: { member: { fields: { role: { type: "string", transform: {
        input() { throw new Error("query-input-must-not-run"); },
        output(value) {
          assertContext();
          events.push(`output:${value}`);
          return value;
        },
      } } } } },
    }] }).$context;
    let reads = 0;
    const operand = { get toString() {
      assertContext();
      const read = ++reads;
      events.push(`get-${read}`);
      if (read === 1) memory.member[1]!.role = "zz";
      return Object.prototype.toString;
    } };
    const observed = observeMemberReads(context.adapter);
    const actual = await runWithEndpointContext({ context, path: "/organization/list-members", headers, request }, () =>
      getOrgAdapter(context, {}).listMembers({
        organizationId: "organization", filter: { field: "role", operator: "gt", value: operand },
      }),
    );
    expectOrdered(actual, {
      members: [visibleMember(queryRows[0]!, "z"), visibleMember(queryRows[1]!, "zz")], total: 2,
    });
    expectOrdered(await observed.page, { value: [adapterMember(queryRows[0]!, "z"), adapterMember(queryRows[1]!, "zz")] });
    expectOrdered(await observed.count, { value: 2 });
    expect(observed.calls).toStrictEqual(["findMany:member", "count:member", "findMany:user"]);
    expect(events).toStrictEqual(["get-1", "get-2", "get-3", "get-4", "output:z", "output:zz"]);
    const after = structuredClone(before);
    after.member[1]!.role = "zz";
    expect(memory).toStrictEqual(after);
  } finally { fixture.close(); }
});
