import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import { date, type Backend, type Events, type Fields, type Policies } from "./organization-team-member-contract";

type Write = "insert" | "create" | "update";
type Mode = "success" | "input-error" | "output-error" | "live";
type List = "ordinary" | "native" | "query";
const id = (operation: Write) => operation === "insert" ? "insert-member" : operation === "create" ? "created-member" : "member-b";
const source = (operation: Write) => `${operation}-source`;
const visible = (id: string, userId: string, role: string, createdAt: unknown) => ({
  organizationId: "organization", userId, role, createdAt, id,
});
const whereId = (value: string) => [{ field: "id", value }];

function replace(snapshot: Record<string, Fields[]>, row: Fields) {
  snapshot.member = [...snapshot.member.filter(existing => existing.id !== row.id), row]
    .toSorted((left, right) => String(left.id).localeCompare(String(right.id)));
}

async function checkWrite(backend: Backend, operation: Write, mode: Mode) {
  const fixture = await setup(backend, { name: `crud-${operation}-${mode}`, route: "cancel" });
  try {
    if (operation === "update") {
      await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: member("member-b", "user-b", "member") });
    }
    const writer = await betterAuth({ ...fixture.options, plugins: [organization(), {
      id: "member-string-date-writer", schema: { member: { fields: { createdAt: { type: "string" } } } },
    }] }).$context;
    const before = fixture.snapshot();
    const events: Events = [];
    const shared = { native: source(operation) };
    const inputFailure = new TypeError("member-input-original");
    const outputFailure = new TypeError("member-output-original");
    const createdAt = outputField("createdAt", [], value => {
      events.push(["createdAt", "output", value]);
      if (mode === "output-error") throw outputFailure;
      return shared;
    }, { type: "string", onUpdate() {
      events.push(["createdAt", "onUpdate", undefined]);
      return "update-source";
    } });
    createdAt.transform!.input = value => {
      if (operation === "create") expect(value).toBeInstanceOf(Date);
      else expect(typeof value).toBe("string");
      events.push(["createdAt", "input", operation === "create" ? "native-date" : value]);
      if (mode === "input-error") throw inputFailure;
      return `stored:${operation === "create" ? source(operation) : value}`;
    };
    const fields: Policies = {
      organizationId: { type: "string", ...(mode === "live" ? { transform: { async output(value) {
        events.push(["organizationId", "output", value]);
        await writer.adapter.update({ model: "member", where: whereId(id(operation)), update: { role: "changed" } });
        return value;
      } } } : {}) },
      role: { type: "string", transform: {
        input(value) { events.push(["role", "input", value]); return value; },
        output(value) { events.push(["role", "output", value]); return value; },
      } },
      createdAt,
    };
    const context = await betterAuth({ ...fixture.options,
      advanced: { ...fixture.options.advanced, database: { ...fixture.options.advanced?.database, generateId: () => "created-member" } },
      plugins: [organization(), {
        id: "superseded-member-timestamp", schema: { member: { fields: {
          createdAt: { type: "date", fieldName: "role", returned: false },
        } } },
      }, { id: "member-crud-fields", schema: { member: { fields } } }],
    }).$context;
    let actual: unknown;
    let caught: unknown;
    try {
      if (operation === "update") {
        actual = await context.adapter.update({ model: "member", where: whereId(id(operation)), update: { role: "requested" } });
      } else {
        const data: Fields = { organizationId: "organization", userId: "user-b", role: "requested", createdAt: operation === "create" ? date(0) : source(operation) };
        if (operation === "insert") data.id = id(operation);
        actual = await context.adapter.create({ model: "member", data, forceAllowId: operation === "insert" });
      }
    } catch (error) { caught = error; }
    const expectedEvents: Events = [["role", "input", "requested"]];
    if (operation === "update") expectedEvents.push(["createdAt", "onUpdate", undefined]);
    expectedEvents.push(["createdAt", "input", operation === "create" ? "native-date" : source(operation)]);
    const after = structuredClone(before);
    if (mode === "input-error") expect(caught).toBe(inputFailure);
    else {
      const role = mode === "live" && backend === "memory" ? "changed" : "requested";
      if (mode === "live") expectedEvents.push(["organizationId", "output", "organization"]);
      expectedEvents.push(["role", "output", role], ["createdAt", "output", `stored:${source(operation)}`]);
      replace(after, fixture.stored({ ...member(id(operation), "user-b", mode === "live" ? "changed" : "requested"), createdAt: `stored:${source(operation)}` }));
      if (mode === "output-error") expect(caught).toBe(outputFailure);
      else {
        expect(caught).toBeUndefined();
        const expected = visible(id(operation), "user-b", role, shared);
        expectOrdered(actual, expected);
        expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
        expect(Reflect.get(actual as object, "createdAt")).toBe(shared);
      }
    }
    expectOrdered(events, expectedEvents);
    expect(fixture.snapshot()).toStrictEqual(after);
  } finally { fixture.close(); }
}

async function checkList(backend: Backend, entry: List) {
  const fixture = await setup(backend, { name: `crud-${entry}`, route: "cancel" });
  try {
    const writer = fixture.context.adapter;
    await writer.delete({ model: "member", where: whereId("owner-member") });
    for (const [id, role] of [["member-a", "10"], ["member-b", "20"]]) {
      await writer.create({ model: "member", forceAllowId: true, data: member(id, "user-b", role) });
    }
    if (entry === "query") {
      for (const [id, role] of [["member-skip", "00"], ["member-tail", "30"]]) {
        await writer.create({ model: "member", forceAllowId: true, data: member(id, "user-b", role) });
      }
    }
    const before = fixture.snapshot();
    const events: Events = [];
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let calls = 0;
    const fields: Policies = {
      organizationId: { type: "string", transform: { async output(value) {
        events.push(["organizationId", "output", value]);
        if (calls++ === 0) {
          await gate;
          await writer.update({ model: "member", where: whereId("member-a"), update: { role: "90" } });
          await writer.delete({ model: "member", where: whereId("member-a") });
          await writer.create({ model: "member", forceAllowId: true, data: member("member-a", "user-a", "replacement") });
          await writer.update({ model: "member", where: whereId("member-b"), update: { role: "after-b" } });
          await writer.create({ model: "member", forceAllowId: true, data: member("member-new", "user-b", "00-new") });
        }
        return value;
      } } },
      role: outputField("role", [], value => { events.push(["role", "output", value]); return value; }, { type: "string" }),
      createdAt: outputField("createdAt", [], value => {
        events.push(["createdAt", "output", value]);
        release();
        return value;
      }, { type: "date" }),
    };
    const context = await betterAuth({ ...fixture.options, plugins: [organization(), {
      id: "member-list-source-fields", schema: { member: { fields } },
    }] }).$context;
    const where = [{ field: "organizationId", value: "organization" }];
    if (entry === "query") expect(await context.adapter.count({ model: "member", where })).toBe(4);
    const actual = await context.adapter.findMany({ model: "member", where, ...(entry === "query"
      ? { limit: 2, offset: 1, sortBy: { field: "role", direction: "asc" as const } } : {}) });
    const firstRole = backend === "memory" ? "90" : "10";
    const expected = [visible("member-a", "user-b", firstRole, date(0)), visible("member-b", "user-b", "20", date(0))];
    expectOrdered(actual, expected);
    expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
    const storedDate = backend === "memory" ? date(0) : date(0).toISOString();
    expectOrdered(events, [
      ["organizationId", "output", "organization"], ["organizationId", "output", "organization"],
      ["role", "output", "20"], ["createdAt", "output", storedDate],
      ["role", "output", firstRole], ["createdAt", "output", storedDate],
    ]);
    const after = structuredClone(before);
    for (const [id, user, role] of [["member-a", "user-a", "replacement"], ["member-b", "user-b", "after-b"], ["member-new", "user-b", "00-new"]]) {
      replace(after, fixture.stored(member(id, user, role)));
    }
    expect(fixture.snapshot()).toStrictEqual(after);
  } finally { fixture.close(); }
}

async function duplicateMemory(mode: Mode) {
  const fixture = await setup("memory", { name: `crud-duplicate-${mode}`, route: "cancel" });
  try {
    for (const [user, role] of [["user-a", "first"], ["user-b", "second"]]) {
      await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: member("duplicate", user, role) });
    }
    const after = fixture.snapshot();
    const events: Events = [];
    const inputFailure = new TypeError("duplicate-input-original");
    const outputFailure = new TypeError("duplicate-output-original");
    const context = await betterAuth({ ...fixture.options, plugins: [organization(), {
      id: "member-duplicate-fields", schema: { member: { fields: { role: { type: "string", transform: {
        input(value) {
          events.push(["role", "input", value]);
          if (mode === "input-error") throw inputFailure;
          return value;
        },
        output(value) {
          events.push(["role", "output", value]);
          if (mode === "output-error") throw outputFailure;
          return value;
        },
      } } } } },
    }] }).$context;
    let actual: unknown;
    let caught: unknown;
    try { actual = await context.adapter.update({ model: "member", where: whereId("duplicate"), update: { role: "updated" } }); }
    catch (error) { caught = error; }
    const expectedEvents: Events = [["role", "input", "updated"]];
    if (mode === "input-error") expect(caught).toBe(inputFailure);
    else {
      expectedEvents.push(["role", "output", "updated"]);
      for (const row of after.member) if (row.id === "duplicate") row.role = "updated";
      if (mode === "output-error") expect(caught).toBe(outputFailure);
      else {
        expect(caught).toBeUndefined();
        const expected = visible("duplicate", "user-a", "updated", date(0));
        expectOrdered(actual, expected);
        expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
      }
    }
    expectOrdered(events, expectedEvents);
    expect(fixture.snapshot()).toStrictEqual(after);
  } finally { fixture.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const operation of ["insert", "create", "update"] as const) {
    for (const mode of ["success", "input-error", "output-error", "live"] as const) {
      test(`${backend} Member ${operation} preserves ${mode} and cross-type timestamp writes`, () => checkWrite(backend, operation, mode));
    }
  }
  for (const entry of ["ordinary", "native", "query"] as const) {
    test(`${backend} Member ${entry} preserves selected objects, order, and pagination`, () => checkList(backend, entry));
  }
}
for (const mode of ["success", "input-error", "output-error"] as const) {
  test(`memory Member duplicate IDs update all rows and project only the first: ${mode}`, () => duplicateMemory(mode));
}
test("sqlite Member rejects duplicate IDs without changing storage", async () => {
  const fixture = await setup("sqlite", { name: "crud-duplicate-id", route: "cancel" });
  try {
    await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: member("duplicate", "user-a", "first") });
    const before = fixture.snapshot();
    let caught: unknown;
    try { await fixture.context.adapter.create({ model: "member", forceAllowId: true, data: member("duplicate", "user-b", "second") }); }
    catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(Error);
    expect(String(caught)).toContain("UNIQUE constraint failed: member.id");
    expect(fixture.snapshot()).toStrictEqual(before);
  } finally { fixture.close(); }
});

type OrganizationModel = "organization" | "invitation" | "team" | "organizationRole";

function modelOutput(model: OrganizationModel, updated: boolean) {
  const createdAt = updated ? "opaque-date:update-source" : "opaque-date:create-source";
  const name = updated ? "Updated" : "Created";
  const id = "opaque-row";
  switch (model) {
    case "organization": return { name, slug: "opaque-organization", logo: null, createdAt, metadata: "{}", id };
    case "invitation": return {
      organizationId: "organization", email: "opaque@fields.test", role: "member", teamId: null,
      status: updated ? "accepted" : "pending", expiresAt: date(0), createdAt, inviterId: "user-a", id,
    };
    case "team": return { name, memberCount: 0, organizationId: "organization", createdAt, updatedAt: date(0), id };
    case "organizationRole": return {
      organizationId: "organization", role: updated ? "renamed" : "custom", permission: "{}", createdAt, updatedAt: date(0), id,
    };
  }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const model of ["organization", "invitation", "team", "organizationRole"] as const) {
    test(`${backend} ${model} create and update preserve genuinely stored opaque timestamps`, async () => {
      const fixture = await setup(backend, { name: `crud-${model}`, route: "cancel", dynamicAccessControl: true });
      try {
        const after = fixture.snapshot();
        const events: Events = [];
        const fields: Policies = {
          createdAt: { type: "string", onUpdate() {
            events.push(["createdAt", "onUpdate", undefined]);
            return "update-source";
          }, transform: {
            input(value) {
              if (model === "organization" && value instanceof Date) {
                events.push(["createdAt", "input", "native-date"]);
                return "opaque-date:create-source";
              }
              events.push(["createdAt", "input", value]);
              expect(typeof value).toBe("string");
              return `opaque-date:${value}`;
            },
            output(value) { events.push(["createdAt", "output", value]); return value; },
          } },
          ...(model === "team" || model === "organizationRole" ? { updatedAt: { type: "date" as const, onUpdate: () => date(0) } } : {}),
        };
        const context = await betterAuth({ ...fixture.options,
          advanced: { ...fixture.options.advanced, database: { ...fixture.options.advanced?.database, generateId: () => "opaque-row" } },
          plugins: [organization({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }), {
            id: "superseded-model-timestamp", schema: { [model]: { fields: {
              createdAt: { type: "date", fieldName: "id", returned: false },
            } } },
          }, { id: "model-crud-timestamp", schema: { [model]: { fields } } }],
        }).$context;
        const data: Fields = { ...modelOutput(model, false), createdAt: model === "organization" ? date(0) : "create-source" };
        delete data.id;
        if (model === "team") delete data.memberCount;
        const created = await context.adapter.create({ model, data });
        const expectedCreated = modelOutput(model, false);
        expectOrdered(created, expectedCreated);
        expect(JSON.stringify(created)).toBe(JSON.stringify(expectedCreated));
        after[model] = [...after[model], fixture.stored(expectedCreated)]
          .toSorted((left, right) => String(left.id).localeCompare(String(right.id)));
        expect(fixture.snapshot()).toStrictEqual(after);
        const update = model === "organization" || model === "team" ? { name: "Updated" }
          : model === "invitation" ? { status: "accepted" } : { role: "renamed" };
        const updated = await context.adapter.update({ model, where: whereId("opaque-row"), update });
        const expectedUpdated = modelOutput(model, true);
        expectOrdered(updated, expectedUpdated);
        expect(JSON.stringify(updated)).toBe(JSON.stringify(expectedUpdated));
        after[model] = after[model].map(row => row.id === "opaque-row" ? fixture.stored(expectedUpdated) : row);
        expect(fixture.snapshot()).toStrictEqual(after);
        expectOrdered(events, [
          ["createdAt", "input", model === "organization" ? "native-date" : "create-source"], ["createdAt", "output", "opaque-date:create-source"],
          ["createdAt", "onUpdate", undefined], ["createdAt", "input", "update-source"],
          ["createdAt", "output", "opaque-date:update-source"],
        ]);
      } finally { fixture.close(); }
    });
  }
}
