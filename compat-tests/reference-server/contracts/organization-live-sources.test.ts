import { expect, test } from "bun:test";
import { expectOrdered, outputField } from "./organization-invitation-response-contract";
import { build, changed, create, early, fixture, late, list, models, mutate, point, replace, update, updated, visible, whereId, type Model } from "./organization-live-source-contract";
import type { Backend, Events, Policies } from "./organization-team-member-contract";

type Operation = "create" | "update" | "point" | "list";

async function live(backend: Backend, model: Model, operation: Operation) {
  const source = await fixture(backend, `live-${model}-${operation}`);
  try {
    if (operation !== "create") await create(source.writer, model, "source-a", "First");
    const after = source.snapshot();
    const events: Events = [];
    const fields: Policies = {
      [early(model)]: outputField("early", [], async value => {
        events.push(["early", value]);
        await mutate(source.writer, model, "source-a");
        return value;
      }, { type: "string" }),
      [late(model)]: outputField("late", [], value => { events.push(["late", value]); return value; }, { type: model === "invitation" ? "date" : "string" }),
    };
    const reader = (await build(source.options, model, fields).$context).adapter;
    const actual = operation === "create" ? [await create(reader, model, "source-a", "First")]
      : operation === "update" ? [await update(reader, model, "source-a")]
      : operation === "point" ? [await point(reader, model, "source-a")]
      : await list(reader, model);
    let expected = visible(model, "source-a", "First");
    if (operation === "update") expected = updated(model, expected);
    if (backend === "memory") expected[late(model)] = changed(model);
    expectOrdered(actual, [expected]);
    expect(JSON.stringify(actual)).toBe(JSON.stringify([expected]));
    expectOrdered(events, [["early", expected[early(model)]], ["late", source.stored({ value: expected[late(model)] }).value]]);
    replace(after, model, "source-a", [source.stored({ ...expected, [late(model)]: changed(model) })]);
    expect(source.snapshot()).toStrictEqual(after);
  } finally { source.close(); }
}

async function selected(backend: Backend, model: Model) {
  const source = await fixture(backend, `selected-${model}`);
  try {
    for (const [id, label] of [["source-a", "First"], ["source-b", "Second"]]) await create(source.writer, model, id, label);
    const after = source.snapshot();
    const events: Events = [];
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let calls = 0;
    const fields: Policies = {
      [early(model)]: outputField("early", [], async value => {
        events.push(["early", value]);
        if (calls++ === 0) {
          await gate;
          await mutate(source.writer, model, "source-a");
          await source.writer.delete({ model, where: whereId("source-a") });
          await create(source.writer, model, "source-a", "Replacement");
          await create(source.writer, model, "source-c", "Third");
        }
        return value;
      }, { type: "string" }),
      [late(model)]: outputField("late", [], value => { events.push(["late", value]); release(); return value; }, { type: "string" }),
    };
    const reader = (await build(source.options, model, fields).$context).adapter;
    const actual = await list(reader, model);
    const first = visible(model, "source-a", "First");
    const second = visible(model, "source-b", "Second");
    if (backend === "memory") first[late(model)] = changed(model);
    expectOrdered(actual, [first, second]);
    expect(JSON.stringify(actual)).toBe(JSON.stringify([first, second]));
    expectOrdered(events, [["early", first[early(model)]], ["early", second[early(model)]], ["late", second[late(model)]], ["late", first[late(model)]]]);
    for (const [id, label] of [["source-a", "Replacement"], ["source-c", "Third"]]) {
      replace(after, model, id, [source.stored(visible(model, id, label))]);
    }
    expect(source.snapshot()).toStrictEqual(after);
  } finally { source.close(); }
}

async function duplicates(backend: Backend, model: Model) {
  const source = await fixture(backend, `duplicate-${model}`);
  try {
    await create(source.writer, model, "source-a", "First");
    const before = source.snapshot();
    const events: Events = [];
    const reader = (await build(source.options, model, {
      [early(model)]: outputField("early", [], value => { events.push(["early", value]); return value; }, { type: "string" }),
    }).$context).adapter;
    if (backend === "sqlite") {
      let caught: unknown;
      try { await create(reader, model, "source-a", "Second"); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(Error);
      expect(String(caught)).toContain(`UNIQUE constraint failed: ${model}.id`);
      expect(events).toStrictEqual([]);
      expect(source.snapshot()).toStrictEqual(before);
      return;
    }
    await create(source.writer, model, "source-a", "Second");
    const after = source.snapshot();
    const actual = await update(reader, model, "source-a");
    const expected = updated(model, visible(model, "source-a", "First"));
    expectOrdered(actual, expected);
    expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
    expectOrdered(events, [["early", expected[early(model)]]]);
    replace(after, model, "source-a", [expected, updated(model, visible(model, "source-a", "Second"))]);
    expect(source.snapshot()).toStrictEqual(after);
  } finally { source.close(); }
}

for (const backend of ["memory", "sqlite"] as const) {
  for (const model of models) {
    for (const operation of ["create", "update", "point", "list"] as const) {
      test(`${backend} ${model} ${operation} reads later output fields from its backend source`, () => live(backend, model, operation));
    }
    test(`${backend} ${model} duplicate IDs preserve backend write and first-output rules`, () => duplicates(backend, model));
  }
  for (const model of ["organization", "team", "organizationRole"] as const) {
    test(`${backend} ${model} list retains selected objects after deletion and same-ID replacement`, () => selected(backend, model));
  }
}
