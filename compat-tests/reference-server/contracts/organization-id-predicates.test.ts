import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { expectOrdered, setup } from "./organization-invitation-response-contract";
import { date, type Fields } from "./organization-team-member-contract";

type Model = "organization" | "invitation" | "team";
type Selector = "shared-object" | "distinct-object" | "null" | "undefined";
const expiryDate = () => new Date(date(0).getTime() + 1_000);
const observedField = (model: Model) => model === "invitation" ? "status" : "name";

function fields(model: Model, label: string, updated = false, expiry = false): Fields {
  const name = updated ? "changed" : label;
  switch (model) {
    case "organization": return { name, slug: `id-${label}`, logo: null, createdAt: date(0), metadata: "{}" };
    case "invitation": return {
      organizationId: "organization", email: `${label}@id.fields.test`, role: "member", teamId: null,
      status: updated ? "accepted" : "pending", expiresAt: expiry ? expiryDate() : date(0),
      createdAt: date(0), inviterId: "user-a",
    };
    case "team": return { name, memberCount: 0, organizationId: "organization", createdAt: date(0), updatedAt: date(0) };
  }
}

function whereId(value: unknown) {
  const where = [{ field: "id", value: null }];
  // The runtime contract accepts values that the public Where type does not represent.
  Object.defineProperty(where[0], "value", { value, enumerable: true });
  return where;
}

function target(model: Model, row: Fields) {
  return model === "invitation"
    ? row.email === "first@id.fields.test" || row.email === "second@id.fields.test"
    : row.name === "first" || row.name === "second";
}

for (const model of ["organization", "invitation", "team"] as const) {
  for (const selector of ["shared-object", "distinct-object", "null", "undefined"] as const satisfies readonly Selector[]) {
    test(`memory ${model} ID read and update preserve ${selector} comparison`, async () => {
      const fixture = await setup("memory", { name: `id-${model}-${selector}`, route: "cancel" });
      try {
        const events: unknown[] = [];
        const field = observedField(model);
        const context = await betterAuth({ ...fixture.options, plugins: [
          organization({ teams: { enabled: true } }),
          { id: "id-predicate-output", schema: { [model]: { fields: {
            [field]: { type: "string", transform: { output(value) { events.push(value); return value; } } },
          } } } },
        ] }).$context;
        const storedId = selector === "shared-object" || selector === "distinct-object" ? { key: "same" } : false;
        const selectedId = selector === "shared-object" ? storedId
          : selector === "distinct-object" ? { key: "same" } : selector === "null" ? null : undefined;
        for (const [label, id] of [["first", storedId], ["second", storedId], ["other", "other"]] as const) {
          await context.adapter.create({ model, forceAllowId: true, data: { ...fields(model, label), id } });
        }
        events.length = 0;
        const before = fixture.snapshot();
        const found = selector !== "distinct-object";
        const id = typeof storedId === "object" ? "[object Object]" : undefined;
        const actual = await context.adapter.findOne({ model, where: whereId(selectedId) });
        expectOrdered(actual, found ? { ...fields(model, "first"), id } : null);
        expect(fixture.snapshot()).toStrictEqual(before);
        const update = model === "invitation" ? { status: "accepted" }
          : model === "team" ? { name: "changed", updatedAt: date(0) } : { name: "changed" };
        const changed = await context.adapter.update({ model, where: whereId(selectedId), update });
        expectOrdered(changed, found ? { ...fields(model, "first", true), id } : null);
        const after = structuredClone(before);
        if (found) after[model] = after[model].map(row => target(model, row) ? { ...row, ...update } : row);
        expect(fixture.snapshot()).toStrictEqual(after);
        const expectedEvents = found ? [model === "invitation" ? "pending" : "first", model === "invitation" ? "accepted" : "changed"] : [];
        if (model === "invitation") {
          const changed = await context.adapter.update({ model, where: whereId(selectedId), update: { expiresAt: expiryDate() } });
          expectOrdered(changed, found ? { ...fields(model, "first", true, true), id } : null);
          if (found) {
            after[model] = after[model].map(row => target(model, row) ? { ...row, expiresAt: expiryDate() } : row);
            expectedEvents.push("accepted");
          }
          expect(fixture.snapshot()).toStrictEqual(after);
        }
        expect(events).toStrictEqual(expectedEvents);
      } finally { fixture.close(); }
    });
  }
}
