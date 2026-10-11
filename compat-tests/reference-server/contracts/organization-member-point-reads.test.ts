import { expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { expectOrdered, member, outputField, setup } from "./organization-invitation-response-contract";
import type { Events } from "./organization-team-member-contract";

for (const backend of ["memory", "sqlite"] as const) {
  for (const entry of ["pair", "native-pair", "id"] as const) {
    for (const mode of ["live", "object", "undefined", "null", "error", "missing"] as const) {
      test(`${backend} ordinary Member ${entry} read preserves ${mode}`, async () => {
        const fixture = await setup(backend, { name: mode, route: "cancel" });
        try {
          const writer = await betterAuth({ ...fixture.options, plugins: [organization(), {
            id: "member-string-date-writer", schema: { member: { fields: { createdAt: { type: "string" } } } },
          }] }).$context;
          await writer.adapter.create({ model: "member", forceAllowId: true,
            data: { ...member("member-b", "user-b", "member"), createdAt: "opaque-date" } });
          const before = fixture.snapshot();
          const events: Events = [];
          const shared = { native: true };
          const failure = new TypeError("member-output-original");
          const fields = {
            organizationId: { type: "string" as const, transform: { async output(value: unknown) {
              events.push(["organizationId", value]);
              await writer.adapter.update({ model: "member", where: [{ field: "id", value: "member-b" }], update: { role: "changed" } });
              return 19;
            } } },
            role: outputField("role", [], value => {
              events.push(["role", value]);
              if (mode === "error") throw failure;
              return mode === "object" ? shared : mode === "undefined" ? undefined : mode === "null" ? null : value;
            }, { type: "string" }),
            createdAt: outputField("createdAt", [], value => { events.push(["createdAt", value]); return value; }, { type: "string" }),
            echo: outputField("echo", [], value => { events.push(["echo", value]); return value; }, { type: "string", fieldName: "role" }),
          };
          const context = await betterAuth({ ...fixture.options, plugins: [organization(), {
            id: "superseded-member-fields", schema: { member: { fields: {
              createdAt: { type: "date", fieldName: "role", returned: false },
            } } },
          }, { id: "member-point-fields", schema: { member: { fields } } }] }).$context;
          const where = entry === "id" ? [{ field: "id", value: mode === "missing" ? "missing" : "member-b" }]
            : [{ field: "organizationId", value: "organization" }, { field: "userId", value: mode === "missing" ? "missing" : "user-b" }];
          let actual: unknown;
          let caught: unknown;
          try { actual = await context.adapter.findOne({ model: "member", where }); } catch (error) { caught = error; }
          const role = backend === "memory" ? "changed" : "member";
          const expectedEvents: Events = [];
          const after = structuredClone(before);
          if (mode === "missing") expect(actual).toBeNull();
          else {
            expectedEvents.push(["organizationId", "organization"], ["role", role]);
            after.member.find(row => row.id === "member-b")!.role = "changed";
            if (mode === "error") expect(caught).toBe(failure);
            else {
              expectedEvents.push(["createdAt", "opaque-date"], ["echo", role]);
              expectOrdered(actual, {
                organizationId: 19, userId: "user-b",
                role: mode === "object" ? shared : mode === "undefined" ? undefined : mode === "null" ? null : role,
                createdAt: "opaque-date", echo: role, id: "member-b",
              });
              if (mode === "object") expect(Reflect.get(actual as object, "role")).toBe(shared);
            }
          }
          if (mode !== "error") expect(caught).toBeUndefined();
          expectOrdered(events, expectedEvents);
          expect(fixture.snapshot()).toStrictEqual(after);
        } finally { fixture.close(); }
      });
    }
  }
}
