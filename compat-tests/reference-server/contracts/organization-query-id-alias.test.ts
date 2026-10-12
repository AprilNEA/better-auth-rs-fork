import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { captureOrganizationQueryIdAliases, organizationQueryIdAliasScenarios } from "./organization-query-id-alias-capture.mjs";

test("Organization queries retain first-ID aliases across direct, joined and atomic operations", async () => {
  const observation = await captureOrganizationQueryIdAliases(captured => {
    writeSync(1, `${JSON.stringify({ contract: "organization-query-id-alias", version: "1.7.6", backend: "memory", case: captured })}\n`);
  });
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual(organizationQueryIdAliasScenarios);
  for (const captured of observation.cases) {
    expect(captured.steps.every(step => step.returned)).toBe(true);
    if (captured.operation === "delete") {
      expect(captured.steps[0].after[captured.model].map(row => row.id)).toStrictEqual([captured.alias]);
    } else if (captured.operation) {
      expect(captured.steps.map(step => step.result.id)).toStrictEqual([captured.canonical, captured.canonical, captured.alias]);
    } else if (captured.scenario.startsWith("member-user-")) {
      expect(captured.steps[0].result.user).toStrictEqual({
        id: { type: "undefined" }, name: { type: "undefined" },
        email: { type: "undefined" }, image: { type: "undefined" },
      });
      expect(captured.steps[0].events).toStrictEqual([
        ["output", "member.role", "member"], ["output", "user.name", "Alias owner"],
      ]);
      expect(captured.steps[0].after).toStrictEqual(captured.steps[0].before);
    } else {
      const step = captured.steps[0];
      if (captured.mutate) {
        expect(step.result).toBeNull();
        expect(step.after.invitation).toStrictEqual(step.before.invitation.map((row, index) => index === 0 ? { ...row, lookup: "changed-alias" } : row));
      } else {
        expect(step.result.id).toBe("canonical-invitation");
        expect(step.after.invitation).toStrictEqual(step.before.invitation.map((row, index) => index === 0 ? { ...row, status: "accepted" } : row));
      }
    }
  }
  const fixture = await Bun.file(new URL("../../../tests/fixtures/organization-query-id-alias-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
});
