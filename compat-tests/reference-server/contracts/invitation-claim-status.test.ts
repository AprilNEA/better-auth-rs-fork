import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { captureInvitationClaimStatusPolicies } from "./organization-query-id-alias-capture.mjs";

test("Invitation claims apply declared status query and write policies", async () => {
  const observation = await captureInvitationClaimStatusPolicies(captured => {
    writeSync(1, `${JSON.stringify({ contract: "invitation-claim-status", version: "1.7.6", backend: "memory", case: captured })}\n`);
  });
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual([
    "invitation-claim-status-json", "invitation-claim-status-string",
  ]);
  for (const captured of observation.cases) {
    const step = captured.steps[0];
    const status = captured.type === "json" ? "accepted" : "claimed";
    expect(step.returned).toBe(true);
    expect(step.result.status).toBe(status);
    expect(step.events).toStrictEqual([
      ["input", "invitation.status", "accepted"], ["output", "invitation.status", status],
    ]);
    expect(step.after).toStrictEqual({
      ...step.before,
      invitation: step.before.invitation.map(row => ({
        ...row, stored_status: captured.type === "json" ? JSON.stringify(status) : status,
      })),
    });
  }
});
