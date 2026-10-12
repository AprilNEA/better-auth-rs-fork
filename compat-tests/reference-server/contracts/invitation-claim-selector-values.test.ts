import { expect, test } from "bun:test";
import { captureInvitationClaimSelectorValues } from "./organization-query-id-alias-capture.mjs";
import { writeObservation } from "./write-observation.mjs";

test("Invitation selector writes retain native values and Memory transaction identity", async () => {
  const observation = await captureInvitationClaimSelectorValues(async captured => {
    await writeObservation(`${JSON.stringify({ contract: "invitation-claim-selector-values", version: "1.7.6", backend: "memory", case: captured })}\n`);
  });
  const fixture = await Bun.file(new URL("../../../tests/fixtures/invitation-claim-selector-values-1.7.6.json", import.meta.url)).json();
  expect(observation).toStrictEqual(fixture);
  expect(observation.version).toBe("1.7.6");
  expect(observation.backend).toBe("memory");
  expect(observation.cases.map(captured => captured.scenario)).toStrictEqual([
    "invitation-own-selector-id-nan", "invitation-own-selector-id-object",
    "invitation-own-selector-lookup-nan", "invitation-own-selector-lookup-object",
  ]);
  for (const captured of observation.cases) {
    expect(captured.steps).toHaveLength(2);
    const [claim, transaction] = captured.steps;
    const replacement = captured.kind === "nan"
      ? { type: "number", value: "NaN" }
      : { marker: "claimed-object", ownUndefined: { type: "undefined" } };
    const stringValue = captured.kind === "nan" ? "NaN" : "[object Object]";
    expect(claim.input).toStrictEqual({
      invitationId: "invitation-alias", status: "accepted", fromStatus: "pending",
    });
    expect(claim.returned).toBe(true);
    expect(claim.result).toStrictEqual({
      organizationId: "parent", email: "recipient@organization-query-id.test", role: "member",
      teamId: null, status: "accepted",
      expiresAt: { type: "date", value: "2100-01-02T03:04:05.000Z" },
      createdAt: { type: "date", value: "2030-01-02T03:04:05.000Z" }, inviterId: "owner",
      id: captured.column === "id" ? stringValue : "canonical-invitation",
      claimLookup: captured.column === "id" ? stringValue : replacement,
    });
    expect(claim.keyOrder).toStrictEqual([
      { path: [], keys: [
        "organizationId", "email", "role", "teamId", "status", "expiresAt",
        "createdAt", "inviterId", "id", "claimLookup",
      ] },
      ...(captured.column === "lookup" && captured.kind === "object"
        ? [{ path: ["claimLookup"], keys: ["marker", "ownUndefined"] }]
        : []),
    ]);
    expect(claim.events).toStrictEqual([["onUpdate", "invitation.claimLookup", replacement]]);
    expect(claim.after).toStrictEqual({
      ...claim.before,
      invitation: claim.before.invitation.map(record => ({
        ...record, status: "accepted", [captured.column]: replacement,
      })),
    });
    const returnedLookupIsReplacement = captured.column === "lookup";
    expect(claim.identities).toStrictEqual({
      originalRows: [true], originalValues: [true], returnedLookupIsReplacement,
    });
    expect(transaction.input).toStrictEqual({ operation: "read-only-adapter-transaction" });
    expect(transaction.before).toStrictEqual(claim.after);
    expect(transaction.returned).toBe(true);
    expect(transaction.result).toBe(true);
    expect(transaction.keyOrder).toStrictEqual([]);
    expect(transaction.events).toStrictEqual([]);
    const duplicateObjectId = captured.column === "id" && captured.kind === "object";
    expect(transaction.after).toStrictEqual({
      ...claim.after,
      invitation: duplicateObjectId
        ? [...claim.after.invitation, ...claim.after.invitation]
        : claim.after.invitation,
    });
    expect(transaction.identities).toStrictEqual({
      originalRows: duplicateObjectId ? [true, false] : [true],
      originalValues: duplicateObjectId ? [true, false] : [true],
      returnedLookupIsReplacement,
    });
  }
});
