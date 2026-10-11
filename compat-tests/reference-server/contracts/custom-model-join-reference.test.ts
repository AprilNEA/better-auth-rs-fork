import { expect, test } from "bun:test";
import { captureCustomModelJoinReferences } from "./custom-model-join-reference-capture.mjs";

const fixture = await Bun.file(new URL("../../../tests/fixtures/custom-model-join-reference-1.7.6.json", import.meta.url)).text();

test("custom model references retain complete joined observations and native guards", async () => {
  expect(`${JSON.stringify(await captureCustomModelJoinReferences(), null, 2)}\n`).toBe(fixture);
}, 60_000);

test("explicit native declarations retain the existing joined contract through logical and aliased references", async () => {
  const scenarios = [
    { name: "declared-passkey-logical", declared: true, model: "passkey", alias: "key_store", reference: "passkey" },
    { name: "declared-passkey-alias", declared: true, model: "passkey", alias: "key_store", reference: "key_store" },
    { name: "declared-rateLimit-logical", declared: true, model: "rateLimit", alias: "counter_store", reference: "rateLimit" },
    { name: "declared-rateLimit-alias", declared: true, model: "rateLimit", alias: "counter_store", reference: "counter_store" },
  ];
  const operationNames = ["user-control", "internal-owner-existing"];
  const baseline = JSON.parse(fixture);
  const cases = scenarios.flatMap(scenario => baseline.cases
    .filter((captured: { scenario: string }) => captured.scenario === "declared-badge-reference")
    .map((captured: { operations: { name: string }[] }) => ({
      ...captured,
      scenario: scenario.name,
      registeredModels: ["user", "session", "account", "verification", scenario.model],
      operations: captured.operations.filter(operation => operationNames.includes(operation.name)),
    })));
  expect(cases).toHaveLength(16);
  expect(await captureCustomModelJoinReferences({ scenarios, operationNames }))
    .toStrictEqual({ version: baseline.version, scenarios, cases });
}, 60_000);
