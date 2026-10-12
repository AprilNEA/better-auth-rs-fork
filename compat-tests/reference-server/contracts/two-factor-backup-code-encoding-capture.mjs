import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { generateBackupCodes } from "../node_modules/better-auth/dist/plugins/two-factor/backup-codes/index.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { captureTwoFactorBackupCodeNativeCase } from "./two-factor-backup-code-native-capture.mjs";
import { consumerSecret } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

export const twoFactorBackupCodeEncodingRouteCases = [
  { name: "filter-function-encrypt-undefined", updated: "function" },
  { name: "filter-to-json-undefined-encrypt-undefined", updated: "object-undefined" },
  { name: "filter-function-encrypt-original-error", updated: "function", fail: "cipher:encrypt" },
  { name: "filter-to-json-undefined-encrypt-original-error", updated: "object-undefined", fail: "cipher:encrypt" },
].map(scenario => ({ consumer: "two-factor-backup-code", value: "owner", status: "true", encrypted: "string", ...scenario }));

export const twoFactorBackupCodeEncodingCases = [
  { name: "plain-function", value: "function", storage: "plain", key: "single" },
  { name: "plain-to-json-undefined", value: "object", storage: "plain", key: "single" },
  { name: "encrypted-function", value: "function", storage: "encrypted", key: "single" },
  { name: "encrypted-to-json-undefined", value: "object", storage: "encrypted", key: "versioned" },
];

async function captureEncoding(scenario) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const events = [];
  const codes = scenario.value === "function" ? function backupGenerated() {} : { marker: "native-generated-codes" };
  if (scenario.value === "object") Object.defineProperty(codes, "toJSON", {
    configurable: true, value: function toJSON(key) {
      events.push({ phase: "toJSON", sameReceiver: this === codes, key: runtime.value(key) });
      assert.equal(this, codes);
      assert.equal(key, "");
      return undefined;
    },
  });
  const key = scenario.key === "single" ? consumerSecret : { currentVersion: 3, keys: new Map([[3, consumerSecret]]) };
  const before = native.snapshot(codes);
  let result;
  let caught;
  let returned = false;
  try {
    result = await generateBackupCodes(key, {
      customBackupCodesGenerate() {
        events.push({ phase: "generate" });
        return codes;
      },
      storeBackupCodes: scenario.storage,
    });
    returned = true;
  } catch (error) {
    if (error instanceof assert.AssertionError) throw error;
    caught = error;
  }
  assert.deepEqual(events, scenario.value === "function" ? [{ phase: "generate" }]
    : [{ phase: "generate" }, { phase: "toJSON", sameReceiver: true, key: "" }]);
  if (scenario.storage === "plain") {
    assert.equal(returned, true);
    assert.equal(result.backupCodes, codes);
    assert.equal(Object.hasOwn(result, "encryptedBackupCodes"), true);
    assert.equal(result.encryptedBackupCodes, undefined);
  } else {
    assert.equal(returned, false);
    assert.ok(caught instanceof TypeError);
  }
  const outcome = returned ? { returned, result: native.snapshot(result) }
    : { returned, error: native.snapshot(caught) };
  const runtimeOutcome = returned ? { returned, sameCodes: result.backupCodes === codes, result: runtime.value(result) }
    : { returned, error: { name: caught.name, message: caught.message, ownEnumerable: runtime.ownValues(caught) } };
  return { name: scenario.name, scenario, before, events, outcome, after: native.snapshot(codes),
    runtime: { before: runtime.value(codes), events, outcome: runtimeOutcome, after: runtime.value(codes) } };
}

export async function captureTwoFactorBackupCodeEncoding() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/plugins/two-factor/backup-codes/index.mjs", "better-auth/dist/crypto/index.mjs", "@noble/ciphers/utils.js"].map(path => ({
    path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of twoFactorBackupCodeEncodingRouteCases) cases.push(await captureTwoFactorBackupCodeNativeCase(scenario));
    const encodings = [];
    for (const scenario of twoFactorBackupCodeEncodingCases) encodings.push(await captureEncoding(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Incremental capture only. Four real verifyBackupCode routes retain Function or toJSON-undefined filter results through JSON.stringify and the configured encrypt callback. Four calls to the unmodified, exported generateBackupCodes function observe the same encodeBackupCodes implementation with Plain and Encrypted storage. Complete native observations, callback errors, runtime identities, attempts, rows and storage remain recorded. No earlier sixteen-case observation is resampled or rewritten.",
      cases, encodings };
  });
}

if (import.meta.main) {
  const observation = { contract: "two-factor-backup-code-encoding", ...await captureTwoFactorBackupCodeEncoding() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
