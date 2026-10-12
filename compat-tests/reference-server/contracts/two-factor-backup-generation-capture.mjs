import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { base32 } from "@better-auth/utils/base32";
import { createAuthMiddleware } from "better-auth/api";
import { symmetricDecrypt } from "better-auth/crypto";
import { twoFactor } from "better-auth/plugins/two-factor";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createConsumerHarness, consumerSecret, consumerUser } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const ciphertext = "generated-native-ciphertext";
export const twoFactorBackupGenerationCases = [
  { name: "regenerate-native-function", generated: "function" },
  { name: "regenerate-native-object" },
  { name: "regenerate-undefined-plain", generated: "undefined", storage: "plain" },
  { name: "regenerate-null-plain", generated: "null", storage: "plain" },
  { name: "regenerate-generator-original-error", fail: "generate" },
  { name: "regenerate-json-original-error", fail: "toJSON" },
  { name: "regenerate-encrypt-original-error", fail: "encrypt" },
  { name: "regenerate-output-original-error", fail: "output" },
  { name: "enable-generator-original-error", action: "enable", fail: "generate" },
  { name: "enable-json-original-error", action: "enable", fail: "toJSON" },
  { name: "enable-encrypt-original-error", action: "enable", fail: "encrypt" },
  { name: "enable-native-object", action: "enable" },
].map(scenario => ({ consumer: "two-factor-backup-generation", value: "owner", action: "regenerate", generated: "object", storage: "custom", ...scenario }));

async function captureCase(scenario) {
  const harness = createConsumerHarness(scenario, "backup-generation-unused-challenge");
  const { native, runtime } = harness;
  const seed = { id: "factor-row", secret: "native-factor-secret", backupCodes: "initial-backup-codes",
    userId: "owner", verified: scenario.action !== "enable", failedVerificationCount: 2, lockedUntil: null };
  harness.database.twoFactor = [{ ...seed }];
  const codes = scenario.generated === "function" ? function generatedCodes() {}
    : scenario.generated === "undefined" ? undefined : scenario.generated === "null" ? null
    : { marker: "native-generated-codes", ownUndefined: undefined };
  let jsonCalls = 0;
  if (scenario.generated === "object") Object.defineProperty(codes, "toJSON", {
    configurable: true, value: function toJSON(key) {
      jsonCalls += 1;
      harness.event("toJSON", { sameReceiver: this === codes, key: runtime.value(key), call: jsonCalls });
      assert.equal(this, codes);
      assert.equal(key, "");
      if (scenario.fail === "toJSON") harness.fail("throw:toJSON");
      return { kept: true };
    },
  });
  const codesBefore = native.snapshot(codes);
  const runtimeCodesBefore = runtime.value(codes);
  const cipher = {
    async encrypt(value) {
      harness.event("encrypt", { value: runtime.value(value) });
      if (scenario.fail === "encrypt") harness.fail("throw:encrypt");
      return ciphertext;
    },
    async decrypt() { assert.fail("Generation must not decrypt backup codes"); },
  };
  const factorPlugin = twoFactor({ allowPasswordless: true, backupCodeOptions: {
    customBackupCodesGenerate() {
      harness.event("generate");
      if (scenario.fail === "generate") harness.fail("throw:generate");
      return codes;
    },
    storeBackupCodes: scenario.storage === "plain" ? "plain" : cipher,
  } });
  const plugins = [factorPlugin];
  if (scenario.fail === "output") plugins.push({
    id: "backup-generation-output", schema: { twoFactor: { fields: { backupCodes: { type: "string", transform: {
      output(value) {
        harness.event("output", { value: runtime.value(value) });
        if (value === ciphertext) harness.fail("throw:output");
        return value;
      },
    } } } } },
  });
  const session = { session: { id: "generation-session", token: "generation-token", userId: "owner",
    expiresAt: new Date(now + 60_000), createdAt: new Date(now), updatedAt: new Date(now) }, user: consumerUser() };
  let returnedSameCodes;
  const captured = await harness.capture(plugins, async auth => {
    const result = scenario.action === "enable"
      ? await auth.api.enableTwoFactor({ body: {} }) : await auth.api.generateBackupCodes({ body: {} });
    returnedSameCodes = result.backupCodes === codes;
    assert.equal(returnedSameCodes, true);
    assert.equal(Object.hasOwn(result, "backupCodes"), true);
    return result;
  }, { hooks: { before: createAuthMiddleware(async ctx => { ctx.context.session = session; }) } });
  if (scenario.fail) {
    assert.equal(captured.caught, harness.original);
    assert.equal(captured.observation.runtime.outcome.sameOriginal, true);
  } else {
    assert.equal(captured.caught, undefined);
    assert.equal(returnedSameCodes, true);
  }
  assert.equal(jsonCalls, scenario.generated === "object" && scenario.fail !== "generate" ? 1 : 0);
  const factor = harness.database.twoFactor[0];
  if (scenario.fail === "output") assert.deepEqual(factor, { ...seed, backupCodes: ciphertext });
  else if (scenario.fail) assert.deepEqual(factor, seed);
  else if (scenario.action === "regenerate" && scenario.storage === "custom") assert.deepEqual(factor, { ...seed, backupCodes: ciphertext });
  else if (scenario.generated === "null") assert.deepEqual(factor, { ...seed, backupCodes: "null" });
  let enrollment;
  if (scenario.action === "enable" && !scenario.fail) {
    const plaintext = await symmetricDecrypt({ key: consumerSecret, data: factor.secret });
    const uri = new URL(captured.result.totpURI);
    assert.equal(new TextDecoder().decode(base32.decode(uri.searchParams.get("secret"))), plaintext);
    assert.equal(plaintext.length, 32);
    const query = new URLSearchParams({ secret: base32.encode(plaintext, { padding: false }), issuer: "Better Auth", digits: "6", period: "30" });
    assert.equal(captured.result.totpURI, `otpauth://totp/Better%20Auth:${encodeURIComponent(consumerUser().email)}?${query}`);
    assert.equal(uri.searchParams.get("digits"), "6");
    assert.equal(uri.searchParams.get("period"), "30");
    assert.equal(factor.backupCodes, ciphertext);
    assert.equal(factor.verified, false);
    assert.equal(factor.failedVerificationCount, 2);
    enrollment = { uriMatchesCiphertext: true, secretLength: plaintext.length, digits: "6", period: "30" };
  }
  return { ...captured.observation, codes: { before: codesBefore, after: native.snapshot(codes) },
    runtime: { ...captured.observation.runtime, codes: { before: runtimeCodesBefore, after: runtime.value(codes) },
      returnedSameCodes: runtime.value(returnedSameCodes), jsonCalls, enrollment: runtime.value(enrollment) } };
}

export async function captureTwoFactorBackupGeneration() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["plugins/two-factor/index.mjs", "plugins/two-factor/backup-codes/index.mjs", "utils/password.mjs", "db/internal-adapter.mjs"].map(path => ({
    path: `better-auth/dist/${path}`, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/better-auth/dist/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of twoFactorBackupGenerationCases) cases.push(await captureCase(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real enableTwoFactor and generateBackupCodes endpoints with a before hook providing a native authenticated session. Record complete generation, JSON, encryption and output-transform callbacks, original thrown identity, native result identity and full Memory state. Preserve the successful enrollment's random ciphertext and TOTP URI; assert that decrypting the persisted ciphertext yields the same secret as the URI. No earlier capture is repeated or rewritten.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "two-factor-backup-generation", ...await captureTwoFactorBackupGeneration() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
