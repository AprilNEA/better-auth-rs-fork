import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { runWithEndpointContext } from "@better-auth/core/context";
import { emailOTP } from "better-auth/plugins/email-otp";
import { phoneNumber } from "better-auth/plugins/phone-number";
import { tryReuseOTP } from "../node_modules/better-auth/dist/plugins/email-otp/otp-token.mjs";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, secondaryNativeNow as now, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { createConsumerHarness, consumerEmail, consumerPhone } from "./verification-consumer-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

export function verificationOtpConsumerCases() {
  const cases = [];
  const add = (consumer, suffix, fields = {}) => cases.push({ name: `${consumer}-${suffix}`, consumer, ...fields });
  for (const consumer of ["email-get", "email-check", "email-reuse", "phone-consume"]) {
    for (const expiry of ["future", "equal", "expired", "missing", "undefined", "null", "nan", "invalid-date", "object", "conversion-error"])
      add(consumer, `expiry-${expiry}`, { expiry });
    add(consumer, "expiry-getter-error", { fail: "expiry:get" });
    add(consumer, "value-getter-error", { fail: "value:get" });
    add(consumer, "expired-unread-value-error", { expiry: "expired", fail: "value:get" });
    add(consumer, "exhausted", { exhausted: true });
    add(consumer, "native-methods", { value: "methods" });
  }
  for (const consumer of ["email-get", "email-check", "email-reuse"]) {
    for (const fail of ["lastIndexOf:get", "lastIndexOf:call", "slice:get", "slice:call"])
      add(consumer, fail.replace(":", "-error-"), { value: "methods", fail });
    for (const index of ["string", "object"]) add(consumer, `index-${index}`, { value: "methods", index });
    for (const otpShape of ["array", "array-like"]) add(consumer, `otp-${otpShape}`, { value: "methods", otpShape });
  }
  add("email-get", "hashed-unread-value-error", { hashed: true, fail: "value:get" });
  add("email-check", "wrong-code-persists-attempt", { wrong: true });
  add("email-check", "wrong-code-set-error-persists-attempt", { wrong: true, fail: "set:after" });
  add("email-check", "wrong-code-update-value-getter-error", { wrong: true, fail: "value:second" });
  add("email-reuse", "update-set-error-persists-expiry", { fail: "set:after" });
  add("email-reuse", "update-value-getter-error", { fail: "value:second" });
  add("email-reuse", "update-expiry-getter-error", { fail: "expiry:second" });
  add("phone-consume", "split-getter-error", { value: "methods", fail: "split:get" });
  add("phone-consume", "split-call-error", { value: "methods", fail: "split:call" });
  add("phone-consume", "split-second-error-after-consume", { value: "methods", fail: "split:second" });
  for (const splitShape of ["string", "array-like"]) add("phone-consume", `split-${splitShape}`, { value: "methods", splitShape });
  for (const attempts of ["object", "conversion-error", "false", "nan"])
    add("phone-consume", `attempts-${attempts}`, { value: "methods", attempts });
  add("phone-consume", "wrong-code-recreates-attempt", { wrong: true });
  add("phone-consume", "wrong-code-set-error-persists-attempt", { wrong: true, fail: "set:after" });
  add("phone-consume", "function-root-rejected-after-precheck", { root: "function" });
  return cases;
}

async function captureCase(scenario) {
  const phone = scenario.consumer === "phone-consume";
  const identifier = phone ? consumerPhone : `sign-in-otp-${consumerEmail}`;
  const harness = createConsumerHarness(scenario, identifier);
  const emailOptions = { sendVerificationOTP: async () => harness.fail("unexpected:send-email"),
    expiresIn: 180, allowedAttempts: 3, storeOTP: scenario.hashed ? "hashed" : "plain" };
  const plugins = phone ? [phoneNumber({ sendOTP: async () => harness.fail("unexpected:send-phone"), allowedAttempts: 3 })]
    : [emailOTP(emailOptions)];
  const captured = await harness.capture(plugins, (auth, context) => {
    const query = { email: consumerEmail, type: "sign-in" };
    switch (scenario.consumer) {
      case "email-get": return auth.api.getVerificationOTP({ query });
      case "email-check": return auth.api.checkVerificationOTP({ body: { ...query, otp: scenario.wrong ? "000000" : "123456" } });
      case "email-reuse": return runWithEndpointContext({ context }, () => tryReuseOTP({ context }, emailOptions, identifier));
      case "phone-consume": return auth.api.consumePhoneNumberOTP({ body: { phoneNumber: consumerPhone, code: scenario.wrong ? "000000" : "123456" } });
      default: throw new Error(`Unknown consumer: ${scenario.consumer}`);
    }
  });
  const { events, outcome, after } = captured.observation.runtime;
  assert.equal(events[0].phase, "storage.get");
  assert.equal(events[0].key, harness.targetKey);
  const firstValue = events.findIndex(event => event.phase === "get:value");
  const firstExpiry = events.findIndex(event => event.phase === "get:expiresAt");
  if (firstValue >= 0 && scenario.expiry !== "missing") assert.ok(firstExpiry >= 0 && firstExpiry < firstValue);
  if (scenario.expiry === "expired" || scenario.expiry === "null") assert.equal(firstValue, -1);
  if (scenario.hashed) assert.equal(firstValue, -1);
  if (scenario.fail === "expiry:get" || scenario.fail === "value:get" && scenario.expiry !== "expired" && !scenario.hashed
      || scenario.expiry === "conversion-error") assert.equal(captured.caught, harness.original);
  if (scenario.expiry === "expired" || scenario.expiry === "null") {
    assert.equal(after.targetPresent, scenario.consumer === "email-get" || scenario.consumer === "email-reuse");
    if (outcome.returned) assert.deepEqual(captured.result, scenario.consumer === "email-get" ? { otp: null } : null);
  }
  if (scenario.fail === "set:after") {
    assert.equal(captured.caught, harness.original);
    assert.equal(after.targetPresent, true);
    assert.equal(after.targetSameRoot, false);
    assert.ok(events.some(event => event.phase === "storage.set"));
  }
  if (scenario.fail === "split:second" || scenario.splitShape === "array-like") {
    assert.equal(after.targetPresent, false);
    assert.equal(outcome.returned, false);
    assert.equal(events.filter(event => event.phase === "storage.getAndDelete").length, 1);
  }
  return captured.observation;
}

export async function captureVerificationOtpConsumerNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["plugins/email-otp/routes.mjs", "plugins/email-otp/otp-token.mjs", "plugins/email-otp/utils.mjs",
    "plugins/phone-number/routes.mjs", "db/internal-adapter.mjs"].map(path => ({
    path: `better-auth/dist/${path}`, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/better-auth/dist/${path}`, import.meta.url))).digest("hex"),
  }));
  return withClock(async setClock => {
    setClock(now);
    const cases = [];
    for (const scenario of verificationOtpConsumerCases()) cases.push(await captureCase(scenario));
    return { version: secondaryNativeVersion, backend: "memory", provenance,
      boundary: "Real Email OTP get/check endpoints and exported tryReuseOTP helper; real Phone consume endpoint. Real internalAdapter and Memory secondary storage preserve native Date/function roots. Complete descriptor audits retain fields and callbacks. Runtime observations retain returned values, exact errors, getter/method order, identity checks, and complete storage before and after failure. No consumer algorithm is copied into the harness.", cases };
  });
}

if (import.meta.main) {
  const observation = { contract: "verification-otp-consumer-native", ...await captureVerificationOtpConsumerNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
