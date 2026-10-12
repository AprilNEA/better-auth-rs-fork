import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { emailOTP } from "better-auth/plugins";
import { withClock } from "./email-verification-duration-capture.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const email = "override-values@example.com";
const epoch = 2_000_000_000_000;
const nextTurn = () => new Promise(resolve => setTimeout(resolve, 0));
export const emailOtpOverrideValueCases = ["ready", "pending"];

async function captureCase(timing) {
  const native = createSecondaryNativeObserver();
  const database = { user: [], session: [], account: [], verification: [] };
  const gate = Promise.withResolvers();
  const entered = Promise.withResolvers();
  const deliveryValue = { sender: "completed", optional: undefined, nullable: null };
  const deliveryBefore = native.snapshot(deliveryValue);
  const events = [];
  const logs = [];
  const tasks = [];
  const taskStates = [];
  const values = [];
  const settlements = [];
  const messages = [];
  let generated = 0;
  let overrideState = { status: "pending" };
  const options = {
    database: memoryAdapter(database), baseURL: "https://email-otp-override-values.test",
    secret: "email-otp-override-values-contract-secret-at-least-thirty-two-characters",
    telemetry: { enabled: false }, rateLimit: { enabled: false },
    logger: { level: "error", disableColors: true, log(level, message, ...args) {
      logs.push({ level, message, arguments: native.snapshot(args) });
    } },
    advanced: {
      database: { generateId: input => `${input.model}-${++generated}` },
      backgroundTasks: { handler(promise) {
        const index = tasks.length;
        tasks.push(promise);
        taskStates.push({ status: "pending" });
        events.push({ phase: "handler:received", index, isPromise: promise instanceof Promise });
        settlements.push(promise.then(value => {
          values[index] = value;
          taskStates[index] = { status: "fulfilled", value: native.snapshot(value), sameDeliveryValue: value === deliveryValue };
          events.push({ phase: "task:fulfilled", index, ...taskStates[index] });
        }));
      } },
    },
    plugins: [emailOTP({
      overrideDefaultEmailVerification: true,
      generateOTP: () => "123456",
      sendVerificationOTP(message, endpoint) {
        messages.push({ message: native.snapshot(message), path: endpoint.path,
          body: native.snapshot(endpoint.body), hasRequest: endpoint.request !== undefined });
        events.push({ phase: "sender:start" });
        entered.resolve();
        return (async () => {
          if (timing === "pending") {
            await gate.promise;
            events.push({ phase: "sender:resume" });
          }
          return deliveryValue;
        })();
      },
    })],
  };
  const context = await betterAuth(options).$context;
  const user = await context.adapter.create({ model: "user", forceAllowId: true, data: {
    id: "owner", name: "Override Values", email, emailVerified: false, image: null,
    createdAt: new Date(epoch), updatedAt: new Date(epoch),
  } });
  const before = native.snapshot(database);
  try {
    // The installed init override calls the real OTP endpoint. No public signup wrapper is added.
    const operation = context.options.emailVerification.sendVerificationEmail({
      user, token: "unused-by-otp-override", url: "https://email-otp-override-values.test/unused",
    }, undefined).then(value => {
      overrideState = { status: "fulfilled", value: native.snapshot(value) };
      events.push({ phase: "override:fulfilled", ...overrideState });
      assert.equal(value, undefined);
    });
    await operation;
    await entered.promise;
    await nextTurn();
    const snapshot = () => ({ overrideState, taskStates: structuredClone(taskStates),
      database: native.snapshot(database), deliveryValue: native.snapshot(deliveryValue) });
    const beforeRelease = snapshot();
    assert.equal(tasks.length, 2);
    assert.equal(beforeRelease.taskStates[0].status, "fulfilled");
    assert.deepEqual(values[0], { success: true });
    assert.equal(beforeRelease.taskStates[1].status, timing === "pending" ? "pending" : "fulfilled");
    events.push({ phase: "gate:release" });
    gate.resolve();
    await Promise.all(settlements);
    const afterSettlement = snapshot();
    assert.deepEqual(values[0], { success: true });
    assert.deepEqual(Reflect.ownKeys(values[0]), ["success"]);
    assert.equal(values[1], deliveryValue);
    assert.deepEqual(native.snapshot(deliveryValue), deliveryBefore);
    assert.deepEqual(logs, []);
    assert.equal(messages.length, 1);
    assert.equal(messages[0].path, "/email-otp/send-verification-otp");
    assert.equal(database.verification.length, 1);
    assert.equal(database.verification[0].value, "123456:0");
    assert.equal(database.verification[0].identifier, `email-verification-otp-${email}`);
    assert.equal(database.verification[0].expiresAt.getTime(), epoch + 300_000);
    assert.deepEqual(database.account, []);
    assert.deepEqual(database.session, []);
    return { name: `email-otp-override/${timing}`, timing, before, beforeRelease, afterSettlement,
      messages, events, logs, deliveryBefore, deliveryAfter: native.snapshot(deliveryValue), functions: native.functions };
  } catch (error) {
    await writeObservation(`${JSON.stringify({ contract: "email-otp-override-values-failure", timing,
      overrideState, taskStates, database: native.snapshot(database), messages, events, logs,
      failure: native.snapshot(error) })}\n`);
    throw error;
  } finally {
    gate.resolve();
  }
}

export async function captureEmailOtpOverrideValues() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  const provenance = ["better-auth/dist/context/create-context.mjs", "better-auth/dist/plugins/email-otp/index.mjs",
    "better-auth/dist/plugins/email-otp/routes.mjs"].map(path => ({ path,
    sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") }));
  return withClock(async setClock => {
    setClock(epoch);
    const cases = [];
    for (const timing of emailOtpOverrideValueCases) cases.push(await captureCase(timing));
    return { contract: "email-otp-override-values", version: secondaryNativeVersion,
      runtime: { name: "bun", version: Bun.version }, provenance,
      boundary: "Invoke the real override installed by emailOTP.init on the real auth context. The inner endpoint result is a complete success object. The outer override returns undefined. A second retained task preserves the sender result and identity. Full Memory storage remains in the observation. Signup scheduling, SQL transaction rollback, missing-user cleanup, and host-runtime timing remain covered separately or unclaimed.", cases };
  });
}

if (import.meta.main) {
  const observation = await captureEmailOtpOverrideValues();
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
