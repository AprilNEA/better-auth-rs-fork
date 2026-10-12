import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver } from "./secondary-native-shared.mjs";

export async function captureDetachedOwnership(run) {
  const name = process.argv[2];
  const output = process.argv[3];
  assert.ok(name && output, "Pass a scenario name and an output path");
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core", "@better-auth/telemetry"]);

  const unhandled = [];
  const handled = [];
  const consoleCalls = [];
  const onUnhandled = (reason, promise) => unhandled.push({ reason, promise });
  const onHandled = promise => handled.push(promise);
  process.on("unhandledRejection", onUnhandled);
  process.on("rejectionHandled", onHandled);
  const originals = new Map(["debug", "info", "log", "warn", "error"].map(level => [level, console[level]]));
  for (const level of originals.keys()) console[level] = (...args) => consoleCalls.push([level, ...args]);
  const restore = () => {
    for (const [level, original] of originals) console[level] = original;
    process.off("unhandledRejection", onUnhandled);
    process.off("rejectionHandled", onHandled);
  };

  let verify;
  try {
    verify = await run({ name, unhandled });
  } catch (error) {
    restore();
    throw error;
  }
  // Only the standalone child observes host events; no catch is attached to an unowned task.
  process.once("beforeExit", () => {
    restore();
    const native = createSecondaryNativeObserver();
    const evidence = JSON.stringify({ version: "1.7.6", name, host: native.snapshot({ unhandled, handled }), console: native.snapshot(consoleCalls) });
    writeFileSync(output, evidence);
    process.stdout.write(`${evidence}\n`);
    assert.deepEqual(handled, [], "The source must not acquire an unowned rejection later");
    assert.deepEqual(consoleCalls, [], "The source must not add a default application log");
    verify();
  });
}

export async function settle(operation) {
  try {
    return { status: "fulfilled", value: await operation() };
  } catch (reason) {
    return { status: "rejected", reason };
  }
}
