import assert from "node:assert/strict";
import { createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

const mode = process.argv[2];
assert.ok(["retained", "eager-reflected", "forced-gc"].includes(mode));
assert.equal(Bun.version, "1.4.2");
assert.equal(Bun.revision, "744846f844374847c902b5e7fd59b4342a51ef99");
const input = "[1,]";
const observer = createSecondaryNativeObserver();

function createFailure(retainCaller) {
  const effects = { parseCalls: 0, reviverCalls: 0 };
  function parseCaller() {
    effects.parseCalls += 1;
    return JSON.parse(input, function reviver(key, value) {
      effects.reviverCalls += 1;
      return value;
    });
  }
  try {
    parseCaller();
  } catch (error) {
    return { error, effects, caller: retainCaller ? parseCaller : null, weakCaller: new WeakRef(parseCaller) };
  }
  assert.fail("The invalid JSON input must throw before the reviver runs");
}

function snapshot(error) {
  const descriptors = observer.snapshot(error);
  return {
    descriptors,
    name: error.name,
    message: error.message,
    display: Error.prototype.toString.call(error),
    isSyntaxError: error instanceof SyntaxError,
  };
}

const captured = createFailure(mode === "retained");
const original = captured.error;
// Descriptor reflection materializes Error metadata, so the GC-first arms must not inspect the error yet.
const before = mode === "eager-reflected" ? snapshot(original) : null;
await new Promise(resolve => setTimeout(resolve, 0));
Bun.gc(true);
const after = snapshot(captured.error);
const caller = captured.weakCaller.deref();
const properties = new Map(after.descriptors.properties);
const stack = properties.get("stack")?.value;
const signature = {
  missingOriginalLine: !properties.has("originalLine"),
  missingOriginalColumn: !properties.has("originalColumn"),
  errorStackHeading: typeof stack === "string" && stack.startsWith("Error\n"),
  missingParseFrame: typeof stack === "string" && !stack.includes("\n    at <parse> "),
};
const observation = {
  contract: "json-error-host-diagnostic",
  mode,
  engine: { bun: Bun.version, revision: Bun.revision },
  input,
  forcedCollections: 1,
  taskBoundariesBeforeCollection: 1,
  sameOriginal: captured.error === original,
  callerRetained: captured.caller !== null,
  callerCollected: caller === undefined,
  retainedCallerMatches: captured.caller === null ? null : caller === captured.caller,
  effects: captured.effects,
  before,
  after,
  signature,
};
await writeObservation(`${JSON.stringify(observation)}\n`);

assert.equal(observation.sameOriginal, true);
assert.deepEqual(captured.effects, { parseCalls: 1, reviverCalls: 0 });
assert.equal(after.isSyntaxError, true);
assert.equal(after.name, "SyntaxError");
assert.equal(after.message, "JSON Parse error: Unexpected comma at the end of array expression");
assert.equal(after.display, `SyntaxError: ${after.message}`);
if (mode === "retained") assert.equal(observation.retainedCallerMatches, true);
if (mode === "eager-reflected") assert.deepEqual(after, before);
