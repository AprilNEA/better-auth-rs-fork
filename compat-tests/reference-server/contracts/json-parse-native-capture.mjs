import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { runWithEndpointContext } from "@better-auth/core/context";
import { safeJSONParse } from "@better-auth/core/utils/json";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";
import { assertSecondaryNativeVersions, createSecondaryNativeObserver, secondaryNativeVersion } from "./secondary-native-shared.mjs";
import { writeObservation } from "./write-observation.mjs";
import { jsonParseNativeTextCases, jsonParseNativeCoercionCases, nativeCoercionInput, observeDocument } from "./json-parse-native-inputs.mjs";

export { jsonParseNativeTextCases, jsonParseNativeCoercionCases } from "./json-parse-native-inputs.mjs";
export const jsonParseNativeModes = ["direct", "reviver", "safe"];
const engineVersion = "1.4.2";
const webkitCommit = "2e2aa2290fac856d6f451ceacb58f7f5b44dd057";

function errorDetails(error, runtime) {
  if (!(error instanceof Error)) return { native: runtime.value(error) };
  return {
    name: error.name, message: error.message, display: Error.prototype.toString.call(error),
    hasOwnMessage: Object.hasOwn(error, "message"), messageEnumerable: Object.getOwnPropertyDescriptor(error, "message")?.enumerable,
    hasOwnName: Object.hasOwn(error, "name"), enumerable: runtime.value(error),
  };
}

async function captureCase(scenario, mode) {
  const native = createSecondaryNativeObserver();
  const runtime = createSecondaryRuntimeObserver();
  const events = [];
  const logs = [];
  const reviverKeys = [];
  const event = (phase, fields = {}, auditFields = fields) => { native.record(phase, auditFields); events.push({ phase, ...fields }); };
  const source = scenario.category === "coercion"
    ? nativeCoercionInput(scenario.name, event, runtime)
    : { input: scenario.text, original: { failure: scenario.name, ownUndefined: undefined } };
  const input = native.snapshot(source.input);
  const logger = { error(message, ...args) {
    const error = args[0]?.error;
    const fields = { message, argumentCount: args.length, argumentKeys: Object.keys(args[0]),
      error: errorDetails(error, runtime), sameOriginal: error === source.original };
    logs.push({ ...fields, arguments: native.snapshot(args) });
    event("logger:error", fields, logs.at(-1));
  } };
  let result;
  let caught;
  const operation = async () => {
    try {
      result = mode === "safe"
        ? await runWithEndpointContext({ context: { logger } }, () => safeJSONParse(source.input))
        : mode === "reviver" ? JSON.parse(source.input, function reviver(key, value) {
          reviverKeys.push(key);
          return value;
        }) : JSON.parse(source.input);
      return result;
    } catch (error) {
      caught = error;
      throw error;
    }
  };
  const outcome = await native.outcome(() => runtime.capture(operation, source.original), source.original);
  const details = caught === undefined ? undefined : errorDetails(caught, runtime);
  if (scenario.category !== "coercion") {
    assert.equal(outcome.returned, scenario.valid || mode === "safe");
    assert.equal(logs.length, !scenario.valid && mode === "safe" ? 1 : 0);
    if (!scenario.valid) {
      assert.deepEqual(reviverKeys, []);
      if (mode === "safe") {
        assert.equal(result, null);
        assert.equal(logs[0].error.name, "SyntaxError");
      } else {
        assert.ok(caught instanceof SyntaxError);
      }
    }
  } else if (mode === "safe") {
    assert.equal(outcome.returned, true);
    assert.equal(logs.length, 0);
    assert.equal(events.length, 0, "safeJSONParse must not coerce non-string input");
  } else if (scenario.name.endsWith("-error")) {
    assert.equal(outcome.returned, false);
    assert.equal(outcome.sameOriginal, true);
    assert.deepEqual(reviverKeys, []);
  } else if (["native-undefined", "native-nan", "native-infinity", "native-empty-array", "native-many-array", "native-date", "to-string-invalid-json"].includes(scenario.name)) {
    assert.equal(outcome.returned, false);
    assert.ok(caught instanceof SyntaxError);
    assert.deepEqual(reviverKeys, []);
  } else if (["native-symbol", "both-methods-return-objects", "symbol-method-object"].includes(scenario.name)) {
    assert.equal(outcome.returned, false);
    assert.ok(caught instanceof TypeError);
    assert.deepEqual(reviverKeys, []);
  } else {
    assert.equal(outcome.returned, true);
  }
  return {
    name: scenario.name, category: scenario.category, mode, input, outcome, error: caught === undefined ? undefined : native.snapshot(caught),
    events: native.events, logs, inputAfter: native.snapshot(source.input), functions: native.functions,
    runtime: { outcome: runtime.outcome, error: details, events, reviverKeys,
      sameInput: result === source.input,
      mutation: runtime.value(source.input !== null && (typeof source.input === "object" || typeof source.input === "function") ? source.input.mutation : undefined),
      functionIds: runtime.functionIds },
  };
}

export async function captureJsonParseNative() {
  assertSecondaryNativeVersions(["better-auth", "@better-auth/core"]);
  assert.equal(Bun.version, engineVersion, "The JSON parser diagnostic contract uses the pinned Bun engine");
  const path = "@better-auth/core/dist/utils/json.mjs";
  const provenance = {
    betterAuth: { path, sha256: createHash("sha256").update(readFileSync(new URL(`../node_modules/${path}`, import.meta.url))).digest("hex") },
    engine: { bun: Bun.version, revision: Bun.revision, webkitCommit },
    officialSources: [
      { path: "scripts/build/deps/webkit.ts", url: "https://github.com/oven-sh/bun/blob/bun-v1.4.2/scripts/build/deps/webkit.ts", sha256: "21d397951be3ac93def2fea1756c4815e9ace068a6a01a8530c1f0c65ac4b343" },
      ...[
        ["LiteralParser.cpp", "0c64eae7e9985a14461f30a986c5482f5eb78d851e11832e44296033679e1f60"],
        ["LiteralParser.h", "71d75286169044b1b93901422da332811c7d3a357175ea5c0759c8ac433004ab"],
        ["JSONObject.cpp", "25006ef8b896b5860fac37815683cd4b0563f31ce879dbaebd87e86d4513a1d1"],
      ].map(([file, sha256]) => ({ path: `Source/JavaScriptCore/runtime/${file}`,
        url: `https://github.com/oven-sh/WebKit/blob/${webkitCommit}/Source/JavaScriptCore/runtime/${file}`, sha256 })),
    ],
  };
  const cases = [];
  const scenarios = [...jsonParseNativeTextCases, ...jsonParseNativeCoercionCases.map(name => ({ name, category: "coercion" }))];
  assert.equal(new Set(scenarios.map(scenario => scenario.name)).size, scenarios.length);
  for (const scenario of scenarios) for (const mode of jsonParseNativeModes) cases.push(await captureCase(scenario, mode));
  return observeDocument({ version: secondaryNativeVersion, provenance,
    boundary: "Actual JSON.parse with and without a callable identity reviver, plus Better Auth safeJSONParse. Lexer, parser-state, UTF-16, numeric, whitespace, depth and ToString failures remain separate observations. Runtime errors retain complete name/message/display and visible fields; complete Error descriptors and host metadata remain in the source audit. Unpaired UTF-16 values use exact code-unit observations; objects with unpaired property names use complete ordered entries. Symbol and BigInt observations are retained without claiming Rust representation support.",
    cases });
}

if (import.meta.main) {
  const observation = { contract: "json-parse-native", ...await captureJsonParseNative() };
  if (process.argv[2]) writeFileSync(process.argv[2], `${JSON.stringify(observation, null, 2)}\n`);
  await writeObservation(`${JSON.stringify(observation)}\n`);
}
