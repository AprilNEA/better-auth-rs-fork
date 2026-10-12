import { expect, test } from "bun:test";
import { captureJsonParseNative } from "./json-parse-native-capture.mjs";
import { assertJsonParseNativeReplay, jsonParserHostStackPaths } from "./json-parse-native-replay.mjs";
import { assertObservationReplay } from "./observation-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

test("capture pinned JSON parser diagnostics, native conversion failures, and safeJSONParse logging", async () => {
  const serialized = JSON.stringify({ contract: "json-parse-native", ...await captureJsonParseNative() });
  await writeObservation(`${serialized}\n`);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/json-parse-native-1.7.6.json", import.meta.url)).json();
  expect(jsonParserHostStackPaths(fixture).size).toBe(724);
  assertJsonParseNativeReplay(JSON.parse(serialized), fixture);
});

test("JSON parser replay retains Error metadata and exact stack descriptor boundaries", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/json-parse-native-1.7.6.json", import.meta.url)).json();
  const expected = fixture.cases.find(captured => captured.name === "empty-input" && captured.mode === "direct");
  const property = (record, name) => record.error.properties.find(([key]) => key === name)[1];
  const hostOnly = structuredClone(expected);
  property(hostOnly, "stack").value = "SyntaxError: the same parser failure from another caller";
  expect(() => assertJsonParseNativeReplay(hostOnly, expected)).not.toThrow();
  for (const change of [
    record => { property(record, "stack").value = 1; },
    record => { property(record, "stack").writable = false; },
    record => { property(record, "message").value = "different parser state"; },
    record => { property(record, "originalLine").value += 1; },
    record => { property(record, "sourceURL").value = "/different/source.mjs"; },
    record => { record.error.ownKeys.reverse(); },
    record => { record.error.properties.reverse(); },
    record => { record.runtime.error.name = "TypeError"; },
    record => { record.runtime.error.message = "different parser state"; },
    record => { record.outcome.sameOriginal = true; },
  ]) {
    const actual = structuredClone(expected);
    change(actual);
    expect(() => assertJsonParseNativeReplay(actual, expected)).toThrow();
  }
});

test("shared replay checks deep observations without using the call stack", () => {
  let actual: unknown = "value";
  let expected: unknown = "value";
  let different: unknown = "changed";
  for (let depth = 0; depth < 4096; depth += 1) {
    actual = [actual];
    expected = [expected];
    different = [different];
  }
  expect(() => assertObservationReplay(actual, expected, "deep-array")).not.toThrow();
  expect(() => assertObservationReplay(different, expected, "deep-array")).toThrow();
});
