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
  const variants = assertJsonParseNativeReplay(JSON.parse(serialized), fixture);
  await writeObservation(`${JSON.stringify({ contract: "json-parse-native-host", ...variants })}\n`);
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
  const utf16 = fixture.cases.find(captured => captured.name === "surrogate-token" && captured.mode === "direct");
  const movedStack = structuredClone(utf16);
  property(movedStack, "stack").value.value.push(32);
  expect(() => assertJsonParseNativeReplay(movedStack, utf16)).not.toThrow();
  for (const change of [
    record => { property(record, "stack").value.type = "array"; },
    record => { property(record, "stack").value.value[0] = "wrong-unit"; },
    record => { property(record, "stack").enumerable = true; },
    record => { property(record, "message").value.value[0] += 1; },
  ]) {
    const actual = structuredClone(utf16);
    change(actual);
    expect(() => assertJsonParseNativeReplay(actual, utf16)).toThrow();
  }
});

test("JSON parser replay admits only the observed GC SyntaxError shape", async () => {
  const fixture = await Bun.file(new URL("../../../tests/fixtures/json-parse-native-1.7.6.json", import.meta.url)).json();
  const evidence = await Bun.file(new URL("../../../tests/fixtures/json-error-host-gc-1.4.2.json", import.meta.url)).json();
  const observed = evidence.sourceObservation.case;
  const expected = fixture.cases.find(captured => captured.name === observed.name && captured.mode === observed.mode);
  const property = (record, name) => record.error.properties.find(([key]) => key === name)[1];
  expect(assertJsonParseNativeReplay(observed, expected)).toEqual({ gcSyntaxErrorPaths: ["/outcome/error", "/error"] });
  expect(assertJsonParseNativeReplay(expected, expected)).toEqual({ gcSyntaxErrorPaths: [] });
  expect(assertJsonParseNativeReplay({ cases: [expected, observed] }, { cases: [expected, expected] }))
    .toEqual({ gcSyntaxErrorPaths: ["/cases/1/outcome/error", "/cases/1/error"] });
  for (const change of [
    record => { record.error = structuredClone(expected.error); },
    record => { property(record, "stack").value += "\n    at differentCaller (unknown)"; },
  ]) {
    const actual = structuredClone(observed);
    change(actual);
    expect(() => assertJsonParseNativeReplay(actual, expected)).toThrow();
  }
  for (const change of [
    record => { property(record, "stack").value = property(expected, "stack").value; },
    record => { property(record, "stack").value = "Error\n    at unrelated (unknown)"; },
    record => { property(record, "stack").value = property(record, "stack").value.replace("parse (unknown)", "different (unknown)"); },
    record => { property(record, "stack").value = property(record, "stack").value.replace("<anonymous>", "differentCaller"); },
    record => { property(record, "stack").value += "\n    at <parse> (:0)"; },
    record => { property(record, "stack").value = 1; },
    record => { property(record, "stack").value = { type: "utf16", value: [69, 114, 114, 111, 114] }; },
    record => { property(record, "stack").writable = false; },
    record => { property(record, "stack").enumerable = true; },
    record => { property(record, "message").value = "different parser state"; },
    record => { property(record, "line").value += 1; },
    record => { property(record, "column").value += 1; },
    record => { property(record, "sourceURL").value = "/different/source.mjs"; },
    record => { record.error.ownKeys.reverse(); },
    record => { record.error.properties.reverse(); },
    record => { record.error.identity = "different-error"; },
    record => { record.runtime.error.name = "TypeError"; },
    record => { record.runtime.error.message = "different parser state"; },
    record => { record.outcome.sameOriginal = true; },
    record => { record.runtime.outcome.sameOriginal = true; },
    ...["originalLine", "originalColumn"].flatMap(name => [
      record => { record.error.ownKeys.splice(1, 0, name); },
      record => { record.error.properties.splice(1, 0, [name, property(expected, name)]); },
      record => {
        record.error.ownKeys.splice(1, 0, name);
        record.error.properties.splice(1, 0, [name, property(expected, name)]);
      },
    ]),
  ]) {
    const actual = structuredClone(observed);
    change(actual);
    actual.outcome.error = structuredClone(actual.error);
    expect(() => assertJsonParseNativeReplay(actual, expected)).toThrow();
  }
  for (const change of [
    record => { record.runtime.error.name = "TypeError"; },
    record => { record.runtime.error.name = "APIError"; },
    record => { record.outcome.sameOriginal = true; },
    record => { delete record.runtime.error; },
  ]) {
    const actual = structuredClone(observed);
    const unsupported = structuredClone(expected);
    change(actual);
    change(unsupported);
    expect(() => assertJsonParseNativeReplay(actual, unsupported)).toThrow();
  }
  const utf16Source = structuredClone(expected);
  for (const error of [utf16Source.error, utf16Source.outcome.error]) {
    const stack = error.properties.find(([key]) => key === "stack")[1];
    stack.value = { type: "utf16", value: Array.from(stack.value, char => char.charCodeAt(0)) };
  }
  expect(() => assertJsonParseNativeReplay(observed, utf16Source)).toThrow();
  expect(() => assertJsonParseNativeReplay({ business: observed }, { business: expected })).toThrow();
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
