import { expect, test } from "bun:test";
import { assertObservationReplay } from "./observation-replay.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { writeObservation } from "./write-observation.mjs";

test("native coercion consumes named methods in runtime order", async () => {
  const records = [];
  const scenarios = [
    ...["array", "date", "function"].flatMap(kind => ["number", "string", "fallback", "get-throws", "call-throws", "non-callable"].map(mode => ({ kind, mode }))),
    ...["json-nan", "json-iso", "json-iso-get-throws", "json-iso-call-throws", "json-iso-non-callable", "json-invalid-finite", "json-valueof-get-throws", "json-valueof-call-throws"].map(mode => ({ kind: "date", mode })),
    { kind: "array", mode: "join" }, { kind: "function", mode: "native-number" },
  ];
  for (const { kind, mode } of scenarios) {
    const observer = createProtectedFunctionObserver();
    const value: any = kind === "array" ? [1] : kind === "date" ? new Date(mode === "json-invalid-finite" ? NaN : 0) : function nativeFunction() {};
    const events: string[] = [];
    const original = new Error("original native coercion error");
    function method(name: string, result: any, throws = false) {
      return function (this: any, ...args: any[]) {
        events.push(`call:${name}:${this === value}:${args.length}`);
        if (throws) throw original;
        return result;
      };
    }
    function property(name: string, result: any, throws = false) {
      Object.defineProperty(value, name, { configurable: true, get() {
        events.push(`get:${name}:${this === value}`);
        if (throws) throw original;
        return result;
      } });
    }
    if (mode.startsWith("json-")) {
      property("valueOf", method("valueOf", mode === "json-nan" ? NaN : 1, mode === "json-valueof-call-throws"), mode === "json-valueof-get-throws");
      if (mode !== "json-invalid-finite") property("toISOString", mode === "json-iso-non-callable" ? null : method("toISOString", "custom-iso", mode === "json-iso-call-throws"), mode === "json-iso-get-throws");
    } else if (mode === "join") {
      property("join", method("join", "joined"));
    } else if (mode !== "native-number") {
      property("valueOf", mode === "non-callable" ? null : method("valueOf", mode === "fallback" ? value : 7, mode === "call-throws"), mode === "get-throws");
      property("toString", method("toString", mode === "string" ? "string-result" : "8"));
    }
    let result: any;
    let error: any;
    try { result = mode.startsWith("json-") ? JSON.stringify(value) : mode === "string" || mode === "join" ? String(value) : Number(value); }
    catch (caught) { error = caught; }
    const record = {
      contract: "native-coercion-properties", kind, mode, events,
      outcome: error ? { kind: "thrown", name: error.name, message: error.message, sameOriginal: error === original }
        : { kind: "returned", value: observer.observe(result) },
    };
    records.push(record);
    await writeObservation(`${JSON.stringify(record)}\n`);
    if (mode.endsWith("throws")) expect(error).toBe(original);
    else if (mode === "json-iso-non-callable") expect(error).toBeInstanceOf(TypeError);
    else if (mode === "json-invalid-finite") expect(error).toBeInstanceOf(RangeError);
    else {
      expect(error).toBeUndefined();
      const expected = mode === "native-number" ? NaN : mode === "json-nan" ? "null" : mode === "json-iso" ? '"custom-iso"'
        : mode === "string" ? "string-result" : mode === "join" ? "joined" : ["fallback", "non-callable"].includes(mode) ? 8 : 7;
      expect(result).toBe(expected);
    }
  }
  expect(records).toHaveLength(scenarios.length);
  const fixture = await Bun.file(new URL("../../../tests/fixtures/native-coercion-properties-1.7.6.json", import.meta.url)).json();
  assertObservationReplay(records, fixture, "native-coercion-properties");
});
