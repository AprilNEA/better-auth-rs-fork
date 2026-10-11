import { expect, test } from "bun:test";
import { toResponse } from "better-call";

type Step = () => unknown;
const tracked = new Set(["buffer", "constructor", "toJSON", "toString", "valueOf"]);

function probe(fields: Record<string, unknown>, reads: Map<string, Step[]>, events: string[]) {
  return new Proxy(fields, {
    get(target, key, receiver) {
      if (typeof key === "string" && tracked.has(key)) events.push(key);
      const steps = typeof key === "string" ? reads.get(key) : undefined;
      if (steps) {
        const step = steps.shift();
        if (!step) throw new Error(`Unexpected repeated ${String(key)} read`);
        return step();
      }
      return Reflect.get(target, key, receiver);
    },
  });
}

function method(events: string[], name: string, result: unknown) {
  return function (...args: unknown[]) {
    if (name === "toJSON") expect(args).toStrictEqual([""]);
    else if (name === "toString") expect(args).toStrictEqual([]);
    events.push(`call:${name}`);
    return result;
  };
}

function sample(name: string, events: string[]) {
  const reads = new Map<string, Step[]>([["toJSON", [() => method(events, "toJSON", "encoded")]]]);
  switch (name) {
    case "buffer": reads.set("buffer", [() => true]); break;
    case "constructor-null":
    case "constructor-undefined":
      reads.set("constructor", [() => name === "constructor-null" ? null : undefined]);
      reads.set("toJSON", [() => undefined]);
      break;
    case "constructor-shift":
      reads.set("constructor", [() => ({ name: "Other" }), () => ({ name: "Object" })]);
      break;
    case "method-shift":
      reads.set("constructor", [() => null]);
      reads.set("toJSON", [() => method(events, "classification", null), () => method(events, "toJSON", "encoded")]);
      break;
    case "prototype": break;
    default: throw new Error(`Unknown HTTP classification sample: ${name}`);
  }
  return probe({ toString: method(events, "toString", "opaque") }, reads, events);
}

test("HTTP classification preserves getter order and BodyInit MIME", async () => {
  const cases = [
    ["buffer", "opaque", ["buffer", "toString", "call:toString"], false],
    ["constructor-null", "opaque", ["buffer", "constructor", "toJSON", "toString", "call:toString"], false],
    ["constructor-undefined", "opaque", ["buffer", "constructor", "toJSON", "toString", "call:toString"], false],
    ["constructor-shift", '"encoded"', ["buffer", "constructor", "constructor", "toJSON", "call:toJSON"], true],
    ["method-shift", '"encoded"', ["buffer", "constructor", "toJSON", "toJSON", "call:toJSON"], true],
    ["prototype", '"encoded"', ["buffer", "constructor", "constructor", "toJSON", "call:toJSON"], true],
  ] as const;
  for (const [name, bytes, expectedEvents, json] of cases) {
    for (const initial of [undefined, "application/custom", ""]) {
      const events: string[] = [];
      const response = toResponse(sample(name, events), {
        headers: initial === undefined ? undefined : { "content-type": initial },
      });
      expect(await response.text(), name).toBe(bytes);
      expect([...response.headers], name).toStrictEqual(json
        ? [["content-type", "application/json"]]
        : initial === undefined ? [] : [["content-type", initial]]);
      expect(events, name).toStrictEqual(expectedEvents);
    }
  }
});

test("HTTP classification preserves original getter errors", () => {
  for (const stage of ["buffer", "constructor-first", "constructor-second", "constructor-name", "toJSON-class", "toJSON-encode", "toString", "valueOf"]) {
    const events: string[] = [];
    const failure = new Error(`original HTTP ${stage} failure`);
    const fail = () => { throw failure; };
    const reads = new Map<string, Step[]>();
    let expected: string[];
    switch (stage) {
      case "buffer":
        reads.set("buffer", [fail]); expected = ["buffer"]; break;
      case "constructor-first":
        reads.set("constructor", [fail]); expected = ["buffer", "constructor"]; break;
      case "constructor-second":
        reads.set("constructor", [() => true, fail]); expected = ["buffer", "constructor", "constructor"]; break;
      case "constructor-name":
        reads.set("constructor", [() => true, () => Object.defineProperty({}, "name", { get: fail })]);
        expected = ["buffer", "constructor", "constructor"]; break;
      case "toJSON-class":
        reads.set("constructor", [() => null]); reads.set("toJSON", [fail]); expected = ["buffer", "constructor", "toJSON"]; break;
      case "toJSON-encode":
        reads.set("toJSON", [fail]); expected = ["buffer", "constructor", "constructor", "toJSON"]; break;
      case "toString":
        reads.set("buffer", [() => true]); reads.set("toString", [fail]); expected = ["buffer", "toString"]; break;
      default:
        reads.set("buffer", [() => true]); reads.set("toString", [() => null]); reads.set("valueOf", [fail]); expected = ["buffer", "toString", "valueOf"];
    }
    let caught: unknown;
    try { toResponse(probe({}, reads, events)); } catch (error) { caught = error; }
    expect(caught, stage).toBe(failure);
    expect(events, stage).toStrictEqual(expected);
  }
});

test("HTTP constructor second read can become null and JSON stays strict", () => {
  const events: string[] = [];
  const value = probe({}, new Map([["constructor", [() => true, () => null]]]), events);
  expect(() => toResponse(value)).toThrow(TypeError);
  expect(events).toStrictEqual(["buffer", "constructor", "constructor"]);
  events.length = 0;
  expect(JSON.stringify(sample("buffer", events))).toBe('"encoded"');
  expect(events).toStrictEqual(["toJSON", "call:toJSON"]);
});

// FieldFunction cannot represent the function source retained by this upstream-only contract.
test("Bun stringifies root functions without invoking them", async () => {
  let calls = 0;
  function rootResult() { calls += 1; return "called"; }
  const source = Function.prototype.toString.call(rootResult);
  for (const initial of [undefined, "application/custom", ""]) {
    const response = toResponse(rootResult, {
      headers: initial === undefined ? undefined : { "content-type": initial },
    });
    expect(response.status).toBe(200);
    expect(response.body).not.toBeNull();
    expect([...response.headers]).toStrictEqual(initial === undefined ? [] : [["content-type", initial]]);
    expect(await response.text()).toBe(source);
    expect(calls).toBe(0);
  }
});
