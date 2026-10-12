import assert from "node:assert/strict";
import { createSecondaryNativeObserver } from "./secondary-native-shared.mjs";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";
import { createSecondaryRuntimeObserver } from "./secondary-native-runtime.mjs";

const primitive = value => ({ kind: "primitive", value });
const boxed = (value, alternate) => ({ kind: "boxed", value, ...(alternate === undefined ? {} : { alternate }) });
const date = value => ({ kind: "date", value });
const numbers = values => values.map(primitive);
const boxes = values => values.map(value => boxed(value));

function runs(length, mixed) {
  return Array.from({ length }, (_, index) => {
    const run = Math.floor(index / 17);
    const offset = index % 17;
    const rank = (run % 2 === 0 ? offset : 16 - offset) + (run % 3) * 5;
    if (!mixed) return boxed(rank);
    if (index % 13 === 0) return boxed(NaN);
    if (index % 11 === 0) return primitive(null);
    if (index % 7 === 0) return primitive(String(rank));
    if (index % 5 === 0) return primitive(rank);
    return boxed(rank);
  });
}

export const nativeSortScenarios = [
  { name: "empty", values: [] },
  { name: "single", values: boxes([7]) },
  { name: "pair-ascending", values: boxes([1, 2]) },
  { name: "pair-descending", values: boxes([2, 1]) },
  { name: "triple-mixed", values: boxes([3, 1, 2]) },
  { name: "eight-mixed", values: boxes([8, 2, 5, 1, 7, 3, 6, 4]) },
  { name: "stable-equal", values: boxes([2, 1, 2, 1, 2]) },
  { name: "nullish-mixed", values: [primitive(null), primitive(2), primitive(undefined), { kind: "missing" }, primitive(1), primitive(null)] },
  { name: "mixed-comparison", values: [primitive(2), primitive("2"), primitive("10"), boxed(1), primitive(false), boxed(NaN), primitive("word")] },
  { name: "dates-shadow-get-time", values: [date(8), date(2), date(6), date(4)] },
  { name: "date-invalid-tie", values: [date(8), date(NaN), date(2)] },
  { name: "changing-conversion", values: [boxed(4, -4), boxed(1, 8), boxed(3, -3), boxed(2, 7)] },
  { name: "getter-mutates-peer", values: boxes([4, 1, 3, 2]), mutate: { phase: "read", at: 2, target: 2, value: 9 } },
  { name: "conversion-mutates-peer", values: boxes([4, 1, 3, 2]), mutate: { phase: "convert", at: 2, target: 2, value: 9 } },
  { name: "getter-throws-first", values: boxes([4, 1, 3, 2]), fail: { phase: "read", at: 1 } },
  { name: "getter-throws-later", values: boxes([4, 1, 3, 2]), fail: { phase: "read", at: 5 } },
  { name: "conversion-throws-first", values: boxes([4, 1, 3, 2]), fail: { phase: "convert", at: 1 } },
  { name: "conversion-throws-later", values: boxes([4, 1, 3, 2]), fail: { phase: "convert", at: 5 } },
  { name: "short-run-boundary-32", values: runs(32, false) },
  { name: "run-boundary-64", values: runs(64, false) },
  { name: "run-boundary-65", values: runs(65, false) },
  { name: "long-mixed-runs-129", values: runs(129, true) },
  { name: "long-mixed-runs-error", values: runs(129, true), fail: { phase: "read", at: 151 } },
];

export const jwkSortScenarios = [
  { name: "get-time-throws-first", values: numbers([4, 1, 3, 2]), fail: { phase: "get-time", at: 1 } },
  { name: "get-time-throws-later", values: numbers([4, 1, 3, 2]), fail: { phase: "get-time", at: 5 } },
  { name: "filter-before-sort", values: boxes([4, 1, 3, 2]), keyring: true },
];

export function createNativeSortHarness(consumer, scenario, access = "getters") {
  const native = createSecondaryNativeObserver();
  const protectedValues = createProtectedFunctionObserver();
  const runtime = access === "data" ? createSecondaryRuntimeObserver() : undefined;
  const events = [];
  const counts = {};
  const rows = [];
  const cells = [];
  const rowCells = new WeakMap();
  const conversionCells = new WeakMap();
  const methodCells = new WeakMap();
  const original = { kind: "native-sort-failure", consumer, scenario: scenario.name };
  const field = consumer === "jwk" ? "createdAt" : "name";

  function event(phase, properties) {
    const count = counts[phase] = (counts[phase] ?? 0) + 1;
    events.push({ phase, count, ...properties });
    if (scenario.mutate?.phase === phase && scenario.mutate.at === count) {
      const cell = cells[scenario.mutate.target];
      cell.value = makeValue(boxed(scenario.mutate.value), `${cell.id}:replacement`);
      if (access === "data" && consumer !== "jwk") rows[scenario.mutate.target][field] = cell.value;
      events.push({ phase: "mutation", target: cell.id, replacement: scenario.mutate.value });
    }
    if (scenario.fail?.phase === phase && scenario.fail.at === count) throw original;
  }

  function convert(method, receiver, args) {
    const cell = conversionCells.get(receiver);
    assert.ok(cell, "Conversion must retain its original receiver");
    const ordinal = ++cell.calls;
    const result = Object.hasOwn(cell.spec, "alternate") && ordinal % 2 === 0 ? cell.spec.alternate : cell.spec.value;
    event("convert", { id: cell.id, method, ordinal, arguments: protectedValues.observe(args), result: protectedValues.observe(result) });
    return method === "toString" ? String(result) : result;
  }

  function valueOf(...args) { return convert("valueOf", this, args); }
  function toString(...args) { return convert("toString", this, args); }
  function getTime(...args) {
    const cell = methodCells.get(this);
    assert.ok(cell, "getTime must retain its original receiver");
    event("get-time", { id: cell.id, arguments: protectedValues.observe(args) });
    return cell.value;
  }

  function makeValue(spec, id) {
    if (spec.kind === "missing") return undefined;
    if (spec.kind === "primitive") return spec.value;
    if (spec.kind === "boxed") {
      const value = { label: id, valueOf, toString };
      conversionCells.set(value, { id, spec, calls: 0 });
      return value;
    }
    assert.equal(spec.kind, "date");
    const value = Object.assign(new Date(spec.value), { getTime });
    methodCells.set(value, { id, value: spec.value });
    return value;
  }

  function readSortField() {
    const cell = rowCells.get(this);
    assert.ok(cell, "Field access must retain its original record");
    event("read", { id: cell.id, field });
    return consumer === "jwk" ? cell.time : cell.value;
  }

  function readExpiry() {
    const cell = rowCells.get(this);
    event("expiry", { id: cell.id });
    return cell.expiry;
  }

  function readAlgorithm() {
    const cell = rowCells.get(this);
    event("algorithm", { id: cell.id });
    return cell.algorithm;
  }

  for (const [index, spec] of scenario.values.entries()) {
    const id = `row-${index}`;
    const cell = { id, value: makeValue(spec, id) };
    const row = { id };
    if (consumer === "jwk") {
      cell.time = { label: id, getTime };
      // The method reads the live cell after another comparison mutates the keyring.
      methodCells.set(cell.time, cell);
      cell.expiry = scenario.keyring && index === 1 ? new Date(0) : null;
      cell.algorithm = scenario.keyring && index === 2 ? "RS256" : index % 2 === 0 ? "EdDSA" : null;
      if (access === "data") {
        row.alg = cell.algorithm;
        row.expiresAt = cell.expiry;
      } else {
        Object.defineProperties(row, {
          alg: { get: readAlgorithm, enumerable: true, configurable: true },
          expiresAt: { get: readExpiry, enumerable: true, configurable: true },
        });
      }
    }
    rowCells.set(row, cell);
    if (consumer === "jwk" || spec.kind !== "missing") {
      if (access === "data") row[field] = consumer === "jwk" ? cell.time : cell.value;
      else Object.defineProperty(row, field, { get: readSortField, enumerable: true, configurable: true });
    }
    cells.push(cell);
    rows.push(row);
  }

  function snapshot(result, includeResult) {
    return native.snapshot({ rows, cells, ...(includeResult ? { result } : {}) });
  }

  async function capture(operation) {
    const before = snapshot();
    const runtimeBefore = runtime?.value({ rows, cells });
    const originalOrder = [...rows];
    let result;
    let outcome;
    try {
      result = await operation();
      outcome = { returned: true };
    } catch (caught) {
      if (caught instanceof assert.AssertionError) throw caught;
      outcome = { returned: false, sameOriginal: caught === original, error: protectedValues.error(caught) };
    }
    assert.equal(rows.length, originalOrder.length);
    for (const [index, row] of rows.entries()) assert.equal(row, originalOrder[index], "Sorting copies must preserve stored record order");
    const captured = {
      before, outcome, after: snapshot(result, outcome.returned), events, counts,
      functions: native.functions,
    };
    if (runtime) {
      const returnedRows = outcome.returned ? consumer === "jwk" ? result === undefined ? [] : [result] : result : [];
      captured.runtime = {
        before: runtimeBefore,
        outcome: { ...outcome, ...(outcome.returned ? { result: runtime.value(result) } : {}) },
        after: runtime.value({ rows, cells }), events, counts,
        identities: returnedRows.map(row => ({
          storedRecord: rows.indexOf(row),
          valueCells: cells.flatMap((cell, index) => row[field] !== null && typeof row[field] === "object"
            && row[field] === (consumer === "jwk" ? cell.time : cell.value) ? [index] : []),
        })),
        functions: runtime.functionIds,
      };
    }
    return captured;
  }

  return {
    rows, cells, events, capture, record: event, observe: protectedValues.observe,
    outputValue: value => runtime ? runtime.value(value)
      : value !== null && typeof value === "object" ? "native-object" : protectedValues.observe(value),
  };
}

export function assertNativeSortObservation(observed) {
  for (const captured of observed.cases) {
    const scenario = [...nativeSortScenarios, ...jwkSortScenarios].find(candidate => candidate.name === captured.scenario);
    assert.ok(scenario);
    const label = `${captured.consumer}/${captured.scenario}/${captured.direction ?? captured.lane}`;
    if (scenario.fail) {
      assert.equal(captured.counts[scenario.fail.phase], scenario.fail.at, `${label}: The configured failure must be reached`);
      assert.equal(captured.outcome.returned, false, label);
      assert.equal(captured.outcome.sameOriginal, true, `${label}: The consumer must propagate the original comparison failure`);
    } else {
      assert.equal(captured.outcome.returned, true, `${label}: ${JSON.stringify(captured.outcome)}`);
    }
  }
}
