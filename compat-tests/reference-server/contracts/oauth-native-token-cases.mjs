export function nativeTokenCases() {
  const cases = [];
  for (const verifier of ["omitted", "undefined", "null", "false", "zero", "nan", "empty", "string", "date", "invalid-date", "array", "object"]) {
    cases.push({ name: `verifier-${verifier}`, verifier, result: "object" });
  }
  for (const result of ["undefined", "null", "false", "zero", "nan", "empty", "string", "true", "number", "array", "date", "function", "object"]) {
    for (const expiry of ["absent", "default"]) cases.push({ name: `result-${result}-${expiry}`, result, expiry });
  }
  for (const result of ["expiry-getter-truthy", "expiry-getter-falsy", "expiry-getter-throws", "expiry-setter-throws", "expiry-readonly", "expiry-nonenumerable", "sparse-array", "callback-throws"]) {
    cases.push({ name: result, result, expiry: "default" });
  }
  for (const expiry of ["zero", "nan", "infinity", "negative", "fractional"]) {
    cases.push({ name: `expiry-${expiry}`, result: "object", expiry });
  }
  return cases;
}
