import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProtectedFunctionObserver } from "./protected-function-shared.mjs";

export const secondaryNativeVersion = "1.7.6";
export const secondaryNativeNow = 2_000_000_000_000;

export function assertSecondaryNativeVersions(names) {
  for (const name of names) {
    const metadata = JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), "utf8"));
    assert.equal(metadata.version, secondaryNativeVersion);
  }
}

export function createSecondaryNativeObserver() {
  const observer = createProtectedFunctionObserver();
  const events = [];
  // Read descriptors so observation cannot call the getters or methods under test.
  function snapshot(root) {
    const identities = new WeakMap();
    let serial = 0;
    function visit(value) {
      if (value === null || typeof value !== "object" && typeof value !== "function") return observer.observe(value);
      if (identities.has(value)) return { reference: identities.get(value) };
      const identity = `object-${++serial}`;
      identities.set(value, identity);
      const keys = Reflect.ownKeys(value);
      const properties = keys.map(key => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        const flags = { enumerable: descriptor.enumerable, configurable: descriptor.configurable };
        return [observer.observe(key), "value" in descriptor
          ? { ...flags, writable: descriptor.writable, value: visit(descriptor.value) }
          : { ...flags, get: visit(descriptor.get), set: visit(descriptor.set) }];
      });
      return {
        identity, type: Array.isArray(value) ? "array" : value instanceof Date ? "date" : typeof value,
        ownKeys: keys.map(observer.observe), properties,
        ...(typeof value === "function" ? { value: observer.observe(value) } : {}),
        ...(value instanceof Date ? { value: Number.isNaN(Date.prototype.getTime.call(value))
          ? "Invalid Date" : Date.prototype.toISOString.call(value) } : {}),
      };
    }
    return visit(root);
  }
  function record(phase, fields = {}) { events.push({ phase, ...fields }); }
  function call(phase, receiver, expected, args) {
    record(phase, { sameReceiver: receiver === expected, arguments: snapshot(args) });
  }
  async function outcome(operation, original) {
    try { return { returned: true, result: snapshot(await operation()) }; }
    catch (error) {
      if (error instanceof assert.AssertionError) throw error;
      return { returned: false, sameOriginal: error === original, error: snapshot(error) };
    }
  }
  return { snapshot, record, call, outcome, events, functions: observer.functions };
}

export async function withSecondarySourceExports(packageName, names, operation) {
  const path = fileURLToPath(import.meta.resolve(packageName));
  const source = readFileSync(path, "utf8");
  const temporary = `${path}.secondary-contract-${randomUUID()}.mjs`;
  const provenance = {
    package: packageName, version: secondaryNativeVersion,
    sha256: createHash("sha256").update(source).digest("hex"),
    addedExports: names, modification: "Append exports only; preserve the complete original module body.",
  };
  try {
    writeFileSync(temporary, `${source}\nexport { ${names.join(", ")} };\n`, { flag: "wx" });
    return await operation(await import(pathToFileURL(temporary).href), provenance);
  } finally { rmSync(temporary, { force: true }); }
}
