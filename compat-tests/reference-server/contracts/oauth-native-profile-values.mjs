import { observeValue } from "./device-where-capture.mjs";
import { native } from "./user-verification-cleanup-support.mjs";

export const origin = "http://oauth-native-profile.test";
export const secret = "oauth-native-profile-contract-secret-at-least-thirty-two-characters";
export const timestamp = Date.parse("2030-01-02T03:04:05.000Z");
export const email = "Owner@oauth-native-profile.test";
export const tables = ["user", "session", "account", "verification"];

export function createState(scenario) {
  const state = {
    scenario, phase: "setup", events: [], replacements: new Map(), admissions: [],
    marker: { source: "same-native-object" },
    failure: Object.assign(new Error("Native provider profile failure"), { code: "PROFILE_NATIVE_FAILURE", detail: { retry: false } }),
    record(event) { this.events.push({ phase: this.phase, ...event }); },
  };
  const raw = { id: "raw-account", sub: "raw-account", name: "Raw User", email, emailVerified: true, image: null, rawExtra: { kept: true } };
  let mapped = {};
  if (scenario.shape === "missing") {
    for (const field of ["name", "email", "emailVerified", "image"]) delete raw[field];
  } else if (scenario.shape === "null") {
    for (const field of ["name", "email", "emailVerified", "image"]) raw[field] = null;
  } else if (scenario.shape === "dynamic") {
    Object.assign(raw, { name: ["Raw", 3], email: 7, emailVerified: [false], image: { url: "native-image" } });
    mapped = { id: "mapped-account", name: { label: "Mapped" }, email: 9, emailVerified: "verified", image: 13, mappedExtra: state.marker, ownUndefined: undefined };
  } else if (scenario.shape === "native-business") {
    Object.assign(raw, { name: { label: "Native User" }, image: ["native-image", 3], emailVerified: "verified" });
    mapped = { id: "mapped-account" };
  } else if (scenario.shape === "identity") {
    mapped = { id: "mapped-account", name: "Mapped User", profileExtra: state.marker };
  } else if (scenario.shape === "empty-email") {
    raw.email = "";
  } else if (scenario.shape === "dynamic-email") {
    Object.assign(raw, { email: 7, name: { label: "Native User" }, emailVerified: [false], image: 19 });
  } else if (scenario.shape === "falsy-defaults") {
    Object.assign(raw, { name: 0, emailVerified: 0, image: false });
  }
  if (scenario.shape === "getters") {
    mapped = { id: "mapped-account", name: { label: "Getter mapped" }, image: null, ownUndefined: undefined };
  }
  if (scenario.shape === "raw-getter-error") Object.defineProperty(raw, "name", {
    enumerable: true, configurable: true, get() { state.record({ kind: "getter-throw", object: "raw", key: "name" }); throw state.failure; },
  });
  if (scenario.shape === "subject-error") Object.defineProperty(raw, "sub", {
    enumerable: true, configurable: true, get() { state.record({ kind: "getter-throw", object: "raw", key: "sub" }); throw state.failure; },
  });
  state.raw = scenario.shape === "scalar" ? 7 : traceObject(raw, "raw", state);
  state.mapped = traceObject(mapped, "mapped", state);
  if (scenario.provider === "social") {
    const user = { id: "mapped-account", name: raw.name, email: raw.email, emailVerified: raw.emailVerified, image: raw.image, ownUndefined: undefined };
    if (scenario.shape.startsWith("response-spread")) Object.assign(user, {
      name: { label: "Native User" }, email: 7, emailVerified: [false], image: false,
    });
    const response = { providerMeta: state.marker, user: traceObject(user, "user", state), account: { untrusted: true }, data: state.raw, ownUndefined: undefined };
    Object.defineProperty(response, "tail", {
      enumerable: true, get() {
        state.record({ kind: "getter", object: "response", key: "tail" });
        if (scenario.shape === "response-spread-error") throw state.failure;
        return { kept: true };
      },
    });
    Object.defineProperty(response, "hidden", { value: "not-enumerable" });
    state.socialResponse = traceObject(response, "response", state);
  }
  state.events.length = 0;
  return state;
}

function traceObject(target, label, state) {
  return new Proxy(target, {
    get(object, key, receiver) {
      if (Object.hasOwn(object, key)) state.record({ kind: "get", object: label, key: String(key) });
      return Reflect.get(object, key, receiver);
    },
    ownKeys(object) {
      const keys = Reflect.ownKeys(object);
      state.record({ kind: "own-keys", object: label, keys: keys.map(String) });
      return keys;
    },
    getOwnPropertyDescriptor(object, key) {
      state.record({ kind: "descriptor", object: label, key: String(key) });
      return Reflect.getOwnPropertyDescriptor(object, key);
    },
  });
}

export function errorValue(error, state) {
  return { error: native(error), originalError: error === state.failure };
}

function attempt(read, state) {
  try { return { returned: true, value: read() }; }
  catch (error) { return { returned: false, ...errorValue(error, state) }; }
}

function keyOrder(value, path = []) {
  if (value === null || typeof value !== "object" || value instanceof Date) return [];
  const keys = Object.keys(value);
  return [{ path, keys }, ...keys.flatMap(key => keyOrder(value[key], [...path, key]))];
}

// Keep observer reads separate from the provider and endpoint reads under test.
export function observeComplete(value, state, label) {
  const previous = state.phase;
  try {
    state.phase = `${label}:native`;
    const observed = attempt(() => observeValue(value), state);
    state.phase = `${label}:json`;
    const json = attempt(() => {
      const text = JSON.stringify(value);
      return text === undefined ? { defined: false } : { defined: true, value: JSON.parse(text) };
    }, state);
    state.phase = `${label}:keys`;
    return { native: observed, json, keyOrder: attempt(() => keyOrder(value), state) };
  } finally { state.phase = previous; }
}

export function replaceGenerated(value, replacements) {
  if (typeof value === "string") return replacements.get(value) ?? value;
  if (Array.isArray(value)) return value.map(child => replaceGenerated(child, replacements));
  if (value !== null && typeof value === "object") return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [key, replaceGenerated(child, replacements)]),
  );
  return value;
}
