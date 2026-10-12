const debug = "OAuth proxy: could not decrypt state package, falling back to regular callback";
const invalidPackage = "Invalid OAuth proxy state package";
const invalidQuery = "Invalid OAuth callback query";
const invalidCookie = "Failed to decrypt OAuth proxy state cookie:";
const noCode = "OAuth callback missing authorization code";
const mismatch = "OAuth proxy state binding mismatch";
const log = (level, message, argument) => ({ level, message, ...(argument ? { argument } : {}) });
const returned = (keys = 0, logs = []) => ({ kind: "returned", keys, logs });
const redirected = (error = "no_code", logs = [log("warn", noCode)], provider = []) => ({ kind: "redirect", error, keys: 2, logs, provider });
const thrown = (kind, keys = 0) => ({ kind, keys, logs: [] });

export const callbackMessages = { debug, invalidPackage, invalidQuery, invalidCookie, noCode, mismatch };

export function callbackCases() {
  const cases = [];
  const add = (name, input, expected, extra = {}) => cases.push({ name, input, expected, ...extra });
  for (const [label, value] of [["undefined", undefined], ["null", null], ["false", false], ["number", 7], ["string", "text"], ["array", []]]) {
    add(`native-root-${label}`, "root", returned(), { value });
  }
  for (const method of ["GET", "POST"]) add(`native-body-${method.toLowerCase()}-without-request`, "body", redirected(), { method });
  add("query-state-wins-over-invalid-body-state", "query-wins", redirected());
  for (const [label, value] of [["undefined", undefined], ["null", null]]) {
    add(`nullish-query-state-${label}-uses-body`, "query-state", redirected(), { value });
    add(`nullish-query-error-${label}-uses-body`, "query-error", redirected("body-error", []), { value });
  }
  for (const [label, value] of [["false", false], ["zero", 0], ["nan", NaN], ["empty", ""], ["object", {}], ["array", []], ["date", new Date(NaN)], ["symbol", Symbol("state")]]) {
    add(`query-state-${label}-does-not-use-body`, "query-state", returned(), { value, ...(label === "symbol" ? { scope: "embedding-only" } : {}) });
  }
  add("query-error-wins", "query-error", redirected("query-error", []), { value: "query-error" });
  add("empty-query-error-suppresses-body-error", "query-error", redirected("no_code"), { value: "" });
  add("empty-query-code-suppresses-body-code", "empty-code", redirected());
  add("nullish-callback-fields-use-body", "nullish-fields", redirected("body-error", []));
  add("native-input-getters-and-identity", "getters", redirected("body-error", []), {
    getters: ["query.state", "query.code", "query.child", "body.state", "body.error", "body.child"],
  });
  for (const key of ["query.state", "query.unread", "body.state", "body.unread"]) {
    const getters = key === "query.state" ? [key] : key === "query.unread" ? ["query.state", key]
      : key === "body.state" ? ["query.state", key] : ["query.state", "body.state", key];
    add(`getter-throws-${key.replaceAll(".", "-")}`, "getter-error", thrown("original-error"), { throwGetter: key, getters });
  }
  add("body-getter-throws-before-falsy-state-guard", "getter-before-guard", thrown("original-error"), { getters: ["body.unread"] });
  add("query-symbol-getter-is-read-before-symbol-is-dropped", "query-symbol", thrown("original-error"), { scope: "embedding-only", getters: ["query.symbol"] });
  add("body-symbol-getter-is-read", "body-symbol", thrown("original-error"), { scope: "embedding-only", getters: ["body.symbol"] });
  add("query-own-proto-value-becomes-inherited-default", "query-proto", redirected(), { scope: "embedding-only" });
  add("body-own-proto-value-is-visible-to-state-read", "body-proto", redirected(), { scope: "embedding-only" });
  add("malformed-cipher-before-invalid-query", "outer-cipher", returned(1, [log("debug", debug)]));
  add("first-key-getter-error-is-caught", "key-error", returned(1, [log("debug", debug)]), { keyFailure: 1 });
  for (const plaintext of ["not JSON", '{"constructor":{}}', '{"__proto__":{}}']) {
    add(`outer-parse-rejection-${cases.length}`, "outer-plaintext", returned(1, [log("debug", debug)]), { plaintext });
  }
  for (const plaintext of ["null", "undefined"]) add(`outer-nullish-${plaintext}`, "outer-plaintext", thrown("type-error", 1), { plaintext });
  for (const plaintext of ["false", "0", "NaN", "Infinity", '""', '"text"', "[]", "{}", '"2030-01-02T03:04:05.000Z"']) {
    add(`outer-primitive-${cases.length}`, "outer-plaintext", returned(1, [log("warn", invalidPackage)]), { plaintext });
  }
  for (const field of ["isOAuthProxy", "state", "stateCookie"]) {
    for (const [label, value] of [["missing", undefined], ["null", null], ["false", false], ["zero", 0], ["empty", ""]]) {
      add(`package-${field}-${label}`, "package-field", returned(1, [log("warn", invalidPackage)]), { field, value });
    }
  }
  for (const field of ["isOAuthProxy", "state"]) {
    for (const [label, value] of [["number", 7], ["string", "truthy"], ["array", []], ["object", {}]]) {
      add(`package-${field}-truthy-${label}`, "package-field", redirected(), { field, value, unbound: true });
    }
  }
  for (const [label, value] of [["number", 7], ["boolean", true], ["array", []], ["object", {}], ["string", "invalid-ciphertext"]]) {
    add(`state-cookie-truthy-${label}-reaches-decrypt`, "package-field", returned(2, [log("error", invalidCookie, "error")]), { field: "stateCookie", value });
  }
  add("invalid-query-precedes-invalid-cookie", "invalid-query", returned(1, [log("warn", invalidQuery, "issues")]), {
    invalidCookie: true, invalidFields: { code: 7, error: null, user: [] },
    issues: [
      { expected: "string", code: "invalid_type", path: ["code"], message: "Invalid input: expected string, received number" },
      { expected: "string", code: "invalid_type", path: ["error"], message: "Invalid input: expected string, received null" },
      { expected: "string", code: "invalid_type", path: ["user"], message: "Invalid input: expected string, received array" },
    ],
  });
  add("second-key-getter-error-is-logged-by-identity", "key-error", returned(2, [log("error", invalidCookie, "original-error")]), { keyFailure: 2 });
  for (const plaintext of ["not JSON", '{"constructor":{}}', '{"__proto__":{}}']) {
    add(`cookie-parse-rejection-${cases.length}`, "cookie-plaintext", returned(2, [log("error", invalidCookie, "error")]), { plaintext });
  }
  for (const plaintext of ["null", "undefined"]) add(`cookie-nullish-${plaintext}`, "cookie-plaintext", thrown("type-error", 2), { plaintext });
  for (const plaintext of ["false", "0", "NaN", "Infinity", '"text"', "[]", "{}", '"2030-01-02T03:04:05.000Z"']) {
    add(`cookie-primitive-${cases.length}`, "cookie-plaintext", redirected(), { plaintext, defaultError: true });
  }
  add("state-binding-mismatch-precedes-provider-error", "binding-mismatch", redirected("state_mismatch", [log("error", mismatch)]));
  add("numeric-state-binding-retains-type", "binding-numeric", redirected());
  add("numeric-state-binding-rejects-string", "binding-string", redirected("state_mismatch", [log("error", mismatch)]));
  add("separate-object-state-bindings-are-not-identical", "binding-object", redirected("state_mismatch", [log("error", mismatch)]));
  add("provider-error-precedes-missing-code", "provider-error", redirected("access_denied", []));
  add("missing-provider-is-reached-after-state-cookie", "provider-missing", redirected("oauth_provider_not_found", [log("warn", "OAuth provider not found", "provider-id")]));
  add("missing-state-data-fields-reach-provider", "provider", redirected("invalid_code", [], ["validate"]), { emptyState: true });
  add("parseJSON-revives-code-verifier-date", "provider", redirected("invalid_code", [], ["validate"]), { verifierDate: true });
  add("provider-validation-error-is-logged-by-identity", "provider", redirected("invalid_code", [log("error", "Failed to validate authorization code", "original-error")], ["validate"]), { providerMode: "validate-throws" });
  add("provider-user-error-escapes-by-identity", "provider", { ...thrown("original-error", 2), provider: ["validate", "user"] }, { providerMode: "user-throws" });
  add("invalid-user-json-becomes-undefined", "provider", redirected("unable_to_get_user_info", [log("error", "Unable to get user info from provider")], ["validate", "user"]), { providerMode: "no-user", invalidUser: true });
  return cases;
}
