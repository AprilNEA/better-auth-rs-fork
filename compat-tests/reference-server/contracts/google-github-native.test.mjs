import { expect, test } from "bun:test";
import { github, google } from "@better-auth/core/social-providers";

// Paired with google_github_native_tests.rs at the production getUserInfo boundary.
const base = {
  google: { sub: "google-native", name: "Before", email: "before@example.test", picture: "before.png", email_verified: true },
  github: { id: 42, login: "octocat", name: "Before", email: null, avatar_url: "before.png" },
};
const selectedEmails = [
  { email: "before@example.test", primary: "primary", verified: { original: true } },
  { email: "after@example.test", primary: false, verified: false },
];
const token = claims => `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`;

async function run(id, profile, emails = [], action = "observe", tokenOverride) {
  const state = {
    events: [], inputs: [], before: [], failed: false,
    shared: { marker: id, missing: undefined },
    failure: { code: "NATIVE_MAPPER_FAILURE", detail: { retry: false }, missing: undefined },
  };
  const original = globalThis.fetch;
  globalThis.fetch = Object.assign(async (input, init) => {
    const request = new Request(input, init);
    expect(id).toBe("github");
    expect(request.method).toBe("GET");
    expect(request.headers.get("authorization")).toBe("Bearer native-profile-token");
    expect(request.headers.get("user-agent")).toBe("better-auth");
    expect(["https://api.github.com/user", "https://api.github.com/user/emails"]).toContain(request.url);
    const emailRequest = request.url.endsWith("/emails");
    state.events.push(emailRequest ? "emails" : "profile");
    return Response.json(emailRequest ? emails : profile);
  }, original);
  try {
    const provider = { google, github }[id]({
      clientId: "client", clientSecret: "secret",
      mapProfileToUser: async raw => {
        state.events.push("mapper");
        state.inputs.push(raw);
        state.before.push({ ...raw });
        if (action === "throw") throw state.failure;
        if (action === "spread-throw") return {
          get extra() { state.events.push("spread:extra"); return state.shared; },
          get email() { state.events.push("spread:email"); throw state.failure; },
        };
        if (action === "mutate") {
          raw.name = id === "google" ? state.shared : 0;
          if (id === "github") raw.login = state.shared;
          raw.email = state.shared;
          raw[id === "google" ? "picture" : "avatar_url"] = undefined;
          if (id === "google") raw.email_verified = 0;
          raw.ownUndefined = undefined;
          return { mappedExtra: state.shared, mappedUndefined: undefined };
        }
        if (action === "overlay") return { name: undefined, email: null, image: state.shared, emailVerified: "mapped", extra: state.shared };
        return {};
      },
    });
    const tokens = tokenOverride ?? { accessToken: "native-profile-token", ...(id === "google" ? { idToken: token(profile) } : {}) };
    try { state.response = await provider.getUserInfo(tokens); }
    catch (error) { state.failed = true; state.error = error; }
    return state;
  } finally {
    globalThis.fetch = original;
  }
}

function expectResponse(actual, user, data) {
  expect(actual.failed).toBe(false);
  expect(actual.response).toStrictEqual({ user, data });
  expect(Object.keys(actual.response)).toStrictEqual(["user", "data"]);
  expect(Object.keys(actual.response.user)).toStrictEqual(Object.keys(user));
  expect(Object.keys(actual.response.data)).toStrictEqual(Object.keys(data));
  expect(actual.response.data).toBe(actual.inputs[0]);
}

for (const [label, fields] of [
  ["missing", {}],
  ["null", { name: null, email: null, picture: null, email_verified: null }],
  ["dynamic", { name: ["Native", 3], email: 17, picture: { url: "native.png" }, email_verified: "verified" }],
]) {
  test(`Google keeps ${label} claims without narrowing default fields`, async () => {
    const profile = { sub: "google-native", ...fields, extension: { kept: true } };
    const actual = await run("google", profile);
    expectResponse(actual, { name: fields.name, email: fields.email, image: fields.picture, emailVerified: fields.email_verified }, profile);
    expect(actual.events).toStrictEqual(["mapper"]);
    expect(actual.before).toStrictEqual([profile]);
    if (label === "missing") {
      for (const field of ["name", "email", "image", "emailVerified"]) {
        expect(Object.hasOwn(actual.response.user, field)).toBe(true);
        expect(actual.response.user[field]).toBeUndefined();
      }
    }
    if (label === "dynamic") {
      expect(actual.response.user.name).toBe(actual.response.data.name);
      expect(actual.response.user.image).toBe(actual.response.data.picture);
    }
  });
}

for (const tokens of [{ accessToken: "native-profile-token" }, ...[undefined, null, false, 0, ""].map(idToken => ({ accessToken: "native-profile-token", idToken }))]) {
  test(`Google skips HTTP and mapper for falsy idToken ${String(tokens.idToken)} own ${Object.hasOwn(tokens, "idToken")}`, async () => {
    const actual = await run("google", base.google, [], "throw", tokens);
    expect(actual.failed).toBe(false);
    expect(actual.response).toBeNull();
    expect(actual.events).toStrictEqual([]);
    expect(actual.inputs).toStrictEqual([]);
  });
}

for (const id of ["google", "github"]) {
  test(`${id} reads native mapper mutations and keeps the complete raw object`, async () => {
    const actual = await run(id, base[id], selectedEmails, "mutate");
    const data = { ...base[id], name: id === "google" ? actual.shared : 0, email: actual.shared,
      [id === "google" ? "picture" : "avatar_url"]: undefined,
      ...(id === "google" ? { email_verified: 0 } : { login: actual.shared }), ownUndefined: undefined };
    expectResponse(actual, { name: actual.shared, email: actual.shared, image: undefined,
      emailVerified: id === "google" ? 0 : { original: true }, mappedExtra: actual.shared, mappedUndefined: undefined }, data);
    expect(actual.events).toStrictEqual(id === "google" ? ["mapper"] : ["profile", "emails", "mapper"]);
    expect(actual.before).toStrictEqual([{ ...base[id], ...(id === "github" ? { email: "before@example.test" } : {}) }]);
    for (const field of ["name", "email", "mappedExtra"]) expect(actual.response.user[field]).toBe(actual.shared);
    expect(Object.hasOwn(actual.response.data, "ownUndefined")).toBe(true);
    actual.shared.marker = "after-return";
    expect(actual.response.user.name.marker).toBe("after-return");
    expect(actual.response.data.email.marker).toBe("after-return");
  });

  test(`${id} mapper spread replaces complete fields including own undefined and null`, async () => {
    const actual = await run(id, base[id], selectedEmails, "overlay");
    expectResponse(actual, { name: undefined, email: null, image: actual.shared, emailVerified: "mapped", extra: actual.shared },
      { ...base[id], ...(id === "github" ? { email: "before@example.test" } : {}) });
    expect(Object.hasOwn(actual.response.user, "name")).toBe(true);
    expect(actual.response.user.image).toBe(actual.shared);
    expect(actual.response.user.extra).toBe(actual.shared);
  });

  for (const action of ["throw", "spread-throw"]) {
    test(`${id} preserves the original ${action} value and stops at the failing callback`, async () => {
      const actual = await run(id, base[id], selectedEmails, action);
      expect(actual.failed).toBe(true);
      expect(actual.error).toBe(actual.failure);
      expect(actual.response).toBeUndefined();
      expect(actual.inputs).toHaveLength(1);
      expect(actual.inputs[0]).toStrictEqual({ ...base[id], ...(id === "github" ? { email: "before@example.test" } : {}) });
      expect(actual.events).toStrictEqual([...(id === "google" ? [] : ["profile", "emails"]), "mapper",
        ...(action === "spread-throw" ? ["spread:extra", "spread:email"] : [])]);
    });
  }
}

for (const [primary, verified, expected] of [
  ["primary", { checked: true }, { checked: true }], [[], [], []], [{}, "yes", "yes"],
  [2, 0, 0], [true, "", ""], [true, null, false], [true, undefined, false],
]) {
  test(`GitHub uses primary truthiness and preserves verified ${JSON.stringify(verified)}`, async () => {
    const profile = { ...base.github, email: 0 };
    const emails = [
      { email: "secondary@example.test", primary: 0, verified: false },
      { email: "primary@example.test", primary, ...(verified === undefined ? {} : { verified }) },
    ];
    const actual = await run("github", profile, emails);
    expectResponse(actual, { name: "Before", email: "primary@example.test", image: "before.png", emailVerified: expected },
      { ...profile, email: "primary@example.test" });
    expect(actual.events).toStrictEqual(["profile", "emails", "mapper"]);
    expect(actual.before).toStrictEqual([{ ...profile, email: "primary@example.test" }]);
  });
}

for (const [email, matched, expected] of [[17, 17, "verified"], [17, "17", false], [{ address: "same" }, { address: "same" }, false]]) {
  test(`GitHub retains native inline email and uses strict equality for ${JSON.stringify(email)} / ${JSON.stringify(matched)}`, async () => {
    const profile = { ...base.github, email };
    const actual = await run("github", profile, [{ email: matched, primary: true, verified: "verified" }]);
    expectResponse(actual, { name: "Before", email, image: "before.png", emailVerified: expected }, profile);
    expect(actual.response.user.email).toBe(actual.response.data.email);
    expect(actual.events).toStrictEqual(["profile", "emails", "mapper"]);
  });
}

for (const initial of [undefined, null, ""]) {
  test(`GitHub empty email list writes own undefined before mapper for ${String(initial)}`, async () => {
    const { email: _email, ...withoutEmail } = base.github;
    const profile = { ...withoutEmail, ...(initial === undefined ? {} : { email: initial }) };
    const actual = await run("github", profile);
    const data = { ...profile, email: undefined };
    expectResponse(actual, { name: "Before", email: undefined, image: "before.png", emailVerified: false }, data);
    expect(actual.before).toStrictEqual([data]);
    expect(Object.hasOwn(actual.before[0], "email")).toBe(true);
    expect(Object.hasOwn(actual.response.data, "email")).toBe(true);
    expect(Object.hasOwn(actual.response.user, "email")).toBe(true);
    expect(actual.events).toStrictEqual(["profile", "emails", "mapper"]);
  });
}
