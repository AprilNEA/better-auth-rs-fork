import { expect, test } from "bun:test";
import { cloudflare, reddit, roblox, zoom } from "@better-auth/core/social-providers";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json" with { type: "json" };

const factories = { cloudflare, reddit, roblox, zoom };
const tokens = { accessToken: "native-default-profile-token" };

async function withProfile(id, mapper, inspect) {
  const input = fixture.providers[id];
  const original = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = Object.assign(async (url, init) => {
    const request = new Request(url, init);
    expect(request.url).toBe(input.userinfoEndpoint);
    expect(request.method).toBe("GET");
    expect(request.headers.get("authorization")).toBe(`Bearer ${tokens.accessToken}`);
    requests += 1;
    return Response.json(id === "cloudflare" ? { success: true, result: input.profile } : input.profile);
  }, original);
  try {
    const provider = factories[id]({ clientId: fixture.clientId, clientSecret: fixture.clientSecret, mapProfileToUser: mapper });
    const response = await provider.getUserInfo(tokens);
    expect(requests).toBe(1);
    await inspect(response, provider);
  } finally {
    globalThis.fetch = original;
  }
}

test("Cloudflare keeps the name computed before mapper and reads the mutated email afterward", async () => {
  const email = { address: "dynamic@cloudflare.test" };
  const events = [];
  let raw;
  await withProfile("cloudflare", async profile => {
    raw = profile;
    events.push("mapper");
    profile.first_name = "Mutated";
    profile.last_name = "Name";
    profile.email = email;
    return { emailVerified: "verified", nativeExtra: undefined };
  }, (response, provider) => {
    expect(events).toStrictEqual(["mapper"]);
    expect(response.user).toStrictEqual({ name: "Cloudflare Owner", email, emailVerified: "verified", nativeExtra: undefined });
    expect(Object.keys(response.user)).toStrictEqual(["name", "email", "emailVerified", "nativeExtra"]);
    expect(response.user.email).toBe(email);
    expect(response.data).toBe(raw);
    expect(response.data).toStrictEqual({ ...fixture.providers.cloudflare.profile, first_name: "Mutated", last_name: "Name", email });
    expect(provider.accountSubject({ profile: response.data, tokens })).toBe("cloudflare-owner");
  });
});

for (const id of ["roblox", "zoom"]) {
  test(`${id} consumes mutated native fields and shallow-copies the complete raw profile`, async () => {
    const shared = { marker: id, missing: undefined };
    const events = [];
    let raw;
    await withProfile(id, async profile => {
      raw = profile;
      events.push("mapper");
      profile[id === "roblox" ? "nickname" : "display_name"] = shared;
      profile[id === "roblox" ? "picture" : "pic_url"] = undefined;
      if (id === "zoom") {
        profile.email = shared;
        profile.verified = [];
      }
      profile.child = shared;
      profile.ownUndefined = undefined;
      return { mappedExtra: shared, mappedUndefined: undefined };
    }, (response, provider) => {
      expect(events).toStrictEqual(["mapper"]);
      expect(response.user).toStrictEqual({
        name: shared, image: undefined,
        email: id === "roblox" ? "1234567890@roblox.placeholder.invalid" : shared,
        emailVerified: id === "zoom", mappedExtra: shared, mappedUndefined: undefined,
      });
      expect(Object.keys(response.user)).toStrictEqual(["name", "image", "email", "emailVerified", "mappedExtra", "mappedUndefined"]);
      expect(response.user.name).toBe(shared);
      expect(response.user.mappedExtra).toBe(shared);
      expect(response.data).not.toBe(raw);
      expect(response.data).toStrictEqual(raw);
      expect(Object.keys(response.data)).toStrictEqual([...Object.keys(fixture.providers[id].profile), "child", "ownUndefined"]);
      expect(response.data.child).toBe(shared);
      expect(Object.hasOwn(response.data, "ownUndefined")).toBe(true);
      expect(response.data.ownUndefined).toBeUndefined();
      expect(provider.accountSubject({ profile: response.data, tokens })).toBe(id === "roblox" ? "1234567890" : "zoom-owner");
      raw.child.marker = "changed-after-copy";
      expect(response.data.child.marker).toBe("changed-after-copy");
    });
  });
}

test("Reddit reads mapper getters around spread and preserves the earlier email fallback", async () => {
  const shared = { marker: "reddit", missing: undefined };
  const events = [];
  let raw;
  let emailReads = 0;
  let verifiedReads = 0;
  await withProfile("reddit", async profile => {
    raw = profile;
    events.push("mapper");
    profile.id = "mutated-reddit";
    profile.name = shared;
    profile.icon_img = undefined;
    return {
      get email() {
        events.push(`email:${++emailReads}`);
        return emailReads === 1 ? "" : "spread@reddit.test";
      },
      get emailVerified() {
        events.push(`verified:${++verifiedReads}`);
        return verifiedReads === 1 ? shared : null;
      },
      nativeExtra: shared,
    };
  }, (response, provider) => {
    expect(events).toStrictEqual(["mapper", "email:1", "email:2", "verified:1", "verified:2"]);
    expect(response.user).toStrictEqual({ name: shared, image: undefined, email: "mutated-reddit@reddit.placeholder.invalid", emailVerified: false, nativeExtra: shared });
    expect(Object.keys(response.user)).toStrictEqual(["name", "image", "email", "emailVerified", "nativeExtra"]);
    expect(response.user.name).toBe(shared);
    expect(response.user.nativeExtra).toBe(shared);
    expect(response.data).toBe(raw);
    expect(response.data).toStrictEqual({ ...fixture.providers.reddit.profile, id: "mutated-reddit", name: shared, icon_img: undefined });
    expect(provider.accountSubject({ profile: response.data, tokens })).toBe("mutated-reddit");
  });
});
