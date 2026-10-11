import { expect, test } from "bun:test";
import { cloudflare, huggingface, kick, linear, notion } from "@better-auth/core/social-providers";
import { runWithEndpointContext } from "@better-auth/core/context";
import { createLogger } from "@better-auth/core/env";
import { once } from "node:events";
import { createServer } from "node:net";
import fixture from "../../../tests/fixtures/social-http-providers-1.7.6.json" with { type: "json" };

const factories = { cloudflare, huggingface, kick, linear, notion };
const tokens = { accessToken: "ordinary-access" };

async function run(id, body, { status = 200, statusText = "OK", contentType = "application/json", failure } = {}) {
  const events = [];
  const inputs = [];
  const logs = [];
  const sockets = new Set();
  let serverFailure;
  const server = createServer(socket => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.once("error", error => { serverFailure ??= error; });
    let bytes = Buffer.alloc(0);
    socket.on("data", function receive(chunk) {
      try {
        bytes = Buffer.concat([bytes, chunk]);
        const end = bytes.indexOf("\r\n\r\n");
        if (end === -1) return;
        const [start, ...lines] = bytes.subarray(0, end).toString().split("\r\n");
        const [method, target] = start.split(" ");
        const headers = new Headers(lines.map(line => {
          const colon = line.indexOf(":");
          return [line.slice(0, colon), line.slice(colon + 1).trim()];
        }));
        const length = Number(headers.get("content-length") ?? 0);
        if (bytes.length < end + 4 + length) return;
        socket.removeListener("data", receive);
        expect(new URL(target, "http://127.0.0.1").pathname).toBe("/profile");
        expect(method).toBe(id === "linear" ? "POST" : "GET");
        expect(headers.get("authorization")).toBe("Bearer ordinary-access");
        if (id === "linear") {
          const posted = JSON.parse(bytes.subarray(end + 4, end + 4 + length).toString());
          expect(posted.query.replace(/\s+/g, " ").trim()).toBe(fixture.providers.linear.profileBody.query);
        }
        events.push("http");
        // Raw HTTP preserves the reason phrase that Bun.serve replaces with canonical text.
        socket.end(`HTTP/1.1 ${status} ${statusText}\r\nContent-Type: ${contentType}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      } catch (error) {
        serverFailure ??= error;
        socket.destroy();
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const profileURL = `http://127.0.0.1:${server.address().port}/profile`;
  const original = globalThis.fetch;
  globalThis.fetch = Object.assign((input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    expect(url).toBe(fixture.providers[id].userinfoEndpoint);
    return original(profileURL, init);
  }, original);
  try {
    const provider = factories[id]({
      clientId: fixture.clientId, clientSecret: fixture.clientSecret,
      mapProfileToUser: async profile => {
        events.push("mapper");
        inputs.push(profile);
        if (failure !== undefined) throw failure;
        return { marker: "mapped", optional: undefined };
      },
    });
    const logger = createLogger({ log: (level, message, ...arguments_) => logs.push([level, message, arguments_]) });
    let response;
    let error;
    await runWithEndpointContext({ context: { logger } }, async () => {
      try { response = await provider.getUserInfo(tokens); }
      catch (thrown) { error = thrown; }
    });
    if (serverFailure !== undefined) throw serverFailure;
    return { response, error, events, inputs, logs };
  } finally {
    globalThis.fetch = original;
    await new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      for (const socket of sockets) socket.destroy();
    });
  }
}

function expectResponse(actual, user, data) {
  expect(actual.error).toBeUndefined();
  expect(actual.response).toStrictEqual({ user, data });
  expect(Object.keys(actual.response)).toStrictEqual(["user", "data"]);
  expect(Object.keys(actual.response.user)).toStrictEqual(Object.keys(user));
}

for (const value of [false, 0, "", null]) {
  for (const id of ["cloudflare", "linear", "notion"]) {
    test(`${id} false wrapper value ${JSON.stringify(value)} skips mapping`, async () => {
      const body = id === "cloudflare" ? { success: true, result: value }
        : id === "linear" ? { data: { viewer: value } }
        : { bot: { owner: { user: value } } };
      const actual = await run(id, JSON.stringify(body));
      expect(actual.error).toBeUndefined();
      expect(actual.response).toBeNull();
      expect(actual.inputs).toStrictEqual([]);
      expect(actual.events).toStrictEqual(["http"]);
      expect(actual.logs).toStrictEqual(id === "cloudflare"
        ? [["error", "Failed to fetch user info from Cloudflare:", [undefined]]] : []);
    });
  }
}

for (const success of ["accepted", [], {}]) {
  test(`Cloudflare truthy success ${JSON.stringify(success)} retains the complete native result`, async () => {
    const profile = fixture.providers.cloudflare.profile;
    const actual = await run("cloudflare", JSON.stringify({ success, result: profile }));
    expectResponse(actual, {
      name: "Cloudflare Owner", email: profile.email, emailVerified: false, marker: "mapped", optional: undefined,
    }, profile);
    expect(actual.inputs).toStrictEqual([profile]);
    expect(actual.response.data).toBe(actual.inputs[0]);
    expect(actual.events).toStrictEqual(["http", "mapper"]);
    expect(actual.logs).toStrictEqual([]);
  });
}

test("Kick mapper(undefined) throws the original value before profile property access", async () => {
  const failure = { name: "MapperFailure", message: "original mapper failure", optional: undefined };
  const actual = await run("kick", '{"data":[]}', { failure });
  expect(actual.response).toBeUndefined();
  expect(actual.error).toBe(failure);
  expect(actual.inputs).toStrictEqual([undefined]);
  expect(actual.events).toStrictEqual(["http", "mapper"]);
  expect(actual.logs).toStrictEqual([]);
});

test("Kick retains the complete upstream native property error observation", async () => {
  const actual = await run("kick", '{"data":[]}');
  expect(actual.response).toBeUndefined();
  expect(actual.error).toBeInstanceOf(TypeError);
  expect(actual.error.name).toBe("TypeError");
  process.stdout.write(`${JSON.stringify({ case: "kick-undefined-read", runtime: "upstream", error: { name: actual.error.name, message: actual.error.message } })}\n`);
  expect(actual.inputs).toStrictEqual([undefined]);
  expect(actual.events).toStrictEqual(["http", "mapper"]);
  expect(actual.logs).toStrictEqual([]);
});

for (const [body, contentType] of [["{not-json", "application/json"], ["", "application/json"], ["plain profile", "text/plain"]]) {
  test(`Malformed JSON or text body ${JSON.stringify(body)} reaches the mapper`, async () => {
    const actual = await run("huggingface", body, { contentType });
    expectResponse(actual, {
      name: "", email: undefined, image: undefined, emailVerified: false, marker: "mapped", optional: undefined,
    }, body);
    expect(actual.inputs).toStrictEqual([body]);
    expect(actual.events).toStrictEqual(["http", "mapper"]);
    expect(actual.logs).toStrictEqual([]);
  });
}

test("HTTP JSON retains UTF16 values and date strings before mapping", async () => {
  const body = String.raw`{"sub":"utf16-owner","name":"\ud800","email":"owner@example.test","picture":null,"email_verified":true,"seenAt":"2025-01-01T00:00:00.000Z"}`;
  const actual = await run("huggingface", body);
  const expected = JSON.parse(body);
  expectResponse(actual, {
    name: "\ud800", email: "owner@example.test", image: null, emailVerified: true, marker: "mapped", optional: undefined,
  }, expected);
  expect(actual.inputs).toStrictEqual([expected]);
  expect(actual.response.data).toBe(actual.inputs[0]);
  expect(actual.events).toStrictEqual(["http", "mapper"]);
  expect(actual.logs).toStrictEqual([]);
});

test("Cloudflare HTTP failure logs the complete native error and actual status text", async () => {
  const body = String.raw`{"status":1,"statusText":"overwritten","detail":"\ud800","extra":null}`;
  const actual = await run("cloudflare", body, { status: 503, statusText: "Provider Unavailable" });
  expect(actual.error).toBeUndefined();
  expect(actual.response).toBeNull();
  expect(actual.inputs).toStrictEqual([]);
  expect(actual.events).toStrictEqual(["http"]);
  expect(actual.logs).toStrictEqual([["error", "Failed to fetch user info from Cloudflare:", [{
    status: 503, statusText: "Provider Unavailable", detail: "\ud800", extra: null,
  }]]]);
  expect(Object.keys(actual.logs[0][2][0])).toStrictEqual(["status", "statusText", "detail", "extra"]);
});
