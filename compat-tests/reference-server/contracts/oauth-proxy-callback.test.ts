import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { callbackCases } from "./oauth-proxy-callback-cases.mjs";
import { assertCallbackReplay } from "./oauth-proxy-callback-replay.mjs";
import { writeObservation } from "./write-observation.mjs";

const helper = new URL("./oauth-proxy-callback-capture.mjs", import.meta.url).pathname;
const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/oauth-proxy-callback-1.7.6.json", import.meta.url), "utf8"));
const processFixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/oauth-proxy-callback-process-1.7.6.json", import.meta.url), "utf8"));

test("OAuth Proxy callback preserves native merge, parsing order, errors, and side effects", async () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, "--no-install", helper],
    env: { ...process.env, NO_COLOR: "1" }, stdout: "pipe", stderr: "pipe",
    maxBuffer: 16 * 1024 * 1024, timeout: 25_000,
  });
  await writeObservation(result.stdout);
  const processObservation = JSON.stringify({ contract: "oauth-proxy-callback-process", exitCode: result.exitCode, signalCode: result.signalCode, stderr: result.stderr.toString() });
  await writeObservation(`${processObservation}\n`);
  expect(result.exitCode).toBe(0);
  expect(result.stderr.toString()).toBe("");
  expect(JSON.parse(processObservation)).toStrictEqual(processFixture);
  const observations = result.stdout.toString().trimEnd().split("\n").map(line => JSON.parse(line));
  const records = observations.filter(record => !Object.hasOwn(record, "contract"));
  const hosts = observations.filter(record => record.contract === "oauth-proxy-callback-host");
  const scenarios = callbackCases();
  expect(observations.length).toBe(scenarios.length * 2);
  expect(records.map(record => record.name)).toStrictEqual(scenarios.map(scenario => scenario.name));
  expect(hosts.map(record => record.name)).toStrictEqual(scenarios.map(scenario => scenario.name));
  expect(new Set(records.map(record => record.name)).size).toBe(records.length);
  expect(records.filter(record => record.globalLogs.length).map(record => record.name))
    .toStrictEqual(["invalid-user-json-becomes-undefined"]);
  expect(fixture.version).toBe("1.7.6");
  expect(fixture.cases.length).toBe(scenarios.length);
  for (const [index, record] of records.entries()) {
    assertCallbackReplay(record, fixture.cases[index], scenarios[index]);
    expect(record.version).toBe("1.7.6");
    expect(record.hasOriginalRequest).toBe(false);
    expect(record.inputs.after).toStrictEqual(record.inputs.before);
    expect(record.originalErrorUnchanged).toBe(true);
    expect(record.storeCalls).toStrictEqual([]);
    expect(record.database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  }
}, 30_000);

test("OAuth callback replay separates only Error host values and rejects lost observations", () => {
  const scenario = callbackCases()[0];
  const expected = structuredClone(fixture.cases[0]);
  expected.originalError.properties.detail.line = "business-value";
  const hostOnly = structuredClone(expected);
  hostOnly.originalError.properties.line += 1;
  hostOnly.originalError.stack = "Error: same error on another host";
  expect(() => assertCallbackReplay(hostOnly, expected, scenario)).not.toThrow();

  const changes = [
    record => { delete record.originalError.properties.line; },
    record => { record.originalError.properties.line = "wrong-type"; },
    record => { record.originalError.properties.detail.line = "changed-business-value"; },
    record => { delete record.originalError.properties.detail.ownUndefined; },
    record => { record.originalError.message = "changed error"; },
    record => { record.functions[0].source = "changed callback"; },
    record => { record.originalError.properties = Object.fromEntries(Object.entries(record.originalError.properties).reverse()); },
    record => { record.originalError.ownKeys.reverse(); },
  ];
  for (const change of changes) {
    const actual = structuredClone(expected);
    change(actual);
    expect(() => assertCallbackReplay(actual, expected, scenario)).toThrow();
  }
});
