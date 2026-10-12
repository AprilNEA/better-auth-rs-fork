import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { nativeTokenCases } from "./oauth-native-token-cases.mjs";
import { writeObservation } from "./write-observation.mjs";
import { assertTokenReplay, tokenHostObservations } from "./oauth-native-token-replay.mjs";

const fixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/oauth-native-token-1.7.6.json", import.meta.url), "utf8"));
const processFixture = JSON.parse(readFileSync(new URL("../../../tests/fixtures/oauth-native-token-process-1.7.6.json", import.meta.url), "utf8"));

test("Generic OAuth retains native token input, expiry operations, errors, and result identity", async () => {
  const helper = new URL("./oauth-native-token-capture.mjs", import.meta.url).pathname;
  const result = Bun.spawnSync({
    cmd: [process.execPath, "--no-install", helper],
    env: { ...process.env, NO_COLOR: "1" }, stdout: "pipe", stderr: "pipe",
    maxBuffer: 16 * 1024 * 1024, timeout: 25_000,
  });
  await writeObservation(result.stdout);
  const processObservation = JSON.stringify({ contract: "oauth-native-token-process", exitCode: result.exitCode, signalCode: result.signalCode, stderr: result.stderr.toString() });
  await writeObservation(`${processObservation}\n`);
  expect(result.exitCode).toBe(0);
  expect(result.stderr.toString()).toBe("");
  expect(JSON.parse(processObservation)).toStrictEqual(processFixture);
  const observations = result.stdout.toString().trimEnd().split("\n").map(line => JSON.parse(line));
  const records = observations.filter(record => !Object.hasOwn(record, "contract"));
  const hosts = observations.filter(record => record.contract === "oauth-native-token-host");
  expect(observations.length).toBe(nativeTokenCases().length * 2);
  expect(records.map(record => record.name)).toStrictEqual(nativeTokenCases().map(scenario => scenario.name));
  expect(new Set(records.map(record => record.name)).size).toBe(records.length);
  expect(hosts.map(record => record.name)).toStrictEqual(records.map(record => record.name));
  expect(fixture.version).toBe("1.7.6");
  expect(fixture.cases.length).toBe(records.length);
  for (const [index, record] of records.entries()) {
    assertTokenReplay(record, fixture.cases[index]);
    expect(hosts[index].observations).toStrictEqual(tokenHostObservations(record));
    expect(record.version).toBe("1.7.6");
    expect(record.after.input).toStrictEqual(record.before.input);
    expect(record.logs).toStrictEqual([]);
    expect(record.database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  }
}, 30_000);
