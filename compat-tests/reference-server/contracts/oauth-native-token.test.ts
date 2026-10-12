import { expect, test } from "bun:test";
import { nativeTokenCases } from "./oauth-native-token-cases.mjs";
import { writeObservation } from "./write-observation.mjs";

test("Generic OAuth retains native token input, expiry operations, errors, and result identity", async () => {
  const helper = new URL("./oauth-native-token-capture.mjs", import.meta.url).pathname;
  const result = Bun.spawnSync({
    cmd: [process.execPath, "--no-install", helper],
    env: { ...process.env, NO_COLOR: "1" }, stdout: "pipe", stderr: "pipe",
    maxBuffer: 16 * 1024 * 1024, timeout: 25_000,
  });
  await writeObservation(result.stdout);
  await writeObservation(`${JSON.stringify({ contract: "oauth-native-token-process", exitCode: result.exitCode, signalCode: result.signalCode, stderr: result.stderr.toString() })}\n`);
  expect(result.exitCode).toBe(0);
  expect(result.stderr.toString()).toBe("");
  const records = result.stdout.toString().trimEnd().split("\n").map(line => JSON.parse(line));
  expect(records.map(record => record.name)).toStrictEqual(nativeTokenCases().map(scenario => scenario.name));
  expect(new Set(records.map(record => record.name)).size).toBe(records.length);
  for (const record of records) {
    expect(record.version).toBe("1.7.6");
    expect(record.after.input).toStrictEqual(record.before.input);
    expect(record.logs).toStrictEqual([]);
    expect(record.database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  }
}, 30_000);
