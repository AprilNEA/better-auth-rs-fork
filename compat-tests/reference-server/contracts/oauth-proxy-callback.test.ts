import { expect, test } from "bun:test";
import { writeSync } from "node:fs";
import { callbackCases } from "./oauth-proxy-callback-cases.mjs";

const helper = new URL("./oauth-proxy-callback-capture.mjs", import.meta.url).pathname;

test("OAuth Proxy callback preserves native merge, parsing order, errors, and side effects", () => {
  const result = Bun.spawnSync({
    cmd: [process.execPath, "--no-install", helper],
    env: { ...process.env, NO_COLOR: "1" }, stdout: "pipe", stderr: "pipe",
  });
  writeSync(1, result.stdout);
  writeSync(1, `${JSON.stringify({ contract: "oauth-proxy-callback-process", exitCode: result.exitCode, signalCode: result.signalCode, stderr: result.stderr.toString() })}\n`);
  expect(result.exitCode).toBe(0);
  expect(result.stderr.toString()).toBe("");
  const records = result.stdout.toString().trimEnd().split("\n").map(line => JSON.parse(line));
  expect(records.map(record => record.name)).toStrictEqual(callbackCases().map(scenario => scenario.name));
  expect(new Set(records.map(record => record.name)).size).toBe(records.length);
  for (const record of records) {
    expect(record.version).toBe("1.7.6");
    expect(record.hasOriginalRequest).toBe(false);
    expect(record.inputs.after).toStrictEqual(record.inputs.before);
    expect(record.originalErrorUnchanged).toBe(true);
    expect(record.storeCalls).toStrictEqual([]);
    expect(record.database).toStrictEqual({ user: [], session: [], account: [], verification: [] });
  }
}, 30_000);
