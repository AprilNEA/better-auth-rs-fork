import { expect, test } from "bun:test";

const helper = new URL("./logger-live-options-capture.mjs", import.meta.url).pathname;
const argument = { value: "retained" };
const sink = (owner: string, message: string, level = "error", receiver = "original") =>
  ["sink", owner, level, message, [argument], receiver];
const formatted = (message: string, colors = false) => colors
  ? `\x1b[2m2033-05-18T03:33:20.123Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[1m[Better Auth]:\x1b[0m ${message}`
  : `2033-05-18T03:33:20.123Z ERROR [Better Auth]: ${message}`;
const consoleError = (message: string, colors = false) =>
  ["console", "error", formatted(message, colors), argument];
const before = sink("first", "before");
const cases: Record<string, unknown[][]> = {
  "replace-log": [before, sink("second", "after")],
  "delete-log": [before, consoleError("after")],
  "replace-logger": [before, sink("first", "after replacement"), sink("second", "after original mutation"), sink("replacement", "new", "error", "replacement")],
  "replace-options": [before, sink("first", "after replacement"), sink("second", "after original mutation"), sink("replacement", "new", "error", "replacement")],
  "freeze-enabled": [sink("second", "new")],
  "freeze-level": [before, sink("second", "existing"), sink("second", "new", "warn")],
  "freeze-colors": [before, consoleError("existing", true), consoleError("new")],
  "throw-sink": [before, sink("throwing", "throwing"), ["throw", "log", true], sink("after-failure", "after failure")],
  "plugin-replace-log": [before, sink("second", "during"), sink("second", "after")],
  "plugin-delete-log": [before, consoleError("during"), consoleError("after")],
  "plugin-replace-logger": [before, sink("first", "during"), sink("first", "after")],
  "plugin-replace-options": [before, sink("first", "during"), sink("first", "after")],
  "plugin-throw-sink": [before, sink("throwing", "during"), ["throw", "initialization", true], sink("after-failure", "after failure")],
  "plugin-throw-after-replacement": [before, ["throw", "initialization", true], sink("after-failure", "after failure")],
};

for (const [name, events] of Object.entries(cases)) {
  test(`logger retains live callback ownership and frozen policy: ${name}`, () => {
    // Each child owns its console and clock so source contracts cannot observe another case's mutations.
    const result = Bun.spawnSync({
      cmd: [process.execPath, "--no-install", helper, name],
      env: { NO_COLOR: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });
    const observation = {
      case: "logger-live-options", name, exitCode: result.exitCode,
      signalCode: result.signalCode, stdout: result.stdout.toString(), stderr: result.stderr.toString(),
    };
    process.stdout.write(`${JSON.stringify(observation)}\n`);
    expect(observation.exitCode).toBe(0);
    expect(observation.stderr).toBe("");
    expect(JSON.parse(observation.stdout)).toStrictEqual({
      name, version: "1.7.6", events, level: "error",
      ...(name.startsWith("plugin-") ? { database: { user: [], session: [], account: [], verification: [] } } : {}),
    });
  });
}
