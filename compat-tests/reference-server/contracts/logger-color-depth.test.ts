import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const cases: Record<string, {
  inputs: Record<string, string>; expectedColors: boolean; expectedDepth?: number;
}> = JSON.parse(
  readFileSync(new URL("../../../tests/fixtures/logger-color-depth-cases-1.7.6.json", import.meta.url), "utf8"),
);
const inheritedDepths: Record<string, { type: string; reference: string }> = {
  "terminal-inherited-constructor": { type: "function", reference: "Object" },
  "terminal-inherited-prototype": { type: "object", reference: "Object.prototype" },
};
const moduleURL = import.meta.resolve("@better-auth/core/env");
const probe = `
  const { getColorDepth } = await import(${JSON.stringify(moduleURL)});
  const before = { ...process.env };
  const depth = getColorDepth();
  process.stdout.write(JSON.stringify({
    before,
    depth: typeof depth === "number" ? depth : {
      type: typeof depth,
      reference: depth === Object ? "Object" : depth === Object.prototype ? "Object.prototype" : null,
    },
    colors: depth !== 1,
    after: { ...process.env }, stdoutIsTTY: process.stdout.isTTY ?? null,
  }));
`;

for (const [name, { inputs, expectedColors, expectedDepth }] of Object.entries(cases)) {
  test(`logger color depth: ${name}`, () => {
    // Each child receives only fixture inputs so CI and terminal variables cannot leak between cases.
    const result = Bun.spawnSync({
      cmd: [process.execPath, "--no-install", "--eval", probe],
      env: inputs,
      stdout: "pipe",
      stderr: "pipe",
    });
    const observation = {
      case: "logger-color-depth", name, inputs, expectedColors, expectedDepth,
      exitCode: result.exitCode, signalCode: result.signalCode,
      stdout: result.stdout.toString(), stderr: result.stderr.toString(),
    };
    process.stdout.write(`${JSON.stringify(observation)}\n`);
    expect(observation.exitCode).toBe(0);
    expect(observation.stderr).toBe("");
    expect(JSON.parse(observation.stdout)).toStrictEqual({
      before: inputs, depth: expectedDepth ?? inheritedDepths[name], colors: expectedColors,
      after: inputs, stdoutIsTTY: null,
    });
  });
}

const transitions = [
  {
    name: "enabled-to-disabled", before: { FORCE_COLOR: "3" }, after: { NO_COLOR: "1" },
    beforeColors: true, afterColors: false,
  },
  {
    name: "disabled-to-enabled", before: { NO_COLOR: "1" }, after: { FORCE_COLOR: "3" },
    beforeColors: false, afterColors: true,
  },
];
const now = 2_000_000_000_123;
const timestamp = "2033-05-18T03:33:20.123Z";
const clockURL = new URL("./email-verification-duration-capture.mjs", import.meta.url).href;
const message = (value: string, colors: boolean) => colors
  ? `\x1b[2m${timestamp}\x1b[0m \x1b[31mERROR\x1b[0m \x1b[1m[Better Auth]:\x1b[0m ${value}`
  : `${timestamp} ERROR [Better Auth]: ${value}`;

for (const transition of transitions) {
  for (const disableColors of [undefined, true, false]) {
    test(`logger color initialization: ${transition.name} disableColors=${disableColors ?? "omitted"}`, () => {
      const options = { level: "error", ...(disableColors === undefined ? {} : { disableColors }) };
      const snapshotProbe = `
        const { createLogger, getColorDepth, logger } = await import(${JSON.stringify(moduleURL)});
        const { withClock } = await import(${JSON.stringify(clockURL)});
        const options = ${JSON.stringify(options)};
        const before = { ...process.env };
        const beforeColors = getColorDepth() !== 1;
        const original = createLogger(options);
        const logs = [];
        let afterColors;
        const originalConsoleError = console.error;
        console.error = (...args) => logs.push(args);
        try {
          await withClock(async setClock => {
            setClock(${now});
            original.error("Existing before");
            logger.error("Default before");
            for (const key of Object.keys(process.env)) delete process.env[key];
            Object.assign(process.env, ${JSON.stringify(transition.after)});
            afterColors = getColorDepth() !== 1;
            original.error("Existing after");
            createLogger(options).error("New after");
            logger.error("Default after");
          });
        } finally {
          console.error = originalConsoleError;
        }
        process.stdout.write(JSON.stringify({
          options, before, beforeColors, after: { ...process.env }, afterColors, logs,
        }));
      `;
      const result = Bun.spawnSync({
        cmd: [process.execPath, "--no-install", "--eval", snapshotProbe],
        env: transition.before,
        stdout: "pipe",
        stderr: "pipe",
      });
      const observation = {
        case: "logger-color-initialization", name: transition.name, options,
        exitCode: result.exitCode, signalCode: result.signalCode,
        stdout: result.stdout.toString(), stderr: result.stderr.toString(),
      };
      process.stdout.write(`${JSON.stringify(observation)}\n`);
      expect(observation.exitCode).toBe(0);
      expect(observation.stderr).toBe("");
      const originalColors = disableColors === undefined ? transition.beforeColors : !disableColors;
      const newColors = disableColors === undefined ? transition.afterColors : !disableColors;
      expect(JSON.parse(observation.stdout)).toStrictEqual({
        options, before: transition.before, beforeColors: transition.beforeColors,
        after: transition.after, afterColors: transition.afterColors,
        logs: [
          [message("Existing before", originalColors)],
          [message("Default before", transition.beforeColors)],
          [message("Existing after", originalColors)],
          [message("New after", newColors)],
          [message("Default after", transition.beforeColors)],
        ],
      });
    });
  }
}
