import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createLogger } from "@better-auth/core/env";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { withClock } from "./email-verification-duration-capture.mjs";

const version = JSON.parse(readFileSync(new URL("../node_modules/@better-auth/core/package.json", import.meta.url), "utf8")).version;
assert.equal(version, "1.7.6");

export async function captureLoggerLiveOptions(name) {
  const events = [];
  const argument = { value: "retained" };
  const cause = new Error("original logger failure");
  const beforeCause = Object.getOwnPropertyDescriptors(cause);
  let original;
  let replacement;
  const sink = owner => function (level, message, ...args) {
    assert.equal(args[0], argument);
    events.push(["sink", owner, level, message, args,
      this === original ? "original" : this === replacement ? "replacement" : "other"]);
  };
  original = { level: "error", disableColors: true, log: sink("first") };
  replacement = { level: "error", disableColors: true, log: sink("replacement") };
  const invoke = (logger, message, level = "error") => logger[level](message, argument);
  const caught = async (stage, operation) => {
    let thrown;
    try { await operation(); } catch (error) { thrown = error; }
    assert.equal(thrown, cause);
    events.push(["throw", stage, thrown === cause]);
    assert.deepEqual(Object.getOwnPropertyDescriptors(cause), beforeCause);
  };
  const savedConsole = { error: console.error, warn: console.warn, log: console.log };
  for (const method of Object.keys(savedConsole)) {
    console[method] = (...args) => {
      assert.equal(args[1], argument);
      events.push(["console", method, ...args]);
    };
  }
  try {
    return await withClock(async setClock => {
      setClock(2_000_000_000_123);
      if (name.startsWith("plugin-")) {
        let retained;
        const database = { user: [], session: [], account: [], verification: [] };
        const auth = betterAuth({
          baseURL: "https://logger-live-options.test",
          secret: "logger-live-options-contract-secret-at-least-thirty-two-characters",
          database: memoryAdapter(database), logger: original, telemetry: { enabled: false },
          plugins: [{ id: "logger-live-options", init(context) {
            retained = context;
            assert.equal(context.options.logger, original);
            invoke(context.logger, "before");
            if (name === "plugin-replace-log") context.options.logger.log = sink("second");
            else if (name === "plugin-delete-log") delete context.options.logger.log;
            else if (name === "plugin-replace-logger") context.options.logger = replacement;
            else if (name === "plugin-replace-options" || name === "plugin-throw-after-replacement") {
              context.options = { ...context.options, logger: replacement };
            } else if (name === "plugin-throw-sink") {
              context.options.logger.log = function (...args) {
                sink("throwing").apply(this, args);
                throw cause;
              };
            } else assert.fail(`Unknown plugin scenario ${name}`);
            if (name === "plugin-throw-after-replacement") throw cause;
            invoke(context.logger, "during");
          } }],
        });
        if (name === "plugin-throw-sink" || name === "plugin-throw-after-replacement") {
          await caught("initialization", () => auth.$context);
          original.log = sink("after-failure");
          invoke(retained.logger, "after failure");
        } else {
          const context = await auth.$context;
          assert.equal(context.logger, retained.logger);
          invoke(context.logger, "after");
        }
        assert.deepEqual(database, { user: [], session: [], account: [], verification: [] });
        return { name, version, events, level: retained.logger.level, database };
      }

      if (name === "freeze-enabled") original.disabled = true;
      if (name === "freeze-colors") original.disableColors = false;
      const logger = createLogger(original);
      invoke(logger, "before");
      if (name === "replace-log") {
        original.log = sink("second");
        invoke(logger, "after");
      } else if (name === "delete-log") {
        delete original.log;
        invoke(logger, "after");
      } else if (name === "replace-logger" || name === "replace-options") {
        let options = { logger: original };
        if (name === "replace-logger") options.logger = replacement;
        else options = { logger: replacement };
        invoke(logger, "after replacement");
        original.log = sink("second");
        invoke(logger, "after original mutation");
        invoke(createLogger(options.logger), "new");
      } else if (name === "freeze-enabled") {
        original.disabled = false;
        original.log = sink("second");
        invoke(logger, "existing");
        invoke(createLogger(original), "new");
      } else if (name === "freeze-level") {
        original.level = "debug";
        original.log = sink("second");
        invoke(logger, "suppressed", "warn");
        invoke(logger, "existing");
        invoke(createLogger(original), "new", "warn");
      } else if (name === "freeze-colors") {
        original.disableColors = true;
        delete original.log;
        invoke(logger, "existing");
        invoke(createLogger(original), "new");
      } else if (name === "throw-sink") {
        original.log = function (...args) {
          sink("throwing").apply(this, args);
          throw cause;
        };
        await caught("log", () => invoke(logger, "throwing"));
        original.log = sink("after-failure");
        invoke(logger, "after failure");
      } else assert.fail(`Unknown logger scenario ${name}`);
      return { name, version, events, level: logger.level };
    });
  } finally {
    Object.assign(console, savedConsole);
  }
}

if (import.meta.main) {
  process.stdout.write(`${JSON.stringify(await captureLoggerLiveOptions(process.argv[2]))}\n`);
}
