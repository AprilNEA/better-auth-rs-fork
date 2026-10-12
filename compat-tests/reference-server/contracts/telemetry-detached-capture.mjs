import assert from "node:assert/strict";
import { runWithEndpointContext, tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { createLogger } from "@better-auth/core/env";
import { createTelemetry } from "@better-auth/telemetry";
import { captureDetachedOwnership, settle } from "./detached-ownership-capture.mjs";

await captureDetachedOwnership(async ({ name, unhandled }) => {
  const [owner, timing] = name.split(":");
  assert.ok(["init", "publish", "metadata"].includes(owner));
  assert.ok(owner === "metadata" ? timing === "sync" : ["ready", "pending"].includes(timing));
  const transportFailure = new Error("telemetry transport failure");
  const loggerFailure = new Error("telemetry logger failure");
  const metadataFailure = new Error("telemetry metadata failure");
  const gate = Promise.withResolvers();
  const started = Promise.withResolvers();
  const logs = [];
  const optionLogs = [];
  const tracks = [];
  const scopes = [];
  let transportTask;
  const scope = { context: { logger: createLogger({ level: "error", disableColors: true, log(...args) {
    logs.push(args);
    scopes.push(tryGetCurrentAuthEndpointContext());
    throw loggerFailure;
  } }) } };
  const options = {
    baseURL: "https://telemetry-detached.test", telemetry: { enabled: true },
    logger: { level: "error", log: (...args) => optionLogs.push(args) },
  };
  if (owner === "metadata") Object.defineProperty(options, "logger", { get() { throw metadataFailure; } });
  const context = { skipTestCheck: true, customTrack(event) {
    tracks.push(event);
    if (owner === "publish" && event.type === "init") return Promise.resolve();
    started.resolve();
    transportTask = (async () => {
      if (timing === "pending") await gate.promise;
      throw transportFailure;
    })();
    return transportTask;
  } };
  const initialized = await settle(() => runWithEndpointContext(scope, () => createTelemetry(options, context)));
  const payload = { value: "retained" };
  let published;
  if (owner === "metadata") {
    assert.equal(initialized.status, "rejected");
    assert.equal(initialized.reason, metadataFailure);
  } else {
    assert.equal(initialized.status, "fulfilled");
    assert.equal(typeof initialized.value.publish, "function");
    if (owner === "publish") {
      // Attach the caller's observer immediately; this publication has an owner.
      const result = settle(() => runWithEndpointContext(scope, () => initialized.value.publish({ type: "probe", payload })));
      await started.promise;
      if (timing === "pending") {
        assert.deepEqual(logs, []);
        assert.deepEqual(unhandled, []);
        gate.resolve();
      }
      published = await result;
      assert.equal(published.status, "rejected");
      assert.equal(published.reason, loggerFailure);
    } else if (timing === "pending") {
      assert.deepEqual(logs, []);
      assert.deepEqual(unhandled, []);
      gate.resolve();
    }
  }

  assert.equal(tryGetCurrentAuthEndpointContext(), undefined);
  return () => {
    assert.deepEqual(optionLogs, [], "The exported logger proxy must use the inherited endpoint scope");
    if (owner === "metadata") {
      assert.deepEqual(tracks, []);
      assert.deepEqual(logs, []);
      assert.deepEqual(scopes, []);
      assert.deepEqual(unhandled, []);
      return;
    }
    assert.deepEqual(tracks.map(event => event.type), owner === "init" ? ["init"] : ["init", "probe"]);
    assert.equal(typeof tracks[0].anonymousId, "string");
    assert.notEqual(tracks[0].anonymousId, "");
    if (owner === "publish") {
      assert.equal(tracks[1].payload, payload);
      assert.equal(tracks[1].anonymousId, tracks[0].anonymousId);
    }
    assert.deepEqual(logs, [["error", transportFailure]]);
    assert.equal(logs[0][1], transportFailure);
    assert.deepEqual(scopes, [scope]);
    assert.equal(scopes[0], scope);
    assert.equal(unhandled.length, owner === "init" ? 1 : 0);
    if (owner === "init") {
      assert.equal(unhandled[0].reason, loggerFailure);
      assert.notEqual(unhandled[0].promise, transportTask, "The source catch owns the transport rejection");
    }
  };
});
