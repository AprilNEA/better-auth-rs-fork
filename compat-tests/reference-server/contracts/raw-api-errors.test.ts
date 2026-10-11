import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("raw APIError contracts preserve live values, phase boundaries, and original failures", async () => {
  const runner = fileURLToPath(new URL("./raw-api-errors.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, "--no-install", runner], { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, status] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  expect({ status, stderr }).toStrictEqual({ status: 0, stderr: "" });
  expect(JSON.parse(stdout)).toStrictEqual({ version: "1.7.6", groups: [
    "phases", "classification", "status", "headers", "conversion", "constructors", "instances", "debug", "trace",
  ] });
}, 60_000);
