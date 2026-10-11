import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { onRequestRateLimit } from "../node_modules/better-auth/dist/api/rate-limiter/index.mjs";
import { captureFreshServerCatalog } from "./server-catalog-shared.mjs";

const window = 600;
const maximum = 7;
const workers = 8;
const ip = "192.0.2.10";
const message = "Too many requests. Please try again later.";

async function call(context, label) {
  const started = Date.now();
  const response = await onRequestRateLimit(new Request(
    new URL(`/api/auth/ordinary-business-${label}`, context.baseURL),
    { headers: { "x-forwarded-for": ip } },
  ), context);
  const finished = Date.now();
  assert.ok(started <= finished);
  if (response === undefined) return { allowed: true, retryAfter: null, started, finished };
  assert.equal(response.status, 429);
  assert.equal(response.statusText, "Too Many Requests");
  const retryAfter = Number(response.headers.get("x-retry-after"));
  assert.ok(Number.isInteger(retryAfter));
  assert.deepEqual([...response.headers], [
    ["content-type", "text/plain;charset=utf-8"],
    ["x-retry-after", String(retryAfter)],
  ]);
  assert.equal(await response.text(), JSON.stringify({ message }));
  return { allowed: false, retryAfter, started, finished };
}

function checkRetry(result, row) {
  assert.equal(result.allowed, false);
  // pg retains BIGINT text. JavaScript concatenates that text before numeric subtraction.
  const expires = Number(row.lastRequest + window * 1000);
  const minimum = Math.ceil((expires - result.finished) / 1000);
  const maximum = Math.ceil((expires - result.started) / 1000);
  assert.ok(result.retryAfter >= minimum && result.retryAfter <= maximum,
    `retryAfter ${result.retryAfter} is outside [${minimum}, ${maximum}]`);
}

async function withWorkers({ options, query, backend }, check) {
  const namespaceSql = backend === "postgres" ? "SELECT current_schema() AS namespace" : "SELECT DATABASE() AS namespace";
  const [{ namespace }] = await query(namespaceSql);
  const pools = [];
  try {
    const contexts = [];
    for (let index = 0; index < workers; index++) {
      let pool;
      let observed;
      if (backend === "postgres") {
        const { Pool } = await import("pg");
        pool = new Pool({ connectionString: process.env.BETTER_AUTH_TEST_POSTGRES_URL,
          max: 1, options: `-c search_path=${namespace}` });
        pools.push(pool);
        observed = (await pool.query(namespaceSql)).rows;
      } else {
        const { createPool } = await import("mysql2/promise");
        const url = new URL(process.env.BETTER_AUTH_TEST_MYSQL_URL);
        url.pathname = `/${namespace}`;
        pool = createPool({ uri: url.href, connectionLimit: 1 });
        pools.push(pool);
        [observed] = await pool.query(namespaceSql);
      }
      assert.deepEqual(observed, [{ namespace }]);
      contexts.push(await betterAuth({ ...options, database: pool }).$context);
    }
    await check(contexts);
  } finally {
    await Promise.all(pools.map(pool => pool.end()));
  }
}

async function verifyBusiness(input) {
  const { options, query, backend } = input;
  const context = await betterAuth(options).$context;
  const quote = name => backend === "postgres" ? `"${name.replaceAll('"', '""')}"` : `\`${name.replaceAll("`", "``")}\``;
  const configuration = options.rateLimit;
  const table = quote(configuration.modelName || "rateLimit");
  const keyColumn = configuration.fields?.key || "key";
  const countColumn = configuration.fields?.count || "count";
  const timeColumn = configuration.fields?.lastRequest || "lastRequest";
  const key = label => `${ip}|/ordinary-business-${label}`;
  const parameter = index => backend === "postgres" ? `$${index}` : "?";
  const physical = label => query(`SELECT * FROM ${table} WHERE ${quote(keyColumn)} = ${parameter(1)}`, [key(label)]);

  async function snapshot(label, count, previousId, interval) {
    const rows = await context.adapter.findMany({ model: "rateLimit", where: [{ field: "key", value: key(label) }] });
    const raw = await physical(label);
    assert.equal(rows.length, 1);
    assert.equal(raw.length, 1);
    const row = rows[0];
    assert.deepEqual(Object.keys(row), ["key", "count", "lastRequest", "id"]);
    assert.deepEqual(Object.keys(raw[0]), ["id", keyColumn, countColumn, timeColumn]);
    assert.equal(typeof raw[0].id, "string");
    assert.ok(raw[0].id.length > 0);
    if (previousId !== undefined) assert.equal(raw[0].id, previousId);
    assert.equal(typeof raw[0][timeColumn], backend === "postgres" ? "string" : "number");
    const time = Number(raw[0][timeColumn]);
    assert.ok(Number.isSafeInteger(time));
    assert.equal(raw[0][timeColumn], backend === "postgres" ? String(time) : time);
    assert.deepEqual(raw[0], { id: row.id, [keyColumn]: key(label), [countColumn]: count, [timeColumn]: row.lastRequest });
    assert.deepEqual(row, { key: key(label), count, lastRequest: raw[0][timeColumn], id: raw[0].id });
    if (interval) assert.ok(interval.started <= time && time <= interval.finished);
    return { row, raw: raw[0] };
  }

  let before;
  for (let count = 1; count <= maximum; count++) {
    const result = await call(context, "sequential");
    assert.equal(result.allowed, true);
    assert.equal(result.retryAfter, null);
    before = await snapshot("sequential", count, before?.row.id, result);
  }
  const denied = await call(context, "sequential");
  checkRetry(denied, before.row);
  assert.deepEqual(await snapshot("sequential", maximum), before);

  assert.equal((await call(context, "stale")).allowed, true);
  await query(`UPDATE ${table} SET ${quote(timeColumn)} = 0 WHERE ${quote(keyColumn)} IN (${parameter(1)}, ${parameter(2)})`,
    [key("sequential"), key("stale")]);
  assert.equal(Number((await snapshot("sequential", maximum)).row.lastRequest), 0);
  assert.equal(Number((await snapshot("stale", 1)).row.lastRequest), 0);
  const reset = await call(context, "sequential");
  assert.equal(reset.allowed, true);
  assert.equal(reset.retryAfter, null);
  await snapshot("sequential", 1, before.row.id, reset);
  assert.deepEqual(await physical("stale"), []);
  assert.deepEqual(await context.adapter.findMany({ model: "rateLimit", where: [{ field: "key", value: key("stale") }] }), []);

  await withWorkers(input, async contexts => {
    for (const initial of [0, 1]) {
      const label = initial === 0 ? "concurrent-create" : "concurrent-increment";
      let existing;
      if (initial === 1) {
        const created = await call(context, label);
        assert.equal(created.allowed, true);
        existing = await snapshot(label, initial, undefined, created);
      } else {
        assert.deepEqual(await physical(label), []);
      }
      let release;
      const gate = new Promise(resolve => { release = resolve; });
      const pending = contexts.map(async worker => { await gate; return call(worker, label); });
      release();
      const results = await Promise.all(pending);
      assert.equal(results.length, workers);
      assert.equal(results.filter(result => result.allowed).length, maximum - initial);
      assert.equal(results.filter(result => !result.allowed).length, workers - maximum + initial);
      const final = await snapshot(label, maximum, existing?.row.id, {
        started: Math.min(...results.map(result => result.started)),
        finished: Math.max(...results.map(result => result.finished)),
      });
      for (const result of results) {
        if (result.allowed) assert.equal(result.retryAfter, null);
        else checkRetry(result, final.row);
      }
      checkRetry(await call(context, label), final.row);
      assert.deepEqual(await snapshot(label, maximum), final);
    }
  });
}

export async function verifyRateLimitServerBusiness(backend) {
  const version = JSON.parse(readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")).version;
  assert.equal(version, "1.7.6");
  const configurations = JSON.parse(readFileSync(new URL("../../schema-consumer/jwk-rate-limit-catalog-config.json", import.meta.url), "utf8"));
  for (const name of ["default", "custom"]) {
    const rateLimit = configurations[name].rateLimit;
    await captureFreshServerCatalog(backend, [rateLimit?.modelName || "rateLimit"], {
      rateLimit: { enabled: true, storage: "database", window, max: maximum, ...rateLimit },
      advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
    }, verifyBusiness);
  }
}
