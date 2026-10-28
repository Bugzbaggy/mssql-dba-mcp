import { test } from "node:test";
import assert from "node:assert/strict";

/*
 * Credential resolution moved from EAGER (at module load) to LAZY (first access of
 * cfg.user / cfg.password), because readOsCredential shells out to powershell.exe
 * synchronously and that ran before server.connect() — losing the MCP client's 30s
 * connect race on a machine where a bare process start costs ~10s.
 *
 * Moving a credential path is the riskiest edit in this server, so these pin the two
 * properties that must not have changed:
 *   1. the resolution CHAIN still produces the same values;
 *   2. the password is strictly LESS exposed than before, never more.
 *
 * No SQL_CRED_TARGET is set here, so nothing shells out — this exercises the getters and
 * the env fallback, which is the path a stdio install without an OS store already uses.
 */

const FLEET = JSON.stringify([
  { name: "t1", host: "h1", port: 1433, database: "AppCatalog" },
  { name: "t2", host: "h2", port: 1433, database: "AppDb", applicationIntent: "ReadWrite" },
]);

let loadSeq = 0;
async function loadWith(env: Record<string, string | undefined>) {
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  // Fresh module instance per case: the resolution chain is read at import time. A plain
  // counter, not the env — encoding JSON into the specifier puts %5C / %2F in a file URL,
  // which Node rejects on Windows.
  const mod = (await import(`../src/connectionManager.js?lazycreds=${++loadSeq}`)) as typeof import("../src/connectionManager.js");
  // initInstances() is what populates the instance map (index.ts calls it at startup); it is
  // also where a plaintext password in the fleet config is refused.
  mod.initInstances();
  return mod;
}

test("the env fallback chain still resolves through the lazy getters", async () => {
  const { listInstances } = await loadWith({
    INSTANCES: FLEET, INSTANCES_FILE: undefined, SQL_CRED_TARGET: undefined,
    SQL_USER: "svc_reader", SQL_PASSWORD: "p@ss-from-env",
  });
  const t1 = listInstances().find((i) => i.name === "t1");
  assert.ok(t1, "instance t1 must load");
  assert.equal(t1.user, "svc_reader", "user must still resolve from SQL_USER");
  assert.equal(t1.password, "p@ss-from-env", "password must still resolve from SQL_PASSWORD");
});

test("a getter is stable across reads (memoised chain, no drift)", async () => {
  const { listInstances } = await loadWith({
    INSTANCES: FLEET, INSTANCES_FILE: undefined, SQL_CRED_TARGET: undefined,
    SQL_USER: "svc_reader", SQL_PASSWORD: "p@ss-from-env",
  });
  const t1 = listInstances().find((i) => i.name === "t1")!;
  assert.equal(t1.password, t1.password);
  assert.equal(t1.user, t1.user);
});

test("the password is NOT enumerable — it cannot leak via spread or JSON.stringify", async () => {
  const { listInstances } = await loadWith({
    INSTANCES: FLEET, INSTANCES_FILE: undefined, SQL_CRED_TARGET: undefined,
    SQL_USER: "svc_reader", SQL_PASSWORD: "p@ss-from-env",
  });
  const t1 = listInstances().find((i) => i.name === "t1")!;

  assert.ok(!Object.keys(t1).includes("password"), "password must not be an own enumerable key");
  assert.ok(!JSON.stringify(t1).includes("p@ss-from-env"), "password must not survive JSON.stringify");
  assert.ok(!JSON.stringify({ ...t1 }).includes("p@ss-from-env"), "password must not survive a spread");
  // ...but the one legitimate reader still gets it.
  assert.equal(t1.password, "p@ss-from-env", "explicit cfg.password access must still work");
});

test("defaults that normalize used to apply eagerly still apply", async () => {
  const { listInstances } = await loadWith({
    INSTANCES: FLEET, INSTANCES_FILE: undefined, SQL_CRED_TARGET: undefined,
    SQL_USER: "u", SQL_PASSWORD: "p",
  });
  const [t1, t2] = ["t1", "t2"].map((n) => listInstances().find((i) => i.name === n)!);
  assert.equal(t1.applicationIntent, "ReadOnly", "ReadOnly is the default and must stay eager");
  assert.equal(t2.applicationIntent, "ReadWrite", "an explicit intent must be preserved");
  assert.equal(t1.database, "AppCatalog", "non-credential fields must be untouched");
});

test("a plaintext password in the fleet file is STILL refused at load, not on first use", async () => {
  // This is the one check that must NOT have become lazy: a secret on disk has to be rejected
  // when the server starts, or it sits there until some query happens to touch that node.
  await assert.rejects(
    () => loadWith({
      INSTANCES: JSON.stringify([{ name: "bad", host: "h", port: 1433, password: "hunter2" }]),
      INSTANCES_FILE: undefined, SQL_CRED_TARGET: undefined, SQL_USER: "u", SQL_PASSWORD: "p",
    }),
    /password/i,
    "a literal password in the fleet config must still throw during load",
  );
});
