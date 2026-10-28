import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CATALOG, DEFAULT_CONFORMANCE, parseConformanceBaseline, agPolicySql, replicaPolicySql, instanceConfigSql, agOnly,
} from "../src/dbatools.js";

// The conformance checks grade against OPINIONATED defaults (FAILURE_CONDITION_LEVEL 2,
// HEALTH_CHECK_TIMEOUT 60000, SESSION_TIMEOUT 60, cost threshold 50, ...). They are a stance, not
// universal truth, so one site setting overrides any of them. These tests pin the defaults, the
// merge and its validation, and - against a live SQL Server when one is configured - that an
// override really changes the grade.

const LABEL = "Instance configuration vs fleet standard";

test("the defaults are the documented opinionated baseline", () => {
  assert.deepEqual(DEFAULT_CONFORMANCE.ag, { DB_FAILOVER: "ON", FAILURE_CONDITION_LEVEL: 2, HEALTH_CHECK_TIMEOUT: 60000, AUTOMATED_BACKUP_PREFERENCE: "SECONDARY" });
  assert.deepEqual(DEFAULT_CONFORMANCE.replica, { SESSION_TIMEOUT: 60, SEEDING_MODE: "AUTOMATIC" });
  assert.equal(DEFAULT_CONFORMANCE.instance.find((r) => r.name === "cost threshold for parallelism")?.expected, 50);
  assert.equal(String(CATALOG.find((c) => c[1] === LABEL)?.[4]), instanceConfigSql(parseConformanceBaseline(process.env.HEALTHCHECK_CONFORMANCE_BASELINE)));
});

test("an override is merged over the defaults, and every value reaches the graded SQL", () => {
  const b = parseConformanceBaseline(JSON.stringify({
    ag: { FAILURE_CONDITION_LEVEL: 3, HEALTH_CHECK_TIMEOUT: 30000, DB_FAILOVER: "off", AUTOMATED_BACKUP_PREFERENCE: "primary" },
    replica: { SESSION_TIMEOUT: 10, SEEDING_MODE: "manual" },
    instance: { "cost threshold for parallelism": 25, "clr enabled": null, "max text repl size (B)": 65536, "max degree of parallelism": 4 },
  }));
  const ag = agPolicySql(b);
  assert.match(ag, /'FAILURE_CONDITION_LEVEL',CONVERT\(varchar\(20\),ag\.failure_condition_level\),'3',CASE WHEN ag\.failure_condition_level=3 THEN 0 ELSE 1 END/);
  assert.match(ag, /CASE WHEN ag\.health_check_timeout=30000 THEN 0 ELSE 1 END/);
  assert.match(ag, /'OFF',CASE WHEN ag\.db_failover=0 THEN 0 ELSE 2 END/);
  assert.match(ag, /automated_backup_preference_desc='PRIMARY' THEN 0/);
  assert.match(ag, /'Site baseline \(HEALTHCHECK_CONFORMANCE_BASELINE\)\.'/, "an overridden row says where its expectation came from");
  const rep = replicaPolicySql(b);
  assert.match(rep, /CASE WHEN ar\.session_timeout>=10 THEN 0/);
  assert.match(rep, /seeding_mode_desc='MANUAL' THEN 0/);
  const inst = instanceConfigSql(b);
  assert.match(inst, /\('cost threshold for parallelism','25',1,'Site baseline/);
  assert.doesNotMatch(inst, /'clr enabled'/, "null drops a setting from the check");
  assert.match(inst, /\('max text repl size \(B\)','65536',1,/, "a new name adds a setting");
  assert.match(inst, /<>4 $/, "a MAXDOP value replaces the box-sized rule");
  // Unchanged defaults keep their own explanation.
  assert.match(inst, /\('xp_cmdshell','0',2,'Shell execution/);
});

test("invalid override values are ignored and the defaults stand", () => {
  const b = parseConformanceBaseline(JSON.stringify({
    ag: { FAILURE_CONDITION_LEVEL: 9, HEALTH_CHECK_TIMEOUT: "fast", DB_FAILOVER: "maybe", NOT_A_SETTING: 1 },
    replica: { SESSION_TIMEOUT: 1 },
    instance: { "x'; DROP TABLE t; --": 0, "clr enabled": "off" },
  }));
  assert.deepEqual(b.ag, DEFAULT_CONFORMANCE.ag);
  assert.deepEqual(b.replica, DEFAULT_CONFORMANCE.replica);
  assert.equal(instanceConfigSql(b), instanceConfigSql(DEFAULT_CONFORMANCE));
  assert.deepEqual(parseConformanceBaseline("not json").ag, DEFAULT_CONFORMANCE.ag);
});

test("the AG-only checks report SKIPPED on an instance with no availability group", () => {
  const s = agOnly("SELECT 1 AS x");
  assert.match(s, /^IF NOT EXISTS \(SELECT 1 FROM sys\.availability_groups WHERE cluster_type_desc='wsfc'\) SELECT TOP \(1\) __hc_skip=/);
  assert.equal(String(CATALOG.find((c) => c[1] === "AG replica policy conformance")?.[4]), agOnly(replicaPolicySql(parseConformanceBaseline(process.env.HEALTHCHECK_CONFORMANCE_BASELINE))));
  assert.match(String(CATALOG.find((c) => c[1] === "AG role-change churn (24h)")?.[4]), /^IF NOT EXISTS \(SELECT 1 FROM sys\.availability_groups/);
});

// Live: needs a reachable SQL Server (SQLVAL_HOST/PORT/USER/PASS) and PowerShell for the real evaluator.
const live = !!(process.env.SQLVAL_USER && process.env.SQLVAL_PASS);
const shell = ["pwsh", "powershell"].find((s) => spawnSync(s, ["-NoProfile", "-Command", "exit 0"]).status === 0);
test("live: an override that matches the instance turns the grade from attention to pass", { skip: !(live && shell) && "set SQLVAL_* to a test SQL Server (and install PowerShell) to run" }, async () => {
  const { default: sql } = await import("mssql");
  const pool = await new sql.ConnectionPool({
    server: process.env.SQLVAL_HOST ?? "127.0.0.1", port: Number(process.env.SQLVAL_PORT ?? 1433),
    user: process.env.SQLVAL_USER, password: process.env.SQLVAL_PASS, database: "master",
    options: { encrypt: true, trustServerCertificate: true },
  }).connect();
  try {
    const actual = (await pool.request().query("SELECT name, CONVERT(bigint, value_in_use) AS v FROM sys.configurations")).recordset as Array<{ name: string; v: number }>;
    const val = (n: string) => Number(actual.find((r) => r.name === n)?.v);
    const evalPs = String(CATALOG.find((c) => c[1] === LABEL)?.[6]);
    const grade = (rows: unknown[]) => {
      // The check is in zeroRowsIsPass: zero rows proves it looked and found nothing.
      if (!rows.length) return "pass";
      const file = join(tmpdir(), `conformance-${process.pid}.json`);
      writeFileSync(file, JSON.stringify(rows));
      try {
        const r = spawnSync(shell!, ["-NoProfile", "-NonInteractive", "-Command",
          `$j = Get-Content -Raw '${file}'; $d = $j | ConvertFrom-Json; $d = @($d); ${evalPs}`], { encoding: "utf8" });
        assert.equal(r.status, 0, r.stderr);
        return r.stdout.trim();
      } finally { rmSync(file, { force: true }); }
    };
    const before = (await pool.request().query(instanceConfigSql(DEFAULT_CONFORMANCE))).recordset;
    const match = Object.fromEntries(DEFAULT_CONFORMANCE.instance.map((r) => [r.name, val(r.name)]));
    match["max degree of parallelism"] = val("max degree of parallelism");
    const after = (await pool.request().query(instanceConfigSql(parseConformanceBaseline(JSON.stringify({ instance: match }))))).recordset;
    assert.ok(before.length > 0, "a stock instance differs from the opinionated defaults (cost threshold 5, backup checksum 0, ...)");
    assert.notEqual(grade(before), "pass");
    assert.equal(after.length, 0, `expected no rows, got ${JSON.stringify(after)}`);
    assert.equal(grade(after), "pass");
  } finally { await pool.close(); }
});
