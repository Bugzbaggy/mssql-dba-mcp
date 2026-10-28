/**
 * AUTO_UPDATE_STATISTICS_ASYNC in "Per-database option hygiene".
 *
 * A core database can have AUTO_UPDATE_STATISTICS_ASYNC = OFF while every other core database has
 * it ON, and the report must say so. The check used to READ the flag (column AsyncStats) but only
 * used it to grade the low-priority wait when async was ON - such a database came back as
 * "db_chaining(info)" only. Which databases are "core" is site data (HEALTHCHECK_CORE_DATABASES),
 * so the SQL is built from that list; unconfigured, nothing is probed or graded as core.
 *
 * Row shapes below are the check's output shape (synthetic values): the ASYNC_STATS_OFF rows are
 * what the SQL returns for a core database with the flag at 0.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, perDbHygieneSql, parseCoreDatabases } from "../src/dbatools.js";

const LABEL = "Per-database option hygiene";
const CORE = ["AppCatalog", "AppDb", "AppDb_Data", "AppDb_Analytics", "AppDb_Routing"];
const SQL = perDbHygieneSql(CORE);

function run(rows: Record<string, unknown>[], status = "attention") {
  return toFinding({ category: "Configuration", label: LABEL, command: "Invoke-DbaQuery", priority: "High",
    status, rows: rows.length, shown: rows.length, capped: false, data: rows } as Parameters<typeof toFinding>[0]);
}
const runnable = (code: string) => code.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("--"));

const PRE_FIX_PRIMARY = { DbName: "AppDb", DataGB: 4.5, Access: "READ_WRITE", Severity: "Attention",
  Issues: "ASYNC_STATS_OFF,db_chaining(info)", AsyncStats: 0, AsyncLowPri: "OFF" };      // writable copy
const PRE_FIX_SECONDARY = { ...PRE_FIX_PRIMARY, DataGB: 4.4, Access: "READ_ONLY" };      // read-only copy
const NOW_PRIMARY = { DbName: "AppDb", DataGB: 4.5, Access: "READ_WRITE", Severity: "Attention",
  Issues: "ASYNC_STATS_NO_LOW_PRIORITY,db_chaining(info)", AsyncStats: 1, AsyncLowPri: "OFF" }; // async ON, low-priority wait OFF

test("the SQL grades async OFF on the core databases - and only those", () => {
  assert.match(SQL, /CASE WHEN ASY=0 AND AU=1 AND CORE=1 THEN 1 ELSE 0 END AS AOFF/);
  assert.match(SQL, /d\.name IN \('AppCatalog','AppDb','AppDb_Data','AppDb_Analytics','AppDb_Routing'\) THEN 1 ELSE 0 END AS CORE/,
    "databases outside the core list (staging copies, DBA and the like) may be OFF on purpose and must not be graded");
  assert.match(SQL, /WHEN ASH=1 OR GAP=1 OR UNK=1 OR AOFF=1 OR \(TRW=1 AND OSA=1\) THEN 'Attention'/);
  assert.match(SQL, /CASE WHEN AOFF=1 THEN ',ASYNC_STATS_OFF' ELSE '' END/);
  assert.match(SQL, /OR GAP=1 OR UNK=1 OR AOFF=1 ORDER BY/, "an AOFF row must be returned, or nothing can grade it");
});

test("each configured core database is probed in its own bracketed three-part read", () => {
  assert.match(SQL, /IF @r0=1 SELECT @l0=CONVERT\(int,value\) FROM \[AppCatalog\]\.sys\.database_scoped_configurations WHERE configuration_id=29;/);
  assert.match(SQL, /CASE d\.name WHEN 'AppCatalog' THEN @l0 WHEN 'AppDb' THEN @l1 .* ELSE -2 END AS LP/);
  assert.match(SQL, /ASY=1 AND LP=0 AND DataGB>=100 THEN 1/, "the low-priority gap is graded by size alone");
  // The probe reads only databases this replica can open, so a non-readable secondary says 'unavailable'.
  assert.match(SQL, /WHERE d\.state_desc='ONLINE' AND d\.user_access=0 AND d\.is_in_standby=0/);
});

test("unconfigured: nothing is probed, nothing is core, and a large async database is UNPROBED, not passed", () => {
  const none = perDbHygieneSql([]);
  assert.doesNotMatch(none, /database_scoped_configurations/);
  assert.match(none, /-2 AS LP,/);
  assert.match(none, /0 AS CORE/);
  assert.match(none, /CASE WHEN ASY=1 AND DataGB>=100 AND LP<0 THEN 1 ELSE 0 END AS UNK/,
    "could not look must still surface as ASYNC_LOW_PRIORITY_UNPROBED");
  assert.ok(none.startsWith("WITH sz AS"), "with no probe block the batch starts at the CTE");
  // The shipped catalog entry is the configured form of the same builder.
  assert.equal(String(CATALOG.find((c) => c[1] === LABEL)?.[4]), perDbHygieneSql(parseCoreDatabases(process.env.HEALTHCHECK_CORE_DATABASES)));
});

test("HEALTHCHECK_CORE_DATABASES accepts database names only, de-duplicated", () => {
  assert.deepEqual(parseCoreDatabases(" AppDb, AppDb_Data ,AppDb,"), ["AppDb", "AppDb_Data"]);
  assert.deepEqual(parseCoreDatabases("x'; DROP TABLE t; --,[bad],ok_db"), ["ok_db"], "anything that could break out of a literal is dropped");
  assert.deepEqual(parseCoreDatabases(undefined), []);
});

test("details name the database and say where the fix has to run", () => {
  const d = run([PRE_FIX_PRIMARY, PRE_FIX_SECONDARY]).details;
  assert.match(d, /\* AppDb: ASYNC_STATS_OFF - writable here/);
  assert.match(d, /\* AppDb: ASYNC_STATS_OFF - READ-ONLY here, so fix it on the writable copy/);
  assert.doesNotMatch(d, /db_chaining/, "the by-design info token is not a finding");
});

test("remediation: before/after checks run, the ALTERs wait for a window, low priority goes with it", () => {
  const code = run([PRE_FIX_PRIMARY]).remediation?.code ?? "";
  const run_ = runnable(code);
  assert.ok(run_.includes("SELECT name, is_auto_update_stats_async_on FROM sys.databases WHERE name = 'AppDb';   -- before: expect 0"));
  assert.match(code, /^-- ALTER DATABASE \[AppDb\] SET AUTO_UPDATE_STATISTICS_ASYNC ON WITH NO_WAIT;$/m,
    "commented: it restarts the database's plan cache");
  assert.match(code, /^-- USE \[AppDb\];  ALTER DATABASE SCOPED CONFIGURATION SET ASYNC_STATS_UPDATE_WAIT_AT_LOW_PRIORITY = ON;$/m);
  assert.ok(!run_.some((l) => /^ALTER /i.test(l)), "no ALTER may be runnable in this branch");
  assert.match(code, /configuration_id = 29;   -- after: expect 1/);
});

test("a flagged row is never also listed as 'no action', and an async-only node is actionable", () => {
  const PURE_INFO = { DbName: "AppDb_Routing", DataGB: 1100.5, Access: "READ_ONLY", Severity: "Info", Issues: "db_chaining(info)", AsyncStats: 1, AsyncLowPri: "ON" };
  const f = run([PRE_FIX_PRIMARY, PURE_INFO]);
  const code = f.remediation?.code ?? "";
  const noAction = code.slice(code.indexOf("-- Informational rows on this node (no action):"));
  assert.match(noAction, /--    AppDb_Routing  db_chaining\(info\)/, "a row with only (info) tokens belongs here");
  assert.doesNotMatch(noAction, /AppDb\b/, "a row with ASYNC_STATS_OFF is a finding - it was listed here as 'no action'");
  assert.match(f.remediation?.summary ?? "", /generated from this node's rows/,
    "ASYNC_STATS_OFF must count as actionable, or the summary says there is nothing to do");
  assert.match(f.remediation?.summary ?? "", /ASYNC_STATS_OFF is AUTO_UPDATE_STATISTICS_ASYNC OFF on one of the core databases/);
});

test("a read-only copy gets no ALTER, only the pointer to the writable copy", () => {
  const code = run([PRE_FIX_SECONDARY]).remediation?.code ?? "";
  assert.doesNotMatch(code, /SET AUTO_UPDATE_STATISTICS_ASYNC ON/);
  assert.match(code, /AppDb/);
});

test("a large ASYNC_STATS_OFF database gets the fix on its writable copy and only a listing on its read-only copy", () => {
  // Synthetic: AUTO_UPDATE_STATISTICS_ASYNC OFF on both copies of a core database (one READ_ONLY, one READ_WRITE).
  const ST = { DbName: "AppDb_Analytics", DataGB: 180.25, Severity: "Attention", Issues: "ASYNC_STATS_OFF", AsyncStats: 0, AsyncLowPri: "OFF" };
  const rw = run([{ ...ST, Access: "READ_WRITE" }]).remediation?.code ?? "";
  assert.match(rw, /^-- ALTER DATABASE \[AppDb_Analytics\] SET AUTO_UPDATE_STATISTICS_ASYNC ON WITH NO_WAIT;$/m);
  assert.match(rw, /ASYNC_STATS_OFF - AUTO_UPDATE_STATISTICS_ASYNC is OFF on a core database/);
  assert.doesNotMatch(rw, /every copy of AppCatalog/, "a non-production copy can be OFF, so the script makes no estate-wide claim");
  const ro = run([{ ...ST, Access: "READ_ONLY" }]).remediation?.code ?? "";
  assert.doesNotMatch(ro, /SET AUTO_UPDATE_STATISTICS_ASYNC ON/);
  assert.match(ro, /--    AppDb_Analytics  \[READ_ONLY\]  ASYNC_STATS_OFF/);
});

test("an UNPROBED row is actionable on its own and never dropped on a read-only copy", () => {
  const UNP = { DbName: "BigNewDb", DataGB: 250, Severity: "Attention", Issues: "ASYNC_LOW_PRIORITY_UNPROBED", AsyncStats: 1, AsyncLowPri: "not-probed" };
  const rw = run([{ ...UNP, Access: "READ_WRITE" }]).remediation!;
  assert.match(rw.summary, /The fix script is generated from this node's rows/, "it was counted as 'nothing actionable'");
  assert.match(rw.code, /FROM \[BigNewDb\]\.sys\.database_scoped_configurations WHERE configuration_id = 29;/);
  assert.match(rw.code, /^-- USE \[BigNewDb\];  ALTER DATABASE SCOPED CONFIGURATION SET ASYNC_STATS_UPDATE_WAIT_AT_LOW_PRIORITY = ON;$/m,
    "the fix is inline: an 'ASYNC_STATS section above' may not exist in this script");
  const ro = run([{ ...UNP, Access: "READ_ONLY" }]).remediation!.code;
  assert.match(ro, /--    BigNewDb  \[READ_ONLY\]  ASYNC_LOW_PRIORITY_UNPROBED/, "it vanished from the script on a secondary");
});

test("the summary stands alone: no 'below', and the writable copy is named per database kind", () => {
  const s = run([PRE_FIX_PRIMARY]).remediation?.summary ?? "";
  assert.doesNotMatch(s, /script below|ONCE per region/);
  assert.match(s, /the global primary for a database carried by a distributed AG/);
  assert.match(s, /off-peak, because each change restarts that database's plan cache/);
  assert.match(s, /ASYNC_LOW_PRIORITY_UNPROBED means the check could not read that setting/);
});

test("a low-priority-only gap on AppDb reuses the existing fix, not a second copy", () => {
  const code = run([NOW_PRIMARY]).remediation?.code ?? "";
  assert.match(code, /ASYNC_STATS_NO_LOW_PRIORITY/);
  assert.match(code, /Graded on databases of 100 GB or more/);
  assert.equal((code.match(/SET ASYNC_STATS_UPDATE_WAIT_AT_LOW_PRIORITY = ON/g) ?? []).length, 1);
  assert.doesNotMatch(code, /ASYNC_STATS_OFF/, "async is ON - nothing to say about it");
});
