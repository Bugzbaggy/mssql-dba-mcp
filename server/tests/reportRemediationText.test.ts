/**
 * Remediation-text defects found by validating weekly reports against live instances.
 *
 * Every one of these passed tsc and the existing suite, because each was wrong in the TEXT the
 * report emits - the part a DBA copies into SSMS - not in the logic that grades. So these tests
 * assert on rendered remediation and details, using the row shapes the checks really return.
 *
 *   1. ERRORLOG fix: 'Software\Microsoft\...' in a TS string lost every backslash -> the emitted
 *      xp_instance_regwrite named 'SoftwareMicrosoftMSSQLServerMSSQLServer', not the instance's
 *      MSSQLServer key, so it could never set NumErrorLogs.
 *   2. ERRORLOG fix: "del ...\ERRORLOG.1" - by ordinal. An instance that restarts after the report
 *      runs renumbers its archives, and ERRORLOG.1 can then be the most complete engine record of
 *      an outage.
 *   3. Alert coverage: the fix pointed at one node's alerts as the reference, but that node's alerts
 *      had zero delay, so every occurrence was a mail; the next reference had severities that notify
 *      nobody; and the script left @op = '<operator>' so it failed as pasted. The reference is now a
 *      shape: all ten alerts enabled, delayed 600 s and routed.
 *   4. CHECKDB fix: no snapshot-space warning - the obvious fix can put a terabyte-scale database's
 *      snapshot on a volume with tens of GB free. The first fix then sized it by database SIZE; the
 *      snapshot grows by pages written during the check, so it must be sized by write rate.
 *   5. Databases & state: a SUSPECT database got an AUTO_SHRINK lecture as "what this means".
 *   6. Per-database option hygiene / ERRORLOG file size: "no per-row summary rule".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { toFinding } from "../src/dbatools.js";

type F = { details?: string; remediation?: { summary: string; code?: string } };
const run = (label: string, command: string, data: unknown[], status = "fail"): F =>
  toFinding({ category: "x", label, command, priority: "High", status,
              rows: data.length, shown: data.length, capped: false, data } as never) as unknown as F;

test("1+2. ERRORLOG fix: real registry path, and files identified by size - never by ordinal", () => {
  // Synthetic: a large current log, a long-unrotated instance and one very large archive.
  // TotalMB is derived: 350 + 12,000 + under 1 MB of small archives.
  const f = run("ERRORLOG file size", "Invoke-DbaQuery", [{
    CurrentMB: 350, LargestMB: 12000, TotalMB: 12351, LargestFile: "ERRORLOG.1",
    LogDir: "D:\\MSSQL\\Log", DaysSinceRotation: 120,
  }]);
  const code = String(f.remediation?.code ?? "");
  assert.match(code, /N'Software\\Microsoft\\MSSQLServer\\MSSQLServer'/, "registry path must keep its backslashes");
  assert.doesNotMatch(code, /SoftwareMicrosoft/, "the eaten-backslash path must be gone");
  assert.doesNotMatch(code, /del "D:\\MSSQL\\Log\\ERRORLOG\.1"/,
    "must not tell anyone to delete a file by an ordinal that moves on every restart");
  assert.match(code, /IDENTIFY IT BY SIZE/);
  assert.match(code, /KEEP - recent; may hold incident evidence/, "recent archives must be protected in the query itself");
  assert.match(code, /BEFORE step 3/, "deleting must come before cycling, which renumbers");
});

test("3. Alert coverage: the reference shape (600 s, all routed), a runnable operator, the AG alerts - never a zero-delay node's", () => {
  const f = run("Agent alert coverage", "Invoke-DbaQuery", [{ Item: "NO ALERTS CONFIGURED", Detail: "msdb.dbo.sysalerts is empty" }]);
  const code = String(f.remediation?.code ?? ""), summary = String(f.remediation?.summary ?? "");
  assert.doesNotMatch(code, /@delay_between_responses = 60,/, "60 s is below the 600 s reference");
  assert.match(code, /@delay_between_responses = 600/);
  assert.doesNotMatch(code + summary, /region\d+-node\d+ (and region\d+-node\d+ )?(is|are) (the working reference|already correct)/,
    "a node whose alerts have no delay is the counter-example, not the reference");
  // A node where some severities notify nobody is not the reference either.
  assert.match(code, /Reference shape: severity 19-25 and 823\/824\/825 all present, enabled, delayed 600 s/);
  assert.doesNotMatch(code + summary, /Copy region\d+-node\d+'s definitions|Reference shape[^\n]*region\d+-node\d+/);
  assert.match(summary, /some severities notify nobody/);
  assert.match(code, /DECLARE @op sysname = N'[^'<>]+';/, "the pasted script must run without hand edits (a concrete operator, not a placeholder)");
  assert.match(code, /IF NOT EXISTS \(SELECT 1 FROM msdb\.dbo\.sysoperators WHERE name = @op\)/);
  assert.match(code, /\(35264\)/, "data movement SUSPENDED can fire many times with nobody told");
  assert.match(code, /\(1480\)/);
});

test("4. CHECKDB fix sizes the snapshot from the WRITE RATE before suggesting any DBCC", () => {
  const f = run("Last good CHECKDB", "Get-DbaLastGoodCheckDb", [
    { Database: "AppDb_Routing", LastGoodCheckDb: "2019-03-04T20:00:27Z", DaysSinceLastGoodCheckDb: 2700 },
  ]);
  const code = String(f.remediation?.code ?? ""), summary = String(f.remediation?.summary ?? "");
  const sizeAt = code.indexOf("SIZE IT FIRST"), dbccAt = code.indexOf("DBCC CHECKDB ([AppDb_Routing])");
  assert.ok(sizeAt > 0, "the sparse-file warning must be present");
  assert.ok(dbccAt > sizeAt, "and it must come BEFORE the first DBCC line");
  assert.match(code, /dm_os_enumerate_fixed_drives/, "with a query that shows the data volume's free space");
  // The snapshot grows by pages modified DURING the check, so database size is the wrong bound and
  // the headroom moves by the hour: a large, quiet database can have hundreds of hours of headroom
  // while a smaller, busy one on the same volume has little more than a day.
  assert.match(code, /dm_io_virtual_file_stats/, "the bound is measured from two write samples");
  assert.match(code, /hours_to_fill/);
  assert.doesNotMatch(code, /ORDER BY data_gb DESC/, "sizing by database size is the defect being fixed");
  // A backup's duration is only a floor for the check, not its duration.
  assert.doesNotMatch(code, /gives you its duration/);
  assert.match(code, /FLOOR for a PHYSICAL_ONLY check/);
  assert.match(summary, /GLOBAL primary/, "a DAG copy's boot page only moves when the global primary checks it");
});

test("5. Databases & state: a SUSPECT database leads the summary - not an AUTO_SHRINK lecture", () => {
  const f = run("Databases & state", "Get-DbaDatabase", [
    { Name: "AppDb_Routing", Status: "Suspect", AutoShrink: false, AutoClose: false },
    { Name: "AppDb_Data", Status: "Normal", AutoShrink: false, AutoClose: false },
  ]);
  const summary = String(f.remediation?.summary ?? "");
  assert.match(summary, /^A database that is not ONLINE is an availability fault/);
  assert.match(summary, /AppDb_Routing is Suspect/);
  assert.ok(summary.indexOf("AppDb_Routing") < summary.indexOf("AUTO_SHRINK"), "the state fault comes first");
  // A specific mechanism, not a generalisation: a database on an AG replica can go SUSPECT on
  // Error 3456 (redo) and a restart can bring it back ONLINE with no reseed.
  assert.match(summary, /SUSPECT on a redo failure \(Error 3456\) and come back ONLINE after a service restart, with no reseed/);
  assert.doesNotMatch(summary, /often not corrupt/);
  const unnamed = run("Databases & state", "Get-DbaDatabase", [{ Status: "Suspect", AutoShrink: false, AutoClose: false }]);
  assert.doesNotMatch(String(unnamed.remediation?.summary ?? ""), /\? is Suspect/, "an unnamed row is dropped, never printed as '?'");

  const clean = run("Databases & state", "Get-DbaDatabase", [{ Name: "DBA", Status: "Normal", AutoShrink: true, AutoClose: false }], "attention");
  assert.match(String(clean.remediation?.summary ?? ""), /^AUTO_SHRINK and AUTO_CLOSE/, "no state preamble when everything is online");
});

test("6. Per-database option hygiene and ERRORLOG file size say what they found", () => {
  // Synthetic: one writable finding, one read-only finding, and one informational-only row.
  const hyg = run("Per-database option hygiene", "Invoke-DbaQuery", [
    { DbName: "AppDb_Staging", Access: "READ_WRITE", Issues: "AUTO_SHRINK_ON", DataGB: 15.5 },
    { DbName: "AppDb_Data", Access: "READ_ONLY", Issues: "ASYNC_STATS_NO_LOW_PRIORITY,db_chaining(info)", DataGB: 420.0 },
    { DbName: "AppDb", Access: "READ_ONLY", Issues: "db_chaining(info)", DataGB: 4.4 },
  ]);
  const d = String(hyg.details ?? "");
  assert.doesNotMatch(d, /no per-row summary rule/);
  assert.match(d, /2 database\(s\) have an option to change/);
  assert.match(d, /\* AppDb_Staging: AUTO_SHRINK_ON - writable here/);
  assert.match(d, /\* AppDb_Data: ASYNC_STATS_NO_LOW_PRIORITY - READ-ONLY here, so fix it on the writable copy/);
  assert.doesNotMatch(d, /\* AppDb:/, "a by-design (info) option is not a finding");

  const el = run("ERRORLOG file size", "Invoke-DbaQuery", [{
    CurrentMB: 350, LargestMB: 12000, TotalMB: 12351, LargestFile: "ERRORLOG.1", LogDir: "D:\\MSSQL\\Log", DaysSinceRotation: 120,
  }]);
  const e = String(el.details ?? "");
  assert.doesNotMatch(e, /no per-row summary rule/);
  assert.match(e, /largest archive: 12,000 MB, named ERRORLOG\.1 when this ran - identify it by SIZE/);
  assert.match(e, /current ERRORLOG: 350 MB, last rotated 120 day\(s\) ago/);
});

test("no source string drops a backslash (the defect class behind 1, and two earlier ones)", () => {
  // The scanner exits non-zero with one line per identity escape; it is validated against known
  // positives (\M, a template \' in CHARINDEX) and negatives (valid escapes, regex \s) separately.
  const out = execFileSync(process.execPath, ["scripts/find-identity-escapes.mjs"], { encoding: "utf8" });
  assert.match(out, /^0 identity escape\(s\)/m, out);
});
