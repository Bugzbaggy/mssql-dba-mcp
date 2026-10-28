/**
 * Grading and advice defects found by validating weekly reports against live instances. Every row
 * shape below is what the check returns (read-only), trimmed to the columns that matter; the
 * values are synthetic.
 *
 *   1. Agent alert coverage looked at Database Mail XPs only. Agent's OWN mail settings
 *      (UseDatabaseMail + DatabaseMailProfile) decide whether an alert or a failed job reaches
 *      anyone: msdb can hold no Agent mail at all on a node whose Database Mail works, and a node
 *      can log "Failed to notify ... via email" for days without anyone noticing.
 *   2. ERRORLOG: the "largest archive" could be the CURRENT log, and the fix cycled before the
 *      NumErrorLogs regwrite with no linked-server sweep.
 *   3. Instance perf: Fail rested on a LIFETIME THREADPOOL average; a node was told to unpin a
 *      worker cap its AG partner depends on.
 *   4. AG replica policy: a routing URL "missing" on a DAG's secondary AG that nothing routes to.
 *   5. SQL Assessment graded "Error 17830 occured N times" High on most nodes.
 *   7. Storage I/O: a lifetime average graded Fail; an ungraded data-write figure printed beside it.
 *   9. Tooling drift: Expected said "2.7.2 or newer" while grading anything but 2.7.2.
 *  10. Index health: one money overflow turned a whole database into a coverage hole every week.
 *  11. Capacity symmetry: the same peer printed once per AG; the baseline's age was invisible.
 *  12. LOCK_ESCALATION: "no per-row summary rule".
 *  13. The weekly mail subject carried no counts.
 * (6 and 8 are covered in evaluatorGrading.test.ts and databaseOwners.test.ts.)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, buildHealthCheckScript, generateHtmlReport, scoreFindings, coverageOf, capacitySymmetrySql, parseCapacityBaseline } from "../src/dbatools.js";

type F = { details?: string; status?: string; remediation?: { summary: string; code?: string } };
const run = (label: string, data: unknown[], status = "attention", command = "Invoke-DbaQuery"): F =>
  toFinding({ category: "x", label, command, priority: "High", status,
              rows: data.length, shown: data.length, capped: false, data } as never) as unknown as F;
const entry = (label: string) => {
  const c = CATALOG.find((x) => x[1] === label);
  assert.ok(c, `no catalog entry labelled ${label}`);
  return { sql: String(c[4]), evalPs: String(c[6] ?? ""), cmd: c[2], target: c[3] };
};

test("1. Agent alert coverage reads Agent's own mail path, guarded so 'could not look' never reads as 'off'", () => {
  const { sql } = entry("Agent alert coverage");
  // The two values live in Agent's registry key; sys.dm_server_registry does not expose them.
  assert.match(sql, /xp_instance_regread N'HKEY_LOCAL_MACHINE',N'SOFTWARE\\Microsoft\\MSSQLServer\\SQLServerAgent',N'UseDatabaseMail'/);
  assert.match(sql, /N'DatabaseMailProfile'/);
  assert.match(sql, /IS_SRVROLEMEMBER\('sysadmin'\)<>1 SET @regOk=0/,
    "a non-sysadmin's regread can return NULL silently - test the role, do not infer it");
  for (const item of ["Agent mail not enabled", "Agent mail delivery failing", "Agent mail not verifiable"])
    assert.ok(sql.includes(`'${item}'`), `missing finding row: ${item}`);
  assert.match(sql, /sysmail_allitems WHERE subject LIKE N'SQL Server Job System:%'/);

  // Synthetic: alerts exist, but Agent itself cannot mail.
  const f = run("Agent alert coverage", [
    { Item: "Agent mail delivery failing", Detail: "3 job run(s) logged 'Failed to notify ... via email' in the last 7 days", Sev: 2, AlertsTotal: 12, OperatorsEnabled: 1 },
    { Item: "Agent mail not enabled", Detail: "UseDatabaseMail=(not set), profile=(none); 5 enabled job(s) e-mail on failure; Agent has never sent a mail here", Sev: 2, AlertsTotal: 12, OperatorsEnabled: 1 },
  ], "fail");
  assert.match(String(f.details), /SQL Agent itself is not set to send mail \(UseDatabaseMail=\(not set\)/);
  assert.match(String(f.details), /Agent mail delivery is failing: 3 job run/);
  const code = String(f.remediation?.code ?? "");
  assert.match(code, /EXEC msdb\.dbo\.sp_set_sqlagent_properties @use_databasemail = 1, @databasemail_profile = @profile;/);
  // msdb's own source (SQL 2022): the procedure ends with sp_sqlagent_notify @op_type = N'M', a reload.
  assert.match(code, /no restart is needed/, "the procedure makes Agent reload its mail settings");
  assert.match(code, /only\s*\n?.*if its mail never arrives, restart/, "a restart is the fallback, not the step");
  assert.ok(code.indexOf("0) SQL Agent's own mail path") < code.indexOf("1) What exists here now"), "the mail path is fixed first");
  // The throwaway self-test job stays commented: it creates and deletes a job on prod.
  for (const l of code.split("\n").filter((x) => /sp_add_job |sp_start_job|sp_delete_job/.test(x)))
    assert.ok(l.trim().startsWith("--"), `self-test job lines must stay commented: ${l.trim()}`);
  assert.match(code, /N'SOFTWARE\\Microsoft\\MSSQLServer\\SQLServerAgent'/, "the verify regread keeps its backslashes");

  // A Sev-0 "not verifiable" row (a non-sysadmin run where Agent HAS mailed before) is not a finding.
  const quiet = run("Agent alert coverage", [{ Item: "Agent mail not verifiable", Detail: "x", Sev: 0, AlertsTotal: 10, OperatorsEnabled: 2 }], "pass");
  assert.doesNotMatch(String(quiet.details ?? ""), /could not be read|not set to send mail/, "an ungraded row is not reported as a finding");
});

test("2. ERRORLOG: the current log is never the 'largest archive', and the fix sweeps before it cycles", () => {
  const { sql, evalPs } = entry("ERRORLOG file size");
  assert.match(sql, /LargestMB = ISNULL\(\(SELECT MAX\(mb\) FROM f WHERE name <> 'ERRORLOG'\), 0\)/);
  assert.match(sql, /LargestFile = ISNULL\(\(SELECT TOP 1 name FROM f WHERE name <> 'ERRORLOG' ORDER BY mb DESC\), ''\)/);
  assert.match(evalPs, /CurrentMB\)\" -ge 2048\) \{'fail'\}/, "a current log over 2 GB is a Fail in its own right");

  // Synthetic: a large current log, archives tiny.
  const f = run("ERRORLOG file size", [{ CurrentMB: 302.4, LargestMB: 0.4, TotalMB: 303.8, LargestFile: "ERRORLOG.3",
    LogDir: "D:\\MSSQL\\Log", DaysSinceRotation: 110 }]);
  const d = String(f.details);
  assert.match(d, /current ERRORLOG: 302 MB.*never delete the current log/);
  assert.doesNotMatch(d, /largest archive: 0 MB, named ERRORLOG\.3 when this ran - identify it by SIZE before deleting/,
    "a 0.4 MB archive gets no delete hint");
  const code = String(f.remediation?.code ?? "");
  const reg = code.indexOf("N'NumErrorLogs', REG_DWORD, 30"), sweep = code.indexOf("--       EXEC <your log-scanning procedure>;"),
    cyc = code.indexOf("EXEC sys.sp_cycle_errorlog;");
  assert.ok(reg > 0 && sweep > reg && cyc > sweep, `order must be regwrite -> sweep -> cycle (got ${reg}, ${sweep}, ${cyc})`);
  assert.ok(!code.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("--")).some((l) => /^EXEC (?!sys\.)/i.test(l)), "the only runnable EXECs are system procedures - no site-specific sweep is assumed");
});

test("3. Instance perf: Fail needs a LIVE THREADPOOL sample, and an AG replica keeps its pin", () => {
  const { sql } = entry("Instance performance settings (workers / parallelism / memory)");
  assert.match(sql, /WAITFOR DELAY '00:00:10'/);
  assert.match(sql, /work_queue_count/, "tasks waiting for a worker right now");
  assert.match(sql, /WHEN @wpct>=90 AND @live=1 THEN 'fail'/, "the worker ratio alone (it counts parked workers) cannot Fail");
  assert.doesNotMatch(sql, /WHEN @wpct>=90 AND @shr>=0\.10 THEN 'fail'/, "the lifetime average must not decide Fail any more");
  assert.match(sql, /WHEN @aw<@mwt AND @ag=1 THEN 'PINNED-AG'/);
  assert.match(sql, /'STARVING-NOW'/);

  // Shape: pinned at 1024 above auto 704, quiet, but an AG replica.
  const f = run("Instance performance settings (workers / parallelism / memory)", [
    { Setting: "05 cost threshold for parallelism", Value: "5", Expected: "25 or more (fleet standard 50)", Verdict: "PRODUCT-DEFAULT", Sev: "attention", Context: "x" },
    { Setting: "01 max worker threads", Value: "1024", Expected: "KEEP the pin at 1024 on every replica - a failover moves the partner's workload here",
      Verdict: "PINNED-AG", Sev: "-", Context: "cap in force 1024" },
  ]);
  assert.match(String(f.details), /NOT a defect, do not "fix" — max worker threads: 1024/);
  assert.match(String(f.remediation?.code ?? ""), /NOT on an AG replica whose partner needs the pin \(verdict PINNED-AG\)/);
});

test("4. AG replica policy: no routing-URL finding on a DAG's secondary AG that nothing routes to", () => {
  const { sql } = entry("AG replica policy conformance");
  assert.match(sql, /IsDagSecondary=CASE WHEN EXISTS/);
  assert.match(sql, /drs\.role_desc='SECONDARY'/, "on the member AG's primary the DAG row says it is the secondary side");
  assert.match(sql, /ag\.name LIKE '%forwarder%'/, "on its secondary no DAG replica row is visible - the AG naming convention is the fallback");
  assert.match(sql, /sys\.availability_read_only_routing_lists/, "a URL matters only when a routing list names the replica");
  assert.match(sql, /CASE WHEN dg\.IsDagSecondary=1 AND dg\.RoutedTo=0 THEN 0 /);
  assert.doesNotMatch(sql, /cross-region/, "a forwarder AG is a LOCAL pair");

  // Synthetic: only the real finding remains.
  const f = run("AG replica policy conformance", [
    { AgName: "ag-region4-forwarder", Replica: "REGION4-NODE1", Setting: "SESSION_TIMEOUT", Actual: "10", Expected: "60", Sev: 2, Note: "…" },
    { AgName: "ag-region4-forwarder", Replica: "REGION4-NODE2", Setting: "SESSION_TIMEOUT", Actual: "10", Expected: "60", Sev: 2, Note: "…" },
  ], "fail");
  const d = String(f.details);
  assert.match(d, /ag-region4-forwarder\/REGION4-NODE1: SESSION_TIMEOUT = 10/);
  assert.doesNotMatch(d, /cross-region/);
  assert.doesNotMatch(d, /routing URL/, "say only what was found");
});

test("5. Error 17830 is classified by cause; SQL Assessment no longer grades its count", () => {
  const { sql, evalPs, target } = entry("Login resets (Error 17830) by source");
  assert.equal(target, "dmv");
  assert.match(sql, /RING_BUFFER_CONNECTIVITY/);
  assert.match(sql, /RecType='LoginTimers' AND Err=17830/);
  assert.match(sql, /DATEADD\(SECOND,-CONVERT\(int,\(@ticks-ts\)\/1000\),@now\)/, "UTC from ms_ticks, not RecordTime's text");
  for (const p of ["LOGIN-QUEUED", "LOCAL-CLIENT", "CLIENT-IDLE-ABANDON", "CLIENT-RESET"]) assert.ok(sql.includes(`'${p}'`), p);
  assert.match(sql, /'<local machine>'/, "shared-memory logins report this as their source");
  assert.match(evalPs, /-ge 2 \}\); .*'fail'/);

  // Synthetic: server-side queueing on one node, and an idle client against another, trimmed.
  const queued = run("Login resets (Error 17830) by source", [
    { Source: "10.0.1.36", Pattern: "LOGIN-QUEUED", Events: 7, MaxEnqueueMs: 9500, AvgNetReadsMs: 0, PatternEvents: 30, PatternSources: 12, ClientSideResets: 600, BufferFromUtc: "2026-01-11T11:40:21.000Z", Sev: 2 },
    { Source: "10.0.1.204", Pattern: "LOGIN-QUEUED", Events: 2, MaxEnqueueMs: 12500, AvgNetReadsMs: 0, PatternEvents: 30, PatternSources: 12, ClientSideResets: 600, BufferFromUtc: "2026-01-11T11:40:21.000Z", Sev: 2 },
    { Source: "10.0.1.220", Pattern: "CLIENT-RESET", Events: 80, MaxEnqueueMs: 33, AvgNetReadsMs: 0, PatternEvents: 600, PatternSources: 30, ClientSideResets: 600, BufferFromUtc: "2026-01-11T11:40:21.000Z", Sev: 1 },
  ], "fail");
  const qd = String(queued.details);
  assert.match(qd, /LOGIN-QUEUED, 30 event\(s\) — SERVER SIDE: the login waited up to 12,500 ms for a worker thread/);
  assert.match(qd, /CLIENT-RESET, 600 event\(s\) from 30 source\(s\)/, "window totals, not the 25-row cut");
  assert.match(qd, /reaches back to 2026-01-11 11:40:21 UTC/);
  const idle = run("Login resets (Error 17830) by source", [
    { Source: "10.0.5.34", Pattern: "CLIENT-IDLE-ABANDON", Events: 900, MaxEnqueueMs: 67, AvgNetReadsMs: 1650, PatternEvents: 901, PatternSources: 2, ClientSideResets: 950, BufferFromUtc: "2026-01-11T19:17:48.000Z", Sev: 1 },
  ]);
  assert.match(String(idle.details), /CLIENT-IDLE-ABANDON, 901 event\(s\).*~1,650 ms.*10\.0\.5\.34 900x/);
  assert.match(String(idle.remediation?.code ?? ""), /Get-NetTCPConnection -RemotePort 1433/);

  // The assessment's evaluator drops exactly that one message and nothing else.
  const sa = entry("Microsoft SQL Assessment (allow-list)").evalPs;
  assert.match(sa, /'SystemHealth' -and "\$\(\$_\.Message\)" -match '\^Error 17830\\b'/);
  assert.match(sa, /\$c=@\(\$g \| /, "Critical/High is counted over the filtered set");
  const saF = run("Microsoft SQL Assessment (allow-list)", [
    { CheckId: "SystemHealth", CheckName: "System health", Severity: "High", Message: "Error 17830 occured 950 times in the last day" },
    { CheckId: "WeakPassword", CheckName: "Weak password", Severity: "Medium", Message: "Login app_x has a weak password" },
  ], "attention", "Invoke-SqlAssessment");
  assert.match(String(saF.details), /NOT graded here: classified by cause in "Login resets \(Error 17830\) by source"/);
  assert.doesNotMatch(String(saF.details), /Critical\/High/, "the 17830 row is not counted as a High here");
});

test("7. Storage I/O grades a LIVE 20-second sample; the lifetime average is context, data writes are gone", () => {
  const { sql, evalPs } = entry("Storage I/O latency (per volume)");
  assert.match(sql, /WAITFOR DELAY '00:00:20'/);
  assert.match(sql, /DECLARE @s TABLE/, "a table variable: nothing left behind if the batch is cancelled");
  assert.doesNotMatch(sql, /DataWriteMs_Info/, "async checkpoint writes are never graded - and no longer printed");
  assert.match(evalPs, /\$lf=@\(\$d\|\?\{\(\[long\]\$_\.LiveReads -ge 200 -and \[double\]\$_\.LiveReadMs -ge 120\)/);
  assert.match(evalPs, /if \(\$lf\) \{'fail'\}/, "only the live sample can Fail");
  const f = run("Storage I/O latency (per volume)", [
    { Volume: "E:\\", LiveReadMs: 3.1, LiveReads: 5000, LiveLogWriteMs: 0, LiveLogWrites: 0, AvgReadMs: 540.0, Reads: 650000000,
      AvgLogWriteMs: 0, LogWrites: 0, SlowestDataFile: "AppDb_Data/AppDb_Data_09", UptimeHrs: 400.0, SampleSec: 20.0 },
  ]);
  const d = String(f.details);
  assert.match(d, /E:\\ now 3 ms read \(5,000 reads\) \/ 0 ms log write \(0 writes\); since start 540 ms read/);
  assert.match(d, /20-second sample/);
  assert.doesNotMatch(d, /ms write \(slowest/, "no data-write latency in the headline");
});

test("9. Tooling drift says what it grades, and grades the library dbatools 2.7.2 needs", () => {
  const { sql } = entry("Health-check tooling version drift");
  assert.match(sql, /'exactly 2\.7\.2'/);
  assert.doesNotMatch(sql, /2\.7\.2 or newer/);
  assert.match(sql, /Modules\\dbatools\.library'/);
  assert.match(sql, /WHEN modul='dbatools\.library' THEN CASE WHEN cnt>1 OR ver<>'2025\.8\.17' THEN 1 ELSE 0 END/);
  // Synthetic: a newer dbatools installed beside the pinned one, and three library copies.
  const f = run("Health-check tooling version drift", [
    { Module: "dbatools", Effective: "2.9.0", InstalledCopies: 2, Expected: "exactly 2.7.2", Sev: 1 },
    { Module: "dbatools.library", Effective: "2026.1.1", InstalledCopies: 3, Expected: "exactly 2025.8.17", Sev: 1 },
    { Module: "SqlServer", Effective: "22.3.0", InstalledCopies: 1, Expected: "(client-side only)", Sev: 0 },
  ]);
  const d = String(f.details);
  assert.match(d, /dbatools 2\.9\.0 is the effective version \(expected exactly 2\.7\.2\), but 2 versions are installed/);
  assert.match(d, /dbatools\.library 2026\.1\.1 is the one that loads \(expected exactly 2025\.8\.17.*3 versions installed/);
  assert.match(String(f.remediation?.code ?? ""), /Uninstall-Module dbatools\.library -RequiredVersion <old> -Force/);
});

test("10. Index health retries a failing database once without partition detail, and says how to diagnose it", () => {
  const ps = buildHealthCheckScript({ name: "region3-node2", host: "10.0.0.1", port: 1433 } as never, false, 25);
  assert.match(ps, /@Mode = 0, @SkipPartitions = 1"\)/, "the per-database retry");
  assert.match(ps, /if \(\$__e1 -notmatch 'timed\? \?out'\)/, "never retried after a timeout");
  assert.match(ps, /diagnose on the node: EXEC DBA\.dbo\.sp_BlitzIndex @DatabaseName = N''' \+ \$__db\.Replace/);
  const label = "Index health (sp_BlitzIndex)";
  const failed = run(label, [{ Priority: 1, "Database Name": "AppDb_Data",
    Finding: "Database Skipped: AppDb_Data - sp_BlitzIndex failed on it: Arithmetic overflow error converting expression to data type money. | retry with @SkipPartitions = 1: Arithmetic overflow error converting expression to data type money. | diagnose on the node: EXEC DBA.dbo.sp_BlitzIndex @DatabaseName = N'AppDb_Data', @BringThePain = 1, @Debug = 1;" }], "fail");
  const d = String(failed.details);
  assert.match(d, /NOT ANALYSED: AppDb_Data — sp_BlitzIndex failed on it \(Arithmetic overflow error converting expression to data type money\.\), and again without partition-level detail/);
  assert.match(d, /run on the node: EXEC DBA\.dbo\.sp_BlitzIndex @DatabaseName = N'AppDb_Data', @BringThePain = 1, @Debug = 1;/);
  assert.match(String(failed.remediation?.code ?? ""), /^EXEC DBA\.dbo\.sp_BlitzIndex @DatabaseName = N'AppDb_Data', @BringThePain = 1, @Debug = 1;$/m);
  const partial = run(label, [
    { Priority: 255, "Database Name": "AppDb_Data", Finding: "Note: partial analysis: AppDb_Data - analysed with @SkipPartitions = 1 because the full analysis failed: Arithmetic overflow error converting expression to data type money." },
    { Priority: 30, "Database Name": "AppDb_Data", Finding: "Indexaphobia: High Value Missing Index", "Details: schema.table.index(indexid)": "dbo.x" },
  ]);
  assert.match(String(partial.details), /PARTIAL: AppDb_Data analysed WITHOUT partition-level detail \(@SkipPartitions = 1\) because the full analysis failed/);
  assert.doesNotMatch(String(partial.details), /NOT ANALYSED/, "a database the retry analysed is not a coverage hole");
});

test("11. Capacity symmetry: one row per replica, and a stale baseline says so", () => {
  const sql = capacitySymmetrySql(parseCapacityBaseline(JSON.stringify([
    { node: "REGION2-NODE1", cores: 16, memMb: 65536 }, { node: "REGION2-NODE2", cores: 8, memMb: 32768 },
    { node: "bad'name", cores: 4, memMb: 1 }, { node: "REGION2-NODE3", cores: 0, memMb: 1024 }])), "2026-01-15");
  assert.match(sql, /VALUES\('REGION2-NODE1',16,65536\),\('REGION2-NODE2',8,32768\)\) v\(a,b,c\)/, "only valid entries reach the SQL");
  assert.match(sql, /GROUP BY ar\.replica_server_name/);
  assert.match(sql, /STRING_AGG\(CONVERT\(varchar\(max\),ag\.name\),', '\)/);
  assert.match(sql, /BaselineMeasured=CONVERT\(varchar\(10\),'2026-01-15'\)/);
  assert.match(sql, /c\.cores<>h\.cores OR ABS\(c\.mem_mb-h\.mem_mb\)>c\.mem_mb\/20/, "this node vs its own baseline row");
  // Unconfigured, the check cannot judge a failover target: it is SKIPPED with the reason, never passed.
  const unconfigured = capacitySymmetrySql([], "unknown");
  assert.match(unconfigured, /__hc_skip=CONVERT\(varchar\(300\),'No capacity baseline configured \(HEALTHCHECK_CAPACITY_BASELINE\)/);
  assert.doesNotMatch(unconfigured, /sys\.availability_replicas/);
  assert.match(buildHealthCheckScript({ name: "region3-node2", host: "10.0.0.1", port: 1433 } as never, true, 25), /\$__skip = \$\(if \(\$null -ne \$d\) \{ @\(\$d\)\[0\]\.__hc_skip \}/, "a __hc_skip row maps to 'skipped'");
  // Synthetic: one row for the undersized peer, covering both AGs it shares with this node.
  const f = run("AG failover capacity symmetry", [
    { AgName: "ag-region2-cluster, ag-region2-forwarder", Replica: "region2-node5", IsThisNode: 0, ThisCores: 16, ThisMemMB: 65536, PeerCores: 8, PeerMemMB: 32768,
      CorePct: 50, MemPct: 50, AutoFailover: "AUTOMATIC", BaselineMeasured: "2026-01-15", Sev: 2, Note: "…" },
    { AgName: "ag-region2-cluster, ag-region2-forwarder", Replica: "region2-node4", IsThisNode: 1, ThisCores: 16, ThisMemMB: 65536, PeerCores: 16, PeerMemMB: 65536,
      CorePct: 100, MemPct: 100, AutoFailover: "AUTOMATIC", BaselineMeasured: "2026-01-15", Sev: 0, Note: "This node (live size)." },
  ], "fail");
  const d = String(f.details);
  assert.equal((d.match(/region2-node5 has/g) ?? []).length, 1, "the peer is named once, not once per AG");
  assert.match(d, /AUTOMATIC failover; ag-region2-cluster, ag-region2-forwarder/);
  assert.match(d, /baseline measured 2026-01-15/);
  const stale = run("AG failover capacity symmetry", [
    { AgName: "ag-region3-cluster, ag-region3-forwarder", Replica: "REGION3-NODE1", IsThisNode: 1, ThisCores: 16, ThisMemMB: 65536, PeerCores: 8, PeerMemMB: 32768,
      BaselineMeasured: "2026-01-15", Sev: 1, Note: "STALE BASELINE: this node now reports 16 cores / 65536 MB, but its row in the configured baseline (measured 2026-01-15) says 8 / 32768 MB - update HEALTHCHECK_CAPACITY_BASELINE, or the peer comparisons are against the wrong size." },
  ]);
  assert.match(String(stale.details), /STALE BASELINE/);
  assert.match(String(stale.remediation?.code ?? ""), /0\) FIRST: the capacity baseline is STALE for this node/);
});

test("12. LOCK_ESCALATION names the tables instead of the generic fallback", () => {
  const rows = [
    { Scope: "SUMMARY", DbName: "(all databases)", TableName: "-", LockEscalation: "-", Partitions: 0, MaxPartitionRows: 0, DbsScanned: 8, PartitionedTables: 40, NotAutoTables: 3 },
    { Scope: "TABLE", DbName: "AppDb_Analytics", TableName: "msg.StatMessageLogDaily", LockEscalation: "TABLE", Partitions: 500, MaxPartitionRows: 350000, DbsScanned: 8 },
    { Scope: "TABLE", DbName: "AppDb_Data", TableName: "svc.StatAlertData_NEW", LockEscalation: "TABLE", Partitions: 90, MaxPartitionRows: 0, DbsScanned: 8 },
    { Scope: "TABLE", DbName: "AppDb_Data", TableName: "dbo.Keep", LockEscalation: "DISABLE", Partitions: 12, MaxPartitionRows: 10, DbsScanned: 8 },
  ];
  const d = String(run("LOCK_ESCALATION on partitioned tables", rows).details);
  assert.doesNotMatch(d, /no per-row summary rule/);
  assert.match(d, /Scanned 8 database\(s\): 40 partitioned table\(s\), 3 not at AUTO\./);
  assert.match(d, /TABLE on partitions of 5,000\+ rows: AppDb_Analytics\.msg\.StatMessageLogDaily \(500 partitions, largest 350,000 rows\)/);
  assert.match(d, /every partition is under 5,000 rows \(not graded until one grows\): AppDb_Data\.svc\.StatAlertData_NEW/);
  assert.match(d, /DISABLE - a deliberate setting, reported and never graded: AppDb_Data\.dbo\.Keep/);
  const aborted = String(run("LOCK_ESCALATION on partitioned tables", [{ Scope: "SUMMARY", DbName: "(scan aborted) Msg 208", DbsScanned: -1, PartitionedTables: -1, NotAutoTables: -1 }], "ok").details);
  assert.match(aborted, /scan aborted, so nothing was graded/);
});

test("13. The report carries its Fail/Attention counts where a mail job can put them in the subject", () => {
  const fail = toFinding({ category: "Availability", label: "Agent alert coverage", command: "Invoke-DbaQuery", priority: "High",
    status: "fail", rows: 1, shown: 1, capped: false, data: [{ Item: "NO ALERTS CONFIGURED", Detail: "x", Sev: 3 }] } as never);
  const attn = toFinding({ category: "Configuration", label: "Build currency", command: "Invoke-DbaQuery", priority: "Medium",
    status: "attention", rows: 1, shown: 1, capped: false, data: [{ Build: "16.0.4150.1", CU: "CU20", Target: "16.0.4200.1", TargetCU: "CU22", Verdict: "BEHIND", Sev: 1 }] } as never);
  const findings = [fail, attn];
  const score = scoreFindings(findings);
  const html = generateHtmlReport("2026-01-05T01:00:00Z", [{
    instance: "region3-node2", computer: "REGION3-NODE2", sql_instance: "REGION3-NODE2", overall_health: score.overall,
    status_counts: score.counts, categories: score.categories, findings, coverage: coverageOf(findings, [{ status: "fail" }, { status: "attention" }]),
  }] as never);
  assert.match(html, /<meta name="hc-counts" content="fail=1;attention=1">/, "exact format: the T-SQL parser depends on it");
  assert.match(html, /<title>SQL Server Instance Health Report - 1 Fail \/ 1 Attention<\/title>/);
});
