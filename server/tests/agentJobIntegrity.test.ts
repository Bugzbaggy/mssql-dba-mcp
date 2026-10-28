/**
 * "Agent job integrity".
 *
 * "SQL Agent jobs" grades the LAST RUN OUTCOME, so a job that is broken without being red passes it.
 * In practice that is most broken jobs: jobs calling dropped procedures behind a primary-role guard
 * (green on the secondary, Error 2812 on the first run after a failover), a job whose failing guard
 * quits with SUCCESS (so the steps after it never run), a job whose start step is past its guard,
 * and appdb_mcp_evt_* PowerShell jobs this server leaks when a tool call times out before cleanup.
 *
 * These tests pin the parts that are easy to break silently: zero rows must be a Pass, the query
 * must never return command text, live fixes must stay commented out, and the details line must
 * separate "fails on its next run" from "fails after a failover".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, buildHealthCheckScript } from "../src/dbatools.js";

const LABEL = "Agent job integrity";
const row = CATALOG.find((c) => c[1] === LABEL);
const SQL = String(row?.[4] ?? "");

/** Row shapes exactly as the check returns them. Job, step and target values are synthetic: one row
 *  per item type, with the severity each one is returned at. */
const ROWS = [
  { Item: "Calls a missing procedure", Job: "AppCatalog: Cost/Price Backfill Weekly", Step: 2, Target: "[msg].[job_Backfill_Run]",
    Detail: "enabled + scheduled; a primary-role guard masks it on this replica - it runs and fails after a failover", Sev: 2 },
  { Item: "Calls a missing procedure", Job: "Ops: Check Metadata", Step: 1, Target: "[dbo].[check_db_status]",
    Detail: "enabled + scheduled; fails on every run that reaches this step", Sev: 2 },
  // The step name (returned as Target for this item) is illustrative.
  { Item: "T-SQL step holds a command line", Job: "AppDb_Data: job_DailyStat_Load Daily", Step: 2, Target: "Run job_DailyStat_Load",
    Detail: "enabled + scheduled; T-SQL cannot parse a shell command - every run fails with a syntax error", Sev: 2 },
  { Item: "Unreachable step", Job: "Ops: QueryStore Health Maintenance", Step: 1, Target: "Check DB primary role",
    Detail: "no path from the start step reaches it - dead step", Sev: 1 },
  { Item: "Unreachable step", Job: "AppDb_Analytics: Usage Load Daily", Step: 4, Target: "Meter Usage",
    Detail: "no path from the start step reaches it - dead step", Sev: 1 },
  { Item: "Calls into a missing database", Job: "Monitoring-Internal-Checks", Step: 1, Target: "dbo.usp_monitoring_process_checks",
    Detail: "job disabled - dead code, delete candidate", Sev: 1 },
  { Item: "Job has no steps", Job: "Monitoring-Logger-Sysconfig", Step: null, Target: null, Detail: "empty job - delete candidate", Sev: 1 },
  // The step name is illustrative.
  { Item: "Empty or comment-only step", Job: "AppDb_Analytics: Daily Rollups", Step: 6, Target: "Monthly rollup",
    Detail: "the step body has no code outside comments", Sev: 1 },
  // Same shape as a real leftover (appdb_mcp_evt_ + 8 hex characters); the owner is illustrative.
  { Item: "Leftover appdb-sql temporary job", Job: "appdb_mcp_evt_3f9a0c1e", Step: null, Target: "CORP\\svc_sql",
    Detail: "left behind by a appdb-sql MCP tool that timed out before its cleanup ran - delete it", Sev: 1 },
  // Illustrative: a Sev 0 row appears only when a call target's database is unreadable on this replica.
  { Item: "Not verifiable on this replica", Job: "AppDb_Data: Hourly", Step: 3, Target: "msg.job_X",
    Detail: "its database is not readable from this replica - verify on the primary", Sev: 0 },
];

function finding(data: Record<string, unknown>[], status = "fail") {
  assert.ok(row, `"${LABEL}" is missing from the catalog`);
  return toFinding({
    category: row[0] as string, label: LABEL, command: row[2] as string, priority: row[5] as string,
    status, rows: data.length, shown: data.length, data,
  } as Parameters<typeof toFinding>[0]);
}

const runnable = (code: string) => code.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("--"));

test("it is a graded Availability check next to SQL Agent jobs", () => {
  assert.ok(row);
  assert.equal(row[0], "Availability");
  assert.equal(row[3], "dmv");
  const ev = String(row[6] ?? "");
  assert.match(ev, /-ge 2 \}\); .*\{'fail'\}/, "Sev 2 (live) must grade Fail");
  assert.match(ev, /-eq 1 \}\); .*\{'attention'\}/, "Sev 1 (dead code) must grade Attention");
  const idx = CATALOG.findIndex((c) => c[1] === LABEL);
  assert.equal(CATALOG[idx - 1][1], "SQL Agent jobs", "keep it adjacent to the outcome check it complements");
});

test("zero rows is a Pass: every branch returns only broken or dead objects", () => {
  const ps = buildHealthCheckScript({ name: "T", host: "10.0.0.1", port: 1433 } as never, true, 25);
  const re = new RegExp(`label='${LABEL}';[^\\n]*?\\$\\(try \\{ if \\(\\$null -eq \\$d\\) \\{'pass'\\}`);
  assert.match(ps, re, "a node with no broken jobs must be able to score Pass, not Info");
});

test("the query never returns command text", () => {
  // A step can hold a credential (see "Secrets in Agent job step text"); this report is emailed.
  assert.match(SQL, /SELECT TOP \(200\) Item, Job, Step, Target, Detail, Sev FROM g /,
    "the outer projection must stay exactly Item/Job/Step/Target/Detail/Sev");
  const outer = SQL.slice(SQL.lastIndexOf("SELECT TOP (200)"));
  assert.doesNotMatch(outer, /\bcommand\b/i);
  // The command-line branch reports the step NAME as its target, never the head of the command.
  const branch = SQL.slice(SQL.indexOf("'T-SQL step holds a command line'"), SQL.indexOf("'Leftover appdb-sql temporary job'"));
  assert.match(branch, /CONVERT\(varchar\(160\), p\.step_name\)/);
  assert.doesNotMatch(branch, /CONVERT\(varchar\(160\), p\.Head\)/);
});

test("the embedded SQL survives being collapsed onto one line", () => {
  // The catalog SQL is concatenated into a single PowerShell string; a T-SQL line comment would
  // silently swallow everything after it. '--' may only appear inside the N'--' literal.
  assert.doesNotMatch(SQL.replace(/N'--'/g, ""), /--/);
  assert.match(SQL, /OPTION \(MAXRECURSION 5000\)$/);
});

test("the AG DMV is read once, not once per call target", () => {
  // sys.dm_hadr_database_replica_states can cost seconds per evaluation on a busy node; reading
  // it once caps that cost regardless of the plan chosen for the joins.
  assert.equal(SQL.match(/sys\.dm_hadr_database_replica_states/g)?.length, 1);
  assert.match(SQL, /^DECLARE @ag xml = \(SELECT /);
});

test("details separate 'fails on its next run' from 'fails after a failover', and name the jobs", () => {
  const d = finding(ROWS).details;
  assert.match(d, /FAILS ON ITS NEXT RUN — Ops: Check Metadata: \[dbo\]\.\[check_db_status\] \(#1\)/);
  assert.match(d, /FAILS ON ITS NEXT RUN — AppDb_Data: job_DailyStat_Load Daily/);
  assert.match(d, /FAILS AFTER A FAILOVER[^\n]*AppCatalog: Cost\/Price Backfill Weekly: \[msg\]\.\[job_Backfill_Run\] \(#2\)/);
  assert.match(d, /dead code \(delete candidates\) — [^\n]*2 unreachable step/);
  assert.match(d, /1 leftover appdb-sql temporary job\(s\), safe to delete — appdb_mcp_evt_3f9a0c1e/);
  assert.match(d, /not graded — 1 target\(s\)/);
  assert.doesNotMatch(d, /no per-row summary rule/);
  assert.ok(d.includes("\n* "), "renders as a bulleted list");
});

test("one dropped procedure called from many steps is one entry, not nine", () => {
  // A job that calls the same dropped procedure from many steps; listing each step separately
  // pushed every other job off the details line.
  const many = [2, 3, 4, 5, 6].map((s) => ({ ...ROWS[0], Job: "AppCatalog: Campaigns Daily Past Week", Step: s,
    Target: "svc.job_Campaign_Delivered_Update" }));
  const d = finding(many).details;
  assert.match(d, /svc\.job_Campaign_Delivered_Update \(#2, #3, #4, #5 \+1 more\)/);
  assert.equal(d.split("svc.job_Campaign_Delivered_Update").length - 1, 1);
});

test("remediation: live fixes stay commented; only the leaked temporary jobs are deleted outright", () => {
  const rem = finding(ROWS).remediation;
  assert.ok(rem?.code && rem.summary);
  const run = runnable(rem.code);
  for (const l of run) {
    assert.doesNotMatch(l, /sp_update_job|sp_delete_jobstep/, `a job-changing statement is runnable:\n  ${l}`);
    if (/sp_delete_job\b/.test(l)) assert.match(l, /appdb_mcp_evt_/, `only leaked appdb-sql jobs may be deleted by a runnable line:\n  ${l}`);
  }
  assert.ok(run.some((l) => /^SELECT j\.name AS job/.test(l)), "the inventory SELECT must be runnable");
  assert.ok(run.some((l) => /^WHERE j\.name IN \(.*N'Ops: Check Metadata'/.test(l)), "inventory is scoped to the flagged jobs");
  assert.ok(run.some((l) => /IF EXISTS .*appdb_mcp_evt_3f9a0c1e.* EXEC msdb\.dbo\.sp_delete_job @job_name = N'appdb_mcp_evt_3f9a0c1e';/.test(l)));
});

test("remediation names the specific fix for each failure shape", () => {
  const code = finding(ROWS).remediation?.code ?? "";
  assert.match(code, /sp_update_job @job_name = N'Ops: QueryStore Health Maintenance', @start_step_id = 1;/,
    "an unreachable step 1 means the start step skips the guard");
  assert.match(code, /sp_update_jobstep @job_name = N'AppDb_Data: job_DailyStat_Load Daily', @step_id = 2, @subsystem = N'CmdExec';/);
  assert.match(code, /sp_update_jobstep @job_name = N'AppDb_Analytics: Usage Load Daily', @step_id = 3, @on_success_action = 3;/,
    "a dead middle step may be a flow bug: offer the flow fix next to the delete");
  assert.match(code, /sp_delete_jobstep @job_name = N'AppDb_Analytics: Daily Rollups', @step_id = 6;/);
  assert.match(code, /sp_delete_job @job_name = N'Monitoring-Logger-Sysconfig';/);
  assert.match(code, /sp_update_job @job_name = N'AppCatalog: Cost\/Price Backfill Weekly', @enabled = 0;/);
  assert.match(code, /\(masked\)/);
  assert.match(code, /BOTH replicas/);
});

test("the summary stands alone and says which shapes are red and which are not", () => {
  // An Attention-tier finding renders WITHOUT its script in the HTML, so the summary cannot point at it.
  const s = finding(ROWS).remediation?.summary ?? "";
  assert.doesNotMatch(s, /in the block|below|fail silently/,
    "the shell-command step is not silent: it fails with Error 102 and the job goes red");
  assert.match(s, /T-SQL step holding a shell command is the exception: it fails with a syntax error on every run, so it is already red/);
  assert.match(s, /quits reporting success skips every step after it while the job stays green/);
  assert.match(s, /only runnable statements are the inventory query and the deletes of leftover appdb_mcp_\* jobs/);
});

test("a shell-command step is offered the subsystem that can run it", () => {
  // The detector also matches cmdlet syntax ($x, Import-Module, Invoke-*), which CmdExec cannot run.
  const code = finding(ROWS).remediation?.code ?? "";
  assert.match(code, /@subsystem = N'CmdExec';   -- or N'PowerShell'/);
  assert.match(code, /CmdExec for an executable \(sqlcmd, osql, bcp, cmd, powershell\.exe,/);
  assert.match(code, /PowerShell for cmdlet syntax/);
});

test("a job name with a quote cannot break out of the generated literal", () => {
  const code = finding([{ ...ROWS[1], Job: "O'Brien's job" }]).remediation?.code ?? "";
  assert.match(code, /N'O''Brien''s job'/);
});

test("a clean node still gets a runnable inventory, never an empty block", () => {
  const rem = finding([], "pass").remediation;
  if (!rem) return;   // no remediation on a pass is fine
  assert.ok(runnable(rem.code ?? "").length > 0);
});
