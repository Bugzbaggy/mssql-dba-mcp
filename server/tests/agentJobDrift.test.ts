/**
 * "Agent job drift between AG replicas".
 *
 * msdb is per node, so a failover runs whatever job set the new primary happens to have. No node can
 * see its partner's msdb, so the check is split: each node returns an ungraded INVENTORY, and
 * applyReplicaJobDrift() compares partners after the run and re-grades the finding in place.
 * In practice replicas drift in every direction: jobs that exist on one side only, a job enabled on
 * one side and disabled on the other, and a job with the same name but a different number of steps.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, DRIFT_LABEL, applyReplicaJobDrift, buildHealthCheckScript, coverageOf, scoreFindings, toFinding } from "../src/dbatools.js";

type Raw = Parameters<typeof toFinding>[0];
const entry = CATALOG.find((c) => c[1] === DRIFT_LABEL);
const SQL = String(entry?.[4] ?? "");

function inventory(server: string, partners: string, jobs: Array<[string, number, number, string, string?]>): Raw {
  const data = jobs.map(([Job, Enabled, Scheduled, StepsHash, Modified]) =>
    ({ Job, Enabled, Scheduled, Steps: 2, StepsHash, Modified: Modified ?? "2026-10-01 00:00:00", Server: server, Partners: partners }));
  return { category: "Availability", label: DRIFT_LABEL, command: "Invoke-DbaQuery", priority: "Medium",
    status: data.length ? "ok" : "empty", rows: data.length, shown: data.length, capped: false, data };
}

function report(instance: string, raws: Raw[]) {
  const findings = raws.map(toFinding);
  const s = scoreFindings(findings);
  return { instance, overall_health: s.overall, status_counts: s.counts, categories: s.categories, findings, coverage: coverageOf(findings, raws) };
}
const driftOf = (r: ReturnType<typeof report>) => r.findings.find((f) => f.label === DRIFT_LABEL)!;

// Synthetic fixture covering each drift pattern once: a one-sided job in each direction, a
// one-sided enabled state, a steps-differ pair and a both-disabled difference. Hashes and dates
// are fixture values: the steps-differ pair only exercises the "modified later" direction.
const NODE1_JOBS: Array<[string, number, number, string, string?]> = [
  ["AppCatalog: MessageLog DeleteOldRecords", 1, 1, "AAA"],          // pre-split job, only on node 1
  ["Ops: Weekly Report", 1, 1, "W1"],                               // identical on both sides in this fixture
  ["AppDb_Routing: RetentionPurge", 0, 1, "P1"],                    // disabled on node 1, enabled on node 2
  ["AppDb_Data: MessageLog DeleteOldRecords", 1, 1, "TWO", "2026-07-01 00:00:00"],  // fixture: modified first
  ["Monitoring-Internal-Actions", 0, 0, "S1"],                      // disabled on both, steps differ
];
const NODE2_JOBS: Array<[string, number, number, string, string?]> = [
  ["Ops: Weekly Report", 1, 1, "W1"],
  ["Ops: Long Running Queries", 1, 1, "L1"],                        // only on node 2
  ["AppDb_Routing: RetentionPurge", 1, 1, "P1"],
  ["AppDb_Data: MessageLog DeleteOldRecords", 1, 1, "FIVE", "2026-09-30 00:00:00"], // fixture: modified later
  ["Monitoring-Internal-Actions", 0, 0, "S2"],
];

test("the inventory is an ungraded Availability entry right after Agent job integrity", () => {
  assert.ok(entry, `"${DRIFT_LABEL}" is missing from the catalog`);
  assert.equal(entry[0], "Availability");
  assert.equal(entry[3], "dmv");
  assert.ok(!entry[6], "a single node cannot grade drift - the evaluator lives in applyReplicaJobDrift()");
  const i = CATALOG.findIndex((c) => c[1] === DRIFT_LABEL);
  assert.equal(CATALOG[i - 1][1], "Agent job integrity");
});

test("the inventory returns a hash, never step text, and skips replication and appdb-sql leftovers", () => {
  const outer = SQL.slice(SQL.indexOf("SELECT TOP (1000)"));
  assert.match(outer, /StepsHash = \(SELECT CONVERT\(varchar\(16\), HASHBYTES\('SHA2_256'/);
  assert.doesNotMatch(outer.replace(/StepsHash = \(SELECT[^]*?FROM st WHERE st\.job_id = j\.job_id\)/, ""), /command/i,
    "only the hash expression may touch step text");
  assert.match(SQL, /NOT LIKE N'REPL-%'/, "replication agent jobs follow the distributor, not the AG (they can exist on one replica only)");
  assert.match(SQL, /NOT LIKE N'appdb\[_\]mcp\[_\]%'/);
  assert.doesNotMatch(SQL.replace(/N'--'/g, ""), /--/, "a line comment would swallow the rest once collapsed onto one line");
});

test("the node's own fleet identity is substituted per instance, so self-references compare equal", () => {
  assert.match(SQL, /N'__HC_INSTANCE__'/);
  assert.match(SQL, /N'__HC_HOST__'/);
  const ps = buildHealthCheckScript({ name: "region2-node1", host: "10.0.2.118", port: 1433 } as never, true, 25);
  const line = ps.split("\n").find((l) => l.includes(`label='${DRIFT_LABEL}'`)) ?? "";
  const block = ps.slice(ps.lastIndexOf("try {", ps.indexOf(line)), ps.indexOf(line));
  assert.match(block, /N''region2-node1''/, "fleet name substituted (doubled quotes: inside a PowerShell single-quoted string)");
  assert.match(block, /N''10\.0\.2\.118''/, "fleet host substituted - region2-node1 calls sqlcmd -S 10.0.2.118");
  assert.doesNotMatch(ps, /__HC_(INSTANCE|HOST)__/);
});

test("the inventory reaches the comparison whole, not cut at the 200-row display cap", () => {
  const ps = buildHealthCheckScript({ name: "T", host: "10.0.0.1", port: 1433 } as never, true, 25);
  const lines = ps.split("\n");
  const shownFor = (label: string) => {
    const at = lines.findIndex((l) => l.includes(`label='${label}'`));
    return lines.slice(Math.max(0, at - 3), at).find((l) => l.includes("$__shown = "));
  };
  assert.match(shownFor(DRIFT_LABEL) ?? "", /Select-Object -First 2000 \}\)/);
  assert.match(shownFor("Agent job integrity") ?? "", /Select-Object -First 200 \}\)/);
});

test("a single-node run leaves it Info and says how to get it graded", () => {
  const r = report("region1-node1", [inventory("REGION1-NODE1", "REGION1-NODE2", NODE1_JOBS)]);
  applyReplicaJobDrift([r], [[inventory("REGION1-NODE1", "REGION1-NODE2", NODE1_JOBS)]]);
  const f = driftOf(r);
  assert.equal(f.status, "Info");
  assert.match(f.details, /NOT compared: the AG partner \(REGION1-NODE2\) was not checked in this run/);
  assert.equal(f.remediation, undefined);
});

test("partners in the same run are compared and both sides are re-graded", () => {
  const raws = [[inventory("REGION1-NODE1", "REGION1-NODE2", NODE1_JOBS)], [inventory("REGION1-NODE2", "REGION1-NODE1", NODE2_JOBS)]];
  const reps = [report("region1-node1", raws[0]), report("region1-node2", raws[1])];
  applyReplicaJobDrift(reps, raws);
  const [a, b] = reps.map(driftOf);
  assert.equal(a.status, "Attention");
  assert.equal(b.status, "Attention");
  assert.match(a.details, /only on this node - stops if REGION1-NODE2 becomes primary \(1\) — AppCatalog: MessageLog DeleteOldRecords/);
  assert.match(a.details, /only on REGION1-NODE2 - stops if this node becomes primary \(1\) — Ops: Long Running Queries/);
  assert.match(a.details, /enabled or scheduled on one side only \(1\) — AppDb_Routing: RetentionPurge \(here: disabled; REGION1-NODE2: enabled\)/);
  assert.match(a.details, /same name, different steps \(1\) — AppDb_Data: MessageLog DeleteOldRecords \(job modified later on REGION1-NODE2\)/);
  assert.match(a.details, /1 more difference\(s\) in jobs disabled or unscheduled on both sides - not graded/);
  assert.doesNotMatch(a.details, /Ops: Weekly Report/, "identical jobs are not drift");
  assert.match(b.details, /only on this node[^\n]*Ops: Long Running Queries/, "the partner sees the mirror image");
  // the report's own score follows the re-grade
  assert.equal(reps[0].status_counts.Attention, 1);
  assert.equal(reps[0].status_counts.Info, 0);
});

test("remediation copies from the right side and keeps every change commented out", () => {
  const raws = [[inventory("REGION1-NODE1", "REGION1-NODE2", NODE1_JOBS)], [inventory("REGION1-NODE2", "REGION1-NODE1", NODE2_JOBS)]];
  const reps = [report("region1-node1", raws[0]), report("region1-node2", raws[1])];
  applyReplicaJobDrift(reps, raws);
  const code = driftOf(reps[0]).remediation?.code ?? "";
  // Both ends by server name: these lines run from any host that reaches both replicas.
  assert.match(code, /Copy-DbaAgentJob -Source 'REGION1-NODE1' -Destination 'REGION1-NODE2' -Job 'AppCatalog: MessageLog DeleteOldRecords'/);
  assert.match(code, /Copy-DbaAgentJob -Source 'REGION1-NODE2' -Destination 'REGION1-NODE1' -Job 'Ops: Long Running Queries'/);
  assert.match(code, /Copy-DbaAgentJob -Source 'REGION1-NODE2' -Destination 'REGION1-NODE1' -Job 'AppDb_Data: MessageLog DeleteOldRecords' -Force/,
    "steps differ: suggest copying FROM the side modified later");
  assert.doesNotMatch(code, /\$env:COMPUTERNAME/, "it names the jump host, not this node, when run from elsewhere");
  assert.match(code, /confirm it is the right copy/, "date_modified moves on any sp_update_job call, so it is a hint, not proof");
  // A one-sided enable gets sp_update_job on the disabled side - and no schedule advice it does not need.
  assert.match(code, /'AppDb_Routing: RetentionPurge': on REGION1-NODE1 disabled; on REGION1-NODE2 enabled\./);
  assert.match(code, /sp_update_job @job_name = N'AppDb_Routing: RetentionPurge', @enabled = 1;   -- on REGION1-NODE1/);
  assert.doesNotMatch(code, /sp_update_schedule/);
  const runnable = code.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("--"));
  assert.ok(runnable.length > 0 && runnable.every((l) => /^(SELECT|steps =|FROM msdb\.dbo\.sysjobs)/.test(l)),
    `only the comparison SELECT may be runnable:\n  ${runnable.join("\n  ")}`);
  assert.ok(runnable.every((l) => !/region\d+-node\d+/i.test(l)), "no runnable line names a node");
});

test("a schedule-only difference gets schedule advice, not an enable it does not need", () => {
  // A job enabled on both replicas that has an enabled schedule on only one of them:
  // sp_update_job @enabled = 1 would change nothing.
  const raws = [[inventory("REGION1-NODE1", "REGION1-NODE2", [["AppDb_Analytics : Update svc.DailyStats", 1, 0, "V1"]])],
    [inventory("REGION1-NODE2", "REGION1-NODE1", [["AppDb_Analytics : Update svc.DailyStats", 1, 1, "V1"]])]];
  const reps = [report("region1-node1", raws[0]), report("region1-node2", raws[1])];
  applyReplicaJobDrift(reps, raws);
  const code = driftOf(reps[0]).remediation?.code ?? "";
  assert.match(code, /on REGION1-NODE1 enabled, no enabled schedule; on REGION1-NODE2 enabled\./);
  assert.match(code, /-- on REGION1-NODE1: enable the schedule it should run on; if none is attached, copy the job across instead/);
  assert.match(code, /sp_update_schedule @schedule_id = <schedule_id>, @enabled = 1;/);
  assert.doesNotMatch(code, /EXEC msdb\.dbo\.sp_update_job @/);
});

test("steps that differ with the same date_modified suggest no direction", () => {
  const raws = [[inventory("A", "B", [["J", 1, 1, "H1", "2026-10-01 00:00:00"]])], [inventory("B", "A", [["J", 1, 1, "H2", "2026-10-01 00:00:00"]])]];
  const reps = [report("a", raws[0]), report("b", raws[1])];
  applyReplicaJobDrift(reps, raws);
  const f = driftOf(reps[0]);
  assert.doesNotMatch(f.details, /modified later/);
  assert.match(f.remediation?.code ?? "", /-Source <the right copy> -Destination <the other> -Job 'J' -Force   # same date_modified on both - read both/);
});

test("the summary carries the how-to: the HTML withholds this Attention-tier script", () => {
  const raws = [[inventory("REGION1-NODE1", "REGION1-NODE2", NODE1_JOBS)], [inventory("REGION1-NODE2", "REGION1-NODE1", NODE2_JOBS)]];
  const reps = [report("region1-node1", raws[0]), report("region1-node2", raws[1])];
  applyReplicaJobDrift(reps, raws);
  const s = driftOf(reps[0]).remediation?.summary ?? "";
  assert.match(s, /Copy-DbaAgentJob from a host that reaches both replicas/);
  assert.match(s, /-Force replaces it/);
  assert.match(s, /date_modified only hints/);
  assert.match(s, /distributor-only task/);
  assert.doesNotMatch(s, /in the block|below/, "the script is not shown next to an Attention finding");
});

test("identical job sets grade Pass", () => {
  const same: Array<[string, number, number, string]> = [["Ops: Weekly Report", 1, 1, "W1"], ["Old dead job", 0, 0, "X"]];
  const raws = [[inventory("A", "B", same)], [inventory("B", "A", same)]];
  const reps = [report("a", raws[0]), report("b", raws[1])];
  applyReplicaJobDrift(reps, raws);
  assert.equal(driftOf(reps[0]).status, "Pass");
  assert.match(driftOf(reps[0]).details, /No difference with B/);
});

test("an inventory that did not arrive whole is never compared", () => {
  const cut = inventory("A", "B", NODE1_JOBS);
  cut.rows = 1500; cut.shown = NODE1_JOBS.length;   // fewer rows shown than fetched
  const raws = [[cut], [inventory("B", "A", NODE2_JOBS)]];
  const reps = [report("a", raws[0]), report("b", raws[1])];
  applyReplicaJobDrift(reps, raws);
  assert.equal(driftOf(reps[0]).status, "Info", "truncation would invent 'only on the partner' jobs");
  assert.equal(driftOf(reps[1]).status, "Info");
});

test("a standalone node has nothing to compare", () => {
  const raws = [[inventory("STANDALONE1", "", [["Job", 1, 1, "H"]])]];
  const reps = [report("standalone1", raws[0])];
  applyReplicaJobDrift(reps, raws);
  assert.equal(driftOf(reps[0]).status, "Info");
  assert.match(driftOf(reps[0]).details, /not an AG replica/);
});
