/**
 * Agent alert coverage: an enabled response job counts as routing.
 *
 * A tiered alert setup can route every alert through the alert's response job (which posts it to a
 * chat channel, say) and notify an operator only for the critical tier. A check that counted
 * operators only would grade severity 19, 20, 21, 24, 25 and 823/824/825 "Alert notifies nobody"
 * on every node that routes this way, although each of them posts. Under the new rule an alert is
 * mute only when it has no operator AND no enabled response job.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding } from "../src/dbatools.js";

type F = { details?: string; status?: string; remediation?: { summary: string; code?: string } };
const run = (label: string, data: unknown[], status = "attention", command = "Invoke-DbaQuery"): F =>
  toFinding({ category: "x", label, command, priority: "High", status,
              rows: data.length, shown: data.length, capped: false, data } as never) as unknown as F;

test("Agent alert coverage: an enabled response job counts as routing, a disabled one does not", () => {
  const c = CATALOG.find((x) => x[1] === "Agent alert coverage");
  assert.ok(c, "no catalog entry labelled Agent alert coverage");
  const sql = String(c[4]);
  assert.match(sql, /job=CASE WHEN EXISTS \(SELECT 1 FROM msdb\.dbo\.sysjobs j WHERE j\.job_id=a\.job_id AND j\.enabled=1\) THEN 1 ELSE 0 END/,
    "the alert's job must exist AND be enabled to count");
  assert.match(sql, /'Alert notifies nobody',CONVERT\(varchar\(80\),name\),2 FROM matched WHERE id IS NOT NULL AND enabled=1 AND notif=0 AND job=0/,
    "mute = no operator AND no enabled response job");
  // the other findings keep their meaning
  assert.match(sql, /'Alert disabled',CONVERT\(varchar\(80\),name\),2 FROM matched WHERE id IS NOT NULL AND enabled=0/);
  assert.match(sql, /'Alert missing'/);
});

test("Agent alert coverage: a mute alert is described and fixed as 'no operator and no enabled response job'", () => {
  const f = run("Agent alert coverage", [
    { Item: "Alert notifies nobody", Detail: "Severity 21 - Fatal Error", Sev: 2, AlertsTotal: 12, OperatorsEnabled: 1 },
  ], "fail");
  assert.match(String(f.details), /enabled but notifying nobody \(no operator and no enabled response job\): .*Severity 21 - Fatal Error/);
  const code = String(f.remediation?.code ?? "");
  assert.match(code, /response_job = \(SELECT j\.name \+ CASE WHEN j\.enabled = 1 THEN N'' ELSE N' \(DISABLED\)' END/,
    "the 'what exists here' query shows each alert's job and whether it is enabled");
  assert.match(code, /standard alert script/);
  assert.match(code, /EXEC msdb\.dbo\.sp_add_notification @alert_name = N'Severity 21 - Fatal Error'/,
    "adding an operator is still offered (commented)");
});

test("Agent alert coverage: missing alerts point to a standard alert script before the hand-made fallback", () => {
  const f = run("Agent alert coverage", [
    { Item: "Alert missing", Detail: "severity 19", Sev: 2, AlertsTotal: 11, OperatorsEnabled: 1 },
  ], "fail");
  const code = String(f.remediation?.code ?? "");
  const pack = code.indexOf("re-run that script");
  const byHand = code.indexOf("EXEC msdb.dbo.sp_add_alert @name = @n");
  assert.ok(pack >= 0 && byHand > pack, "the standard script comes first; creating alerts by hand is the fallback");
});
