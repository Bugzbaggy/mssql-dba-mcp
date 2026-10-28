/**
 * Transient Agent jobs must not outlive their tool call.
 *
 * get_host_event_log and generate_cluster_log run work on the host through a temporary SQL Agent
 * PowerShell job and remove it in a `finally`. runPowerShell() kills the process on its timeout, so
 * the finally never ran: enabled appdb_mcp_evt_* jobs were left behind on the nodes, each owned by
 * the caller's personal login.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { transientJobGuard } from "../src/dbatools.js";

test("the wait budget ends well before the process is killed", () => {
  const g = transientJobGuard("appdb[_]mcp[_]evt[_]", 120);
  assert.match(g.start, /^\$__t0 = \[DateTime\]::UtcNow; \$__budget = 95$/, "budget = timeout - 25 s, counted from script start");
  assert.equal(transientJobGuard("x", 40).start.endsWith("$__budget = 30"), true, "never below 30 s");
  assert.match(g.inBudget, /\(\[DateTime\]::UtcNow - \$__t0\)\.TotalSeconds -lt \$__budget/);
});

test("stale leftovers are found by the SERVER's clock and only under the tool's own prefix", () => {
  const [sweep, refuse] = transientJobGuard("appdb[_]mcp[_]evt[_]", 120).beforeCreate;
  assert.match(sweep, /WHERE name LIKE N'appdb\[_\]mcp\[_\]evt\[_\]%' AND date_created < DATEADD\(HOUR, -1, GETDATE\(\)\)/,
    "the client can be hours off the server, so age must be judged server-side");
  assert.match(sweep, /^try \{ .* \} catch \{\}$/, "a failed sweep must never break the tool itself");
  assert.match(refuse, /throw "Connecting took/, "no job is created when connecting used up the budget");
  assert.match(refuse, /Nothing was created on the server/);
});

test("both transient-job tools use the guard: sweep before create, deadline in the poll", () => {
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  for (const [prefix, guard] of [["appdb_mcp_evt_", "evtGuard"], ["appdb_mcp_clog_", "clogGuard"]] as const) {
    const create = src.indexOf(`$job = '${prefix}'`);
    assert.ok(create > 0, `${prefix}: job creation not found`);
    const before = src.slice(src.lastIndexOf("const script = [", create), create);
    assert.match(before, new RegExp(`${guard}\\.start,`), `${prefix}: deadline must start at the top of the script`);
    assert.match(before, new RegExp(`\\.\\.\\.${guard}\\.beforeCreate,`), `${prefix}: sweep + budget check must precede creation`);
    const poll = src.slice(create, src.indexOf("} finally {", create));
    assert.match(poll, new RegExp(`while \\(\\$j\\.CurrentRunStatus -ne 'Idle'[^\\n]*\\$\\{${guard}\\.inBudget\\}\\)`),
      `${prefix}: the poll loop must stop at the deadline so the finally runs`);
  }
});
