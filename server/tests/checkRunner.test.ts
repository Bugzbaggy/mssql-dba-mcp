import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildHealthCheckScript, CONN_STATE_PS_RE } from "../src/dbatools.js";

// How the generated health check survives a stuck check and a broken shared connection. Both were
// seen running it end to end against SQL Server 2022: a run that sat far past its 120 s per-check
// cap, and "There is already an open DataReader" / "The connection is closed" failing a check and
// then every later check on the same connection.

const script = () => buildHealthCheckScript({ name: "n1", host: "10.0.0.1", port: 1433 } as never, true, 25);
const shell = ["pwsh", "powershell"].find((s) => spawnSync(s, ["-NoProfile", "-Command", "exit 0"]).status === 0);

/** A top-level `function Name {` ... `}` block of the generated script. */
function fnBlock(ps: string, name: string): string {
  const lines = ps.split("\n");
  const i = lines.findIndex((l) => l.startsWith(`function ${name}`));
  assert.ok(i >= 0, `function ${name} not found`);
  if (lines[i].trimEnd().endsWith("}")) return lines[i];
  const j = lines.findIndex((l, k) => k > i && l === "}");
  return lines.slice(i, j + 1).join("\n");
}

function runPs(body: string): { out: string; secs: number; status: number | null; stderr: string } {
  const f = join(tmpdir(), `hc-runner-${process.pid}-${Date.now()}.ps1`);
  writeFileSync(f, body, "utf8");
  const t0 = Date.now();
  try {
    const r = spawnSync(shell!, ["-NoProfile", "-NonInteractive", "-File", f], { encoding: "utf8", timeout: 90_000 });
    return { out: (r.stdout ?? "").trim(), secs: (Date.now() - t0) / 1000, status: r.status, stderr: r.stderr ?? "" };
  } finally { rmSync(f, { force: true }); }
}

test("the wall-clock cap never waits on the stuck pipeline", () => {
  const ps = script();
  const fn = fnBlock(ps, "Invoke-CheckWithTimeout");
  const onTimeout = fn.slice(fn.indexOf("if (-not $completed) {"), fn.indexOf("exceeded per-check wall-clock timeout"));
  // Stop() and Dispose() both block until the pipeline stops; a pipeline inside a .NET call cannot.
  assert.doesNotMatch(onTimeout, /\$ps\.Stop\(\)|\$ps\.Dispose\(\)|__hcWorker\.Dispose\(\)/);
  assert.match(onTimeout, /\$ps\.BeginStop\(\$null, \$null\)/);
  assert.match(onTimeout, /\$script:__hcWorker\.CloseAsync\(\)/);
  assert.match(onTimeout, /\$script:__hcAbandoned = \$true/);
  assert.ok(onTimeout.indexOf("Reset-HcServer") < onTimeout.indexOf("New-HcWorkerRunspace"),
    "reconnect BEFORE the new worker is built, or the worker captures the old connection");
  assert.ok(ps.trimEnd().endsWith("if ($__hcAbandoned) { [Console]::Out.Flush(); [Environment]::Exit(0) }"),
    "after the JSON, exit instead of waiting for an abandoned thread");
});

test("live: a check stuck in a .NET call is cut off at the cap, and the run carries on and exits", { skip: !shell && "no PowerShell on this host" }, () => {
  const fn = fnBlock(script(), "Invoke-CheckWithTimeout");
  const r = runPs([
    "$__perCheckTimeoutSec = 2; $__hcAbandoned = $false; $script:resets = 0",
    "function New-HcWorkerRunspace { $rs = [runspacefactory]::CreateRunspace(); $rs.Open(); return $rs }",
    "function Reset-HcServer { $script:resets++ }",
    "$__hcWorker = New-HcWorkerRunspace",
    fn,
    "$sw = [Diagnostics.Stopwatch]::StartNew(); $err = ''",
    // [Thread]::Sleep is one .NET call: PowerShell cannot interrupt it, as with a stuck SqlClient read.
    // 60 s, so the exit bound below can absorb a slow pwsh start and still tell the two cases apart.
    "try { Invoke-CheckWithTimeout -Action { [System.Threading.Thread]::Sleep(60000) } } catch { $err = $_.Exception.Message }",
    "$capped = [int]$sw.Elapsed.TotalSeconds",
    "$next = Invoke-CheckWithTimeout -Action { 'next check ran' }",
    "Write-Output ('{0}|{1}|{2}|{3}|{4}' -f $capped, $err, $script:resets, $__hcAbandoned, $next)",
    "if ($__hcAbandoned) { [Console]::Out.Flush(); [Environment]::Exit(0) }",
  ].join("\n"));
  assert.equal(r.status, 0, r.stderr);
  const [capped, err, resets, abandoned, next] = r.out.split(/\r?\n/).pop()!.split("|");
  assert.ok(Number(capped) <= 6, `the cap took ${capped}s (a blocking Stop() takes the full 60 s)`);
  assert.equal(err, "exceeded per-check wall-clock timeout of 2s");
  assert.equal(resets, "1");
  assert.equal(abandoned, "True");
  assert.equal(next, "next check ran");
  // r.secs includes starting pwsh, which took 20 s under a loaded full-suite run.
  assert.ok(r.secs < 45, `the process took ${r.secs}s to exit; PowerShell 7 otherwise waits for the stuck thread`);
});

test("every check retries once on a connection-state failure, after a new connection and worker", () => {
  const ps = script();
  const blocks = ps.split("\n$__try = 0\n").length - 1;
  assert.equal(blocks, (ps.match(/^ {2}\$d = /gm) ?? []).length, "every check runs inside the retry loop");
  assert.ok(ps.includes(`  if ($__m -match '${CONN_STATE_PS_RE}') { Reset-HcConnection; if ($__try -lt 2) { continue } }`));
  // One connect function, so a reconnect builds exactly what the run started with.
  assert.match(ps, /\n\$server = New-HcServer\n/);
  assert.match(fnBlock(ps, "New-HcServer"), /Connect-DbaInstance .*StatementTimeout/s);
  assert.equal(fnBlock(ps, "Reset-HcServer"), "function Reset-HcServer { try { $script:server = New-HcServer } catch {} }");
  const reset = fnBlock(ps, "Reset-HcConnection");
  assert.match(reset, /Reset-HcServer/);
  assert.match(reset, /CloseAsync\(\).*New-HcWorkerRunspace/);
  assert.doesNotMatch(reset, /Dispose\(\)/, "Dispose waits for whatever the old worker is still running");
  for (const m of ["There is already an open DataReader associated with this Connection which must be closed first.",
    "Invalid operation. The connection is closed.", "Internal connection fatal error."]) {
    assert.match(m, new RegExp(CONN_STATE_PS_RE), m);
  }
  assert.doesNotMatch("exceeded per-check wall-clock timeout of 120s", new RegExp(CONN_STATE_PS_RE), "a slow check is not retried");
});

test("live: the retry turns one broken-connection failure into a result, and reports a second", { skip: !shell && "no PowerShell on this host" }, () => {
  const ps = script();
  const lines = ps.split("\n");
  const starts = lines.flatMap((l, i) => (l === "$__try = 0" ? [i] : []));
  const at = starts.findIndex((s) => lines.slice(s, starts[starts.indexOf(s) + 1]).some((l) => l.includes("label='Suspect pages'")));
  assert.ok(at >= 0);
  const block = lines.slice(starts[at], starts[at + 1]).join("\n");
  const harness = (failures: number) => [
    "$ErrorActionPreference = 'Stop'; $results = @(); $__inaccessibleDbs = @(); $script:calls = 0; $script:resets = 0",
    fnBlock(ps, "ConvertTo-PlainRows"),
    "function Reset-HcConnection { $script:resets++ }",
    `function Invoke-CheckWithTimeout { param([scriptblock]$Action, [int]$TimeoutSec = 0) $script:calls++; if ($script:calls -le ${failures}) { throw 'There is already an open DataReader associated with this Connection which must be closed first.' }; [pscustomobject]@{ DatabaseName = 'db1'; PageId = 7 } }`,
    block,
    "Write-Output ('{0}|{1}|{2}|{3}' -f $results[0].status, $script:calls, $script:resets, $results.Count)",
  ].join("\n");
  const once = runPs(harness(1));
  assert.equal(once.status, 0, once.stderr);
  const [s1, c1, r1, n1] = once.out.split(/\r?\n/).pop()!.split("|");
  assert.notEqual(s1, "error", "the second attempt ran on the new connection and was graded");
  assert.deepEqual([c1, r1, n1], ["2", "1", "1"]);
  const twice = runPs(harness(5));
  assert.equal(twice.status, 0, twice.stderr);
  const [s2, c2, r2, n2] = twice.out.split(/\r?\n/).pop()!.split("|");
  assert.deepEqual([s2, c2, r2, n2], ["error", "2", "2", "1"], "no third attempt, one error result, and the next check still gets a fresh connection");
});
