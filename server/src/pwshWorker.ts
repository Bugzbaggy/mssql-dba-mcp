import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

// Resolved fresh in start() (not a module-level constant) so a test can point a single
// worker instance at a bogus executable via PWSH_EXE without affecting anything already
// running, and so the launch-failure error message below can name the exact path tried.
function resolvePwshExe(): string {
  return process.env.PWSH_EXE ?? (process.platform === "win32" ? "pwsh" : "pwsh");
}

export interface PwshWorkerOptions {
  /** Import dbatools at boot. Off in unit tests: the import costs seconds and needs the module. */
  importDbatools?: boolean;
  /** Default per-call timeout. */
  timeoutSec?: number;
  /** Max outstanding calls before `call()` rejects rather than buffering without bound. */
  maxQueue?: number;
  /** Max consecutive unexpected-exit restarts before the worker gives up for good. */
  maxRestarts?: number;
}

interface Pending {
  resolve: (rows: unknown[]) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  // The process this request was actually written to. A restart can start a new
  // process while an old one's async "exit" event is still in flight; tagging each
  // pending entry lets onExit() reject only the requests that belonged to it,
  // instead of collaterally failing calls already running against the replacement.
  proc: ChildProcessWithoutNullStreams;
}

// One long-lived pwsh process, fed newline-delimited JSON on stdin and answering the
// same on stdout. The alternative - spawning pwsh per call - pays the dbatools import
// (seconds) on every single tool invocation, which is unusable across 40+ tools.
export class PwshWorker {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private buf = "";
  private readonly opts: Required<PwshWorkerOptions>;
  // Consecutive unexpected-exit restarts since the last call that actually completed
  // successfully (reset in onData() below). Compared against maxRestarts in start().
  restarts = 0;
  // Per-process bounded tail of stderr, keyed by the exact process instance it came from
  // (a restart must never blend one generation's stderr into another's error message).
  // WeakMap so a finished process's entry is simply dropped, not explicitly cleaned up.
  private readonly stderrTails = new WeakMap<ChildProcessWithoutNullStreams, { tail: string }>();
  private static readonly STDERR_TAIL_MAX = 8 * 1024;

  constructor(opts: PwshWorkerOptions = {}) {
    this.opts = {
      importDbatools: opts.importDbatools ?? true,
      timeoutSec: opts.timeoutSec ?? 120,
      maxQueue: opts.maxQueue ?? 32,
      maxRestarts: opts.maxRestarts ?? 5,
    };
  }

  async start(): Promise<void> {
    if (this.proc) return;
    if (this.restarts > this.opts.maxRestarts) {
      throw new Error(`pwsh worker failed to stay up after ${this.opts.maxRestarts} restarts`);
    }
    const boot = [
      "$ErrorActionPreference = 'Stop'",
      this.opts.importDbatools ? "Import-Module dbatools -ErrorAction Stop" : "",
      // dbatools cmdlets that return raw SMO objects (Get-DbaAgReplica, Get-DbaAvailabilityGroup,
      // Get-DbaComputerSystem, ...) have circular navigation properties (ParentCollection -> Parent
      // -> ... ) that ConvertTo-Json cannot serialize. That failure happens on the FINAL
      // WriteLine(ConvertTo-Json) below, which is outside the request's own try/catch — with
      // $ErrorActionPreference = 'Stop' it was a terminating error that killed the whole worker
      // process (every in-flight call failing with "pwsh worker exited", not just this one).
      // ConvertTo-PlainRows (same flattening dbatools.ts's health-check script already uses for
      // the same reason) converts each row to a shallow object of scalars first, so normal cmdlet
      // output never reaches ConvertTo-Json in a shape it can't handle.
      "function ConvertTo-PlainRows($rows) {",
      "  if ($null -eq $rows) { return @() }",
      "  @($rows) | ForEach-Object {",
      "    $row = $_",
      "    if ($null -eq $row) { return }",
      "    if (($row -is [string]) -or ($row -is [valuetype])) { return ,$row }",
      "    $o = [ordered]@{}",
      "    foreach ($p in $row.PSObject.Properties) {",
      "      try {",
      "        $val = $p.Value",
      "        if ($null -eq $val) { $o[$p.Name] = $null }",
      "        elseif (($val -is [string]) -or ($val -is [bool]) -or ($val -is [int]) -or ($val -is [int64]) -or ($val -is [double]) -or ($val -is [decimal])) { $o[$p.Name] = $val }",
      "        elseif ($val -is [datetime]) { $o[$p.Name] = $val.ToString('o') }",
      "        elseif ($val.GetType().IsEnum) { $o[$p.Name] = $val.ToString() }",
      "        else { $o[$p.Name] = [string]$val }",
      "      } catch { $o[$p.Name] = '<unreadable>' }",
      "    }",
      "    [pscustomobject]$o",
      "  }",
      "}",
      // Build ONE PSCredential at boot from the same SQL_USER/SQL_PASSWORD env vars
      // connectionManager.ts already uses (never written to disk or into the JSON
      // protocol — spawn() inherits the parent's env by default, so these two vars
      // just need to be set in the Node process's environment). dbatools cmdlets take
      // -SqlCredential as a PSCredential object, which cannot travel through the
      // newline-JSON request/response framing below, so it is built once here and
      // splatted in per-request instead — see the per-request block further down.
      "$script:__sqlCred = $null",
      "if ($env:SQL_USER -and $env:SQL_PASSWORD) {",
      "  $__sqlSecure = ConvertTo-SecureString $env:SQL_PASSWORD -AsPlainText -Force",
      "  $script:__sqlCred = New-Object System.Management.Automation.PSCredential($env:SQL_USER, $__sqlSecure)",
      "}",
      // Read one JSON request per line, answer with one JSON response per line.
      // ConvertTo-Json -Compress keeps each response on a single line, which is what
      // makes newline framing safe.
      "while ($line = [Console]::In.ReadLine()) {",
      "  if (-not $line) { continue }",
      "  $req = $null",
      "  try { $req = $line | ConvertFrom-Json } catch { continue }",
      "  try {",
      "    $p = @{}",
      "    if ($req.params) { $req.params.PSObject.Properties | ForEach-Object { $p[$_.Name] = $_.Value } }",
      // Splat the boot-time credential in ONLY when the target cmdlet actually accepts
      // -SqlCredential (Get-DbaComputerSystem/-OperatingSystem etc. don't) and the caller
      // hasn't already supplied one explicitly in params. The password itself never
      // appears in $req/$p — only the already-built PSCredential object reference does.
      "    if ($script:__sqlCred -and -not $p.ContainsKey('SqlCredential')) {",
      "      $__cmdInfo = Get-Command $req.cmd -ErrorAction SilentlyContinue",
      "      if ($__cmdInfo -and $__cmdInfo.Parameters.ContainsKey('SqlCredential')) { $p['SqlCredential'] = $script:__sqlCred }",
      "    }",
      "    $out = @(& $req.cmd @p)",
      // Optional server-side column narrowing: some cmdlets (Get-DbaDatabase et al.) return a
      // full SMO object with ~200 properties, including nested collections (Tables, Views,
      // StoredProcedures, ...). Narrowing has to happen HERE, before ConvertTo-PlainRows walks
      // the object graph, or the flattening cost (and the oversized payload) is already paid.
      // $req.select is an optional string array of property names; Select-Object -Property
      // builds a shallow projection object per row that ConvertTo-PlainRows then flattens as
      // usual. A name with no matching property is simply set to $null (Select-Object does not
      // throw), so a caller-side typo degrades to a missing field rather than an error here.
      "    if ($req.select) { $out = @($out | Select-Object -Property @($req.select)) }",
      "    $resp = [pscustomobject]@{ id = $req.id; ok = $true; rows = (ConvertTo-PlainRows $out) }",
      "  } catch {",
      "    $resp = [pscustomobject]@{ id = $req.id; ok = $false; error = $_.Exception.Message }",
      "  }",
      // Defense in depth: ConvertTo-PlainRows above already keeps normal cmdlet output out of
      // ConvertTo-Json's way, but if serialization somehow still fails, that must degrade to a
      // per-call error response (like any other failure above) rather than a terminating error
      // that takes the whole worker down with every other in-flight call.
      "  try {",
      "    [Console]::Out.WriteLine(($resp | ConvertTo-Json -Compress -Depth 8))",
      "  } catch {",
      "    $fallback = [pscustomobject]@{ id = $req.id; ok = $false; error = ('response serialization failed: ' + $_.Exception.Message) }",
      "    [Console]::Out.WriteLine(($fallback | ConvertTo-Json -Compress))",
      "  }",
      "}",
    ].filter(Boolean).join("\n");

    // `-Command -` reads its ENTIRE stdin as script text before executing anything, so
    // any request lines written after the boot script are consumed as more "script" and
    // never reach the running loop's Console.In.ReadLine() (confirmed empirically: the
    // process exits at EOF having printed nothing). Writing the boot script to a file and
    // using `-File` instead leaves stdin free for the executing script to read live, which
    // is what the newline-JSON request/response framing requires.
    const bootDir = mkdtempSync(join(tmpdir(), "pwsh-worker-"));
    const bootPath = join(bootDir, `${randomUUID()}.ps1`);
    writeFileSync(bootPath, boot, "utf8");

    const pwshExe = resolvePwshExe();
    const proc = spawn(pwshExe, ["-NoProfile", "-NonInteractive", "-File", bootPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => this.onData(chunk));
    // A write against a pipe whose reader is already gone (killed process, or one that
    // died on its own) raises EPIPE as an `error` event. Node treats an unhandled
    // `error` event as fatal - without this listener it becomes an uncaughtException
    // that takes down the whole server, exactly the outage the supervisor exists to
    // prevent. call()'s own try/catch around the write covers the synchronous throw;
    // this covers the stream's own async error event. The failure is still surfaced:
    // the process's "exit" event fires regardless and onExit() rejects whatever of
    // its own pending calls are left.
    proc.stdin.on("error", () => { /* handled via the pending map on exit */ });
    // Same class of bug as the stdin EPIPE guard above, on the other two std streams:
    // an unhandled `error` event on ANY stream of a ChildProcess is fatal to the whole
    // Node process (e.g. EIO/ECONNRESET on the Windows pipe when the timeout path below
    // calls proc.kill()). The failure is still surfaced normally - the process's "exit"
    // event fires regardless and settle() rejects whatever of its own pending calls
    // are left - these listeners exist purely so the stream-level error itself can never
    // crash the server.
    proc.stdout.on("error", () => { /* handled via the pending map on exit */ });
    proc.stderr.on("error", () => { /* handled via the pending map on exit */ });
    // stderr MUST be drained - this is not optional bookkeeping, do not "simplify" this
    // listener away. Nothing else ever reads this stream, and an OS pipe has a bounded
    // buffer (64KB on Windows): a child that writes enough to stderr without a reader
    // blocks on its next write to it, forever - and since it's now blocked, it never gets
    // back around to reading stdin or writing stdout either, wedging every future call()
    // against this worker. dbatools writes warnings constantly (Write-Message/
    // Stop-Function), and `-File` mode (used below) routes the warning/error/verbose
    // streams to stderr, so this fills up over the worker's entire lifetime, not just on
    // one bad call - a slow-fuse hang, not a one-off. A bounded tail (not the whole
    // stream) is kept per-process so a failure like a broken `Import-Module dbatools`
    // enriches the resulting error instead of surfacing only as "pwsh worker exited".
    const stderrState = { tail: "" };
    this.stderrTails.set(proc, stderrState);
    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      stderrState.tail = (stderrState.tail + chunk).slice(-PwshWorker.STDERR_TAIL_MAX);
    });
    // bootDir belongs to this exact process instance (not instance state), so a
    // restart can never leak or double-clean another generation's temp directory.
    proc.on("exit", () => this.onExit(proc, bootDir));
    // A process that never starts (missing pwsh, EACCES, ...) emits 'error', not
    // 'exit' - Node treats an unhandled 'error' event on a ChildProcess as fatal to
    // the whole process, same class of bug as the stdin EPIPE above. The per-call
    // helper this worker replaced already guarded this (dbatools.ts's runPowerShell,
    // `ps.on("error", ...)`); losing it here would turn "pwsh/dbatools not installed
    // on this host" - the first thing a real operator is likely to hit under
    // DBATOOLS_FIRST - into an outage instead of the documented DMV-fallback
    // degradation. Route it through the same reject-pending-and-clean-up path as a
    // normal exit so withFallback() sees an ordinary rejection.
    proc.on("error", (e) => this.onSpawnError(proc, bootDir, pwshExe, e));
    this.proc = proc;
  }

  private onData(chunk: string): void {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      let msg: { id?: number; ok?: boolean; rows?: unknown; error?: string };
      try { msg = JSON.parse(line); } catch { continue; }
      if (typeof msg.id !== "number") continue;
      const p = this.pending.get(msg.id);
      if (!p) continue;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.ok) {
        // A completed call proves the worker is healthy again - without this, a
        // long-running server that merely restarts maxRestarts times over its whole
        // life (each restart separated by weeks of normal successful calls) is bricked
        // for good, contradicting the "max CONSECUTIVE restarts" doc comment on the
        // field itself.
        this.restarts = 0;
        p.resolve(msg.rows === null || msg.rows === undefined ? [] : ([] as unknown[]).concat(msg.rows as never));
      } else {
        p.reject(new Error(msg.error ?? "pwsh worker reported an error with no message"));
      }
    }
  }

  // A dead worker must fail every in-flight call that was actually sent to IT. Left
  // pending they would hang until their own timeouts, one by one, which looks like a
  // slow server rather than a crash. This can fire for a process that a timeout or
  // stop() already disowned (this.proc has moved on to a replacement, or to null) -
  // in that case only this process's own temp dir is cleaned up and its own
  // stragglers in `pending` are rejected; the live worker's bookkeeping is untouched.
  private onExit(deadProc: ChildProcessWithoutNullStreams, bootDir: string): void {
    this.settle(deadProc, bootDir, "pwsh worker exited");
  }

  // A process that fails to launch at all (bad executable, EACCES, ...) never gets an
  // "exit" - only "error". Same accounting as onExit (bootDir cleanup, restart count,
  // reject this process's own pending entries), just a message that names what was
  // actually tried, mirroring dbatools.ts's runPowerShell wording so both paths read
  // the same way to a caller/operator.
  private onSpawnError(deadProc: ChildProcessWithoutNullStreams, bootDir: string, pwshExe: string, e: Error): void {
    this.settle(deadProc, bootDir, `Failed to launch '${pwshExe}': ${e.message}`);
  }

  // Shared by onExit() and onSpawnError(): a process instance (successfully started or
  // not) is done, for good, and every request that was actually sent to it must be
  // rejected - never left to hang until its own timeout looks like a slow server
  // rather than a crash.
  private settle(deadProc: ChildProcessWithoutNullStreams, bootDir: string, baseMessage: string): void {
    try { rmSync(bootDir, { recursive: true, force: true }); } catch { /* best effort */ }

    // Only bump the restart counter/null the slot if this was still the active
    // process - a timeout handler that already killed-and-disowned it (or stop())
    // has already accounted for that transition itself.
    if (this.proc === deadProc) {
      this.proc = null;
      this.restarts += 1;
    }

    const suffix = this.formatStderrSuffix(deadProc);
    const err = this.restarts > this.opts.maxRestarts
      ? new Error(`pwsh worker failed to stay up after ${this.opts.maxRestarts} restarts${suffix}`)
      : new Error(`${baseMessage}${suffix}`);
    for (const [id, p] of this.pending) {
      if (p.proc !== deadProc) continue;
      clearTimeout(p.timer);
      p.reject(err);
      this.pending.delete(id);
    }
  }

  // Renders the given process's captured stderr tail (see stderrTails above) as a
  // message suffix, or "" when nothing was ever written to it - so a call that never
  // touched stderr keeps a clean, unadorned error message.
  private formatStderrSuffix(proc: ChildProcessWithoutNullStreams): string {
    const tail = this.stderrTails.get(proc)?.tail.trim();
    return tail ? ` (stderr: ${tail})` : "";
  }

  // `select`, when given, is a list of property names applied server-side (see the boot
  // script's `$req.select` handling above) BEFORE the result is flattened — narrowing a
  // wide SMO object at the source, in the worker, rather than in the caller after the
  // full object has already been paid for.
  async call(cmd: string, params: Record<string, unknown> = {}, timeoutSec?: number, select?: string[]): Promise<unknown[]> {
    if (!this.proc) await this.start();
    const proc = this.proc;
    if (!proc) throw new Error("pwsh worker is not running");
    if (this.pending.size >= this.opts.maxQueue) {
      throw new Error(`pwsh worker queue full (${this.opts.maxQueue} outstanding)`);
    }
    const id = this.nextId++;
    const limit = (timeoutSec ?? this.opts.timeoutSec) * 1000;
    return new Promise<unknown[]>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // Kill rather than abandon: a cmdlet that hung once will hang the next caller
        // too, and a half-consumed stdout stream would desynchronise the framing.
        try { proc.kill(); } catch { /* already gone */ }
        // Disown it now rather than waiting for the (async) "exit" event: otherwise a
        // call() made in the window between kill() and that event would see `this.proc`
        // still set and write its request into a process that is already dying and will
        // never answer. onExit() still runs later, purely to clean up this process's own
        // temp dir and reject any of its own pending entries.
        if (this.proc === proc) {
          this.proc = null;
          this.restarts += 1;
        }
        reject(new Error(`pwsh call '${cmd}' timed out after ${limit / 1000}s${this.formatStderrSuffix(proc)}`));
      }, limit);
      this.pending.set(id, { resolve, reject, timer, proc });
      // A write can throw synchronously (e.g. the pipe already destroyed) in addition
      // to raising an async `error` event (handled where stdin is wired up in start()).
      // Catch that here so it rejects this one call instead of propagating out of
      // call() as an unhandled exception.
      try {
        proc.stdin.write(JSON.stringify({ id, cmd, params, ...(select && select.length ? { select } : {}) }) + "\n");
      } catch (e) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(new Error(`pwsh worker stdin is closed: ${(e as Error).message}`));
        return;
      }
    });
  }

  async stop(): Promise<void> {
    const proc = this.proc;
    if (!proc) return;
    this.proc = null;
    try { proc.stdin.end(); } catch { /* already gone */ }
    proc.kill();
  }
}
