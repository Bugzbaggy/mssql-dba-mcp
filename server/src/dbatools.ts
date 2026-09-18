import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { listInstances, DEFAULT_INSTANCE, InstanceConfig, queryInstance } from "./connectionManager.js";
import { PwshWorker } from "./pwshWorker.js";

// ─────────────────────────────────────────────────────────────────────────────
// dbatools / PowerShell bridge for the sql-dba (DBA) profile — STRICTLY READ-ONLY.
//
//   run_health_check        : a self-contained, dbatools-only health check across
//                             Availability, Performance, Recoverability, Reliability,
//                             Security, Configuration, Maintenance AND Host/OS
//                             (power plan, disk, firewall, computer/OS). No external
//                             suite — every check is a read-only dbatools cmdlet.
//   run_dbatools_command    : one ad-hoc read-only dbatools cmdlet
//   list_dbatools_commands  : discover read-only dbatools cmdlets
//   check_dbatools_environment
//
// Read-only is enforced by a hard allowlist: only Get-/Test-/Measure-/Find-Dba*
// (plus Invoke-DbaDiagnosticQuery) are permitted, and a denylist removes the few
// read-verb cmdlets that actually write — notably Test-DbaLastBackup, which RESTORES
// a copy of each backup to verify it. Connections use ApplicationIntent=ReadOnly.
//
// PowerShell is invoked by writing the script to a temp .ps1 and running it with
// -File (no argument is ever shell-parsed, and large scripts can't overflow the OS
// command-line length limit); results are returned as JSON via ConvertTo-Json.
// ─────────────────────────────────────────────────────────────────────────────

const log = (m: string) => console.error(m);

const PWSH = process.env.PWSH_EXE ?? (process.platform === "win32" ? "powershell" : "pwsh");
const CMD_TIMEOUT_S = parseInt(process.env.DBATOOLS_TIMEOUT_SECONDS ?? "120", 10);
const HC_TIMEOUT_S = parseInt(process.env.HEALTHCHECK_TIMEOUT_SECONDS ?? "1800", 10);
// Per-query, per-cmdlet and connect ceilings so a single slow/hanging check can't consume
// the whole budget (the cause of remote nodes blowing the overall timeout).
//   HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS  bounds a single SQL statement on the shared SMO
//                                          connection. Doesn't bound a *cmdlet* that runs
//                                          many statements (e.g. Find-DbaDbUnusedIndex
//                                          iterates every database).
//   HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS  bounds the WALL-CLOCK of each catalog cmdlet.
//                                          The cmdlet runs in a worker runspace (dbatools
//                                          preloaded once); on timeout the runspace is
//                                          Stop()'d, the check errors as 'error', and the
//                                          run continues. Set to 0 to disable wrapping
//                                          (falls back to the per-statement timeout only).
//   HEALTHCHECK_CONNECT_TIMEOUT_SECONDS    caps Connect-DbaInstance so a dead node fails fast.
const HC_STMT_TIMEOUT_S = parseInt(process.env.HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS ?? "60", 10);
const HC_PER_CHECK_TIMEOUT_S = parseInt(process.env.HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS ?? "120", 10);
const HC_CONNECT_TIMEOUT_S = parseInt(process.env.HEALTHCHECK_CONNECT_TIMEOUT_SECONDS ?? "15", 10);
// PowerShell stdout cap. Rows are flattened to scalars (small), but raise/lower via
// DBATOOLS_MAX_OUTPUT_MB if a very wide check ever approaches the limit.
const MAX_BUFFER_BYTES = parseInt(process.env.DBATOOLS_MAX_OUTPUT_MB ?? "64", 10) * 1024 * 1024;
const DEFAULT_DB = process.env.DEFAULT_DATABASE ?? "AppCatalog";
// Where run_health_check writes its self-contained HTML report. Defaults to the OS
// temp dir; set HEALTHCHECK_REPORT_DIR to keep reports somewhere durable.
const REPORT_DIR = process.env.HEALTHCHECK_REPORT_DIR ?? tmpdir();

// Per-user: the health check runs under the caller's OWN login (HEALTHCHECK_SQL_USER,
// else SQL_USER) — never a shared service account. That login must hold read-only DBA
// rights (VIEW SERVER STATE + read). Empty ⇒ Windows auth as the current user.
const HC_USER = process.env.HEALTHCHECK_SQL_USER ?? process.env.SQL_USER ?? "";
const HC_PASS = process.env.HEALTHCHECK_SQL_PASSWORD ?? process.env.SQL_PASSWORD ?? "";
// Optional Windows credential for the OS/CIM checks (power plan, disk, firewall,
// computer/OS). If unset, those checks run as the MCP host's own identity.
const HC_WIN_USER = process.env.HEALTHCHECK_WIN_USER ?? "";
const HC_WIN_PASS = process.env.HEALTHCHECK_WIN_PASSWORD ?? "";
// Run the Host/OS checks (power plan, disk, firewall, computer/OS) against the LOCAL machine
// under the current process identity — for the on-server scheduled job, where the SQL Agent
// service account already has local rights. No explicit Windows credential needed; the checks
// run (not "skipped") and target $env:COMPUTERNAME. Set HEALTHCHECK_OS_LOCAL=1 in that job.
const HC_OS_LOCAL = process.env.HEALTHCHECK_OS_LOCAL === "1";

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };
const ok = (v: unknown): ToolResult => ({ content: [{ type: "text", text: JSON.stringify(v, null, 2) }] });
const err = (m: string): ToolResult => ({ content: [{ type: "text", text: `Error: ${m}` }], isError: true });

// ── Read-only command allowlist ──────────────────────────────────────────────
const READONLY_DBA = /^(Get|Test|Measure|Find)-Dba[A-Za-z0-9]+$/;
const EXTRA_ALLOWED = new Set(["Invoke-DbaDiagnosticQuery"]); // purely read (Glenn Berry DMV queries)
// Read-verb cmdlets that actually WRITE — rejected even though they match the regex.
// Test-DbaLastBackup restores each backup to a temp database to verify it (a write).
const DENY = new Set<string>(["Test-DbaLastBackup"]);
const PROP_RE = /^[A-Za-z][A-Za-z0-9]*$/;

// Hard policy (defense-in-depth): the MCP must NEVER change a login or other server
// principal — disable/enable/alter/create/drop. Such cmdlets (Set-/Disable-/Enable-/
// New-/Remove-/Rename-DbaLogin, *DbaUser, *DbaCredential, *DbaDbRole…) already fail the
// read-verb allowlist below, but we reject them FIRST with an explicit policy message so
// the prohibition is self-documenting and cannot be loosened by accident.
const FORBIDDEN_PRINCIPAL_CMD =
  /^(Set|Disable|Enable|New|Remove|Add|Rename|Grant|Revoke)-Dba(Login|User|Credential|.*Role.*|ServerRole.*)/i;

function assertReadOnlyCommand(name: string): void {
  if (FORBIDDEN_PRINCIPAL_CMD.test(name)) {
    throw new Error(`Command "${name}" is STRICTLY FORBIDDEN: the MCP is read-only and must never enable, disable, create, drop, or alter a SQL login or principal. This is a hard policy, not a permission prompt — make login/principal changes outside this tool.`);
  }
  if (DENY.has(name)) {
    throw new Error(`Command "${name}" is blocked: it writes (restores a backup copy). Use Get-DbaLastBackup for read-only backup history.`);
  }
  if (!READONLY_DBA.test(name) && !EXTRA_ALLOWED.has(name)) {
    throw new Error(
      `Command "${name}" is not allowed. Only read-only dbatools cmdlets are permitted: ` +
      `Get-/Test-/Measure-/Find-Dba* (and Invoke-DbaDiagnosticQuery).`
    );
  }
}

// One worker for the whole process. Created on first use so a server that never calls a
// dbatools tool never pays the module import.
let _worker: PwshWorker | null = null;

/**
 * The single entry point for every dbatools-backed tool.
 *
 * assertReadOnlyCommand runs FIRST and unconditionally: the guarantee this server makes
 * is that it cannot mutate, and that guarantee has to hold before anything reaches a
 * shell. Routing a call around this function defeats it.
 */
// `select`, when given, narrows the cmdlet's output to just those property names
// BEFORE it is flattened for the wire (see PwshWorker.call) — for a cmdlet like
// Get-DbaDatabase that returns a ~200-property SMO object including nested
// collections (Tables, Views, StoredProcedures, ...), this keeps that cost out of
// both the worker's flattening pass and the JSON payload, instead of fetching
// everything and trimming it back down in TypeScript after the fact.
export async function callDbatools(
  cmd: string,
  params: Record<string, unknown> = {},
  timeoutSec?: number,
  select?: string[],
): Promise<unknown[]> {
  assertReadOnlyCommand(cmd);
  if (!_worker) _worker = new PwshWorker({ importDbatools: true });
  return _worker.call(cmd, params, timeoutSec, select);
}

// Temp script files are tracked so a crash/termination between spawn and close still
// removes them (the per-call cleanup runs on close/error; this is the backstop).
const _activeScripts = new Set<string>();
function _cleanupAllScripts() { for (const p of _activeScripts) { try { unlinkSync(p); } catch { /* best effort */ } } _activeScripts.clear(); }
for (const sig of ["exit", "SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => { _cleanupAllScripts(); if (sig !== "exit") process.exit(0); });
}

// ── PowerShell runner ─────────────────────────────────────────────────────────
// The script is written to a temp .ps1 and run with -File. We do NOT pass it as a
// -EncodedCommand / -Command argument: the health-check script (one try/catch per
// catalog entry) is large, and as a single argument its Base64 form overflows the
// OS command-line length limit (Windows ~32 KB) → spawn fails with ENAMETOOLONG
// before PowerShell ever starts. A file path argument is always short, so this
// removes the size cap for every dbatools call. No script text is ever shell-parsed.
//
// SECRETS: passwords are NEVER written into the script body. They are passed to the
// child process's environment (extraEnv) and the script reads them via $env:... — so
// the temp file on disk contains no credentials (an AV/EDR scan or a leftover file
// after a crash exposes nothing sensitive). A process's env block is not readable by
// other non-privileged processes.
function runPowerShell(
  script: string,
  timeoutSec: number,
  extraEnv?: Record<string, string>
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    let scriptPath: string;
    try {
      scriptPath = join(tmpdir(), `appdb-dbatools-${randomBytes(8).toString("hex")}.ps1`);
      // UTF-8 BOM so PowerShell (incl. 5.1) decodes any non-ASCII correctly.
      writeFileSync(scriptPath, "﻿" + script, { encoding: "utf8" });
      _activeScripts.add(scriptPath);
    } catch (e) {
      reject(new Error(`Could not write temp PowerShell script: ${(e as Error).message}`));
      return;
    }
    const cleanup = () => { _activeScripts.delete(scriptPath); try { unlinkSync(scriptPath); } catch { /* best effort */ } };

    const ps = spawn(
      PWSH,
      ["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath],
      { shell: false, env: extraEnv ? { ...process.env, ...extraEnv } : process.env }
    );
    let stdout = "", stderr = "", total = 0, settled = false;
    const fail = (e: Error) => { if (!settled) { settled = true; ps.kill("SIGKILL"); cleanup(); reject(e); } };
    const timer = setTimeout(() => fail(new Error(`PowerShell timed out after ${timeoutSec}s`)), timeoutSec * 1000);
    const onData = (buf: Buffer, sink: "out" | "err") => {
      total += buf.length;
      if (total > MAX_BUFFER_BYTES) { clearTimeout(timer); fail(new Error("PowerShell output exceeded 25 MB")); return; }
      if (sink === "out") stdout += buf.toString(); else stderr += buf.toString();
    };
    ps.stdout.on("data", (b: Buffer) => onData(b, "out"));
    ps.stderr.on("data", (b: Buffer) => onData(b, "err"));
    ps.on("close", (code) => { clearTimeout(timer); if (!settled) { settled = true; cleanup(); resolve({ stdout, stderr, exitCode: code ?? 1 }); } });
    ps.on("error", (e) => { clearTimeout(timer); fail(new Error(`Failed to launch '${PWSH}': ${e.message}`)); });
  });
}

const sq = (v: string) => v.replace(/'/g, "''"); // single-quote escape for PS string literals

// dbatools cmdlets return rich SMO-backed objects. Passing them straight to
// ConvertTo-Json blows up — it recurses into lazy navigation properties (e.g.
// Server.Settings.OleDbProviderSettings) that throw or self-reference on
// enumeration. This helper flattens each row to a shallow object of scalar values
// (complex/unreadable properties are ToString'd or marked) so serialization is
// safe and bounded. Status/row-count are still computed from the raw objects.
const PS_SANITIZER = [
  `function ConvertTo-PlainRows($rows) {`,
  `  if ($null -eq $rows) { return @() }`,
  `  @($rows) | ForEach-Object {`,
  `    $row = $_`,
  `    if ($null -eq $row) { return }`,
  `    if (($row -is [string]) -or ($row -is [valuetype])) { return ,$row }`,
  `    $o = [ordered]@{}`,
  `    foreach ($p in $row.PSObject.Properties) {`,
  `      try {`,
  `        $val = $p.Value`,
  `        if ($null -eq $val) { $o[$p.Name] = $null }`,
  `        elseif (($val -is [string]) -or ($val -is [bool]) -or ($val -is [int]) -or ($val -is [int64]) -or ($val -is [double]) -or ($val -is [decimal])) { $o[$p.Name] = $val }`,
  `        elseif ($val -is [datetime]) { $o[$p.Name] = $val.ToString('o') }`,
  `        elseif ($val.GetType().IsEnum) { $o[$p.Name] = $val.ToString() }`,
  `        else { $o[$p.Name] = [string]$val }`,
  `      } catch { $o[$p.Name] = '<unreadable>' }`,
  `    }`,
  `    [pscustomobject]$o`,
  `  }`,
  `}`,
].join("\n");

function resolveInstance(name?: string): InstanceConfig {
  const target = name ?? DEFAULT_INSTANCE;
  const cfg = listInstances().find((i) => i.name === target);
  if (!cfg) throw new Error(`Unknown instance "${target}". Call list_instances for available names.`);
  return cfg;
}

// Read-only Connect-DbaInstance preamble using the caller's own SQL login (or Windows
// auth when SQL_USER is empty). Used by run_dbatools_command.
function connectBlock(cfg: InstanceConfig): string {
  // On-box scheduled report (HEALTHCHECK_OS_LOCAL=1): connect to the LOCAL instance by COMPUTER
  // NAME (Shared Memory) — NOT the node's own routable IP. A TCP loopback to the box's own IP under
  // a domain service account trips the Windows loopback NTLM check and is rejected as anonymous/
  // untrusted (SQL 18452 "the login is from an untrusted domain"; seen on a secondary region). The machine name
  // resolves via Shared Memory (no network auth), so local Windows auth always works. NB: '(local)'
  // is NOT a valid dbatools DbaInstanceParameter — use $env:COMPUTERNAME. Remote/interactive runs
  // (HEALTHCHECK_OS_LOCAL unset) still use the fleet host:port.
  const sqlInstance = `${cfg.host},${cfg.port}`;
  const sqlInstanceArg = HC_OS_LOCAL ? "$env:COMPUTERNAME" : `'${sq(sqlInstance)}'`;
  const user = process.env.SQL_USER ?? "";
  // Set the runtime config (no -Scope: older dbatools' Set-DbatoolsConfig has no
  // -Scope parameter, and the default scope is already the current runtime).
  const lines = [`Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null`];
  const args = [
    `-SqlInstance ${sqlInstanceArg}`,
    `-Database '${sq(cfg.database ?? DEFAULT_DB)}'`,
    `-ApplicationIntent ReadOnly`,
    `-TrustServerCertificate`,
  ];
  if (user) {
    // Password read from the child-process env ($env:APPDB_SQL_PASSWORD), never written
    // into the script body / temp file. The caller passes it via runPowerShell(extraEnv).
    lines.push(
      `$__sp = ConvertTo-SecureString $env:APPDB_SQL_PASSWORD -AsPlainText -Force`,
      `$__cred = New-Object System.Management.Automation.PSCredential('${sq(user)}', $__sp)`
    );
    args.push(`-SqlCredential $__cred`);
  }
  lines.push(`$server = Connect-DbaInstance ${args.join(" ")}`);
  return lines.join("\n");
}

// Build the PowerShell prologue/epilogue that gives the script access to a host's
// C$ admin share. The prologue sets $hostC to a path the rest of the script can
// Join-Path against — either a PSDrive root (X:\) when we mount with a credential,
// or a bare UNC (\\host\C$) when we don't. Credential precedence on the MCP host:
//   1) HEALTHCHECK_WIN_USER/PASSWORD env vars → explicit credential, mount PSDrive.
//   2) Windows Credential Manager — CredRead is called at runtime for the target:
//        a) Generic-type cred (cmdkey /generic:<target> /user:... /pass:...) →
//           extract user+password and mount PSDrive with a PSCredential.
//        b) Domain-type cred (cmdkey /add:<target> /user:... /pass:...) → the
//           password blob is held by LSA and not user-readable; SMB auto-binds
//           it transparently, so we fall through to bare UNC for this case.
//   3) No stored credential → bare UNC under the MCP process identity (works if
//      the MCP host's account already has admin rights on the target).
// The prologue sets $__credSource ('env' | 'cred-manager' | 'cred-manager-domain-autobind'
// | 'mcp-identity') so the caller's failure message can name which path ran.
// Drive name has a random suffix so concurrent calls don't collide; epilogue
// removes it in `finally`.
//
// Back-compat: also sets $reportsPath = "$hostC\Windows\Cluster\Reports" so existing
// callers (read_cluster_reports) keep working unchanged. New tools should use $hostC.
function buildHostAccess(target: string): {
  prologue: string;
  epilogue: string;
  extraEnv?: Record<string, string>;
} {
  const drive = `AppDbCl${Math.floor(Math.random() * 1e9).toString(36)}`;
  const epilogue = `Remove-PSDrive -Name '${drive}' -Force -ErrorAction SilentlyContinue`;
  const root = `\\\\${sq(target)}\\C$`;

  if (HC_WIN_USER && HC_WIN_PASS) {
    return {
      prologue: [
        `$__credSource = 'env'`,
        `$__wsp = ConvertTo-SecureString $env:APPDB_HC_WIN_PASSWORD -AsPlainText -Force`,
        `$__wincred = New-Object System.Management.Automation.PSCredential('${sq(HC_WIN_USER)}', $__wsp)`,
        `New-PSDrive -Name '${drive}' -PSProvider FileSystem -Root '${root}' -Credential $__wincred -ErrorAction Stop | Out-Null`,
        `$hostC = '${drive}:\\'`,
        `$reportsPath = (Join-Path $hostC 'Windows\\Cluster\\Reports')`,
      ].join("\n"),
      epilogue,
      extraEnv: { APPDB_HC_WIN_PASSWORD: HC_WIN_PASS },
    };
  }

  // CredRead probe — looks up a cmdkey-stored entry under the MCP-user's profile.
  // Tries type 1 (CRED_TYPE_GENERIC) first so we get a user-readable password
  // blob when one exists; falls back to type 2 (CRED_TYPE_DOMAIN_PASSWORD) which
  // returns username only (LSA hides the password — Windows binds it for SMB).
  const credLookup = [
    `Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'`,
    `using System;`,
    `using System.Runtime.InteropServices;`,
    `public static class AppDbCred {`,
    `  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]`,
    `  public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credPtr);`,
    `  [DllImport("advapi32.dll", SetLastError=true)]`,
    `  public static extern bool CredFree(IntPtr cred);`,
    `  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]`,
    `  public struct NativeCred {`,
    `    public uint Flags; public uint Type; public string TargetName; public string Comment;`,
    `    public long LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob;`,
    `    public uint Persist; public uint AttributeCount; public IntPtr Attributes;`,
    `    public string TargetAlias; public string UserName;`,
    `  }`,
    `}`,
    `'@`,
    `function Read-AppDbCred([string]$t) {`,
    `  foreach ($type in 1,2) {`,
    `    $p = [IntPtr]::Zero`,
    `    if ([AppDbCred]::CredRead($t, $type, 0, [ref]$p)) {`,
    `      $nc = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type][AppDbCred+NativeCred])`,
    `      $user = $nc.UserName`,
    `      $blobSize = [int]$nc.CredentialBlobSize`,
    `      $pwd = $null`,
    `      if ($blobSize -gt 0 -and $nc.CredentialBlob -ne [IntPtr]::Zero) {`,
    `        $bytes = New-Object byte[] $blobSize`,
    `        [System.Runtime.InteropServices.Marshal]::Copy($nc.CredentialBlob, $bytes, 0, $blobSize)`,
    `        $pwd = [System.Text.Encoding]::Unicode.GetString($bytes)`,
    `      }`,
    `      [AppDbCred]::CredFree($p) | Out-Null`,
    `      return [pscustomobject]@{ Type=$type; User=$user; Pwd=$pwd }`,
    `    }`,
    `  }`,
    `  return $null`,
    `}`,
  ].join("\n");

  return {
    prologue: [
      credLookup,
      `$__cm = Read-AppDbCred '${sq(target)}'`,
      `if ($__cm -and $__cm.Pwd -and $__cm.User) {`,
      `  $__credSource = 'cred-manager'`,
      `  $__wsp = ConvertTo-SecureString $__cm.Pwd -AsPlainText -Force`,
      `  $__wincred = New-Object System.Management.Automation.PSCredential($__cm.User, $__wsp)`,
      `  New-PSDrive -Name '${drive}' -PSProvider FileSystem -Root '${root}' -Credential $__wincred -ErrorAction Stop | Out-Null`,
      `  $hostC = '${drive}:\\'`,
      `} elseif ($__cm) {`,
      `  $__credSource = 'cred-manager-domain-autobind'`,
      `  $hostC = '${root}\\'`,
      `} else {`,
      `  $__credSource = 'mcp-identity'`,
      `  $hostC = '${root}\\'`,
      `}`,
      `$reportsPath = (Join-Path $hostC 'Windows\\Cluster\\Reports')`,
    ].join("\n"),
    epilogue,
  };
}

// Backwards-compat alias — existing tools call buildClusterAccess.
const buildClusterAccess = buildHostAccess;

// ─────────────────────────────────────────────────────────────────────────────
// Health-check catalog — every entry is a read-only dbatools cmdlet.
//   target: 'sql' → -SqlInstance $server
//           'os'  → -ComputerName $computer  (+ optional Windows -Credential)
//           'fw'  → -SqlInstance $server     (+ optional Windows -Credential; CIM)
// ─────────────────────────────────────────────────────────────────────────────
// [category, label, command, target, extra, priority, evalPs?]
//   target   — 'sql' → -SqlInstance $server · 'os' → -ComputerName $osComputer (+Win cred)
//              'fw' → -SqlInstance $server (+Win cred) · 'dmv' → Invoke-DbaQuery with the
//              read-only SELECT in `extra` (works over the SQL login alone — no WinRM —
//              the fallback for disk/OS/service-account when WinRM/CIM can't reach the node).
//   priority — High | Medium | Low (severity weight for the agent to rank by)
//   evalPs   — optional PowerShell expression over $d (the result rows) returning
//              'pass' | 'attention' | 'fail'. Evaluated defensively (any error or an
//              unexpected shape falls back to 'ok'); checks without one report 'ok'
//              when rows are returned, 'empty' when none, 'error' on failure.
type Check = [category: string, label: string, command: string, target: "sql" | "os" | "fw" | "dmv", extra: string, priority: "High" | "Medium" | "Low", evalPs?: string];
export const CATALOG: Check[] = [
  ["Availability", "Availability groups",     "Get-DbaAvailabilityGroup", "sql", "", "High"],
  ["Availability", "AG replica health",       "Get-DbaAgReplica",         "sql", "", "High"],
  ["Availability", "Databases & state",       "Get-DbaDatabase",          "sql", "", "High",
    "if ($d | Where-Object { $_.AutoShrink -or $_.AutoClose }) {'attention'} else {'pass'}"],
  // FAIL when an ENABLED job's most recent run ended in Failure (a broken backup / integrity /
  // linked-server job is exactly what a weekly report must surface — was Info-only before).
  ["Availability", "SQL Agent jobs",          "Get-DbaAgentJob",          "sql", "", "Medium",
    "if (@($d | ?{ $_.Enabled -ne $false -and \"$($_.LastRunOutcome)\" -eq 'Failed' }).Count) {'fail'} else {'pass'}"],
  ["Availability", "Database free space",     "Get-DbaDbSpace",           "sql", "", "Medium"],
  // AG data movement — grades the LOCAL replica's per-DB synchronization state + queues (the two
  // AG checks above are Info inventory only). FAIL on a suspended / NOT SYNCHRONIZING database;
  // ATTENTION on a large redo backlog (a secondary applying log slower than it arrives).
  // Non-AG instances return no rows -> Info.
  ["Availability", "AG data movement",        "Invoke-DbaQuery",          "dmv",
    "SELECT ag.name AS AG, DB_NAME(drs.database_id) AS DBName, drs.synchronization_state_desc AS S, drs.is_suspended AS Suspended, drs.redo_queue_size/1024 AS RedoMB, drs.log_send_queue_size/1024 AS SendMB FROM sys.dm_hadr_database_replica_states drs JOIN sys.availability_groups ag ON ag.group_id = drs.group_id WHERE drs.is_local = 1",
    "High",
    "if (@($d | ?{ [int]$_.Suspended -eq 1 -or $_.S -eq 'NOT SYNCHRONIZING' }).Count) {'fail'} elseif (@($d | ?{ $null -ne $_.RedoMB -and [int]$_.RedoMB -gt 1024 }).Count) {'attention'} else {'pass'}"],

  ["Performance",  "Wait statistics",         "Get-DbaWaitStatistic",     "sql", "-Threshold 95", "Medium"],
  ["Performance",  "MaxDOP",                  "Test-DbaMaxDop",           "sql", "", "Medium",
    "$r=@($d)[0]; if ($r -and $null -ne $r.RecommendedMaxDop -and $r.CurrentInstanceMaxDop -ne $r.RecommendedMaxDop) {'attention'} else {'pass'}"],
  ["Performance",  "Max server memory",       "Test-DbaMaxMemory",        "sql", "", "Medium",
    "$r=@($d)[0]; if ($r -and ($r.MaxValue -ge 2147483647 -or ($r.Total -and $r.MaxValue -gt $r.Total))) {'attention'} else {'pass'}"],
  ["Performance",  "Latch statistics",        "Get-DbaLatchStatistic",    "sql", "", "Low"],
  ["Performance",  "Query Store state",       "Test-DbaDbQueryStore",     "sql", "", "Low"],

  // Backups are INFORMATIONAL (no evaluator → never scored): in this AG they're taken
  // on the backup-preferred (secondary) replica, so local backup history on any one node
  // is not a reliable health signal. The Details still list per-DB last-backup age +
  // recovery model and direct verification to the backup replica (see detailFor).
  // Backup currency is AG-aware: grade only where this node should actually back the DB up.
  // sys.fn_hadr_backup_is_preferred_replica() handles the local-AG backup preference — BUT it also
  // returns 1 on a distributed-AG FORWARDER leg (the regional primary of an ag-*-forwarder), even
  // though those DBs (AppCatalog, AppDb_Routing) are backed up on the GLOBAL PRIMARY. The distributed
  // AG object isn't visible from a forwarder region, so we key off the AG name: any DB whose local AG
  // is a '%forwarder%' leg is excluded (PreferredHere=0 -> 'ok' -> Info, NOT scored). Net: graded on
  // the global primary (ag-region1-cluster, where backups run) and on region-local AGs (ag-*-cluster); the forwarded
  // copies in ag-*-forwarder are never scored outside the global primary.
  // A FULL-recovery DB that has NEVER been log-backed (e.g. DBA / SQLAssessment left in FULL) is NOT a stale-backup Fail:
  // its full is current, so it's an Attention recovery-model smell (log won't truncate). Only a FULL DB whose EXISTING
  // log chain has gone >= 24h stale (or a missing/>=8d full) is a Fail.
  ["Recoverability", "Last backups", "Invoke-DbaQuery", "dmv",
    "SELECT d.name AS [Database], d.recovery_model_desc AS RecoveryModel, CASE WHEN drs.database_id IS NULL THEN CAST(1 AS bit) WHEN ag.name LIKE '%forwarder%' THEN CAST(0 AS bit) ELSE sys.fn_hadr_backup_is_preferred_replica(d.name) END AS PreferredHere, CONVERT(varchar(19), lf.LastFull, 120) AS LastFull, DATEDIFF(HOUR, lf.LastFull, GETDATE())/24 AS FullAgeDays, CONVERT(varchar(19), ll.LastLog, 120) AS LastLog, DATEDIFF(MINUTE, ll.LastLog, GETDATE()) AS LogAgeMin FROM sys.databases d LEFT JOIN sys.dm_hadr_database_replica_states drs ON drs.database_id=d.database_id AND drs.is_local=1 LEFT JOIN sys.availability_groups ag ON ag.group_id=drs.group_id OUTER APPLY (SELECT MAX(backup_finish_date) AS LastFull FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type IN ('D','I')) lf OUTER APPLY (SELECT MAX(backup_finish_date) AS LastLog FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='L') ll WHERE d.database_id>4 AND d.state_desc='ONLINE' AND d.source_database_id IS NULL",
    "High",
    "$g=@($d | ?{ $_.PreferredHere }); if ($g.Count -eq 0) {'ok'} else { $f=@($g | ?{ -not $_.LastFull -or [int]$_.FullAgeDays -ge 8 -or ($_.RecoveryModel -eq 'FULL' -and $_.LastLog -and [int]$_.LogAgeMin -ge 1440) }); $a=@($g | ?{ ($_.RecoveryModel -eq 'FULL' -and -not $_.LastLog) -or ($_.RecoveryModel -eq 'FULL' -and $_.LastLog -and [int]$_.LogAgeMin -ge 360 -and [int]$_.LogAgeMin -lt 1440) }); if ($f.Count) {'fail'} elseif ($a.Count) {'attention'} else {'pass'} }"],
  ["Recoverability", "Recovery model",        "Get-DbaDbRecoveryModel",   "sql", "", "Medium"],

  ["Reliability",  "Suspect pages",           "Get-DbaSuspectPage",       "sql", "", "High",
    // event_type 1/2/3 = unresolved (823 / bad checksum / torn) => fail; 4/5/7 = restored/repaired/deallocated
    // => historical only, de-prioritised to attention; none => pass.
    "$u=@($d | ?{ [int]$_.EventType -in @(1,2,3) }); if ($u.Count) {'fail'} elseif (@($d).Count) {'attention'} else {'pass'}"],
  // Access violations / fatal exceptions write SQLDump<NNNN>.txt to the Log dir. Enumerate
  // them on disk (sys.dm_os_enumerate_filesystem — authoritative; the dm_server_memory_dumps
  // DMV under-reports) across the ERRORLOG dir + the install Log dirs, last 24 hours. Any hit = FAIL.
  ["Reliability",  "Access violations / stack dumps (24h)", "Invoke-DbaQuery", "dmv",
    "DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));DECLARE @errDir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX('\\',REVERSE(@log)));;WITH cand(dir) AS (SELECT @errDir UNION SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Log' UNION SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log' UNION SELECT N'L:\\MSSQL\\ErrorLogs') SELECT CAST(f.file_or_directory_name AS nvarchar(260)) AS DumpFile, CAST(f.size_in_bytes/1024 AS bigint) AS SizeKB, CONVERT(varchar(19),f.last_write_time,120) AS LastWriteUtc FROM cand c CROSS APPLY sys.dm_os_enumerate_filesystem(c.dir,'SQLDump*.txt') f WHERE f.is_directory=0 AND f.last_write_time >= DATEADD(HOUR,-24,SYSUTCDATETIME()) ORDER BY f.last_write_time DESC",
    "High", "if (@($d | Where-Object { $_.DumpFile }).Count -gt 0) {'fail'} else {'pass'}"],
  ["Reliability",  "Last good CHECKDB",       "Get-DbaLastGoodCheckDb",   "sql", "", "High",
    // Scored on the OLDEST known clean CHECKDB across DBs (DaysSinceLastGoodCheckDb). Never-checked
    // DBs (LastGoodCheckDb year <= 2000, e.g. tempdb) are excluded from scoring but still listed in detail.
    "$x=@($d | ?{ $_.LastGoodCheckDb -ne $null -and $_.LastGoodCheckDb.Year -gt 2000 }); $mx=($x | Measure-Object -Property DaysSinceLastGoodCheckDb -Maximum).Maximum; if ($mx -ge 30) {'fail'} elseif ($mx -ge 14) {'attention'} else {'pass'}"],
  ["Reliability",  "VLF count",               "Measure-DbaDbVirtualLogFile", "sql", "", "Medium",
    "$m=($d | Measure-Object -Property Total -Maximum).Maximum; if ($m -ge 10000) {'fail'} elseif ($m -ge 1000) {'attention'} else {'pass'}"],
  ["Reliability",  "DB compatibility level",  "Test-DbaDbCompatibility",  "sql", "", "Low"],
  ["Reliability",  "Identity column capacity","Test-DbaIdentityUsage",    "sql", "", "High",
    "$m=($d | Measure-Object -Property PercentUsed -Maximum).Maximum; if ($m -ge 95) {'fail'} elseif ($m -ge 80) {'attention'} else {'pass'}"],
  ["Reliability",  "Collation drift",         "Test-DbaDbCollation",      "sql", "", "Low"],
  // Page verification — a DB on TORN_PAGE_DETECTION / NONE can't reliably detect I/O corruption on
  // read (this fleet has prior suspect pages on AppDb_Data). Returns only the offending DBs -> ATTENTION.
  ["Reliability",  "Page verify option",      "Invoke-DbaQuery",          "dmv",
    "SELECT name AS DBName, page_verify_option_desc AS PageVerify FROM sys.databases WHERE database_id > 4 AND state_desc = 'ONLINE' AND page_verify_option_desc <> 'CHECKSUM'",
    "Medium", "if (@($d).Count) {'attention'} else {'pass'}"],
  ["Reliability",  "Recent error log",        "Get-DbaErrorLog",          "sql", "-LogNumber 0", "Medium"],

  ["Security",     "Logins",                  "Get-DbaLogin",             "sql", "", "Medium"],
  ["Security",     "Connection auth scheme",  "Test-DbaConnectionAuthScheme", "sql", "", "Low"],
  ["Security",     "Server audits",           "Get-DbaInstanceAudit",     "sql", "", "Low"],
  ["Security",     "sysadmin members",        "Get-DbaServerRoleMember",  "sql", "-ServerRole sysadmin", "High",
    "if (@($d).Count -gt 5) {'attention'} else {'pass'}"],
  ["Security",     "Database owners",         "Test-DbaDbOwner",          "sql", "", "Low"],

  ["Configuration", "sp_configure",           "Get-DbaSpConfigure",       "sql", "", "Medium",
    "$bad=@($d | Where-Object { $_.Name -in @('xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries','cross db ownership chaining') -and ($_.RunningValue -eq 1 -or $_.ConfiguredValue -eq 1) }).Count; if ($bad) {'attention'} else {'pass'}"],
  ["Configuration", "Trace flags",            "Get-DbaTraceFlag",         "sql", "", "Low"],
  ["Configuration", "Optimize for ad hoc",    "Test-DbaOptimizeForAdHoc", "sql", "", "Low",
    "$r=@($d)[0]; if ($r -and $null -ne $r.RecommendedOptimizeAdHoc -and $r.CurrentOptimizeAdHoc -ne $r.RecommendedOptimizeAdHoc) {'attention'} else {'pass'}"],
  ["Configuration", "Build currency",         "Test-DbaBuild",            "sql", "-Latest", "Medium",
    "$r=@($d)[0]; if ($r -and $r.Compliant -eq $false) {'attention'} else {'pass'}"],
  // TempDB layout — a single data file on a multi-core box serializes allocation (PFS/GAM/SGAM latch
  // contention), unequal file sizes defeat proportional fill, and percent-growth files grow erratically.
  // ATTENTION on any of those. Recommended: min(cores, 8) equal-sized data files, fixed MB autogrowth.
  ["Configuration", "TempDB configuration",   "Invoke-DbaQuery",          "dmv",
    "SELECT (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0) AS DataFiles, (SELECT cpu_count FROM sys.dm_os_sys_info) AS Cores, (SELECT COUNT(DISTINCT size) FROM tempdb.sys.database_files WHERE type = 0) AS DistinctSizes, (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0 AND is_percent_growth = 1) AS PctGrowthFiles",
    "Medium",
    "$r=@($d)[0]; if ($r -and (([int]$r.DataFiles -eq 1 -and [int]$r.Cores -gt 1) -or [int]$r.DistinctSizes -gt 1 -or [int]$r.PctGrowthFiles -gt 0)) {'attention'} else {'pass'}"],

  ["Maintenance",  "Unused indexes",          "Find-DbaDbUnusedIndex",    "sql", "", "Low"],
  ["Maintenance",  "Duplicate indexes",       "Find-DbaDbDuplicateIndex", "sql", "", "Low"],

  ["Host",         "Power plan",              "Test-DbaPowerPlan",        "os", "", "Medium"],
  ["Host",         "Disk space",              "Get-DbaDiskSpace",         "os", "", "High",
    // FAIL is scoped to the SQL/OS volumes only (C: OS, B: backups, D:/E:/L:/T: data/log/tempdb) so a stray
    // small utility mount that hosts no SQL files (e.g. F:\ on some nodes) can't drive a false FAIL. Per-volume
    // FAIL threshold on those: E:\ (large data volume) under 5% free; the rest under 10%. ATTENTION is < 15% on
    // ANY volume (a full non-SQL volume is still surfaced amber, just not red).
    "$sql=@('C:','B:','D:','E:','L:','T:'); $fl=@($d | Where-Object { $null -ne $_.PercentFree -and $_.Name.Length -ge 2 -and $_.Name.Substring(0,2) -in $sql -and $_.PercentFree -lt $(if ($_.Name -like 'E:*') {5} else {10}) }).Count; $at=@($d | Where-Object { $null -ne $_.PercentFree -and $_.PercentFree -lt 15 }).Count; if ($fl) {'fail'} elseif ($at) {'attention'} else {'pass'}"],
  ["Host",         "Firewall rules",          "Get-DbaFirewallRule",      "fw", "", "Low"],
  ["Host",         "Computer system",         "Get-DbaComputerSystem",    "os", "", "Low"],
  ["Host",         "Operating system",        "Get-DbaOperatingSystem",   "os", "", "Low"],
  ["Host",         "Service account privileges (IFI/LPIM)", "Get-DbaPrivilege", "os", "", "Medium"],

  // SQL-DMV fallbacks — run over the SQL login alone (no WinRM/CIM), so disk, OS and
  // service-account facts are available even when the Windows checks above can't reach
  // the node. (Power plan and firewall have no SQL equivalent — those still need Windows.)
  // NOTE: no SQL fallback for disk space — Get-DbaDiskSpace (Host / OS, above) is authoritative
  // and the service account reads it locally on-box, so a dm_os_volume_stats duplicate just
  // produced a second identical "Disk space (SQL)" row. Removed.
  ["Host", "Service account & IFI/LPIM (SQL)", "Invoke-DbaQuery", "dmv",
    "SELECT s.servicename AS [Service], s.service_account AS [Account], s.status_desc AS [Status], s.instant_file_initialization_enabled AS [IFI], (SELECT sql_memory_model_desc FROM sys.dm_os_sys_info) AS [MemoryModel] FROM sys.dm_server_services s", "Medium",
    "$e=@($d | Where-Object { $_.Service -like 'SQL Server (*' })[0]; $att=$false; if ($e -and $e.IFI -eq 'N') {$att=$true}; if (@($d)[0].MemoryModel -eq 'CONVENTIONAL') {$att=$true}; if ($att) {'attention'} else {'pass'}"],
  ["Host", "Operating system (SQL)", "Invoke-DbaQuery", "dmv",
    "SELECT windows_release AS [WindowsRelease], windows_service_pack_level AS [ServicePack], windows_sku AS [SKU], os_language_version AS [OSLanguage] FROM sys.dm_os_windows_info", "Low"],
];
// Fail fast at load if any catalog cmdlet is not read-only. 'dmv' entries run a hardcoded,
// read-only SELECT via Invoke-DbaQuery (not user input), so they are exempt from the cmdlet
// allowlist that guards the ad-hoc command tool.
for (const [, , cmd, target] of CATALOG) if (target !== "dmv") assertReadOnlyCommand(cmd);

export function buildHealthCheckScript(cfg: InstanceConfig, useSql: boolean, rowsPerCheck: number): string {
  // On-box scheduled report (HEALTHCHECK_OS_LOCAL=1): connect to the LOCAL instance by COMPUTER
  // NAME (Shared Memory) — NOT the node's own routable IP. A TCP loopback to the box's own IP under
  // a domain service account trips the Windows loopback NTLM check and is rejected as anonymous/
  // untrusted (SQL 18452 "the login is from an untrusted domain"; seen on a secondary region). The machine name
  // resolves via Shared Memory (no network auth), so local Windows auth always works. NB: '(local)'
  // is NOT a valid dbatools DbaInstanceParameter — use $env:COMPUTERNAME. Remote/interactive runs
  // (HEALTHCHECK_OS_LOCAL unset) still use the fleet host:port.
  const sqlInstance = `${cfg.host},${cfg.port}`;
  const sqlInstanceArg = HC_OS_LOCAL ? "$env:COMPUTERNAME" : `'${sq(sqlInstance)}'`;
  const lines: string[] = [
    `Set-StrictMode -Off`,
    `$ErrorActionPreference = 'Stop'`,
    `$ProgressPreference = 'SilentlyContinue'`,
    `Import-Module dbatools -ErrorAction Stop`,
    // No -Scope: older dbatools' Set-DbatoolsConfig has no -Scope parameter (default is runtime).
    `Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null`,
    PS_SANITIZER,
  ];
  // Passwords are read from the child-process env ($env:APPDB_HC_*), never embedded in
  // the script body / temp file. run_health_check passes them via runPowerShell(extraEnv).
  let sqlCredArg = "";
  if (useSql) {
    lines.push(
      `$__sp = ConvertTo-SecureString $env:APPDB_HC_SQL_PASSWORD -AsPlainText -Force`,
      `$__cred = New-Object System.Management.Automation.PSCredential('${sq(HC_USER)}', $__sp)`
    );
    sqlCredArg = " -SqlCredential $__cred";
  }
  let winArg = "";
  if (HC_WIN_USER && HC_WIN_PASS) {
    lines.push(
      `$__wsp = ConvertTo-SecureString $env:APPDB_HC_WIN_PASSWORD -AsPlainText -Force`,
      `$__wincred = New-Object System.Management.Automation.PSCredential('${sq(HC_WIN_USER)}', $__wsp)`
    );
    winArg = " -Credential $__wincred";
  }
  // OS/CIM checks target the CONFIGURED host (port stripped) rather than the SQL
  // ComputerName. For IP/host targets this forces NTLM with the supplied -Credential,
  // which sidesteps the Kerberos/WinRM double-hop that fails when the MCP host can't
  // delegate (the common "WinRM/Kerberos to <node> failed" case). Falls back to the
  // server's ComputerName if the host is blank.
  const osHost = (cfg.host.split(",")[0] || "").trim();
  const winCred = !!(HC_WIN_USER && HC_WIN_PASS);
  lines.push(
    `$server = Connect-DbaInstance -SqlInstance ${sqlInstanceArg} -Database '${sq(cfg.database ?? DEFAULT_DB)}' -ApplicationIntent ReadOnly -TrustServerCertificate -ConnectTimeout ${HC_CONNECT_TIMEOUT_S}${sqlCredArg}`,
    // Cap each SQL query so one slow check can't consume the whole run (remote nodes).
    `try { $server.ConnectionContext.StatementTimeout = ${HC_STMT_TIMEOUT_S} } catch {}`,
    `$computer = $server.ComputerName`,
    `$osComputer = ${HC_OS_LOCAL ? "$env:COMPUTERNAME" : `$(if ('${sq(osHost)}') { '${sq(osHost)}' } else { $server.ComputerName })`}`,
    `$results = @()`,
    // ── Per-check wall-clock cap ─────────────────────────────────────────────
    // The StatementTimeout above bounds a single SQL statement, not a whole cmdlet.
    // dbatools cmdlets that iterate every database (Find-DbaDbUnusedIndex,
    // Find-DbaDbDuplicateIndex, Test-DbaIdentityUsage, etc.) run many statements per
    // cmdlet, so on a high-latency link one cmdlet can still consume the whole budget.
    // We run each check in a worker runspace (dbatools preloaded once) and Stop() it
    // when the cap fires; the check errors as 'error' and the run continues. The
    // worker is recycled after a timeout (the stopped cmdlet may have left it busy).
    // Set HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS=0 to disable wrapping (every check
    // runs inline; relies on the per-statement timeout alone).
    `$__perCheckTimeoutSec = ${HC_PER_CHECK_TIMEOUT_S}`,
    `function New-HcWorkerRunspace {`,
    `  $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()`,
    `  $iss.ImportPSModule(@('dbatools')) | Out-Null`,
    `  $rs = [runspacefactory]::CreateRunspace($iss)`,
    `  $rs.Open()`,
    `  $rs.SessionStateProxy.SetVariable('server', $server) | Out-Null`,
    `  $rs.SessionStateProxy.SetVariable('osComputer', $osComputer) | Out-Null`,
    `  if (Test-Path Variable:Script:__wincred) { $rs.SessionStateProxy.SetVariable('__wincred', $script:__wincred) | Out-Null }`,
    `  return $rs`,
    `}`,
    `$__hcWorker = $null`,
    `if ($__perCheckTimeoutSec -gt 0) { try { $__hcWorker = New-HcWorkerRunspace } catch { $__hcWorker = $null } }`,
    `function Invoke-CheckWithTimeout {`,
    `  param([scriptblock]$Action)`,
    `  if ($null -eq $script:__hcWorker) { return & $Action }`,
    `  $ps = [powershell]::Create()`,
    `  $ps.Runspace = $script:__hcWorker`,
    `  [void]$ps.AddScript($Action.ToString())`,
    `  $async = $ps.BeginInvoke()`,
    `  $completed = $async.AsyncWaitHandle.WaitOne($script:__perCheckTimeoutSec * 1000)`,
    `  if (-not $completed) {`,
    `    try { $ps.Stop() } catch {}`,
    `    try { $ps.Dispose() } catch {}`,
    `    try { $script:__hcWorker.Dispose() } catch {}`,
    `    $script:__hcWorker = $null`,
    `    try { $script:__hcWorker = New-HcWorkerRunspace } catch { $script:__hcWorker = $null }`,
    `    throw ("exceeded per-check wall-clock timeout of {0}s" -f $script:__perCheckTimeoutSec)`,
    `  }`,
    `  try { return $ps.EndInvoke($async) } catch { throw } finally { try { $ps.Dispose() } catch {} }`,
    `}`
  );
  for (const [cat, label, cmd, target, extra, priority, evalPs] of CATALOG) {
    // WinRM/CIM checks (os/fw) can't succeed without a Windows credential and may hang
    // for a long time against a remote node before failing — which is what blows the
    // overall timeout on remote regions. With no credential configured, skip them fast and rely
    // on the SQL-DMV fallbacks (disk/OS/service-account) instead of letting them hang.
    const skip = (target === "os" || target === "fw") && !winCred && !HC_OS_LOCAL;
    // 'dmv' runs a hardcoded read-only SELECT over the SQL connection (no WinRM);
    // every other target invokes the dbatools cmdlet with the right instance/host args.
    // Each cmdlet is wrapped in Invoke-CheckWithTimeout (when enabled) so its wall-clock
    // is bounded — the cmdlet name still appears verbatim in the script so the catalog
    // remains greppable, and the wrapper is a no-op when HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS=0.
    const inner = target === "dmv"
      ? `Invoke-DbaQuery -SqlInstance $server -Query '${sq(extra)}' -As PSObject -EnableException -WarningAction SilentlyContinue 3>$null | Select-Object -First ${rowsPerCheck}`
      : `${cmd} ${
          target === "sql" ? `-SqlInstance $server`
          : target === "os" ? `-ComputerName $osComputer${winArg}`
          : `-SqlInstance $server${winArg}` // fw (CIM via instance host)
        }${extra ? ` ${extra}` : ""} -EnableException -WarningAction SilentlyContinue 3>$null | Select-Object -First ${rowsPerCheck}`;
    const invoke = skip ? `$null` : `Invoke-CheckWithTimeout -Action { ${inner} }`;
    // Graded status when an evaluator is defined; otherwise ok/empty. The evaluator is
    // run defensively so an unexpected result shape degrades to 'ok' (never crashes a check).
    const statusExpr = skip
      ? `'skipped'`
      : evalPs
        ? `$(try { if ($null -eq $d) {'empty'} else { ${evalPs} } } catch { 'ok' })`
        : `$(if ($null -eq $d) {'empty'} else {'ok'})`;
    const rowsExpr = skip ? `0` : `@($d).Count`;
    lines.push(
      `try {`,
      `  $d = ${invoke}`,
      `  $results += [pscustomobject]@{ category='${cat}'; label='${sq(label)}'; command='${cmd}'; priority='${priority}'; status=${statusExpr}; rows=${rowsExpr}; data=(ConvertTo-PlainRows $d) }`,
      `} catch {`,
      `  $results += [pscustomobject]@{ category='${cat}'; label='${sq(label)}'; command='${cmd}'; priority='${priority}'; status='error'; rows=0; data=$null; error=$_.Exception.Message }`,
      `}`
    );
  }
  lines.push(
    // Tear down the worker runspace (best-effort) before emitting the JSON.
    `try { if ($null -ne $__hcWorker) { $__hcWorker.Dispose() } } catch {}`,
    `[pscustomobject]@{ instance='${sq(cfg.name)}'; computer=$computer; sqlInstance=$server.Name; checks=$results } | ConvertTo-Json -Depth 6 -Compress`
  );
  return lines.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Report model + self-contained HTML report.
//
// Mirrors the dbatools "SQL Server Instance Health Report" layout: an overall
// health % (weighted by priority), per-category health, status counts, and an
// all-findings table (Category | Label | dbatools function | Spoke | Priority |
// Status | Details). Statuses collapse to Pass / Attention / Fail / Info exactly
// as the reference report — inventory checks with no pass/fail judgement (and any
// check that could not run) are Informational and do NOT affect the score.
//   Score per check: Pass=100, Attention=60, Fail=0, weighted by priority
//   (High=3, Medium=2, Low=1). Category/overall = weighted average of scored checks.
// ─────────────────────────────────────────────────────────────────────────────
type DisplayStatus = "Pass" | "Attention" | "Fail" | "Info";
const STATUS_MAP: Record<string, DisplayStatus> = {
  pass: "Pass", attention: "Attention", fail: "Fail", ok: "Info", empty: "Info", error: "Info", skipped: "Info",
};
const PRIORITY_WEIGHT: Record<string, number> = { High: 3, Medium: 2, Low: 1 };
const SCORE_VALUE: Partial<Record<DisplayStatus, number>> = { Pass: 100, Attention: 60, Fail: 0 };
// Map label→target (label is unique; command is not, e.g. Invoke-DbaQuery for all DMV checks).
const LABEL_TARGET = new Map<string, "sql" | "os" | "fw" | "dmv">(CATALOG.map(([, label, , target]) => [label, target]));

interface RawCheck { category: string; label: string; command: string; priority?: string; status: string; rows: number; data?: unknown; error?: string; }
// A grounded, deterministic remediation for an actionable finding: a one-line summary,
// a COPY-PASTE-READY fix (T-SQL/PowerShell, with this node's real values interpolated),
// and the Microsoft Learn reference. Generated by rule (never an LLM) so it is safe and
// identical in the scheduled email and the interactive MCP output.
interface Remediation { summary: string; code?: string; lang?: "tsql" | "powershell" | "text"; docUrl?: string; }
interface Finding { category: string; label: string; command: string; spoke: string; priority: string; status: DisplayStatus; rows: number; details: string; remediation?: Remediation; }
interface CategoryScore { name: string; health: number | null; counts: Record<DisplayStatus, number>; }
interface InstanceReport { instance: string; computer?: string; sql_instance?: string; overall_health: number | null; status_counts: Record<DisplayStatus, number>; categories: CategoryScore[]; findings: Finding[]; }

const emptyCounts = (): Record<DisplayStatus, number> => ({ Pass: 0, Attention: 0, Fail: 0, Info: 0 });

// Per-check explanatory notes appended to Details for expected-by-design results.
const CHECK_NOTES: Record<string, string> = {
  "Get-DbaLastGoodCheckDb": "Note: last-known-good is read from the (replicated) boot page, so it is identical on every AG replica — a CHECKDB on a SECONDARY does NOT refresh it. To clear a stale value, run DBCC CHECKDB on the PRIMARY (a secondary run still validates that node's own physical copy).",
};

// ── Detail builders ───────────────────────────────────────────────────────────
// describe(c) reads the (scalar-flattened) rows and returns a specific, data-driven
// Detail string — naming the objects and the concrete fix — for ANY status (so even
// healthy/info rows are informative). Field names are looked up defensively; returns
// null when no useful shape is present, so detailFor falls back to a generic line.
type Row = Record<string, unknown>;
const rowsOf = (data: unknown): Row[] =>
  Array.isArray(data) ? (data as Row[]) : data && typeof data === "object" ? [data as Row] : [];
const pick = (r: Row, ...keys: string[]): unknown => {
  for (const k of keys) { const v = r[k]; if (v !== undefined && v !== null && v !== "") return v; }
  return undefined;
};
const num = (v: unknown): number => Number(v);
const ageDays = (iso: unknown): number | null => {
  if (typeof iso !== "string") return null;
  const t = Date.parse(iso); return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
};
const listOf = (items: string[], max = 6): string =>
  items.length <= max ? items.join(", ") : `${items.slice(0, max).join(", ")} +${items.length - max} more`;
const sizeStr = (v: unknown): string => (typeof v === "number" ? `${v} GB` : String(v));

// Generic fallback for informational checks with no bespoke builder: summarize the rows
// by their most identifying column (or the first row's key fields) so Details says
// something concrete instead of a bare "N row(s)".
const LABEL_KEYS = ["Database", "Name", "DatabaseName", "Login", "LoginName", "Job", "JobName",
  "ServiceName", "Service", "WaitType", "TraceFlag", "Role", "AvailabilityGroup", "User", "ComputerName"];
function summarizeRows(rows: Row[]): string | null {
  if (!rows.length) return null;
  const first = rows[0];
  const labelKey = LABEL_KEYS.find((k) => first[k] !== undefined && first[k] !== null && first[k] !== "");
  if (labelKey) {
    const vals = [...new Set(rows.map((r) => String(pick(r, labelKey) ?? "")).filter(Boolean))];
    return `${rows.length} row(s) — ${labelKey}: ${listOf(vals)}.`;
  }
  const kv = Object.entries(first)
    .filter(([, v]) => v !== null && v !== undefined && v !== "" && typeof v !== "object")
    .slice(0, 3).map(([k, v]) => `${k}=${v}`);
  return kv.length ? `${rows.length} row(s) — ${kv.join(", ")}${rows.length > 1 ? " …" : ""}.` : `${rows.length} row(s).`;
}

function describe(c: RawCheck): string | null {
  const rows = rowsOf(c.data);
  // DMV checks all share command Invoke-DbaQuery; key them by label.
  const key = c.command === "Invoke-DbaQuery" ? c.label : c.command;
  switch (key) {
    case "Last backups": {
      if (!rows.length) return null;
      const isHere = (r: Row) => { const v = pick(r, "PreferredHere"); return v === true || v === 1 || v === "1" || v === "True"; };
      const here = rows.filter(isHere);
      const elsewhere = rows.filter((r) => !isHere(r));
      const parts: string[] = [];
      if (here.length) {
        const mapped = here.map((r) => ({ db: String(pick(r, "Database") ?? "?"), lf: pick(r, "LastFull"), age: num(pick(r, "FullAgeDays")), rm: String(pick(r, "RecoveryModel") ?? ""), log: pick(r, "LastLog"), logMin: num(pick(r, "LogAgeMin")) }));
        // Genuinely STALE (Fail): no full / full >= 8d / FULL-recovery whose EXISTING log chain has gone >= 24h stale.
        const stale = mapped.filter((x) => x.lf === undefined || (!Number.isNaN(x.age) && x.age >= 8) || (x.rm === "FULL" && x.log !== undefined && !Number.isNaN(x.logMin) && x.logMin >= 1440));
        // FULL recovery but NEVER log-backed (Attention, not a stale-backup Fail): full is current; the log just never truncates.
        const noLog = mapped.filter((x) => x.rm === "FULL" && x.log === undefined && x.lf !== undefined && !(!Number.isNaN(x.age) && x.age >= 8));
        if (stale.length) parts.push(`Backup-preferred on this node but STALE: ${listOf(stale.map((x) => x.lf === undefined ? `${x.db} (no full backup)` : `${x.db} (full ${x.age}d${x.rm === "FULL" && !Number.isNaN(x.logMin) ? `, log ${Math.round(x.logMin / 60)}h` : ""})`))}. Check the backup job on this replica.`);
        if (noLog.length) parts.push(`FULL recovery but no log backups (transaction log won't truncate): ${listOf(noLog.map((x) => x.db))}. Set to SIMPLE if point-in-time recovery isn't needed, or add them to the log-backup job.`);
        if (!stale.length && !noLog.length) parts.push(`${here.length} DB(s) back up on this (backup-preferred) replica and are current.`);
      }
      if (elsewhere.length) {
        const names = [...new Set(elsewhere.map((r) => String(pick(r, "Database") ?? "?")))];
        parts.push(`${elsewhere.length} DB(s) back up on their backup-preferred replica elsewhere (${listOf(names)}) — incl. distributed-AG DBs whose full backup is held on the the primary region global primary; not scored on this node.`);
      }
      return parts.join(" ");
    }
    case "Get-DbaDatabase": {
      const bad = rows.filter((r) => pick(r, "AutoShrink") === true || pick(r, "AutoClose") === true)
        .map((r) => `${pick(r, "Name", "Database") ?? "?"}${pick(r, "AutoShrink") === true ? " [AUTO_SHRINK]" : ""}${pick(r, "AutoClose") === true ? " [AUTO_CLOSE]" : ""}`);
      if (bad.length) return `AUTO_SHRINK/AUTO_CLOSE enabled on ${bad.length} DB(s): ${listOf(bad)}. Disable — ALTER DATABASE [db] SET AUTO_SHRINK OFF; SET AUTO_CLOSE OFF — both cause file fragmentation and connection-warmup latency.`;
      return rows.length ? `${rows.length} database(s); AUTO_SHRINK/AUTO_CLOSE not set.` : null;
    }
    case "Get-DbaSuspectPage": {
      if (!rows.length) return null;
      // event_type: 1/2/3 = unresolved (823 / bad checksum / torn); 4=restored, 5=repaired, 7=deallocated = resolved.
      const num = (v: unknown) => Number(v ?? 0);
      const dbsOf = (rs: typeof rows) => listOf([...new Set(rs.map((r) => String(pick(r, "Database", "DatabaseName") ?? "?")))]);
      const unresolved = rows.filter((r) => [1, 2, 3].includes(num(pick(r, "EventType", "event_type"))));
      const resolved = rows.filter((r) => [4, 5, 7].includes(num(pick(r, "EventType", "event_type"))));
      if (unresolved.length) {
        const tail = resolved.length ? ` (plus ${resolved.length} already restored/repaired/deallocated row(s).)` : "";
        return `UNRESOLVED suspect/corrupt pages (823 / bad-checksum / torn) in: ${dbsOf(unresolved)}. Run DBCC CHECKDB to assess, restore the affected page(s) from a known-good backup (RESTORE ... PAGE=...), and investigate the storage/I-O subsystem.${tail}`;
      }
      return `No ACTIVE suspect pages — ${resolved.length} historical msdb.dbo.suspect_pages row(s) already restored/repaired/deallocated (event_type 4/5/7) for: ${dbsOf(resolved)}. Optional cleanup: DELETE FROM msdb.dbo.suspect_pages WHERE event_type IN (4,5,7).`;
    }
    case "Access violations / stack dumps (24h)": {
      const dumps = rows.filter((r) => pick(r, "DumpFile"));
      if (!dumps.length) return "No SQLDump stack dumps written in the last 24 hours.";
      const files = dumps.map((r) => `${pick(r, "DumpFile")} (${pick(r, "LastWriteUtc") ?? "?"})`);
      return `${dumps.length} stack dump(s) in the last 24 hours — likely ACCESS VIOLATION / fatal exception: ${listOf(files)}. ` +
        `Investigate with read_sql_dump (Exception Address + faulting module), correlate the workload with get_hiq for that timestamp, ` +
        `and diff loaded modules against a healthy same-cloud peer.`;
    }
    case "Measure-DbaDbVirtualLogFile": {
      const high = rows.map((r) => ({ db: String(pick(r, "Database", "Name") ?? "?"), n: num(pick(r, "Total", "Count", "VLFCount")) }))
        .filter((x) => x.n >= 1000).sort((a, b) => b.n - a.n).map((x) => `${x.db} (${x.n} VLFs)`);
      return high.length ? `High VLF count: ${listOf(high)}. Shrink the log once (DBCC SHRINKFILE), then regrow in large fixed steps (e.g. 8 GB) with a large autogrowth — excessive VLFs slow crash recovery and log backups.` : null;
    }
    case "Test-DbaIdentityUsage": {
      const near = rows.map((r) => ({ obj: `${pick(r, "Database") ?? "?"}.${pick(r, "Table", "Object") ?? "?"}.${pick(r, "Column") ?? "?"}`, p: num(pick(r, "PercentUsed", "Percent")) }))
        .filter((x) => x.p >= 80).sort((a, b) => b.p - a.p).map((x) => `${x.obj} (${Math.round(x.p)}%)`);
      return near.length ? `Identity column(s) near exhaustion: ${listOf(near)}. Reseed (DBCC CHECKIDENT) if rows were deleted, or migrate the column to BIGINT before it overflows and inserts fail.` : null;
    }
    case "Test-DbaMaxDop": {
      const r = rows[0]; if (!r) return null;
      const cur = pick(r, "CurrentInstanceMaxDop"), rec = pick(r, "RecommendedMaxDop");
      if (cur !== undefined && rec !== undefined && num(cur) !== num(rec))
        return `MaxDOP is ${cur}; recommended ${rec}. Apply: EXEC sp_configure 'max degree of parallelism', ${rec}; RECONFIGURE; (align to cores per NUMA node).`;
      return `MaxDOP ${cur ?? "?"} matches the recommendation.`;
    }
    case "Test-DbaMaxMemory": {
      const r = rows[0]; if (!r) return null;
      const max = num(pick(r, "MaxValue")), tot = num(pick(r, "Total")), rec = pick(r, "RecommendedValue");
      if (max >= 2147483647) return `'max server memory' is unlimited; physical RAM ${Number.isFinite(tot) ? tot + " MB" : "?"}. Cap it (~${rec ?? "leave OS headroom"} MB): EXEC sp_configure 'max server memory (MB)', <value>; RECONFIGURE;`;
      if (Number.isFinite(tot) && max > tot) return `'max server memory' (${max} MB) exceeds physical RAM (${tot} MB). Lower it to ~${rec ?? tot} MB to protect the OS.`;
      return `'max server memory' ${Number.isFinite(max) ? max + " MB" : "?"} of ${Number.isFinite(tot) ? tot + " MB" : "?"} physical.`;
    }
    case "Test-DbaBuild": {
      const r = rows[0]; if (!r) return null;
      const b = pick(r, "Build"), tgt = pick(r, "BuildTarget", "CUTarget", "SPTarget"), comp = pick(r, "Compliant");
      if (comp === false) return `Build ${b ?? "?"} is behind the latest available${tgt ? ` (${tgt})` : ""}. Plan a CU/SP update — newer builds carry security and stability fixes.`;
      return `Build ${b ?? "?"} is current.`;
    }
    case "Test-DbaOptimizeForAdHoc": {
      const r = rows[0]; if (!r) return null;
      const cur = pick(r, "CurrentOptimizeAdHoc"), rec = pick(r, "RecommendedOptimizeAdHoc");
      if (cur !== undefined && rec !== undefined && String(cur) !== String(rec))
        return `'optimize for ad hoc workloads' is ${cur}; recommended ${rec}. Enable: EXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE; (curbs single-use plan-cache bloat).`;
      return null;
    }
    case "Get-DbaSpConfigure": {
      const risky = ["xp_cmdshell", "Ole Automation Procedures", "Ad Hoc Distributed Queries", "cross db ownership chaining"];
      const on = rows.filter((r) => risky.includes(String(pick(r, "Name"))) && (num(pick(r, "RunningValue")) === 1 || num(pick(r, "ConfiguredValue")) === 1)).map((r) => String(pick(r, "Name")));
      return on.length ? `Risky options ENABLED: ${on.join(", ")}. Disable any not required: EXEC sp_configure '<name>', 0; RECONFIGURE; (reduces attack surface).` : null;
    }
    case "Get-DbaServerRoleMember": {
      const members = rows.map((r) => String(pick(r, "Name", "Login", "Member", "MemberName") ?? "?"));
      if (members.length > 5) return `${members.length} sysadmin members: ${listOf(members)}. Review and remove any that don't need full control (least privilege).`;
      return members.length ? `${members.length} sysadmin member(s): ${listOf(members)}.` : null;
    }
    case "Get-DbaDiskSpace": {
      const drives = rows.map((r) => ({
        d: String(pick(r, "Drive", "Name", "Label", "DriveLetter") ?? "?"),
        p: num(pick(r, "PercentFree", "FreePercent")),
        free: pick(r, "FreeGB", "Free", "FreeSpace"),
        cap: pick(r, "CapacityGB", "Capacity", "Size", "Total"),
      }));
      const fmt = (x: { d: string; p: number; free: unknown; cap: unknown }) =>
        `${x.d} (${Number.isNaN(x.p) ? "?" : Math.round(x.p)}% free${x.free ? `, ${sizeStr(x.free)}${x.cap ? ` of ${sizeStr(x.cap)}` : ""}` : ""})`;
      const low = drives.filter((x) => !Number.isNaN(x.p) && x.p < 15).sort((a, b) => a.p - b.p);
      if (low.length) return `Low disk space: ${low.map(fmt).join(", ")}. FAIL applies only to SQL/OS volumes (C: / B: backups / D: / E: / L: / T:) — under 5% free on E:\\ (large data volume) and 10% on the others; other volumes (e.g. F:\\ that hosts no SQL files) are shown for awareness but don't fail the check. Reclaim space or expand the volume — autogrow stalls and backup failures follow below the threshold.`;
      return drives.length ? `Drives: ${listOf(drives.map(fmt))}.` : null;
    }
    case "Service account & IFI/LPIM (SQL)": {
      const eng = rows.find((r) => String(pick(r, "Service") ?? "").startsWith("SQL Server (")) ?? rows[0];
      if (!eng) return null;
      const ifi = pick(eng, "IFI"), mm = pick(rows[0], "MemoryModel"), acct = pick(eng, "Account");
      const issues: string[] = [];
      if (ifi === "N") issues.push("Instant File Initialization is OFF — grant 'Perform volume maintenance tasks' to the service account to speed data-file growth and restores");
      if (mm === "CONVENTIONAL") issues.push("Lock Pages in Memory not enabled — consider granting it to the service account to prevent working-set trimming");
      const base = `Service account ${acct ?? "?"}; IFI ${ifi === "Y" ? "on" : ifi === "N" ? "off" : "?"}; memory model ${mm ?? "?"}.`;
      return issues.length ? `${base} ${issues.join("; ")}.` : base;
    }
    case "Operating system (SQL)": {
      const r = rows[0]; if (!r) return null;
      return `Windows release ${pick(r, "WindowsRelease") ?? "?"}${pick(r, "ServicePack") ? ` SP ${pick(r, "ServicePack")}` : ""}, SKU ${pick(r, "SKU") ?? "?"}.`;
    }
    // ── Informational summaries (short detail of the rows) ──
    case "Get-DbaAvailabilityGroup": {
      const ags = rows.map((r) => `${pick(r, "AvailabilityGroup", "Name") ?? "?"}${pick(r, "PrimaryReplica") ? ` (primary ${pick(r, "PrimaryReplica")}` : ""}${pick(r, "AutomatedBackupPreference") ? `${pick(r, "PrimaryReplica") ? ", " : " ("}backup pref ${pick(r, "AutomatedBackupPreference")})` : pick(r, "PrimaryReplica") ? ")" : ""}`);
      return ags.length ? `AG: ${listOf(ags)}.` : null;
    }
    case "Get-DbaAgReplica": {
      const reps = rows.map((r) => `${pick(r, "Replica", "Name") ?? "?"} (${pick(r, "Role") ?? "?"}${pick(r, "AvailabilityMode") ? `, ${pick(r, "AvailabilityMode")}` : ""})`);
      return reps.length ? `Replicas: ${listOf(reps)}.` : null;
    }
    case "Get-DbaDbRecoveryModel": {
      const counts: Record<string, number> = {};
      for (const r of rows) { const m = String(pick(r, "RecoveryModel") ?? "?"); counts[m] = (counts[m] ?? 0) + 1; }
      const parts = Object.entries(counts).map(([m, n]) => `${m}: ${n}`);
      return parts.length ? `${rows.length} DB(s) — recovery model ${parts.join(", ")}.` : null;
    }
    case "Get-DbaWaitStatistic": {
      const top = rows.map((r) => ({ w: String(pick(r, "WaitType") ?? "?"), p: num(pick(r, "Percentage", "Percent")) }))
        .filter((x) => Number.isFinite(x.p)).sort((a, b) => b.p - a.p).slice(0, 5).map((x) => `${x.w} (${Math.round(x.p)}%)`);
      if (top.length) return `Top waits: ${top.join(", ")}.`;
      const names = rows.map((r) => String(pick(r, "WaitType") ?? "")).filter(Boolean).slice(0, 5);
      return names.length ? `Top waits: ${listOf(names)}.` : null;
    }
    case "Get-DbaTraceFlag": {
      const flags = rows.map((r) => String(pick(r, "TraceFlag", "Name") ?? "?"));
      return flags.length ? `Global trace flags: ${listOf(flags)}.` : "No global trace flags set.";
    }
    case "Get-DbaAgentJob": {
      const disabled = rows.filter((r) => pick(r, "Enabled") === false).map((r) => String(pick(r, "Name") ?? "?"));
      const failed = rows.filter((r) => String(pick(r, "LastRunOutcome") ?? "") === "Failed").map((r) => String(pick(r, "Name") ?? "?"));
      let s = `${rows.length} SQL Agent job(s)`;
      if (disabled.length) s += `, ${disabled.length} disabled (${listOf(disabled, 4)})`;
      if (failed.length) s += `; last run FAILED: ${listOf(failed, 4)}`;
      return s + ".";
    }
    case "Get-DbaLastGoodCheckDb": {
      const aged = rows.map((r) => ({ db: String(pick(r, "Database", "Name") ?? "?"), age: ageDays(pick(r, "LastGoodCheckDb")) }));
      const known = aged.filter((x) => x.age !== null) as Array<{ db: string; age: number }>;
      const never = aged.filter((x) => x.age === null).map((x) => x.db);
      const oldest = known.sort((a, b) => b.age - a.age).slice(0, 5).map((x) => `${x.db} (${x.age}d ago)`);
      let s = `${rows.length} DB(s).`;
      if (oldest.length) s += ` Oldest clean DBCC CHECKDB: ${oldest.join(", ")}.`;
      if (never.length) s += ` No record: ${listOf(never)}.`;
      return s;
    }
    case "Get-DbaLogin": {
      const disabled = rows.filter((r) => pick(r, "IsDisabled") === true).length;
      const mustChange = rows.filter((r) => pick(r, "MustChangePassword") === true).length;
      let s = `${rows.length} login(s)`;
      if (disabled) s += `, ${disabled} disabled`;
      if (mustChange) s += `, ${mustChange} must-change-password`;
      return s + ".";
    }
    case "Test-DbaConnectionAuthScheme": {
      const r = rows[0]; if (!r) return null;
      return `Connection auth scheme: ${pick(r, "AuthScheme") ?? "?"}.`;
    }
    case "Get-DbaPrivilege": {
      const r = rows.find((x) => pick(x, "InstantFileInitialization") !== undefined || pick(x, "LockPagesInMemory") !== undefined) ?? rows[0];
      if (!r) return null;
      const ifi = pick(r, "InstantFileInitialization"), lpim = pick(r, "LockPagesInMemory");
      return `Service privileges — Instant File Initialization: ${ifi === true ? "on" : ifi === false ? "off" : "?"}; Lock Pages in Memory: ${lpim === true ? "on" : lpim === false ? "off" : "?"}.`;
    }
    case "Get-DbaOperatingSystem": {
      const r = rows[0]; if (!r) return null;
      return `OS: ${pick(r, "OSVersion", "Caption", "Version") ?? "?"}${pick(r, "Architecture") ? ` (${pick(r, "Architecture")})` : ""}.`;
    }
    case "Get-DbaComputerSystem": {
      const r = rows[0]; if (!r) return null;
      return `Host: ${pick(r, "NumberLogicalProcessors", "ProcessorCount") ?? "?"} logical CPU(s), ${pick(r, "TotalPhysicalMemory") ?? "?"} RAM${pick(r, "Domain") ? `, domain ${pick(r, "Domain")}` : ""}.`;
    }
    case "AG data movement": {
      if (!rows.length) return "Not in an availability group (no local AG databases).";
      const bad = rows.filter((r) => num(pick(r, "Suspended")) === 1 || String(pick(r, "S")) === "NOT SYNCHRONIZING")
        .map((r) => `${pick(r, "DBName") ?? "?"} (${pick(r, "S") ?? "?"}${num(pick(r, "Suspended")) === 1 ? ", SUSPENDED" : ""})`);
      if (bad.length) return `AG database(s) NOT healthily synchronizing: ${listOf(bad)}. Resume data movement — ALTER DATABASE [db] SET HADR RESUME — and check the log/redo path on the secondary.`;
      const behind = rows.map((r) => ({ db: String(pick(r, "DBName") ?? "?"), redo: num(pick(r, "RedoMB")) }))
        .filter((x) => Number.isFinite(x.redo) && x.redo > 1024).sort((a, b) => b.redo - a.redo).map((x) => `${x.db} (${x.redo} MB redo)`);
      if (behind.length) return `AG secondary redo backlog: ${listOf(behind)}. The secondary is applying log slower than it arrives — check its log-volume I/O and CPU before it breaches RPO.`;
      return `${rows.length} local AG database(s), all synchronized.`;
    }
    case "Page verify option": {
      if (!rows.length) return null;
      const dbs = rows.map((r) => `${pick(r, "DBName") ?? "?"} (${pick(r, "PageVerify") ?? "?"})`);
      return `Not using CHECKSUM page verification: ${listOf(dbs)}. Enable — ALTER DATABASE [db] SET PAGE_VERIFY CHECKSUM — so torn/bit-rot pages are detected on read (applies to pages written after the change).`;
    }
    case "TempDB configuration": {
      const r = rows[0]; if (!r) return null;
      const files = num(pick(r, "DataFiles")), cores = num(pick(r, "Cores")), sizes = num(pick(r, "DistinctSizes")), pct = num(pick(r, "PctGrowthFiles"));
      const rec = Math.min(Number.isFinite(cores) && cores > 0 ? cores : 8, 8);
      const issues: string[] = [];
      if (files === 1 && cores > 1) issues.push(`only 1 data file on ${cores} cores — add files to ${rec} equal-sized ones to cut PFS/GAM/SGAM latch contention`);
      if (sizes > 1) issues.push("data files are unequal sizes — make them identical so proportional-fill spreads allocations evenly");
      if (pct > 0) issues.push(`${pct} file(s) use percent autogrowth — switch to a fixed MB growth so files grow predictably`);
      return issues.length ? `TempDB: ${issues.join("; ")}.` : `TempDB OK — ${Number.isFinite(files) ? files : "?"} equal data file(s), fixed growth.`;
    }
    default:
      return null;
  }
}

function detailFor(c: RawCheck, status: DisplayStatus): string {
  if (c.status === "skipped")
    return "Skipped — no Windows credential. Set HEALTHCHECK_WIN_USER / HEALTHCHECK_WIN_PASSWORD to run this Windows check; disk, OS and service-account facts are already covered by the SQL-DMV fallbacks.";
  if (c.error) return `Could not run: ${c.error.replace(/\s+/g, " ").slice(0, 200)}`;
  const note = CHECK_NOTES[c.command] ? ` ${CHECK_NOTES[c.command]}` : "";
  const desc = describe(c);
  if (desc) return `${desc}${note}`;
  if (status === "Fail" || status === "Attention")
    return `${c.rows} item(s) ${status === "Fail" ? "flagged — action needed" : "to review"}.${note}`;
  // For graded checks, 0 rows means "nothing flagged" — not "0 checked".
  if (status === "Pass") return `${c.rows === 0 ? "None found — OK." : `OK (${c.rows} checked).`}${note}`;
  // Info: summarize the rows rather than a bare count.
  const sum = summarizeRows(rowsOf(c.data));
  return `${sum ?? (c.rows > 0 ? `${c.rows} row(s) (informational).` : "No rows returned.")}${note}`;
}

// ── Remediation rules ─────────────────────────────────────────────────────────
// For Fail/Attention findings, emit a grounded, copy-paste fix following Microsoft /
// industry guidance. Where a wrong object name would be dangerous (logs, owners), the
// "fix" is a GENERATOR query that emits the exact statements with correct names for
// review — safer on prod than a blind ALTER. sp_configure fixes are exact and idempotent.
const DOC = {
  vlf: "https://learn.microsoft.com/sql/relational-databases/logs/manage-the-size-of-the-transaction-log-file",
  disk: "https://learn.microsoft.com/sql/relational-databases/databases/move-database-files",
  adhoc: "https://learn.microsoft.com/sql/database-engine/configure-windows/optimize-for-ad-hoc-workloads-server-configuration-option",
  maxdop: "https://learn.microsoft.com/sql/database-engine/configure-windows/configure-the-max-degree-of-parallelism-server-configuration-option",
  maxmem: "https://learn.microsoft.com/sql/database-engine/configure-windows/server-memory-server-configuration-options",
  sysadmin: "https://learn.microsoft.com/sql/relational-databases/security/authentication-access/server-level-roles",
  powerplan: "https://learn.microsoft.com/troubleshoot/sql/database-engine/performance/sql-server-performance-power-plan",
  build: "https://learn.microsoft.com/troubleshoot/sql/releases/download-and-install-latest-updates",
  owner: "https://learn.microsoft.com/sql/t-sql/statements/alter-authorization-transact-sql",
  checkdb: "https://learn.microsoft.com/sql/t-sql/database-console-commands/dbcc-checkdb-transact-sql",
  suspect: "https://learn.microsoft.com/sql/relational-databases/backup-restore/restore-pages-sql-server",
  identity: "https://learn.microsoft.com/sql/t-sql/database-console-commands/dbcc-checkident-transact-sql",
  av: "https://learn.microsoft.com/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-dump-files",
};
const qList = (names: string[]) => names.map((n) => `'${n.replace(/'/g, "''")}'`).join(", ");

function remediationFor(c: RawCheck, status: DisplayStatus): Remediation | undefined {
  if (status !== "Fail" && status !== "Attention") return undefined;
  const rows = rowsOf(c.data);
  switch (c.label) {
    case "VLF count": {
      const dbs = rows.map((r) => ({ db: String(pick(r, "Database", "Name") ?? ""), n: num(pick(r, "Total", "Count", "VLFCount")) }))
        .filter((x) => x.db && x.n >= 1000).map((x) => x.db);
      const inList = dbs.length ? qList(dbs) : "/* db names from Details */";
      return {
        summary: "Too many VLFs slows crash recovery and log backups. The log only shrinks PAST its active region after a LOG BACKUP frees it — so back up FIRST, then repeat backup+shrink until small, THEN grow ONCE in large fixed steps. Don't use TRUNCATEONLY (won't cut VLFs) and don't blind-set 8 GB — size to the post-backup active log (active_gb below).",
        lang: "tsql",
        code:
`-- 1) Inspect the flagged logs. active_gb (especially right after a backup) = your real steady-state
--    size; reuse_wait says what holds the log (LOG_BACKUP = needs a backup; ACTIVE_TRANSACTION = open tran).
SELECT d.name AS [database], d.log_reuse_wait_desc, mf.name AS log_logical_name,
       CAST(mf.size/128.0/1024 AS DECIMAL(10,1)) AS log_gb,
       CAST((SELECT SUM(CASE WHEN vlf_active=1 THEN vlf_size_mb ELSE 0 END)/1024.0
             FROM sys.dm_db_log_info(d.database_id)) AS DECIMAL(10,1)) AS active_gb,
       (SELECT COUNT(*) FROM sys.dm_db_log_info(d.database_id)) AS vlfs
FROM sys.databases d
JOIN sys.master_files mf ON mf.database_id = d.database_id AND mf.type_desc = 'LOG'
WHERE d.name IN (${inList});

-- 2) PER DB: BACK UP THE LOG FIRST (frees the active region), then shrink. Repeat the pair until the
--    file is small / VLFs low (busy or AG DBs need 2-3 passes), THEN grow ONCE. If active_gb won't
--    drop after a backup, look for a long-running transaction: DBCC OPENTRAN('<db>').
--    USE [<db>];
--    BACKUP LOG [<db>] TO DISK = N'<your managed log-backup path>';   -- NOT NUL (keeps the chain)
--    DBCC SHRINKFILE (N'<log_logical_name>', 512);                    -- repeat BACKUP LOG + this if it stalls
--    ALTER DATABASE [<db>] MODIFY FILE (NAME = N'<log_logical_name>', SIZE = <~active_gb + headroom, in MB>, FILEGROWTH = 1024MB);
--    SELECT COUNT(*) FROM sys.dm_db_log_info(DB_ID('<db>'));          -- verify (aim well under 1000)`,
        docUrl: DOC.vlf,
      };
    }
    case "Optimize for ad hoc": return {
      summary: "Enable 'optimize for ad hoc workloads' to stop single-use plans from bloating the plan cache. Safe, online, no restart.",
      lang: "tsql", code: "EXEC sys.sp_configure 'optimize for ad hoc workloads', 1;\nRECONFIGURE;", docUrl: DOC.adhoc,
    };
    case "MaxDOP": {
      const rec = pick(rows[0] ?? {}, "RecommendedMaxDop", "Recommended", "recommended");
      return {
        summary: `Align max degree of parallelism with the recommendation (see Details)${rec ? ` — recommended ${rec}` : ""}. Online, no restart.`,
        lang: "tsql",
        code: `EXEC sys.sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sys.sp_configure 'max degree of parallelism', ${rec ?? "<recommended>"};\nRECONFIGURE;`,
        docUrl: DOC.maxdop,
      };
    }
    case "Max server memory": {
      const rec = pick(rows[0] ?? {}, "RecommendedValue", "Recommended", "MaxValue");
      return {
        summary: "Cap 'max server memory' so the OS and non-buffer-pool consumers keep headroom (this fleet runs Lock Pages in Memory). Set to the recommended MB in Details.",
        lang: "tsql",
        code: `EXEC sys.sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sys.sp_configure 'max server memory (MB)', ${rec ?? "<recommended_mb>"};\nRECONFIGURE;`,
        docUrl: DOC.maxmem,
      };
    }
    case "sysadmin members": return {
      summary: "Trim sysadmin to least privilege. List current members, then remove any that don't need full control.",
      lang: "tsql",
      code:
`SELECT sp.name AS [member], sp.type_desc
FROM sys.server_role_members rm
JOIN sys.server_principals r  ON r.principal_id = rm.role_principal_id AND r.name = 'sysadmin'
JOIN sys.server_principals sp ON sp.principal_id = rm.member_principal_id
ORDER BY sp.name;
-- Remove one (example): ALTER SERVER ROLE [sysadmin] DROP MEMBER [DOMAIN\\login];`,
      docUrl: DOC.sysadmin,
    };
    case "Power plan": return {
      summary: "SQL Server hosts should use the High Performance power plan (Balanced throttles CPU). Run on the host as admin.",
      lang: "powershell", code: "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c   # High performance", docUrl: DOC.powerplan,
    };
    case "Build currency": return {
      summary: "Instance is behind on cumulative updates. Schedule the latest CU/GDR for this major version (patch the secondary first, then fail over).",
      lang: "text", code: undefined, docUrl: DOC.build,
    };
    case "Database owners": return {
      summary: "Databases should be owned by a standard SA-equivalent, not a personal/expired login. This query emits the fix per flagged DB — review, then run.",
      lang: "tsql",
      code: "SELECT 'ALTER AUTHORIZATION ON DATABASE::['+name+'] TO [sa];' AS fix_tsql\nFROM sys.databases WHERE owner_sid <> 0x01;",
      docUrl: DOC.owner,
    };
    case "Identity column capacity": return {
      summary: "An IDENTITY column is near its type ceiling. If values cycled low, DBCC CHECKIDENT reseed buys time; otherwise plan a migration to a larger type (e.g. INT→BIGINT) in a maintenance window.",
      lang: "tsql", code: "-- Inspect the flagged table, then either reseed (if safe) or migrate the column type:\n-- DBCC CHECKIDENT ('schema.table', RESEED, <new_seed>);", docUrl: DOC.identity,
    };
    case "Suspect pages": return {
      summary: "Pages are listed in msdb.dbo.suspect_pages. UNRESOLVED entries (event_type 1/2/3 — 823 / bad-checksum / torn) are real: run CHECKDB and restore the affected page(s) from a known-good backup, then investigate the storage path. Rows for already restored/repaired/deallocated pages (event_type 4/5/7) are historical and can be cleared.",
      lang: "tsql", code: "-- See what is actually flagged (resolved vs unresolved):\nSELECT DB_NAME(database_id) AS database_name, file_id, page_id, event_type, error_count, last_update_date\nFROM msdb.dbo.suspect_pages ORDER BY last_update_date DESC;\n-- UNRESOLVED (event_type 1/2/3): assess + page-restore\nDBCC CHECKDB ([<database>]) WITH NO_INFOMSGS, ALL_ERRORMSGS;\n-- RESTORE DATABASE [<db>] PAGE = '<file:page>' FROM DISK = '<good_backup>';\n-- RESOLVED only (event_type 4/5/7): clear the history\n-- DELETE FROM msdb.dbo.suspect_pages WHERE event_type IN (4,5,7);", docUrl: DOC.suspect,
    };
    case "Access violations / stack dumps (24h)": return {
      summary: "Fatal exception(s) dumped in the last 24h — investigate, don't 'fix' blindly. Pull the faulting module/RVA, correlate the workload, and diff loaded modules vs a healthy same-cloud peer.",
      lang: "text",
      code: "1) read_sql_dump action='read' on the newest SQLDump*.txt → grab 'Exception Address' pdb/rva\n2) get_hiq for the dump timestamp → workload at the moment\n3) fan_out_query sys.dm_os_loaded_modules vs a healthy peer → what's injected here that isn't there",
      docUrl: DOC.av,
    };
    case "Disk space": case "Disk space (SQL)": return {
      summary: "Low free space risks autogrow stalls and backup failures. FAIL is scoped to SQL/OS volumes (C: / B: / D: / E: / L: / T:) — under 5% free on E:\\ (the large data volume) and 10% on the others; non-SQL utility volumes (e.g. F:\\) are surfaced but never fail the check. Find the biggest files to relocate/clean (old SQLDump*.mdmp and backups under MSSQL\\Log often reclaim the most).",
      lang: "tsql",
      code:
`SELECT DB_NAME(mf.database_id) AS [Database], mf.type_desc, mf.physical_name,
       CAST(mf.size/128.0/1024 AS DECIMAL(10,1)) AS FileGB
FROM sys.master_files mf
ORDER BY mf.size DESC;`,
      docUrl: DOC.disk,
    };
    default: return undefined;  // describe() already carries guidance for the rest
  }
}

export function toFinding(c: RawCheck): Finding {
  const status = STATUS_MAP[c.status] ?? "Info";
  const target = LABEL_TARGET.get(c.label);
  const spoke = target === "os" || target === "fw" ? "Host / OS" : target === "dmv" ? "Host (via SQL)" : "SQL Instance";
  return { category: c.category, label: c.label, command: c.command, spoke, priority: c.priority ?? "Medium", status, rows: c.rows, details: detailFor(c, status), remediation: remediationFor(c, status) };
}

export function scoreFindings(findings: Finding[]): { overall: number | null; categories: CategoryScore[]; counts: Record<DisplayStatus, number> } {
  let wsum = 0, wval = 0;
  const counts = emptyCounts();
  const cats = new Map<string, { wsum: number; wval: number; counts: Record<DisplayStatus, number> }>();
  for (const f of findings) {
    counts[f.status]++;
    const cat = cats.get(f.category) ?? { wsum: 0, wval: 0, counts: emptyCounts() };
    cat.counts[f.status]++;
    const v = SCORE_VALUE[f.status];
    if (v !== undefined) {
      const w = PRIORITY_WEIGHT[f.priority] ?? 1;
      wsum += w; wval += w * v; cat.wsum += w; cat.wval += w * v;
    }
    cats.set(f.category, cat);
  }
  const categories = [...cats.entries()].map(([name, c]) => ({ name, health: c.wsum ? Math.round(c.wval / c.wsum) : null, counts: c.counts }));
  // Overall = the unweighted MEAN of the per-category scores (each scored dimension counts
  // once), so the headline matches the category table the reader sees and no check-heavy
  // category dominates. Priority weighting still applies WITHIN each category above.
  // (Not the all-findings pool — that over-weights whichever category has the most checks.)
  const scored = categories.map((c) => c.health).filter((h): h is number => h !== null);
  const overall = scored.length ? Math.round(scored.reduce((s, h) => s + h, 0) / scored.length) : null;
  return { overall, categories, counts };
}

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch] as string));
const healthColor = (p: number | null) => p === null ? "#8b98a5" : p >= 80 ? "#2e7d32" : p >= 50 ? "#b8860b" : "#c62828";
const STATUS_COLOR: Record<DisplayStatus, string> = { Pass: "#2e7d32", Attention: "#b8860b", Fail: "#c62828", Info: "#1565c0" };
const pctText = (p: number | null) => (p === null ? "—" : `${p}%`);
const statusRank = (s: DisplayStatus) => (s === "Fail" ? 0 : s === "Attention" ? 1 : s === "Info" ? 3 : 2);

// Inline-style fragments. The report is emailed to Slack, where email clients strip
// <head><style> blocks entirely — only inline style="" attributes survive. So every
// structural style (panels, tables, borders, spacing) MUST be inlined, not class-based.
const S_PANEL = "background:#ffffff;border:1px solid #e1e6ea;border-radius:10px;padding:16px 18px;margin:0 0 16px";
const S_H3 = "font-size:12px;margin:0 0 10px;color:#41505e;text-transform:uppercase;letter-spacing:.5px;font-weight:700";
const S_TABLE = "width:100%;border-collapse:collapse;font-size:13px";
const S_TH = "background:#f4f6f8;color:#41505e;font-weight:700;text-align:left;padding:8px 10px;border-bottom:2px solid #d6dce1;font-size:11px;text-transform:uppercase;letter-spacing:.3px";
const S_TD = "padding:7px 10px;border-bottom:1px solid #eceff2;vertical-align:top";
const ROW_BG: Record<DisplayStatus, string> = { Fail: "#fdf2f2", Attention: "#fdfaf0", Pass: "", Info: "" };
const badge = (s: DisplayStatus) => `<span style="background:${STATUS_COLOR[s]};color:#fff;border-radius:5px;padding:2px 8px;font-size:12px;font-weight:700;white-space:nowrap">${s}</span>`;

export function generateHtmlReport(generatedAt: string, instances: InstanceReport[]): string {
  const agg = scoreFindings(instances.flatMap((i) => i.findings));
  const overall = agg.overall;
  const total = agg.counts.Pass + agg.counts.Attention + agg.counts.Fail + agg.counts.Info;

  // Category summary as a bordered table (email-safe; the old CSS-grid cards collapsed
  // to an unstyled stack once the <style> block was stripped).
  const catRows = agg.categories.map((c) => `<tr>
        <td style="${S_TD};border-left:4px solid ${healthColor(c.health)};font-weight:600">${esc(c.name)}</td>
        <td style="${S_TD};color:${healthColor(c.health)};font-weight:800">${pctText(c.health)}</td>
        <td style="${S_TD};color:${STATUS_COLOR.Pass}">${c.counts.Pass}</td>
        <td style="${S_TD};color:${STATUS_COLOR.Attention}">${c.counts.Attention}</td>
        <td style="${S_TD};color:${STATUS_COLOR.Fail}">${c.counts.Fail}</td>
        <td style="${S_TD};color:${STATUS_COLOR.Info}">${c.counts.Info}</td></tr>`).join("");

  const catHeaders = agg.categories.map((c) => `<th style="${S_TH}">${esc(c.name)}</th>`).join("");
  const instRows = instances.map((i) => {
    const byCat = new Map(i.categories.map((c) => [c.name, c.health]));
    const cells = agg.categories.map((c) => { const h = byCat.get(c.name) ?? null; return `<td style="${S_TD};color:${healthColor(h)};font-weight:600">${pctText(h)}</td>`; }).join("");
    return `<tr><td style="${S_TD}"><b>${esc(i.instance)}</b><div style="color:#8b98a5;font-size:11px">${esc(i.sql_instance ?? "")}</div></td><td style="${S_TD};color:${healthColor(i.overall_health)};font-weight:800">${pctText(i.overall_health)}</td>${cells}</tr>`;
  }).join("");

  const multi = instances.length > 1;   // Instance column only adds value across instances
  const findingRows = instances.flatMap((i) => i.findings.map((f) => ({ ...f, instance: i.instance })))
    .sort((a, b) => statusRank(a.status) - statusRank(b.status) || (PRIORITY_WEIGHT[b.priority] ?? 0) - (PRIORITY_WEIGHT[a.priority] ?? 0))
    .map((f) => { const td = `${S_TD}${ROW_BG[f.status] ? `;background:${ROW_BG[f.status]}` : ""}`;
      return `<tr>${multi ? `<td style="${td}">${esc(f.instance)}</td>` : ""}
        <td style="${td}">${esc(f.category)}</td>
        <td style="${td};font-weight:600">${esc(f.label)}</td>
        <td style="${td}">${esc(f.priority)}</td>
        <td style="${td}">${badge(f.status)}</td>
        <td style="${td}">${esc(f.details)}</td></tr>`; }).join("");

  // Recommended actions: the actionable (Fail/Attention) findings that carry a grounded
  // copy-paste remediation, surfaced at the top so the reader sees what to DO first.
  const actionable = instances.flatMap((i) => i.findings.map((f) => ({ ...f, instance: i.instance })))
    .filter((f) => f.remediation)
    .sort((a, b) => statusRank(a.status) - statusRank(b.status) || (PRIORITY_WEIGHT[b.priority] ?? 0) - (PRIORITY_WEIGHT[a.priority] ?? 0));
  const codeBox = (r: Remediation) => r.code
    ? `<pre style="background:#f4f6f8;border:1px solid #d6dce1;border-radius:6px;padding:10px;margin:8px 0 0;font:12px/1.45 Consolas,monospace;color:#1b2733;white-space:pre-wrap;word-break:break-word">${esc(r.code)}</pre>` : "";
  const docLink = (r: Remediation) => r.docUrl
    ? `<div style="margin-top:6px"><a href="${esc(r.docUrl)}" style="color:#1565c0;font-size:12px;text-decoration:none">Microsoft guidance ↗</a></div>` : "";
  const recItems = actionable.map((f) => `
      <div style="border-left:4px solid ${STATUS_COLOR[f.status]};background:${ROW_BG[f.status] || "#ffffff"};padding:10px 12px;margin:0 0 10px;border-radius:0 6px 6px 0">
        <div style="font-weight:700">${badge(f.status)} &nbsp;${esc(f.label)}
          <span style="color:#8b98a5;font-weight:600;font-size:12px">· ${esc(f.category)} · ${esc(f.priority)} priority · ${esc(f.instance)}</span></div>
        <div style="margin-top:6px">${esc(f.remediation!.summary)}</div>
        ${codeBox(f.remediation!)}${docLink(f.remediation!)}
      </div>`).join("");
  const recPanel = actionable.length
    ? `<div style="${S_PANEL}"><div style="${S_H3}">Recommended actions <span style="color:#8b98a5;font-weight:600;text-transform:none;letter-spacing:0">(${actionable.length} — copy-paste fixes; review before running on prod)</span></div>${recItems}</div>`
    : `<div style="${S_PANEL}"><div style="${S_H3}">Recommended actions</div><div style="color:#2e7d32;font-weight:600">✔ Nothing to action — no failures or warnings with an automated fix.</div></div>`;

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQL Server Instance Health Report</title></head>
<body style="margin:0;background:#f4f6f8;color:#1b2733;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.55">
<div style="max-width:1180px;margin:0 auto;padding:24px">
  <h1 style="font-size:22px;margin:0 0 2px">SQL Server Instance Health Report</h1>
  <p style="color:#65727f;margin:0 0 18px;font-size:13px">Read-only dbatools checks scored Pass / Attention / Fail, plus informational inventory. Generated ${esc(generatedAt)}.</p>

  <div style="${S_PANEL}">
    <div style="font-size:38px;font-weight:800;color:${healthColor(overall)};line-height:1.1">${pctText(overall)}
      <span style="font-size:13px;font-weight:600;color:#65727f">average health · ${instances.length} instance(s) · ${total} checks</span></div>
    <div style="margin:12px 0 0">
      <span style="display:inline-block;margin:0 16px 4px 0;font-weight:700;color:${STATUS_COLOR.Pass}">✔ Pass ${agg.counts.Pass}</span>
      <span style="display:inline-block;margin:0 16px 4px 0;font-weight:700;color:${STATUS_COLOR.Attention}">▲ Attention ${agg.counts.Attention}</span>
      <span style="display:inline-block;margin:0 16px 4px 0;font-weight:700;color:${STATUS_COLOR.Fail}">✖ Fail ${agg.counts.Fail}</span>
      <span style="display:inline-block;margin:0 16px 4px 0;font-weight:700;color:${STATUS_COLOR.Info}">◌ Info ${agg.counts.Info}</span>
    </div>
    <div style="color:#65727f;font-size:12px;margin-top:8px">Color scale: red (0–50%) · amber (50–80%) · green (80–100%). Informational checks don't affect the score.</div>
  </div>

  ${recPanel}

  <div style="${S_PANEL}"><div style="${S_H3}">Categories</div>
    <table style="${S_TABLE}"><thead><tr>
      <th style="${S_TH}">Category</th><th style="${S_TH}">Health</th>
      <th style="${S_TH}">Pass</th><th style="${S_TH}">Attention</th><th style="${S_TH}">Fail</th><th style="${S_TH}">Info</th>
    </tr></thead><tbody>${catRows}</tbody></table>
  </div>

  <div style="${S_PANEL}"><div style="${S_H3}">Instances</div>
    <table style="${S_TABLE}"><thead><tr><th style="${S_TH}">Instance</th><th style="${S_TH}">Overall</th>${catHeaders}</tr></thead><tbody>${instRows}</tbody></table>
  </div>

  <div style="${S_PANEL}"><div style="${S_H3}">All findings <span style="color:#8b98a5;font-weight:600;text-transform:none;letter-spacing:0">(failures first)</span></div>
    <table style="${S_TABLE}"><thead><tr>
      ${multi ? `<th style="${S_TH}">Instance</th>` : ""}<th style="${S_TH}">Category</th><th style="${S_TH}">Label</th><th style="${S_TH}">Priority</th><th style="${S_TH}">Status</th><th style="${S_TH}">Details</th>
    </tr></thead><tbody>${findingRows}</tbody></table>
  </div>

  <div style="color:#8b98a5;font-size:12px;margin-top:14px">appdb-sql-mcp health check · read-only dbatools cmdlets · every query runs under the caller's own SQL login.</div>
</div></body></html>`;
}

// All tools in this server are READ-ONLY. Annotate each so MCP clients can surface that,
// and so any future write capability must be added as a SEPARATE, explicitly destructive
// tool — never silently mixed in. Every operation runs under the calling user's own SQL
// login (per-user identity), so SQL Server governs and audits it; this server holds no
// standing privileged/shared credential.
const READ_ONLY_ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
// See tools.ts for why we use this lightweight mapped type instead of the SDK's
// ToolCallback<Args> (the latter's zod3|zod4 compat inference exhausts tsc's heap).
type HandlerArgs<Args extends z.ZodRawShape> = { [K in keyof Args]: z.infer<Args[K]> };
function roTool<Args extends z.ZodRawShape>(
  server: McpServer,
  name: string,
  description: string,
  schema: Args,
  cb: (args: HandlerArgs<Args>, extra: unknown) => unknown,
) {
  return (server as { tool: (...a: unknown[]) => unknown }).tool(name, description, schema, READ_ONLY_ANNOTATIONS, cb);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared headless health-report engine. Runs the SAME dbatools checks (incl. the AV
// check) and renders the SAME HTML as the run_health_check MCP tool — both call
// generateHtmlReport over identically-scored reports, so the scheduled weekly email is
// byte-for-byte the interactive report. Used by the `report` CLI mode (see index.ts).
// Instances that error/produce no output are skipped (logged), not failed.
// ─────────────────────────────────────────────────────────────────────────────
export async function runHealthReport(
  targets: InstanceConfig[],
  opts: { useSql: boolean; rowsPerCheck?: number; generatedAt: string },
): Promise<{ reports: InstanceReport[]; html: string }> {
  const rows = opts.rowsPerCheck ?? 25;
  const reports: InstanceReport[] = [];
  for (const cfg of targets) {
    if (cfg.kind === "witness") continue;
    try {
      const r = await runPowerShell(
        buildHealthCheckScript(cfg, opts.useSql, rows),
        HC_TIMEOUT_S,
        { APPDB_HC_SQL_PASSWORD: HC_PASS, APPDB_HC_WIN_PASSWORD: HC_WIN_PASS },
      );
      if (!r.stdout.trim()) { log(`[report] ${cfg.name}: no output (${(r.stderr.trim() || "").slice(0, 200)})`); continue; }
      const parsed = JSON.parse(r.stdout.trim()) as { computer?: string; sqlInstance?: string; checks?: RawCheck[] };
      const findings = (parsed.checks ?? []).map(toFinding);
      const score = scoreFindings(findings);
      reports.push({
        instance: cfg.name, computer: parsed.computer, sql_instance: parsed.sqlInstance,
        overall_health: score.overall, status_counts: score.counts, categories: score.categories, findings,
      });
    } catch (e) { log(`[report] ${cfg.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { reports, html: generateHtmlReport(opts.generatedAt, reports) };
}

export function registerDbatoolsTools(server: McpServer): void {
  // ============================================================
  // check_dbatools_environment
  // ============================================================
  roTool(server, 
    "check_dbatools_environment",
    "Verify the dbatools prerequisites on this machine: the PowerShell host and the installed dbatools module version. Call this first if other dbatools tools fail.",
    {},
    async () => {
      try {
        const r = await runPowerShell(
          `$v = $PSVersionTable.PSVersion.ToString()
$m = (Get-Module -ListAvailable dbatools | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
[pscustomobject]@{ powershell = $v; dbatools = $m; exe = '${sq(PWSH)}' } | ConvertTo-Json -Compress`,
          30
        );
        if (r.exitCode !== 0) return err(r.stderr.trim() || "dbatools not available. Install-Module dbatools -Scope CurrentUser");
        return { content: [{ type: "text", text: r.stdout.trim() }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // list_dbatools_commands
  // ============================================================
  roTool(server, 
    "list_dbatools_commands",
    "List read-only dbatools cmdlets (Get-/Test-/Measure-/Find-Dba*) available on this machine, optionally filtered by a keyword in the name.",
    { keyword: z.string().optional().describe("Case-insensitive substring to match (e.g. 'backup', 'wait', 'memory').") },
    async ({ keyword }) => {
      try {
        const filter = keyword ? ` | Where-Object Name -match '${sq(keyword)}'` : "";
        const r = await runPowerShell(
          `Import-Module dbatools -ErrorAction Stop
Get-Command -Module dbatools -CommandType Function,Cmdlet |
  Where-Object { $_.Verb -in 'Get','Test','Measure','Find' }${filter} |
  Select-Object -ExpandProperty Name | Sort-Object | ConvertTo-Json -Compress`,
          60
        );
        if (r.exitCode !== 0) return err(r.stderr.trim() || "Failed to list commands");
        return { content: [{ type: "text", text: r.stdout.trim() || "[]" }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_dbatools_command_help — parameters + examples for a cmdlet (read-only)
  // ============================================================
  roTool(server,
    "get_dbatools_command_help",
    "Get help for a dbatools cmdlet — synopsis, syntax, parameters (name/type/required), and examples — so you can call run_dbatools_command correctly. Reads `Get-Help -Full` at request time; does not execute the cmdlet.",
    { command: z.string().describe("dbatools cmdlet name, e.g. 'Get-DbaWaitStatistic' or 'Test-DbaMaxMemory'.") },
    async ({ command }) => {
      try {
        if (!/^[A-Za-z]+-Dba[A-Za-z0-9]+$/.test(command)) {
          throw new Error(`Invalid cmdlet name: ${command}. Expected a dbatools cmdlet like Get-DbaDatabase.`);
        }
        const r = await runPowerShell(
          `Import-Module dbatools -ErrorAction Stop
$h = Get-Help -Full ${command} -ErrorAction Stop
[pscustomobject]@{
  name       = $h.Name
  synopsis   = ($h.Synopsis | Out-String).Trim()
  syntax     = ($h.syntax | Out-String).Trim()
  parameters = @($h.parameters.parameter | ForEach-Object { [pscustomobject]@{ name = $_.name; type = $_.type.name; required = $_.required; description = (($_.description | Out-String).Trim()) } })
  examples   = @($h.examples.example | Select-Object -First 5 | ForEach-Object { (($_.code, ($_.remarks | Out-String)) -join "\`n").Trim() })
} | ConvertTo-Json -Depth 6 -Compress`,
          60
        );
        if (r.exitCode !== 0) return err(r.stderr.trim() || `No help found for ${command}`);
        return { content: [{ type: "text", text: r.stdout.trim() }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // run_dbatools_command — one read-only dbatools cmdlet
  // ============================================================
  roTool(server, 
    "run_dbatools_command",
    "Run a single READ-ONLY dbatools cmdlet against a fleet instance and return JSON. Allowed: Get-/Test-/Measure-/Find-Dba* and Invoke-DbaDiagnosticQuery — every write verb is rejected, including Test-DbaLastBackup (it restores a copy). Connects with ApplicationIntent=ReadOnly. Examples: Get-DbaWaitStatistic, Get-DbaLastBackup, Test-DbaMaxMemory, Find-DbaDbUnusedIndex.",
    {
      command: z.string().describe("dbatools cmdlet name, e.g. 'Get-DbaWaitStatistic'."),
      instance_name: z.string().optional().default(DEFAULT_INSTANCE).describe(`Fleet instance to target. Defaults to "${DEFAULT_INSTANCE}". Call list_instances for names.`),
      parameters: z.record(z.union([z.string(), z.number(), z.boolean()])).optional().describe("Extra cmdlet parameters as a map. -SqlInstance is supplied automatically."),
      max_rows: z.number().int().min(1).max(2000).optional().default(200).describe("Max rows to return (default 200)."),
    },
    async ({ command, instance_name, parameters, max_rows }) => {
      try {
        assertReadOnlyCommand(command);
        const cfg = resolveInstance(instance_name);
        const splat: string[] = [];
        for (const [k, v] of Object.entries(parameters ?? {})) {
          if (!PROP_RE.test(k)) throw new Error(`Invalid parameter name: ${k}`);
          if (k === "SqlInstance" || k === "SqlCredential") continue;
          if (typeof v === "boolean") { if (v) splat.push(`  ${k} = $true`); }
          else if (typeof v === "number") { if (Number.isFinite(v)) splat.push(`  ${k} = ${v}`); }
          else splat.push(`  ${k} = '${sq(String(v))}'`);
        }
        const splatBlock = splat.length ? [`$p = @{`, ...splat, `}`].join("\n") : `$p = @{}`;
        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          `Import-Module dbatools -ErrorAction Stop`,
          PS_SANITIZER,
          connectBlock(cfg),
          splatBlock,
          `$result = ${command} -SqlInstance $server @p | Select-Object -First ${max_rows}`,
          `if ($null -eq $result) { Write-Output '[]'; exit 0 }`,
          `ConvertTo-PlainRows $result | ConvertTo-Json -Depth 5 -Compress`,
        ].join("\n");
        const r = await runPowerShell(script, CMD_TIMEOUT_S, { APPDB_SQL_PASSWORD: process.env.SQL_PASSWORD ?? "" });
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        return { content: [{ type: "text", text: (r.stdout.trim() || "[]") + (r.stderr.trim() ? `\n\n[stderr]\n${r.stderr.trim().slice(0, 1000)}` : "") }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // read_error_log — read the SQL Server error log (crash / AV / stack-dump evidence)
  // ============================================================
  roTool(server,
    "read_error_log",
    "Read the SQL Server ERRORLOG (via the read-only dbatools Get-DbaErrorLog) to investigate crashes/instability — " +
      "filter for 'Stack Dump', 'exception', 'access violation', a module/sensor name, etc. Returns timestamped log " +
      "rows. Pair with get_log_paths (where the log + SQLDump* live) and get_memory_dumps (which dumps exist). When a " +
      "node is crashing, also read the error log of a healthy PEER on the SAME cloud and compare (build, modules, errors).",
    {
      instance_name: z.string().optional().default(DEFAULT_INSTANCE).describe(`Fleet instance to target. Defaults to "${DEFAULT_INSTANCE}". Call list_instances for names.`),
      contains: z.string().optional().describe("Case-insensitive text/regex to match a log line (e.g. 'Stack Dump', 'access violation', 'ctiuser'). Omit for everything."),
      log_number: z.number().int().min(0).max(99).optional().default(0).describe("Which archived log: 0 = current ERRORLOG (default), 1 = previous, etc."),
      max_rows: z.number().int().min(1).max(5000).optional().default(500).describe("Max log rows to return (default 500, newest first)."),
    },
    async ({ instance_name, contains, log_number, max_rows }: { instance_name?: string; contains?: string; log_number?: number; max_rows?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        const ln = Number(log_number) || 0;
        const cap = Number(max_rows) || 500;
        // `contains` is applied here as a real CASE-INSENSITIVE REGEX (PowerShell -match),
        // NOT via Get-DbaErrorLog -Text. -Text maps to xp_readerrorlog's search argument,
        // which is a LITERAL substring filter — so an alternation like
        // 'Stack Dump|access violation|c0000005' matched the literal string and silently
        // returned []. Filtering BEFORE the row cap also guarantees crash signatures aren't
        // truncated away by the newest-N limit.
        const matchLine = contains
          ? `$rows = @($rows) | Where-Object { $_.Text -match '${sq(contains)}' }`
          : `# (no contains filter — keep all rows)`;
        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          `Import-Module dbatools -ErrorAction Stop`,
          PS_SANITIZER,
          connectBlock(cfg),
          `$result = Get-DbaErrorLog -SqlInstance $server -LogNumber ${ln} -EnableException -WarningAction SilentlyContinue 3>$null`,
          `if ($null -eq $result) { Write-Output '[]'; exit 0 }`,
          `$rows = @($result)`,
          matchLine,
          `$rows = @($rows) | Sort-Object LogDate -Descending | Select-Object -First ${cap}`,
          `if (-not $rows) { Write-Output '[]'; exit 0 }`,
          // Project only the meaningful columns. Raw rows are System.Data.DataRow objects
          // whose Table/ItemArray/RowError/RowState props serialize the ENTIRE table per
          // row — that bloated a crash log past 10 MB and blew the response cap. Keep just
          // LogDate/Source/ProcessInfo/Text.
          `$out = @($rows) | Select-Object @{n='LogDate';e={ if ($_.LogDate -is [datetime]) { $_.LogDate.ToString('o') } else { [string]$_.LogDate } }}, @{n='Source';e={ [string]$_.Source }}, @{n='ProcessInfo';e={ [string]$_.ProcessInfo }}, @{n='Text';e={ [string]$_.Text }}`,
          `ConvertTo-PlainRows $out | ConvertTo-Json -Depth 5 -Compress`,
        ].join("\n");
        const r = await runPowerShell(script, CMD_TIMEOUT_S, { APPDB_SQL_PASSWORD: process.env.SQL_PASSWORD ?? "" });
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        return { content: [{ type: "text", text: (r.stdout.trim() || "[]") + (r.stderr.trim() ? `\n\n[stderr]\n${r.stderr.trim().slice(0, 1000)}` : "") }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // run_health_check — self-contained dbatools health check (read-only)
  // ============================================================
  roTool(server, 
    "run_health_check",
    "Comprehensive READ-ONLY health check built entirely from dbatools cmdlets. Covers Availability, Performance, Recoverability, Reliability, Security, Configuration, Maintenance AND Host/OS (power plan, disk space, firewall, computer/OS). Returns the dbatools-report model: overall health % + per-category health (priority-weighted; Pass=100, Attention=60, Fail=0; informational inventory excluded), status counts (Pass/Attention/Fail/Info), and a findings list — plus a self-contained HTML report whose path is returned as `report.path` (set HEALTHCHECK_REPORT_DIR for a durable location). The response is compact by default; pass include_raw_data:true to also embed each check's raw rows. Runs under your own SQL login (HEALTHCHECK_SQL_USER / SQL_USER); OS/CIM checks (power plan/disk/firewall/OS) need a Windows login on the node — set HEALTHCHECK_WIN_USER/PASSWORD — and degrade gracefully to Info when unreachable.",
    {
      instance_name: z.string().optional().describe("A single fleet instance (e.g. 'region1-node2'). Omit + region for a region; omit both = the default instance only."),
      region: z.string().optional().describe("Check every instance in a region: sg, id, uk, or us."),
      auth: z.enum(["sql", "windows"]).optional().describe("'sql' (default when configured) uses the SQL login; 'windows' uses the operator's AD account."),
      include_raw_data: z.boolean().optional().default(false).describe("Embed each check's raw result rows in the response (can be large). Default false — the scored findings + HTML report are returned regardless."),
      summary_only: z.boolean().optional().default(false).describe("Deprecated alias; the response is already compact by default. Has no additional effect."),
      html_report: z.boolean().optional().default(true).describe("Write a self-contained HTML report (overall/category health + findings table, dbatools-report layout) and return its path. Default true."),
      max_rows_per_check: z.number().int().min(1).max(200).optional().default(25).describe("Rows kept per check (default 25)."),
    },
    async ({ instance_name, region, auth, include_raw_data, summary_only, html_report, max_rows_per_check }) => {
      try {
        let targets = listInstances();
        if (region) targets = targets.filter((i) => (i.region ?? "").toLowerCase() === region.toLowerCase());
        if (instance_name) targets = targets.filter((i) => i.name === instance_name);
        if (!region && !instance_name) targets = targets.filter((i) => i.name === DEFAULT_INSTANCE);
        if (targets.length === 0) return err("No matching instances. Call list_instances for names/regions.");

        const useSql = (auth ?? (HC_USER && HC_PASS ? "sql" : "windows")) === "sql";
        if (useSql && (!HC_USER || !HC_PASS)) {
          return err("auth='sql' requires HEALTHCHECK_SQL_USER/HEALTHCHECK_SQL_PASSWORD (or SQL_USER/SQL_PASSWORD). Set them, or pass auth:'windows'.");
        }

        const rows = max_rows_per_check ?? 25;
        const results: unknown[] = [];
        const reports: InstanceReport[] = [];
        for (const cfg of targets) {
          const script = buildHealthCheckScript(cfg, useSql, rows);
          try {
            const r = await runPowerShell(script, HC_TIMEOUT_S, { APPDB_HC_SQL_PASSWORD: HC_PASS, APPDB_HC_WIN_PASSWORD: HC_WIN_PASS });
            if (!r.stdout.trim()) { results.push({ instance: cfg.name, error: (r.stderr.trim() || "no output").slice(0, 2000) }); continue; }
            const parsed = JSON.parse(r.stdout.trim()) as { instance: string; computer?: string; sqlInstance?: string; checks?: RawCheck[] };
            const checks = parsed.checks ?? [];
            const findings = checks.map(toFinding);
            const score = scoreFindings(findings);
            const report: InstanceReport = {
              instance: cfg.name,
              computer: parsed.computer,
              sql_instance: parsed.sqlInstance,
              overall_health: score.overall,
              status_counts: score.counts,
              categories: score.categories,
              findings,
            };
            reports.push(report);
            // Compact response by default; embed raw rows only when explicitly asked
            // (keeps the response — and the PowerShell output — well under any size cap).
            results.push((include_raw_data && !summary_only) ? { ...report, checks } : report);
          } catch (e: unknown) {
            results.push({ instance: cfg.name, error: e instanceof Error ? e.message : String(e) });
          }
        }

        // Self-contained HTML report (decoupled from response size — built from the
        // scored findings, not the raw rows). Path is always surfaced below.
        let report: { path: string | null; note: string };
        if (html_report && reports.length) {
          try {
            const generatedAt = new Date().toISOString();
            const label = (region || instance_name || "fleet").replace(/[^A-Za-z0-9_-]/g, "_");
            const file = `sql-health-${label}-${generatedAt.replace(/[:.]/g, "-")}.html`;
            const path = join(REPORT_DIR, file);
            writeFileSync(path, generateHtmlReport(generatedAt, reports), "utf8");
            log(`[dbatools] health report written: ${path}`);
            report = { path, note: `Open this file in a browser. Reports are written to ${REPORT_DIR} — set HEALTHCHECK_REPORT_DIR to keep them elsewhere.` };
          } catch (e: unknown) {
            report = { path: null, note: `HTML report not written: ${e instanceof Error ? e.message : String(e)}` };
          }
        } else {
          report = { path: null, note: reports.length ? "html_report disabled (pass html_report:true to generate it)." : "No instance produced results, so no report was written." };
        }

        // Topology / credential hints so expected-by-design results aren't misread.
        const notes: string[] = [];
        const hostUnreachable = reports.some((r) => r.findings.some((f) => f.category === "Host" && f.details.startsWith("Could not run")));
        if (hostUnreachable && !(HC_WIN_USER && HC_WIN_PASS)) {
          notes.push("Some Host/OS checks could not run. Set HEALTHCHECK_WIN_USER and HEALTHCHECK_WIN_PASSWORD (a Windows login on the node, e.g. DOMAIN\\\\user) so power plan / disk / firewall / OS checks can connect over WinRM/CIM.");
        } else if (hostUnreachable) {
          notes.push("Some Host/OS checks could not run even with a Windows credential — verify the account can reach the node over WinRM/CIM (WinRM service + firewall) and that the configured host/IP is correct.");
        }
        notes.push("Backups and integrity checks may be maintained on a secondary replica in this AG; 'stale/missing' backup results on this node can be expected — verify on the backup-preferred replica (see the AG's AutomatedBackupPreference).");

        return ok({ auth: useSql ? `sql (${HC_USER})` : "windows", instances_checked: results.length, report, notes, results });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // read_cluster_reports — WSFC Cluster.log + validation reports from any cluster node
  // ============================================================
  // Reads files under \\<host>\C$\Windows\Cluster\Reports\ on a fleet DB host.
  // Cluster.log is large (hundreds of MB) — never returned in full; always grep'd
  // by a required `contains` regex OR tailed (last N lines). action='list' enumerates
  // files with size/mtime so the agent can see which reports exist.
  //
  // Authn: HEALTHCHECK_WIN_USER/PASSWORD > Windows Credential Manager (cmdkey-stored
  // generic credential for the target, read via CredRead and mounted on a temp
  // PSDrive) > MCP process identity. No WinRM. See buildClusterAccess for the full
  // precedence and how Domain-type cmdkey entries auto-bind via LSA.
  // Witness hosts are rejected — they're not cluster nodes, they only hold the FSW share.
  roTool(server,
    "read_cluster_reports",
    "Read WSFC cluster artifacts under C:\\Windows\\Cluster\\Reports\\ on a fleet DB host (cluster node) — use for diagnosing AG/cluster events: nodes going RESOLVING, quorum loss, witness arbitration failures, validation findings. " +
      "action='list' enumerates the files (size + LastWriteTime) so you can see what's there (Cluster.log, validation reports, MHT snapshots). " +
      "action='read' fetches lines from one file — Cluster.log is large, so you MUST pass either `contains` (regex; recommended for incident timelines, e.g. '2026/06/08-18:4[0-5]') OR `tail` (last N lines). " +
      "Auth on the MCP host (precedence): (1) HEALTHCHECK_WIN_USER/PASSWORD env vars — mounted as a temp PSDrive on \\\\<host>\\C$; (2) Windows Credential Manager — a cmdkey-stored entry for the target host is read via CredRead, prefer 'cmdkey /generic:<host> /user:DOMAIN\\\\user /pass:...' (the password blob is user-readable and mounts the PSDrive explicitly), but 'cmdkey /add:<host> ...' domain entries are also accepted (Windows SMB auto-binds them via LSA); (3) bare UNC under the MCP process identity. No WinRM. " +
      "REJECTED for kind='witness' hosts: file-share witnesses are not cluster nodes; pick the affected db node (e.g. region2-node2). " +
      "For a fresh full Cluster.log generated from current cluster state (vs. the on-disk file), use run_dbatools_command with Get-DbaCluster + Get-ClusterLog cmdlets from a node.",
    {
      instance_name: z.string().describe("Cluster-node fleet instance (e.g. 'region2-node2', 'region1-node1'). Witness hosts are refused."),
      action: z.enum(["list", "read"]).optional().default("list").describe("'list' (default) = enumerate files; 'read' = return lines from `file`."),
      file: z.string().optional().describe("Filename to read (required for action='read'). Plain filename only — no path separators. e.g. 'Cluster.log'."),
      contains: z.string().optional().describe("Regex to filter lines (case-insensitive). Strongly recommended for Cluster.log — e.g. '2026/06/08-18:4[0-9]' for an incident window, or 'witness|quorum'."),
      tail: z.number().int().min(1).max(50000).optional().describe("Return the last N lines after filtering. If neither `contains` nor `tail` is provided for Cluster.log, defaults to tail=500."),
      max_lines: z.number().int().min(1).max(20000).optional().default(2000).describe("Hard cap on returned lines (default 2000)."),
    },
    async ({ instance_name, action, file, contains, tail, max_lines }: { instance_name: string; action?: "list" | "read"; file?: string; contains?: string; tail?: number; max_lines?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        if (cfg.kind === "witness") {
          return err(`Instance "${instance_name}" is a WSFC file-share witness, not a cluster node — there is no C:\\Windows\\Cluster\\Reports\\ on this host. Pick the affected db node (e.g. region2-node2).`);
        }
        // Reach the host by its computer_name when provided (NetBIOS resolves over SMB without depending on
        // forward DNS for IP-only fleet entries); otherwise fall back to the IP/hostname.
        const target = cfg.computer_name || cfg.host;
        const access = buildClusterAccess(target);
        const act = action ?? "list";

        if (act === "list") {
          const script = [
            `Set-StrictMode -Off`,
            `$ErrorActionPreference = 'Stop'`,
            access.prologue,
            `try {`,
            `  if (-not (Test-Path -LiteralPath $reportsPath)) { throw "Path not reachable: $reportsPath (auth=$__credSource; if 'mcp-identity' or 'cred-manager-domain-autobind', either set HEALTHCHECK_WIN_USER/PASSWORD or 'cmdkey /generic:<host> /user:DOMAIN\\user /pass:...' on the MCP host, and confirm SMB/445 is open to the target)" }`,
            `  Get-ChildItem -LiteralPath $reportsPath -File -ErrorAction Stop |`,
            `    Sort-Object LastWriteTime -Descending |`,
            `    Select-Object Name, Length, @{n='LastWriteTimeUtc';e={$_.LastWriteTimeUtc.ToString('o')}} |`,
            `    ConvertTo-Json -Depth 3 -Compress`,
            `} finally {`,
            `  ${access.epilogue}`,
            `}`,
          ].join("\n");
          const r = await runPowerShell(script, CMD_TIMEOUT_S, access.extraEnv ?? {});
          if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
          return { content: [{ type: "text", text: r.stdout.trim() || "[]" }] };
        }

        // action='read'
        if (!file) throw new Error("action='read' requires `file` (e.g. 'Cluster.log').");
        if (/[\\/]|\.\./.test(file)) throw new Error(`Invalid file name: ${file}. Plain filename only — no path separators or '..'.`);
        const isClusterLog = /^cluster(\.\d+)?\.log$/i.test(file);
        // Cluster.log without any filter would be enormous — apply a default tail.
        const effectiveTail = tail ?? (isClusterLog && !contains ? 500 : undefined);
        const filterClause = contains ? ` | Where-Object { $_ -match '${sq(contains)}' }` : "";
        const tailClause   = effectiveTail ? ` | Select-Object -Last ${effectiveTail}` : "";
        const capClause    = ` | Select-Object -First ${max_lines}`;

        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          access.prologue,
          `try {`,
          `  $f = Join-Path $reportsPath '${sq(file)}'`,
          `  if (-not (Test-Path -LiteralPath $f)) { throw "File not found: $f" }`,
          // Stream line-by-line so we never materialise the whole Cluster.log in memory.
          `  $lines = Get-Content -LiteralPath $f -ReadCount 0${filterClause}${tailClause}${capClause}`,
          `  [pscustomobject]@{`,
          `    file        = $f`,
          `    filter      = '${sq(contains ?? "")}'`,
          `    tail        = ${effectiveTail ?? "$null"}`,
          `    line_count  = @($lines).Count`,
          `    lines       = @($lines)`,
          `  } | ConvertTo-Json -Depth 3 -Compress`,
          `} finally {`,
          `  ${access.epilogue}`,
          `}`,
        ].join("\n");
        const r = await runPowerShell(script, CMD_TIMEOUT_S, access.extraEnv ?? {});
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        return { content: [{ type: "text", text: r.stdout.trim() || "{}" }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // generate_cluster_log — render a FRESH WSFC Cluster.log on the node and read it back
  // ============================================================
  // Get-ClusterLog regenerates the cluster log from CURRENT cluster state (vs the on-disk
  // file read_cluster_reports returns). SMB/445 is firewalled fleet-wide, so we don't pull it
  // over \\host\C$ — a transient SQL Agent PowerShell job runs Get-ClusterLog ON THE NODE into
  // the SQL Log dir, we read it back over the SQL connection (OPENROWSET BULK), then DROP the
  // job (always, in finally). Same channel as get_host_event_log; no xp_cmdshell/OLE/CLR. Needs
  // the FailoverClusters module + the Agent service account to have cluster read rights; on
  // failure the job records CLUSTERLOG_ERROR which is surfaced. Witness hosts are refused.
  roTool(server,
    "generate_cluster_log",
    "Generate a FRESH WSFC Cluster.log from CURRENT cluster state on a fleet node (Get-ClusterLog) and return the matching " +
      "lines — for AG/cluster incident analysis (node RESOLVING, quorum loss, witness arbitration, netft) when you want a " +
      "freshly-rendered log rather than the on-disk snapshot read_cluster_reports returns. Runs ON THE NODE via a transient " +
      "SQL Agent PowerShell job (SMB/445 is firewalled fleet-wide), reads it back over the SQL connection, and auto-removes " +
      "the job. Cluster.log is large: pass `contains` (regex; recommended — e.g. an incident timestamp '2026/06/19-05:2[0-9]' " +
      "or 'witness|quorum|RESOLVING|netft') and/or `tail`, and keep time_span_minutes tight. Pair with read_error_log + " +
      "read_sql_dump + get_hiq for the SQL side of the same window. REJECTED for kind='witness' (no SQL endpoint to run the job).",
    {
      instance_name: z.string().describe("Cluster-node fleet instance (e.g. 'region3-node1'). Witness hosts are refused."),
      time_span_minutes: z.number().int().min(5).max(1440).optional().default(60).describe("How far back Get-ClusterLog renders (-TimeSpan, minutes). Default 60; smaller = faster + smaller log."),
      contains: z.string().optional().describe("Regex to filter lines (case-insensitive). STRONGLY recommended — e.g. an incident-window timestamp or 'witness|quorum|RESOLVING|netft'."),
      tail: z.number().int().min(1).max(50000).optional().describe("Return the last N lines after filtering."),
      max_lines: z.number().int().min(1).max(20000).optional().default(2000).describe("Hard cap on returned lines (default 2000)."),
    },
    async ({ instance_name, time_span_minutes, contains, tail, max_lines }: { instance_name: string; time_span_minutes?: number; contains?: string; tail?: number; max_lines?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        if (cfg.kind === "witness") {
          return err(`Instance "${instance_name}" is a WSFC file-share witness with no SQL endpoint — generate_cluster_log runs via the node's SQL Agent. Pick the affected db node (e.g. region3-node1).`);
        }
        const span = time_span_minutes ?? 60;
        const cap = max_lines ?? 2000;

        // Inner PowerShell run by the Agent job ON THE HOST. __OUTPATH__ is substituted at runtime.
        // Single-quoted here-string below, so $-vars here are the inner script's own.
        const innerCmd = [
          `$ErrorActionPreference='Stop'`,
          `try {`,
          `  Import-Module FailoverClusters -ErrorAction Stop`,
          `  $dst = Split-Path -Path '__OUTPATH__'`,
          `  $fi = Get-ClusterLog -Node $env:COMPUTERNAME -Destination $dst -TimeSpan ${span} -UseLocalTime -ErrorAction Stop`,
          `  $src = @($fi | ForEach-Object { $_.FullName } | Where-Object { $_ })[0]`,
          `  if (-not $src) { $src = (Get-ChildItem -Path $dst -Filter '*cluster.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName }`,
          `  if (-not $src) { throw 'Get-ClusterLog produced no file' }`,
          `  Copy-Item -LiteralPath $src -Destination '__OUTPATH__' -Force`,
          `} catch {`,
          `  ('CLUSTERLOG_ERROR: ' + $_.Exception.Message) | Out-File -FilePath '__OUTPATH__' -Encoding Unicode`,
          `}`,
        ].join("\n");

        const dirExpr =
          `DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));` +
          `DECLARE @dir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX('\\',REVERSE(@log)));SELECT @dir AS d;`;

        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          `Import-Module dbatools -ErrorAction Stop`,
          connectBlock(cfg),
          `$dirQ = @'`,
          dirExpr,
          `'@`,
          `$dir = [string](Invoke-DbaQuery -SqlInstance $server -Query $dirQ -EnableException -As PSObject).d`,
          `if (-not $dir) { throw "Could not resolve the SQL log directory via SERVERPROPERTY('ErrorLogFileName')." }`,
          `$out = (Join-Path $dir 'appdb_mcp_clusterlog.txt')`,
          `$pesc = $out -replace "'","''"`,
          `$stepTpl = @'`,
          innerCmd,
          `'@`,
          `$step = $stepTpl.Replace('__OUTPATH__', $out)`,
          `$job = 'appdb_mcp_clog_' + ([guid]::NewGuid().ToString('N').Substring(0,8))`,
          `$body = $null`,
          `try {`,
          `  New-DbaAgentJob -SqlInstance $server -Job $job -Category '[Uncategorized (Local)]' -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  New-DbaAgentJobStep -SqlInstance $server -Job $job -StepName 'run' -Subsystem PowerShell -Command $step -OnSuccessAction QuitWithSuccess -OnFailAction QuitWithFailure -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  Start-DbaAgentJob -SqlInstance $server -Job $job -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  $tries = 0`,
          `  do { Start-Sleep -Seconds 3; $j = Get-DbaAgentJob -SqlInstance $server -Job $job; $tries++ } while ($j.CurrentRunStatus -ne 'Idle' -and $tries -lt 60)`,
          `  if ($j.CurrentRunStatus -ne 'Idle') { throw "Transient Agent job '$job' did not finish in time (status=$($j.CurrentRunStatus))." }`,
          `  $body = [string](Invoke-DbaQuery -SqlInstance $server -Query "SELECT CAST(BulkColumn AS nvarchar(max)) AS body FROM OPENROWSET(BULK N'$pesc', SINGLE_NCLOB) AS x" -EnableException -As PSObject).body`,
          `  if (-not $body) { $body = [string](Invoke-DbaQuery -SqlInstance $server -Query "SELECT CAST(BulkColumn AS varchar(max)) AS body FROM OPENROWSET(BULK '$pesc', SINGLE_CLOB) AS x" -EnableException -As PSObject).body }`,
          `} finally {`,
          `  Remove-DbaAgentJob -SqlInstance $server -Job $job -Confirm:$false -EnableException -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null`,
          `}`,
          `if ($null -eq $body) { $body = '' }`,
          `Write-Output $body`,
        ].join("\n");

        const r = await runPowerShell(script, HC_TIMEOUT_S, { APPDB_SQL_PASSWORD: process.env.SQL_PASSWORD ?? "" });
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        const body = r.stdout;
        const errMatch = body.match(/CLUSTERLOG_ERROR:.*/);
        if (errMatch) {
          return err(`Get-ClusterLog failed on ${cfg.name}: ${errMatch[0].slice(0, 300)} — the SQL Agent service account likely lacks cluster permissions, or the FailoverClusters module is not present on the node.`);
        }
        let lines = body.split(/\r?\n/);
        const total = lines.length;
        if (contains) { const re = new RegExp(contains, "i"); lines = lines.filter((l) => re.test(l)); }
        const matched = lines.length;
        if (tail) lines = lines.slice(-tail);
        if (lines.length > cap) lines = lines.slice(0, cap);
        return { content: [{ type: "text", text: JSON.stringify({
          instance: cfg.name,
          channel: "sql:agent-powershell-job (Get-ClusterLog)",
          time_span_minutes: span,
          total_lines: total, matched_lines: matched, returned_lines: lines.length,
          filter: contains ?? "", tail: tail ?? null,
          lines,
        }) }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // read_sql_dump — list / read SQLDump*.txt produced by AV/exception
  // ============================================================
  // SQL Server writes stack-dump text + minidump on AV (c0000005), assertion failure,
  // non-yielding scheduler, latch timeout etc. Files land in the instance Log directory
  // alongside ERRORLOG: <SqlInstall>\MSSQL\Log\SQLDump<NNNN>.txt (human-readable stack +
  // module load list) and SQLDump<NNNN>.mdmp (binary minidump for windbg/sqldumper).
  //
  // CHANNEL: SQL/1433 (NOT SMB). SMB/445 is firewalled fleet-wide, so this reads over
  // the same TDS connection the other SQL tools use — the log directory is resolved from
  // SERVERPROPERTY('ErrorLogFileName'); action='list' enumerates via the read-only
  // sys.dm_os_enumerate_filesystem DMF; action='read' streams the .txt via OPENROWSET
  // BULK (SINGLE_NCLOB/SINGLE_CLOB). Read-only, no host-side side effects. The binary
  // .mdmp is rejected here — use windbg/sqldumper on the host for the minidump.
  roTool(server,
    "read_sql_dump",
    "Read SQL Server stack-dump artifacts (SQLDump<NNNN>.txt produced on AV / exception / non-yielding-scheduler / latch-timeout) from the instance MSSQL\\Log directory — OVER THE SQL CONNECTION (1433), not SMB, so it works even though SMB/445 is firewalled across the fleet. " +
      "action='list' enumerates SQLDump*.txt/.log files (filename, size, LastWriteTimeUtc via sys.dm_os_enumerate_filesystem) so you can pick the dump for an incident window. " +
      "action='read' returns the text lines of one .txt file (the full stack + module load list — search for 'Exception Address', 'pdb=', 'Module load completed') via OPENROWSET BULK. " +
      "Pair with read_error_log (matching SQLDump<NNNN>.txt in ERRORLOG by the 'Stack Dump being sent to ...' line) and read_cluster_reports (Cluster.log around the same window). " +
      "REJECTED for kind='witness' hosts — file-share witnesses don't run SQL. " +
      "Use this whenever you have a c0000005 / 17311 / 17310 / non-yielding-scheduler hit in ERRORLOG and need the faulting module/RVA (e.g. 'SqlDK.pdb rva=0x68E8') to confirm a crash class.",
    {
      instance_name: z.string().describe("Fleet instance whose SQL Log directory to read (e.g. 'region2-node2', 'region3-node1'). Witness hosts are refused."),
      action: z.enum(["list", "read"]).optional().default("list").describe("'list' (default) = enumerate SQLDump* files; 'read' = return lines from one .txt file."),
      file: z.string().optional().describe("Filename to read (required for action='read'). Plain filename only — no path separators. e.g. 'SQLDump0004.txt'. .mdmp is rejected (binary)."),
      contains: z.string().optional().describe("Regex to filter lines (case-insensitive). e.g. 'Exception (Address|Code)|pdb=|Module load completed' to extract just the faulting frame + module table."),
      tail: z.number().int().min(1).max(50000).optional().describe("Return the last N lines after filtering."),
      max_lines: z.number().int().min(1).max(20000).optional().default(2000).describe("Hard cap on returned lines (default 2000)."),
    },
    async ({ instance_name, action, file, contains, tail, max_lines }: { instance_name: string; action?: "list" | "read"; file?: string; contains?: string; tail?: number; max_lines?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        if (cfg.kind === "witness") {
          return err(`Instance "${instance_name}" is a WSFC file-share witness, not a SQL host — there is no MSSQL\\Log directory here. Pick the affected db node (e.g. region2-node2).`);
        }
        const act = action ?? "list";
        const cap = max_lines ?? 2000;

        // ---- Channel: SQL/1433, NOT SMB ----------------------------------
        // SMB/445 is firewalled across the AppDb DB fleet (only 1433 + 3389 are
        // reachable from the MCP host — verified 2026-06-11), so the dump files
        // cannot be read via \\<host>\C$. Everything below rides the existing SQL
        // connection instead:
        //   * log dir : SERVERPROPERTY('ErrorLogFileName') -> its parent directory
        //   * list    : sys.dm_os_enumerate_filesystem(@dir,'SQLDump*')  (SQL2022+, read-only)
        //   * read    : OPENROWSET(BULK '<file>', SINGLE_NCLOB|SINGLE_CLOB) (needs ADMINISTER BULK OPERATIONS)
        // The fleet runs SQL 2022 and the MCP login is sysadmin + has bulk rights,
        // so this is read-only with zero host-side side effects. OPENROWSET requires
        // a STRING-LITERAL data path (no @variable), so the literal is assembled in
        // PowerShell from the resolved directory + the (validated) file name.
        // Dump-dir resolution: on most nodes SQLDump*.txt land in the ERRORLOG directory,
        // but where -e relocates the ERRORLOG (e.g. L:\MSSQL\ErrorLogs on most nodes)
        // the dumps still go to the install default ...\MSSQL\Log on C:. So we probe the
        // ERRORLOG dir (SERVERPROPERTY, authoritative) AND the known install Log dirs AND the
        // fleet's relocated log volume L:\MSSQL\ErrorLogs, and use whichever holds the dumps.
        // sys.dm_os_enumerate_filesystem returns 0 rows (no error) for a missing dir, so
        // listing non-existent candidates is safe (verified on the fleet 2026-06-11).
        const dirExpr =
          `DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));` +
          `DECLARE @errDir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX('\\',REVERSE(@log)));`;
        const candCte =
          `;WITH cand(dir,pref) AS (` +
          `SELECT @errDir,0 ` +
          `UNION ALL SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Log',1 ` +
          `UNION ALL SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log',2 ` +
          `UNION ALL SELECT N'L:\\MSSQL\\ErrorLogs',3),` +
          `d AS (SELECT dir,MIN(pref) AS pref FROM cand GROUP BY dir) `;
        const dirQ = dirExpr + `SELECT @errDir AS log_directory;`;

        // Both actions run over the DIRECT mssql channel (queryInstance) — the same fast,
        // pooled TDS connection execute_query uses, authenticated as the same SQL login with
        // the same ReadOnly intent. We deliberately do NOT use the dbatools/PowerShell bridge
        // here: Import-Module dbatools + Invoke-DbaQuery adds seconds of overhead and HANGS on a
        // node with slow auth (e.g. REGION3-NODE1's SPN-registration failure → Kerberos→NTLM fallback),
        // which made dump reads time out at 120s even though direct SQL to the node was instant.
        if (act === "list") {
          const listQ =
            dirExpr + candCte +
            `SELECT d.dir AS log_directory,f.file_or_directory_name AS [Name],` +
            `CAST(f.size_in_bytes AS bigint) AS [Length],` +
            `CONVERT(varchar(33),f.last_write_time,126) AS [LastWriteTimeUtc] ` +
            `FROM d CROSS APPLY sys.dm_os_enumerate_filesystem(d.dir,'SQLDump*') f ` +
            `WHERE f.is_directory=0 ORDER BY f.last_write_time DESC;`;
          const { rows } = await queryInstance(cfg.name, listQ, 5000);
          const dumps = rows.map((rw) => ({
            Name: String(rw.Name),
            Length: Number(rw.Length),
            LastWriteTimeUtc: String(rw.LastWriteTimeUtc),
          }));
          let log_directory: string | null = rows.length ? String(rows[0].log_directory) : null;
          if (!log_directory) {
            const dr = await queryInstance(cfg.name, dirQ, 1);
            log_directory = (dr.rows[0]?.log_directory as string) ?? null;
          }
          return { content: [{ type: "text", text: JSON.stringify({
            instance: cfg.name,
            channel: "sql:dm_os_enumerate_filesystem",
            log_directory,
            dump_count: dumps.length,
            dumps,
          }) }] };
        }

        // action='read'
        if (!file) throw new Error("action='read' requires `file` (e.g. 'SQLDump0004.txt').");
        if (/[\\/]|\.\./.test(file)) throw new Error(`Invalid file name: ${file}. Plain filename only — no path separators or '..'.`);
        if (!/^SQLDump\d+\.txt$/i.test(file)) {
          throw new Error(`read_sql_dump only reads SQLDump<NNNN>.txt files. '${file}' is not a text stack-dump. For the binary .mdmp use windbg or sqldumper on the host.`);
        }
        // Resolve which candidate dir actually contains this dump (errorlog dir or install Log dir).
        const fileDirQ = dirExpr + candCte +
          `SELECT TOP 1 d.dir AS log_directory ` +
          `FROM d CROSS APPLY sys.dm_os_enumerate_filesystem(d.dir,N'${sq(file)}') f ` +
          `WHERE f.is_directory=0 ORDER BY d.pref;`;
        let dir = ((await queryInstance(cfg.name, fileDirQ, 1)).rows[0]?.log_directory as string) || "";
        if (!dir) dir = ((await queryInstance(cfg.name, dirQ, 1)).rows[0]?.log_directory as string) || "";
        if (!dir) throw new Error("Could not resolve the SQL dump directory (searched the ERRORLOG dir and the install \\MSSQL\\Log dirs).");
        const fullPath = dir.replace(/[\\/]+$/, "") + "\\" + file;
        const pesc = fullPath.replace(/'/g, "''");
        // SQLDump*.txt are usually UTF-16 (SINGLE_NCLOB); some builds emit DBCS/ASCII (SINGLE_CLOB).
        // Try Unicode first, fall back to DBCS on a codepage error. OPENROWSET needs a string-literal
        // path (no @variable), so the validated dir + (regex-checked) file name is embedded directly.
        let body = "";
        try {
          const rr = await queryInstance(cfg.name, `SELECT CAST(BulkColumn AS nvarchar(max)) AS body FROM OPENROWSET(BULK N'${pesc}', SINGLE_NCLOB) AS x`, 1);
          body = (rr.rows[0]?.body as string) ?? "";
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          if (/Unicode|double-byte|DBCS|SINGLE_NCLOB|SINGLE_CLOB|code page/i.test(msg)) {
            const rr = await queryInstance(cfg.name, `SELECT CAST(BulkColumn AS varchar(max)) AS body FROM OPENROWSET(BULK '${pesc}', SINGLE_CLOB) AS x`, 1);
            body = (rr.rows[0]?.body as string) ?? "";
          } else {
            throw e;
          }
        }
        if (!body) throw new Error(`File not found or empty over the SQL channel: ${fullPath} (OPENROWSET BULK returned nothing — confirm the file exists via action='list').`);
        let lines = body.split(/\r?\n/);
        if (contains) {
          const re = new RegExp(contains, "i");
          lines = lines.filter((l) => re.test(l));
        }
        if (tail) lines = lines.slice(-tail);
        if (lines.length > cap) lines = lines.slice(0, cap);
        return { content: [{ type: "text", text: JSON.stringify({
          file: fullPath,
          channel: "sql:openrowset",
          filter: contains ?? "",
          tail: tail ?? null,
          line_count: lines.length,
          lines,
        }) }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_host_event_log — Application/System Event Log over the SQL connection (1433)
  // ============================================================
  // SMB/445 is firewalled fleet-wide, so we CANNOT read \\<host>\C$\...\winevt\Logs\<log>.evtx
  // directly (and a binary .evtx isn't OPENROWSET-parseable anyway). Instead we run
  // Get-WinEvent ON THE HOST via a one-shot SQL Agent PowerShell-subsystem job, have it
  // write a JSON array to a temp file in the SQL Log dir, read that back over the SQL
  // connection with OPENROWSET BULK, then DROP the job (always, in a finally). No
  // xp_cmdshell / OLE / CLR is enabled — no server-wide config is changed.
  //
  // Filters applied on the host via FilterHashtable (LogName is required since we read
  // the live log by name, plus level/provider/id/timestamp). The 'contains' regex is
  // applied on the host to the message text since FilterHashtable has no text predicate.
  roTool(server,
    "get_host_event_log",
    "Read Windows Event Log entries from a fleet host over the SQL connection (1433) — Application by default. Use to correlate SQL Server AV / process crashes / WER reports with the SQL ERRORLOG. " +
      "SMB/445 is firewalled fleet-wide, so this runs Get-WinEvent ON THE HOST via a transient SQL Agent PowerShell job that writes JSON to the SQL Log dir, which is read back via OPENROWSET BULK; the job is always auto-removed. No xp_cmdshell/OLE/CLR is enabled. " +
      "Filters: provider (e.g. 'Application Error', 'Windows Error Reporting', 'MSSQLSERVER'), level (1=Critical, 2=Error, 3=Warning, 4=Info), event_id, time window (after/before, ISO-8601), and a host-side `contains` regex on the message text. " +
      "Defaults to the last 200 events. Pair with read_sql_dump (SQLDumpNNNN.txt timestamp ≈ Application Error / sqlservr.exe event timestamp) and read_error_log. " +
      "Witness hosts (kind='witness') are REJECTED — they have no SQL endpoint, so the Agent-job channel cannot reach them; target the affected DB node instead.",
    {
      instance_name: z.string().describe("Fleet DB instance to read events from (e.g. 'region2-node2', 'region3-node1'). Witness hosts are refused — they have no SQL endpoint."),
      log_name: z.enum(["Application", "System", "Security", "Setup"]).optional().default("Application").describe("Which event log to read. Default 'Application' — covers sqlservr.exe Application Error and WER reports. 'System' covers service crashes, disk, network, cluster netft."),
      provider: z.string().optional().describe("Filter to one provider/source name (e.g. 'Application Error', 'Windows Error Reporting', 'MSSQLSERVER', 'MSSQL$MSSQLSERVER', 'Service Control Manager')."),
      level: z.number().int().min(1).max(5).optional().describe("1=Critical, 2=Error, 3=Warning, 4=Informational, 5=Verbose. Omit for all."),
      event_id: z.number().int().optional().describe("Filter to one event ID (e.g. 1000 = Application Error for sqlservr.exe crash)."),
      after: z.string().optional().describe("ISO-8601 datetime (UTC) lower bound, e.g. '2026-06-10T20:00:00Z'. Inclusive."),
      before: z.string().optional().describe("ISO-8601 datetime (UTC) upper bound."),
      contains: z.string().optional().describe("Regex to filter the event Message text (case-insensitive, applied locally after the FilterHashtable). Use this to scope to 'sqlservr.exe', 'ctiuser.dll', etc."),
      max_events: z.number().int().min(1).max(5000).optional().default(200).describe("Hard cap on events returned (default 200, newest first)."),
    },
    async ({ instance_name, log_name, provider, level, event_id, after, before, contains, max_events }: { instance_name: string; log_name?: "Application" | "System" | "Security" | "Setup"; provider?: string; level?: number; event_id?: number; after?: string; before?: string; contains?: string; max_events?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        if (cfg.kind === "witness") {
          return err(`Instance "${instance_name}" is a WSFC file-share witness with no SQL endpoint. The event-log reader now rides the SQL connection (SMB/445 is firewalled fleet-wide), so it cannot target a witness — pick the affected DB node (e.g. region2-node2).`);
        }
        const ln = log_name ?? "Application";
        const cap = max_events ?? 200;
        const readCap = contains ? cap * 4 : cap;

        // ---- Channel: SQL/1433 via a TRANSIENT SQL Agent PowerShell job ---------
        // SMB/445 is firewalled across the AppDb DB fleet, so we can't read
        // \\<host>\C$\...\winevt\Logs\<log>.evtx directly — and the .evtx is binary,
        // so OPENROWSET can't parse it either. Instead we run Get-WinEvent ON THE HOST
        // through a one-shot SQL Agent PowerShell-subsystem job (Agent is running fleet-
        // wide; PowerShell subsystem registered), have it write a JSON array to a temp
        // file in the SQL Log dir, read that file back over the SQL connection via
        // OPENROWSET BULK, then DROP the job. No xp_cmdshell / OLE / CLR is enabled (all
        // remain off), and no server-wide config is changed. The job is always removed in
        // a finally block. LogName is REQUIRED in the FilterHashtable (we read the live
        // log by name on the host, not a .evtx -Path).
        const hashEntries: string[] = [`LogName='${sq(ln)}'`];
        if (provider) hashEntries.push(`ProviderName='${sq(provider)}'`);
        if (typeof level === "number") hashEntries.push(`Level=${level}`);
        if (typeof event_id === "number") hashEntries.push(`Id=${event_id}`);
        if (after)  hashEntries.push(`StartTime=[datetime]::Parse('${sq(after)}').ToUniversalTime()`);
        if (before) hashEntries.push(`EndTime=[datetime]::Parse('${sq(before)}').ToUniversalTime()`);
        const filterHash = `@{${hashEntries.join("; ")}}`;
        const containsClause = contains ? ` | Where-Object { $_.Message -match '${sq(contains)}' }` : "";

        // Inner PowerShell run by the Agent job ON THE HOST. __OUTPATH__ is substituted
        // at runtime with the resolved temp-file path. All $-vars here are the inner
        // script's own, so this is emitted inside a SINGLE-quoted here-string (no outer
        // interpolation).
        const innerCmd = [
          `$ErrorActionPreference='Stop'`,
          `try {`,
          `  $evts = Get-WinEvent -FilterHashtable ${filterHash} -MaxEvents ${readCap} -ErrorAction Stop${containsClause} | Select-Object -First ${cap}`,
          `} catch {`,
          `  if ($_.Exception.Message -match 'No events were found') { '[]' | Out-File -FilePath '__OUTPATH__' -Encoding Unicode; return }`,
          `  throw`,
          `}`,
          `$rows = @($evts) | ForEach-Object { $m = if ($_.Message) { ($_.Message -replace '\\s+',' ') } else { $null }; if ($m -and $m.Length -gt 800) { $m = $m.Substring(0,800) }; [pscustomobject]@{ TimeCreatedUtc=$_.TimeCreated.ToUniversalTime().ToString('o'); Id=$_.Id; Level=$_.LevelDisplayName; Provider=$_.ProviderName; Machine=$_.MachineName; RecordId=$_.RecordId; Message=$m } }`,
          `if (@($rows).Count -eq 0) { '[]' | Out-File -FilePath '__OUTPATH__' -Encoding Unicode } else { @($rows) | ConvertTo-Json -Depth 4 | Out-File -FilePath '__OUTPATH__' -Encoding Unicode }`,
        ].join("\n");

        const dirExpr =
          `DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));` +
          `DECLARE @dir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX('\\',REVERSE(@log)));SELECT @dir AS d;`;

        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          `Import-Module dbatools -ErrorAction Stop`,
          PS_SANITIZER,
          connectBlock(cfg),
          `$dirQ = @'`,
          dirExpr,
          `'@`,
          `$dir = [string](Invoke-DbaQuery -SqlInstance $server -Query $dirQ -EnableException -As PSObject).d`,
          `if (-not $dir) { throw "Could not resolve the SQL log directory via SERVERPROPERTY('ErrorLogFileName')." }`,
          `$out = (Join-Path $dir 'appdb_mcp_evtlog_${sq(ln)}.json')`,
          `$pesc = $out -replace "'","''"`,
          `$stepTpl = @'`,
          innerCmd,
          `'@`,
          `$step = $stepTpl.Replace('__OUTPATH__', $out)`,
          `$job = 'appdb_mcp_evt_' + ([guid]::NewGuid().ToString('N').Substring(0,8))`,
          `$body = $null`,
          `try {`,
          `  New-DbaAgentJob -SqlInstance $server -Job $job -Category '[Uncategorized (Local)]' -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  New-DbaAgentJobStep -SqlInstance $server -Job $job -StepName 'run' -Subsystem PowerShell -Command $step -OnSuccessAction QuitWithSuccess -OnFailAction QuitWithFailure -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  Start-DbaAgentJob -SqlInstance $server -Job $job -EnableException -WarningAction SilentlyContinue | Out-Null`,
          `  $tries = 0`,
          `  do { Start-Sleep -Milliseconds 1500; $j = Get-DbaAgentJob -SqlInstance $server -Job $job; $tries++ } while ($j.CurrentRunStatus -ne 'Idle' -and $tries -lt 40)`,
          `  if ($j.CurrentRunStatus -ne 'Idle') { throw "Transient Agent job '$job' did not finish within timeout (status=$($j.CurrentRunStatus))." }`,
          `  if ("$($j.LastRunOutcome)" -ne 'Succeeded') { throw "Transient Agent job '$job' failed (outcome=$($j.LastRunOutcome)) — the Agent service account may lack rights to read the '${sq(ln)}' event log, or Get-WinEvent errored on the host." }`,
          `  $body = [string](Invoke-DbaQuery -SqlInstance $server -Query "SELECT CAST(BulkColumn AS nvarchar(max)) AS body FROM OPENROWSET(BULK N'$pesc', SINGLE_NCLOB) AS x" -EnableException -As PSObject).body`,
          `} finally {`,
          `  Remove-DbaAgentJob -SqlInstance $server -Job $job -Confirm:$false -EnableException -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null`,
          `}`,
          `if ($null -eq $body -or $body.Length -eq 0) { $body = '[]' }`,
          `$parsed = @($body | ConvertFrom-Json)`,
          `[pscustomobject]@{`,
          `  instance     = '${sq(cfg.name)}'`,
          `  log_name     = '${sq(ln)}'`,
          `  channel      = 'sql:agent-powershell-job'`,
          `  note         = 'SMB/445 is firewalled fleet-wide; events were read by a transient SQL Agent PowerShell job (auto-removed). Temp JSON at ' + $out`,
          `  filter       = '${sq(filterHash)}'`,
          `  contains     = '${sq(contains ?? "")}'`,
          `  event_count  = @($parsed).Count`,
          `  events       = @($parsed)`,
          `} | ConvertTo-Json -Depth 5 -Compress`,
        ].join("\n");
        const r = await runPowerShell(script, CMD_TIMEOUT_S, { APPDB_SQL_PASSWORD: process.env.SQL_PASSWORD ?? "" });
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        return { content: [{ type: "text", text: r.stdout.trim() || "{}" }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_host_dll_versions — the EDR agent / third-party / SQL binary versions
  // ============================================================
  // When comparing a crashing node against a healthy peer, the actionable signal is
  // *which DLLs (and which versions) are loaded inside sqlservr.exe and on disk*. This
  // tool reads file metadata + Authenticode signer for a curated watchlist of injected
  // agents and SQL core binaries, plus any caller-supplied paths.
  //
  // Watchlist covers the modules that have appeared in AppDb AV stacks (the EDR agent
  // ctiuser/repmgr, third-party the cloud data warehouse ODBC, VC++ runtime, Windows core, SQL Binn). Paths
  // are wildcard-expanded under \\<host>\C$\... so MSSQL16.* / MSSQL15.* upgrade dirs
  // both match. Returns version + ProductVersion + signer + LastWriteTime per match.
  roTool(server,
    "get_host_dll_versions",
    "Get file version + signer + mtime for known third-party agents and SQL binaries on a fleet host. Use this to confirm or deny module-version hypotheses when diagnosing AV crashes — e.g. 'is the the EDR agent ctiuser.dll on region2-node2 the same 4.1:0.5463 build as REGION3-NODE1?', or 'do both nodes have identical sqldk.dll/sqllang.dll versions?'. " +
      "Watchlist (always probed): the EDR agent (Confer\\*.dll, including ctiuser.dll, repmgr.dll), third-party the cloud data warehouse ODBC (Googlethe cloud data warehouseODBC_sb64.dll), Windows core (ntdll, KERNELBASE, ucrtbase, bcrypt, bcryptPrimitives, vcruntime140, msvcp140), SQL binaries (sqlservr.exe, sqldk.dll, sqllang.dll, sqlmin.dll, sqltses.dll). Wildcards expand under MSSQL*.MSSQLSERVER and Program Files (x86) for x86 SQL features. " +
      "Optionally pass `paths` for ad-hoc lookups (relative-to-C: or \\\\absolute, no '..'). Returns: Path, FileVersion, ProductVersion, LastWriteTimeUtc, Length, SignerSubject (Authenticode). " +
      "Same SMB/PSDrive auth precedence as read_cluster_reports. REJECTED for kind='witness' hosts.",
    {
      instance_name: z.string().describe("Fleet instance to probe (e.g. 'region2-node2', 'region3-node1'). Witness hosts are refused."),
      include_watchlist: z.boolean().optional().default(true).describe("Probe the built-in watchlist of the EDR agent / third-party / Windows core / SQL Binn binaries. Default true."),
      paths: z.array(z.string()).optional().describe("Extra paths to probe under C:\\ — e.g. 'Program Files\\Microsoft Monitoring Agent\\Agent\\MonAgent.dll' or wildcards like 'Program Files\\*\\*.exe'. Relative paths (no leading slash) are joined under \\\\<host>\\C$\\. No '..' allowed."),
      include_signer: z.boolean().optional().default(true).describe("Include Authenticode SignerSubject (slower, one Get-AuthenticodeSignature per file). Default true. Set false for fast version-only listing."),
      max_files: z.number().int().min(1).max(500).optional().default(80).describe("Cap on rows returned (default 80)."),
    },
    async ({ instance_name, include_watchlist, paths, include_signer, max_files }: { instance_name: string; include_watchlist?: boolean; paths?: string[]; include_signer?: boolean; max_files?: number }) => {
      try {
        const cfg = resolveInstance(instance_name);
        if (cfg.kind === "witness") {
          return err(`Instance "${instance_name}" is a WSFC file-share witness — get_host_dll_versions is for SQL hosts. Use get_host_event_log for witness diagnostics.`);
        }
        const target = cfg.computer_name || cfg.host;
        const access = buildHostAccess(target);

        const watchlist = [
          // the EDR agent
          "Program Files\\Confer\\ctiuser.dll",
          "Program Files\\Confer\\repmgr.dll",
          "Program Files\\Confer\\scanner\\*.dll",
          // third-party the cloud data warehouse ODBC + its OpenSSL/curl deps
          "Program Files\\third-party the cloud data warehouse ODBC Driver\\lib\\Googlethe cloud data warehouseODBC_sb64.dll",
          "Program Files\\third-party the cloud data warehouse ODBC Driver\\lib\\libcurl.dll",
          "Program Files\\third-party the cloud data warehouse ODBC Driver\\lib\\libcrypto-3-x64.dll",
          "Program Files\\third-party the cloud data warehouse ODBC Driver\\lib\\libssl-3-x64.dll",
          // Windows core DLLs the crash path traverses
          "Windows\\System32\\ntdll.dll",
          "Windows\\System32\\KERNELBASE.dll",
          "Windows\\System32\\KERNEL32.DLL",
          "Windows\\System32\\ucrtbase.dll",
          "Windows\\System32\\bcrypt.dll",
          "Windows\\System32\\bcryptPrimitives.dll",
          // VC++ runtime (where heap-corruption AVs surface)
          "Windows\\System32\\vcruntime140.dll",
          "Windows\\System32\\msvcp140.dll",
          // SQL Binn — auto-expand to whichever MSSQL*.MSSQLSERVER is installed
          "Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
          "Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Binn\\sqldk.dll",
          "Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Binn\\sqllang.dll",
          "Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Binn\\sqlmin.dll",
          "Program Files\\Microsoft SQL Server\\MSSQL*.MSSQLSERVER\\MSSQL\\Binn\\sqltses.dll",
        ];
        // Path safety: only relative-to-C paths (no leading backslash, no drive letter, no ..)
        const userPaths = (paths ?? []).map((p) => {
          if (/\.\./.test(p)) throw new Error(`Path contains '..': ${p}`);
          if (/^[A-Za-z]:[\\/]/.test(p)) throw new Error(`Absolute drive path not allowed: ${p} (use relative-to-C, e.g. 'Program Files\\\\App\\\\app.dll').`);
          if (/^\\\\/.test(p)) throw new Error(`UNC path not allowed in 'paths': ${p}`);
          return p.replace(/^[\\/]+/, "");
        });
        const allPaths = [
          ...(include_watchlist !== false ? watchlist : []),
          ...userPaths,
        ];
        if (allPaths.length === 0) return err(`No paths to probe — set include_watchlist:true (default) or supply 'paths'.`);

        // Quote each path as a single-quoted PS literal; the outer @(...) makes an array.
        const psArray = `@(${allPaths.map((p) => `'${sq(p)}'`).join(", ")})`;
        const wantSigner = include_signer !== false;

        const script = [
          `Set-StrictMode -Off`,
          `$ErrorActionPreference = 'Stop'`,
          access.prologue,
          `try {`,
          `  $patterns = ${psArray}`,
          `  $results = @()`,
          `  foreach ($rel in $patterns) {`,
          `    $full = Join-Path $hostC $rel`,
          `    $items = @()`,
          `    try { $items = @(Resolve-Path -Path $full -ErrorAction Stop | ForEach-Object { Get-Item -LiteralPath $_.Path -ErrorAction Stop }) } catch { $items = @() }`,
          `    if ($items.Count -eq 0) {`,
          `      $results += [pscustomobject]@{ Pattern=$rel; Path=$null; Status='not-found'; FileVersion=$null; ProductVersion=$null; LengthBytes=$null; LastWriteTimeUtc=$null; SignerSubject=$null }`,
          `      continue`,
          `    }`,
          `    foreach ($item in $items) {`,
          `      $vi = $item.VersionInfo`,
          `      $signer = $null`,
          wantSigner
            ? `      try { $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop; if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject } else { $signer = $sig.Status.ToString() } } catch { $signer = '<sig-error>' }`
            : `      $signer = '<not-requested>'`,
          `      $results += [pscustomobject]@{`,
          `        Pattern          = $rel`,
          `        Path             = $item.FullName`,
          `        Status           = 'ok'`,
          `        FileVersion      = $vi.FileVersion`,
          `        ProductVersion   = $vi.ProductVersion`,
          `        LengthBytes      = $item.Length`,
          `        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')`,
          `        SignerSubject    = $signer`,
          `      }`,
          `      if ($results.Count -ge ${max_files}) { break }`,
          `    }`,
          `    if ($results.Count -ge ${max_files}) { break }`,
          `  }`,
          `  [pscustomobject]@{`,
          `    host          = '${sq(target)}'`,
          `    cred_source   = $__credSource`,
          `    pattern_count = $patterns.Count`,
          `    result_count  = @($results).Count`,
          `    results       = @($results)`,
          `  } | ConvertTo-Json -Depth 4 -Compress`,
          `} finally {`,
          `  ${access.epilogue}`,
          `}`,
        ].join("\n");
        const r = await runPowerShell(script, CMD_TIMEOUT_S, access.extraEnv ?? {});
        if (r.exitCode !== 0) return err((r.stderr.trim() || r.stdout.trim()).slice(0, 4000));
        return { content: [{ type: "text", text: r.stdout.trim() || "{}" }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  log(`[dbatools] bridge registered (exe=${PWSH}); read-only health check uses ${HC_USER ? `SQL login ${HC_USER}` : "Windows auth"}`);
}
