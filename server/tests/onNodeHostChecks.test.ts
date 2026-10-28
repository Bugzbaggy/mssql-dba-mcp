/**
 * On-node Host checks that do not need an elevated token, and the other "Could not run" causes
 * a weekly report can hit.
 *
 * The weekly job runs as the SQL Agent service account in a CmdExec step, and that process is
 * typically not elevated: Test-DbaPowerPlan "Console not elevated", Get-DbaPrivilege WSManFault
 * Code 5 Access is denied, Get-DbaOperatingSystem "Multiple protocol connections were attempted"
 * and Get-DbaComputerSystem "Host: ? logical CPU(s), ? RAM". Also: sp_BlitzIndex can time out at
 * the 60 s statement timeout or overflow money on one database; Get-DbaLastGoodCheckDb and
 * Test-DbaIdentityUsage throw when a database on the replica is not accessible.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildHealthCheckScript, toFinding, HOST_LOCAL_INNER } from "../src/dbatools.js";

const cfg = { name: "region1-node2", host: "10.0.9.9", port: 1433, database: "AppCatalog" } as never;
const remote = buildHealthCheckScript(cfg, false, 25);

// HEALTHCHECK_OS_LOCAL is read once at module load, so the deployed variant is built in a child.
function onNode(): string {
  const file = new URL("./.on-node-host.tmp.mts", import.meta.url);
  writeFileSync(file, [
    "import { buildHealthCheckScript } from '../src/dbatools.js';",
    "const cfg = { name: 'region1-node2', host: '10.0.9.9', port: 1433, database: 'AppCatalog' };",
    "process.stdout.write(buildHealthCheckScript(cfg, false, 25));",
  ].join("\n"), "utf8");
  try {
    return execFileSync(process.execPath, ["--import", "tsx", fileURLToPath(file)], {
      encoding: "utf8", env: { ...process.env, HEALTHCHECK_OS_LOCAL: "1" }, maxBuffer: 32 * 1024 * 1024,
    });
  } finally { rmSync(file, { force: true }); }
}
const local = onNode();

/** The scriptblock text handed to Invoke-CheckWithTimeout for one label. */
function actionFor(script: string, label: string): string {
  const at = script.indexOf(`label='${label}'`);
  const start = script.lastIndexOf("  $d = ", at);
  return script.slice(start, script.indexOf("\n  $__skip = ", start));
}

test("the run identity and token are read by SID, not by localized group names", () => {
  assert.match(local, /whoami\.exe \/groups \/fo csv \/nh/);
  for (const sid of ["S-1-5-32-544", "S-1-16-12288", "S-1-16-8192", "S-1-16-16384"])
    assert.ok(local.includes(`'${sid}'`), `missing ${sid}`);
  assert.match(local, /IsInRole\(\[Security\.Principal\.WindowsBuiltInRole\]::Administrator\)/,
    "the same test dbatools' Test-ElevationRequirement applies");
  assert.match(local, /BUILTIN\\Administrators /, "the backslash must reach the script");
  assert.match(local, /foreach \(\$__v in '__elevated','__admState','__runCtx','__inaccessibleDbs'\)/,
    "the worker runspace must see the same values, or every check there reads 'not elevated'");
});

test("on-node, each Host check reads locally when not elevated and keeps dbatools when it is", () => {
  const pp = actionFor(local, "Power plan");
  assert.match(pp, /if \(\$__elevated\) \{[\s\S]*Test-DbaPowerPlan -ComputerName \$osComputer/);
  assert.match(pp, /& powercfg\.exe \/getactivescheme/);
  assert.match(pp, /IsBestPractice = \(\$__guid -eq \$__hp\)/);
  assert.match(pp, /\\\(\(\[\^\)\]\*\)\\\)\\s\*\$/, "the scheme-name regex must keep its backslashes");
  assert.match(actionFor(local, "Operating system"), /Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop/);
  const cs = actionFor(local, "Computer system");
  assert.match(cs, /Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop/);
  assert.match(cs, /\$null -ne \$__r\[0\]\.NumberLogicalProcessors/,
    "a dbatools row with no processor data is the '? logical CPU(s)' case and must fall back too");
  const pv = actionFor(local, "Service account privileges (IFI/LPIM)");
  assert.match(pv, /if \(\$__elevated\) \{ Get-DbaPrivilege -ComputerName \$osComputer/);
  assert.match(pv, /__hc_skip = /);
  assert.doesNotMatch(local, /Get-CimInstance[^\n]*-ComputerName/, "local CIM means no -ComputerName: no WinRM, no network logon");
});

test("remote runs keep their behaviour: no credential still means a fast skip, never a local read", () => {
  // A remote run reading the MCP host's own power plan or OS would report the wrong machine.
  assert.equal(actionFor(remote, "Power plan").trim(), "$d = $null");
  assert.doesNotMatch(remote, /powercfg\.exe \/getactivescheme|Get-CimInstance -ClassName Win32_OperatingSystem|__hc_skip = /);
});

test("a run-time skip is recorded as 'skipped' with its reason, never as data", () => {
  assert.match(local, /\$__skip = \$\(if \(\$null -ne \$d\) \{ @\(\$d\)\[0\]\.__hc_skip \} else \{ \$null \}\)/);
  assert.match(local, /status='skipped'; rows=0; shown=0; capped=\$false; data=\$null; reason=\[string\]\$__skip/);
  const f = toFinding({ category: "Host", label: "Service account privileges (IFI/LPIM)", command: "Get-DbaPrivilege",
    priority: "Medium", status: "skipped", rows: 0, reason: "Not run: needs a local Administrator token." } as never);
  assert.equal(f.status, "Info");
  assert.equal(f.details, "Not run: needs a local Administrator token.");
});

test("fallback rows render real values and say how they were read", () => {
  const run = (label: string, command: string, row: Record<string, unknown>) =>
    toFinding({ category: "Host", label, command, priority: "Low", status: "ok", rows: 1, shown: 1, data: [row] } as never).details;
  assert.equal(run("Computer system", "Get-DbaComputerSystem",
    { NumberLogicalProcessors: 8, TotalPhysicalMemory: "32.00 GB", Domain: "corp.example.com", Source: "local CIM (this run is not elevated)" }),
    "Host: 8 logical CPU(s), 32.00 GB RAM, domain corp.example.com. Read with local CIM (this run is not elevated).");
  assert.match(run("Computer system", "Get-DbaComputerSystem", { ComputerName: "REGION1-NODE2" }),
    /no processor or memory data/, "never '? logical CPU(s), ? RAM'");
  assert.equal(run("Operating system", "Get-DbaOperatingSystem",
    { OSVersion: "Microsoft Windows Server 2025 Datacenter", Architecture: "64-bit" }),
    "OS: Microsoft Windows Server 2025 Datacenter (64-bit).");
  const pp = run("Power plan", "Test-DbaPowerPlan",
    { ActivePowerPlan: "Balanced", IsBestPractice: false, RecommendedPowerPlan: "High performance", Source: "powercfg /getactivescheme (this run is not elevated)" });
  assert.match(pp, /^Active power plan: Balanced - not High performance/);
  assert.match(pp, /powercfg \/setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c/);
  assert.match(pp, /Read with powercfg \/getactivescheme \(this run is not elevated\)\.$/);
});

test("the fallbacks are wired for exactly the four on-node Host checks", () => {
  assert.deepEqual(Object.keys(HOST_LOCAL_INNER).sort(),
    ["Computer system", "Operating system", "Power plan", "Service account privileges (IFI/LPIM)"]);
});

test("sp_BlitzIndex has its own budget and retries per database after a non-timeout failure", () => {
  const a = actionFor(local, "Index health (sp_BlitzIndex)");
  assert.match(a, /Invoke-CheckWithTimeout -TimeoutSec 600 -Action/);
  assert.match(a, /@GetAllDatabases = 1, @BringThePain = 1, @Mode = 0' -QueryTimeout 270/,
    "without -QueryTimeout, Invoke-DbaQuery uses the connection's 60 s StatementTimeout");
  assert.match(a, /if \(\$_\.Exception\.Message -match 'timed\? \?out'\) \{ throw \}/);
  assert.match(a, /@DatabaseName = N'" \+ \$__db\.Replace\("'", "''"\) \+ "', @BringThePain = 1, @Mode = 0"\) -QueryTimeout 120/);
  assert.match(a, /Finding = \('Database Skipped: ' \+ \$__db \+ ' - sp_BlitzIndex failed on it: '/);
  assert.match(local, /param\(\[scriptblock\]\$Action, \[int\]\$TimeoutSec = 0\)/);
  // Every other check keeps the global budget.
  assert.match(actionFor(local, "Agent job integrity"), /Invoke-CheckWithTimeout -Action \{/);
});

test("a database sp_BlitzIndex failed on is named with the error, and the retry note is shown", () => {
  const rows = [
    { Priority: 255, Finding: "Note: the all-databases call failed (Arithmetic overflow error converting expression to data type money.), so each database was analysed on its own.", "Database Name": "(all)" },
    { Priority: 1, Finding: "Database Skipped: AppDb_Data - sp_BlitzIndex failed on it: Arithmetic overflow error converting expression to data type money.", "Database Name": "AppDb_Data" },
  ];
  const f = toFinding({ category: "Performance", label: "Index health (sp_BlitzIndex)", command: "Invoke-DbaQuery",
    priority: "Medium", status: "fail", rows: rows.length, shown: rows.length, data: rows } as never);
  assert.match(f.details, /NOT ANALYSED: AppDb_Data — sp_BlitzIndex failed on it \(Arithmetic overflow error converting expression to data type money\.\)/);
  assert.match(f.details, /Note: the all-databases call failed/);
  assert.doesNotMatch(f.details, /skipped these/, "it was not a >100-partition skip");
  const s = f.remediation?.summary ?? "";
  assert.match(s, /sp_BlitzIndex FAILED on 1 database\(s\)/);
  assert.doesNotMatch(s, /because they have over 100 partitions/);
});

test("an inaccessible database is excluded from the two cmdlets that throw on it, and named", () => {
  for (const label of ["Last good CHECKDB", "Identity column capacity"]) {
    const a = actionFor(local, label);
    assert.match(a, /\$__xd = @\{\}; if \(@\(\$__inaccessibleDbs\)\.Count\) \{ \$__xd\['ExcludeDatabase'\] = @\(\$__inaccessibleDbs\) \}/, label);
  }
  assert.match(local, /SELECT name FROM sys\.databases WHERE state <> 0 OR HAS_DBACCESS\(name\) = 0/);
  assert.match(local, /note=\$\(if \(@\(\$__inaccessibleDbs\)\.Count\) \{ 'Not accessible on this replica when it ran, so not checked: '/);
  const f = toFinding({ category: "Recoverability", label: "Last good CHECKDB", command: "Get-DbaLastGoodCheckDb", priority: "High",
    status: "ok", rows: 0, note: "Not accessible on this replica when it ran, so not checked: AppDb_Routing." } as never);
  assert.match(f.details, /Not accessible on this replica when it ran, so not checked: AppDb_Routing\.$/);
});

test("the SQL Assessment child trusts the certificate on-node only, where the connection stays on the box", () => {
  // In practice the only connection in a run that validated the certificate was also the only
  // one that failed. Trusting it is acceptable for the on-node run, where the connection stays
  // on the box; a remote run crosses the network.
  assert.match(local, /Get-SqlInstance -ServerInstance \$env:COMPUTERNAME -TrustServerCertificate -ErrorAction Stop/);
  const winRemote = buildHealthCheckScript({ name: "region1-node2", host: "10.0.9.9", port: 1433, database: "AppCatalog" } as never, false, 25);
  assert.match(winRemote, /Get-SqlInstance -ServerInstance '10.0.9.9,1433' -ErrorAction Stop/);
  assert.doesNotMatch(winRemote, /Get-SqlInstance[^\n]*-TrustServerCertificate/);
});

test("the SQL Assessment child reports the innermost cause, not only SMO's 'Failed to connect'", () => {
  assert.match(local, /\$__e = \$_\.Exception; while \(\$null -ne \$__e\.InnerException\) \{ \$__e = \$__e\.InnerException \}/);
  assert.match(local, /__sa_error = \$\(if \(\$__e -ne \$_\.Exception\) \{ \$_\.Exception\.Message \+ ' Cause: ' \+ \$__e\.Message \}/);
});

test("both generated scripts parse in Windows PowerShell", { skip: process.platform !== "win32" }, () => {
  const dir = tmpdir();
  const files = [["local", local], ["remote", remote]].map(([tag, body]) => {
    const p = join(dir, `appdb-hc-parse-${tag}-${process.pid}.ps1`);
    writeFileSync(p, "﻿" + body, "utf8");
    return p;
  });
  try {
    const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
      files.map((p) => `$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('${p}',[ref]$t,[ref]$e);` +
        `'${p.endsWith("local-" + process.pid + ".ps1") ? "local" : "remote"}=' + @($e).Count; @($e) | Select-Object -First 3 | ForEach-Object { '  ' + $_.Extent.StartLineNumber + ': ' + $_.Message }`).join(";")],
      { encoding: "utf8" });
    assert.match(out, /local=0/, out);
    assert.match(out, /remote=0/, out);
  } finally { for (const p of files) rmSync(p, { force: true }); }
});
