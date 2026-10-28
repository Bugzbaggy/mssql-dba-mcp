/**
 * Every dbatools cmdlet the generated health-check scripts call exists in the INSTALLED dbatools,
 * and every parameter they pass to it is real — otherwise that check fails at run time with
 * "command not found" / "a parameter cannot be found", which reads like a node problem.
 *
 * This replaces section 2 of the retired tests/validate-healthcheck.ps1. It reads the scripts the
 * engine actually generates — remote (with a Windows credential, so the OS checks render) and
 * on-node (HEALTHCHECK_OS_LOCAL=1) — rather than a hand-kept list, so a new cmdlet or parameter
 * is covered the moment the generator emits it. Needs Windows PowerShell with dbatools
 * installed (this repository is tested against 2.7.2); skipped elsewhere.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const havePs = process.platform === "win32" &&
  spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
    "if (Get-Module -ListAvailable dbatools) { 'yes' }"], { encoding: "utf8" }).stdout?.trim() === "yes";

function generate(env: Record<string, string>): string {
  const file = new URL("./.dbatools-cmdlets-gen.tmp.mts", import.meta.url);
  writeFileSync(file, [
    "import { buildHealthCheckScript } from '../src/dbatools.js';",
    "const cfg = { name: 'region1-node2', host: '10.0.9.9', port: 1433, database: 'AppCatalog' };",
    "process.stdout.write(buildHealthCheckScript(cfg as never, false, 25));",
  ].join("\n"), "utf8");
  try {
    return execFileSync(process.execPath, ["--import", "tsx", fileURLToPath(file)],
      { encoding: "utf8", env: { ...process.env, ...env }, maxBuffer: 32 * 1024 * 1024 });
  } finally { rmSync(file, { force: true }); }
}

/** cmdlet -> parameters it is called with, from every `Verb-Dba*` call in the scripts. */
function usage(scripts: string[]): Map<string, Set<string>> {
  const used = new Map<string, Set<string>>();
  const call = /\b((?:Get|Test|Measure|Find|Invoke|Connect|Set|New|Start|Remove)-Dba[A-Za-z]+)\b([^|;}\n]*)/g;
  for (const s of scripts)
    for (const m of s.matchAll(call)) {
      const params = used.get(m[1]) ?? new Set<string>();
      for (const p of m[2].matchAll(/(?:^|\s)-([A-Za-z][A-Za-z0-9]*)\b/g)) params.add(p[1]);
      used.set(m[1], params);
    }
  // Passed by splatting (@__xd), so invisible to the regex above.
  for (const c of ["Get-DbaLastGoodCheckDb", "Test-DbaIdentityUsage"]) used.get(c)?.add("ExcludeDatabase");
  return used;
}

test("every dbatools cmdlet and parameter the health check uses exists in the installed dbatools", { skip: !havePs && "needs Windows PowerShell with dbatools" }, () => {
  const scripts = [
    generate({ HEALTHCHECK_WIN_USER: "DOMAIN\\svc", HEALTHCHECK_WIN_PASSWORD: "x" }),
    generate({ HEALTHCHECK_OS_LOCAL: "1" }),
  ];
  const used = usage(scripts);
  assert.ok(used.size >= 30, `expected the catalog's cmdlets, found ${used.size}`);
  assert.ok(used.get("Invoke-DbaQuery")?.has("QueryTimeout"), "sp_BlitzIndex's own budget is a real parameter");
  const spec = JSON.stringify(Object.fromEntries([...used].map(([c, ps]) => [c, [...ps]])));
  const file = join(tmpdir(), `appdb-hc-cmdlets-${process.pid}.json`);
  writeFileSync(file, spec, "utf8");
  try {
    const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", [
      "Import-Module dbatools -ErrorAction Stop -WarningAction SilentlyContinue",
      `$spec = Get-Content -Raw '${file}' | ConvertFrom-Json`,
      "$bad = @()",
      "foreach ($p in $spec.PSObject.Properties) {",
      "  $c = Get-Command $p.Name -ErrorAction SilentlyContinue",
      "  if (-not $c) { $bad += ('missing cmdlet ' + $p.Name); continue }",
      "  foreach ($a in $p.Value) { if (-not $c.Parameters.ContainsKey($a)) { $bad += ($p.Name + ' has no -' + $a) } }",
      "}",
      "'VERSION ' + (Get-Module dbatools).Version",
      "if ($bad.Count) { $bad } else { 'ALL OK' }",
    ].join("; ")], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
    assert.match(out, /ALL OK/, out);
  } finally { rmSync(file, { force: true }); }
});
