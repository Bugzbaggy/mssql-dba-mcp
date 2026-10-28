import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  CATALOG, parseCapacityBaseline, capacitySymmetrySql, diskFailRule, diskSpaceEvalPs, diskRuleText,
  parseCoreDatabases, STRUCTURAL_LOGINS, DBATOOLS_EXPECTED, DBATOOLS_LIBRARY_EXPECTED,
} from "../src/dbatools.js";

// Several health checks need facts about the estate that one node cannot see (its partner's size)
// or that differ per site (which logins are structural, which volumes matter, which databases are
// core). Those are configuration, never constants in the code. These tests pin the defaults - safe
// and honest with nothing configured - and that configured values reach the emitted SQL and
// PowerShell intact and cannot inject anything.

const sqlOf = (label: string) => String(CATALOG.find((c) => c[1] === label)?.[4] ?? "");
const evalOf = (label: string) => String(CATALOG.find((c) => c[1] === label)?.[6] ?? "");

test("defaults: no site data is baked into the catalog", () => {
  const all = CATALOG.map((c) => `${c[4]}\n${c[6] ?? ""}`).join("\n");
  assert.doesNotMatch(all, /VALUES\('[A-Z0-9-]+-NODE\d/i, "no node sizing table");
  assert.doesNotMatch(all, /N'[D-Z]:\\/, "no site volume literal in a candidate-directory list");
  assert.doesNotMatch(all, /'[B-Z]:','[B-Z]:'/, "no drive-letter layout");
  assert.match(sqlOf("AG failover capacity symmetry"), /__hc_skip=/, "unconfigured capacity is SKIPPED, not judged");
  assert.equal(DBATOOLS_EXPECTED, "2.7.2");
  assert.equal(DBATOOLS_LIBRARY_EXPECTED, "2025.8.17");
  assert.deepEqual(STRUCTURAL_LOGINS, ["sa", "distributor_admin"]);
});

test("capacity baseline: only well-formed entries are accepted, and names are spliced safely", () => {
  const rows = parseCapacityBaseline(JSON.stringify([
    { node: "NODE-A", cores: 8, memMb: 32768 },
    { node: "HOST\\INST1", cores: 4, memMb: 16384 },
    { node: "x');DROP TABLE t;--", cores: 4, memMb: 1 },
    { node: "NODE-B", cores: -1, memMb: 1 },
    { node: "NODE-C", cores: 2.5, memMb: 1 },
  ]));
  assert.deepEqual(rows.map((r) => r.node), ["NODE-A", "HOST\\INST1"]);
  assert.deepEqual(parseCapacityBaseline("not json"), []);
  assert.deepEqual(parseCapacityBaseline('{"node":"x"}'), [], "an object is not a list");
  const sql = capacitySymmetrySql(rows, "2026-01-15");
  assert.match(sql, /VALUES\('NODE-A',8,32768\),\('HOST\\INST1',4,16384\)\)/);
  assert.match(sql, /BaselineMeasured=CONVERT\(varchar\(10\),'2026-01-15'\)/);
});

test("disk rule: default fails any volume under 10%; a scoped list narrows FAIL and can lower one volume", () => {
  assert.deepEqual(diskFailRule(undefined), { volumes: [], pct: {} });
  assert.deepEqual(diskFailRule(" c:, D: ,f:=5, junk, Z:=150 "), { volumes: ["C:", "D:", "F:"], pct: { "F:": 5 } });
  assert.match(diskSpaceEvalPs(diskFailRule(undefined)), /PercentFree -lt 10 \}\)\.Count/);
  const scoped = diskSpaceEvalPs(diskFailRule("C:,F:=5"));
  assert.match(scoped, /^\$sql=@\('C:','F:'\); \$pct=@\{'F:'=5\};/);
  assert.match(evalOf("Disk space"), /PercentFree -lt 15/, "Attention stays on every volume");
  assert.match(diskRuleText(diskFailRule(undefined)), /under 10% free on any volume/);
  assert.match(diskRuleText(diskFailRule("C:,F:=5")), /C:, F: \(5%\)/);
});

test("core databases, structural logins and patterns are validated before they reach SQL", () => {
  assert.deepEqual(parseCoreDatabases("A,B'C,[D],E F"), ["A", "E F"]);
  assert.match(evalOf("sysadmin members"), /\$x -eq 'sa' -or \$x -eq 'distributor_admin'/);
});

test("configured values reach the catalog (fresh module instance with site env)", async () => {
  const keep = { ...process.env };
  Object.assign(process.env, {
    HEALTHCHECK_STRUCTURAL_LOGINS: "dbaowner, bad'login",
    HEALTHCHECK_FORWARDER_AG_LIKE: "%-fwd",
    HEALTHCHECK_SANCTIONED_INPROC_PATHS: "%\\Program Files\\Vendor ODBC Driver\\%,bad'pattern",
    HEALTHCHECK_PRIMARY_GUARD_PROC: "dbo.IsPrimaryGuard",
    HEALTHCHECK_DBATOOLS_VERSION: "2.8.4",
    HEALTHCHECK_DBATOOLS_LIBRARY_VERSION: "not-a-version",
    SQL_EXTRA_DUMP_DIRS: "D:\\Dumps",
    HEALTHCHECK_CORE_DATABASES: "AppDb",
  });
  try {
    const m = (await import(`../src/dbatools.js?siteconfig=1`)) as typeof import("../src/dbatools.js");
    const sql = (l: string) => String(m.CATALOG.find((c) => c[1] === l)?.[4] ?? "");
    assert.deepEqual(m.STRUCTURAL_LOGINS, ["sa", "distributor_admin", "dbaowner"], "an invalid login is dropped");
    assert.match(String(m.CATALOG.find((c) => c[1] === "sysadmin members")?.[6]), /\$x -eq 'dbaowner'/);
    assert.match(sql("Last backups"), /ag\.name LIKE '%-fwd'/);
    assert.match(sql("AG replica policy conformance"), /ag\.name LIKE '%-fwd'/);
    assert.match(sql("Linked-server providers in-process"), /ok=CASE WHEN path LIKE '%\\Program Files\\Vendor ODBC Driver\\%' THEN 1/);
    assert.doesNotMatch(sql("Linked-server providers in-process"), /bad'pattern/);
    assert.match(sql("Agent job integrity"), /g\.command LIKE N'%dbo\.IsPrimaryGuard%'/);
    assert.match(sql("Health-check tooling version drift"), /'exactly 2\.8\.4'.*'exactly 2025\.8\.17'/s, "an invalid version falls back");
    assert.match(sql("Access violations / stack dumps (24h)"), /UNION SELECT N'D:\\Dumps'\)/);
    assert.match(sql("Stack-dump storm rate (7d)"), /UNION SELECT N'D:\\Dumps'\)/);
    assert.match(sql("Per-database option hygiene"), /FROM \[AppDb\]\.sys\.database_scoped_configurations/);
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in keep)) delete process.env[k];
    Object.assign(process.env, keep);
  }
});

// The evaluators are PowerShell, so grade real rows in a real PowerShell when one is installed.
const shell = ["pwsh", "powershell"].find((s) => spawnSync(s, ["-NoProfile", "-Command", "exit 0"]).status === 0);
test("the disk and sysadmin evaluators grade synthetic rows as intended", { skip: !shell && "no PowerShell on this host" }, () => {
  const row = (n: string, p: number) => `[pscustomobject]@{Name='${n}';PercentFree=${p}}`;
  const floor = ["NT SERVICE\\SQLWriter", "NT AUTHORITY\\SYSTEM", "sa", "distributor_admin"].map((n) => `[pscustomobject]@{Name='${n}'}`);
  const cases: Array<[string, string, string]> = [
    [diskSpaceEvalPs(diskFailRule(undefined)), `@(${row("G:\\", 8)})`, "fail"],
    [diskSpaceEvalPs(diskFailRule("C:,F:=5")), `@(${row("G:\\", 8)})`, "attention"],
    [diskSpaceEvalPs(diskFailRule("C:,F:=5")), `@(${row("F:\\", 6)})`, "attention"],
    [diskSpaceEvalPs(diskFailRule("C:,F:=5")), `@(${row("F:\\", 4)})`, "fail"],
    [diskSpaceEvalPs(diskFailRule(undefined)), `@(${row("C:\\", 40)})`, "pass"],
    [evalOf("sysadmin members"), `@(${floor.join(",")})`, "pass"],
    [evalOf("sysadmin members"), `@(${[...floor, "[pscustomobject]@{Name='BUILTIN\\Administrators'}"].join(",")})`, "fail"],
  ];
  const script = cases.map(([e, d], i) => `$d = ${d}; Write-Output ('${i}=' + $(${e}))`).join("\n");
  const r = spawnSync(shell!, ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const got = Object.fromEntries(r.stdout.trim().split(/\r?\n/).map((l) => l.trim().split("=")));
  cases.forEach(([, , want], i) => assert.equal(got[String(i)], want, `case ${i}`));
});
