import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, windowsOnly, agOnly } from "../src/dbatools.js";
import { DUMP_DIR_DECLARE } from "../src/dumpPaths.js";

// Found by executing the catalog against SQL Server 2022 on a standalone Linux container: checks
// that could not look returned zero rows, and three of them grade zero rows as a PASS.
const sqlOf = (label: string) => String(CATALOG.find((c) => c[1] === label)?.[4] ?? "");

test("the ERRORLOG directory is derived for either path separator wherever a check enumerates it", () => {
  const sepAware = /CHARINDEX\(CASE WHEN CHARINDEX\('\\',@\w+\)>0 THEN '\\' ELSE '\/' END,REVERSE\(@\w+\)\)/;
  for (const label of ["Access violations / stack dumps (24h)", "Stack-dump storm rate (7d)", "ERRORLOG / stack-dump volume free space", "AG role-change churn (24h)", "ERRORLOG file size"]) {
    assert.match(sqlOf(label), sepAware, `${label}: a '\\'-only split leaves the file path, and the dump probe then finds nothing`);
  }
  assert.match(DUMP_DIR_DECLARE, sepAware);
});

test("ERRORLOG file size reports SKIPPED when it finds no ERRORLOG file, instead of a zero-file pass", () => {
  // On Linux the '\'-only split enumerated the log FILE as a directory: six OS errors in the
  // ERRORLOG per run, zero files, and a Pass.
  const s = sqlOf("ERRORLOG file size");
  assert.match(s, /IF NOT EXISTS \(SELECT 1 FROM sys\.dm_os_enumerate_filesystem\(@dir, 'ERRORLOG\*'\) WHERE is_directory = 0\) SELECT TOP \(1\) __hc_skip=CONVERT/);
  assert.ok(s.trimEnd().endsWith("; END"));
});

test("offender-only AG checks report SKIPPED without an availability group instead of a vacuous pass", () => {
  for (const label of ["AG replica policy conformance", "AG role-change churn (24h)"]) {
    assert.ok(sqlOf(label).startsWith("IF NOT EXISTS (SELECT 1 FROM sys.availability_groups"), label);
  }
  assert.match(agOnly("SELECT 1"), /__hc_skip=CONVERT\(varchar\(300\),'No WSFC availability group on this instance/);
});

test("Windows-only inventories report SKIPPED on SQL Server on Linux instead of grading platform DLLs", () => {
  for (const label of ["Linked-server providers in-process", "Health-check tooling version drift"]) {
    assert.ok(sqlOf(label).startsWith("IF EXISTS (SELECT 1 FROM sys.dm_os_host_info WHERE host_platform <> N'Windows')"), label);
  }
  assert.match(windowsOnly("SELECT 1", "It's"), /'It''s is Windows-only; this instance runs on '/, "the reason is quoted safely");
});

test("a cmdlet that says HADR is not configured is 'skipped', not 'could not run'", async () => {
  const { buildHealthCheckScript, NOT_APPLICABLE_PS_RE } = await import("../src/dbatools.js");
  const ps = buildHealthCheckScript({ name: "n1", host: "10.0.0.1", port: 1433 } as never, true, 25);
  assert.ok(ps.includes(`$__m -match '${NOT_APPLICABLE_PS_RE}'`));
  assert.match(ps, /status='skipped'; rows=0; shown=0; capped=\$false; data=\$null; reason=\('Not applicable on this instance: ' \+ \$__m\)/);
  // sp_BlitzIndex missing is one skipped row with the reason, not a per-database "Database Skipped" Fail.
  assert.match(ps, /-match 'Could not find stored procedure'\) \{ \[pscustomobject\]@\{ __hc_skip='sp_BlitzIndex is not installed in the DBA database/);
});
