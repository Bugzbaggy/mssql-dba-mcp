import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDumpDirCte, extraDumpDirLiterals, DUMP_DIR_DECLARE } from "../src/dumpPaths.js";

// The dump directory is resolved from candidates, never from one hardcoded path. These pin that
// the derived candidates are always present, that no site-specific path is baked in, and that a
// configured extra directory is quoted safely into the T-SQL.

test("the default candidate set derives every path and hardcodes no site volume", () => {
  const cte = buildDumpDirCte([]);
  assert.match(cte, /SELECT @errDir,0 /, "the ERRORLOG directory is always a candidate");
  assert.match(cte, /@mssql\+N'\\Log',1/, "the running instance's own Log directory is a candidate");
  assert.match(cte, /sys\.dm_os_enumerate_filesystem\(@root,'MSSQL\*'\)/, "sibling MSSQL<nn> trees are enumerated");
  assert.doesNotMatch(cte, /,3\b/, "no extra directory is listed unless one is configured");
  assert.doesNotMatch(cte, /[A-Z]:\\MSSQL/i, "no drive-letter literal outside the install-root fallback");
  assert.match(cte, /\),d AS \(SELECT dir,MIN\(pref\) AS pref FROM cand WHERE dir IS NOT NULL GROUP BY dir\) $/);
});

test("SQL_EXTRA_DUMP_DIRS entries are trimmed, de-slashed and quoted as N'' literals", () => {
  assert.deepEqual(extraDumpDirLiterals(""), []);
  assert.deepEqual(extraDumpDirLiterals(" ; ;"), []);
  assert.deepEqual(extraDumpDirLiterals("E:\\SQLLogs\\Dumps\\; D:\\Dumps"), [
    "N'E:\\SQLLogs\\Dumps'",
    "N'D:\\Dumps'",
  ]);
  // A quote in a configured path must not be able to end the literal.
  assert.deepEqual(extraDumpDirLiterals("D:\\it's"), ["N'D:\\it''s'"]);
});

test("configured extra directories join the candidate CTE at the lowest preference", () => {
  const cte = buildDumpDirCte(extraDumpDirLiterals("E:\\SQLLogs\\Dumps;D:\\Dumps"));
  assert.match(cte, /UNION ALL SELECT N'E:\\SQLLogs\\Dumps',3 UNION ALL SELECT N'D:\\Dumps',3\),d AS/);
});

test("the DECLAREs every consumer relies on are emitted", () => {
  for (const v of ["@log", "@errDir", "@binn", "@mssql", "@instDir", "@root"]) {
    assert.match(DUMP_DIR_DECLARE, new RegExp(`DECLARE ${v} nvarchar\\(512\\)`), `${v} must be declared`);
  }
});
