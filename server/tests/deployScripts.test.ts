import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

// deploy/01-03 were run end to end in SQL Server 2022 (twice each, through sqlcmd). These pin the
// defects that run found, so they cannot come back.
const dir = new URL("../../deploy/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".sql"));
const read = (f: string) => readFileSync(new URL(f, dir), "utf8");

test("the three deploy scripts are present", () => {
  assert.deepEqual(files.sort(), ["01-svc_sqldiag-login-and-grants.sql", "02-Test-svc_sqldiag-grants.sql", "03-audit-svc_sqldiag.sql"]);
});

test("no script contains a sqlcmd scripting-variable opener, which makes sqlcmd refuse the file", () => {
  for (const f of files) assert.doesNotMatch(read(f), /\$\(/, `${f}: sqlcmd reads a dollar-paren as a variable`);
});

test("01 is re-runnable: every CREATE of a role or user is guarded", () => {
  const s = read("01-svc_sqldiag-login-and-grants.sql");
  const lines = s.split("\n");
  lines.forEach((line, i) => {
    if (!/\bCREATE (SERVER ROLE|USER)\b/.test(line) || /^\s*--/.test(line)) return;
    // Guarded on the same line, or by an IF on the line above.
    assert.ok(/^\s*IF /.test(line) || /^\s*IF /.test(lines[i - 1] ?? ""), `unguarded: ${line.trim()}`);
  });
  assert.match(s, /IF NOT EXISTS \(SELECT 1 FROM sys\.server_principals WHERE name = N'role_sqldiag' AND type = 'R'\)\n\s+CREATE SERVER ROLE role_sqldiag;/);
  // The optional DBA tables are granted only when they exist, and only the two the server reads.
  assert.match(s, /IF OBJECT_ID\(N'dbo\.HIQMonitor', N'U'\) IS NOT NULL/);
  assert.match(s, /IF OBJECT_ID\(N'dbo\.CommandLog', N'U'\) IS NOT NULL/);
  assert.doesNotMatch(s, /dbo\.HIQ\s|HIQBlocking/, "no private capture objects");
});

test("01 grants the msdb tables the health checks read directly", () => {
  const s = read("01-svc_sqldiag-login-and-grants.sql");
  for (const t of ["sysjobs", "sysjobsteps", "sysjobschedules", "sysschedules", "sysjobhistory", "sysjobactivity", "sysalerts", "sysoperators", "sysnotifications", "sysmail_profile"]) {
    assert.match(s, new RegExp(`GRANT SELECT ON OBJECT::dbo\\.${t}\\s+TO svc_sqldiag;`), `missing msdb grant: ${t}`);
  }
});

test("03 and 02 derive the ERRORLOG directory for either path separator", () => {
  assert.match(read("03-audit-svc_sqldiag.sql"), /CASE WHEN CHARINDEX\(N'\\', @log\) > 0 THEN N'\\' ELSE N'\/' END/);
  assert.match(read("02-Test-svc_sqldiag-grants.sql"), /CASE WHEN CHARINDEX\(N'\\', @s\) > 0 THEN N'\\' ELSE N'\/' END/);
});

test("02's write-boundary probe targets a column a permission check can actually reach", () => {
  const s = read("02-Test-svc_sqldiag-grants.sql");
  assert.doesNotMatch(s, /N.UPDATE DBA.dbo.CommandLog SET ID = ID/, "an identity column fails to compile (Msg 8102) before any permission check");
  assert.match(s, /UPDATE DBA\.dbo\.CommandLog SET DatabaseName = DatabaseName WHERE 1 = 0/);
});
