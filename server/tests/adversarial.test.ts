import { test } from "node:test";
import assert from "node:assert/strict";
import { validateQuery, validateWriteQuery } from "../src/safety.js";

/*
 * ADVERSARIAL suite. The other test files assert that the fixes do what they were written
 * to do. This one tries to BREAK them: every case here is an attempt to reach a
 * state-changing or privilege-changing statement through a guard that is supposed to allow
 * only reads. A failure here is a live hole, not a style question — the login behind this
 * guard is often sysadmin (see dbatools.ts).
 *
 * Mechanics being attacked, all in safety.ts:
 *   - ALLOWED_START permits DECLARE, which opens a multi-statement batch;
 *   - T-SQL needs no ';' between statements, so the ';'-anchored guard never fires;
 *   - stripNoise() collapses string literals BEFORE the blocklist runs.
 */

const mustBlock: Array<[string, string]> = [
  // ── Statement smuggling after DECLARE, no semicolon ──────────────────────────
  ["EXEC with parens",            "DECLARE @x INT EXEC('SELECT 1')"],
  ["EXEC proc, no parens",        "DECLARE @x INT EXEC sys.sp_readerrorlog 0,1"],
  ["EXECUTE spelled out",         "DECLARE @x INT EXECUTE sp_who"],
  ["mixed case",                  "DECLARE @x INT ExEcUtE sp_who"],
  ["newline instead of space",    "DECLARE @x INT\nEXEC('SELECT 1')"],
  ["tab separated",               "DECLARE @x INT\tEXEC('SELECT 1')"],
  ["comment between",             "DECLARE @x INT /* hi */ EXEC('SELECT 1')"],
  ["assemble then execute",       "DECLARE @s NVARCHAR(MAX) SET @s=N'DROP TABLE x' EXEC(@s)"],

  // ── DDL / DCL smuggled after DECLARE ─────────────────────────────────────────
  ["forced failover",             "DECLARE @x INT ALTER AVAILABILITY GROUP [ag] FORCE_FAILOVER_ALLOW_DATA_LOSS"],
  ["set single user",             "DECLARE @x INT ALTER DATABASE AppCatalog SET SINGLE_USER WITH ROLLBACK IMMEDIATE"],
  ["grant sysadmin",              "DECLARE @x INT ALTER SERVER ROLE sysadmin ADD MEMBER svc_sqldiag"],
  ["grant a permission",          "DECLARE @x INT GRANT CONTROL SERVER TO svc_sqldiag"],
  ["drop a table",                "DECLARE @x INT DROP TABLE dbo.Foo"],
  ["insert",                      "DECLARE @x INT INSERT INTO dbo.Foo VALUES (1)"],
  ["update",                      "DECLARE @x INT UPDATE dbo.Foo SET a = 1"],

  // ── Ownership / privilege changes NOT in the CREATE|ALTER|DROP object list ───
  ["alter authorization (db)",    "DECLARE @x INT ALTER AUTHORIZATION ON DATABASE::DBA TO svc_sqldiag"],
  ["alter authorization (obj)",   "DECLARE @x INT ALTER AUTHORIZATION ON OBJECT::dbo.Foo TO svc_sqldiag"],

  // ── Turning the detective control OFF (03-audit-svc_sqldiag.sql) ────────────
  ["stop the XE session",         "DECLARE @x INT ALTER EVENT SESSION [Audit_AutoDiag] ON SERVER STATE = STOP"],
  ["disable the server audit",    "DECLARE @x INT ALTER SERVER AUDIT [Audit_SvcSqlDiag] WITH (STATE = OFF)"],
  ["disable the audit spec",      "DECLARE @x INT ALTER SERVER AUDIT SPECIFICATION [AuditSpec_SvcSqlDiag] WITH (STATE = OFF)"],

  // ── Resource Governor / server state ────────────────────────────────────────
  ["disable resource governor",   "DECLARE @x INT ALTER RESOURCE GOVERNOR DISABLE"],
  ["reset RG stats",              "DECLARE @x INT ALTER RESOURCE GOVERNOR RESET STATISTICS"],

  // ── CTE-fronted DML: starts with WITH, so ALLOWED_START passes ──────────────
  ["CTE then UPDATE",             "WITH x AS (SELECT * FROM dbo.Foo) UPDATE x SET a = 1"],
  ["CTE then DELETE",             "WITH x AS (SELECT * FROM dbo.Foo) DELETE FROM x"],
  ["CTE then INSERT",             "WITH x AS (SELECT 1 n) INSERT INTO dbo.Foo SELECT n FROM x"],

  // ── Passthrough / filesystem reach ─────────────────────────────────────────
  ["openquery passthrough",       "SELECT * FROM OPENQUERY(REMOTE1, 'DROP TABLE x')"],
  ["openrowset bulk",             "SELECT * FROM OPENROWSET(BULK N'C:\\x.txt', SINGLE_CLOB) AS a"],
  ["xp_ family",                  "DECLARE @x INT EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE',''"],

  // ── Length / shape abuse ───────────────────────────────────────────────────
  ["padded start",                "   \n\t  DECLARE @x INT EXEC('SELECT 1')"],

  // ── Round 2: DML/state verbs whose pattern demands a specific following token ─
  // INSERT ... INTO is optional in T-SQL, so an INTO-anchored pattern misses the legal form.
  ["INSERT without INTO",         "DECLARE @x INT INSERT dbo.Foo VALUES (1)"],
  ["INSERT without INTO, cols",   "DECLARE @x INT INSERT dbo.Foo (a) VALUES (1)"],
  // KILL with a variable rather than a literal spid.
  ["KILL a variable spid",        "DECLARE @s INT = 55 KILL @s"],
  ["KILL with session name",      "DECLARE @x INT KILL '6B5C1B2A-0000-0000-0000-000000000000'"],
  // Other state changers with no object keyword after the verb.
  ["CHECKPOINT",                  "DECLARE @x INT CHECKPOINT"],
  ["RAISERROR WITH LOG",          "DECLARE @x INT RAISERROR('down', 20, 1) WITH LOG"],
  ["DENY spelled alone",          "DECLARE @x INT DENY VIEW ANY DEFINITION TO svc_sqldiag"],
  // Service Broker can move data off-box without any DML verb.
  ["service broker send",         "DECLARE @h UNIQUEIDENTIFIER SEND ON CONVERSATION @h MESSAGE TYPE [x] ('data')"],
  ["service broker dialog",       "DECLARE @h UNIQUEIDENTIFIER BEGIN DIALOG @h FROM SERVICE [a] TO SERVICE 'b'"],
  // Session-scoped but changes what later statements mean / bypasses row filters.
  ["SET CONTEXT_INFO",            "DECLARE @x INT SET CONTEXT_INFO 0x0102030405"],
  // Snapshot/isolation abuse that pins the version store on a struggling instance.
  ["BEGIN TRAN then hold",        "DECLARE @x INT BEGIN TRANSACTION"],
];

for (const [label, query] of mustBlock) {
  test(`BLOCKED: ${label}`, () => {
    const r = validateQuery(query);
    assert.equal(r.valid, false, `HOLE — validateQuery ACCEPTED: ${query}`);
  });
}

/*
 * The guard has to remain usable, or people stop using execute_query and the guard becomes
 * decorative. These are shapes a DBA genuinely types during an incident.
 */
const mustAllow: Array<[string, string]> = [
  ["plain DMV read",       "SELECT TOP 10 * FROM sys.dm_exec_sessions"],
  ["CTE read",             "WITH x AS (SELECT 1 AS n) SELECT n FROM x"],
  ["DECLARE then SELECT",  "DECLARE @since DATETIME = DATEADD(hour,-1,GETDATE()) SELECT * FROM sys.dm_exec_requests WHERE start_time > @since"],
  ["multiple DECLAREs",    "DECLARE @a INT = 1 DECLARE @b INT = 2 SELECT @a + @b"],
  ["temp table is fine",   "SELECT TOP 5 name INTO #t FROM sys.objects SELECT * FROM #t"],
  ["keyword as column",    "SELECT updated_at, created_date, deleted_flag FROM sys.objects"],
  ["keyword in a literal", "SELECT * FROM sys.objects WHERE name = 'DROP TABLE customers'"],
  ["AG health read",       "SELECT database_id, synchronization_state_desc, last_hardened_lsn FROM sys.dm_hadr_database_replica_states"],
  ["join across catalogs", "SELECT d.name, s.state_desc FROM sys.databases d JOIN sys.databases s ON s.database_id = d.database_id"],
];

for (const [label, query] of mustAllow) {
  test(`ALLOWED: ${label}`, () => {
    const r = validateQuery(query);
    assert.equal(r.valid, true, `FALSE POSITIVE — rejected a legitimate read (${r.reason}): ${query}`);
  });
}

/*
 * The eng-write profile is dry-run by default and bounded by the caller's own SQL grants, so
 * it is a smaller prize than the read guard — but it had the SAME defect: an enumerated DDL
 * object list. These are the escalations that list missed.
 */
const writeMustBlock: Array<[string, string]> = [
  ["alter authorization",  "ALTER AUTHORIZATION ON DATABASE::DBA TO svc_sqldiag"],
  ["stop an XE session",   "ALTER EVENT SESSION [Audit_AutoDiag] ON SERVER STATE = STOP"],
  ["disable the audit",    "ALTER SERVER AUDIT [Audit_SvcSqlDiag] WITH (STATE = OFF)"],
  ["disable RG",           "ALTER RESOURCE GOVERNOR DISABLE"],
  ["add to sysadmin",      "ALTER SERVER ROLE sysadmin ADD MEMBER svc_sqldiag"],
  ["create a login",       "CREATE LOGIN backdoor WITH PASSWORD = 'x'"],
  ["drop a table",         "DROP TABLE dbo.Foo"],
  ["dynamic SQL",          "EXEC('DROP TABLE x')"],
  ["sp_executesql",        "EXEC sp_executesql N'DROP TABLE x'"],
];

for (const [label, query] of writeMustBlock) {
  test(`WRITE guard blocks: ${label}`, () => {
    const r = validateWriteQuery(query);
    assert.equal(r.valid, false, `HOLE — validateWriteQuery ACCEPTED: ${query}`);
  });
}

const writeMustAllow: Array<[string, string]> = [
  ["targeted UPDATE",   "UPDATE dbo.Foo SET status = 'done' WHERE id = 7"],
  ["targeted DELETE",   "DELETE FROM dbo.Foo WHERE id = 7"],
  ["INSERT",            "INSERT INTO dbo.Foo (a) VALUES (1)"],
  // A procedure whose name merely contains a blocked verb must still be callable.
  ["EXEC CreateOrder",  "EXEC dbo.CreateOrder @id = 7"],
  ["EXEC Drop_Stale",   "EXEC dbo.Drop_StaleRows @days = 30"],
];

for (const [label, query] of writeMustAllow) {
  test(`WRITE guard allows: ${label}`, () => {
    const r = validateWriteQuery(query);
    assert.equal(r.valid, true, `FALSE POSITIVE — rejected a legitimate write (${r.reason}): ${query}`);
  });
}
