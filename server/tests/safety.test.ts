import { test } from "node:test";
import assert from "node:assert/strict";
import { validateQuery, validateWriteQuery } from "../src/safety.js";

// The per-user identity design (DEPLOYMENT.md §2) stakes the read-only guarantee on THIS layer: "the read-only guarantee holds
// regardless of how privileged the login is". A DBA tool's login is often sysadmin
// (see dbatools.ts), and then these patterns are the only thing in front of the estate. Every case
// below was ACCEPTED before the EXEC token was blocked — the smuggling works because
// ALLOWED_START permits DECLARE (opening a batch), T-SQL needs no ';' between statements, and
// stripNoise() collapses string literals before any pattern runs, hiding the payload.

const mustBlock = [
  ["dynamic EXEC() after DECLARE", "DECLARE @x INT EXEC('SELECT 1')"],
  ["forced failover smuggled in a literal",
    "DECLARE @x INT EXEC('ALTER AVAILABILITY GROUP [ag-region3-cluster] FORCE_FAILOVER_ALLOW_DATA_LOSS')"],
  ["system proc without parentheses", "DECLARE @x INT EXEC sys.sp_readerrorlog 0, 1, N'Stack Dump'"],
  ["assemble then execute", "DECLARE @s NVARCHAR(MAX) SET @s=N'DROP TABLE x' EXEC(@s)"],
  ["agent job start", "DECLARE @x INT EXEC msdb.dbo.sp_start_job N'SomeJob'"],
  ["EXECUTE spelled out", "DECLARE @x INT EXECUTE sp_who"],
  ["semicolon form (was already blocked)", "SELECT 1; EXEC sp_who"],
  ["plain DDL", "DROP TABLE x"],
  ["xp_cmdshell", "DECLARE @x INT EXEC xp_cmdshell 'dir'"],
  ["linked-server passthrough", "SELECT * FROM OPENQUERY(REMOTE1, 'DROP TABLE x')"],
  // The server caps every read with SET ROWCOUNT; a batch must not be able to switch it off.
  ["row cap switched off mid-batch", "SELECT 1; SET ROWCOUNT 0; SELECT name FROM sys.objects"],
  ["row cap switched off with no semicolon", "SELECT 1 SET ROWCOUNT 0 SELECT name FROM sys.objects"],
  // An apostrophe inside a comment or a delimited identifier opened a phantom string in stripNoise()
  // that ran to the next quote, hiding the statement in between from every pattern. All four of
  // these were ACCEPTED; T-SQL reads the apostrophe as part of the comment or name and runs the DROP.
  ["an apostrophe in a line comment", "SELECT 1 -- don't\n; DROP TABLE dbo.x --'"],
  ["an apostrophe in a block comment", "SELECT 1 /* it's */; DROP TABLE dbo.x --'"],
  ["an apostrophe in a bracketed identifier", "SELECT 1 AS [it's]; DROP TABLE dbo.x; SELECT 'z'"],
  ["an apostrophe in a quoted identifier", "SELECT 1 AS \"it's\"; DROP TABLE dbo.x; SELECT 'z'"],
  ["a carriage return outside CRLF is refused", "SELECT 1 --x\rDROP TABLE dbo.x"],
  ["a carriage return outside CRLF is refused even in a harmless read", "SELECT name\rFROM sys.objects"],
  ["an unbounded scan of a bracketed sensitive table", "SELECT * FROM [msg].[MessageLog]"],
];

for (const [label, query] of mustBlock) {
  test(`read guard blocks: ${label}`, () => {
    const r = validateQuery(query);
    assert.equal(r.valid, false, `ACCEPTED a non-read query: ${query}`);
    assert.ok(r.reason, "a rejection must explain itself");
  });
}

// The guard has to stay usable for real diagnostic work, or people route around it.
const mustAllow = [
  ["plain select", "SELECT TOP 10 * FROM sys.dm_exec_sessions"],
  ["CTE", "WITH x AS (SELECT 1 AS n) SELECT n FROM x"],
  ["DECLARE then SELECT — the common diagnostic shape",
    "DECLARE @since DATETIME = DATEADD(hour,-1,GETDATE()) SELECT * FROM sys.dm_exec_requests WHERE start_time > @since"],
  ["a column whose name merely contains a keyword", "SELECT updated_at, created_date FROM sys.objects"],
  ["a keyword inside a string literal is not a match",
    "SELECT * FROM sys.objects WHERE name = 'DROP TABLE customers'"],
  ["SET ROWCOUNT inside a string literal is not a match", "SELECT * FROM sys.objects WHERE name = 'SET ROWCOUNT 0'"],
  ["an apostrophe inside a bracketed identifier", "SELECT [it's] FROM sys.objects"],
  ["an escaped quote inside a string", "SELECT 'don''t' AS x"],
  ["an apostrophe in a trailing comment", "SELECT 1 -- don't"],
  ["nested block comments, as T-SQL nests them", "/* a /* b */ c */ SELECT 1"],
  ["a bounded read of a bracketed sensitive table", "SELECT TOP (1) * FROM [msg].[MessageLog] WHERE 1 = 0"],
  ["CRLF line endings", "SELECT name\r\nFROM sys.objects"],
];

for (const [label, query] of mustAllow) {
  test(`read guard allows: ${label}`, () => {
    const r = validateQuery(query);
    assert.equal(r.valid, true, `REJECTED a legitimate read (${r.reason}): ${query}`);
  });
}

// The write guard is a different contract — EXEC of an application procedure is allowed there
// on purpose — but dynamic SQL must still be refused, or it becomes a general DDL primitive.
test("write guard still permits a plain DML write", () => {
  assert.equal(validateWriteQuery("UPDATE dbo.Foo SET x = 1 WHERE id = 7").valid, true);
});

test("write guard still refuses dynamic SQL", () => {
  assert.equal(validateWriteQuery("EXEC('DROP TABLE x')").valid, false);
  assert.equal(validateWriteQuery("EXEC sp_executesql N'DROP TABLE x'").valid, false);
});

// The write guard shares stripNoise(), so the phantom-string bypass reached its DDL ban too.
test("write guard refuses a carriage return outside CRLF, and accepts CRLF", () => {
  assert.equal(validateWriteQuery("UPDATE dbo.Foo SET x = 1\rWHERE id = 7").valid, false);
  assert.equal(validateWriteQuery("UPDATE dbo.Foo SET x = 1\r\nWHERE id = 7").valid, true);
});

test("write guard refuses DDL hidden behind an apostrophe in a comment", () => {
  assert.equal(validateWriteQuery("UPDATE dbo.t SET c = 1 WHERE id = 1 -- don't\n; DROP TABLE dbo.x --'").valid, false);
});
