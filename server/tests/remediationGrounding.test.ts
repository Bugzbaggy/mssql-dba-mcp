/**
 * Remediation grounding.
 *
 * A remediation block is the part of the report people copy and run. It is only safe if
 * every RUNNABLE statement in it refers to something the check actually found ON THIS NODE.
 * Two real defects motivated these tests, both found in real weekly reports:
 *
 *   1. The Query Store fix emitted a hardcoded, uncommented
 *      `ALTER DATABASE [AppDb_Data] SET QUERY_STORE = ON (...)` on every node. It was the
 *      only runnable statement in the block, so it was the one people copied - reconfiguring
 *      a healthy database while the store that had actually stopped stayed broken.
 *   2. Prose from one node leaked into another's report (one node's PDF cited another node's
 *      billion-row msg.MessageLog and told the reader to run fixes on two other nodes).
 *
 * The invariant: a runnable line may only name a database the input rows named. Commentary
 * may reference other nodes - it is explicitly labelled as context - but must never be the
 * thing that executes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding } from "../src/dbatools.js";

type Raw = Parameters<typeof toFinding>[0];
const CATS = new Map(CATALOG.map((c) => [c[1] as string, c[0] as string]));
const CMDS = new Map(CATALOG.map((c) => [c[1] as string, c[2] as string]));
const LABELS = CATALOG.map((c) => c[1] as string);

/** Database names the source or its fixtures know about - the names most likely to be hardcoded. */
const FLEET_DBS = ["AppDb_Data", "AppCatalog", "AppDb", "AppDb_Analytics", "AppDb_Routing",
  "AppDb_VOICE", "AppDb_Media", "AppDb_Archive", "AppDb_Reporting", "AppDb_Audit",
  // A node-local staging copy and a third-party monitoring database were the names actually
  // hardcoded in an earlier version of the source, and they were missing from this list, so the
  // test could not have caught the regression it exists for. Keep names of that kind here.
  "AppDb_Staging", "MonitoringDb", "AppDb_dev", "DBA"];
/** Node names that must never appear in a runnable line. */
const FLEET_NODES = ["region1-node1", "region1-node2", "region3-node1", "region3-node2", "region4-node1", "region4-node2", "region2-node1", "region2-node2"];

/** Lines that would actually execute if pasted into SSMS. */
function runnable(code: string): string[] {
  return code.split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("--") && !l.startsWith("#") && !l.startsWith("/*"));
}

function remediate(label: string, rows: unknown[], status: string = "fail"): { code: string; summary: string } | undefined {
  const raw: Raw = {
    category: CATS.get(label)!, label, command: CMDS.get(label)!, priority: "High",
    status, rows: rows.length, shown: rows.length, data: rows,
  };
  const r = toFinding(raw).remediation;
  return r ? { code: r.code ?? "", summary: r.summary } : undefined;
}

/** A row carrying every column name any check reads, all pointing at a database that is NOT
 *  in FLEET_DBS. Anything from FLEET_DBS that still shows up is hardcoded, not derived. */
const FOREIGN_ROW = {
  // Both spellings. `pick` is an exact, case-sensitive key lookup, and the checks disagree:
  // Query Store reads DBName, LOCK_ESCALATION reads DbName (its own SQL aliases it that way).
  // With only DBName present the LOCK_ESCALATION rows were silently dropped and the block
  // degraded to its diagnostic SELECT - so the invariant below never saw a single ALTER TABLE.
  Node: "TEST-NODE", DBName: "ZZ_Foreign", DbName: "ZZ_Foreign", Database: "ZZ_Foreign", Name: "ZZ_Foreign",
  DatabaseName: "ZZ_Foreign", Graded: 1, Replica: "STANDALONE", Compat: 150, DataMB: 2048,
  Desired: "OFF", Actual: "OFF", ROReason: 0, CaptureMode: "ALL", SizeCleanup: "OFF",
  StaleDays: 367, MaxPlans: 0, WaitStats: "OFF", IntervalMin: 60, CurMB: 10, MaxMB: 100,
  PctUsed: 10, StateInfo: "", Issues: "QS-OFF-ON-AG-DB,CAPTURE-ALL,CLEANUP-OFF,WAITSTATS-OFF,STALE-GT-90D,MAXPLANS-UNBOUNDED,COMPAT-GATES-FEEDBACK",
  Scope: "TABLE", TableName: "zz.Foreign", LockEscalation: "TABLE", Partitions: 40,
  MaxPartitionRows: 5_000_000, ApproxTableRows: 50_000_000, PartitionScheme: "ps_zz",
  Severity: "Fail", Access: "READ_WRITE", DaysSinceLastGoodCheckDb: 900, LastGoodCheckDb: null,
  PageVerify: "NONE", AsyncStats: 1, AsyncLowPri: "OFF", Rcsi: 1, Chaining: 1, Trustworthy: 1,
};

/** FOREIGN_ROW's `Issues` string is entirely Query-Store tokens, so in the two checks that emit
 *  the most ALTERs it reaches NO per-issue branch: `Per-database option hygiene` degraded to two
 *  lines of boilerplate and `LOCK_ESCALATION on partitioned tables` to one diagnostic SELECT. The
 *  invariant was being enforced against banner text rather than against anything that would run -
 *  which is exactly how the hardcoded-database defect this file exists for stayed reachable.
 *  One case per branch family; the two guards below keep the list honest as tokens are added. */
const HYGIENE_TOKENS = "AUTO_UPDATE_STATS_OFF,AUTO_CREATE_STATS_OFF,AUTO_CLOSE_ON,AUTO_SHRINK_ON," +
  "CHAINING_PLUS_TRUSTWORTHY,ASYNC_STATS_OFF,ASYNC_STATS_NO_LOW_PRIORITY,TRUSTWORTHY_SYSADMIN_OWNER," +
  "ASYNC_LOW_PRIORITY_UNPROBED,db_chaining(info),trustworthy(info),rcsi_on(info)";
const CASES: Array<[string, Record<string, unknown>]> = [
  ["query-store issues", FOREIGN_ROW],
  ["per-database option issues", { ...FOREIGN_ROW, Issues: HYGIENE_TOKENS }],
  ["flagged on a replica that cannot be altered",
    { ...FOREIGN_ROW, Access: "READ_ONLY", Graded: 0, Replica: "AG-SEC",
      Issues: "AUTO_SHRINK_ON,TRUSTWORTHY_SYSADMIN_OWNER" }],
  ["lock escalation left at DISABLE", { ...FOREIGN_ROW, LockEscalation: "DISABLE" }],
  ["a scan-summary row rather than a table row",
    { ...FOREIGN_ROW, Scope: "SUMMARY", DbsScanned: 12, PartitionedTables: 40, NotAutoTables: 3 }],
];

test("no runnable statement names a database the check did not return", () => {
  for (const [caseName, row] of CASES)
    for (const label of LABELS) {
      const rem = remediate(label, [row]);
      if (!rem?.code) continue;
      for (const line of runnable(rem.code)) {
        // `DBA.dbo.<proc>` is a TOOL LOCATION, not a finding. sp_BlitzIndex, sp_WhoIsActive and
        // the Ola procs are expected in the DBA database on each node, so referencing them is
        // not the defect this test exists for. The rule
        // is "do not name a DATABASE the check did not return" — keep DBA in FLEET_DBS so a bare
        // `[DBA]` still fails, and exempt only the qualified proc call.
        const stripped = line.replace(/\bDBA\.dbo\.[A-Za-z_][A-Za-z0-9_]*/g, "<toolproc>");
        for (const db of FLEET_DBS)
          assert.ok(
            !new RegExp(`\\[${db}\\]|\\b${db}\\b`).test(stripped),
            `${label} (${caseName}): a RUNNABLE line hardcodes the database "${db}", which this node's rows never mentioned.\n  ${line}`,
          );
      }
    }
});

test("no runnable statement names another node", () => {
  for (const [caseName, row] of CASES)
    for (const label of LABELS) {
      const rem = remediate(label, [row]);
      if (!rem?.code) continue;
      for (const line of runnable(rem.code))
        for (const n of FLEET_NODES)
          assert.ok(!line.toLowerCase().includes(n),
            `${label} (${caseName}): a RUNNABLE line names node "${n}".\n  ${line}`);
    }
});

test("the matrix actually reaches the branches that emit ALTER statements", () => {
  // Without this, a case can quietly stop reaching its branch - a renamed token, a new column
  // name - and the two tests above keep passing while asserting on boilerplate.
  const ALTERING = ["Per-database option hygiene", "LOCK_ESCALATION on partitioned tables",
    "Query Store configuration"];
  for (const label of ALTERING) {
    const alters = CASES.flatMap(([, row]) =>
      runnable(remediate(label, [row])?.code ?? "").filter((l) => /^ALTER\b/i.test(l)));
    assert.ok(alters.length,
      `${label}: no case in the matrix produces a single ALTER, so the grounding invariant is only ` +
      `being applied to commentary and banners. Add a row shape that reaches its per-issue branches.`);
  }
});

test("every Issues token the hygiene check emits appears in the matrix", () => {
  // The tokens are generated by the check's own SQL (`... THEN ',AUTO_SHRINK_ON' ...`). Reading
  // them back from there is what stops the matrix from silently going stale when one is added.
  const sql = String((CATALOG.find((c) => c[1] === "Per-database option hygiene") ?? [])[4] ?? "");
  const tokens = [...new Set([...sql.matchAll(/'(,[A-Za-z_][A-Za-z_0-9()]*)'/g)].map((m) => m[1].slice(1)))];
  assert.ok(tokens.length >= 8, `expected to recover the Issues tokens from the check SQL; got ${tokens.length}`);
  const covered = CASES.map(([, r]) => String(r.Issues ?? "")).join(",");
  const uncovered = tokens.filter((t) => !covered.includes(t));
  assert.deepEqual(uncovered, [],
    `these Issues tokens are emitted by the check but no test row carries them, so their ` +
    `remediation branches are never grounded:\n  ${uncovered.join("\n  ")}`);
});

test("a remediation summary never points at a report element that does not exist", () => {
  // generateHtmlReport renders ONE `details` string per finding and no row table, so
  // "the Details table below" sent readers looking for something that is not in the PDF.
  const PHANTOM = [/Details table below/i, /table below/i, /rows? (?:listed )?below/i];
  for (const label of LABELS) {
    const rem = remediate(label, [FOREIGN_ROW]);
    if (!rem) continue;
    for (const re of PHANTOM)
      for (const [where, text] of [["summary", rem.summary], ["code", rem.code]] as const)
        assert.ok(!re.test(text),
          `${label}: remediation ${where} points at "${re.source}", but the report has no row table.`);
  }
});

test("sp_configure reads DisplayName, not the SMO property name in .Name", () => {
  // THE defect this guards: Get-DbaSpConfigure returns
  //   { Name: "OleAutomationProceduresEnabled", DisplayName: "Ole Automation Procedures" }
  // and the code matched its risky-option list against .Name, which never matches. The check
  // graded Pass on every node, including one where OLE Automation was enabled. `pick` returns the
  // FIRST non-empty key, so pick(r,"Name","DisplayName") could never reach DisplayName.
  const realShape = [
    { Name: "OleAutomationProceduresEnabled", DisplayName: "Ole Automation Procedures",
      ConfigName: "OleAutomationProceduresEnabled", ConfiguredValue: 1, RunningValue: 1 },
    { Name: "XPCmdShellEnabled", DisplayName: "xp_cmdshell",
      ConfigName: "XPCmdShellEnabled", ConfiguredValue: 0, RunningValue: 0 },
  ];
  const rem = remediate("sp_configure", realShape, "attention");
  assert.ok(rem, "sp_configure must produce a remediation when a risky option is on");
  assert.match(rem.code, /Ole Automation Procedures/,
    "the enabled option must be named using its sp_configure DisplayName");
  assert.doesNotMatch(rem.code, /None of the risky options is enabled/,
    "the block must not claim nothing is enabled while RunningValue = 1");
  assert.doesNotMatch(rem.code, /OleAutomationProceduresEnabled/,
    "must not emit the SMO property name - sp_configure does not accept it");
});

test("Query Store: the generated ALTER targets the database that actually failed", () => {
  const rem = remediate("Query Store configuration", [FOREIGN_ROW]);
  assert.ok(rem, "Query Store must produce a remediation on Fail");
  const runs = runnable(rem.code);
  assert.ok(runs.some((l) => l.includes("ALTER DATABASE [ZZ_Foreign] SET QUERY_STORE = ON")),
    `expected an enable for ZZ_Foreign; got:\n${runs.join("\n")}`);
  // 2 GB of data -> the 4096 tier, not the 8192 tier copied from the largest databases.
  assert.ok(rem.code.includes("MAX_STORAGE_SIZE_MB         = 4096"),
    "store size must be derived from this database's data volume");
});

test("Query Store: a read-only secondary produces no ALTER at all", () => {
  // Graded = 0 is the AG-secondary case: desired READ_WRITE + actual READ_ONLY with
  // readonly_reason 8 is normal there, and ALTER cannot run against it anyway.
  const sec = { ...FOREIGN_ROW, Graded: 0, Replica: "AG-SEC", Desired: "READ_WRITE", Actual: "READ_ONLY", ROReason: 8 };
  const rem = remediate("Query Store configuration", [sec]);
  assert.ok(rem);
  assert.deepEqual(runnable(rem.code).filter((l) => l.startsWith("ALTER")), [],
    "must not emit an ALTER for a row on a read-only replica");
});

test("Query Store: a stalled store is resumed, not re-created", () => {
  const stalled = { ...FOREIGN_ROW, Desired: "READ_WRITE", Actual: "READ_ONLY",
    ROReason: 65536, Issues: "!QS-STALLED-READONLY", MaxMB: 1024, CurMB: 1024, PctUsed: 100 };
  const rem = remediate("Query Store configuration", [stalled]);
  assert.ok(rem);
  const runs = runnable(rem.code);
  assert.ok(runs.some((l) => /SET QUERY_STORE \(OPERATION_MODE = READ_WRITE\)/.test(l)),
    "a stalled store needs OPERATION_MODE set explicitly - raising the cap alone does not resume it");
  assert.ok(!runs.some((l) => /SET QUERY_STORE = ON/.test(l)),
    "must not re-issue a full SET QUERY_STORE = ON on a store that is merely stalled");
});

test("a truncated result set says so inside the remediation, not just the details", () => {
  const raw: Raw = {
    category: CATS.get("Query Store configuration")!, label: "Query Store configuration",
    command: "Invoke-DbaQuery", priority: "High", status: "fail",
    rows: 60, shown: 1, data: [FOREIGN_ROW],
  };
  const code = toFinding(raw).remediation?.code ?? "";
  assert.match(code, /matched 60 row\(s\); only the first 1 are shown/,
    "a script built from a truncated sample must not read as if it covers everything");
});
