/**
 * "Database owners" — the check that graded every node against the wrong constant.
 *
 * Test-DbaDbOwner with no -TargetLogin compares every database against 'sa'. Where the standard
 * owner is a different service login (a renamed sa, say) on some nodes and 'sa' on others, the
 * evaluator's old rule (OwnerMatch -eq $false) made:
 *
 *   a node whose standard owner is the service login report all 17 databases as mismatched —
 *           15 of them owned perfectly correctly — and the fix block emit 17 ALTER AUTHORIZATION
 *           statements, 15 of which would have reassigned a correct database away from the
 *           service account.
 *   a node whose standard owner is 'sa' report the correct 2, purely by coincidence.
 *
 * The same check disagreeing with itself across nodes, and burying the two rows that matter.
 * The risk the check's own comment describes is a database owned by a NAMED PERSON (escalation
 * via db_owner, and continuity when that person leaves) or by NOBODY (orphaned SID).
 *
 * The rule now lives in two places that cannot import each other — PowerShell that runs on the
 * node and decides the badge, and TypeScript that decides what the report says it found. These
 * tests pin them to the same data, because a disagreement produces either an ATTENTION
 * badge whose text names nothing, or a PASS that hides a real row.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, isPersonalOwner } from "../src/dbatools.js";

const evalPs = (() => {
  const c = CATALOG.find((x) => x[1] === "Database owners");
  assert.ok(c, "no catalog entry labelled 'Database owners'");
  return String((c as unknown as unknown[])[6] ?? "");
})();

const mk = (pairs: [string, string][]) =>
  pairs.map(([Database, CurrentOwner]) => ({
    Database, CurrentOwner, TargetOwner: "sa", OwnerMatch: CurrentOwner === "sa",
  }));

// Synthetic: a node whose standard owner is a bare service login, with two personally owned databases.
const NODE_A = mk([
  ["DBA", "svc_sql"], ["master", "svc_sql"], ["model", "svc_sql"], ["msdb", "svc_sql"],
  ["tempdb", "svc_sql"], ["AppCatalog", "svc_sql"], ["AppDb", "svc_sql"],
  ["AppDb_Analytics", "svc_sql"], ["AppDb_Archive", "svc_sql"], ["AppDb_Audit", "svc_sql"],
  ["AppDb_Config", "svc_sql"], ["AppDb_Routing", "svc_sql"], ["AppDb_Data", "svc_sql"],
  ["AppDb_Reporting", "svc_sql"], ["AppDb_Staging", "svc_sql"],
  ["AppDb_Media", "CORP\\jane.doe"], ["AppDb_Billing", "CORP\\john.smith"],
]);
// Synthetic: a node whose standard owner is 'sa'.
const NODE_B = mk([
  ["DBA", "sa"], ["AppDb_Archive", "sa"], ["master", "sa"], ["model", "sa"], ["msdb", "sa"], ["tempdb", "sa"],
  ["AppDb", "sa"], ["AppDb_Data", "sa"], ["AppDb_Staging", "sa"],
  ["AppCatalog", "CORP\\jane.doe"], ["AppDb_Routing", "CORP\\jane.doe"],
]);

// The check is a DMV read (Invoke-DbaQuery); describe() keys it by label.
const findingFor = (rows: object[], status = "attention"): Record<string, unknown> =>
  toFinding({
    category: "Security", label: "Database owners", command: "Invoke-DbaQuery", priority: "Medium",
    status, rows: rows.length, shown: rows.length, capped: false, data: rows,
  } as never) as unknown as Record<string, unknown>;

test("the evaluator no longer grades on OwnerMatch, which encodes the wrong constant", () => {
  assert.doesNotMatch(
    evalPs, /OwnerMatch/,
    "OwnerMatch compares against TargetOwner, which is 'sa' unless -TargetLogin is passed — " +
    "and where 'sa' is not the standard owner, this flags every correctly owned database",
  );
  assert.match(evalPs, /CurrentOwner/, "it must grade on who actually owns the database");
  assert.match(evalPs, /attention/);
  assert.match(evalPs, /pass/);
});

test("the PowerShell rule and the TypeScript rule exclude the same service principals", () => {
  // Both sides must treat a domain-qualified SERVICE account as fine. If they drift, the badge
  // and the text disagree. These are the exact tokens each side excludes.
  for (const tok of ["NT (SERVICE|AUTHORITY)", "BUILTIN", "svc", "app", "sql"])
    assert.ok(evalPs.includes(tok), `the PowerShell rule must still exclude ${tok}`);

  const cases: [string, boolean][] = [
    ["CORP\\jane.doe", true],
    ["CORP\\john.smith", true],
    ["svc_sql", false],                     // bare SQL login — a service account
    ["sa", false],
    ["NT SERVICE\\MSSQLSERVER", false],
    ["NT AUTHORITY\\SYSTEM", false],
    ["BUILTIN\\Administrators", false],
    ["CORP\\svc_backup", false],
    ["CORP\\app_service", false],
    ["", false],                            // orphaned — a separate branch, not a "person"
  ];
  for (const [owner, want] of cases)
    assert.equal(isPersonalOwner(owner), want, `isPersonalOwner(${JSON.stringify(owner)})`);
});

test("a node with two personal owners names the 2 databases that matter and clears the 15 that do not", () => {
  const d = String(findingFor(NODE_A).details);
  assert.match(d, /2 of 17 database\(s\) are owned by a named person/);
  assert.match(d, /\* AppDb_Media - owned by CORP\\jane\.doe/);
  assert.match(d, /\* AppDb_Billing - owned by CORP\\john\.smith/);
  // The 15 correct ones must not be listed as findings...
  for (const db of ["AppCatalog", "AppDb_Data", "AppDb_Routing", "master", "msdb"])
    assert.doesNotMatch(d, new RegExp(`\\* ${db} - owned by`), `${db} is owned correctly and must not be flagged`);
  // ...but must be accounted for, so their absence does not read as an oversight.
  assert.match(d, /other 15 database\(s\) .* owned by svc_sql/);
  assert.doesNotMatch(d, /no per-row summary rule/, "the generic fallback means the text names nothing");
});

test("a node where every database is owned by a service account passes and says so", () => {
  const clean = mk([["master", "svc_sql"], ["msdb", "svc_sql"], ["AppDb", "svc_sql"]]);
  const d = String(findingFor(clean, "pass").details);
  assert.match(d, /All 3 database\(s\) are owned by a service account \(svc_sql\)/);
  assert.doesNotMatch(d, /owned by a named person, not/, "nothing should be flagged here");
});

test("an orphaned owner SID is reported as its own problem, not as a person", () => {
  const orphan = mk([["master", "svc_sql"], ["msdb", "svc_sql"], ["OrphanDb", ""]]);
  const d = String(findingFor(orphan).details);
  assert.match(d, /owner SID that maps to no login/);
  assert.match(d, /\* OrphanDb/);
  assert.doesNotMatch(d, /owned by a named person/, "an orphan is not a named person");
  assert.doesNotMatch(d, /when that person leaves/, "the 'why' must match the problem actually found");
});

test("read-only copies (AG secondary, DAG forwarder) are reported but never graded or ALTERed", () => {
  // On a DAG forwarder, the forwarded databases are Updateability READ_ONLY with local AG role
  // PRIMARY, and can be owned by a person. sys.databases.is_read_only is 0 for them, so only
  // DATABASEPROPERTYEX can tell. ALTER AUTHORIZATION cannot run against a read-only database,
  // and the Test-DbaDbOwner version emitted it anyway.
  assert.match(evalPs, /Fixable/, "the PowerShell rule must grade only writable rows, like the text does");
  const NODE_B_LIVE = [
    { Database: "DBA", CurrentOwner: "sa", Updateability: "READ_WRITE", AgRole: "", Fixable: 1 },
    { Database: "AppDb", CurrentOwner: "sa", Updateability: "READ_WRITE", AgRole: "PRIMARY", Fixable: 1 },
    { Database: "AppCatalog", CurrentOwner: "CORP\\jane.doe", Updateability: "READ_ONLY", AgRole: "PRIMARY", Fixable: 0 },
    { Database: "AppDb_Routing", CurrentOwner: "CORP\\jane.doe", Updateability: "READ_ONLY", AgRole: "PRIMARY", Fixable: 0 },
  ];
  const d = String(findingFor(NODE_B_LIVE, "pass").details);
  assert.match(d, /All 2 writable database\(s\) are owned by a service account \(sa\)/);
  assert.match(d, /Not graded: 2 read-only copies/);
  assert.match(d, /AppCatalog - CORP\\jane\.doe, READ_ONLY PRIMARY/);
  assert.doesNotMatch(d, /owned by a named person, not/, "a read-only copy is not a graded finding");

  // A writable local database owned by a person next to a read-only secondary copy.
  // Only the writable one gets a statement.
  const NODE_C_LIVE = [
    { Database: "master", CurrentOwner: "svc_sql", Updateability: "READ_WRITE", AgRole: "", Fixable: 1 },
    { Database: "AppDb_Archive", CurrentOwner: "CORP\\jane.doe", Updateability: "READ_WRITE", AgRole: "", Fixable: 1 },
    { Database: "AppDb_Routing", CurrentOwner: "CORP\\john.smith", Updateability: "READ_ONLY", AgRole: "SECONDARY", Fixable: 0 },
  ];
  const f = findingFor(NODE_C_LIVE);
  assert.match(String(f.details), /1 of 2 writable database\(s\) are owned by a named person/);
  const code = String((f.remediation as { code?: string } | undefined)?.code ?? "");
  const alters = code.split("\n").filter((l) => l.includes("ALTER AUTHORIZATION ON DATABASE"));
  assert.equal(alters.length, 1, `only AppDb_Archive is writable and flagged:\n${alters.join("\n")}`);
  assert.ok(alters[0].includes("::[AppDb_Archive]"));
  assert.match(code, /NOT FIXABLE HERE/);
  assert.match(code, /AppDb_Routing: owner CORP\\john\.smith, READ_ONLY \/ AG role SECONDARY/);
});

test("the fix block targets only the flagged databases, at this node's own service account", () => {
  for (const [rows, house, want] of [
    [NODE_A, "svc_sql", ["AppDb_Media", "AppDb_Billing"]],
    [NODE_B, "sa", ["AppCatalog", "AppDb_Routing"]],
  ] as [ReturnType<typeof mk>, string, string[]][]) {
    const f = findingFor(rows);
    const code = String((f.remediation as { code?: string } | undefined)?.code ?? "");
    const alters = code.split("\n").filter((l) => l.includes("ALTER AUTHORIZATION ON DATABASE"));

    assert.equal(alters.length, want.length,
      `expected one statement per flagged database, got:\n${alters.join("\n")}`);
    for (const db of want)
      assert.ok(alters.some((a) => a.includes(`::[${db}]`)), `${db} must have a statement`);
    for (const r of rows)
      if (!isPersonalOwner(r.CurrentOwner) && r.CurrentOwner)
        assert.ok(!alters.some((a) => a.includes(`::[${r.Database}]`)),
          `${r.Database} is owned correctly and must not be reassigned`);
    // The suggested owner is the one the rest of THIS node uses — 'sa' on one node, 'svc_sql' on the other.
    for (const a of alters)
      assert.ok(a.includes(`TO [${house}]`), `target should be this node's service account: ${a.trim()}`);
    // Left commented on purpose: picking the new owner is a judgement call (a sysadmin target
    // closes no escalation path), so this must never be a paste-and-run block.
    for (const a of alters)
      assert.ok(a.trim().startsWith("--"), `statement must stay commented: ${a.trim()}`);
  }
});
