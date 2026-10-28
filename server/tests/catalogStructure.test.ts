/**
 * Catalog structure invariants.
 *
 * The report's per-category health % is a weighted average of the GRADED checks in that
 * category. A category carrying only one graded check is therefore not a score, it is that
 * one check wearing a percentage - and it reads as reassurance it has not earned. That is
 * exactly what happened to Recoverability: it held "Last backups" (graded) and "Recovery
 * model" (informational), so a node whose backup job was healthy scored Recoverability 100%
 * while several of its databases had no record of a clean CHECKDB and msdb.dbo.suspect_pages
 * had entries. Both of those checks now live in Recoverability.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding } from "../src/dbatools.js";

const CATEGORY = 0, LABEL = 1, COMMAND = 2, TARGET = 3, SEVERITY = 5, EVAL = 6;

const graded = CATALOG.filter((c) => typeof c[EVAL] === "string" && (c[EVAL] as string).trim().length > 0);

test("every category that produces a score has more than one graded check", () => {
  const byCat = new Map<string, string[]>();
  for (const c of graded) {
    const k = c[CATEGORY] as string;
    byCat.set(k, [...(byCat.get(k) ?? []), c[LABEL] as string]);
  }
  for (const [cat, labels] of byCat)
    assert.ok(labels.length >= 2,
      `category "${cat}" has only one graded check (${labels[0]}), so its health % is that single ` +
      `check dressed as a score. Either add a graded check or fold the category into another.`);
});

test("the checks that make Recoverability a real score are still in Recoverability", () => {
  // The >= 2 guard above has slack here: Recoverability now carries three graded checks, so
  // either CHECKDB or Suspect pages could drift back to Reliability and the guard would still
  // pass - which is exactly the regression this file's header is written about. Pin them.
  for (const label of ["Last backups", "Suspect pages", "Last good CHECKDB"]) {
    const row = graded.find((c) => c[LABEL] === label);
    assert.ok(row, `"${label}" is no longer a graded check. Recoverability's health % is only ` +
      `honest while it grades all three of backups, suspect pages and CHECKDB.`);
    assert.equal(row[CATEGORY], "Recoverability",
      `"${label}" is now graded under "${row[CATEGORY]}". A node whose backup job is green is ` +
      `still not recoverable if CHECKDB has never come back clean or suspect_pages has rows.`);
  }
});

test("check labels are unique - the label is the key for grading and remediation", () => {
  // LABEL_TARGET and the remediationFor() switch are both keyed on the label. A duplicate
  // silently makes one of the two checks unreachable for remediation.
  const seen = new Set<string>();
  for (const c of CATALOG) {
    const l = c[LABEL] as string;
    assert.ok(!seen.has(l), `duplicate check label: "${l}"`);
    seen.add(l);
  }
});

test("a check's label matches the time window its query actually uses", () => {
  // A label saying (48h) over a query using DATEADD(HOUR,-168,...) understates a dump storm
  // by a factor of 3.5. Parse the window out of the label and out of the SQL, and compare.
  const hoursFromLabel = (l: string): number | null => {
    const m = /\((\d+)\s*(h|d)\)/i.exec(l);
    if (!m) return null;
    return m[2].toLowerCase() === "d" ? Number(m[1]) * 24 : Number(m[1]);
  };
  for (const c of CATALOG) {
    if (c[TARGET] !== "dmv") continue;
    const label = c[LABEL] as string;
    const want = hoursFromLabel(label);
    if (want == null) continue;
    const sql = String(c[4] ?? "");
    const windows = [...sql.matchAll(/DATEADD\s*\(\s*(HOUR|DAY|MINUTE)\s*,\s*-(\d+)/gi)]
      .map((m) => {
        const n = Number(m[2]);
        return m[1].toUpperCase() === "DAY" ? n * 24 : m[1].toUpperCase() === "MINUTE" ? n / 60 : n;
      });
    if (!windows.length) continue;
    // Compare against the WIDEST window, not membership. "Stack-dump storm rate (7d)" carries
    // DATEADD(HOUR,-168) - what it counts over - AND DATEADD(HOUR,-24) for one context column,
    // so includes() waves through a relabel to (24h): the same mislabel, one window over.
    assert.ok(Math.max(...windows) === want,
      `"${label}" advertises a ${want}h window, but its query uses ${windows.join("h, ")}h. ` +
      `A reader sizes the problem from the label.`);
  }
});

test("every graded check can produce a remediation when it fails", () => {
  // A Fail with no fix is the report telling someone their data may be corrupt and then
  // stopping. Prior to this, "Last good CHECKDB" - one of the highest-impact Fails - had
  // no case in remediationFor() at all.
  const missing: string[] = [];
  for (const c of graded) {
    const label = c[LABEL] as string;
    const f = toFinding({
      category: c[CATEGORY] as string, label, command: c[COMMAND] as string,
      priority: c[SEVERITY] as string, status: "fail", rows: 1, shown: 1,
      data: [{ Database: "ZZ_Probe", Name: "ZZ_Probe", DbName: "ZZ_Probe", DBName: "ZZ_Probe",
               DaysSinceLastGoodCheckDb: 900, Graded: 1, Access: "READ_WRITE", Scope: "TABLE",
               TableName: "zz.Probe", LockEscalation: "TABLE", MaxPartitionRows: 900_000,
               Issues: "AUTO_SHRINK_ON", Desired: "OFF", Status: "ATTENTION: compat 140" }],
    });
    // A summary alone is not a fix. Require a code block with at least one line that is not
    // a comment or a banner - otherwise "has a remediation" is satisfied by prose.
    const code = f.remediation?.code ?? "";
    const substantive = code.split("\n").map((l) => l.trim())
      .filter((l) => l && !l.startsWith("--") && !l.startsWith("#") && !/^-+$/.test(l));
    if (!f.remediation?.summary || !substantive.length) missing.push(label);
  }
  assert.deepEqual(missing, [],
    `these graded checks report a Fail with no runnable fix attached:\n  ${missing.join("\n  ")}`);
});
