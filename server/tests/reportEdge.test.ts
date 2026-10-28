/**
 * Report-rendering edge cases.
 *
 * The weekly health report is read by people who act on it directly, so a rendering
 * artefact is not cosmetic: "Not using CHECKSUM page verification: ? (?)" sends a DBA
 * looking for a database called "?", and a Fail whose Details say "25 item(s) flagged"
 * when the check matched 450 understates the work by 18x. These tests drive every
 * catalog check through the shapes real data actually takes - no rows, rows whose
 * columns came back NULL, and a result larger than the display cap - and assert the
 * rendered HTML never contains a placeholder or a count that contradicts the data.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, generateHtmlReport, buildHealthCheckScript } from "../src/dbatools.js";

type Raw = Parameters<typeof toFinding>[0];

const LABELS = CATALOG.map((c) => c[1] as string);
const CATS = new Map(CATALOG.map((c) => [c[1] as string, c[0] as string]));
const CMDS = new Map(CATALOG.map((c) => [c[1] as string, c[2] as string]));

const raw = (label: string, over: Partial<Raw>): Raw => ({
  category: CATS.get(label)!, label, command: CMDS.get(label)!,
  priority: "High", status: "pass", rows: 0, shown: 0, data: [], ...over,
});

/** Placeholder artefacts that must never reach a human-readable string. */
const ARTEFACTS: Array<[RegExp, string]> = [
  [/\?\s*\(\?\)/, 'literal "? (?)" - a null column rendered as a database name'],
  [/:\s*\.\s/, 'an empty list rendered as ": ."'],
  [/\bundefined\b/, 'the JS value "undefined" leaked into prose'],
  [/\bNaN\b/, 'NaN leaked from a numeric conversion'],
  [/\[object Object\]/, "an object was string-concatenated"],
  // `%` cannot live inside the \b group: it is not a word character, so `%\b` demands a word
  // character AFTER the percent - "null %" and "null%" both walk straight past the net. And the
  // space must be optional, because every percent here is interpolated as `${v}%`, so "null%" is
  // the only shape this code could actually emit. The (?<!%) keeps a T-SQL `LIKE '%null%'` in a
  // remediation snippet from failing the test for a string that is doing its job.
  [/\bnull\s+(?:day|row|item|GB|MB|ms)\b|(?<!%)\bnull\s*%/, "a null was formatted as a quantity"],
];

function scan(where: string, text: string) {
  for (const [re, why] of ARTEFACTS) {
    const m = re.exec(text);
    assert.equal(m, null, `${where}: ${why}\n  ...${text.slice(Math.max(0, (m?.index ?? 0) - 90), (m?.index ?? 0) + 90)}...`);
  }
}

function strings(label: string, over: Partial<Raw>): string {
  const f = toFinding(raw(label, over));
  return [f.details, f.remediation?.summary ?? "", f.remediation?.code ?? ""].join("\n");
}

test("no placeholder artefacts when a check returns zero rows", () => {
  for (const label of LABELS)
    for (const status of ["pass", "attention", "fail", "ok", "empty"])
      scan(`${label} / ${status} / 0 rows`, strings(label, { status, rows: 0, shown: 0, data: [] }));
});

test("no placeholder artefacts when every column of a row is NULL", () => {
  // A cross-database scan that cannot read a database, or a DMV that returns a row of
  // NULLs, is the exact shape that produced "? (?)" in real reports.
  const nulls = [{ DBName: null, PageVerify: null, Database: null, Name: null, DbName: null,
                   TableName: null, LockEscalation: null, Scope: null, Value: null,
                   DaysSinceLastGoodCheckDb: null, LastGoodCheckDb: null, MaxPartitionRows: null }];
  for (const label of LABELS)
    for (const status of ["attention", "fail", "ok"])
      scan(`${label} / ${status} / all-NULL row`, strings(label, { status, rows: 1, shown: 1, data: nulls }));
});

test("Suspect pages: every event_type branch renders without a dangling list", () => {
  // The all-NULL row above CANNOT reach this check's resolved/unresolved branches: a row
  // with no EventType lands in the "unrecognised" bucket, so the `for: ${where}` guard that
  // produced the real "... for: ." artefact was never executed by a test. The resolved
  // branch is common in practice (a node can carry historical "Repaired (DBCC)" rows), and
  // DB_NAME() reads NULL once the database has been dropped - which is precisely the input
  // that empties the list. Get-DbaSuspectPage returns EventType as a descriptive STRING;
  // the raw msdb column is numeric, so drive both shapes.
  const EVENTS: unknown[] = [1, 2, 3, 4, 5, 7, 9, "Bad checksum", "Torn page", "Repaired (DBCC)", "Restored", "", null];
  for (const ev of EVENTS)
    for (const status of ["attention", "fail", "ok"])
      scan(`Suspect pages / ${status} / EventType=${JSON.stringify(ev)} / NULL Database`,
        strings("Suspect pages", { status, rows: 1, shown: 1,
          data: [{ Database: null, FileId: 1, PageId: 2345678, EventType: ev, ErrorCount: 1, LastUpdateDate: null }] }));
  // A resolved row alongside an unresolved one takes the "(plus N ...)" tail.
  scan("Suspect pages / fail / mixed event types / NULL Database", strings("Suspect pages", {
    status: "fail", rows: 2, shown: 2,
    data: [{ Database: null, EventType: 2 }, { Database: null, EventType: "Repaired (DBCC)" }],
  }));
});

test("Details never claims a smaller count than the check actually matched", () => {
  // rows = full matched set (graded); shown = what the Details table renders.
  const f = toFinding(raw("Identity column capacity", {
    status: "fail", rows: 450, shown: 25,
    data: Array.from({ length: 25 }, (_, i) => ({ TableName: `t${i}`, PctUsed: 99 })),
  }));
  assert.match(f.details, /450/, "Details must state the full matched count, not the displayed count");
  assert.match(f.details, /first 25 of 450/, "Details must disclose that the table below is truncated");
  assert.doesNotMatch(f.details, /^25 item/, "must not present the display cap as the finding count");
});

test("a zero-row graded check reports 0, not PowerShell's @($null).Count of 1", () => {
  // The defect lives in the GENERATED POWERSHELL, not in toFinding: @($null).Count is 1 in
  // PowerShell, so `rows=@($d).Count` reported a check that found nothing as rows=1. Feeding
  // rows:0 into toFinding cannot exercise that at all - it asserts on a value the test itself
  // supplied. Assert on the emitted script instead.
  const ps = buildHealthCheckScript({ name: "T", host: "10.0.0.1", port: 1433 } as never, true, 25);
  assert.doesNotMatch(ps, /rows=@\(\$d\)\.Count/,
    "rows= must guard the null case explicitly; @($null).Count is 1 in PowerShell");
  assert.match(ps, /rows=\$\(if \(\$null -eq \$d\) \{ 0 \}/,
    "rows= must read 0 when the check returned nothing");
  // And the rendering side must not turn an empty result into a row count either.
  const f = toFinding(raw("Suspect pages", { status: "empty", rows: 0, shown: 0, data: null }));
  assert.doesNotMatch(f.details, /\b1 row\(s\)/, "an empty result must not render as '1 row(s)'");
});

test("the full HTML report renders clean for every check at once", () => {
  const findings = LABELS.map((label, i) =>
    toFinding(raw(label, { status: ["pass", "attention", "fail", "ok", "empty"][i % 5], rows: 0, shown: 0, data: [] })));
  const html = generateHtmlReport("2026-01-05T00:00:00Z", [{
    instance: "TEST-NODE", computer: "TEST-NODE", sql_instance: "TEST-NODE",
    overall_health: 80, status_counts: { Pass: 1, Attention: 1, Fail: 1, Info: 1 },
    categories: [], findings,
  }] as Parameters<typeof generateHtmlReport>[1]);
  scan("full HTML report", html.replace(/<[^>]+>/g, " "));
});
