/**
 * Details-line quality.
 *
 * generateHtmlReport renders exactly ONE string per finding — `details` — and no row
 * table. So a graded check without a describe() rule reaches the reader as
 * "Graded FAIL over N returned row(s). This check has no per-row summary rule..." and
 * nothing else: the substance never makes it onto the page. In practice, on a real node,
 * every Fail rendered exactly that line.
 *
 * Also guards the offender-only grading rule: a check whose query returns ONLY offending
 * rows proves it looked when it returns nothing, so zero rows must grade Pass, not Info.
 * Getting this wrong makes a check able to lower a score but never raise one.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CATALOG, toFinding, buildHealthCheckScript } from "../src/dbatools.js";

const GENERIC = /no per-row summary rule/;
const byLabel = new Map(CATALOG.map((c) => [c[1] as string, c]));

function detailsFor(label: string, data: Record<string, unknown>[], status = "fail"): string {
  const c = byLabel.get(label);
  assert.ok(c, `unknown check label: ${label}`);
  return toFinding({
    category: c[0] as string, label, command: c[2] as string, priority: c[5] as string,
    status, rows: data.length, shown: data.length, data,
  } as Parameters<typeof toFinding>[0]).details;
}

/** Rows shaped exactly as each check returns them (synthetic values). */
const SAMPLE: Record<string, Record<string, unknown>[]> = {
  "Instance configuration vs fleet standard": [
    { Setting: "Ole Automation Procedures", Actual: "1", Expected: "0", Sev: 2, Note: "…" },
    { Setting: "backup checksum default", Actual: "0", Expected: "1", Sev: 1, Note: "…" },
  ],
  "AG policy conformance (HA settings)": [
    { Scope: "AG", AgName: "ag-region1-cluster", Setting: "DB_FAILOVER", Actual: "OFF", Expected: "ON", Sev: 2, Note: "…" },
  ],
  "AG replica policy conformance": [
    { AgName: "ag-region4-forwarder", Replica: "REGION4-NODE1", Setting: "SESSION_TIMEOUT", Actual: "10", Expected: "60", Sev: 2, Note: "…" },
  ],
  "AG failover capacity symmetry": [
    { AgName: "ag-region2-cluster", Replica: "region2-node5", IsThisNode: 0, ThisCores: 16, ThisMemMB: 65536,
      PeerCores: 8, PeerMemMB: 32768, CorePct: 50, MemPct: 50, AutoFailover: "AUTOMATIC", Sev: 2, Note: "…" },
  ],
  "Stack-dump storm rate (7d)": [
    { MaxDumpsIn10Min: 60, MaxDumpsIn1Min: 30, PeakWindowStartUtc: "2026-01-12 09:18:47",
      DistinctDumps7d: 60, DistinctDumps24h: 0, LastDumpUtc: "2026-01-12 09:28:08", DumpDir: "C:\\…" },
  ],
  "Storage I/O latency (per volume)": [
    // Synthetic: both the live sample and the lifetime averages are slow.
    { Volume: "E:\\", LiveReadMs: 120.5, LiveReads: 900, LiveLogWriteMs: 0.0, LiveLogWrites: 0,
      AvgReadMs: 540.0, Reads: 650000000, AvgLogWriteMs: 0.0, LogWrites: 0,
      SlowestDataFile: "AppDb_Data/AppDb_Data_09", UptimeHrs: 400.0, SampleSec: 20.0 },
  ],
  "Linked-server providers in-process": [
    { Kind: "InProcDll", Name: "vendorhook.dll", InProc: "IN-PROCESS", Ver: null, Company: "(unsigned)",
      Sanctioned: 0, LinkedServers: 0, RpcOut: 0, UpHrs: 400, Detail: "C:\\WINDOWS\\System32\\vendorhook.dll" },
    { Kind: "Provider", Name: "MSDASQL", InProc: "IN-PROCESS", Ver: "10.0", Company: "Microsoft",
      Sanctioned: 1, LinkedServers: 4, RpcOut: 4, UpHrs: 400, Detail: "LS_WAREHOUSE_REGION1" },
  ],
  "Instance performance settings (workers / parallelism / memory)": [
    { Setting: "02 workers vs configured target", Value: "1100 / 1024 = 107.4%", Expected: "below 100%",
      Verdict: "ABOVE-TARGET", Sev: "fail", Context: "…" },
  ],
};

test("every check that grades Fail on realistic data names what failed", () => {
  for (const [label, data] of Object.entries(SAMPLE)) {
    const d = detailsFor(label, data);
    assert.doesNotMatch(d, GENERIC,
      `"${label}" falls back to the generic line, so its Details cell tells the reader nothing:\n  ${d}`);
    assert.ok(d.length > 40, `"${label}" details is too short to be useful: ${d}`);
  }
});

test("the details line quotes the actual offending values, not just a count", () => {
  assert.match(detailsFor("Instance configuration vs fleet standard", SAMPLE["Instance configuration vs fleet standard"]),
    /Ole Automation Procedures/, "must name the setting that drifted");
  assert.match(detailsFor("AG failover capacity symmetry", SAMPLE["AG failover capacity symmetry"]),
    /region2-node5/, "must name the undersized replica");
  assert.match(detailsFor("Storage I/O latency (per volume)", SAMPLE["Storage I/O latency (per volume)"]),
    /E:/, "must name the slow volume");
});

test("a 7-day dump storm distinguishes a live incident from a historic one", () => {
  // The same 7-day window covers both, and they need opposite responses.
  const historic = detailsFor("Stack-dump storm rate (7d)", SAMPLE["Stack-dump storm rate (7d)"]);
  assert.match(historic, /stopped|historic/i, "a storm with nothing in 24h must be marked as stopped");
  const live = detailsFor("Stack-dump storm rate (7d)",
    [{ ...SAMPLE["Stack-dump storm rate (7d)"][0], DistinctDumps24h: 12 }]);
  assert.match(live, /ONGOING|live incident/i, "dumps inside 24h must be marked ongoing");
  assert.notEqual(historic, live, "the two cases must not read identically");
});

test("offender-only checks grade Pass on zero rows, not Info", () => {
  // These queries return ONLY offending rows, so an empty result proves the probe looked
  // and found nothing. Routing that to Info makes the check unable to ever raise a score.
  const OFFENDER_ONLY = [
    "Suspect pages", "Page verify option", "Access violations / stack dumps (24h)",
    "Stack-dump storm rate (7d)", "AG role-change churn (24h)", "Per-database option hygiene",
    "Instance configuration vs fleet standard", "AG replica policy conformance",
    "Login resets (Error 17830) by source",
  ];
  const ps = buildHealthCheckScript({ name: "T", host: "10.0.0.1", port: 1433 } as never, true, 25);
  for (const label of OFFENDER_ONLY) {
    const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`label='${esc}';[^\\n]*?\\$\\(try \\{ if \\(\\$null -eq \\$d\\) \\{'pass'\\}`);
    assert.match(ps, re, `"${label}" is offender-only but its emitted check treats zero rows as 'empty' (Info)`);
  }
});

test("inventory checks still treat zero rows as 'empty', not an unearned all-clear", () => {
  // The mirror image: these enumerate a population, so "no rows" means the probe returned
  // nothing — which must NOT read as a pass.
  const INVENTORY = ["Last good CHECKDB", "sysadmin members", "sp_configure", "Last backups"];
  const ps = buildHealthCheckScript({ name: "T", host: "10.0.0.1", port: 1433 } as never, true, 25);
  for (const label of INVENTORY) {
    const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`label='${esc}';[^\\n]*?\\$\\(try \\{ if \\(\\$null -eq \\$d\\) \\{'empty'\\}`);
    assert.match(ps, re, `"${label}" enumerates a population; zero rows must not grade Pass`);
  }
});
