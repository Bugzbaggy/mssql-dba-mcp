/**
 * Guards on what the graded evaluators actually DISCRIMINATE.
 *
 * A check can run cleanly, return rows, never throw, and still be useless — because its
 * verdict is the same no matter what it sees. Two in this catalog were exactly that, and
 * neither showed up in any existing test:
 *
 *   - "Databases & state" is the High-priority Availability check, and it graded ONLY
 *     AutoShrink/AutoClose. A database sitting SUSPECT, RECOVERY_PENDING, EMERGENCY or
 *     OFFLINE came back in $d and graded 'pass'. Measured against live rows: Get-DbaDatabase
 *     carries both Status and State, and State is SMO's object-lifecycle enum reading
 *     'Existing' for every row — so an evaluator keyed on State could never fire either.
 *
 *   - "sysadmin members" graded a raw head count against >5, but the NON-REMOVABLE floor can
 *     be 5-6 on every node (four NT SERVICE principals, sa or a renamed sa, plus
 *     distributor_admin where replication runs). So every node graded Attention, none could
 *     ever reach 'pass', and the check could not register the least-privilege cleanup its own
 *     remediation prescribes.
 *
 * These assert on the catalog source, because the evaluator is PowerShell text that the
 * TypeScript side never executes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CATALOG, toFinding, scoreFindings, coverageOf, generateHtmlReport } from "../src/dbatools.js";

const evalOf = (label: string) => {
  const c = CATALOG.find((x) => x[1] === label);
  assert.ok(c, `no catalog entry labelled ${label}`);
  return String(c[6] ?? "");
};

test("Databases & state grades on database STATE, not just options", () => {
  const e = evalOf("Databases & state");
  assert.match(e, /Status/, "the evaluator must read Status");
  assert.doesNotMatch(e, /\$_\.State\b/, "State is SMO's object-lifecycle enum ('Existing' for every row) — useless here");
  for (const s of ["Offline", "Suspect", "Recover", "Emergency", "Inaccessible"])
    assert.ok(e.includes(s), `a non-online state must be graded: ${s} is missing`);
  assert.match(e, /'fail'/, "a database that is not online is a Fail, not an Attention");
});

test("a non-online database is described and reaches the act-now tier", () => {
  const f: any = toFinding({
    category: "Availability", label: "Databases & state", command: "Get-DbaDatabase",
    priority: "High", status: "fail", rows: 2, shown: 2, capped: false,
    data: [
      { Name: "AppCatalog", Status: "Normal", AutoShrink: false, AutoClose: false },
      { Name: "AppDb_Data", Status: "Suspect", AutoShrink: false, AutoClose: false },
    ],
  } as any);
  assert.match(f.details, /AppDb_Data/, "the details line must name the database that is not online");
  assert.match(f.details, /Suspect/i);
  assert.ok(f.remediation, "a Fail with no remediation is a dead end");
  assert.match(f.remediation.code, /suspect_pages/, "the fix must reach for the corruption evidence");
  assert.match(f.remediation.code, /last_hardened_lsn/, "on an AG primary this is a failover question first");

  // It must be in the act-now list — this is the "losing data / cannot recover" tier.
  const src = readFileSync(new URL("../src/dbatools.ts", import.meta.url), "utf8");
  const block = /const ACT_NOW_LABELS = new Set<string>\(\[([\s\S]*?)\]\);/.exec(src);
  assert.ok(block);
  assert.ok(block[1].includes('"Databases & state"'), "a SUSPECT database must be act-now");
});

test("sysadmin members grades discretionary membership, not a raw head count", () => {
  const e = evalOf("sysadmin members");
  // The old evaluator was exactly `if (@($d).Count -gt 5) {'attention'} else {'pass'}`.
  assert.doesNotMatch(e, /^\s*if \(@\(\$d\)\.Count -gt \d+\)/, "grading the raw count can never reach 'pass' where the non-removable floor already exceeds it");
  assert.match(e, /NT SERVICE/, "the non-removable service principals must be excluded from the count");
  assert.match(e, /\$x -eq 'sa'/, "sa is not removable (a renamed sa is listed in HEALTHCHECK_STRUCTURAL_LOGINS)");
  assert.match(e, /distributor_admin/, "required by the Publisher/Distributor on the replication nodes");
  assert.match(e, /BUILTIN/, "BUILTIN\\Administrators is a distinct and worse problem");
  assert.match(e, /'fail'/, "the check needs a failure tier it can actually reach");
});

test("BUILTIN\\Administrators is called out by name, not folded into a count", () => {
  const mk = (names: string[]) => toFinding({
    category: "Security", label: "sysadmin members", command: "Get-DbaServerRoleMember",
    priority: "High", status: "fail", rows: names.length, shown: names.length, capped: false,
    data: names.map((n) => ({ Name: n })),
  } as any) as any;

  const structural = ["NT SERVICE\\SQLWriter", "NT SERVICE\\Winmgmt", "NT Service\\MSSQLSERVER", "NT SERVICE\\SQLSERVERAGENT", "sa"];
  const withBuiltin = mk([...structural, "BUILTIN\\Administrators", "admin_jdoe"]);
  assert.match(withBuiltin.details, /BUILTIN\\Administrators/, "name it — it is the reason this failed");
  assert.match(withBuiltin.details, /local Windows administrator/i, "say why it matters");
  assert.match(withBuiltin.remediation.code, /DROP MEMBER \[BUILTIN\\Administrators\]/);

  // The service principals must not crowd the humans out of the details line.
  const noBuiltin = mk([...structural, "CORP\\SQL Admins", "admin_jdoe", "admin_jsmith"]);
  assert.doesNotMatch(noBuiltin.details, /NT SERVICE/, "structural principals belong in the floor, not the summary");
  assert.match(noBuiltin.details, /admin_jdoe/, "the discretionary members are the point");
});

test("Max server memory notices a cap that leaves the OS nothing", () => {
  const e = evalOf("Max server memory");
  assert.match(e, /-ge \$r\.Total/, "a cap set to EXACTLY physical RAM must trip it (-gt let it pass)");
  assert.match(e, /\$r\.Total \* 0\.10/, "the OS-headroom floor is proportional to physical RAM");
  // The floor must have NO absolute term. An earlier max(4096, 10%) was calibrated on large
  // production nodes, but region:'all' sweeps every SQL instance: on a small dev box it failed an
  // instance with MORE free memory than passing production primaries, and on a 2 GB instance the
  // 4096 MB floor exceeded the machine's entire RAM, so no setting could ever pass.
  // That is the same permanently-Attention defect this suite pins for 'sysadmin members'.
  assert.doesNotMatch(e, /Math\]::Max\(\s*\d{3,}/, "an absolute MB floor is unsatisfiable on small instances");
});

test("the memory floor is satisfiable on every instance, including a 2 GB instance", () => {
  // Guard the property, not the constant: for each representative instance size, there must
  // exist a max-server-memory setting that passes. On a 2 GB instance the old absolute floor
  // made that impossible, and an unreachable 'pass' is a check that can only ever cry wolf.
  const e = evalOf("Max server memory");
  const m = /\$r\.Total \* (0\.\d+)/.exec(e);
  assert.ok(m, "expected a proportional floor");
  const frac = Number(m[1]);
  assert.ok(frac > 0 && frac < 1, `floor fraction ${frac} must be a proper fraction`);
  for (const total of [2048, 4096, 8192, 16384, 32768, 131072]) {
    const floor = Math.trunc(total * frac);
    // The smallest legal max server memory is 128 MB, so the best achievable headroom is
    // total - 128. If that cannot clear the floor, the check is unsatisfiable on that box.
    assert.ok(total - 128 >= floor, `unsatisfiable on a ${total} MB instance: floor ${floor} > best achievable headroom ${total - 128}`);
  }
});

test("VLF count includes the system and distribution logs", () => {
  const c = CATALOG.find((x) => x[1] === "VLF count");
  assert.ok(c);
  // Measure-DbaDbVirtualLogFile defaults to IsSystemObject -eq $false, which drops msdb and
  // the distribution database — often the busiest log on a replication Distributor.
  assert.match(String(c[4]), /-IncludeSystemDBs/);
});

test("Identity column capacity proposes DBCC only for the columns near the limit", () => {
  // This check returns one row per identity column on the instance (hundreds on a busy node), so an
  // unfiltered slice(0,12) emitted twelve arbitrary healthy columns instead of the offenders.
  const data = [
    ...Array.from({ length: 30 }, (_, i) => ({ Database: "AppDb_Data", Table: `dbo.cold${i}`, Column: `id${i}`, PercentUsed: 1 })),
    { Database: "AppDb_Data", Table: "msg.MessageLog", Column: "MessageLogId", PercentUsed: 97 },
    { Database: "AppDb_Routing", Table: "route.Endpoint", Column: "EndpointId", PercentUsed: 84 },
  ];
  const f: any = toFinding({
    category: "Reliability", label: "Identity column capacity", command: "Test-DbaIdentityUsage",
    priority: "High", status: "fail", rows: data.length, shown: data.length, capped: false, data,
  } as any);
  const code: string = f.remediation.code;
  const checkident = code.split("\n").filter((l) => l.startsWith("DBCC CHECKIDENT"));
  assert.ok(checkident.length > 0, "a Fail must propose something to run");
  assert.ok(checkident.every((l) => /MessageLog|Endpoint/.test(l)),
    `every proposed DBCC must target a column near the limit, got:\n${checkident.join("\n")}`);
  assert.ok(/MessageLogId/.test(checkident[0]), "worst first — 97% before 84%");
});

test("Build currency reads the engine's own build and CU against the fleet target, not a dbatools index", () => {
  // This used to run Test-DbaBuild, which compares against an index shipped INSIDE the dbatools
  // module. A node with no internet cannot refresh it, so the index goes stale - every node is then
  // either "Compliant" against a stale list or "Approximate" (Attention everywhere for a reason that
  // says nothing about the node), and the CU it prints is the nearest KNOWN build's, not the
  // node's. SERVERPROPERTY knows the node's build, CU and KB exactly.
  const c = CATALOG.find((x) => x[1] === "Build currency");
  assert.ok(c);
  assert.equal(c[2], "Invoke-DbaQuery", "no dbatools build index in the loop any more");
  const sql = String(c[4]);
  assert.match(sql, /SERVERPROPERTY\('ProductVersion'\)/);
  assert.match(sql, /SERVERPROPERTY\('ProductUpdateLevel'\)/);
  assert.match(sql, /N'16\.0\.4275\.2'/, "the pinned default target when no override is set");
  assert.match(sql, /PARSENAME/, "builds compare numerically, part by part - never as strings");
  const e = evalOf("Build currency");
  assert.doesNotMatch(e, /MatchType|Compliant/, "the dbatools fields are gone");
  assert.match(e, /'attention'/);
  assert.match(e, /NO-TARGET-FOR-THIS-MAJOR/, "a different major version is not graded against this target");

  const mk = (row: object, status: string): any => toFinding({
    category: "Configuration", label: "Build currency", command: "Invoke-DbaQuery",
    priority: "Medium", status, rows: 1, shown: 1, capped: false, data: [row],
  } as any);
  // Synthetic: a node four CUs behind the target (build and KB values are placeholders).
  const behind = mk({ Build: "16.0.4100.1", CU: "CU18", KB: "KB0000018", Edition: "Enterprise", Target: "16.0.4200.1",
    TargetCU: "CU22", Verdict: "BEHIND", Sev: 1 }, "attention");
  assert.match(behind.details, /16\.0\.4100\.1 \(CU18, KB0000018\)/, "the node's own CU and KB, from the engine");
  assert.match(behind.details, /4 cumulative update\(s\) behind/);
  assert.doesNotMatch(behind.remediation.code, /Update-DbaBuildReference/, "no index to refresh any more");
  assert.match(behind.remediation.code, /Patch the SECONDARY first|SECONDARY first/);
  // Synthetic: a node at the target.
  const at = mk({ Build: "16.0.4200.1", CU: "CU22", KB: "KB0000022", Target: "16.0.4200.1", TargetCU: "CU22",
    Verdict: "AT-TARGET", Sev: 0 }, "pass");
  assert.match(at.details, /the fleet target/);
});

test("the Agent-jobs details line grades the same jobs the evaluator does", () => {
  // The evaluator requires Enabled -ne $false; describe() did not, so the line named disabled
  // jobs as current failures — in practice it named several while the Fail rested on one.
  const f: any = toFinding({
    category: "Availability", label: "SQL Agent jobs", command: "Get-DbaAgentJob",
    priority: "Medium", status: "fail", rows: 4, shown: 4, capped: false,
    data: [
      { Name: "AppDb_Analytics: Usage Load Daily", Enabled: true, LastRunOutcome: "Failed" },
      { Name: "old-retired-job", Enabled: false, LastRunOutcome: "Failed" },
      { Name: "another-retired-job", Enabled: false, LastRunOutcome: "Failed" },
      { Name: "healthy-job", Enabled: true, LastRunOutcome: "Succeeded" },
    ],
  } as any);
  const graded = /ENABLED job\(s\) whose last run FAILED: ([^;.]+)/.exec(f.details);
  assert.ok(graded, `expected the enabled-failed list, got: ${f.details}`);
  assert.match(graded[1], /Usage Load Daily/);
  assert.doesNotMatch(graded[1], /retired-job/, "a disabled job must not be listed as a current failure");
  // Disabled failures may still be mentioned, but must be marked as not graded.
  if (/retired-job/.test(f.details)) assert.match(f.details, /not graded/i);
});

test("an action block leads with what was MEASURED on this node", () => {
  // The actions panel used to render only the remediation summary, which is generic prose about
  // the check. A review-tier item (script withheld) therefore carried no fact about the node at
  // all: "Suspect pages" read as a lecture on event_type 1/2/3 without saying the rows here are
  // event_type 5, repaired, months old. Some summaries cover several nodes by nature, so a per-node
  // report could even open with a paragraph about OTHER nodes.
  const raw: any = {
    category: "Recoverability", label: "Suspect pages", command: "Get-DbaSuspectPage",
    priority: "High", status: "attention", rows: 1, shown: 1, capped: false,
    data: [{ Database: "AppDb_Data", FileId: 1, PageId: 1234567, EventType: "Repaired (DBCC)", ErrorCount: 1, LastUpdateDate: "2025-06-02T04:27:29Z" }],
  };
  const f: any = toFinding(raw);
  const score = scoreFindings([f]);
  const html = generateHtmlReport("2026-10-01T00:00:00Z", [{
    instance: "region1-node2", computer: "REGION1-NODE2", sql_instance: "REGION1-NODE2",
    overall_health: score.overall, status_counts: score.counts, categories: score.categories,
    findings: [f], coverage: coverageOf([f], [raw]),
  }] as any);
  assert.match(html, /Measured on region1-node2/, "the node's own finding must lead the action block");
  assert.match(html, /What this means/, "the generic explanation is labelled as such, not presented as the finding");
  assert.match(html, /NO ACTIVE CORRUPTION/, "the measured verdict must be visible even when the script is withheld");
  assert.match(html, /page 1:1234567/, "name the actual page, not just the database");
});

test("bulleted details render as a list, in the order written", () => {
  // describe() may emit "* " lines. An earlier renderer hoisted every non-bullet line above
  // every bullet, which moved a trailing "here is how to dig further" note above the list it
  // referred to.
  const raw: any = {
    category: "Performance", label: "Instance performance settings (workers / parallelism / memory)",
    command: "Invoke-DbaQuery", priority: "Medium", status: "fail", rows: 2, shown: 2, capped: false,
    data: [
      { Setting: "02 workers vs configured target", Value: "1040 / 1024 = 101.6%", Expected: "below 100%", Sev: "fail", Context: "high-water mark" },
      { Setting: "03 THREADPOOL queue depth", Value: "0.5500", Expected: "below 0.10", Sev: "fail", Context: "12,000,000 waits" },
    ],
  };
  const f: any = toFinding(raw);
  assert.ok(String(f.details).includes("\n* "), "multi-setting details must be bulleted, not a run-on sentence");
  const score = scoreFindings([f]);
  const html = generateHtmlReport("2026-10-01T00:00:00Z", [{
    instance: "region1-node2", computer: "REGION1-NODE2", sql_instance: "REGION1-NODE2",
    overall_health: score.overall, status_counts: score.counts, categories: score.categories,
    findings: [f], coverage: coverageOf([f], [raw]),
  }] as any);
  assert.match(html, /<li style="margin:3px 0">/, "bullets must become real list items");
  const lead = html.indexOf("setting(s) outside target");
  const firstLi = html.indexOf('<li style="margin:3px 0">');
  assert.ok(lead > 0 && firstLi > lead, "the lead line must precede its bullets");
});

test("the max-worker-threads target is derived, never a flat '0 (auto)'", () => {
  // x64 auto = 512 + (cpu-4)*16, which on a 16-core box is 704 — BELOW a 1024 pin. Telling a node
  // already at its ceiling to set 0 would CUT the cap by 31% and turn queueing into login
  // failures. Example: a 16-core node pinned at 1024 (auto 704), workers over 100% and a deep THREADPOOL queue.
  const c = CATALOG.find((x) => x[1] === "Instance performance settings (workers / parallelism / memory)");
  assert.ok(c);
  const sql = String(c[4]);
  assert.match(sql, /KEEP the pin at/, "a load-bearing pin must be reported as such, not as a defect");
  assert.match(sql, /PINNED-AND-NEEDED/);
  assert.match(sql, /THIS PIN IS LOAD-BEARING/, "say why unpinning would hurt, with the live numbers");
  // The unconditional form is what produced the dangerous advice.
  assert.doesNotMatch(sql, /max worker threads',CONVERT\(varchar\(20\),@mwt\),'0 \(auto\)'/,
    "the Expected column must depend on the auto value and the live worker pressure");
});

test("a load-bearing setting stays visible as context, not dropped", () => {
  // Grading the pin as "-" stopped it being a false finding, but it then fell out of the
  // fail/attention filter entirely — so the reader saw "workers 112.3% OVER TARGET" with no
  // indication that the cap is already pinned above the auto value and must NOT be lowered.
  // That is the one change someone would reach for, so the line has to say it.
  const f: any = toFinding({
    category: "Configuration", label: "Instance performance settings (workers / parallelism / memory)",
    command: "Invoke-DbaQuery", priority: "High", status: "fail", rows: 3, shown: 3, capped: false,
    data: [
      { Setting: "02 workers vs configured target", Value: "1150 / 1024 = 112.3%", Expected: "below 100%", Verdict: "ABOVE-TARGET", Sev: "fail", Context: "160 tasks" },
      { Setting: "03 THREADPOOL queue depth", Value: "0.5800", Expected: "below 0.10", Verdict: "STARVING", Sev: "attention", Context: "12500000 waits" },
      { Setting: "01 max worker threads", Value: "1024", Expected: "KEEP the pin at 1024 - auto would LOWER it to 704", Verdict: "PINNED-AND-NEEDED", Sev: "-", Context: "auto for 16 cores = 704" },
    ],
  } as any);
  const d = String(f.details);
  assert.match(d, /max worker threads/, "a load-bearing setting must still appear");
  assert.match(d, /NOT a defect/, "and must be marked as context rather than a finding");
  assert.match(d, /KEEP the pin at 1024/);
  assert.doesNotMatch(d, /want KEEP/, "an instruction-shaped target must not be prefixed with 'want'");
  assert.match(d, /2 of 3 setting\(s\) outside target/, "it must not inflate the outside-target count");
});
