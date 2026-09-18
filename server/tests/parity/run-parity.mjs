// Field-presence smoke test, NOT a parity harness, despite the file name/location.
//
// What this actually does: for each case, it calls the dbatools CMDLET DIRECTLY against a
// live instance and asserts the first row has every field in keyFields present as a key
// (`field in rows[0]`) and that at least one row came back. That is the entire check.
//
// What this does NOT do, contrary to what the name implies:
//   - It never runs the DMV query the tool used to use (or still uses by default), so it
//     asserts nothing about whether the two paths agree — not on values, not even on
//     which rows exist.
//   - It never checks field VALUES at all, only that the key is present (e.g. a field
//     that is always null/wrong would still pass).
//   - It never calls the tool handler in src/tools.ts, only the underlying cmdlet — so a
//     bug in a tool's own filtering/mapping/withFallback wiring is invisible to it.
//   - It never reads DBATOOLS_FIRST — every case here always exercises the dbatools
//     cmdlet, so running this file with DBATOOLS_FIRST=0 vs =1 does identical work; it
//     says nothing about which path a real tool call would take.
//
// In short: this proves the listed dbatools cmdlets return rows with the expected field
// NAMES against a live instance, on the dbatools 2.7.2 + SQL Server 2022 CU14 container
// this repo tests against — nothing more. Useful for catching a cmdlet/dbatools-version
// field rename; not a substitute for comparing against the DMV path or for exercising the
// tool handlers themselves.
//
// Run against a live instance:
//   node --import tsx tests/parity/run-parity.mjs --instance local
//
// Exits 0 when every case's expected fields are present, 1 otherwise. Prints one line per
// case.
import { callDbatools } from "../../src/dbatools.ts";

const CASES = [
  // NOTE ON FIELD NAMES: the task-5 brief's mapping table listed keyFields for several of
  // these tools that do not actually exist on the cmdlet's output (verified empirically
  // against dbatools 2.7.2 + a live SQL Server 2022 container - see task-5-report.md for
  // the full list). Per the brief ("a renamed field ... changes the mapping table, rather
  // than being worked around"), the keyFields below are the VERIFIED real property names,
  // not the brief's literal text, everywhere the two differ. Each such case says so inline.

  // Brief said LastFull/LastDiff/LastLog - the real properties are LastFullBackup/
  // LastDiffBackup/LastLogBackup.
  { tool: "get_backup_status", cmdlet: "Get-DbaLastBackup", params: {}, keyFields: ["Database", "LastFullBackup", "LastDiffBackup", "LastLogBackup"] },

  // Brief listed AvailabilityGroup/Replica/Role - all three are correct as-is on
  // Get-DbaAgReplica.
  { tool: "get_current_primary", cmdlet: "Get-DbaAgReplica", params: {}, keyFields: ["AvailabilityGroup", "Replica", "Role"] },

  // Brief said SynchronizationState - Get-DbaAgReplica (and Get-DbaAvailabilityGroup) has
  // no field by that name; the real property is RollupSynchronizationState. (The old DMV's
  // per-DATABASE synchronization_state_desc lives on Get-DbaAgDatabase, which isn't one of
  // the two cmdlets named for this tool.)
  { tool: "get_ag_health", cmdlet: "Get-DbaAgReplica", params: {}, keyFields: ["AvailabilityGroup", "Replica", "Role", "RollupSynchronizationState"] },

  // Brief listed Name/Enabled/LastRunOutcome - all three are correct as-is.
  { tool: "get_job_status", cmdlet: "Get-DbaAgentJob", params: {}, keyFields: ["Name", "Enabled", "LastRunOutcome"] },

  // Brief said InstanceName/Version for Get-DbaInstanceProperty + Get-DbaBuild combined.
  // Neither cmdlet has a literal field called "Version": Get-DbaInstanceProperty returns
  // one Name/Value row per fact (Name='VersionString' carries it as a VALUE, not a property
  // key), and Get-DbaBuild's build-level field is called "Build", not "Version" (and has no
  // "InstanceName" property at all - "SqlInstance" plays that role there). Tested against
  // Get-DbaBuild, the cleaner single-row source of the two.
  { tool: "get_server_info", cmdlet: "Get-DbaBuild", params: {}, keyFields: ["SqlInstance", "Build"] },

  // Brief listed NumberLogicalProcessors/TotalPhysicalMemory - both correct as-is on
  // Get-DbaComputerSystem. HARNESS LIMITATION (not a field mismatch): this cmdlet takes
  // -ComputerName, not -SqlInstance, at all - unlike every other cmdlet in this wave. The
  // harness always sends `{ SqlInstance: instance, ...params }`, so SqlInstance is
  // explicitly undefined here (JSON.stringify drops undefined-valued keys, so the worker
  // never actually receives a SqlInstance param) and ComputerName is supplied instead.
  { tool: "get_machine_spec", cmdlet: "Get-DbaComputerSystem", params: { SqlInstance: undefined, ComputerName: "localhost" }, keyFields: ["NumberLogicalProcessors", "TotalPhysicalMemory"] },

  // Brief listed Database/LogicalName/PhysicalName/Size - all four are correct as-is.
  { tool: "get_database_files", cmdlet: "Get-DbaDbFile", params: { Database: "master" }, keyFields: ["Database", "LogicalName", "PhysicalName", "Size"] },

  // Brief listed FileName/CreationTime - both correct as-is.
  { tool: "get_memory_dumps", cmdlet: "Get-DbaDump", params: {}, keyFields: ["FileName", "CreationTime"] },

  // Brief said Get-DbaDbVirtualLogFile, but that cmdlet returns ONE ROW PER VLF (FileId,
  // FileSize, Status, ...) with no aggregate at all - no "Total" field, nor anything like
  // it. The cmdlet that actually aggregates per database (Database, Total, ...) is
  // Measure-DbaDbVirtualLogFile - a DIFFERENT, pre-existing dbatools cmdlet (already used
  // for the same purpose in this file's own health-check CATALOG). IncludeSystemDBs is
  // passed here only so the case has rows on a fresh container with no user databases yet;
  // the migrated tool itself omits it, to match the old query's user-database-only scope.
  { tool: "get_vlf_count", cmdlet: "Measure-DbaDbVirtualLogFile", params: { IncludeSystemDBs: true }, keyFields: ["Database", "Total"] },

  // Wave 2. Brief listed Spid/Database/CurrentUserAllocatedKB/TotalUserAllocatedKB - all
  // four are correct as-is on Get-DbaTempdbUsage. NOTE: this cmdlet reports ACTIVE tempdb
  // allocations only - on an idle instance it legitimately returns zero rows, which the
  // harness (correctly) treats as a FAIL just like a broken migration would. If this case
  // fails with "returned no rows", generate real tempdb activity (open a session, create a
  // temp table, leave a transaction open) and re-run - do not weaken the assertion.
  { tool: "get_tempdb_usage", cmdlet: "Get-DbaTempdbUsage", params: {},
    keyFields: ["Spid", "Database", "CurrentUserAllocatedKB", "TotalUserAllocatedKB"] },

  // Fix round 1 (R19): the tool's file_space half is restored via Get-DbaDbSpace(-Database
  // tempdb) - the dbatools equivalent for that half (Get-DbaTempdbUsage only ever covered
  // sessions). Brief/ruling listed Database/FileName/UsedSpace/FreeSpace/PercentUsed - all
  // five are correct as-is, verified live.
  { tool: "get_tempdb_usage_files", cmdlet: "Get-DbaDbSpace", params: { Database: "tempdb" },
    keyFields: ["Database", "FileName", "UsedSpace", "FreeSpace", "PercentUsed"] },

  // Wave 2. Brief listed Database/Object/Name/Updated/Rows/RowsSampled - all six are
  // correct as-is on Get-DbaDbccStatistic. This cmdlet needs statistics to exist - a bare
  // instance with no user tables/indexes returns zero rows.
  { tool: "get_statistics_health", cmdlet: "Get-DbaDbccStatistic", params: {},
    keyFields: ["Database", "Object", "Name", "Updated", "Rows", "RowsSampled"] },

  // Task 2. Get-DbaDatabase returns a ~200-property SMO object; the migrated tool narrows it
  // server-side via callDbatools' optional `select` param (applied inside the pwsh worker,
  // before ConvertTo-PlainRows). This case calls the cmdlet unnarrowed, same as every other
  // case in this harness - it is checking field parity against the DMV the tool replaced, not
  // the narrowing itself. All five keyFields (plus the rest of the tool's select list)
  // verified present on a live SQL 2022 CU14 probe.
  { tool: "get_database_info", cmdlet: "Get-DbaDatabase", params: {},
    keyFields: ["Name", "Status", "RecoveryModel", "CompatibilityLevel", "Owner"] },

  // Task 4 (Wave 3, live diagnostics behind DBATOOLS_FIRST). All three keyField sets were
  // verified present on a live SQL 2022 CU14 probe (this repo's own container) and match the
  // task-4 brief's field list exactly - no renames needed for these three.
  { tool: "get_wait_stats", cmdlet: "Get-DbaWaitStatistic", params: {},
    keyFields: ["WaitType", "WaitSeconds", "WaitCount", "Percentage"] },
  { tool: "get_latch_stats", cmdlet: "Get-DbaLatchStatistic", params: {},
    keyFields: ["WaitType", "WaitSeconds", "WaitCount", "Percentage"] },
  { tool: "get_active_sessions", cmdlet: "Get-DbaProcess", params: {},
    keyFields: ["Spid", "Login", "Database", "Status", "BlockingSpid"] },
];

const args = process.argv.slice(2);
const instIdx = args.indexOf("--instance");
const instance = instIdx !== -1 ? args[instIdx + 1] : "local";

let failures = 0;

for (const c of CASES) {
  try {
    const rows = await callDbatools(c.cmdlet, { SqlInstance: instance, ...c.params });
    if (!Array.isArray(rows) || rows.length === 0) {
      console.log(`FAIL ${c.tool}: ${c.cmdlet} returned no rows`);
      failures++;
      continue;
    }
    const missing = c.keyFields.filter((f) => !(f in rows[0]));
    if (missing.length) {
      console.log(`FAIL ${c.tool}: ${c.cmdlet} is missing field(s): ${missing.join(", ")}`);
      failures++;
      continue;
    }
    console.log(`ok   ${c.tool}: ${c.cmdlet} (${rows.length} row(s), expected fields present by NAME — values/DMV-parity/tool-handler/DBATOOLS_FIRST not checked)`);
  } catch (e) {
    console.log(`FAIL ${c.tool}: ${e.message}`);
    failures++;
  }
}

if (CASES.length === 0) {
  console.log("::error::no field-presence cases registered - this harness proves nothing");
  process.exit(1);
}
console.log(failures === 0
  ? `\nAll ${CASES.length} case(s) returned the expected field NAMES. This does not confirm field values, DMV parity, tool-handler behavior, or DBATOOLS_FIRST wiring — see the header comment.`
  : `\n${failures} case(s) FAILED (missing an expected field name, or the cmdlet call itself errored/returned no rows).`);
process.exit(failures === 0 ? 0 : 1);
