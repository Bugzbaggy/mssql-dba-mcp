/**
 * The exact tool set of every profile.
 *
 * README, DEPLOYMENT.md §4, USER-GUIDE.md and .env.example all state these counts, and they had
 * drifted for months ("31 DMV tools", "the 6 read tools") because nothing pinned them once the
 * original tests/validate.mjs stopped running. A new tool must be added here AND in those docs.
 *
 * TOOLSET, ENG_WRITE_ENABLED, SCHEMA_DOCS_ENABLED and DBATOOLS_ENABLED are read when tools.ts
 * loads, so each profile is registered in its own child process against the real McpServer;
 * nothing connects to SQL.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The 11 app-data tools every profile has (7 query/metadata + the 4 schema-docs tools). */
const APP = ["describe_doc_object", "describe_object", "describe_schema", "execute_query", "fan_out_query",
  "get_current_primary", "list_databases", "list_instances", "list_schema_docs", "list_tables", "search_schema_docs"];
const DOCS = ["describe_doc_object", "describe_schema", "list_schema_docs", "search_schema_docs"];
/** The 32 DMV tools: plain SQL over the user's login. */
const DMV = ["get_active_sessions", "get_ag_health", "get_backup_status", "get_blocking_chains", "get_buffer_pool_by_object",
  "get_columnstore_health", "get_cpu_history", "get_database_files", "get_database_info", "get_deadlock_history",
  "get_distributed_ag_health", "get_file_io_stats", "get_hiq", "get_index_fragmentation", "get_index_usage_stats",
  "get_job_status", "get_latch_stats", "get_log_paths", "get_long_running_transactions", "get_machine_spec",
  "get_memory_dumps", "get_memory_usage", "get_missing_indexes", "get_perfmon_counters", "get_plan_cache_pollution",
  "get_query_store_regressions", "get_server_info", "get_statistics_health", "get_tempdb_usage", "get_top_queries",
  "get_vlf_count", "get_wait_stats"];
/** The 12 tools that run through PowerShell + dbatools (gone with DBATOOLS_ENABLED=false). */
const POWERSHELL = ["check_dbatools_environment", "generate_cluster_log", "get_dbatools_command_help", "get_host_dll_versions",
  "get_host_event_log", "list_dbatools_commands", "read_cluster_reports", "read_error_log", "read_sql_dump",
  "run_dbatools_command", "run_diagnostic_query", "run_health_check"];

const PROBE = new URL("./.toolset-probe.tmp.mts", import.meta.url);
const PROFILES = {
  dba: { TOOLSET: "dba" },
  dbaNoDbatools: { TOOLSET: "dba", DBATOOLS_ENABLED: "false" },
  ops: { TOOLSET: "ops" },
  opsNoDocs: { TOOLSET: "ops", SCHEMA_DOCS_ENABLED: "false" },
  eng: { TOOLSET: "eng" },
  engWrite: { TOOLSET: "eng-write" },
  engWriteEnabled: { TOOLSET: "eng-write", ENG_WRITE_ENABLED: "1" },
} as const;
const got = {} as Record<keyof typeof PROFILES, string[]>;

function registered(env: Record<string, string>): Promise<string[]> {
  const base: Record<string, string | undefined> = { ...process.env, INSTANCES_FILE: fileURLToPath(new URL("../../fleet.example.json", import.meta.url)) };
  for (const k of ["SQL_CRED_TARGET", "SQL_USER", "SQL_PASSWORD", "TOOLSET", "ENG_WRITE_ENABLED", "SCHEMA_DOCS_ENABLED", "DBATOOLS_ENABLED"]) delete base[k];
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ["--import", "tsx", fileURLToPath(PROBE)], { encoding: "utf8", env: { ...base, ...env } },
      (err, out) => { if (err) reject(err); else resolve(JSON.parse(out) as string[]); });
  });
}

// One probe per profile, all at once: each child compiles tools.ts + dbatools.ts, ~20 s apiece.
before(async () => {
  writeFileSync(PROBE, [
    `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";`,
    `import { registerTools } from "../src/tools.js";`,
    `const s = new McpServer({ name: "probe", version: "0" });`,
    `const names: string[] = [];`,
    `const t = s as unknown as { tool: (...a: unknown[]) => unknown };`,
    `const orig = t.tool.bind(s);`,
    `t.tool = (name: unknown, ...rest: unknown[]) => { names.push(String(name)); return orig(name, ...rest); };`,
    `registerTools(s);`,
    `process.stdout.write(JSON.stringify(names.sort()));`,
  ].join("\n"), "utf8");
  const keys = Object.keys(PROFILES) as (keyof typeof PROFILES)[];
  const lists = await Promise.all(keys.map((k) => registered(PROFILES[k])));
  keys.forEach((k, i) => { got[k] = lists[i]; });
});
after(() => rmSync(PROBE, { force: true }));
const sorted = (...xs: string[][]) => [...new Set(xs.flat())].sort();

test("dba: 55 tools — 32 DMV, 12 PowerShell/dbatools, 11 app-data", () => {
  assert.equal(new Set([...DMV, ...POWERSHELL, ...APP]).size, DMV.length + POWERSHELL.length + APP.length, "the groups must not overlap");
  assert.deepEqual(got.dba, sorted(DMV, POWERSHELL, APP));
});

test("ops and eng: the same 11 SELECT-only app-data tools, no DMV and no PowerShell", () => {
  assert.deepEqual(got.ops, sorted(APP));
  assert.deepEqual(got.eng, sorted(APP));
});

test("eng-write: execute_write only when ENG_WRITE_ENABLED=1", () => {
  assert.deepEqual(got.engWrite, sorted(APP), "without the flag the profile stays read-only");
  assert.deepEqual(got.engWriteEnabled, sorted(APP, ["execute_write"]));
});

test("the switches remove exactly their own tools", () => {
  assert.deepEqual(got.opsNoDocs, sorted(APP.filter((t) => !DOCS.includes(t))));
  assert.deepEqual(got.dbaNoDbatools, sorted(DMV, APP));
});
