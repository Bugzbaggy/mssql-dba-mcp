import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { queryInstance, listInstances, DEFAULT_INSTANCE, executeWrite, resolveRegionPrimary, invalidatePrimaryCache } from "./connectionManager.js";
import { registerDbatoolsTools, callDbatools } from "./dbatools.js";
import { withFallback } from "./dbatoolsFirst.js";
import { listSchemaDocs, describeSchema, describeDocObject, searchSchemaDocs, docsRoot } from "./schemaDocs.js";

function toJson(value: unknown): string {
  return JSON.stringify(
    value,
    (_, v) => (typeof v === "bigint" ? v.toString() : v),
    2
  );
}
import { validateQuery, validateWriteQuery } from "./safety.js";

type ToolResult = { content: Array<{ type: "text"; text: string }> };

function ok(value: unknown): ToolResult {
  return { content: [{ type: "text", text: toJson(value) }] };
}

function err(message: string): ToolResult {
  return { content: [{ type: "text", text: `Error: ${message}` }] };
}

function truncationNote(count: number): string {
  return `\n\n[Note: Result was truncated to ${count} rows. Use a more specific WHERE clause to narrow the result set.]`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve instance_name (including the "<region>-primary" alias every tool already
// accepts) to the host:port pair dbatools needs for -SqlInstance. Wave-1 tools that
// were migrated onto dbatools (Task 5) use this instead of queryInstance so the
// "<region>-primary" alias keeps working the same way it already does for every
// other tool.
// ─────────────────────────────────────────────────────────────────────────────
async function resolveDbaSqlInstance(instance_name: string): Promise<{ host: string; port: number }> {
  let name = instance_name;
  if (name.endsWith("-primary")) {
    const region = name.slice(0, -"-primary".length);
    name = await resolveRegionPrimary(region);
  }
  const cfg = listInstances().find((i) => i.name === name);
  if (!cfg) throw new Error(`Unknown instance "${instance_name}". Call list_instances for available names.`);
  return { host: cfg.host, port: cfg.port };
}
function dbaSqlInstanceArg(cfg: { host: string; port: number }): string {
  return `${cfg.host},${cfg.port}`;
}
// ─────────────────────────────────────────────────────────────────────────────
// Shared instance_name parameter added to every tool.
// Copilot can call list_instances to discover available names.
// ─────────────────────────────────────────────────────────────────────────────
const instanceParam = {
  instance_name: z
    .string()
    .optional()
    .default(DEFAULT_INSTANCE)
    .describe(
      `Named SQL Server instance to query. Defaults to "${DEFAULT_INSTANCE}" (the NLB listener, read-only). ` +
      "Call list_instances first to see all available instance names. " +
      "AG-PRIMARY ALIAS: pass '<region>-primary' (e.g. 'region1-primary', 'region2-primary', … one per region) " +
      "to route to the LIVE PRIMARY node of that region's local AG — resolved at query time, so failovers don't " +
      "leave you pinned to a stale node. Use this whenever you want the primary specifically (active workload, " +
      "writes via the engineering profile, or any analysis that the NLB's read-only routing might land on a secondary). " +
      "The plain '<region>-nlb' listener may route to a readable secondary under ApplicationIntent=ReadOnly."
    ),
};

// Database names differ by region: the config/reference DB is named AppCatalog on the primary region
// (the global primary, also the replication Distributor) but AppDb in the secondary regions (the
// transactional-replication Subscribers, reached via the regional AG listeners) — same
// logical database, different name per region. the secondary regions also carry AppDb_Data, AppDb_Routing and
// a forwarded read-only AppCatalog (distributed AG). Because of this, list_databases reads
// sys.databases at runtime rather than using a hardcoded list. What an ops login can actually
// read is still governed by its role_team_ops* grants per database.

// Data-model guidance surfaced in the app-data tool descriptions so the agent picks the
// right source: config/reference data vs high-volume transactional data vs aggregates.
const DATA_MODEL_GUIDANCE =
  "DATA MODEL: the configuration & reference database is named AppCatalog on the primary region and AppDb in " +
  "the secondary regions (same logical DB — the regional replication subscriber); reference either by the name that " +
  "exists in the region you are querying. " +
  "AppDb_Data = high-volume TRANSACTIONAL data — its large partitioned tables (e.g. messageLog) are " +
  "business-critical and sensitive. AppDb_Analytics = pre-aggregated reporting tables AND the conformed " +
  "dimensional model (schema bi). " +
  "FOR ANY ANALYSIS (counts, trends, revenue, volumes, reporting) query the aggregated tables in " +
  "AppDb_Analytics (e.g. msg.StatMessageLog*) — do NOT scan messageLog or other large AppDb_Data tables. " +
  "AppDb_Analytics.bi ALSO holds SCD-2 HISTORY of account/partner attributes and OWNERSHIP — it is the place for any " +
  "'over time / as-of / who-managed-X-when' question; AppCatalog/AppDb config tables keep only the CURRENT value " +
  "(and audit.OperatorActionLog is an operator ACTION log, not ownership history). For 'distinct owners over time' " +
  "collapse on the NATURAL key (bi.Manager.UserID/Email), NOT the surrogate DimManagerId; prefer the blessed views " +
  "bi.vwDimManagerAccount / bi.vwDimManagerPartner. " +
  "Use AppDb_Data only for a narrow point lookup (filter on a key + TOP N). Unbounded scans of the " +
  "sensitive tables are rejected (override with allow_large_scan:true). " +
  "VERIFY COLUMN SEMANTICS: when a result hinges on a column's DIRECTION, PRIMACY, SIGN, ordering or key-stability " +
  "(e.g. a Priority/rank, an SCD surrogate vs natural key), confirm the meaning against the CONSUMING proc/view (the " +
  "ORDER BY / join it actually uses) BEFORE presenting — do not infer from the column name or a 'lower = first' " +
  "convention and call it confirmed. " +
  "SEMANTIC LAYER: before writing SQL against an unfamiliar object, consult the schema-doc tools — " +
  "search_schema_docs to locate where a concept lives (db.schema.object), describe_schema for a schema's " +
  "purpose/data-flow/access-roles, and describe_doc_object for a table's columns, ENUM DECODINGS, foreign keys " +
  "and a procedure's parameters/usage/grants. These cover the documented databases (run list_schema_docs to see " +
  "which) and turn 'guess the column' into 'look it up'. They are offline doc lookups — no DB round-trip.";

// Crash / instability investigation playbook — so the agent locates evidence itself and
// compares against the right peers instead of asking for paths or guessing the cause.
const INVESTIGATION_GUIDANCE =
  "INSTABILITY/CRASH PLAYBOOK: don't ask for log paths — locate evidence yourself. " +
  "(1) get_log_paths → the SQL error-log directory (e.g. ...\\MSSQL\\Log) + where dumps land; " +
  "(2) get_memory_dumps → recent SQLDump* (sys.dm_server_memory_dumps: filename, time, size; resets at restart — for pre-restart dumps use read_sql_dump action='list'); " +
  "(3) read_error_log on log_number=0 AND log_number=1 (log_number=1 holds the entries before the crash if SQL restarted) filtered for 'Stack Dump'/'exception'/'access violation'/'SqlDumpExceptionHandler'/module names — extract the faulting 'pdb=' + 'rva=' from the Exception Address frame; " +
  "(4) read_sql_dump action='list' enumerates SQLDump*.txt/.mdmp on disk (works even after restart, unlike (2)); action='read' returns the full text stack + loaded-module list from one .txt — diff Exception Address pdb/rva against peer crashes to confirm bug class; " +
  "(5) get_host_event_log (log_name='Application' or 'System') reads the .evtx over SMB — correlate Windows 'Application Error' (sqlservr.exe), WER, and Service Control Manager events with the SQL ERRORLOG timestamp; provider='Application Error' + event_id=1000 captures process crashes; " +
  "(6) get_host_dll_versions probes the EDR agent ctiuser.dll, third-party ODBC, Windows core, and SQL Binn versions on the host — diff against the healthy peer to confirm/deny EDR-version or DLL-skew hypotheses; " +
  "(7) get_machine_spec → CPU/RAM/NUMA/build/OS/VM type evidence; " +
  "(8) read_cluster_reports for the ON-DISK Cluster.log around the crash window (node going RESOLVING, witness arbitration); " +
  "(8b) generate_cluster_log to render a FRESH Cluster.log from CURRENT cluster state (Get-ClusterLog on the node) for that " +
  "window when the on-disk file is stale/rolled — pass a `contains` timestamp regex; " +
  "(9) get_hiq → the persisted sp_WhoIsActive history (DBA.dbo.HIQMonitor, ~1-min cadence, ~30-day retention per node) for " +
  "the WORKLOAD around the incident: pass start+end matching the dump/error-log timestamp to see the long/blocked/blocking " +
  "sessions, CPU/IO/tempdb and open transactions at that moment (a witness to correlate, not proof of cause). " +
  "(10) get_query_store_regressions (+ get_top_queries) — for a DB-call-failure / blocking / contention alert, run this " +
  "ALONGSIDE get_hiq on the hot DB(s) (on the primary region: AppDb_Data AND AppCatalog — the status-update procs run in " +
  "AppCatalog but hit AppDb_Data via the msg.MessageLog synonym) to catch plan-regression / parameter-sniffing " +
  "amplifiers HIQ cannot see; get_top_queries (order_by reads/cpu) surfaces the raw offenders. DISCIPLINE: treat a huge " +
  "regression_pct with recent_plan_executions=1 and a sub-ms best plan as one-off noise — prioritise regressions that " +
  "fired IN the alert window, with high execution count and high ABSOLUTE reads/CPU/duration, and cross-check the HIQ " +
  "lead blockers before blaming a plan (interim fix: sp_query_store_force_plan the best_plan_id — reversible; then " +
  "address stale stats / parameter sniffing). " +
  "ALWAYS COMPARE the affected node against PEER nodes on the SAME cloud (list_instances shows " +
  "region + cloud) — diff the spec, SQL build, OS build, and loaded modules/sensors. A healthy " +
  "same-cloud peer with similar build is the control; spec/capacity is rarely the cause if a " +
  "smaller/busier peer is stable. Use fan_out_query to gather the same signal fleet-wide at once. " +
  "When comparing 'the primary in region X' across the conversation, NEVER reuse a primary " +
  "identification from earlier — failovers happen mid-session. Use the '<region>-primary' alias " +
  "(e.g. 'region3-primary') in instance_name, or call get_current_primary, so the live AG primary is " +
  "resolved at query time. Don't hard-code 'region3-node1' / 'region2-node1' / etc. across calls.";

// Cross-region topology surfaced so the agent reasons correctly about replication and routing.
const FLEET_TOPOLOGY =
  "TOPOLOGY: One region is the GLOBAL PRIMARY. The config/reference database is named AppCatalog on the primary region and AppDb in " +
  "the secondary regions — the SAME logical database kept in cross-region sync, so it holds global data everywhere. TODAY that " +
  "sync is TRANSACTIONAL REPLICATION: the primary region AppCatalog is the Publisher/Distributor, regional AppDb are the " +
  "Subscribers (read via the regional AG listeners). AppDb_Routing and a forwarded read-only AppCatalog also reach " +
  "secondary regions via distributed AGs (dag-<region>-cluster, over the ag-<region>-forwarder). PLANNED: cut the config " +
  "DB over to that read-only AppCatalog DAG replica and DEPRECATE the AppDb transactional replication. Net: " +
  "config/reference data (AppCatalog/AppDb) and AppDb_Routing are global (same data in every region, modulo replication " +
  "lag); AppDb_Data and AppDb_Analytics are genuinely REGION-LOCAL and differ per region. Use get_distributed_ag_health " +
  "(run on the primary region) for distributed-AG health, get_ag_health for the local AG.";

// TOOLSET selects which tools this process exposes:
//   "dba" (default) — everything: 28 DMV tools + the common app-data tools below.
//   "all"           — same as dba.
//   "ops" / "eng"   — common app-data tools only (SELECT-only; no DMVs, no EXEC).
//                     Both are the same read-only app-data profile (msg-ops / msg-eng);
//                     they differ only by the login each user connects as, so the
//                     database's own roles scope what each can see. Any non-dba/all
//                     value falls through to this SELECT-only profile.
const TOOLSET = (process.env.TOOLSET ?? "dba").toLowerCase();
const DMV_TOOLS_ENABLED = TOOLSET === "dba" || TOOLSET === "all";
// Opt-in engineering write profile. The single write tool (execute_write) is registered
// ONLY when TOOLSET=eng-write AND the explicit kill-switch ENG_WRITE_ENABLED=1 is set.
// The kill-switch is currently REQUIRED so the deployment is strictly read-only by default
// — even TOOLSET=eng-write yields a read-only server unless writes are deliberately turned
// on. To re-enable writes later: set TOOLSET=eng-write and ENG_WRITE_ENABLED=1.
// Every other profile (dba/all/ops/eng) is always read-only.
const WRITE_ENABLED = TOOLSET === "eng-write" && process.env.ENG_WRITE_ENABLED === "1";
if (TOOLSET === "eng-write" && !WRITE_ENABLED) {
  console.error(
    "[safety] TOOLSET=eng-write but writes are DISABLED (ENG_WRITE_ENABLED is not '1') — " +
    "execute_write will NOT be registered; the server is read-only. Set ENG_WRITE_ENABLED=1 to enable writes."
  );
}

function escapeSqlString(v: string): string {
  return v.replace(/'/g, "''");
}
// Database / schema / object identifiers must match SQL Server naming so they cannot be
// used to smuggle SQL into the fixed queries — in EITHER a single-quoted ('x') or a
// bracket-quoted ([x]) context. (Single-quote escaping alone is unsafe for [ ... ].)
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_$#@]{0,127}$/;
function assertIdentifier(value: string, label: string): void {
  if (!IDENT_RE.test(value)) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
}

// Pure, exported for testing (get_database_info). SMO reports Database.Size in MEGABYTES
// and Database.SpaceAvailable in KILOBYTES — confirmed against dbatools' own Get-DbaDatabase
// source (its default display view aliases the raw Size property as "SizeMB") and Microsoft's
// SMO Database class docs (SpaceAvailable is documented in KB). Left as raw adjacent columns
// named "Size"/"SpaceAvailable", nothing conveys that 1024x mismatch. This relabels + converts
// so both are directly comparable in the same unit.
export function toDatabaseInfoRow(row: Record<string, unknown>): Record<string, unknown> {
  const { Size, SpaceAvailable, ...rest } = row;
  return {
    ...rest,
    SizeMB: Size,
    SpaceAvailableMB: typeof SpaceAvailable === "number"
      ? Math.round((SpaceAvailable / 1024) * 100) / 100
      : SpaceAvailable,
  };
}

// Pure, exported for testing (get_statistics_health's dbatools path). Decides which of the
// candidate stats-bearing objects actually get probed and whether the database had more of
// them than max_objects — the truncation decision, split out from the DMV pre-check query and
// the per-object DBCC calls so it can be tested without a live SQL Server. `objectNames` is
// expected pre-sorted (by name) so the cap is deterministic.
export function selectStatsObjects(objectNames: string[], maxObjects: number): { selected: string[]; truncated: boolean } {
  const truncated = objectNames.length > maxObjects;
  return { selected: truncated ? objectNames.slice(0, maxObjects) : objectNames, truncated };
}

// All tools in this server are READ-ONLY. Annotate each so MCP clients can surface that,
// and so any future write capability must be added as a SEPARATE, explicitly destructive
// tool — never silently mixed in. Every operation runs under the calling user's own SQL
// login (per-user identity), so SQL Server governs and audits it; this server holds no
// standing privileged/shared credential.
const READ_ONLY_ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
// Handler args inferred from the Zod shape with a lightweight mapped type. We deliberately
// avoid the SDK's ToolCallback<Args> here: its zod3|zod4 compat inference is so expensive to
// instantiate across every tool that `tsc` exhausts its heap. This gives the same per-tool
// arg typing (clearing the implicit-any on destructured params) at negligible compiler cost.
type HandlerArgs<Args extends z.ZodRawShape> = { [K in keyof Args]: z.infer<Args[K]> };
function roTool<Args extends z.ZodRawShape>(
  server: McpServer,
  name: string,
  description: string,
  schema: Args,
  cb: (args: HandlerArgs<Args>, extra: unknown) => unknown,
) {
  return (server as { tool: (...a: unknown[]) => unknown }).tool(name, description, schema, READ_ONLY_ANNOTATIONS, cb);
}

export function registerTools(server: McpServer): void {

  // ============================================================
  // list_instances — discover available SQL Server instances
  // ============================================================
  roTool(server,
    "list_instances",
    "List all configured fleet hosts grouped by region (sg, id, uk, us) and by cloud (aws, gcp). Most entries are SQL " +
      "Server instances (kind='sql', the default — names like region1-listener, region1-node1, region1-node2). Each region also has ONE WSFC " +
      "file-share witness host (kind='witness', name '<region>-witness', e.g. region2-witness=192.0.2.26) — SQL tools refuse " +
      "those because they don't run SQL; address them with host-level tools (read_cluster_reports for cluster nodes, " +
      "host diagnostics for the witness itself). Call this first when the user does not specify which instance/region " +
      "they want — and to pick PEER nodes on the SAME cloud when diagnosing a crash/instability. " +
      "ALSO available (not in the static list, resolved at query time): '<region>-primary' for each region — pass " +
      "that as instance_name to ANY tool and it routes to the LIVE AG primary node. Use it instead of pinning a " +
      "specific db node when you want 'the primary right now' — failovers won't strand you. Use get_current_primary " +
      "to see which physical node a region's primary alias currently resolves to.",
    {},
    async () => {
      const cfg = listInstances().map(({ name, region, cloud, host, port, user, kind, computer_name }) => ({
        name, region, cloud, host,
        port: kind === "witness" ? undefined : port,
        user: kind === "witness" ? undefined : user,
        kind: kind ?? "sql",
        ...(computer_name ? { computer_name } : {}),
      }));
      // Surface the synthetic <region>-primary aliases the connection manager understands,
      // so AI clients can discover them without having to remember the naming convention.
      const regions = [...new Set(cfg.map((i) => i.region).filter((r): r is string => !!r))];
      const primaryAliases = regions.map((r) => ({
        name:   `${r}-primary`,
        region: r,
        cloud:  cfg.find((i) => i.region === r)?.cloud,
        host:   "(resolved at query time → current AG primary)",
        port:   1433,
        user:   "(per-user identity)",
        kind:   "alias",
      }));
      return ok([...cfg, ...primaryAliases]);
    }
  );

  // ============================================================
  // get_current_primary — resolve "<region>-primary" to the live AG primary node
  // ============================================================
  roTool(server,
    "get_current_primary",
    "Resolve which physical node is the CURRENT AG primary in a region (region1/region2/region3/region4). Failovers move the " +
      "primary; never carry a primary identification across a conversation — call this whenever you need to know. " +
      "Returns the resolved instance_name (e.g. 'region3-node2'), the host/port, and the server name reported by SQL. " +
      "You can ALSO just pass '<region>-primary' (e.g. 'region3-primary') as instance_name to any tool and it auto-routes " +
      "to this node; this tool is for when you want to know which physical node was chosen, or to refresh the " +
      "60s primary-cache by calling with refresh:true. Faster + safer than chaining list_instances + get_ag_health.",
    {
      region: z
        .string()
        .describe("Region code: sg, id, uk, or us."),
      refresh: z
        .boolean()
        .optional()
        .default(false)
        .describe("If true, invalidates the 60s primary cache before resolving — use after a failover."),
    },
    async ({ region, refresh }) => {
      try {
        const r = region.toLowerCase().trim();
        if (refresh) invalidatePrimaryCache(r);
        // Candidate discovery + the region -> physical-node cache stay on
        // connectionManager.resolveRegionPrimary: it is shared, load-bearing
        // infrastructure (every tool's "<region>-primary" alias routes through it via
        // getPool), not a self-contained DMV body — rewriting it is out of scope for
        // this migration. What DOES move to dbatools here is the confirmation step:
        // once a candidate is resolved, Get-DbaAgReplica (Task 5's migration for this
        // tool) is queried against it to report the AG name + role dbatools itself sees,
        // instead of trusting the cache alone.
        const instanceName = await resolveRegionPrimary(r);
        const inst = listInstances().find((i) => i.name === instanceName);
        let availabilityGroup: string | undefined;
        let role: string | undefined;
        if (inst) {
          try {
            const replicas = (await callDbatools("Get-DbaAgReplica", {
              SqlInstance: dbaSqlInstanceArg(inst),
            })) as Array<Record<string, unknown>>;
            const local = replicas.find((row) => String(row.Role) === "Primary") ?? replicas[0];
            availabilityGroup = local ? String(local.AvailabilityGroup) : undefined;
            role = local ? String(local.Role) : undefined;
          } catch {
            // Best-effort confirmation only — the cache-resolved instanceName above is
            // still the authoritative answer even if this dbatools call fails.
          }
        }
        return ok({
          region: r,
          primary_instance_name: instanceName,
          primary_host: inst?.host,
          primary_port: inst?.port,
          cloud: inst?.cloud,
          availability_group: availabilityGroup,
          role,
          cache_ttl_seconds: 60,
          hint: `Pass instance_name='${r}-primary' to any other tool to auto-route to this node.`,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // list_databases — the application databases in the AG (all read-only)
  // ============================================================
  roTool(server, 
    "list_databases",
    "List the online user databases on the target instance (reads sys.databases). Names vary by region — " +
      "the primary region hosts AppCatalog + AppDb_* databases; the secondary regions host AppDb, AppDb_Data, AppDb_Routing and a distributed " +
      "AppCatalog (some regions also carry additional databases). All are read-only via execute_query and the per-database tools " +
      "(pass the name as database_name). Call this to discover databases before an application-data query. " +
      FLEET_TOPOLOGY,
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT name, database_id, state_desc, recovery_model_desc
          FROM sys.databases
          WHERE database_id > 4 AND state = 0
          ORDER BY name
        `);
        return ok({ instance: instance_name, databases: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // list_tables — discover readable tables/views in a database (schema-aware)
  // INFORMATION_SCHEMA is permission-scoped, so an ops login only sees objects it
  // has been granted access to via its role_team_ops* membership.
  // ============================================================
  roTool(server, 
    "list_tables",
    "List the tables and views in a database with their APPROXIMATE ROW COUNT and whether they're PARTITIONED, " +
      "so you can judge cost before querying. Results are scoped by your login's permissions (you only see what you " +
      "can read), ordered largest-first. Use this before execute_query: avoid full scans of high-row / partitioned " +
      "tables — for analytics use the AppDb_Analytics aggregates; for a big transactional table, filter on a key/partition " +
      "column (call describe_object to see its indexes + partition column) and add TOP.",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .default(process.env.DEFAULT_DATABASE ?? "AppCatalog")
        .describe("Database to inspect (e.g. AppCatalog, AppDb_Data, AppDb_Routing ...). The same ops roles exist across these databases."),
      schema: z.string().optional().describe("Filter to a schema (e.g. svc, core, msg)."),
      name_like: z.string().optional().describe("Case-insensitive substring to match in the table/view name."),
    },
    async ({ instance_name, database_name, schema, name_like }) => {
      try {
        assertIdentifier(database_name, "database_name");
        const tf = [
          schema ? `AND s.name = '${escapeSqlString(schema)}'` : "",
          name_like ? `AND t.name LIKE '%${escapeSqlString(name_like)}%'` : "",
        ].join(" ");
        const vf = [
          schema ? `AND s.name = '${escapeSqlString(schema)}'` : "",
          name_like ? `AND v.name LIKE '%${escapeSqlString(name_like)}%'` : "",
        ].join(" ");
        // sys.* catalog views are metadata-visibility-scoped (you only see objects you have
        // some permission on), same as INFORMATION_SCHEMA — but they also carry row counts
        // (sys.partitions, no VIEW DATABASE STATE needed) and partition info.
        const { rows, truncated } = await queryInstance(instance_name, `
          SELECT [schema], [name], [type], approx_rows, is_partitioned FROM (
            SELECT s.name AS [schema], t.name AS [name], 'BASE TABLE' AS [type],
                   SUM(CASE WHEN p.index_id IN (0,1) THEN p.rows ELSE 0 END) AS approx_rows,
                   CASE WHEN MAX(p.partition_number) > 1 THEN 1 ELSE 0 END AS is_partitioned
            FROM [${database_name}].sys.tables t
            JOIN [${database_name}].sys.schemas s ON s.schema_id = t.schema_id
            LEFT JOIN [${database_name}].sys.partitions p ON p.object_id = t.object_id
            WHERE 1=1 ${tf}
            GROUP BY s.name, t.name
            UNION ALL
            SELECT s.name, v.name, 'VIEW', NULL, 0
            FROM [${database_name}].sys.views v
            JOIN [${database_name}].sys.schemas s ON s.schema_id = v.schema_id
            WHERE 1=1 ${vf}
          ) q
          ORDER BY CASE WHEN approx_rows IS NULL THEN 0 ELSE approx_rows END DESC, [schema], [name]
        `, 1000);
        return ok({ database: database_name, objects: rows, truncated });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // describe_object — columns + types for a table or view (schema-aware)
  // ============================================================
  roTool(server, 
    "describe_object",
    "Describe a table/view: columns (name, type, nullability) PLUS its indexes (key columns) and partition column " +
      "and approximate row count — so you can write an efficient, index-/partition-aligned WHERE instead of a scan. " +
      "Also returns any table/column DESCRIPTIONS stored as extended properties (MS_Description) when present. " +
      "Scoped by your login's permissions. Use after list_tables, before execute_query: filter on a leading index key " +
      "or the partition column, and add TOP. For richer semantics (enum decodings, FKs, usage) use describe_doc_object. " +
      "NOTE: descriptions/types do NOT encode a column's ordering DIRECTION or primacy — when a result depends on that " +
      "(e.g. a Priority/rank, SCD surrogate vs natural key), verify against the consuming proc/view's ORDER BY first.",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .default(process.env.DEFAULT_DATABASE ?? "AppCatalog")
        .describe("Database containing the object."),
      schema: z.string().describe("Schema of the object (e.g. svc, core, msg)."),
      object_name: z.string().describe("Table or view name (no schema prefix)."),
    },
    async ({ instance_name, database_name, schema, object_name }) => {
      try {
        assertIdentifier(database_name, "database_name");
        const sch = escapeSqlString(schema), obj = escapeSqlString(object_name);
        const { rows } = await queryInstance(instance_name, `
          SELECT
            c.ORDINAL_POSITION                              AS position,
            c.COLUMN_NAME                                   AS column_name,
            c.DATA_TYPE                                     AS data_type,
            COALESCE(c.CHARACTER_MAXIMUM_LENGTH, c.NUMERIC_PRECISION) AS length_or_precision,
            c.IS_NULLABLE                                   AS is_nullable,
            c.COLUMN_DEFAULT                                AS column_default,
            (SELECT CAST(ep.value AS nvarchar(4000))
               FROM [${database_name}].sys.extended_properties ep
               JOIN [${database_name}].sys.objects o2 ON o2.object_id = ep.major_id
               JOIN [${database_name}].sys.schemas s2 ON s2.schema_id = o2.schema_id
               JOIN [${database_name}].sys.columns sc ON sc.object_id = ep.major_id AND sc.column_id = ep.minor_id
               WHERE ep.class = 1 AND ep.name = 'MS_Description'
                 AND s2.name = '${sch}' AND o2.name = '${obj}' AND sc.name = c.COLUMN_NAME) AS column_description
          FROM [${database_name}].INFORMATION_SCHEMA.COLUMNS c
          WHERE c.TABLE_SCHEMA = '${sch}' AND c.TABLE_NAME = '${obj}'
          ORDER BY c.ORDINAL_POSITION
        `, 1000);
        if (rows.length === 0) {
          return err(`No columns visible for [${database_name}].[${schema}].[${object_name}] — it may not exist or your login may lack permission on it.`);
        }
        // Indexes (with key columns) — so the agent filters on a leading key for a seek.
        const idx = await queryInstance(instance_name, `
          SELECT i.name AS index_name, i.type_desc AS index_type, i.is_unique, i.is_primary_key,
                 STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS key_columns
          FROM [${database_name}].sys.indexes i
          JOIN [${database_name}].sys.objects o  ON o.object_id = i.object_id
          JOIN [${database_name}].sys.schemas s  ON s.schema_id = o.schema_id
          JOIN [${database_name}].sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
          JOIN [${database_name}].sys.columns c  ON c.object_id = ic.object_id AND c.column_id = ic.column_id
          WHERE s.name = '${sch}' AND o.name = '${obj}' AND i.type > 0
          GROUP BY i.name, i.type_desc, i.is_unique, i.is_primary_key
          ORDER BY i.is_primary_key DESC, i.is_unique DESC, i.name
        `, 200).catch(() => ({ rows: [] as Record<string, unknown>[] }));
        // Partition column + approximate row count (partition elimination is the cheap filter).
        const meta = await queryInstance(instance_name, `
          SELECT
            (SELECT CAST(ep.value AS nvarchar(4000)) FROM [${database_name}].sys.extended_properties ep
               WHERE ep.class = 1 AND ep.minor_id = 0 AND ep.name = 'MS_Description' AND ep.major_id = o.object_id) AS object_description,
            (SELECT c.name FROM [${database_name}].sys.indexes i2
               JOIN [${database_name}].sys.index_columns ic2 ON ic2.object_id=i2.object_id AND ic2.index_id=i2.index_id AND ic2.partition_ordinal > 0
               JOIN [${database_name}].sys.columns c ON c.object_id=ic2.object_id AND c.column_id=ic2.column_id
               WHERE i2.object_id = o.object_id AND i2.index_id IN (0,1)) AS partition_column,
            (SELECT SUM(CASE WHEN p.index_id IN (0,1) THEN p.rows ELSE 0 END) FROM [${database_name}].sys.partitions p WHERE p.object_id = o.object_id) AS approx_rows
          FROM [${database_name}].sys.objects o
          JOIN [${database_name}].sys.schemas s ON s.schema_id = o.schema_id
          WHERE s.name = '${sch}' AND o.name = '${obj}'
        `, 1).catch(() => ({ rows: [] as Record<string, unknown>[] }));
        const m = (meta.rows[0] ?? {}) as { partition_column?: unknown; approx_rows?: unknown; object_description?: unknown };
        return ok({
          database: database_name, schema, object: object_name,
          object_description: m.object_description ?? null,
          approx_rows: m.approx_rows ?? null,
          partition_column: m.partition_column ?? null,
          indexes: idx.rows,
          columns: rows,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // fan_out_query — run any T-SQL across all (or selected) instances in parallel
  // ============================================================
  roTool(server, 
    "fan_out_query",
    "Run the same read-only T-SQL SELECT across many SQL Server instances at once and return results keyed by instance name. " +
      "Use it to compare a metric across the fleet — e.g. pending message counts per region, wait stats, blocking. " +
      "Filter by region (region1/region2/region3/region4) and/or an explicit instance list. Only SELECT/WITH/DECLARE is allowed (writes and EXEC are rejected). " +
      "Failures on individual instances are returned as errors without cancelling the others. " +
      FLEET_TOPOLOGY + " " + DATA_MODEL_GUIDANCE,
    {
      query: z
        .string()
        .describe("Read-only T-SQL SELECT statement to execute on every targeted instance."),
      region: z
        .string()
        .optional()
        .describe("Limit to one region: sg, id, uk, or us. Omit for all regions."),
      instances: z
        .array(z.string())
        .optional()
        .describe(
          "Subset of instance names to query. Omit to query all (within the region filter if given). Call list_instances to see names."
        ),
      allow_large_scan: z
        .boolean()
        .optional()
        .default(false)
        .describe("Override the guardrail that blocks UNBOUNDED scans of large/critical tables (e.g. messageLog) — fanned out to EVERY instance, so use with care. Prefer the AppDb_Analytics aggregates."),
    },
    async ({ query: sql, region, instances: subset, allow_large_scan }) => {
      const check = validateQuery(sql, { allowLargeScan: allow_large_scan });
      if (!check.valid) return err(check.reason!);

      let targets = listInstances();
      if (region) targets = targets.filter((i) => (i.region ?? "").toLowerCase() === region.toLowerCase());
      if (subset?.length) targets = targets.filter((i) => subset.includes(i.name));

      if (targets.length === 0) {
        return err("No matching instances found. Call list_instances to see available names and regions.");
      }

      const settled = await Promise.allSettled(
        targets.map(async (inst) => {
          const { rows, truncated } = await queryInstance(inst.name, sql, 200);
          return { instance: inst.name, rows, truncated };
        })
      );

      const results: Record<string, unknown> = {};
      let failed = 0;
      for (let i = 0; i < settled.length; i++) {
        const r = settled[i];
        const name = targets[i].name;
        if (r.status === "fulfilled") {
          results[name] = { rows: r.value.rows, truncated: r.value.truncated };
        } else {
          results[name] = { error: r.reason instanceof Error ? r.reason.message : String(r.reason) };
          failed++;
        }
      }

      return ok({
        instances_queried: targets.length,
        instances_failed: failed,
        results,
      });
    }
  );

  // ============================================================
  // execute_query — free-form read-only T-SQL
  // ============================================================
  roTool(server, 
    "execute_query",
    "Execute a read-only T-SQL SELECT against any database on the target instance (call list_databases to see " +
      "what exists in that region — DB names differ across the primary region vs the secondary regions). Connections are read-only and default " +
      "to the regional NLB listener. Fully qualify cross-database reads as [Database].[schema].[table]. " +
      "Use this for ad-hoc analysis and custom JOINs/CTEs/CROSS APPLY the pre-built tools don't cover. " +
      "Only SELECT / WITH / DECLARE statements are allowed — every write, DDL, and DCL operation is rejected. " +
      "QUERY EFFICIENTLY: call describe_object first to see indexes + the partition column, then filter on a leading " +
      "index key or the partition column and add TOP; select only the columns you need (avoid SELECT * on wide/large " +
      "tables). Reads use READ UNCOMMITTED (no locks on prod) and results are row-capped. " +
      DATA_MODEL_GUIDANCE,
    { ...instanceParam,
      query: z
        .string()
        .describe(
          "T-SQL SELECT statement to execute. May include CTEs (WITH ...), CROSS APPLY, sub-queries, etc."
        ),
      allow_large_scan: z
        .boolean()
        .optional()
        .default(false)
        .describe("Override the guardrail that blocks UNBOUNDED scans of large/critical tables (e.g. messageLog). Prefer the AppDb_Analytics aggregates; only set true for a deliberate, scoped scan."),
    },
    async ({ instance_name, query: sql, allow_large_scan }) => {
      const check = validateQuery(sql, { allowLargeScan: allow_large_scan });
      if (!check.valid) return err(check.reason!);

      try {
        const { rows, truncated } = await queryInstance(instance_name, sql, 500);
        const note = truncated ? truncationNote(500) : "";
        return { content: [{ type: "text", text: toJson(rows) + note }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // execute_write — OPT-IN engineering writes (TOOLSET=eng-write only)
  // ============================================================
  if (WRITE_ENABLED) {
    (server as { tool: (...a: unknown[]) => unknown }).tool(
      "execute_write",
      "Run a single data-modifying statement (INSERT / UPDATE / DELETE / MERGE / EXEC of a stored procedure) " +
        "as YOUR OWN SQL login — SQL Server enforces exactly what your role permits, and anything outside it is " +
        "denied. DDL, GRANT/REVOKE, server/database settings, backups, SQL Agent jobs (msdb), dynamic SQL, and " +
        "unqualified UPDATE/DELETE are blocked. By default this is a DRY RUN: the statement runs inside a " +
        "transaction that is ROLLED BACK and the affected-row count is returned. Re-call with confirm:true to COMMIT.",
      {
        query: z.string().describe("A single INSERT/UPDATE/DELETE/MERGE statement, or EXEC of a stored procedure."),
        instance_name: z.string().optional().default(DEFAULT_INSTANCE).describe(`Target instance (writes route to the PRIMARY). Defaults to "${DEFAULT_INSTANCE}".`),
        confirm: z.boolean().optional().default(false).describe("false (default) = dry-run, rolled back. true = apply and COMMIT."),
        allow_unfiltered: z.boolean().optional().default(false).describe("Allow an UPDATE/DELETE that has no WHERE clause (affects every row). Default false."),
      },
      { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      async ({ query, instance_name, confirm, allow_unfiltered }: { query: string; instance_name: string; confirm?: boolean; allow_unfiltered?: boolean }) => {
        const check = validateWriteQuery(query, { allowUnfiltered: allow_unfiltered === true });
        if (!check.valid) return err(check.reason!);
        try {
          const r = await executeWrite(instance_name, query, confirm === true);
          return ok(confirm === true
            ? { mode: "APPLIED (committed)", instance: instance_name, rows_affected: r.rowsAffected, result: r.recordset.slice(0, 50) }
            : {
                mode: "DRY RUN (rolled back — nothing changed)",
                instance: instance_name,
                rows_that_would_change: r.rowsAffected,
                preview: r.recordset.slice(0, 20),
                note: "Re-call with confirm:true to apply. SQL Server enforced your login's permissions; a permission error here means your role does not allow this write.",
              });
        } catch (e: unknown) {
          return err(e instanceof Error ? e.message : String(e));
        }
      }
    );
  }

  // ============================================================
  // Schema-doc semantic layer (sql-documenter output).
  // Read-only, offline JSON lookups — no DB connection — so they are registered
  // for EVERY profile (ops/eng most of all: they help write correct SELECTs).
  // Disable with SCHEMA_DOCS_ENABLED=false on a deployment that ships no docs.
  // ============================================================
  if (process.env.SCHEMA_DOCS_ENABLED !== "false") {
    roTool(server,
      "list_schema_docs",
      "List the databases and schemas covered by the schema-doc semantic layer (generated by sql-documenter from the " +
        "appdb-*-db repos). Returns each documented database → its schemas, with full name, one-line purpose, " +
        "object counts, and access_profiles (which ops/eng roles can read the schema + how many objects). Call this " +
        "FIRST to discover what offline schema knowledge is available before writing SQL. In the ops/eng profiles, " +
        "use access_profiles to focus on the schemas your login can actually SELECT. Empty result means no docs are " +
        "bundled for this deployment.",
      {},
      async () => {
        const docs = listSchemaDocs();
        if (!docs.length) {
          return ok({ documented: [], note: `No schema docs found under ${docsRoot()}. Run the sync:docs script, or set SCHEMA_DOCS_DIR.` });
        }
        const byDb = new Map<string, Array<Record<string, unknown>>>();
        for (const d of docs) {
          if (!byDb.has(d.database)) byDb.set(d.database, []);
          byDb.get(d.database)!.push({ schema: d.schema, full_name: d.fullName, purpose: d.purpose, object_count: d.objectCount, access_profiles: d.accessProfiles ?? undefined });
        }
        return ok({
          source: docsRoot(),
          databases: [...byDb.entries()].map(([database, schemas]) => ({ database, schema_count: schemas.length, schemas })),
        });
      }
    );

    roTool(server,
      "describe_schema",
      "Get the documented OVERVIEW of one schema: its purpose, write/read data flow, key tables, dependencies on other " +
        "schemas, access roles, and any physical-layout notes (e.g. which SSDT project / database a table physically lives in). " +
        "Use this to understand what a schema is for and how data moves through it before drilling into individual objects. " +
        "database = the logical DB (e.g. AppDb, AppDb_Analytics — see list_schema_docs); schema = the schema name (e.g. bi, msg, core).",
      {
        database: z.string().describe("Logical database name as shown by list_schema_docs (e.g. 'AppDb_Analytics'). Case-insensitive."),
        schema: z.string().describe("Schema name within that database (e.g. 'msg'). Case-insensitive."),
      },
      async ({ database, schema }) => {
        const doc = describeSchema(database, schema);
        if (!doc) return err(`No overview doc for ${database}.${schema}. Call list_schema_docs to see what is documented.`);
        return ok(doc);
      }
    );

    roTool(server,
      "describe_doc_object",
      "Get the full documentation for ONE named object (table, view, function, synonym, or stored procedure) within a " +
        "documented schema. For a table/view: columns with types, nullability, descriptions, ENUM DECODINGS (e.g. " +
        "Status 0=Inactive/1=Active), primary key, foreign keys, indexes, and notes. For a procedure: parameters, a " +
        "realistic usage example, and which roles it is granted to. This is the offline equivalent of inspecting the " +
        "object — consult it before writing a query so you use the right columns and decode coded values correctly.",
      {
        database: z.string().describe("Logical database name (e.g. 'AppDb'). Case-insensitive."),
        schema: z.string().describe("Schema name (e.g. 'bi'). Case-insensitive."),
        name: z.string().describe("Object name to look up (table/view/function/synonym/procedure). Case-insensitive."),
      },
      async ({ database, schema, name }) => {
        const doc = describeDocObject(database, schema, name);
        if (!doc) return err(`No documented object named '${name}' in ${database}.${schema}. Try search_schema_docs to locate it.`);
        return ok(doc);
      }
    );

    roTool(server,
      "search_schema_docs",
      "Free-text search across ALL bundled schema docs to locate where a concept lives. Matches object names, " +
        "descriptions, column names, column descriptions, and enum decodings. Returns ranked hits as " +
        "{database, schema, objectType, object, matchedOn}. Use this when you know WHAT you want (e.g. 'conversion rate', " +
        "'sender id', 'wallet status') but not which database/schema/table holds it. Then call describe_doc_object on the hit.",
      {
        term: z.string().describe("Concept to search for, e.g. 'conversion rate', 'msisdn', 'delivery status'."),
        database: z.string().optional().describe("Optional: restrict the search to one logical database (e.g. 'AppDb_Analytics')."),
      },
      async ({ term, database }) => {
        const hits = searchSchemaDocs(term, database);
        return ok({ term, database: database ?? "(all)", hit_count: hits.length, hits });
      }
    );
  }

  // ── DMV / DBA tools below are registered only when TOOLSET=dba (default). ──
  // The app-data profiles (TOOLSET=ops/eng/eng-write) expose only the SELECT-only,
  // schema-aware tools above (list_instances, list_databases, list_tables,
  // describe_object, fan_out_query, execute_query) plus the schema-doc tools — no
  // DMVs. eng-write adds the single execute_write tool above; every other profile
  // stays strictly read-only.
  if (!DMV_TOOLS_ENABLED) return;

  // dbatools / PowerShell-backed health-check tools (DBA profile only). Disable
  // with DBATOOLS_ENABLED=false on hosts without PowerShell + dbatools installed.
  if (process.env.DBATOOLS_ENABLED !== "false") {
    registerDbatoolsTools(server);
  }

  // ============================================================
  // get_active_sessions
  // ============================================================

  // Step 1 (Task 4): the pre-existing DMV body, moved verbatim into a named function.
  // SQL unchanged — this is the default path (DBATOOLS_FIRST unset/0).
  async function activeSessionsViaDmv(instance_name: string, include_sleeping: boolean): Promise<ToolResult> {
    const sleepFilter = include_sleeping
      ? ""
      : "AND (r.session_id IS NOT NULL OR s.status NOT IN ('sleeping', 'dormant'))";

    try {
      const { rows, truncated } = await queryInstance(instance_name, `
        SELECT
          s.session_id,
          s.login_name,
          s.host_name,
          s.program_name,
          s.status                                        AS session_status,
          r.status                                        AS request_status,
          r.command,
          r.wait_type,
          r.wait_time                                     AS wait_ms,
          r.blocking_session_id,
          r.total_elapsed_time                            AS elapsed_ms,
          r.cpu_time                                      AS request_cpu_ms,
          s.cpu_time                                      AS session_cpu_ms,
          r.logical_reads                                 AS request_logical_reads,
          s.reads                                         AS session_reads,
          s.writes                                        AS session_writes,
          r.percent_complete,
          DB_NAME(r.database_id)                          AS database_name,
          r.statement_start_offset,
          SUBSTRING(
            t.text,
            (r.statement_start_offset / 2) + 1,
            ((CASE r.statement_end_offset
                WHEN -1 THEN DATALENGTH(t.text)
                ELSE r.statement_end_offset
              END - r.statement_start_offset) / 2) + 1
          )                                               AS current_statement,
          s.last_request_start_time,
          s.last_request_end_time
        FROM sys.dm_exec_sessions s
        LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
        OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
        WHERE s.is_user_process = 1
          ${sleepFilter}
        ORDER BY
          CASE WHEN r.blocking_session_id > 0 THEN 0 ELSE 1 END,
          COALESCE(r.total_elapsed_time, 0) DESC
      `);
      return ok({ sessions: rows, truncated });
    } catch (e: unknown) {
      return err(e instanceof Error ? e.message : String(e));
    }
  }

  // Step 2 (Task 4): the dbatools path — Get-DbaProcess (~36 properties unnarrowed; brief:
  // "consider select for it"). Narrowed at the source to the 15 fields verified present on a
  // live SQL 2022 CU14 probe: Spid, Login, Host, Database, Status, Command, Cpu, MemUsage,
  // BlockingSpid, IsSystem, Program, LastQuery, LoginTime, LastRequestStartTime,
  // ClientNetAddress — matches the task-4 brief's field list exactly.
  //
  // Get-DbaProcess has no direct equivalent of the DMV's `is_user_process = 1` filter — its
  // own -ExcludeSystemSpids switch was verified live to NOT drop the engine's background
  // worker spids (PARALLEL REDO TASK, LAZY WRITER, ...); the cmdlet's own `IsSystem` property
  // is what actually distinguishes them (verified: True for every background/system spid,
  // False for the one real user connection in the probe). So `is_user_process = 1` is
  // reproduced here as `!IsSystem`, and the DMV's "NOT sleeping/dormant unless it has an
  // active request" is reproduced as `Status` outside {sleeping, dormant} — filtered in JS
  // since the cmdlet has no server-side equivalent of either.
  //
  // Throws on failure (does NOT catch) so withFallback's catch sees the failure and falls
  // back to activeSessionsViaDmv.
  async function activeSessionsViaDbatools(instance_name: string, include_sleeping: boolean): Promise<ToolResult> {
    const cfg = await resolveDbaSqlInstance(instance_name);
    const rows = (await callDbatools(
      "Get-DbaProcess",
      { SqlInstance: dbaSqlInstanceArg(cfg) },
      undefined,
      [
        "Spid", "Login", "Host", "Database", "Status", "Command", "Cpu", "MemUsage",
        "BlockingSpid", "IsSystem", "Program", "LastQuery", "LoginTime",
        "LastRequestStartTime", "ClientNetAddress",
      ],
    )) as Array<Record<string, unknown>>;

    const filtered = rows.filter((r) => {
      if (r.IsSystem === true) return false;
      if (!include_sleeping) {
        const status = String(r.Status ?? "").toLowerCase();
        if (status === "sleeping" || status === "dormant") return false;
      }
      return true;
    });
    return ok({ sessions: filtered, truncated: false });
  }

  roTool(server,
    "get_active_sessions",
    "Get all active SQL Server sessions with current request details, CPU, blocking status, and current SQL text. Best starting point for performance investigations. Uses CROSS APPLY dm_exec_sql_text to fetch the actual query being run.",
    { ...instanceParam,
      include_sleeping: z
        .boolean()
        .optional()
        .default(false)
        .describe("Include sleeping/idle sessions (default: false — active requests only)"),
    },
    async ({ instance_name, include_sleeping }) =>
      withFallback(
        () => activeSessionsViaDbatools(instance_name, include_sleeping),
        () => activeSessionsViaDmv(instance_name, include_sleeping),
      )
  );

  // ============================================================
  // get_blocking_chains
  // ============================================================
  roTool(server, 
    "get_blocking_chains",
    "Show all current blocking chains — which sessions are blocked and which session is causing the blockage. Includes the SQL text of both the blocked and blocking session, wait time, and lock details. Returns a message if there is no blocking.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT
            r.session_id                                    AS blocked_session_id,
            r.blocking_session_id,
            r.wait_type,
            r.wait_time / 1000.0                            AS wait_seconds,
            r.status                                        AS blocked_status,
            r.command                                       AS blocked_command,
            DB_NAME(r.database_id)                          AS database_name,
            s_blocked.login_name                            AS blocked_login,
            s_blocked.host_name                             AS blocked_host,
            s_blocked.program_name                          AS blocked_program,
            SUBSTRING(
              t_blocked.text,
              (r.statement_start_offset / 2) + 1,
              ((CASE r.statement_end_offset
                  WHEN -1 THEN DATALENGTH(t_blocked.text)
                  ELSE r.statement_end_offset
                END - r.statement_start_offset) / 2) + 1
            )                                               AS blocked_statement,
            s_blocker.login_name                            AS blocker_login,
            s_blocker.host_name                             AS blocker_host,
            s_blocker.program_name                          AS blocker_program,
            t_blocker.text                                  AS blocker_sql_text,
            s_blocker.last_request_start_time               AS blocker_last_request_start
          FROM sys.dm_exec_requests r
          JOIN sys.dm_exec_sessions s_blocked
            ON r.session_id = s_blocked.session_id
          LEFT JOIN sys.dm_exec_sessions s_blocker
            ON r.blocking_session_id = s_blocker.session_id
          -- Use dm_exec_connections.most_recent_sql_handle so we can retrieve
          -- the blocker's SQL even when it is sleeping (not in dm_exec_requests).
          -- Source: Brent Ozar First Responder Kit (sp_Blitz.sql)
          LEFT JOIN sys.dm_exec_connections c_blocker
            ON r.blocking_session_id = c_blocker.session_id
          OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t_blocked
          OUTER APPLY sys.dm_exec_sql_text(c_blocker.most_recent_sql_handle) t_blocker
          WHERE r.blocking_session_id > 0
          ORDER BY wait_seconds DESC
        `);

        if (rows.length === 0) {
          return { content: [{ type: "text", text: "No blocking detected at this time." }] };
        }
        return ok({ blocking_chains: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_hiq — persisted "handling-impacting queries" history (DBA.dbo.HIQMonitor)
  // ============================================================
  roTool(server,
    "get_hiq",
    "Query the persisted Handling-Impacting Queries history (DBA.dbo.HIQMonitor) — a sp_WhoIsActive snapshot captured " +
      "~every minute and retained ~30 days PER NODE. This is the go-to for 'what was running on this server at <time>' / " +
      "post-incident review: long-running, blocked or blocking sessions, high CPU/reads/writes, open transactions, tempdb " +
      "use and waits — each row a point-in-time capture keyed on collection_time. Around an AV/crash window, run this for " +
      "the SAME window as read_error_log / read_sql_dump to see the workload at the moment of the dump (a witness, not " +
      "necessarily the cause — see evidence discipline), and generate_cluster_log for the cluster side. " +
      "Default window: last 60 minutes; pass start+end (e.g. start='2026-06-19 02:00', end='2026-06-19 02:30') for a " +
      "specific incident. ALERT WORKFLOW: for a 'DB Call Failures'/blocking/disaster alert, query the alert window with " +
      "blocking='blockers' to surface the LEAD blockers — the sessions holding locks others wait on (a classic cause is " +
      "partition management, e.g. a partition SWITCH/MERGE/TRUNCATE taking a schema/Sch-M lock); blocking='blocked' shows " +
      "the victims, 'any' the whole picture. THEN run get_query_store_regressions (+ get_top_queries) on the hot DB(s) " +
      "to catch plan-regression amplifiers behind the contention (discount single-execution, sub-ms-best regressions as " +
      "noise). sql_text is truncated to 1000 chars; set include_plan / include_locks for the " +
      "(large) XML (locks shows exactly which objects/HoBts are locked). Reads the DBA database.",
    { ...instanceParam,
      last_minutes: z.number().int().min(1).max(43200).optional().default(60).describe("Look-back window in minutes from now (default 60). Ignored when start+end are given."),
      start: z.string().optional().describe("Window start 'YYYY-MM-DD[ HH:MM[:SS]]' (server local time). Use WITH end for a specific incident window."),
      end: z.string().optional().describe("Window end 'YYYY-MM-DD[ HH:MM[:SS]]'."),
      blocking: z.enum(["all", "blocked", "blockers", "any"]).optional().default("all").describe("Filter by blocking role: 'all' (default); 'blocked' = waiting on a blocker; 'blockers' = LEAD blockers holding locks others wait on (e.g. partition mgmt) — best for a disaster/blocking alert; 'any' = either."),
      top_n: z.number().int().min(1).max(2000).optional().default(200).describe("Max rows, newest first (default 200)."),
      include_plan: z.boolean().optional().default(false).describe("Include the query_plan XML (large)."),
      include_locks: z.boolean().optional().default(false).describe("Include the locks XML (large)."),
    },
    async ({ instance_name, last_minutes, start, end, blocking, top_n, include_plan, include_locks }) => {
      const DT = /^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?)?$/;
      let windowClause: string;
      if (start || end) {
        if (!start || !end) return err("Provide BOTH start and end (or neither, to use last_minutes).");
        if (!DT.test(start) || !DT.test(end)) return err("start/end must be 'YYYY-MM-DD[ HH:MM[:SS]]'.");
        windowClause = `collection_time BETWEEN '${start.replace("T", " ")}' AND '${end.replace("T", " ")}'`;
      } else {
        windowClause = `collection_time >= DATEADD(MINUTE,-${Number(last_minutes) || 60},SYSDATETIME())`;
      }
      const n = Number(top_n) || 200;
      // blocked_session_count is a padded, comma-formatted varchar (sp_WhoIsActive) — strip commas before TRY_CONVERT.
      const blockClause =
        blocking === "blocked"  ? " AND blocking_session_id IS NOT NULL"
        : blocking === "blockers" ? " AND TRY_CONVERT(int, REPLACE(blocked_session_count, ',', '')) > 0"
        : blocking === "any"      ? " AND (blocking_session_id IS NOT NULL OR TRY_CONVERT(int, REPLACE(blocked_session_count, ',', '')) > 0)"
        : "";
      const extra = [
        include_plan ? "CAST(query_plan AS nvarchar(max)) AS query_plan" : "",
        include_locks ? "CAST(locks AS nvarchar(max)) AS locks" : "",
      ].filter(Boolean).join(",\n          ");
      const sqlText = `
        SELECT TOP (${n})
          CONVERT(varchar(23),collection_time,121) AS collection_time,
          CONVERT(varchar(23),start_time,121)      AS start_time,
          Duration, session_id, status, wait_info,
          blocking_session_id, blocked_session_count,
          CPU, reads, physical_reads, writes, tempdb_allocations, used_memory,
          open_tran_count, percent_complete,
          login_name, host_name, program_name, database_name,
          LEFT(CAST(sql_text AS nvarchar(max)),1000) AS sql_text${extra ? ",\n          " + extra : ""}
        FROM [DBA].[dbo].[HIQMonitor]
        WHERE ${windowClause}${blockClause}
        ORDER BY collection_time DESC`;
      try {
        const { rows, truncated } = await queryInstance(instance_name, sqlText, n);
        return ok({
          instance: instance_name,
          window: start && end ? `${start} .. ${end}` : `last ${last_minutes} min`,
          blocking,
          row_count: rows.length, truncated, rows,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_top_queries
  // ============================================================
  roTool(server, 
    "get_top_queries",
    "Get the most expensive queries from the plan cache ranked by a resource metric. Use to find the worst offenders for CPU, logical I/O, elapsed time, memory grants, or total executions since the last SQL Server restart.",
    { ...instanceParam,
      order_by: z
        .enum(["cpu", "reads", "writes", "elapsed", "memory", "executions"])
        .default("cpu")
        .describe("Metric to rank by: cpu (worker time), reads (logical reads), writes, elapsed, memory (grant KB), or executions"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(20)
        .describe("Number of queries to return (default 20, max 100)"),
    },
    async ({ instance_name, order_by, top_n }) => {
      const orderMap: Record<string, string> = {
        cpu:        "qs.total_worker_time DESC",
        reads:      "qs.total_logical_reads DESC",
        writes:     "qs.total_logical_writes DESC",
        elapsed:    "qs.total_elapsed_time DESC",
        memory:     "qs.total_grant_kb DESC",
        executions: "qs.execution_count DESC",
      };

      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT TOP (${top_n})
            qs.execution_count,
            qs.total_worker_time / 1000                     AS total_cpu_ms,
            qs.total_worker_time / qs.execution_count / 1000 AS avg_cpu_ms,
            qs.total_elapsed_time / 1000                    AS total_elapsed_ms,
            qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_ms,
            qs.total_logical_reads,
            qs.total_logical_reads / qs.execution_count     AS avg_logical_reads,
            qs.total_physical_reads,
            qs.total_logical_writes,
            COALESCE(qs.total_grant_kb, 0)                  AS total_grant_kb,
            COALESCE(qs.total_grant_kb / NULLIF(qs.execution_count, 0), 0) AS avg_grant_kb,
            COALESCE(qs.total_rows / NULLIF(qs.execution_count, 0), 0)     AS avg_rows,
            DB_NAME(t.dbid)                                 AS database_name,
            OBJECT_NAME(t.objectid, t.dbid)                 AS object_name,
            qs.creation_time,
            qs.last_execution_time,
            SUBSTRING(
              t.text,
              (qs.statement_start_offset / 2) + 1,
              ((CASE qs.statement_end_offset
                  WHEN -1 THEN DATALENGTH(t.text)
                  ELSE qs.statement_end_offset
                END - qs.statement_start_offset) / 2) + 1
            )                                               AS query_text
          FROM sys.dm_exec_query_stats qs
          OUTER APPLY sys.dm_exec_sql_text(qs.sql_handle) t
          WHERE t.text IS NOT NULL
          ORDER BY ${orderMap[order_by]}
        `);
        return ok({ top_queries: rows, ordered_by: order_by });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_wait_stats
  // ============================================================

  // Step 1 (Task 4): the pre-existing DMV body, moved verbatim into a named function.
  // SQL unchanged — this is the default path (DBATOOLS_FIRST unset/0).
  async function waitStatsViaDmv(instance_name: string, exclude_benign: boolean): Promise<ToolResult> {
    // Source: Brent Ozar First Responder Kit (sp_Blitz.sql, #IgnorableWaits)
    const benignList = [
      // Sleep / idle background tasks
      "SLEEP_TASK", "SLEEP_SYSTEMTASK", "SLEEP_DBSTARTUP", "SLEEP_DBTASK",
      "SLEEP_TEMPDBSTARTUP", "SLEEP_MASTERDBREADY", "SLEEP_MASTERMDREADY",
      "SLEEP_MASTERUPGRADED", "SLEEP_MSDBSTARTUP", "SLEEP_REPLICATION_MONITOR",
      // Service Broker background threads
      "BROKER_EVENTHANDLER", "BROKER_RECEIVE_WAITFOR", "BROKER_TASK_STOP",
      "BROKER_TO_FLUSH", "BROKER_TRANSMITTER",
      // Checkpoint / CLR
      "CHECKPOINT_QUEUE",
      "CLR_AUTO_EVENT", "CLR_MANUAL_EVENT", "CLR_SEMAPHORE",
      // Database mirroring background threads
      "DBMIRROR_DBM_EVENT", "DBMIRROR_DBM_MUTEX", "DBMIRROR_EVENTS_QUEUE",
      "DBMIRROR_WORKER_QUEUE", "DBMIRRORING_CMD",
      // Miscellaneous background
      "DIRTY_PAGE_POLL", "DISPATCHER_QUEUE_SEMAPHORE",
      // Full-text
      "FT_IFTS_SCHEDULER_IDLE_WAIT", "FT_IFTSHC_MUTEX",
      // Always On / HADR background threads
      "HADR_CLUSAPI_CALL", "HADR_FABRIC_CALLBACK",
      "HADR_FILESTREAM_IOMGR_IOCOMPLETION", "HADR_LOGCAPTURE_WAIT",
      "HADR_WORK_QUEUE",
      // Lazy writer, log manager
      "LAZYWRITER_SLEEP", "LOGMGR_QUEUE",
      // On-demand / task queue
      "ONDEMAND_TASK_QUEUE",
      // Parallel redo (AG / log apply threads)
      "PARALLEL_REDO_DRAIN_WORKER", "PARALLEL_REDO_LOG_CACHE",
      "PARALLEL_REDO_TRAN_LIST", "PARALLEL_REDO_TRAN_TURN",
      "PARALLEL_REDO_WORKER_SYNC", "PARALLEL_REDO_WORKER_WAIT_WORK",
      "POPULATE_LOCK_ORDINALS",
      // Preemptive OS / HADR
      "PREEMPTIVE_HADR_LEASE_MECHANISM", "PREEMPTIVE_OS_FLUSHFILEBUFFERS",
      "PREEMPTIVE_SP_SERVER_DIAGNOSTICS",
      // Persistent Version Store / extensibility
      "PVS_PREALLOCATE", "PWAIT_EXTENSIBILITY_CLEANUP_TASK",
      // Query Data Store background threads
      "QDS_ASYNC_QUEUE",
      "QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP",
      "QDS_PERSIST_TASK_MAIN_LOOP_SLEEP", "QDS_SHUTDOWN_QUEUE",
      // Redo / deadlock detection
      "REDO_THREAD_PENDING_WORK", "REQUEST_FOR_DEADLOCK_SEARCH",
      // Misc background
      "RESOURCE_QUEUE", "SERVER_IDLE_CHECK", "SNI_HTTP_ACCEPT",
      "SOS_WORK_DISPATCHER", "SP_SERVER_DIAGNOSTICS_SLEEP",
      // SQL Trace
      "SQLTRACE_BUFFER_FLUSH", "SQLTRACE_INCREMENTAL_FLUSH_SLEEP",
      // UCS / XTP
      "UCS_SESSION_REGISTRATION",
      "WAIT_XTP_OFFLINE_CKPT_NEW_LOG",
      // Explicit WAITFOR statements (application-level sleeps)
      "WAITFOR",
      // Extended Events background
      "XE_DISPATCHER_WAIT", "XE_LIVE_TARGET_TVF", "XE_TIMER_EVENT",
    ];

    const benignFilter = exclude_benign
      ? `AND wait_type NOT IN (${benignList.map((w) => `'${w}'`).join(", ")})`
      : "";

    try {
      const { rows } = await queryInstance(instance_name, `
        SELECT
          wait_type,
          waiting_tasks_count,
          wait_time_ms,
          max_wait_time_ms,
          signal_wait_time_ms,
          wait_time_ms - signal_wait_time_ms              AS resource_wait_time_ms,
          CAST(
            100.0 * wait_time_ms / NULLIF(SUM(wait_time_ms) OVER (), 0)
          AS DECIMAL(6, 2))                               AS pct_total
        FROM sys.dm_os_wait_stats
        WHERE wait_time_ms > 0
          ${benignFilter}
        ORDER BY wait_time_ms DESC
      `);
      return ok({ wait_stats: rows, benign_waits_excluded: exclude_benign });
    } catch (e: unknown) {
      return err(e instanceof Error ? e.message : String(e));
    }
  }

  // Step 2 (Task 4): the dbatools path — Get-DbaWaitStatistic. Fields verified on a live
  // SQL 2022 CU14 probe (this repo's own container): WaitType, Category, WaitSeconds,
  // ResourceSeconds, SignalSeconds, WaitCount, Percentage, AverageWaitSeconds, Ignorable,
  // URL, Notes — matches the task-4 brief's field list exactly.
  //
  // `Ignorable` is dbatools' OWN benign-wait classification — a different list than the
  // Brent Ozar #IgnorableWaits list the DMV path filters on above. Reusing dbatools' native
  // field instead of re-deriving/duplicating the DMV path's list in JS keeps this path
  // faithful to what the cmdlet itself considers benign. The two paths are therefore not
  // guaranteed to agree row-for-row on what exclude_benign drops — that divergence is the
  // known, expected gap DBATOOLS_FIRST exists to surface, not something to paper over.
  //
  // Throws on failure (does NOT catch) so withFallback's catch sees the failure and falls
  // back to waitStatsViaDmv.
  async function waitStatsViaDbatools(instance_name: string, exclude_benign: boolean): Promise<ToolResult> {
    const cfg = await resolveDbaSqlInstance(instance_name);
    const rows = (await callDbatools("Get-DbaWaitStatistic", {
      SqlInstance: dbaSqlInstanceArg(cfg),
    })) as Array<Record<string, unknown>>;
    const filtered = exclude_benign ? rows.filter((r) => r.Ignorable !== true) : rows;
    return ok({ wait_stats: filtered, benign_waits_excluded: exclude_benign });
  }

  roTool(server,
    "get_wait_stats",
    "Get cumulative wait statistics since the last SQL Server restart (or last DBCC SQLPERF('sys.dm_os_wait_stats', CLEAR)). Shows where SQL Server spends its time waiting. Key signals: PAGEIOLATCH_* = disk I/O pressure; LCK_* = lock contention; CXPACKET/CXCONSUMER = parallelism; SOS_SCHEDULER_YIELD = CPU pressure; RESOURCE_SEMAPHORE = memory grants.",
    { ...instanceParam,
      exclude_benign: z
        .boolean()
        .default(true)
        .describe("Exclude known idle/background waits to focus on actionable waits (default: true)"),
    },
    async ({ instance_name, exclude_benign }) =>
      withFallback(
        () => waitStatsViaDbatools(instance_name, exclude_benign),
        () => waitStatsViaDmv(instance_name, exclude_benign),
      )
  );

  // ============================================================
  // get_file_io_stats
  // ============================================================
  roTool(server, 
    "get_file_io_stats",
    "Get I/O statistics for all database files including average read and write latency. Latency thresholds: < 5 ms excellent, 5–20 ms good, 20–50 ms acceptable, > 50 ms concerning, > 100 ms critical. Also shows available free space on each volume.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT
            DB_NAME(f.database_id)                          AS database_name,
            f.file_id,
            f.name                                          AS logical_name,
            f.type_desc                                     AS file_type,
            f.physical_name,
            io.num_of_reads,
            io.num_of_bytes_read / 1048576                  AS mb_read,
            io.io_stall_read_ms,
            CASE WHEN io.num_of_reads > 0
                 THEN io.io_stall_read_ms / io.num_of_reads
                 ELSE 0 END                                 AS avg_read_latency_ms,
            io.num_of_writes,
            io.num_of_bytes_written / 1048576               AS mb_written,
            io.io_stall_write_ms,
            CASE WHEN io.num_of_writes > 0
                 THEN io.io_stall_write_ms / io.num_of_writes
                 ELSE 0 END                                 AS avg_write_latency_ms,
            io.io_stall,
            io.size_on_disk_bytes / 1048576                 AS size_on_disk_mb,
            v.volume_mount_point,
            v.available_bytes / 1073741824                  AS volume_available_gb,
            CAST(100.0 * v.available_bytes / v.total_bytes AS DECIMAL(5, 1)) AS volume_free_pct
          FROM sys.master_files f
          CROSS APPLY sys.dm_io_virtual_file_stats(f.database_id, f.file_id) io
          CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) v
          ORDER BY io.io_stall DESC
        `);
        return ok({ file_io_stats: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_cpu_history
  // ============================================================
  roTool(server, 
    "get_cpu_history",
    "Get SQL Server CPU utilization history from the ring buffer (last ~256 minutes, sampled every ~60 seconds). Shows sql_cpu_pct, system_idle_pct, and other_process_cpu_pct. Use to detect CPU spikes and determine if SQL Server or OS processes are the culprit.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT TOP 256
            ROW_NUMBER() OVER (ORDER BY r.timestamp DESC)   AS sample_num,
            DATEADD(
              ms,
              -1 * (
                sys_info.ms_ticks
                - CAST(r.timestamp AS BIGINT)
              ),
              GETDATE()
            )                                               AS approx_utc_time,
            r.record.value(
              '(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]',
              'int'
            )                                               AS sql_cpu_pct,
            r.record.value(
              '(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]',
              'int'
            )                                               AS system_idle_pct,
            -- On Linux, SystemIdle is always reported as 0 (the kernel does not
            -- populate it in the ring buffer).  In that case other_process_cpu_pct
            -- cannot be computed and is returned as NULL to avoid a misleading value.
            CASE WHEN r.record.value(
                   '(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]',
                   'int'
                 ) > 0
            THEN 100
                 - r.record.value(
                     '(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]',
                     'int'
                   )
                 - r.record.value(
                     '(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]',
                     'int'
                   )
            ELSE NULL
            END                                             AS other_process_cpu_pct
          FROM (
            SELECT
              timestamp,
              CAST(record AS XML) AS record
            FROM sys.dm_os_ring_buffers
            WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
              AND record LIKE '%<ProcessUtilization>%'
          ) r
          CROSS JOIN sys.dm_os_sys_info AS sys_info
          ORDER BY r.timestamp DESC
        `);
        return ok({ cpu_history: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_memory_usage
  // ============================================================
  roTool(server, 
    "get_memory_usage",
    "Get SQL Server memory breakdown: overall system memory availability, top memory consumers by clerk (MEMORYCLERK_SQLBUFFERPOOL = buffer pool, OBJECTSTORE_LOCK_MANAGER = lock memory, etc.), and query memory grant semaphore status (waiter_count > 0 means memory grant pressure).",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const [systemResult, clerksResult, semaphoresResult] = await Promise.all([
          queryInstance(instance_name, `
            SELECT
              total_physical_memory_kb / 1024     AS total_physical_mb,
              available_physical_memory_kb / 1024 AS available_physical_mb,
              total_page_file_kb / 1024           AS total_page_file_mb,
              available_page_file_kb / 1024       AS available_page_file_mb,
              system_memory_state_desc
            FROM sys.dm_os_sys_memory
          `),
          queryInstance(instance_name, `
            SELECT TOP 30
              type,
              name,
              pages_kb,
              virtual_memory_reserved_kb,
              virtual_memory_committed_kb,
              shared_memory_committed_kb
            FROM sys.dm_os_memory_clerks
            WHERE pages_kb > 0
            ORDER BY pages_kb DESC
          `),
          queryInstance(instance_name, `
            SELECT
              resource_semaphore_id,
              pool_id,
              target_memory_kb / 1024             AS target_memory_mb,
              available_memory_kb / 1024          AS available_memory_mb,
              granted_memory_kb / 1024            AS granted_memory_mb,
              used_memory_kb / 1024               AS used_memory_mb,
              grantee_count,
              waiter_count,
              timeout_error_count
            FROM sys.dm_exec_query_resource_semaphores
          `),
        ]);

        return ok({
          system_memory:       systemResult.rows,
          top_memory_clerks:   clerksResult.rows,
          resource_semaphores: semaphoresResult.rows,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_tempdb_usage
  // ============================================================
  roTool(server,
    "get_tempdb_usage",
    "Get TempDB space pressure: per-file space usage on tempdb (Get-DbaDbSpace — Database/FileName/FileGroup/PhysicalName/FileType/UsedSpace/FreeSpace/FileSize/PercentUsed/AutoGrowth/... as dbatools' native, human-formatted size strings, e.g. '1.17 GB', not raw MB) plus the sessions currently holding active TempDB allocations (Get-DbaTempdbUsage). Use when you see PAGELATCH_* waits or tempdb contention. Does NOT report a per-file internal-objects/user-objects/version-store MB breakdown — that split isn't available from either cmdlet.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const sqlInstance = dbaSqlInstanceArg(cfg);
        // Migrated to dbatools (Wave 2; restored per fix-round-1 R19). Get-DbaTempdbUsage
        // covers ACTIVE per-session allocations only — it has no per-file space data at all —
        // so this tool composes TWO cmdlets: Get-DbaDbSpace(-Database tempdb) for file_space,
        // Get-DbaTempdbUsage for top_sessions. Get-DbaDbSpace IS the dbatools equivalent for the
        // file_space half; it is not left unmigrated.
        //
        // Field-name note: Get-DbaDbSpace's size fields (UsedSpace/FreeSpace/FileSize/...) are
        // human-formatted Size strings (e.g. "72.00 MB", "1.17 GB" — verified live), not the old
        // DMV's raw numeric MB (total_mb/allocated_mb/free_mb). Renaming them to the old *_mb
        // names would misrepresent a formatted string as a plain number, so file_space rows keep
        // dbatools' native field names (Database, FileName, FileGroup, PhysicalName, FileType,
        // UsedSpace, FreeSpace, FileSize, PercentUsed, AutoGrowth, ...) instead of a lossy rename.
        // The old file_id, version_store_mb, user_objects_mb and internal_objects_mb columns have
        // NO counterpart on Get-DbaDbSpace at all — that per-file version-store/user-objects/
        // internal-objects breakdown isn't something this generic file-space cmdlet reports —
        // genuinely missing, not renamed to something else.
        const [fileRows, sessionRows] = await Promise.all([
          callDbatools("Get-DbaDbSpace", { SqlInstance: sqlInstance, Database: "tempdb" }) as Promise<Array<Record<string, unknown>>>,
          callDbatools("Get-DbaTempdbUsage", { SqlInstance: sqlInstance }) as Promise<Array<Record<string, unknown>>>,
        ]);
        return ok({
          file_space:   fileRows,
          top_sessions: sessionRows,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_database_info
  // ============================================================
  roTool(server,
    "get_database_info",
    "Get all SQL Server databases with state, recovery model, compatibility level, size, ownership, backup history, and log reuse wait reason. SizeMB (total database size) and SpaceAvailableMB (unallocated free space) are both reported in MEGABYTES — converted here from SMO's native units (Database.Size is MB, Database.SpaceAvailable is KB) so the two adjacent size columns can be compared directly. Use for capacity planning, identifying databases in SIMPLE recovery that should be FULL, or spotting databases not in a normal state.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        // Migrated to dbatools (Wave 2, Task 2). Get-DbaDatabase returns a full SMO object —
        // ~200 properties per database on a live probe, including nested collections (Tables,
        // Views, StoredProcedures, Triggers, Schemas, ...). Returning that verbatim would be an
        // enormous payload and would force the worker's ConvertTo-PlainRows flattening to walk
        // object graphs it should never touch. So this narrows at the SOURCE — a `select` list
        // passed down to callDbatools, applied server-side (Select-Object -Property, inside the
        // pwsh worker, before ConvertTo-PlainRows runs) — rather than fetching everything and
        // filtering in TypeScript after the fact, which would pay the flattening/serialization
        // cost the narrowing exists to avoid. Measured live (4 databases): 433,402 bytes wide
        // (all ~222 properties) vs 2,395 bytes narrowed to the select list below — see
        // task-2-report.md.
        //
        // All 19 fields below were confirmed present on a live SQL 2022 CU14 probe (this repo's
        // own container, not just the brief's claim) before being relied on here.
        const rows = (await callDbatools(
          "Get-DbaDatabase",
          { SqlInstance: dbaSqlInstanceArg(cfg) },
          undefined,
          [
            "Name", "Status", "RecoveryModel", "CompatibilityLevel", "Collation", "Owner", "CreateDate",
            "Size", "SpaceAvailable", "IsAccessible", "IsUpdateable", "ReadOnly", "LastBackupDate",
            "LastDifferentialBackupDate", "LastLogBackupDate", "LastGoodCheckDbTime",
            "AvailabilityGroupName", "AvailabilityDatabaseSynchronizationState", "LogReuseWaitStatus",
          ],
        )) as Array<Record<string, unknown>>;
        // See toDatabaseInfoRow: the pwsh worker's `select` only supports plain
        // Select-Object -Property names (no calculated/renamed properties), so the
        // KB->MB conversion + SizeMB/SpaceAvailableMB rename happens here in TS instead
        // of through that mechanism.
        const databases = rows.map(toDatabaseInfoRow);
        return ok({ databases });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_server_info
  // ============================================================
  roTool(server, 
    "get_server_info",
    "Get SQL Server instance details: version, edition, hardware (CPU count, physical memory), uptime, and key sp_configure settings (max server memory, MAXDOP, CTFP). Good first call to establish the environment before deeper investigation.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const sqlInstance = dbaSqlInstanceArg(cfg);
        // Migrated to dbatools (Task 5): server_properties now comes from Get-DbaInstanceProperty
        // (a Name/Value row per SERVERPROPERTY-equivalent fact, flattened into one object below)
        // plus Get-DbaBuild for the CU/build-currency facts neither Get-DbaInstanceProperty nor the
        // old SERVERPROPERTY query carried. key_configurations/system_info are unrelated DMVs
        // (sp_configure, dm_os_sys_info) — not part of this tool's dbatools mapping — left as-is.
        const [propRows, buildRows, configResult, sysInfoResult] = await Promise.all([
          callDbatools("Get-DbaInstanceProperty", { SqlInstance: sqlInstance }) as Promise<Array<Record<string, unknown>>>,
          callDbatools("Get-DbaBuild", { SqlInstance: sqlInstance }) as Promise<Array<Record<string, unknown>>>,
          queryInstance(instance_name, `
            SELECT
              name,
              CAST(value_in_use AS NVARCHAR(256)) AS current_value,
              description
            FROM sys.configurations
            WHERE name IN (
              'max server memory (MB)', 'min server memory (MB)',
              'max degree of parallelism', 'cost threshold for parallelism',
              'optimize for ad hoc workloads', 'max worker threads',
              'remote admin connections'
            )
            ORDER BY name
          `),
          queryInstance(instance_name, `
            SELECT
              cpu_count,
              hyperthread_ratio,
              cpu_count / hyperthread_ratio           AS physical_cpus,
              physical_memory_kb / 1024               AS physical_memory_mb,
              virtual_machine_type_desc,
              sqlserver_start_time,
              DATEDIFF(HOUR, sqlserver_start_time, GETDATE()) AS uptime_hours,
              committed_kb / 1024                     AS sql_committed_mb,
              committed_target_kb / 1024              AS sql_target_mb
            FROM sys.dm_os_sys_info
          `),
        ]);

        // Get-DbaInstanceProperty returns one Name/Value row per fact; flatten to a single
        // object so callers get back the same "one row of server properties" shape as before.
        const properties: Record<string, unknown> = {};
        for (const r of propRows) properties[String(r.Name)] = r.Value;

        return ok({
          server_properties:  [{ ...properties, ...(buildRows[0] ?? {}) }],
          key_configurations: configResult.rows,
          system_info:        sysInfoResult.rows,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_missing_indexes
  // ============================================================
  roTool(server, 
    "get_missing_indexes",
    "Get missing index recommendations from the query optimizer. impact_score = user_seeks × avg_user_impact. High impact_score with many seeks = strong candidate. The suggested_create_index column contains a ready-to-use CREATE INDEX statement. Always test index additions in a non-production environment first.",
    { ...instanceParam,
      min_impact: z
        .number()
        .min(0)
        .max(100)
        .default(50)
        .describe("Minimum avg_user_impact % threshold (default 50)"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(50)
        .default(20)
        .describe("Number of recommendations to return (default 20)"),
    },
    async ({ instance_name, min_impact, top_n }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT TOP (${top_n})
            DB_NAME(mid.database_id)                        AS database_name,
            OBJECT_NAME(mid.object_id, mid.database_id)     AS table_name,
            mid.equality_columns,
            mid.inequality_columns,
            mid.included_columns,
            migs.unique_compiles,
            migs.user_seeks,
            migs.user_scans,
            migs.last_user_seek,
            migs.last_user_scan,
            CAST(migs.avg_user_impact AS DECIMAL(5, 1))     AS avg_user_impact_pct,
            CAST(migs.avg_total_user_cost AS DECIMAL(18, 4)) AS avg_total_user_cost,
            -- Source: Brent Ozar First Responder Kit (sp_BlitzIndex.sql), "magic_benefit_number"
            CAST(migs.user_seeks * migs.avg_total_user_cost * (migs.avg_user_impact / 100.0) AS DECIMAL(18, 2)) AS impact_score,
            'CREATE INDEX [IX_'
              + OBJECT_NAME(mid.object_id, mid.database_id)
              + '_missing_'
              + CAST(mig.index_group_handle AS VARCHAR(20))
              + '] ON '
              + mid.statement
              + ' ('
              + ISNULL(mid.equality_columns, '')
              + CASE
                  WHEN mid.equality_columns IS NOT NULL
                   AND mid.inequality_columns IS NOT NULL THEN ','
                  ELSE ''
                END
              + ISNULL(mid.inequality_columns, '')
              + ')'
              + ISNULL(' INCLUDE (' + mid.included_columns + ')', '')
                                                            AS suggested_create_index
          FROM sys.dm_db_missing_index_groups mig
          JOIN sys.dm_db_missing_index_group_stats migs
            ON mig.index_group_handle = migs.group_handle
          JOIN sys.dm_db_missing_index_details mid
            ON mig.index_handle = mid.index_handle
          WHERE migs.avg_user_impact >= ${min_impact}
          ORDER BY impact_score DESC
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No missing index recommendations with avg_user_impact >= ${min_impact}%.`,
              },
            ],
          };
        }
        return ok({ missing_indexes: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_index_usage_stats
  // NOT MIGRATED (Task 5): no dbatools equivalent verified — stays on the DMV query below.
  // ============================================================
  roTool(server,
    "get_index_usage_stats",
    "Get index usage statistics (seeks, scans, lookups, updates) since the last SQL Server restart. Use to find unused indexes (high updates, zero reads = write overhead with no read benefit — candidates for removal) and heavily-scanned indexes (candidates for covering index improvements).",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .describe("Filter to a specific database name (default: all user databases)"),
      include_unused: z
        .boolean()
        .default(true)
        .describe("Include indexes with zero reads — shows unused index candidates (default: true)"),
    },
    async ({ instance_name, database_name, include_unused }) => {
      if (database_name && !IDENT_RE.test(database_name)) return err(`Invalid database_name: ${database_name}`);
      // sys.indexes is a per-database catalog view. From master context it only returns
      // master's indexes; any user-DB rows in dm_db_index_usage_stats either get dropped
      // (no matching object_id in master) or return wrong index metadata (accidental
      // object_id collision). Fix: execute per-database via sp_executesql so sys.indexes
      // resolves in the correct DB context.
      const dbWhere = database_name
        ? `WHERE name = N'${database_name.replace(/'/g, "''")}' AND state = 0`
        : "WHERE database_id > 4 AND state = 0 AND is_read_only = 0";
      const usageFilter = include_unused
        ? ""
        : "AND (ius.user_seeks + ius.user_scans + ius.user_lookups) > 0";

      try {
        const { rows, truncated } = await queryInstance(instance_name, `
          IF OBJECT_ID('tempdb..#idx_usage') IS NOT NULL DROP TABLE #idx_usage;
          CREATE TABLE #idx_usage (
            database_name    NVARCHAR(128),
            table_name       NVARCHAR(256),
            index_name       NVARCHAR(256),
            index_type       NVARCHAR(60),
            user_seeks       BIGINT,
            user_scans       BIGINT,
            user_lookups     BIGINT,
            user_updates     BIGINT,
            total_reads      BIGINT,
            last_user_seek   DATETIME,
            last_user_scan   DATETIME,
            last_user_lookup DATETIME,
            last_user_update DATETIME,
            status           NVARCHAR(20)
          );

          DECLARE @db        NVARCHAR(128);
          DECLARE @inner_sql NVARCHAR(MAX) = N'
            INSERT INTO #idx_usage
            SELECT
              DB_NAME()                           AS database_name,
              OBJECT_NAME(ius.object_id)          AS table_name,
              i.name                              AS index_name,
              i.type_desc                         AS index_type,
              ius.user_seeks,
              ius.user_scans,
              ius.user_lookups,
              ius.user_updates,
              ius.user_seeks + ius.user_scans
                + ius.user_lookups               AS total_reads,
              ius.last_user_seek,
              ius.last_user_scan,
              ius.last_user_lookup,
              ius.last_user_update,
              CASE
                WHEN ius.user_updates > 0
                 AND (ius.user_seeks + ius.user_scans + ius.user_lookups) = 0
                THEN ''UNUSED_INDEX''
                ELSE ''USED''
              END                                AS status
            FROM sys.dm_db_index_usage_stats ius
            JOIN sys.indexes i
              ON ius.object_id = i.object_id
             AND ius.index_id  = i.index_id
            WHERE ius.database_id = DB_ID()
              AND i.name IS NOT NULL
              ${usageFilter}';

          DECLARE db_cur CURSOR LOCAL FAST_FORWARD FOR
            SELECT name FROM sys.databases ${dbWhere};
          OPEN db_cur;
          FETCH NEXT FROM db_cur INTO @db;
          WHILE @@FETCH_STATUS = 0
          BEGIN
            DECLARE @full_sql NVARCHAR(MAX) = N'USE [' + @db + N']; ' + @inner_sql;
            BEGIN TRY
              EXEC sp_executesql @full_sql;
            END TRY
            BEGIN CATCH
              -- Skip inaccessible databases
            END CATCH;
            FETCH NEXT FROM db_cur INTO @db;
          END;
          CLOSE db_cur; DEALLOCATE db_cur;

          SELECT * FROM #idx_usage
          ORDER BY
            CASE WHEN (user_seeks + user_scans + user_lookups) = 0 THEN 0 ELSE 1 END,
            user_updates DESC;
          DROP TABLE #idx_usage;
        `, 1000);
        const note = truncated ? truncationNote(1000) : "";
        return { content: [{ type: "text", text: toJson({ index_usage_stats: rows }) + note }] };
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_database_files
  // ============================================================
  roTool(server, 
    "get_database_files",
    "Get detailed information about all database files (data and log) including size, growth settings, physical location, and space usage. Use for capacity planning, identifying autogrow/shrink settings that need tuning, or finding files on slow storage.",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .describe("Filter to a specific database name (default: all databases)"),
    },
    async ({ instance_name, database_name }) => {
      if (database_name && !IDENT_RE.test(database_name)) return err(`Invalid database_name: ${database_name}`);

      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const params: Record<string, unknown> = { SqlInstance: dbaSqlInstanceArg(cfg) };
        if (database_name) params.Database = database_name;
        const rows = await callDbatools("Get-DbaDbFile", params);
        return ok({ database_files: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_query_store_regressions
  // NOT MIGRATED (Task 5): no dbatools equivalent verified — stays on the DMV query below.
  // ============================================================
  roTool(server,
    "get_query_store_regressions",
    "Get queries with plan regressions detected by Query Store (queries where a plan change caused performance degradation). Only works if Query Store is enabled on the database. Shows queries with forced plans, multiple plans per query, and significant performance differences between plans. DEFAULT TROUBLESHOOTING: on a DB-call-failure / blocking / contention alert, run this as a standard step alongside get_hiq (and get_top_queries) on the hot DB(s) — on the primary region that is AppDb_Data AND AppCatalog. DISCIPLINE: a huge regression_pct with recent_plan_executions=1 and a sub-millisecond best plan is usually one-off parameter-sniffing noise — prioritise regressions that executed IN the alert window with high execution count and high absolute reads/CPU, cross-check the HIQ lead blockers, then sp_query_store_force_plan the best_plan_id as a reversible interim fix.",
    { ...instanceParam,
      database_name: z
        .string()
        .describe("Database name to query (Query Store is per-database)"),
      min_regression_pct: z
        .number()
        .min(0)
        .default(50)
        .describe("Minimum performance regression % to report (default: 50%)"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(50)
        .default(20)
        .describe("Number of regressions to return (default: 20)"),
    },
    async ({ instance_name, database_name, min_regression_pct, top_n }) => {
      try {
        assertIdentifier(database_name, "database_name");
        const { rows } = await queryInstance(instance_name, `
          USE [${database_name}];
          
          WITH PlanStats AS (
            SELECT
              q.query_id,
              q.object_id,
              qp.plan_id,
              qp.is_forced_plan,
              TRY_CAST(qp.query_plan AS XML)              AS query_plan_xml,
              rs.last_execution_time,
              rs.count_executions,
              rs.avg_duration / 1000.0                    AS avg_duration_ms,
              rs.avg_cpu_time / 1000.0                    AS avg_cpu_ms,
              rs.avg_logical_io_reads,
              ROW_NUMBER() OVER (
                PARTITION BY q.query_id
                ORDER BY rs.last_execution_time DESC
              )                                           AS plan_recency_rank,
              ROW_NUMBER() OVER (
                PARTITION BY q.query_id
                ORDER BY rs.avg_duration DESC
              )                                           AS plan_slowest_rank
            FROM sys.query_store_query q
            JOIN sys.query_store_plan qp ON q.query_id = qp.query_id
            JOIN sys.query_store_runtime_stats rs ON qp.plan_id = rs.plan_id
            WHERE rs.last_execution_time >= DATEADD(DAY, -7, GETDATE())
          ),
          Regressions AS (
            SELECT
              recent.query_id,
              recent.plan_id                              AS recent_plan_id,
              recent.is_forced_plan,
              recent.last_execution_time                  AS recent_last_exec,
              recent.avg_duration_ms                      AS recent_avg_duration_ms,
              recent.avg_cpu_ms                           AS recent_avg_cpu_ms,
              best.plan_id                                AS best_plan_id,
              best.avg_duration_ms                        AS best_avg_duration_ms,
              best.avg_cpu_ms                             AS best_avg_cpu_ms,
              CAST(
                100.0 * (recent.avg_duration_ms - best.avg_duration_ms)
                / NULLIF(best.avg_duration_ms, 0)
              AS DECIMAL(10, 1))                          AS regression_pct,
              recent.count_executions,
              recent.avg_logical_io_reads
            FROM PlanStats recent
            CROSS APPLY (
              SELECT TOP 1 *
              FROM PlanStats best
              WHERE best.query_id = recent.query_id
                AND best.plan_id <> recent.plan_id
              ORDER BY best.avg_duration_ms ASC
            ) best
            WHERE recent.plan_recency_rank = 1
              AND recent.avg_duration_ms > best.avg_duration_ms * (1 + ${min_regression_pct} / 100.0)
          )
          SELECT TOP (${top_n})
            r.query_id,
            OBJECT_NAME(q.object_id)                      AS object_name,
            qt.query_sql_text,
            r.recent_plan_id,
            r.best_plan_id,
            r.regression_pct,
            r.recent_avg_duration_ms,
            r.best_avg_duration_ms,
            r.recent_avg_cpu_ms,
            r.best_avg_cpu_ms,
            r.avg_logical_io_reads,
            r.count_executions                            AS recent_plan_executions,
            r.is_forced_plan,
            r.recent_last_exec,
            q.is_internal_query
          FROM Regressions r
          JOIN sys.query_store_query q ON r.query_id = q.query_id
          JOIN sys.query_store_query_text qt ON q.query_text_id = qt.query_text_id
          ORDER BY r.regression_pct DESC;
          USE master;
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No Query Store regressions found in database '${database_name}' with >= ${min_regression_pct}% degradation. Either Query Store is disabled, or there are no significant regressions in the last 7 days.`,
              },
            ],
          };
        }
        return ok({ query_store_regressions: rows, database: database_name });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_plan_cache_pollution
  // NOT MIGRATED (Task 5): no dbatools equivalent verified — stays on the DMV query below.
  // ============================================================
  roTool(server,
    "get_plan_cache_pollution",
    "Identify plan cache pollution: single-use plans that waste memory, and queries with high execution time variance (parameter sniffing candidates). Single-use plans indicate missing parameterization or ad-hoc queries. High variance (max_elapsed >> min_elapsed) suggests plan reuse with bad parameter values.",
    { ...instanceParam,
      analysis_type: z
        .enum(["single_use", "high_variance", "both"])
        .default("both")
        .describe("Type of pollution to analyze: single_use plans, high_variance queries, or both"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(30)
        .describe("Number of results to return per category (default: 30)"),
    },
    async ({ instance_name, analysis_type, top_n }) => {
      try {
        const results: Record<string, unknown> = {};

        if (analysis_type === "single_use" || analysis_type === "both") {
          const { rows: singleUse } = await queryInstance(instance_name, `
            SELECT TOP (${top_n})
              DB_NAME(t.dbid)                             AS database_name,
              OBJECT_NAME(t.objectid, t.dbid)             AS object_name,
              cp.size_in_bytes / 1024                     AS plan_size_kb,
              qs.creation_time,
              SUBSTRING(
                t.text,
                (qs.statement_start_offset / 2) + 1,
                ((CASE qs.statement_end_offset
                    WHEN -1 THEN DATALENGTH(t.text)
                    ELSE qs.statement_end_offset
                  END - qs.statement_start_offset) / 2) + 1
              )                                           AS query_text
            FROM sys.dm_exec_cached_plans cp
            JOIN sys.dm_exec_query_stats qs ON cp.plan_handle = qs.plan_handle
            OUTER APPLY sys.dm_exec_sql_text(qs.sql_handle) t
            WHERE cp.usecounts = 1
              AND cp.objtype = 'Adhoc'
            ORDER BY cp.size_in_bytes DESC
          `);
          results.single_use_plans = singleUse;
        }

        if (analysis_type === "high_variance" || analysis_type === "both") {
          const { rows: highVariance } = await queryInstance(instance_name, `
            SELECT TOP (${top_n})
              DB_NAME(t.dbid)                             AS database_name,
              OBJECT_NAME(t.objectid, t.dbid)             AS object_name,
              qs.execution_count,
              qs.min_elapsed_time / 1000                  AS min_elapsed_ms,
              qs.max_elapsed_time / 1000                  AS max_elapsed_ms,
              (qs.max_elapsed_time - qs.min_elapsed_time) / 1000 AS elapsed_variance_ms,
              CAST(
                CASE WHEN qs.min_elapsed_time > 0
                  THEN CAST(qs.max_elapsed_time AS FLOAT) / qs.min_elapsed_time
                  ELSE 0
                END
              AS DECIMAL(10, 1))                          AS variance_ratio,
              qs.total_worker_time / 1000                 AS total_cpu_ms,
              qs.total_logical_reads,
              qs.last_execution_time,
              qs.creation_time,
              SUBSTRING(
                t.text,
                (qs.statement_start_offset / 2) + 1,
                ((CASE qs.statement_end_offset
                    WHEN -1 THEN DATALENGTH(t.text)
                    ELSE qs.statement_end_offset
                  END - qs.statement_start_offset) / 2) + 1
              )                                           AS query_text
            FROM sys.dm_exec_query_stats qs
            OUTER APPLY sys.dm_exec_sql_text(qs.sql_handle) t
            WHERE qs.execution_count >= 10
              AND qs.min_elapsed_time > 0
              -- Source: Brent Ozar First Responder Kit (sp_BlitzCache.sql), parameter sniffing detection
              AND qs.max_elapsed_time >= 1000
              AND CAST(qs.max_elapsed_time AS FLOAT) / qs.min_elapsed_time >= 10
            ORDER BY
              (qs.max_elapsed_time - qs.min_elapsed_time) * qs.execution_count DESC
          `);
          results.high_variance_queries = highVariance;
        }

        return ok(results);
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_long_running_transactions
  // ============================================================
  roTool(server, 
    "get_long_running_transactions",
    "Get long-running open transactions. Open transactions hold locks, prevent log truncation, and can cause blocking cascades. Critical for troubleshooting production incidents. Shows transaction age, log bytes used, lock count, and current SQL text.",
    { ...instanceParam,
      min_duration_seconds: z
        .number()
        .min(0)
        .default(60)
        .describe("Minimum transaction duration in seconds to report (default: 60)"),
    },
    async ({ instance_name, min_duration_seconds }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT
            st.session_id,
            s.login_name,
            s.host_name,
            s.program_name,
            DB_NAME(sdt.database_id)                      AS database_name,
            at.transaction_id,
            at.name                                       AS transaction_name,
            at.transaction_begin_time,
            DATEDIFF(SECOND, at.transaction_begin_time, GETDATE()) AS duration_seconds,
            CASE at.transaction_type
              WHEN 1 THEN 'Read/write'
              WHEN 2 THEN 'Read-only'
              WHEN 3 THEN 'System'
              WHEN 4 THEN 'Distributed'
              ELSE 'Unknown'
            END                                           AS transaction_type,
            CASE at.transaction_state
              WHEN 0 THEN 'Not initialized'
              WHEN 1 THEN 'Initialized, not started'
              WHEN 2 THEN 'Active'
              WHEN 3 THEN 'Read-only ended'
              WHEN 4 THEN 'Distributed - prepared'
              WHEN 5 THEN 'Distributed - committed'
              WHEN 6 THEN 'Committed'
              WHEN 7 THEN 'Rolling back'
              WHEN 8 THEN 'Rolled back'
              ELSE 'Unknown'
            END                                           AS transaction_state,
            sdt.database_transaction_log_bytes_used / 1048576 AS log_mb_used,
            sdt.database_transaction_log_bytes_reserved / 1048576 AS log_mb_reserved,
            (SELECT COUNT(*)
             FROM sys.dm_tran_locks tl
             WHERE tl.request_session_id = st.session_id
            )                                             AS locks_held,
            r.command,
            r.status                                      AS request_status,
            r.wait_type,
            r.blocking_session_id,
            SUBSTRING(
              sqlt.text,
              (r.statement_start_offset / 2) + 1,
              ((CASE r.statement_end_offset
                  WHEN -1 THEN DATALENGTH(sqlt.text)
                  ELSE r.statement_end_offset
                END - r.statement_start_offset) / 2) + 1
            )                                             AS current_statement
          FROM sys.dm_tran_active_transactions at
          JOIN sys.dm_tran_session_transactions st ON at.transaction_id = st.transaction_id
          JOIN sys.dm_exec_sessions s ON st.session_id = s.session_id
          LEFT JOIN sys.dm_tran_database_transactions sdt
            ON at.transaction_id = sdt.transaction_id
          LEFT JOIN sys.dm_exec_requests r ON st.session_id = r.session_id
          OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) sqlt
          WHERE DATEDIFF(SECOND, at.transaction_begin_time, GETDATE()) >= ${min_duration_seconds}
            AND s.is_user_process = 1
          ORDER BY duration_seconds DESC
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No transactions running longer than ${min_duration_seconds} seconds.`,
              },
            ],
          };
        }
        return ok({ long_running_transactions: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_deadlock_history
  // ============================================================
  roTool(server, 
    "get_deadlock_history",
    "Get recent deadlock history from the system_health Extended Events ring buffer. Returns parsed deadlock XML including victim query, deadlock graph, resources involved, and timestamps. No trace flags or profiler required.",
    { ...instanceParam,
      max_deadlocks: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of recent deadlocks to return (default: 20)"),
    },
    async ({ instance_name, max_deadlocks }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          WITH DeadlockData AS (
            SELECT
              CAST(target_data AS XML)                    AS target_data_xml
            FROM sys.dm_xe_session_targets xet
            JOIN sys.dm_xe_sessions xes
              ON xes.address = xet.event_session_address
            WHERE xes.name = 'system_health'
              AND xet.target_name = 'ring_buffer'
          ),
          DeadlockEvents AS (
            SELECT
              event_data.value('(@timestamp)[1]', 'datetime2') AS event_timestamp,
              CAST(event_data.query('.') AS NVARCHAR(MAX)) AS deadlock_xml
            FROM DeadlockData
            CROSS APPLY target_data_xml.nodes('//RingBufferTarget/event[@name="xml_deadlock_report"]') AS t(event_data)
          )
          SELECT TOP (${max_deadlocks})
            event_timestamp,
            deadlock_xml
          FROM DeadlockEvents
          ORDER BY event_timestamp DESC
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: "No deadlocks found in the system_health ring buffer. The buffer may have wrapped or there have been no recent deadlocks.",
              },
            ],
          };
        }
        return ok({ deadlock_history: rows, note: "Parse deadlock_xml for detailed victim/process/resource information" });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_latch_stats
  // ============================================================

  // Step 1 (Task 4): the pre-existing DMV body, moved verbatim into a named function.
  // SQL unchanged — this is the default path (DBATOOLS_FIRST unset/0).
  async function latchStatsViaDmv(instance_name: string, exclude_zero_waits: boolean, top_n: number): Promise<ToolResult> {
    const zeroFilter = exclude_zero_waits ? "WHERE waiting_requests_count > 0" : "";

    try {
      const { rows } = await queryInstance(instance_name, `
        SELECT TOP (${top_n})
          latch_class,
          waiting_requests_count,
          wait_time_ms,
          max_wait_time_ms,
          CASE WHEN waiting_requests_count > 0
               THEN wait_time_ms / waiting_requests_count
               ELSE 0
          END                                           AS avg_wait_time_ms
        FROM sys.dm_os_latch_stats
        ${zeroFilter}
        ORDER BY wait_time_ms DESC
      `);

      if (rows.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: "No latch waits detected (all classes have zero wait time).",
            },
          ],
        };
      }
      return ok({ latch_stats: rows });
    } catch (e: unknown) {
      return err(e instanceof Error ? e.message : String(e));
    }
  }

  // Step 2 (Task 4): the dbatools path — Get-DbaLatchStatistic. Fields verified on a live
  // SQL 2022 CU14 probe: WaitType, WaitSeconds, WaitCount, Percentage, AverageWaitSeconds,
  // URL — matches the task-4 brief's field list exactly. The cmdlet has no -Top/zero-wait
  // filter of its own, so exclude_zero_waits/top_n are applied here in JS to match the DMV
  // path's semantics (ORDER BY wait_time_ms DESC → WaitSeconds descending).
  //
  // Throws on failure (does NOT catch) so withFallback's catch sees the failure and falls
  // back to latchStatsViaDmv.
  async function latchStatsViaDbatools(instance_name: string, exclude_zero_waits: boolean, top_n: number): Promise<ToolResult> {
    const cfg = await resolveDbaSqlInstance(instance_name);
    const rows = (await callDbatools("Get-DbaLatchStatistic", {
      SqlInstance: dbaSqlInstanceArg(cfg),
    })) as Array<Record<string, unknown>>;
    const filtered = (exclude_zero_waits ? rows.filter((r) => Number(r.WaitCount) > 0) : rows)
      .sort((a, b) => Number(b.WaitSeconds) - Number(a.WaitSeconds))
      .slice(0, top_n);

    if (filtered.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "No latch waits detected (all classes have zero wait time).",
          },
        ],
      };
    }
    return ok({ latch_stats: filtered });
  }

  roTool(server,
    "get_latch_stats",
    "Get latch wait statistics by class. Latches are lightweight internal synchronization primitives. Key signals: PAGEIOLATCH_* = physical I/O waits (should be near-zero on flash storage); PAGELATCH_* = in-memory page contention (e.g., hot last-page inserts on identity PKs, allocation contention). High PAGELATCH_EX on non-flash is often tempdb or allocation.",
    { ...instanceParam,
      exclude_zero_waits: z
        .boolean()
        .default(true)
        .describe("Exclude latch classes with zero waits (default: true)"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(30)
        .describe("Number of latch classes to return (default: 30)"),
    },
    async ({ instance_name, exclude_zero_waits, top_n }) =>
      withFallback(
        () => latchStatsViaDbatools(instance_name, exclude_zero_waits, top_n),
        () => latchStatsViaDmv(instance_name, exclude_zero_waits, top_n),
      )
  );

  // ============================================================
  // get_ag_health
  // ============================================================
  roTool(server, 
    "get_ag_health",
    "Get Always On Availability Group health: replica sync state, send/redo queue size, estimated data loss/recovery time, failover readiness. Only returns data if AG is configured. Key metrics: synchronization_health (HEALTHY vs PARTIALLY_HEALTHY), redo_queue_size (backlog on secondary), estimated_data_loss_time. This is the LOCAL (within-region) AG; for CROSS-REGION replication (the primary region→the secondary regions of AppCatalog & AppDb_Routing) use get_distributed_ag_health.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const sqlInstance = dbaSqlInstanceArg(cfg);
        const [ags, replicas] = await Promise.all([
          callDbatools("Get-DbaAvailabilityGroup", { SqlInstance: sqlInstance }) as Promise<Array<Record<string, unknown>>>,
          callDbatools("Get-DbaAgReplica", { SqlInstance: sqlInstance }) as Promise<Array<Record<string, unknown>>>,
        ]);

        if (replicas.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: "No Always On Availability Groups configured on this instance.",
              },
            ],
          };
        }
        // Get-DbaAgReplica is per-replica (AvailabilityGroup, Replica, Role,
        // RollupSynchronizationState, ...); enrich each row with the AG-level facts
        // (ClusterType, PrimaryReplica) that only Get-DbaAvailabilityGroup carries.
        const agByName = new Map(ags.map((a) => [String(a.AvailabilityGroup), a]));
        const merged = replicas.map((r) => {
          const ag = agByName.get(String(r.AvailabilityGroup));
          return { ...r, ClusterType: ag?.ClusterType, PrimaryReplica: ag?.PrimaryReplica };
        });
        return ok({ ag_health: merged });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_distributed_ag_health — cross-region replication (distributed AGs)
  // ============================================================
  roTool(server,
    "get_distributed_ag_health",
    "Get DISTRIBUTED Availability Group health — i.e. CROSS-REGION replication from the global primary to the other regions. " +
      "Run this on the global primary. Only the databases you enrol replicate cross-region (via the " +
      "dag-<region>-cluster distributed AGs over the ag-<region>-forwarder); every other database is region-local " +
      "and will NOT appear here. Each row is one (distributed AG → underlying forwarder AG → database): role, sync " +
      "health, and the log-send / redo backlog (lag). Healthy = synchronization_health HEALTHY with low/zero " +
      "redo_queue_size. Use get_ag_health for the LOCAL (within-region) AG instead.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT
            ag.name                         AS distributed_ag,
            ar.replica_server_name          AS underlying_ag,
            dbs.name                        AS database_name,
            ars.role_desc                   AS role,
            drs.synchronization_health_desc AS sync_status,
            drs.log_send_queue_size         AS log_send_queue_kb,
            drs.log_send_rate               AS log_send_rate,
            drs.redo_queue_size             AS redo_queue_kb,
            drs.redo_rate                   AS redo_rate
          FROM sys.databases dbs
          JOIN sys.dm_hadr_database_replica_states drs ON dbs.database_id = drs.database_id
          JOIN sys.availability_groups ag ON drs.group_id = ag.group_id
          JOIN sys.dm_hadr_availability_replica_states ars ON ars.replica_id = drs.replica_id
          JOIN sys.availability_replicas ar ON ar.replica_id = ars.replica_id
          WHERE ag.is_distributed = 1
          ORDER BY ag.name, dbs.name, ar.replica_server_name
        `);
        if (rows.length === 0) {
          return { content: [{ type: "text", text: "No distributed Availability Groups visible from this instance. Run it on the global primary; only AppCatalog and AppDb_Routing replicate cross-region." }] };
        }
        return ok({ distributed_ag_health: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_log_paths — locate the SQL error-log directory + default paths (no manual paths)
  // ============================================================
  roTool(server,
    "get_log_paths",
    "Locate this instance's log/dump directories automatically — so you never have to be given a path. Returns the " +
      "current ERRORLOG file and its directory (e.g. C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\" +
      "MSSQL\\Log — where SQLDump*.txt/.mdmp also land), plus the default data/log paths. Pair with get_memory_dumps " +
      "and read_error_log to investigate a crash. " + INVESTIGATION_GUIDANCE,
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        // dump_directory is resolved separately from the ERRORLOG dir: where -e relocates the
        // ERRORLOG (e.g. L:\MSSQL\ErrorLogs on some nodes) the SQLDump*.txt still land in
        // the install default ...\MSSQL\Log on C:. Probe the ERRORLOG dir + known install Log
        // dirs and report whichever actually holds the dumps (enumerate is null-safe on a
        // missing dir, so non-existent candidates cost nothing).
        const { rows } = await queryInstance(instance_name, `
          DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));
          DECLARE @errDir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX('\\',REVERSE(@log)));
          ;WITH cand(dir,pref) AS (
            SELECT @errDir,0
            UNION ALL SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Log',1
            UNION ALL SELECT N'C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log',2),
          d AS (SELECT dir,MIN(pref) AS pref FROM cand GROUP BY dir)
          SELECT
            @log    AS error_log_file,
            @errDir AS log_directory,
            CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(512)) AS default_data_path,
            CAST(SERVERPROPERTY('InstanceDefaultLogPath')  AS nvarchar(512)) AS default_log_path,
            (SELECT TOP 1 d.dir FROM d CROSS APPLY sys.dm_os_enumerate_filesystem(d.dir,'SQLDump*') f
               WHERE f.is_directory=0 GROUP BY d.dir ORDER BY MAX(f.last_write_time) DESC) AS dump_directory
        `, 1);
        const r = (rows[0] ?? {}) as {
          error_log_file?: string; log_directory?: string; dump_directory?: string;
          default_data_path?: string; default_log_path?: string;
        };
        const elf = r.error_log_file ?? "";
        const log_directory = r.log_directory ?? (elf ? elf.replace(/[\\/][^\\/]*$/, "") : null);
        // Fall back to the ERRORLOG dir only if no candidate dir held any SQLDump* files.
        const dump_directory = r.dump_directory ?? log_directory;
        return ok({
          instance: instance_name,
          error_log_file: elf || null,
          log_directory,
          dump_directory,
          default_data_path: r.default_data_path ?? null,
          default_log_path: r.default_log_path ?? null,
        });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_memory_dumps — recent crash/stack dumps (sys.dm_server_memory_dumps)
  // ============================================================
  roTool(server,
    "get_memory_dumps",
    "List the SQL Server memory/stack dumps this instance has generated (sys.dm_server_memory_dumps): full path, " +
      "creation time, and size. The fastest way to confirm a crash storm and see how recent/frequent it is — an " +
      "empty result since the last restart means no AVs/exceptions since then. Filenames are SQLDump<NNNN>.mdmp/.txt " +
      "in the Log directory (see get_log_paths). " + INVESTIGATION_GUIDANCE,
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const rows = await callDbatools("Get-DbaDump", { SqlInstance: dbaSqlInstanceArg(cfg) });
        return ok({ instance: instance_name, dump_count: rows.length, dumps: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_machine_spec — CPU/RAM/NUMA/build/OS/VM — for cross-node comparison
  // ============================================================
  roTool(server,
    "get_machine_spec",
    "Get this instance's hardware/OS/build profile: CPU (sockets, cores, schedulers, hyperthread ratio), physical " +
      "RAM + SQL memory target, NUMA, VM type, SQL edition/version/CU level, and the host OS platform/release. Use it " +
      "to COMPARE a node against peers on the same cloud when diagnosing instability — run it on the affected node " +
      "and its same-cloud peers (or via fan_out_query) and diff CPU/RAM/build/OS. " + INVESTIGATION_GUIDANCE,
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        // Get-DbaComputerSystem / Get-DbaOperatingSystem take -ComputerName, not -SqlInstance
        // (unlike every other cmdlet migrated in this wave) — pass the bare host, no port.
        const computerName = cfg.host.split(",")[0];
        const [systemRows, osRows] = await Promise.all([
          callDbatools("Get-DbaComputerSystem", { ComputerName: computerName }) as Promise<Array<Record<string, unknown>>>,
          callDbatools("Get-DbaOperatingSystem", { ComputerName: computerName }) as Promise<Array<Record<string, unknown>>>,
        ]);
        const spec = { ...(systemRows[0] ?? {}), ...(osRows[0] ?? {}) };
        return ok({ instance: instance_name, spec: Object.keys(spec).length ? spec : null });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_backup_status
  // ============================================================
  roTool(server, 
    "get_backup_status",
    "Get last backup time for each database (full, differential, and log) from msdb.dbo.backupset. Identifies databases with stale backups or missing log backups. Compliance risk if last_full_backup_days > 7 or last_log_backup_hours > 1 (for FULL recovery model).",
    { ...instanceParam,
      include_system_dbs: z
        .boolean()
        .default(false)
        .describe("Include system databases (master, model, msdb) in results (default: false)"),
    },
    async ({ instance_name, include_system_dbs }) => {
      // Migrated to dbatools (Task 5). Get-DbaLastBackup has no "include system DBs"
      // switch, so that part of the schema is now applied client-side instead of in SQL.
      const SYSTEM_DBS = new Set(["master", "model", "msdb", "tempdb"]);
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const rows = (await callDbatools("Get-DbaLastBackup", {
          SqlInstance: dbaSqlInstanceArg(cfg),
        })) as Array<Record<string, unknown>>;
        const filtered = include_system_dbs
          ? rows
          : rows.filter((r) => !SYSTEM_DBS.has(String(r.Database)));
        return ok({ backup_status: filtered });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_vlf_count
  // ============================================================
  roTool(server, 
    "get_vlf_count",
    "Get Virtual Log File (VLF) count per database. High VLF counts (>1000) indicate the transaction log was grown in many small increments, causing slow recovery, backups, and log shipping. Fix by shrinking the log (after a log backup in FULL mode) and pre-growing it in large chunks.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        // Brief said Get-DbaDbVirtualLogFile, but that cmdlet returns one row per VLF
        // with no aggregate count at all (no "Total" field, or anything like it) — it is
        // not what get_vlf_count needs. Measure-DbaDbVirtualLogFile is the one that
        // aggregates per database (Database, Total, ...); see task-5-report.md.
        // -IncludeSystemDBs is omitted to match the old query's "d.database_id > 4" filter.
        const rows = (await callDbatools("Measure-DbaDbVirtualLogFile", {
          SqlInstance: dbaSqlInstanceArg(cfg),
        })) as Array<Record<string, unknown>>;
        return ok({ vlf_counts: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_buffer_pool_by_object
  // ============================================================
  roTool(server, 
    "get_buffer_pool_by_object",
    "Get buffer pool (RAM cache) consumption by table and index. Shows which objects are resident in memory. On large-memory servers, knowing what's cached is critical for capacity planning. High buffer counts for a table = hot data; low buffer counts despite high reads = potential memory pressure.",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .describe("Filter to a specific database (default: all user databases)"),
      top_n: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(50)
        .describe("Number of top objects to return (default: 50)"),
    },
    async ({ instance_name, database_name, top_n }) => {
      if (database_name && !IDENT_RE.test(database_name)) return err(`Invalid database_name: ${database_name}`);
      // sys.allocation_units, sys.partitions, and sys.indexes are per-database catalog
      // views; from master context they only return master's data. dm_os_buffer_descriptors
      // is instance-wide, so user-DB pages drop out of the JOIN. Fix: execute per-database
      // via sp_executesql so catalog views resolve in the correct DB context.
      const dbWhere = database_name
        ? `WHERE name = N'${database_name.replace(/'/g, "''")}' AND state = 0`
        : "WHERE database_id > 4 AND state = 0 AND is_read_only = 0";

      try {
        const { rows } = await queryInstance(instance_name, `
          IF OBJECT_ID('tempdb..#bp_objects') IS NOT NULL DROP TABLE #bp_objects;
          CREATE TABLE #bp_objects (
            database_name NVARCHAR(128),
            object_name   NVARCHAR(256),
            index_name    NVARCHAR(256),
            index_type    NVARCHAR(60),
            buffer_mb     BIGINT,
            page_count    BIGINT,
            dirty_pages   BIGINT
          );

          DECLARE @db        NVARCHAR(128);
          DECLARE @inner_sql NVARCHAR(MAX) = N'
            INSERT INTO #bp_objects
            SELECT
              DB_NAME()                           AS database_name,
              OBJECT_NAME(p.object_id)            AS object_name,
              i.name                              AS index_name,
              i.type_desc                         AS index_type,
              COUNT(*) * 8 / 1024                 AS buffer_mb,
              COUNT(*)                            AS page_count,
              SUM(CASE WHEN bd.is_modified = 1 THEN 1 ELSE 0 END) AS dirty_pages
            FROM sys.dm_os_buffer_descriptors bd
            JOIN sys.allocation_units au
              ON bd.allocation_unit_id = au.allocation_unit_id
            JOIN sys.partitions p
              ON au.container_id = p.hobt_id
             AND au.type IN (1, 3)
            LEFT JOIN sys.indexes i
              ON p.object_id = i.object_id
             AND p.index_id  = i.index_id
            WHERE bd.database_id = DB_ID()
            GROUP BY p.object_id, i.name, i.type_desc';

          DECLARE db_cur CURSOR LOCAL FAST_FORWARD FOR
            SELECT name FROM sys.databases ${dbWhere};
          OPEN db_cur;
          FETCH NEXT FROM db_cur INTO @db;
          WHILE @@FETCH_STATUS = 0
          BEGIN
            DECLARE @full_sql NVARCHAR(MAX) = N'USE [' + @db + N']; ' + @inner_sql;
            BEGIN TRY
              EXEC sp_executesql @full_sql;
            END TRY
            BEGIN CATCH
              -- Skip inaccessible databases
            END CATCH;
            FETCH NEXT FROM db_cur INTO @db;
          END;
          CLOSE db_cur; DEALLOCATE db_cur;

          SELECT TOP (${top_n}) * FROM #bp_objects ORDER BY buffer_mb DESC;
          DROP TABLE #bp_objects;
        `);
        return ok({ buffer_pool_by_object: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_statistics_health
  // ============================================================

  // Step 1 (finding 4 / wave-3 pattern): the pre-migration DMV body, recovered from git
  // history (commit ae99b36, which replaced it with the dbatools-only call below) and
  // moved verbatim into a named function — SQL unchanged. This is the default path again
  // (DBATOOLS_FIRST unset/0): it is the only implementation that actually has a
  // modification-counter to filter min_modification_pct on.
  async function statisticsHealthViaDmv(instance_name: string, database_name: string, min_modification_pct: number): Promise<ToolResult> {
    try {
      const { rows } = await queryInstance(instance_name, `
        USE [${database_name}];

        SELECT
          OBJECT_SCHEMA_NAME(s.object_id)               AS schema_name,
          OBJECT_NAME(s.object_id)                      AS table_name,
          s.name                                        AS stats_name,
          sp.last_updated,
          DATEDIFF(DAY, sp.last_updated, GETDATE())     AS days_since_update,
          sp.rows                                       AS rows_at_last_update,
          sp.rows_sampled,
          sp.modification_counter,
          CASE WHEN sp.rows > 0
               THEN CAST(100.0 * sp.modification_counter / sp.rows AS DECIMAL(10, 2))
               ELSE 0
          END                                           AS modification_pct,
          sp.steps                                      AS histogram_steps,
          s.auto_created,
          s.user_created,
          s.no_recompute,
          s.is_incremental
        FROM sys.stats s
        CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
        WHERE OBJECTPROPERTY(s.object_id, 'IsUserTable') = 1
          AND sp.rows > 0
          AND CAST(100.0 * sp.modification_counter / sp.rows AS DECIMAL(10, 2)) >= ${min_modification_pct}
        ORDER BY
          sp.modification_counter DESC;
        USE master;
      `);

      if (rows.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: `No stale statistics found in database '${database_name}' with modification >= ${min_modification_pct}%.`,
            },
          ],
        };
      }
      return ok({ statistics_health: rows, database: database_name });
    } catch (e: unknown) {
      return err(e instanceof Error ? e.message : String(e));
    }
  }

  // Default cap for statisticsHealthViaDbatools' max_objects param. Get-DbaDbccStatistic
  // has no -Top/limit of its own and issues one DBCC SHOW_STATISTICS round trip per
  // statistics object it enumerates, so the round-trip count this tool can trigger is
  // otherwise unbounded (thousands, on a database with many indexed tables). 50 gives a
  // useful investigative sample (bad/stale stats tend to cluster on the busiest handful of
  // tables) while keeping the worst case a fixed, small number of sequential DBCC calls
  // instead of an open-ended sweep of the whole catalog.
  const DEFAULT_MAX_STATS_OBJECTS = 50;

  // Step 2: the dbatools path (originally wave-2's only implementation). Get-DbaDbccStatistic
  // issues one DBCC SHOW_STATISTICS call PER statistics object in the database (it enumerates
  // sys.stats then loops) — there is no TOP/limit of its own, so on a database with many
  // indexes this is many round trips, not one, and can be slow. It also has NO modification-
  // counter/rowmodctr field at all — it reports Rows/RowsSampled/Updated/Density/Steps per
  // stats object instead — so min_modification_pct has no effect on this path; every
  // statistics object is returned unfiltered.
  //
  // max_objects bounds those round trips. Get-DbaDbccStatistic can't be told "stop after N"
  // internally (no -Top, and -Object only accepts ONE schema.table at a time — no array), so
  // by the time it returns anything every DBCC call it made has already happened; trimming the
  // result afterward wouldn't undo those round trips. Instead this does a cheap DMV pre-check
  // (mirrors the object-enumeration query Get-DbaDbccStatistic itself runs internally —
  // sys.stats/sys.objects filtered to types 'U'/'V') to learn the true candidate count AND get
  // a deterministic (name-ordered) list, then only calls Get-DbaDbccStatistic -Object once per
  // table in the first max_objects of that list — capping the DBCC round trips at max_objects
  // (plus the one cheap pre-check query) regardless of how many tables/stats the database has.
  //
  // Throws on failure (does NOT catch) so withFallback's catch sees the failure and falls
  // back to statisticsHealthViaDmv.
  async function statisticsHealthViaDbatools(instance_name: string, database_name: string, max_objects: number): Promise<ToolResult> {
    const cfg = await resolveDbaSqlInstance(instance_name);

    // maxRows set generously high (not the tool's own row-oriented default) so this
    // count/list query is never itself truncated by queryInstance's usual row cap — the
    // truncation decision here is made explicitly below, against max_objects.
    const { rows: objectRows } = await queryInstance(instance_name, `
      USE [${database_name}];
      SELECT DISTINCT SCHEMA_NAME(o.schema_id) + '.' + o.name AS object_name
      FROM sys.stats st
      INNER JOIN sys.objects o ON o.object_id = st.object_id
      WHERE o.type IN ('U', 'V')
      ORDER BY object_name;
      USE master;
    `, 1_000_000);

    const allObjectNames = objectRows.map((r) => String(r.object_name));
    const totalObjects = allObjectNames.length;
    const { selected: selectedObjects, truncated } = selectStatsObjects(allObjectNames, max_objects);

    const allRows: Array<Record<string, unknown>> = [];
    for (const objectName of selectedObjects) {
      const objRows = (await callDbatools("Get-DbaDbccStatistic", {
        SqlInstance: dbaSqlInstanceArg(cfg),
        Database: database_name,
        Object: objectName,
      })) as Array<Record<string, unknown>>;
      allRows.push(...objRows);
    }

    if (allRows.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No statistics found in database '${database_name}'.`,
          },
        ],
      };
    }
    return ok({
      statistics_health: allRows,
      database: database_name,
      truncated,
      objects_checked: selectedObjects.length,
      objects_total: totalObjects,
    });
  }

  roTool(server,
    "get_statistics_health",
    "Get statistics staleness for all user tables in a database. Default path (DMV): reports rows modified since the last statistics update (rowmodctr) and last-updated time for every statistics object with modification_pct >= min_modification_pct — high modification_pct relative to rows means stale stats, which cause bad cardinality estimates and poor query plans (SQL Server's own auto-update threshold is roughly ~20% for small tables, lower for large ones). Under DBATOOLS_FIRST=1 this instead runs DBCC SHOW_STATISTICS per statistics object via dbatools (Get-DbaDbccStatistic): it returns Rows/RowsSampled/Updated/Density/Steps per object but has no modification-counter field at all, so min_modification_pct is not applied; and because each object is one DBCC round trip with no cap of its own, this path is bounded by max_objects (default 50) — at most that many tables/views are probed, ordered by name, and the response's `truncated` flag (plus objects_checked/objects_total) says whether the database actually had more than that.",
    { ...instanceParam,
      database_name: z
        .string()
        .describe("Database name to check (statistics are per-database)"),
      min_modification_pct: z
        .number()
        .min(0)
        .max(100)
        .default(10)
        .describe("Minimum modification % to report (default: 10%). Only applied on the default DMV path — ignored under DBATOOLS_FIRST=1, whose Get-DbaDbccStatistic path has no modification-counter field to filter on and always returns every statistics object it checks."),
      max_objects: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(DEFAULT_MAX_STATS_OBJECTS)
        .describe(`Only applies under DBATOOLS_FIRST=1 (the dbatools path). Max number of distinct tables/views to run DBCC SHOW_STATISTICS against, ordered by name (default ${DEFAULT_MAX_STATS_OBJECTS}) — that path has no built-in limit and issues one DBCC round trip per object, so on a database with many indexed tables it would otherwise be thousands of round trips. When the database has more qualifying objects than this cap, the response's truncated field is true and objects_checked/objects_total show how much of the database was actually covered. Ignored on the default DMV path, which filters by min_modification_pct in one query instead.`),
    },
    async ({ instance_name, database_name, min_modification_pct, max_objects }) => {
      try {
        assertIdentifier(database_name, "database_name");
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
      return withFallback(
        () => statisticsHealthViaDbatools(instance_name, database_name, max_objects),
        () => statisticsHealthViaDmv(instance_name, database_name, min_modification_pct),
      );
    }
  );

  // ============================================================
  // get_index_fragmentation
  // NOT MIGRATED (Task 5): no dbatools equivalent verified — stays on the DMV query below.
  // ============================================================
  roTool(server,
    "get_index_fragmentation",
    "Get index fragmentation and page density for all user tables using dm_db_index_physical_stats in SAMPLED mode. Key metrics: avg_fragmentation_in_percent (rebuild if > 30%, reorganize if 10-30%), avg_page_space_used_in_percent (low density = wasted space and I/O amplification). On flash storage, fragmentation hurts less for reads but increases log write amplification from page splits.",
    { ...instanceParam,
      database_name: z
        .string()
        .describe("Database name to analyze (fragmentation is per-database)"),
      min_fragmentation_pct: z
        .number()
        .min(0)
        .max(100)
        .default(10)
        .describe("Minimum fragmentation % to report (default: 10%)"),
      min_page_count: z
        .number()
        .int()
        .min(0)
        .default(1000)
        .describe("Minimum page count threshold — skip small indexes (default: 1000)"),
    },
    async ({ instance_name, database_name, min_fragmentation_pct, min_page_count }) => {
      try {
        assertIdentifier(database_name, "database_name");
        const { rows } = await queryInstance(instance_name, `
          USE [${database_name}];

          SELECT
            OBJECT_SCHEMA_NAME(ips.object_id)             AS schema_name,
            OBJECT_NAME(ips.object_id)                    AS table_name,
            i.name                                        AS index_name,
            i.type_desc                                   AS index_type,
            ips.index_level,
            ips.avg_fragmentation_in_percent,
            ips.fragment_count,
            ips.avg_fragment_size_in_pages,
            ips.page_count,
            ips.avg_page_space_used_in_percent,
            ips.record_count,
            ips.ghost_record_count,
            CASE
              WHEN ips.avg_fragmentation_in_percent >= 30 THEN 'REBUILD'
              WHEN ips.avg_fragmentation_in_percent >= 10 THEN 'REORGANIZE'
              ELSE 'OK'
            END                                           AS recommendation
          FROM sys.dm_db_index_physical_stats(
            DB_ID(),
            NULL,
            NULL,
            NULL,
            'SAMPLED'
          ) ips
          JOIN sys.indexes i
            ON ips.object_id = i.object_id
           AND ips.index_id = i.index_id
          WHERE ips.index_level = 0
            AND ips.page_count >= ${min_page_count}
            AND ips.avg_fragmentation_in_percent >= ${min_fragmentation_pct}
            AND i.name IS NOT NULL
          ORDER BY
            ips.avg_fragmentation_in_percent DESC;
          USE master;
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No fragmented indexes found in database '${database_name}' with fragmentation >= ${min_fragmentation_pct}% and page_count >= ${min_page_count}.`,
              },
            ],
          };
        }
        return ok({ index_fragmentation: rows, database: database_name });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_job_status
  // ============================================================
  roTool(server, 
    "get_job_status",
    "Get SQL Agent job execution status: last run outcome, duration, next scheduled run, currently executing jobs. Essential for operational monitoring. Identifies failed jobs that need attention.",
    { ...instanceParam },
    async ({ instance_name }) => {
      try {
        const cfg = await resolveDbaSqlInstance(instance_name);
        const rows = await callDbatools("Get-DbaAgentJob", { SqlInstance: dbaSqlInstanceArg(cfg) });
        return ok({ job_status: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_columnstore_health
  // NOT MIGRATED (Task 5): no dbatools equivalent verified — stays on the DMV query below.
  // ============================================================
  roTool(server,
    "get_columnstore_health",
    "Get columnstore index health: rowgroup states, delta store size, compression quality. Delta stores are uncompressed rowgroups — too many indicate the tuple mover isn't keeping up or inserts are trickle-loading. Low compressed rowgroup size (<1M rows per rowgroup) indicates small batch inserts or excessive deletes.",
    { ...instanceParam,
      database_name: z
        .string()
        .optional()
        .describe("Filter to a specific database (default: all user databases)"),
    },
    async ({ instance_name, database_name }) => {
      if (database_name && !IDENT_RE.test(database_name)) return err(`Invalid database_name: ${database_name}`);
      const dbWhere = database_name
        ? `WHERE name = N'${database_name.replace(/'/g, "''")}'`
        : "WHERE database_id > 4 AND state = 0 AND is_read_only = 0";

      try {
        // sys.dm_db_column_store_row_group_physical_stats is database-scoped,
        // so query each target database via sp_executesql with USE [db].
        const { rows } = await queryInstance(instance_name, `
          IF OBJECT_ID('tempdb..#cs_health') IS NOT NULL DROP TABLE #cs_health;
          CREATE TABLE #cs_health (
            database_name         NVARCHAR(128),
            schema_name           NVARCHAR(128),
            table_name            NVARCHAR(128),
            index_name            NVARCHAR(128),
            index_type            NVARCHAR(60),
            rowgroup_state        NVARCHAR(60),
            rowgroup_count        INT,
            total_rows            BIGINT,
            avg_rows_per_rowgroup BIGINT,
            total_deleted_rows    BIGINT,
            total_size_mb         BIGINT,
            health_status         NVARCHAR(60)
          );

          DECLARE @db       NVARCHAR(128);
          DECLARE @inner_sql NVARCHAR(MAX) = N'
            INSERT INTO #cs_health
            SELECT
              DB_NAME()                       AS database_name,
              OBJECT_SCHEMA_NAME(i.object_id) AS schema_name,
              OBJECT_NAME(i.object_id)        AS table_name,
              i.name                          AS index_name,
              i.type_desc                     AS index_type,
              rg.state_desc                   AS rowgroup_state,
              COUNT(*)                        AS rowgroup_count,
              SUM(rg.total_rows)              AS total_rows,
              AVG(rg.total_rows)              AS avg_rows_per_rowgroup,
              SUM(rg.deleted_rows)            AS total_deleted_rows,
              SUM(CASE WHEN rg.size_in_bytes > 0 THEN rg.size_in_bytes ELSE 0 END) / 1048576
                                              AS total_size_mb,
              CASE
                WHEN rg.state_desc = ''OPEN'' THEN ''DELTA_STORE''
                WHEN AVG(rg.total_rows) < 500000 THEN ''SMALL_ROWGROUPS''
                WHEN SUM(rg.deleted_rows) * 1.0 / NULLIF(SUM(rg.total_rows), 0) > 0.1 THEN ''HIGH_DELETES''
                ELSE ''HEALTHY''
              END                             AS health_status
            FROM sys.indexes i
            JOIN sys.dm_db_column_store_row_group_physical_stats rg
              ON i.object_id = rg.object_id AND i.index_id = rg.index_id
            WHERE i.type IN (5, 6)
            GROUP BY i.object_id, i.name, i.type_desc, rg.state_desc';

          DECLARE db_cur CURSOR LOCAL FAST_FORWARD FOR
            SELECT name FROM sys.databases ${dbWhere};
          OPEN db_cur;
          FETCH NEXT FROM db_cur INTO @db;
          WHILE @@FETCH_STATUS = 0
          BEGIN
            DECLARE @full_sql NVARCHAR(MAX) = N'USE [' + @db + N']; ' + @inner_sql;
            BEGIN TRY
              EXEC sp_executesql @full_sql;
            END TRY
            BEGIN CATCH
              -- Skip inaccessible databases
            END CATCH;
            FETCH NEXT FROM db_cur INTO @db;
          END;
          CLOSE db_cur; DEALLOCATE db_cur;

          SELECT * FROM #cs_health
          ORDER BY database_name, table_name, index_name, rowgroup_state;
          DROP TABLE #cs_health;
        `);

        if (rows.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: database_name
                  ? `No columnstore indexes found in database '${database_name}'.`
                  : "No columnstore indexes found in any user database.",
              },
            ],
          };
        }
        return ok({ columnstore_health: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );

  // ============================================================
  // get_perfmon_counters
  // ============================================================
  roTool(server, 
    "get_perfmon_counters",
    "Get Windows Performance Monitor counters exposed by SQL Server. Includes key metrics: batch requests/sec, page life expectancy, lazy writes/sec, buffer cache hit ratio, etc. Use counter_category to filter (e.g., 'SQLServer:Buffer Manager', 'SQLServer:SQL Statistics').",
    { ...instanceParam,
      counter_category: z
        .string()
        .optional()
        .describe("Filter by counter category (e.g., 'SQLServer:Buffer Manager', 'SQLServer:SQL Statistics'). Leave empty for all categories."),
      counter_name: z
        .string()
        .optional()
        .describe("Filter by specific counter name (e.g., 'Page life expectancy', 'Batch requests/sec'). Leave empty for all counters."),
    },
    async ({ instance_name, counter_category, counter_name }) => {
      const categoryFilter = counter_category
        ? `AND object_name LIKE '%${counter_category.replace(/'/g, "''")}%'`
        : "";
      const nameFilter = counter_name
        ? `AND counter_name LIKE '%${counter_name.replace(/'/g, "''")}%'`
        : "";

      try {
        const { rows } = await queryInstance(instance_name, `
          SELECT
            RTRIM(object_name)                            AS object_name,
            RTRIM(counter_name)                           AS counter_name,
            RTRIM(instance_name)                          AS instance_name,
            cntr_value,
            cntr_type,
            CASE cntr_type
              WHEN 65792 THEN 'Count'
              WHEN 537003264 THEN 'Per-second rate'
              WHEN 1073939712 THEN 'Average'
              WHEN 1073874176 THEN 'Ratio (requires base)'
              WHEN 272696576 THEN 'Base counter for ratio'
              ELSE CAST(cntr_type AS VARCHAR(20))
            END                                           AS counter_type_description
          FROM sys.dm_os_performance_counters
          WHERE 1=1
            ${categoryFilter}
            ${nameFilter}
          ORDER BY
            object_name,
            counter_name,
            instance_name
        `);
        return ok({ perfmon_counters: rows });
      } catch (e: unknown) {
        return err(e instanceof Error ? e.message : String(e));
      }
    }
  );
}
