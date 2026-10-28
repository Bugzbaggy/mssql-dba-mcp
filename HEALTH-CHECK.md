# AppDb SQL MCP — dbatools Health Check

A comprehensive, **read-only** SQL Server health check available to the `sql-dba` profile, built entirely from
read-only `dbatools` cmdlets and fixed read-only DMV queries. Exposed as the tool **`run_health_check`** (plus
`run_dbatools_command`, `list_dbatools_commands`, `get_dbatools_command_help`, `check_dbatools_environment`,
`run_diagnostic_query`, and `read_error_log`). The ops profile does not get these tools, and none of them is
registered on the HTTP transport.

**Crash / instability forensics (sql-dba).** Alongside the health check, the DBA profile can locate evidence on its
own — no manual paths: **`get_log_paths`** (the ERRORLOG directory where `SQLDump*.txt/.mdmp` also land + default
data/log paths), **`get_memory_dumps`** (the `sys.dm_server_memory_dumps` DMV *and* an on-disk enumeration of
`SQLDump*` files, tagged by `source` — the DMV under-reports and resets at restart), **`read_sql_dump`** (list or read
the dump files over the SQL connection), **`read_error_log`** (filter the SQL error log for `Stack Dump` /
`access violation` / a module name), and **`get_machine_spec`** (CPU/RAM/NUMA/build/OS/VM type). `list_instances`
reports each node's **`cloud`** (from the fleet entry's `cloud` key) so the agent compares an affected node against a
healthy **peer on the same cloud** (diff spec, SQL/OS build, loaded modules) — spec/capacity is rarely the cause when
a smaller/busier same-cloud peer is stable.

## What `run_health_check` runs (66 read-only checks, 7 categories)

The table names the dbatools cmdlets and the first DMV checks; the full list, with each check's grading rule, is
`CATALOG` in `server/src/dbatools.ts`.

| Category (checks) | Cmdlets and first DMV checks |
|---|---|
| Availability (12) | `Get-DbaAvailabilityGroup`, `Get-DbaAgReplica`, `Get-DbaDatabase`*, `Get-DbaAgentJob`*, Agent job integrity (DMV)*, Agent job drift between AG replicas (DMV)†, `Get-DbaDbSpace`, AG data movement (DMV)*, AG policy and replica-policy conformance (DMV)*, AG failover capacity symmetry (DMV)*, Agent alert coverage (DMV)* |
| Performance (7) | `Get-DbaWaitStatistic`, `Test-DbaMaxDop`*, `Test-DbaMaxMemory`*, `Get-DbaLatchStatistic`, `Test-DbaDbQueryStore`, Storage I/O latency (DMV)*, Index health (`sp_BlitzIndex`)* |
| Recoverability (4) | Last backups (DMV over `msdb.dbo.backupset`, graded only where this replica is backup-preferred)*, `Get-DbaDbRecoveryModel`, `Get-DbaSuspectPage`*, `Get-DbaLastGoodCheckDb`* |
| Reliability (14) | Access violations / stack dumps (DMV)*, `Measure-DbaDbVirtualLogFile`*, `Test-DbaDbCompatibility`, `Test-DbaIdentityUsage`*, `Test-DbaDbCollation`, Page verify option (DMV)*, ERRORLOG file size (DMV)*, Recent error log (DMV: `xp_readerrorlog`, last 24 h), Login resets (Error 17830) by source (DMV)* |
| Security (6) | `Get-DbaLogin`, `Test-DbaConnectionAuthScheme`, `Get-DbaInstanceAudit`, `Get-DbaServerRoleMember`* (sysadmin count), Database owners (DMV)*, Secrets in Agent job step text (DMV)* |
| Configuration (15) | `Get-DbaSpConfigure`* (risky options), `Get-DbaTraceFlag`, `Test-DbaOptimizeForAdHoc`*, Build currency (DMV: `SERVERPROPERTY` against your build target)*, TempDB configuration (DMV)*, Microsoft SQL Assessment (`Invoke-SqlAssessment`)* |
| **Host / OS** (8) | `Test-DbaPowerPlan`, `Get-DbaDiskSpace`*, `Get-DbaFirewallRule`, `Get-DbaComputerSystem`, `Get-DbaOperatingSystem`, `Get-DbaPrivilege` **+ SQL-DMV fallbacks:** Service account & IFI/LPIM (`sys.dm_server_services` + `sys.dm_os_sys_info`)*, Operating system (`sys.dm_os_windows_info`) |

There is no separate index-maintenance category: unused and duplicate indexes are reported by Index health
(`sp_BlitzIndex`, Performance) with a priority, a URL and the create/drop T-SQL. It needs `sp_BlitzIndex` installed
in a `DBA` database on the node; without it the check reports *skipped*.

**Agent jobs beyond the last outcome.** `SQL Agent jobs` grades each job's last run, so it cannot see a job
that is broken without being red. **Agent job integrity** resolves every T-SQL step's `EXEC` target against the
database the step runs in and walks the step flow from `start_step_id`. It fails on an enabled, scheduled job that
reaches a missing procedure or database, including one a primary-role guard hides on a secondary, which fails on the
first run after a failover. It also flags a T-SQL step holding a shell command line. Dead code (disabled or
unscheduled jobs, unreachable or comment-only steps) and leftover `appdb_mcp_*` jobs are Attention. It never returns
step text. **Agent job drift between AG replicas** (†) compares each node's job set with its AG partner's. msdb is per
node, so it is graded only when **both replicas are checked in the same run** (`run_health_check` with both
instance names, or the report CLI with `--instances a,b`). A single-node run reports the inventory as Info.

`*` = **graded** (Pass/Attention/Fail). The rest are informational inventory. **Backups are graded only where this
node should take them** — in an AG they're usually taken on the backup-preferred (secondary) replica, so *Last
backups* grades a database only where `sys.fn_hadr_backup_is_preferred_replica` says this replica is preferred (and
never on a distributed-AG forwarder, matched by `HEALTHCHECK_FORWARDER_AG_LIKE`); elsewhere it reports Info. Fail is a
missing or ≥ 8-day-old full backup, or a FULL-recovery database whose existing log chain is ≥ 24 h stale; a FULL
database never log-backed, or a log backup 6–24 h old, is Attention.

**SQL-DMV host fallbacks** run over the **SQL login alone** (no WinRM/CIM), so OS and service-account facts (incl.
IFI / Lock-Pages-in-Memory) are available even when the Windows checks can't reach the node. Disk space has no SQL
fallback in the health check (`Get-DbaDiskSpace` is the source); free space on the volumes holding database files
is available over SQL from `get_file_io_stats`. Power plan and firewall have no SQL equivalent either — those still
need a Windows credential.

Each check carries a **`priority`** (High/Medium/Low) and a raw status. A subset with built-in thresholds grade
themselves (suspect pages, identity-column capacity ≥80/95%, VLF ≥1000/10000, last good CHECKDB ≥14/30 days,
stale full backups >7 days, auto-shrink/auto-close enabled, an enabled Agent job whose last run **Failed**,
an AG database that is suspended / `NOT SYNCHRONIZING` (or a >1 GB redo backlog), any DB not on `PAGE_VERIFY CHECKSUM`,
and TempDB layout — single data file on a multi-core box, unequal file sizes, or percent-autogrowth), evaluated
defensively; the rest are inventory reads.

### Report model & scoring
The tool collapses every check to one of four display statuses and scores them like the dbatools report:

| Display status | From | Score |
|---|---|---|
| **Pass** | graded `pass` | 100 |
| **Attention** | graded `attention` | 60 |
| **Fail** | graded `fail` | 0 |
| **Info** | inventory (`ok`/`empty`), a check that was `skipped` on purpose, **or** a check that couldn't run (`error`) | excluded from scoring (`coverage` keeps `errored` and `skipped` apart) |

**Health %** = priority-weighted average of the scored checks (High=3, Medium=2, Low=1) — per category and overall.
Informational checks never lower the score. `run_health_check` returns `auth`, `instances_checked`, `report`
(`{ path, note }`), `notes`, and `results` — one entry per instance with `overall_health`, `status_counts`
(Pass/Attention/Fail/Info), `categories` (`{ name, health, counts }`), `coverage` (`{ total, scored, errored, skipped }`
— a run where 10% or more of the checks errored is marked INCOMPLETE), and `findings`
(`{ category, label, command, spoke, priority, status, details, rows, remediation? }`). The raw rows of each check
(`checks[]`) are embedded only with `include_raw_data:true`; `summary_only` is a deprecated alias with no effect.

Parameters: scope with `instance_name`, `region` (a region name, or `'all'` for every SQL instance in the fleet —
witnesses are excluded), or an explicit `instances` list (takes precedence); with none of them it checks the default
instance only. `concurrency` (default 3, max 6) sets how many instances run at once, `max_rows_per_check`
(default 25, max 200) caps the rows kept per check, `auth` is `'sql'` or `'windows'`, and `html_report`
(default `true`) writes the HTML file.

### HTML report (looks like the dbatools report)
By default (`html_report:true`) it also writes a **self-contained HTML report** — the overall health percentage and
status counts, a *Recommended actions* panel that leads with an ACT NOW block, a Categories table, an Instances
table, and an all-findings table (Category · Label · Priority · Status · Details, plus Instance when more than one
instance ran) with red/amber/green scoring — and returns its path as `report.path`. The file is written to
`HEALTHCHECK_REPORT_DIR` (default: the OS temp dir; set it to keep reports somewhere durable) as
`sql-health-<scope>-<timestamp>.html`. No external assets — open it in any browser.

## Strictly read-only — how
1. **Hard allowlist** — every cmdlet a tool runs, and every cmdlet check in the catalog, must be
   `Get-/Test-/Measure-/Find-Dba*` (+ `Invoke-DbaDiagnosticQuery`); the catalog is validated against this at load.
   Two kinds of catalog check are exempt because they take no caller input: the DMV checks run a fixed read-only
   `SELECT` through `Invoke-DbaQuery`, and *Microsoft SQL Assessment* runs `Invoke-SqlAssessment`, which only
   evaluates rules.
2. **Write-in-disguise denylist** — `Test-DbaLastBackup` is **blocked**: despite its `Test-` verb it *restores* a
   copy of each backup to verify it (a write). Backup currency is read via `Get-DbaLastBackup` instead.
3. **Connection** — `Connect-DbaInstance -ApplicationIntent ReadOnly -TrustServerCertificate`.

## Authentication
- **SQL checks** default to **SQL auth** via `HEALTHCHECK_SQL_USER`/`HEALTHCHECK_SQL_PASSWORD` (your own read-only DBA login), falling
  back to `SQL_USER`/`SQL_PASSWORD`. Cloud nodes are generally not reachable via Windows/Kerberos from a
  workstation, so SQL auth is the working path. Pass `auth:'windows'` to use the operator's AD account; with no SQL
  login configured that is also the default.
  These variables are read from the **environment only** — `SQL_CRED_TARGET` (the OS credential store the T-SQL tools
  use) is not consulted by any PowerShell-backed tool. An empty-but-set `HEALTHCHECK_SQL_USER` counts as set and does
  not fall back to `SQL_USER`, so leave it unset rather than blank.
  > Use **your own** read-only DBA login (not a shared/sysadmin account such as `sa`) so every check is
  > attributable to you. The check is read-only regardless — it runs read cmdlets exclusively and blocks
  > `Test-DbaLastBackup` (which restores).
- **OS/CIM checks** (power plan, disk, firewall, computer/OS) read via CIM/WMI and need **Windows access** to the
  node — set `HEALTHCHECK_WIN_USER`/`HEALTHCHECK_WIN_PASSWORD`. Without it, on a remote node they are **skipped**
  (see *OS/CIM checks* below) and the SQL checks still run fully. On the node itself — a scheduled job,
  `HEALTHCHECK_OS_LOCAL=1` — they run against the local machine as the job's own identity (see *On-node runs*).
  (Disk free space + I/O latency are also independently available over SQL via the DMV tool `get_file_io_stats`.)
- Passwords are supplied via environment only — never stored in a file.

## Prerequisites
- PowerShell 5.1+ (Windows PowerShell is fine; PS7 optional via `PWSH_EXE`).
- `dbatools` ≥ 2.7 : `Install-Module dbatools -Scope CurrentUser`.
- Optional, per node: a `DBA` database holding the First Responder Kit's `sp_BlitzIndex` (for *Index health*; without
  it the check is skipped), and the `SqlServer` PowerShell module (for *Microsoft SQL Assessment*). The assessment is
  also skipped under SQL auth — it runs in a child PowerShell process and would expose the password on its command
  line — so it runs only with Windows auth, e.g. the on-node job.
- Verify with the `check_dbatools_environment` tool.

## Configuration
| Variable | Default | Meaning |
|---|---|---|
| `DBATOOLS_ENABLED` | `true` | Set `false` to hide the 12 PowerShell tools where PowerShell/dbatools isn't installed (the DMV-group tools that call dbatools stay registered — see [DEPLOYMENT.md](DEPLOYMENT.md) §4) |
| `PWSH_EXE` | `powershell` on Windows for the script-based tools (`run_health_check` and the other per-call scripts); `pwsh` for the long-lived worker behind `get_current_primary`'s AG confirmation, the `DBATOOLS_FIRST` paths and the dbatools-backed DMV tools | PowerShell host; set it explicitly (`powershell` or `pwsh`) to use one host for both |
| `HEALTHCHECK_SQL_USER` / `_PASSWORD` | `SQL_USER`/`SQL_PASSWORD` | SQL login for the health check (your own read-only DBA login) |
| `HEALTHCHECK_WIN_USER` / `_PASSWORD` | — | Windows login on the node for OS/CIM checks (power plan/disk/firewall/OS). With it set, those checks connect to the configured host/IP via **NTLM**, avoiding the Kerberos/WinRM double-hop that otherwise fails |
| `HEALTHCHECK_OS_LOCAL` | unset | `1` only in an on-node scheduled job: connect to the local instance by machine name (shared memory) and run the OS checks against this machine as the job's identity — see *On-node runs* |
| `DBATOOLS_TIMEOUT_SECONDS` | `120` | Timeout for `run_dbatools_command`, `run_diagnostic_query`, `read_error_log`, `read_cluster_reports`, `get_host_event_log` and `get_host_dll_versions` |
| `HEALTHCHECK_TIMEOUT_SECONDS` | `1800` | Overall (per-instance) ceiling for `run_health_check`; also the ceiling for `generate_cluster_log` |
| `HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS` | `60` | Per-SQL-query cap on the shared SMO connection |
| `HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS` | `120` | Wall-clock cap on each catalog cmdlet (worker runspace; set 0 to disable) |
| `HEALTHCHECK_CONNECT_TIMEOUT_SECONDS` | `15` | Connect cap, so a dead/slow node fails fast |
| `HEALTHCHECK_REPORT_DIR` | OS temp dir | Where the HTML report is written (`report.path`) |
| `HEALTHCHECK_BUILD_TARGET` | `16.0.4275.2` | Your build target for *Build currency* (four dotted numbers; anything else is ignored). The default (`BUILD_TARGET_DEFAULT` in `dbatools.ts`) is SQL Server 2022 **CU26 + GDR** (KB5122768), the security update on the CU26 line — the plain CU26 build is 16.0.4265.3 (KB5093420) and grades *BEHIND* this default. It is only the newest build this code has been exercised against - set your own. An override names a build only, so the report's `TargetCU` column is left blank for it |
| `DBATOOLS_MAX_OUTPUT_MB` | `64` | PowerShell stdout cap; rows are scalar-flattened so this is rarely approached |

### OS/CIM checks (power plan, disk, firewall, OS)
These need a Windows login on the target node. Set `HEALTHCHECK_WIN_USER` (e.g. `example\\someuser`) and
`HEALTHCHECK_WIN_PASSWORD` — the checks then target the **configured host/IP** with that credential (NTLM), which is
what makes them work when Kerberos/WinRM to the node name fails.

**Without a Windows credential these WinRM checks are SKIPPED (status `skipped` → Info), not attempted** — because
they can't succeed and, against a remote node, an attempt can hang long enough to blow the overall timeout (this was
why remote regions runs timed out). The SQL-DMV fallbacks still report OS and service-account facts over the SQL
login (disk space has no fallback; use `get_file_io_stats`), and the response's `notes` says which credential to set
to enable the Windows checks.

### Site configuration (facts one node cannot know)

Some checks need facts about *your* estate: a partner node's size, which logins are structural, which volumes
matter. Those are configuration, never constants in the code, and every default is safe with nothing set — a check
that cannot judge without its data reports **skipped** (or *unprobed*), never a pass.

| Variable | Default | Used by |
|---|---|---|
| `HEALTHCHECK_CAPACITY_BASELINE` | unset → *skipped* | *AG failover capacity symmetry*: JSON list of every replica's size, e.g. `[{"node":"REGION1-NODE1","cores":16,"memMb":131072}, …]` (`node` = `@@SERVERNAME`) |
| `HEALTHCHECK_CAPACITY_BASELINE_DATE` | `unknown` | The date those sizes were measured (`YYYY-MM-DD`); printed on every row, and a node whose live size no longer matches its own row grades Attention |
| `HEALTHCHECK_CORE_DATABASES` | unset | *Per-database option hygiene*: comma-separated databases whose low-priority statistics wait is probed and whose `AUTO_UPDATE_STATISTICS_ASYNC = OFF` is graded |
| `HEALTHCHECK_STRUCTURAL_LOGINS` | `sa`, `distributor_admin` | *sysadmin members*: extra logins that are in sysadmin by construction (a renamed `sa`); the SQL side also matches `sa` by SID `0x01` |
| `HEALTHCHECK_DISK_FAIL_VOLUMES` | unset → every volume fails under 10% | *Disk space*: scope FAIL to the volumes that hold SQL/OS files, with an optional lower threshold per volume, e.g. `C:,D:,F:=5`; Attention stays < 15% on every volume |
| `HEALTHCHECK_SANCTIONED_INPROC_PATHS` | unset | *Linked-server providers in-process*: comma-separated T-SQL `LIKE` patterns for third-party DLLs you have deliberately allowed inside `sqlservr.exe`; any other one grades Attention |
| `HEALTHCHECK_PRIMARY_GUARD_PROC` | unset | *Agent job integrity*: your own primary-role guard procedure, recognised alongside `sys.fn_hadr_is_primary_replica` |
| `HEALTHCHECK_FORWARDER_AG_LIKE` | `%forwarder%` | *Last backups* and *AG replica policy conformance*: `LIKE` pattern naming the local AG that receives a distributed AG |
| `HEALTHCHECK_DBATOOLS_VERSION` / `HEALTHCHECK_DBATOOLS_LIBRARY_VERSION` | `2.7.2` / `2025.8.17` | *Health-check tooling version drift*: the versions you pin (defaults: the dbatools release this repository tests against, and the library it requires) |
| `SQL_EXTRA_DUMP_DIRS` | unset | Stack-dump checks and `get_memory_dumps`/`get_log_paths`: `;`-separated directories to probe in addition to the derived candidates |
| `HEALTHCHECK_CONFORMANCE_BASELINE` | the opinionated defaults below | *AG policy conformance*, *AG replica policy conformance*, *Instance configuration vs fleet standard*: JSON merged over the defaults (see below) |
| `HEALTHCHECK_HOST_DLL_WATCHLIST` | Microsoft binaries only | `get_host_dll_versions`: JSON list of extra third-party DLLs to compare across nodes, e.g. `[{"path":"Program Files\\<Vendor>\\<agent>.dll","label":"security agent"}]` (paths relative to `C:\`) |

#### Conformance baselines: opinionated defaults, not universal truth

The three conformance checks grade every node against a baseline, and the defaults are a **stance** — a reasonable
HA and hardening position, not a rule that fits every estate. Several differ from SQL Server's own defaults on purpose:

| Setting | Default baseline | SQL Server default | Why the baseline differs |
|---|---|---|---|
| `DB_FAILOVER` | `ON` | `OFF` | a database going SUSPECT/OFFLINE should fail the AG over, not be ridden out |
| `FAILURE_CONDITION_LEVEL` | `2` | `3` | level 3+ fails over on an in-process dump storm that only killed sessions |
| `HEALTH_CHECK_TIMEOUT` | `60000` | `30000` | a busy primary can miss a diagnostics heartbeat under load |
| `AUTOMATED_BACKUP_PREFERENCE` | `SECONDARY` | `SECONDARY` | keeps backup I/O off the primary |
| `SESSION_TIMEOUT` | `>= 60` | `10` | a 10 s stall (checkpoint, VM pause) otherwise disconnects the replica |
| `SEEDING_MODE` | `AUTOMATIC` | `MANUAL` | manual seeding is how a database ends up in the AG on one replica only |
| instance settings | `xp_cmdshell`/`Ole Automation`/`Ad Hoc Distributed Queries`/`cross db ownership chaining`/`clr enabled`/`priority boost`/`lightweight pooling` = 0; `cost threshold for parallelism` = 50; `optimize for ad hoc workloads`, `backup compression default`, `backup checksum default`, `remote admin connections` = 1; `max degree of parallelism` = min(cores, 8) | various | each row's Note says why |

Override any of them with one setting, merged over the defaults; a row whose expectation came from it says so
("Site baseline"):

```bash
HEALTHCHECK_CONFORMANCE_BASELINE='{"ag":{"FAILURE_CONDITION_LEVEL":3,"HEALTH_CHECK_TIMEOUT":30000},
  "replica":{"SESSION_TIMEOUT":10},
  "instance":{"cost threshold for parallelism":25,"clr enabled":null,"max degree of parallelism":4}}'
```

An `instance` entry set to `null` drops that setting from the check, and a name that is not in the defaults adds one.
Invalid values are logged and ignored, so the defaults stand. On an instance with no WSFC availability group the two AG
checks report **skipped**, never a pass.

### On-node runs (a scheduled job on the node)
With `HEALTHCHECK_OS_LOCAL=1` the OS checks are not skipped: they target `$env:COMPUTERNAME` as the SQL Agent
service account. That account being **sysadmin in SQL does not make the job step an elevated Windows process**, and
in practice an Agent CmdExec step usually is not elevated — dbatools refuses `Test-DbaPowerPlan` ("Console not
elevated") and WinRM refuses the loopback `Get-DbaPrivilege` opens (WSManFault Code 5, Access is denied). So each
check chooses at run time:

| Check | Elevated token | Not elevated |
|---|---|---|
| Power plan | `Test-DbaPowerPlan` | `powercfg /getactivescheme` |
| Operating system / Computer system | `Get-DbaOperatingSystem` / `Get-DbaComputerSystem` | local CIM (`Get-CimInstance`, no `-ComputerName`: no WinRM, no network logon) |
| Service account privileges (IFI/LPIM) | `Get-DbaPrivilege` | not run — it needs WinRM and `secedit /export` |

An elevated run also falls back if the dbatools cmdlet fails or comes back empty (`Get-DbaComputerSystem` returned a
row with no CPU or RAM on some nodes — the "? logical CPU(s), ? RAM" line). A row read the local way says so
("Read with local CIM …"). The skipped privileges row names the identity and what its token held — `BUILTIN\Administrators`
enabled, present only as deny-only (a UAC-filtered token), or not in the token — read by SID from `whoami /groups`.
If it is not in the token although the account is a local Administrator, restart SQL Server Agent: a service reads
its group memberships when it starts. Instant File Initialization and Lock Pages in Memory are graded either way by
*Service account & IFI/LPIM (SQL)*.

### Timeouts (why remote nodes no longer time out)
Three nested caps stop any single check from consuming the whole run:

1. **Per-statement** — `HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS` (60s) is set on the shared SMO `ConnectionContext`.
   Bounds one SQL statement; doesn't bound a *cmdlet* that issues many statements.
2. **Per-cmdlet wall-clock** — `HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS` (120s). Each catalog cmdlet runs in a
   **worker runspace** (dbatools preloaded once via `InitialSessionState.ImportPSModule`). When the cap fires the
   stuck pipeline is **not** waited on: `Stop()` and `Dispose()` both block until a pipeline inside a .NET call
   returns, so the script only asks it to stop (`BeginStop`), closes the runspace asynchronously, opens a **new
   connection and a new worker** for the next check, and records this check as `'error'` ("exceeded per-check
   wall-clock timeout of Ns"). This is what stops the per-DB iteration cmdlets (`Test-DbaIdentityUsage`,
   `Get-DbaLastGoodCheckDb`, `Measure-DbaDbVirtualLogFile`, etc.) from chewing the whole budget on a high-latency
   link — those cmdlets run many statements per cmdlet, so the per-statement cap alone doesn't bound them. Once a
   worker has been abandoned, the script exits the process right after writing its JSON, rather than letting
   PowerShell 7 wait for the abandoned thread. Set to `0` to disable wrapping (every check runs inline; the
   per-statement cap is still in effect).
3. **Per-connect** — `HEALTHCHECK_CONNECT_TIMEOUT_SECONDS` (15s) on `Connect-DbaInstance`, so a dead/slow node
   fails fast instead of stalling the whole run.

**Broken-connection retry.** A check that fails with a connection-state error ("There is already an open
DataReader", "The connection is closed", "Internal connection fatal error", a transport-level error) says nothing
about the check, only about the shared connection, so the script reconnects, builds a new worker, and runs that
check **once more**; a second failure is reported as `'error'`. A timeout is not retried. A check whose cmdlet throws
"Availability Group (HADR) is not configured" is reported as *skipped* with that reason, not as an error. The
wall-clock cap and the retry are pinned by `server/tests/checkRunner.test.ts`.

Combined with skipping dead WinRM checks (the catalog auto-skips OS/CIM cmdlets when no Windows credential is set,
unless `HEALTHCHECK_OS_LOCAL=1`), this keeps remote primaries (remote regions) inside the
`HEALTHCHECK_TIMEOUT_SECONDS` (1800s) ceiling.

Per-check exceptions:
- **Index health (sp_BlitzIndex)** has its own budget: 270 s for the all-databases call (`-QueryTimeout`; without it
  `Invoke-DbaQuery` uses the 60 s per-statement cap, which a large instance can exceed) and 600 s of wall clock. A
  failure that is not a timeout (for example "Arithmetic overflow error converting expression to data type money") is
  retried one database at a time, so one database's error no longer blanks the others. A database that fails on its
  own is retried once more with `@SkipPartitions = 1`: if that works it is reported as a *partial* analysis
  (per-partition findings missing), and if it fails it is *Database Skipped* with both errors and the
  `@Debug = 1` command that finds the failing statement.
- **Instance performance settings** and **Storage I/O latency** take a live sample (10 s and 20 s `WAITFOR`) inside
  the 60 s statement cap. Only the live sample can grade Fail; the lifetime averages since instance start are
  reported beside it and can grade Attention.
- **Last good CHECKDB** and **Identity column capacity** exclude databases this login cannot open when the check runs
  (SUSPECT, RESTORING, a non-readable secondary) and name them; both cmdlets otherwise throw for the whole instance
  ("The database <name> is not accessible").
- **Microsoft SQL Assessment** lists its SystemHealth row "Error 17830 occured N times" but does not grade it:
  *Login resets (Error 17830) by source* grades the same events by cause, from `RING_BUFFER_CONNECTIVITY`.
  The assessment runs in a child PowerShell and only under Windows auth (it is *skipped* under SQL auth, and reports
  its absence when the `SqlServer` module is not installed). On-node it connects with `-TrustServerCertificate`, as
  every dbatools connection in the run does; a remote run validates the certificate. A connection failure reports
  SMO's message and the innermost cause.

### Response shape & report
`run_health_check` returns a **compact** response by default (scored findings, not raw rows); pass
`include_raw_data:true` to embed each check's rows. The self-contained **HTML report** path is returned as
`report.path` (with a note on where it landed). Fail/Attention findings carry **specific, actionable Details** —
they name the offending objects and the fix (e.g. the DBs with `AUTO_SHRINK` on + the `ALTER`, the stale-backup DBs
+ ages + `BACKUP` command, identity columns near max + `BIGINT` advice, high-VLF DBs + shrink/regrow).

## Headless report (scheduled runs)

The same checks and the same HTML run without an MCP client, from `server/src/reportCli.ts`:

```bash
node dist/index.js report --region region1 --recipients dba-team@example.com   # email via Database Mail
node dist/index.js report --instances region1-node1,region1-node2 --dry-run --out ./weekly-health.html
```

| Flag | Meaning |
|---|---|
| `--region <name>` / `--instances a,b` | Which fleet entries to check (witnesses are always excluded). Pass both AG partners to grade *Agent job drift between AG replicas* |
| `--recipients <list>` | Email the report through `msdb.dbo.sp_send_dbmail`; required unless `--dry-run` |
| `--profile <name>` | Database Mail profile (default `DBA Mail Profile`) |
| `--mail-instance <name>` | Instance that sends the mail (default `<region>-primary` with `--region`, else the first target); needs a login that can run `sp_send_dbmail` |
| `--dry-run` [`--out <file>`] | Write the HTML (UTF-16LE with a BOM) instead of emailing; default path is under `HEALTHCHECK_REPORT_DIR` |
| `--auth sql\|windows` | Default `sql` when `SQL_USER`/`SQL_PASSWORD` are set, else `windows` |

The subject line carries the worst status, the Fail/Attention counts, and `INCOMPLETE` when 10% or more of the
checks could not run. `npm run package:report` builds the same CLI into a standalone Windows executable
(`dist/appdb-sql-report.exe`) for nodes without Node.js; it takes the same flags.

## Example prompts
- "Run a health check on `region1-node2` and summarise the failures by category."
- "Health check the `region2` region — any recoverability or reliability risks?"
- "Use `Get-DbaWaitStatistic` on `region1-listener` and tell me the top waits."