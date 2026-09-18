# AppDb SQL MCP — dbatools Health Check

A comprehensive, **read-only** SQL Server health check available to the `sql-dba` profile, built entirely from
read-only `dbatools` cmdlets. Exposed as the tool **`run_health_check`** (plus `run_dbatools_command`,
`list_dbatools_commands`, `get_dbatools_command_help`, `check_dbatools_environment`, and `read_error_log`). The ops profile does not get these tools.

**Crash / instability forensics (sql-dba).** Alongside the health check, the DBA profile can locate evidence on its
own — no manual paths: **`get_log_paths`** (the ERRORLOG directory where `SQLDump*.txt/.mdmp` also land + default
data/log paths), **`get_memory_dumps`** (`sys.dm_server_memory_dumps` — recent dumps, time, size), **`read_error_log`**
(filter the SQL error log for `Stack Dump` / `access violation` / a module name), and **`get_machine_spec`**
(CPU/RAM/NUMA/build/OS/VM type). `list_instances` now also reports each node's **`cloud`** (aws/gcp) so the agent
compares an affected node against a healthy **peer on the same cloud** (diff spec, SQL/OS build, loaded modules) —
spec/capacity is rarely the cause when a smaller/busier same-cloud peer is stable.

## What `run_health_check` runs (42 read-only checks, 8 categories)

| Category | Cmdlets |
|---|---|
| Availability | `Get-DbaAvailabilityGroup`, `Get-DbaAgReplica`, `Get-DbaDatabase`, `Get-DbaAgentJob`*, `Get-DbaDbSpace`, AG data movement (DMV)* |
| Performance | `Get-DbaWaitStatistic`, `Test-DbaMaxDop`*, `Test-DbaMaxMemory`*, `Get-DbaLatchStatistic`, `Test-DbaDbQueryStore` |
| Recoverability | `Get-DbaLastBackup` (informational), `Get-DbaDbRecoveryModel` |
| Reliability | `Get-DbaSuspectPage`*, `Get-DbaLastGoodCheckDb`*, `Measure-DbaDbVirtualLogFile`*, `Test-DbaDbCompatibility`, `Test-DbaIdentityUsage`*, `Test-DbaDbCollation`, Page verify option (DMV)*, `Get-DbaErrorLog` |
| Security | `Get-DbaLogin`, `Test-DbaConnectionAuthScheme`, `Get-DbaInstanceAudit`, `Get-DbaServerRoleMember`* (sysadmin count), `Test-DbaDbOwner` |
| Configuration | `Get-DbaSpConfigure`* (risky options), `Get-DbaTraceFlag`, `Test-DbaOptimizeForAdHoc`*, `Test-DbaBuild`*, TempDB configuration (DMV)* |
| Maintenance | `Find-DbaDbUnusedIndex`, `Find-DbaDbDuplicateIndex` |
| **Host / OS** | `Test-DbaPowerPlan`, `Get-DbaDiskSpace`*, `Get-DbaFirewallRule`, `Get-DbaComputerSystem`, `Get-DbaOperatingSystem`, `Get-DbaPrivilege` **+ SQL-DMV fallbacks:** Disk space (`sys.dm_os_volume_stats`)*, Service account & IFI/LPIM (`sys.dm_server_services` + `sys.dm_os_sys_info`)*, Operating system (`sys.dm_os_windows_info`) |

`*` = **graded** (Pass/Attention/Fail). The rest are informational inventory. **Backups are informational** — in an
AG they're taken on the backup-preferred (secondary) replica, so per-node local history isn't a reliable signal;
the Details still list per-DB last-backup age + recovery model and point to the backup replica.

**SQL-DMV host fallbacks** run over the **SQL login alone** (no WinRM/CIM), so disk space, OS and service-account
facts (incl. IFI / Lock-Pages-in-Memory) are available even when the Windows checks can't reach the node. Power
plan and firewall have no SQL equivalent — those still need a Windows credential.

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
| **Info** | inventory (`ok`/`empty`) **or** a check that couldn't run (`error`) | excluded from scoring |

**Health %** = priority-weighted average of the scored checks (High=3, Medium=2, Low=1) — per category and overall.
Informational checks never lower the score. `run_health_check` returns, per instance: `overall_health`,
`status_counts` (Pass/Attention/Fail/Info), `categories` (`{ name, health, counts }`), and `findings`
(`{ category, label, command, spoke, priority, status, details, rows }`) — plus the raw `checks[].data` rows for
drill-down unless `summary_only:true`. Scope with `instance_name` or `region`.

### HTML report (looks like the dbatools report)
By default (`html_report:true`) it also writes a **self-contained HTML report** — overall health donut, per-category
cards, an instances table, and an all-findings table (Category · Label · dbatools function · Spoke · Priority ·
Status · Details) with red/amber/green scoring — and returns its path as `report_path`. The file is written to
`HEALTHCHECK_REPORT_DIR` (default: the OS temp dir; set it to keep reports somewhere durable). No external assets —
open it in any browser. See `sample-health-report.html` for the layout.

## Strictly read-only — how
1. **Hard allowlist** — only `Get-/Test-/Measure-/Find-Dba*` (+ `Invoke-DbaDiagnosticQuery`) ever run; the catalog
   is validated against this at load.
2. **Write-in-disguise denylist** — `Test-DbaLastBackup` is **blocked**: despite its `Test-` verb it *restores* a
   copy of each backup to verify it (a write). Backup currency is read via `Get-DbaLastBackup` instead.
3. **Connection** — `Connect-DbaInstance -ApplicationIntent ReadOnly -TrustServerCertificate`.

## Authentication
- **SQL checks** default to **SQL auth** via `HEALTHCHECK_SQL_USER`/`HEALTHCHECK_SQL_PASSWORD` (your own read-only DBA login), falling
  back to `SQL_USER`/`SQL_PASSWORD`. Cloud nodes are generally not reachable via Windows/Kerberos from a
  workstation, so SQL auth is the working path. Pass `auth:'windows'` to use the operator's AD account.
  > Use **your own** read-only DBA login (not a shared/sysadmin account such as `sa`) so every check is
  > attributable to you. The check is read-only regardless — it runs read cmdlets exclusively and blocks
  > `Test-DbaLastBackup` (which restores).
- **OS/CIM checks** (power plan, disk, firewall, computer/OS) read via CIM/WMI and need **Windows access** to the
  node — set `HEALTHCHECK_WIN_USER`/`HEALTHCHECK_WIN_PASSWORD`. Without it they run as the host's own identity; if
  the node is unreachable that way (typical for cloud over SQL-only), those specific checks return `status:"error"`
  and the SQL checks still run fully. (Disk free space + I/O latency are also independently available over SQL via
  the DMV tool `get_file_io_stats`.)
- Passwords are supplied via environment only — never stored in a file.

## Prerequisites
- PowerShell 5.1+ (Windows PowerShell is fine; PS7 optional via `PWSH_EXE`).
- `dbatools` ≥ 2.7 : `Install-Module dbatools -Scope CurrentUser`.
- Verify with the `check_dbatools_environment` tool.

## Configuration
| Variable | Default | Meaning |
|---|---|---|
| `DBATOOLS_ENABLED` | `true` | Set `false` to hide these tools where PowerShell/dbatools isn't installed |
| `PWSH_EXE` | `powershell` (Win) | PowerShell host; `pwsh` for PS7 |
| `HEALTHCHECK_SQL_USER` / `_PASSWORD` | `SQL_USER`/`SQL_PASSWORD` | SQL login for the health check (your own read-only DBA login) |
| `HEALTHCHECK_WIN_USER` / `_PASSWORD` | — | Windows login on the node for OS/CIM checks (power plan/disk/firewall/OS). With it set, those checks connect to the configured host/IP via **NTLM**, avoiding the Kerberos/WinRM double-hop that otherwise fails |
| `DBATOOLS_TIMEOUT_SECONDS` | `120` | Timeout for `run_dbatools_command` |
| `HEALTHCHECK_TIMEOUT_SECONDS` | `1800` | Overall (per-instance) ceiling for `run_health_check` |
| `HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS` | `60` | Per-SQL-query cap on the shared SMO connection |
| `HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS` | `120` | Wall-clock cap on each catalog cmdlet (worker runspace; set 0 to disable) |
| `HEALTHCHECK_CONNECT_TIMEOUT_SECONDS` | `15` | Connect cap, so a dead/slow node fails fast |
| `HEALTHCHECK_REPORT_DIR` | OS temp dir | Where the HTML report is written (`report.path`) |
| `DBATOOLS_MAX_OUTPUT_MB` | `64` | PowerShell stdout cap; rows are scalar-flattened so this is rarely approached |

### OS/CIM checks (power plan, disk, firewall, OS)
These need a Windows login on the target node. Set `HEALTHCHECK_WIN_USER` (e.g. `example\\someuser`) and
`HEALTHCHECK_WIN_PASSWORD` — the checks then target the **configured host/IP** with that credential (NTLM), which is
what makes them work when Kerberos/WinRM to the node name fails.

**Without a Windows credential these WinRM checks are SKIPPED (status `skipped` → Info), not attempted** — because
they can't succeed and, against a remote node, an attempt can hang long enough to blow the overall timeout (this was
why remote regions runs timed out). The SQL-DMV fallbacks still report disk/OS/service-account over the SQL login, and the
response's `notes` says which credential to set to enable power-plan and firewall too.

### Timeouts (why remote nodes no longer time out)
Three nested caps stop any single check from consuming the whole run:

1. **Per-statement** — `HEALTHCHECK_STATEMENT_TIMEOUT_SECONDS` (60s) is set on the shared SMO `ConnectionContext`.
   Bounds one SQL statement; doesn't bound a *cmdlet* that issues many statements.
2. **Per-cmdlet wall-clock** — `HEALTHCHECK_PER_CHECK_TIMEOUT_SECONDS` (120s). Each catalog cmdlet runs in a
   **worker runspace** (dbatools preloaded once via `InitialSessionState.ImportPSModule`); when the cap fires the
   running pipeline is `Stop()`'d, that check errors as `'error'`, and the worker is recycled for the next check.
   This is what stops the per-DB iteration cmdlets (`Find-DbaDbUnusedIndex`, `Find-DbaDbDuplicateIndex`,
   `Test-DbaIdentityUsage`, etc.) from chewing the whole budget on a high-latency link — those cmdlets run many
   statements per cmdlet, so the per-statement cap alone doesn't bound them. Set to `0` to disable wrapping
   (every check runs inline; the per-statement cap is still in effect).
3. **Per-connect** — `HEALTHCHECK_CONNECT_TIMEOUT_SECONDS` (15s) on `Connect-DbaInstance`, so a dead/slow node
   fails fast instead of stalling the whole run.

Combined with skipping dead WinRM checks (the catalog auto-skips OS/CIM cmdlets when `HEALTHCHECK_WIN_USER` is
unset), this keeps remote primaries (remote regions) inside the `HEALTHCHECK_TIMEOUT_SECONDS` (1800s) ceiling.

### Response shape & report
`run_health_check` returns a **compact** response by default (scored findings, not raw rows); pass
`include_raw_data:true` to embed each check's rows. The self-contained **HTML report** path is returned as
`report.path` (with a note on where it landed). Fail/Attention findings carry **specific, actionable Details** —
they name the offending objects and the fix (e.g. the DBs with `AUTO_SHRINK` on + the `ALTER`, the stale-backup DBs
+ ages + `BACKUP` command, identity columns near max + `BIGINT` advice, high-VLF DBs + shrink/regrow).

## Example prompts
- "Run a health check on `region1-node2` and summarise the failures by category."
- "Health check the `uk` region (summary only) — any recoverability or reliability risks?"
- "Use `Get-DbaWaitStatistic` on `region1-listener` and tell me the top waits."