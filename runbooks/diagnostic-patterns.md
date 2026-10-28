# Runbook — Diagnostic patterns (symptom → hypothesis cookbook)

A pattern library, not a tuning guide. For each symptom shape, this names the most likely causes ranked by base rate in this fleet, the specific MCP tool calls to confirm or deny, and the common wrong-answers to avoid.

The patterns are intentionally **specific to one fleet profile** — distributed AG topology, Lock Pages in Memory enabled, third-party ODBC linked servers, the EDR agent injection, GCP/AWS mix. Generic SQL Server tuning advice is not repeated here; see Microsoft Learn for that.

---

## How to use this doc

When a symptom is reported, find the matching pattern. Each entry has:
- **Signal** — what you observe
- **Most likely cause** — ordered by base rate in this fleet, not by SQL Server textbook frequency
- **Confirm via** — specific MCP tools and queries
- **Common wrong answer** — the hypothesis that *feels* right but usually isn't
- **Notes** — fleet-specific context

---

## CPU patterns

### CPU at 100% sustained, queries timing out
- **Most likely cause:** A single bad plan or a recent stat update changed an estimate and the optimizer picked a scan/loop join where it used to seek. Or one runaway query is dominating.
- **Confirm via:** `get_active_sessions` (sort by CPU), `get_top_queries` (`order_by: cpu` — plan-cache totals since each plan was cached, not a time window), `get_query_store_regressions` for the affected DB. Look for one or two queries dominating, not a fleet-wide pattern.
- **Common wrong answer:** "We need more CPU." Resizing the instance hides a single-bad-plan root cause and the new instance will have the same problem in two weeks. Find the query first.
- **Notes:** With Lock Pages in Memory the buffer pool can't shrink to absorb pressure, so CPU stays at 100% rather than swapping out. That's a feature, not a symptom.

### CPU climbing slowly over hours/days, never recovers
- **Most likely cause:** Plan cache pollution (lots of ad-hoc plans), or a memory clerk leak driving compilation pressure. Less commonly: a sessions/connections leak.
- **Confirm via:** `get_plan_cache_pollution`, `get_memory_usage` (look at `CACHESTORE_SQLCP` size growth), `get_active_sessions` with `include_sleeping: true` for long-idle sessions.
- **Common wrong answer:** "Restart SQL Server." Works but doesn't explain why. If you don't find the source, it'll recur. Restart is the immediate fix, not the resolution.

### CPU bursts that correlate with backup/maintenance jobs
- **Most likely cause:** Ola Hallengren `IndexOptimize` or `DatabaseIntegrityCheck` overlapping with peak workload. Check `dbo.CommandLog` for runtimes.
- **Confirm via:** `get_job_status`, `execute_query` against `dbo.CommandLog`, correlate with `get_cpu_history`.
- **Notes:** Ola jobs are vendor code; tune the calling job's parameters (e.g. `@TimeLimit`, `@MaxDOP`) instead of the procedure.

---

## Memory patterns

### `MemoryLoad` reaches >90% on a server with Lock Pages in Memory enabled
- **Most likely cause:** Non-buffer-pool growth inside `sqlservr.exe` (linked-server providers, CLR, XEvent buffers) or OS-side pressure (EDR, antivirus, agents). The buffer pool is locked and can't shrink.
- **Confirm via:** `get_memory_usage`, then `execute_query` of `sys.dm_os_memory_clerks` ordered desc excluding `MEMORYCLERK_SQLBUFFERPOOL`. Compare against `region1-node2`.
- **Common wrong answer:** "Lower `max server memory`." This makes the locked pool smaller while non-BPool keeps growing — it makes things worse.
- **Notes:** See [`memory-pressure.md`](memory-pressure.md) for the full decision tree.

### `PAGEIOLATCH_SH` dominating waits, page life expectancy dropping
- **Most likely cause:** Buffer pool churn — query reading more pages than fit, often a scan caused by a missing or unused index, or by a parameter-sensitivity plan.
- **Confirm via:** `get_wait_stats` (cumulative since startup — bound it to the incident window with the snapshot diff in [`performance-investigation.md`](performance-investigation.md) §3), `get_top_queries` with `order_by: reads`, `get_missing_indexes` for the affected DB.
- **Common wrong answer:** "Disk is slow." Sometimes true (`get_file_io_stats` to confirm), but usually it's a query reading too much.

### Plan cache wiped repeatedly, ad-hoc plans dominate
- **Most likely cause:** `optimize for ad hoc workloads` is off, or the workload is genuinely ad-hoc (e.g. from a BI tool generating one-off queries). Check via `get_plan_cache_pollution`.
- **Confirm via:** `Test-DbaOptimizeForAdHoc` (in `run_health_check`) or `get_plan_cache_pollution`.
- **Notes:** Don't enable `optimize for ad hoc workloads` blindly — it can mask the actual problem (an app generating non-parameterized SQL). If the app team can parameterize, that's the better fix.

---

## I/O patterns

### Log file I/O latency >20ms (`WRITELOG` waits high)
- **Most likely cause:** AG synchronous-commit secondary is slow to harden, AG transit, or log file on slow storage. In this fleet with distributed AGs, latency between `ag-X-cluster` and `ag-X-forwarder` accumulates.
- **Confirm via:** `get_file_io_stats` for the log file, `get_wait_stats` for `HADR_SYNC_COMMIT` and `WRITELOG` (cumulative — diff two samples for the window), `get_ag_health` for `log_send_queue_kb`.
- **Common wrong answer:** "Move to faster disk." Often the actual bottleneck is the secondary, not the primary's disk.
- **Notes:** when regions run on different clouds, cross-region log shipping is bounded by network latency, not local disk.

### Data file read latency >20ms intermittently
- **Most likely cause:** Backup window contention (Ola `DatabaseBackup` reading from the same file), or another agent scanning files (antivirus, EDR file scans, monitoring agents).
- **Confirm via:** `get_file_io_stats` correlated with `get_job_status` timestamps. `get_perfmon_counters` returns SQL Server's own counters (`sys.dm_os_performance_counters`), not Windows-side disk counters — read those on the host.
- **Notes:** the EDR agent has been observed to slow file I/O on hosts with file-scan rules enabled. Confirm with SecOps that DB file paths are excluded.

### TempDB file I/O latency, PAGELATCH_UP on `2:1:1` / `2:1:2` / `2:1:3`
- **Most likely cause:** TempDB allocation contention. PFS / GAM / SGAM page contention.
- **Confirm via:** `get_latch_stats` (look for PAGELATCH_UP on database_id=2), `get_tempdb_usage`.
- **Notes:** The standard fix is multiple equal-sized tempdb data files. Trace flags 1117/1118 matter only on SQL Server 2014 and earlier; from SQL Server 2016 tempdb grows all files together and allocates uniform extents by default, and the flags have no effect. Check what's already configured (`get_database_files` for tempdb) before changing.

---

## Blocking & locking patterns

### Long blocking chain with one head at the top
- **Most likely cause:** An open transaction holding locks — usually an application connection that opened a transaction and forgot to commit, or a long-running update with poor predicates.
- **Confirm via:** `get_blocking_chains` — the head is the `blocking_session_id` that never appears as a `blocked_session_id`; its `blocker_login`, `blocker_host`, `blocker_program` and `blocker_sql_text` come back in the same rows. Then `get_active_sessions` (`include_sleeping: true` if it is idle) for that spid.
- **Common wrong answer:** Killing the head blocker without understanding what it's doing. If it's a long write, you may roll back significant work. Capture the query first.
- **Notes:** See [`blocking-and-deadlocks.md`](blocking-and-deadlocks.md).

### Many short blocking events, no consistent head
- **Most likely cause:** Lock escalation under a hot table, often when row-level locks are escalated to table-level. Or default `READ COMMITTED` blocking with long readers.
- **Confirm via:** `get_blocking_chains` snapshots over time (or `get_hiq` with `blocking: 'blockers'` for a past window). `get_blocking_chains` has no lock-resource column; to see whether it is the same object repeatedly, `execute_query` `sys.dm_exec_requests.wait_resource` for the blocked sessions. Check whether `is_read_committed_snapshot_on` is set on the DB.
- **Notes:** RCSI is the durable fix for read-heavy workloads being blocked by writers — but it has tempdb implications.

### Deadlocks (XDL graph in ERRORLOG or alerts)
- **Confirm via:** `get_deadlock_history`, parse the XDL graph for the resources and statements involved.
- **Most likely cause:** Two queries acquiring locks in different orders on the same set of objects. Standard pattern: one updates `A` then `B`, another updates `B` then `A`.
- **Fix patterns:** Add covering indexes to shorten lock hold time; serialize via app-level locks; rewrite to acquire locks in consistent order.

---

## AG / HADR patterns

### `synchronization_health_desc` shows `NOT_HEALTHY` or `PARTIALLY_HEALTHY`
- **Most likely cause:** Either a transient network blip (recovers in seconds), a secondary that's behind on redo (look at `redo_queue_kb` and `redo_rate`), or a database that's not healthy on the secondary.
- **Confirm via:** `get_ag_health`, then check `redo_queue_kb` and `log_send_queue_kb` — these are the actual lag metrics.
- **Notes:** Healthy is not the same as "caught up." A small log_send_queue is normal under load.

### Frequent automatic failovers
- **Most likely cause:** A crash on the primary (`get_memory_dumps`, `read_sql_dump action='list'`, `read_error_log` with `log_number: 1` for the log before the restart), aggressive cluster health-check thresholds, or transient network issues triggering quorum loss.
- **Confirm via:** Cluster log (`read_cluster_reports`, or `generate_cluster_log` to render a fresh one with `Get-ClusterLog`), ERRORLOG for what happened before the failover.
- **Notes:** Failover isn't a fault — it's a feature working. The fault is whatever crashed the primary.

### Distributed AG forwarder lag (`ag-X-forwarder` databases behind)
- **Most likely cause:** The forwarder consumes a global commit, so it's bound by the slowest of the cross-region links. Saturation at one region propagates to the others.
- **Confirm via:** `get_ag_health` on the forwarder; `get_file_io_stats` for the LOG on both ends.
- **Notes:** Distributed AGs cross GCP↔AWS in this fleet, so the latency floor is network-bound. Don't expect <1s lag cross-region.

---

## Backup / recovery patterns

### "Full backup didn't run last night"
- **Most likely cause:** Backups are taken on the backup-preferred replica, not the primary. Per-node `get_backup_status` can show "stale" for a node that isn't supposed to back up.
- **Confirm via:** Run `get_backup_status` against each AG replica. The successful one is the backup-preferred replica.
- **Notes:** This is the #1 false alarm in this fleet's backup monitoring. AG-aware monitoring needs to aggregate across replicas.

### Last good DBCC CHECKDB > 7 days
- **Most likely cause:** CHECKDB is offloaded to a secondary or runs weekly, not daily. Or it's been disabled because it was painful and never re-enabled.
- **Confirm via:** `run_health_check` includes this check (`Get-DbaLastGoodCheckDb`).
- **Notes:** Don't lower the cadence to make the check pass. Either move CHECKDB to a secondary or to a copy-restored sandbox.

---

## Query Store patterns

### "Query Store is in `READ_ONLY` state"
- **Most likely cause:** Either it hit `MAX_STORAGE_SIZE_MB`, or it was set read-only manually. Hit storage is more common in this fleet.
- **Confirm via:** `execute_query` against `sys.database_query_store_options` for the DB, or `run_health_check` / `Test-DbaDbQueryStore`.
- **Notes:** Alert on `current_storage_size_mb` / `max_storage_size_mb` well before it reaches 100% (for example at 80% and 90%). Bump `MAX_STORAGE_SIZE_MB` or shorten `STALE_QUERY_THRESHOLD_DAYS`.

### "Plans regressed after the deploy"
- **Most likely cause:** The deploy changed parameter values, recompiled statistics, or changed query shape. Plan choice diverged from the prior shape.
- **Confirm via:** `get_query_store_regressions` for the DB; over the last 7 days it returns queries whose most recent plan's average duration is at least `min_regression_pct` (default 50%) worse than the fastest other plan for the same query, with `recent_plan_id` and `best_plan_id`. Check `recent_last_exec` against the deploy time yourself — the tool does not know when the deploy happened.
- **Fix patterns:** Force a known-good plan via `sp_query_store_force_plan` — captures the plan_id from Query Store. Reversible (`sp_query_store_unforce_plan`).

---

## Connection / login patterns

### "Cannot connect to GCP NLB"
- **Most likely cause:** Hostname resolution. The GCP load balancers in this fleet (`region2-listener`, `region3-listener`) are IP-only — no DNS.
- **Confirm via:** `fleet.json` has the correct IP. `ping <ip>` from the client.
- **Notes:** Use `Encrypt=True;TrustServerCertificate=True` because the IP doesn't match the cert SAN.

### "Connection works but no databases visible"
- **Most likely cause:** The login is on the wrong replica for read-only intent, or `ApplicationIntent=ReadOnly` is missing. In the distributed AG topology you must specify `Database=AppCatalog` (or the relevant DB).
- **Confirm via:** Check connection string, verify with `sys.dm_exec_connections`.

---

## "It's a [name a famous SQL Server feature]" — usually it isn't

A few hypotheses that always feel right but are rarely the answer in this fleet:

| Hypothesis | Why it's usually wrong here |
|---|---|
| "It's stats out of date" | Auto-stats is on; Ola updates statistics nightly. Stale stats *does* happen, but check `get_statistics_health` before claiming this. |
| "It's index fragmentation" | Modern SSDs make logical fragmentation low-impact. `get_index_fragmentation` is for awareness; only act if a specific query is paying the cost. |
| "It's parallelism / MAXDOP" | `Test-DbaMaxDop` runs in `run_health_check`. If it doesn't flag, MAXDOP isn't the issue. |
| "It's tempdb file count" | Standard recommendation is 4–8 equal files; check existing first via `get_database_files` for tempdb. Usually already set. |
| "It's autoclose / autoshrink" | Both flagged by `run_health_check`. If unflagged, this isn't it. |
| "It's RCSI not enabled" | If you're seeing read/write blocking, *consider* it. But check that the app isn't relying on read-committed-with-locks semantics first. |

---

## Cross-reference

When a pattern matches, route to the specific runbook for the deeper procedure:

| Pattern class | Detailed runbook |
|---|---|
| Engine crash / AV | No dedicated runbook. Restore service first ([`service-restoration-first.md`](service-restoration-first.md)), then the crash playbook built into the forensic tools' descriptions: `get_log_paths` → `get_memory_dumps` → `read_error_log` → `read_sql_dump` → `get_host_event_log` → `get_host_dll_versions`, compared against a healthy peer ([`evidence-discipline.md`](evidence-discipline.md)) |
| Performance / slow queries | [`performance-investigation.md`](performance-investigation.md) |
| Blocking / deadlocks | [`blocking-and-deadlocks.md`](blocking-and-deadlocks.md) |
| Memory pressure | [`memory-pressure.md`](memory-pressure.md) |
| AG health / failover | No dedicated runbook. The failover gate is in [`service-restoration-first.md`](service-restoration-first.md); health is `get_ag_health` (local AG) and `get_distributed_ag_health` (distributed AG) |
| TempDB contention | No dedicated runbook — the TempDB pattern above |
| How to investigate generally | [`investigation-methodology.md`](investigation-methodology.md) |
| How to argue from evidence | [`evidence-discipline.md`](evidence-discipline.md) |
