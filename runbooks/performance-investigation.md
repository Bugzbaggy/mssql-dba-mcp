# Runbook — Performance investigation (slow queries, regressions, server feels slow)

**Use this when:** A user reports queries are slow, a workload regressed, or "the server feels slow." Most-common SQL Server incident class after blocking. Distinct from `sql-crash-investigation.md` (engine AVs) and [`blocking-and-deadlocks.md`](blocking-and-deadlocks.md) (locking).

## TL;DR — first 5 minutes

1. **Bound the symptom in time.** "Slow since when?" If they can't answer, recover from `get_cpu_history` + `xp_readerrorlog` for the suspected window.
2. **Decide if it's one query or the whole server.** `get_active_sessions` sorted by CPU/duration tells you which.
3. **Pick the right tool for that branch** — see §1 below.
4. **Get a workload-window-bounded wait profile.** `get_wait_stats` since-startup is noise; the symptom-window slice is the signal.
5. **Form one hypothesis, test it cheap, validate via control if possible.** See [`investigation-methodology.md`](investigation-methodology.md) §5.

---

## 1. The single most important branch: one query vs. whole server

Almost every performance investigation forks here. Pick the wrong branch and you waste an hour.

### Branch A — "This specific query is slow"

Most likely causes, ranked:
1. **Bad plan** (parameter sniffing, missing/unused index, recent stats change).
2. **Plan eviction + recompile cost** under memory pressure.
3. **Blocking on the query's target** — even though the *symptom* is "slow," the cause is lock waits.

Tools, in order:
- `get_top_queries` filtered to the affected DB and recent window → confirm the query's recent execution stats.
- `get_query_store_regressions` for the DB → if it's a regression, Query Store has the before/after plan.
- `get_blocking_chains` → eliminate blocking as the cause before chasing plans.
- For the specific query, get its plan: `execute_query` against `sys.dm_exec_query_plan(plan_handle)` or via Query Store `sys.query_store_plan`.

Fix patterns (smallest-first, per [`investigation-methodology.md`](investigation-methodology.md) §7):
- **Force a known-good plan** via Query Store (`sp_query_store_force_plan`). Most reversible. The right first move when a deploy regressed a plan.
- **Update statistics** on the relevant table if `get_statistics_health` shows stale stats *and* the plan choice depends on cardinality estimates the stats can't see.
- **Add a missing index** via `get_missing_indexes` — but cross-check with `get_index_usage_stats` for the same table to avoid index bloat. Only add an index if (a) the suggestion has a high improvement_measure and (b) the table doesn't already have 6+ indexes.
- **Rewrite the query** (last resort because it requires app team coordination).

### Branch B — "Whole server / workload feels slow"

Most likely causes, ranked:
1. **Resource bottleneck** — CPU, memory, or I/O.
2. **Blocking storm** affecting many queries.
3. **TempDB contention** — affects everything that uses temp objects.
4. **Plan cache pollution** — high compilation rate, cache flush.
5. **External pressure** — backups, antivirus, EDR file scans, OS-level work.

Tools, in order:
- `get_cpu_history` → if CPU is near 100%, branch into top-N CPU queries via `get_top_queries` and `get_active_sessions`.
- `get_wait_stats` **filtered to the incident window** → top waits tell you which subsystem is the bottleneck. See §2.
- `get_blocking_chains` → eliminate broad blocking.
- `get_memory_usage` → if Page Life Expectancy dropping or non-BPool memory climbing, route to [`memory-pressure.md`](memory-pressure.md).
- `get_tempdb_usage` + `get_latch_stats` → if PAGELATCH waits on `2:1:*` dominate, route to TempDB contention.

---

## 2. Wait-stat triage (the 60-second decoder)

`get_wait_stats` filtered to the incident window is the most informationally-dense tool for "whole server is slow." This table maps the top wait to the most likely investigation branch.

| Top wait | Most likely cause | Next tool |
|---|---|---|
| `CXCONSUMER`, `CXPACKET` | Query parallelism — usually a single big query, not a server-wide issue. | `get_top_queries` for high CPU + parallel queries |
| `PAGEIOLATCH_SH`, `PAGEIOLATCH_EX` | Reading from disk — buffer pool churn or slow disk. | `get_file_io_stats`; if disk is OK, `get_top_queries` for high logical reads |
| `PAGELATCH_UP` on `2:1:1` / `2:1:2` / `2:1:3` | TempDB allocation contention | `get_tempdb_usage`, then add tempdb files if needed |
| `WRITELOG` | Log write latency — disk, AG sync, or large transactions | `get_file_io_stats` for log file; `get_ag_health` for sync state |
| `HADR_SYNC_COMMIT` | Synchronous AG secondary is slow to harden | `get_ag_health` (log_send_queue, redo_queue); check secondary I/O |
| `LCK_M_*` | Blocking — read `_S`, write `_X`, etc. | `get_blocking_chains` |
| `RESOURCE_SEMAPHORE` | Memory grant wait — queries asking for more memory than available | `get_top_queries` for high memory grants; check `max server memory` headroom |
| `THREADPOOL` | Worker thread exhaustion — usually a blocking storm hidden as starvation | `get_blocking_chains` immediately |
| `ASYNC_NETWORK_IO` | Client is slow to consume results — usually app-side, not SQL | App team; check client connection patterns |
| `OLEDB` | Linked-server query in progress | `get_active_sessions` to find the query; usually third-party ODBC |
| `SOS_SCHEDULER_YIELD` | CPU pressure or runaway query | `get_active_sessions` sorted by CPU |
| `BACKUP*`, `BACKUPIO`, `BACKUPBUFFER` | Backup running and contending | `get_job_status`, `get_backup_status` |

If the top wait doesn't match any of these, it's likely a long-tail wait — search Microsoft docs for the specific name before assuming it's pathological.

---

## 3. Bounding waits to the incident window (critical step)

`sys.dm_os_wait_stats` is cumulative since instance start. If uptime is 100+ days, the top waits reflect 100 days of normal load and tell you nothing about today's incident. To get the right answer, sample twice and diff.

```sql
-- Snapshot 1 — run before the workload
SELECT wait_type, waiting_tasks_count, wait_time_ms, signal_wait_time_ms
INTO #wait_before
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'CLR_AUTO_EVENT','CLR_MANUAL_EVENT','CLR_SEMAPHORE','DBMIRROR_DBM_EVENT',
    'DBMIRROR_EVENTS_QUEUE','DBMIRROR_WORKER_QUEUE','DBMIRRORING_CMD',
    'DIRTY_PAGE_POLL','DISPATCHER_QUEUE_SEMAPHORE','EXECSYNC',
    'FSAGENT','FT_IFTS_SCHEDULER_IDLE_WAIT','FT_IFTSHC_MUTEX',
    'HADR_FILESTREAM_IOMGR_IOCOMPLETION','HADR_LOGCAPTURE_WAIT',
    'HADR_NOTIFICATION_DEQUEUE','HADR_TIMER_TASK','HADR_WORK_QUEUE',
    'KSOURCE_WAKEUP','LAZYWRITER_SLEEP','LOGMGR_QUEUE','MEMORY_ALLOCATION_EXT',
    'ONDEMAND_TASK_QUEUE','PARALLEL_REDO_DRAIN_WORKER','PARALLEL_REDO_LOG_CAPTURE',
    'PARALLEL_REDO_TRAN_LIST','PARALLEL_REDO_WORKER_SYNC','PARALLEL_REDO_WORKER_WAIT_WORK',
    'PREEMPTIVE_HADR_LEASE_MECHANISM','PREEMPTIVE_SP_SERVER_DIAGNOSTICS',
    'PREEMPTIVE_OS_LIBRARYOPS','PREEMPTIVE_OS_COMOPS','PREEMPTIVE_OS_CRYPTOPS',
    'PREEMPTIVE_OS_PIPEOPS','PREEMPTIVE_OS_AUTHENTICATIONOPS',
    'PREEMPTIVE_OS_GENERICOPS','PREEMPTIVE_OS_VERIFYTRUST','PREEMPTIVE_OS_FILEOPS',
    'PREEMPTIVE_OS_DEVICEOPS','PREEMPTIVE_OS_QUERYREGISTRY','PREEMPTIVE_OS_WRITEFILE',
    'PREEMPTIVE_XE_GETTARGETSTATE','PWAIT_ALL_COMPONENTS_INITIALIZED',
    'PWAIT_DIRECTLOGCONSUMER_GETNEXT','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP',
    'QDS_ASYNC_QUEUE','QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
    'REQUEST_FOR_DEADLOCK_SEARCH','RESOURCE_QUEUE','SERVER_IDLE_CHECK',
    'SLEEP_BPOOL_FLUSH','SLEEP_DBSTARTUP','SLEEP_DCOMSTARTUP','SLEEP_MASTERDBREADY',
    'SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED','SLEEP_MSDBSTARTUP',
    'SLEEP_SYSTEMTASK','SLEEP_TASK','SLEEP_TEMPDBSTARTUP','SNI_HTTP_ACCEPT',
    'SP_SERVER_DIAGNOSTICS_SLEEP','SQLTRACE_BUFFER_FLUSH','SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
    'SQLTRACE_WAIT_ENTRIES','WAIT_FOR_RESULTS','WAITFOR','WAITFOR_TASKSHUTDOWN',
    'WAIT_XTP_RECOVERY','WAIT_XTP_HOST_WAIT','WAIT_XTP_OFFLINE_CKPT_NEW_LOG',
    'WAIT_XTP_CKPT_CLOSE','XE_DISPATCHER_JOIN','XE_DISPATCHER_WAIT',
    'XE_TIMER_EVENT'
);

-- Wait the symptom window (e.g. 10 minutes)
WAITFOR DELAY '00:10:00';

-- Snapshot 2 + diff
SELECT TOP 10
    a.wait_type,
    a.waiting_tasks_count - b.waiting_tasks_count AS tasks_delta,
    a.wait_time_ms - b.wait_time_ms AS wait_ms_delta,
    (a.wait_time_ms - b.wait_time_ms) -
        (a.signal_wait_time_ms - b.signal_wait_time_ms) AS resource_wait_ms_delta
FROM sys.dm_os_wait_stats a
JOIN #wait_before b ON a.wait_type = b.wait_type
WHERE a.wait_time_ms > b.wait_time_ms
ORDER BY wait_ms_delta DESC;

DROP TABLE #wait_before;
```

`get_wait_stats` from this MCP exposes the cumulative shape, which is useful but not symptom-window-bounded. For an active incident, run the snapshot diff above via `execute_query`.

---

## 4. The plan-regression checklist

If the symptom is "queries got slow around the time of [deploy/patch/CU upgrade]":

1. **Identify the regressed query.** `get_query_store_regressions` for the affected DB returns queries whose duration / CPU / logical reads got materially worse.
2. **Get the prior good plan_id.** From Query Store, both the regressed plan and prior plan_ids are available.
3. **Force the prior plan as a stopgap:**
   ```sql
   EXEC sp_query_store_force_plan @query_id = <q>, @plan_id = <prior>;
   ```
   This is fully reversible (`sp_query_store_unforce_plan`) and ships visibility immediately.
4. **Decide on the durable fix.** Sometimes the regressed plan is correct for the *new* workload (e.g. a deploy that genuinely changed data distribution). In that case, update statistics, add an index, or accept the new plan.
5. **Validate via Query Store** that the forced plan's runtime stats match the pre-regression baseline.

This is the highest-leverage fix when a deploy regresses something. It's reversible at any time, doesn't require an app change, and tells you exactly what changed.

---

## 5. Workload comparison via fan-out

When a region's primary is slow but its read-only secondary or a peer region's primary is fine, fan-out comparison reveals what's different. Run via `fan_out_query`:

```sql
-- Currently-executing workload shape
SELECT
    DB_NAME(database_id) AS db,
    COUNT(*) AS active_requests,
    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running,
    SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended,
    MAX(total_elapsed_time)/1000 AS longest_running_sec
FROM sys.dm_exec_requests
WHERE session_id > 50
GROUP BY database_id;
```

If `suspended` count is high on the slow node but not on the peer, blocking is the cause. If `running` is high and `longest_running_sec` is high, it's a runaway query.

---

## 6. What this runbook does *not* cover

- **Engine crashes** — see `sql-crash-investigation.md`.
- **Pure blocking storms** — see [`blocking-and-deadlocks.md`](blocking-and-deadlocks.md).
- **Memory pressure narratives** — see [`memory-pressure.md`](memory-pressure.md).
- **AG-specific lag** — see `ag-health-and-failover.md`.
- **Index design choices** in general — that's outside an incident; do it via deliberate review with the app team.

---

## Cases

### Case 1 — "Reports are slow after the Friday deploy"

**Symptom.** Two hour spike in customer-reported slow load of analytics dashboards. Started within 10 minutes of a routine app deploy.

**First call.** `get_query_store_regressions` for `AppDb_Analytics`. Returned 3 queries with 10×–40× duration increase post-deploy. All hit the same fact table.

**Diagnosis.** The deploy had updated row counts via a backfill. The optimizer recompiled and picked a hash-join plan where the prior plan was a nested-loop with a covering index. New plan was correct for some parameter values, terrible for the dashboard's typical parameter range (parameter sensitivity).

**Fix.** Forced the prior plan via `sp_query_store_force_plan` for the 3 regressed queries. Validation: dashboard load time back to baseline within 90 seconds (Query Store applies forced plans on next compile, which is on next call).

**Durable resolution.** Filed a ticket with the data team to either parameter-sniff-hint the query or partition the fact table by the dashboard's filter column.

**Lesson.** A 5-minute Query Store check beat a 4-hour wait-stat analysis. Always check Query Store regressions when "slow since a deploy."

### Case 2 — "Server feels slow but no single query stands out"

**Symptom.** Application 99p latency doubled. No single query in `get_top_queries` was unusually slow; `get_blocking_chains` returned empty.

**First call.** Wait-stat snapshot diff (§3) over a 10-minute window. Top wait was `PAGELATCH_UP` on `2:1:1` (PFS) by a wide margin.

**Diagnosis.** TempDB allocation contention. Workload had shifted to use more temporary objects after the deploy (some new ORM-generated `#temp` tables in a hot code path).

**Fix.** Added 4 more tempdb data files (existing 4 → 8), equal-sized, on the same drive. Enabled trace flag 1118 already by default. Latch waits dropped to <5% of previous within 15 minutes.

**Lesson.** "No slow query" + high latch waits on tempdb PFS pages = tempdb file count. The wait-stat diff would have pointed here in a single tool call if anyone had run it first.

### Case 3 — "OLEDB waits suddenly dominant"

**Symptom.** Wait stats showed `OLEDB` as the top wait, growing daily.

**First call.** `get_active_sessions` to find the OLEDB waiters. All were spids running queries against linked server `LINKED_SRV` (third-party ODBC for the cloud data warehouse).

**Diagnosis.** A BI tool had been left running an unattended overnight job that pulled 50M rows from the cloud data warehouse into a local `INSERT...SELECT FROM OPENQUERY`. The third-party ODBC pull was bottlenecking on cross-cloud latency.

**Fix.** Killed the job; rewrote it to stage into the cloud data warehouse first, then bulk-load via gcloud + BCP rather than synchronous linked-server pull. Wait stats normalized within hours.

**Lesson.** Linked-server waits show up as `OLEDB` and look mysterious. `get_active_sessions` resolves the mystery in one call. Don't tune linked-server queries in-place — move them out-of-band when possible. See `known-fleet-quirks.md` §1.
