# Runbook — Memory pressure

**Use this when:** `MemoryLoad` is reported high; page life expectancy is dropping; `RESOURCE_SEMAPHORE` waits are climbing; users report queries running out of memory; or `get_memory_usage` shows process-level pressure.

## TL;DR — the fleet-specific shape

The AppDb messaging fleet has **Lock Pages in Memory enabled on every production AG primary**. This changes the entire diagnostic shape vs. a default SQL Server install:

- The buffer pool is **pinned** at `max server memory`. It cannot grow or shrink under pressure.
- "Memory pressure" therefore means pressure **outside** the buffer pool — non-BPool inside `sqlservr.exe`, or OS-side.
- "Lower max server memory" is **not** the answer here. It shrinks the locked pool while the actual growth happens above it.

If you don't internalize that, you'll make every memory investigation in this fleet worse.

---

## 1. The first three queries

Run via `execute_query` (or pair with `get_memory_usage` which wraps similar info):

```sql
-- Q1: Process committed vs locked vs OS view
SELECT
    physical_memory_in_use_kb / 1024 AS sql_committed_mb,
    locked_page_allocations_kb / 1024 AS locked_pages_mb,
    large_page_allocations_kb / 1024 AS large_pages_mb,
    memory_utilization_percentage,
    process_physical_memory_low,
    process_virtual_memory_low,
    page_fault_count
FROM sys.dm_os_process_memory;
```

Read this as: `sql_committed_mb` is what `sqlservr.exe` has reserved. `locked_pages_mb` should equal `max server memory` (or very close) on this fleet's hosts. **The delta `committed - locked` is non-buffer-pool memory** — that's what's grown.

```sql
-- Q2: Top non-buffer-pool clerks
SELECT TOP 20
    type,
    SUM(pages_kb)/1024 AS mb
FROM sys.dm_os_memory_clerks
WHERE type <> 'MEMORYCLERK_SQLBUFFERPOOL'
GROUP BY type
ORDER BY mb DESC;
```

Read which clerk is largest. Common offenders and what they mean:

| Clerk | What it is | Common cause of growth |
|---|---|---|
| `CACHESTORE_SQLCP` | SQL plan cache (parameterized) | Plan reuse working — but high size + churn = plan cache pollution |
| `CACHESTORE_OBJCP` | Object plan cache (procedures, triggers) | High if many SPs being recompiled |
| `MEMORYCLERK_SQLQERESERVATIONS` | Query workspace memory | Big sort/hash operations; high under heavy analytical workload |
| `OBJECTSTORE_LOCK_MANAGER` | Lock manager memory | Lots of concurrent locks held; check `get_blocking_chains` |
| `OBJECTSTORE_SERVICE_BROKER` | Service Broker objects | Service Broker conversation accumulation |
| `MEMORYCLERK_SQLCLR` | CLR | Sustained growth = potential CLR leak |
| `MEMORYCLERK_XTP` | In-Memory OLTP (Hekaton) | In-memory table data — should be sized to physical memory at design time |
| `MEMORYCLERK_SQLEXTERNAL` | Linked-server provider memory | third-party ODBC, MSDASQL, etc. — see `known-fleet-quirks.md` §1 |
| `MEMORYCLERK_SQLLOGPOOL` | Log pool | Heavy transaction log traffic |
| `MEMORYCLERK_QUERYDISKSTORE_*` | Query Store | If huge, Query Store is over its `MAX_STORAGE_SIZE_MB` |
| `USERSTORE_TOKENPERM` | Token/permission cache | Many distinct logins; check for application connection-pooling misconfig |

```sql
-- Q3: Buffer pool by database (which DB owns the cached pages)
SELECT
    CASE database_id WHEN 32767 THEN 'ResourceDb' ELSE DB_NAME(database_id) END AS db,
    COUNT_BIG(*) * 8 / 1024 AS cached_mb,
    COUNT_BIG(*) AS cached_pages
FROM sys.dm_os_buffer_descriptors
GROUP BY database_id
ORDER BY cached_mb DESC;
```

`get_buffer_pool_by_object` exposes a finer-grained version of this. Useful when buffer-pool *composition* is the question (e.g. "did the analytics DB just blow out the messaging DB's cache?").

---

## 2. Decision tree

After Q1–Q2:

```
sql_committed_mb - locked_pages_mb > 4 GB?
├── Yes — significant non-BPool growth
│    Which clerk dominates Q2?
│    ├── CACHESTORE_SQLCP / OBJCP large + high churn → plan cache pollution
│    │     → `get_plan_cache_pollution`
│    │     → Investigate: app generating non-parameterized SQL?
│    ├── MEMORYCLERK_SQLQERESERVATIONS large + growing → memory grant pressure
│    │     → `get_top_queries` for high memory grants
│    │     → Sometimes a single large analytical query
│    ├── MEMORYCLERK_XTP large → Hekaton in-memory tables
│    │     → Check `sys.dm_db_xtp_table_memory_stats`
│    │     → Hekaton tables are sized to physical memory; if growing, design issue
│    ├── MEMORYCLERK_SQLEXTERNAL large → linked-server provider
│    │     → `get_active_sessions` for OLEDB waits
│    │     → Usually third-party ODBC pulling large result sets in-process
│    ├── OBJECTSTORE_LOCK_MANAGER large → many locks held
│    │     → `get_blocking_chains` to find the holders
│    ├── MEMORYCLERK_QUERYDISKSTORE_HASHMAP large → Query Store
│    │     → Check `MAX_STORAGE_SIZE_MB` and trim retention
│    └── USERSTORE_TOKENPERM large → token cache bloat
│          → DBCC FREESYSTEMCACHE('TokenAndPermUserStore') as immediate fix
│          → Check app connection pooling
│
└── No — committed ≈ locked, so SQL itself is not eating extra
     OS-side pressure. Common causes:
     ├── EDR agent (the EDR agent ctiuser.dll) under heavy load
     ├── Antivirus scanning DB volumes (file paths should be excluded)
     ├── Other process on the host (rare — these are dedicated SQL hosts)
     └── Provider VM is undersized for the workload
```

---

## 3. What "MemoryLoad 96%" actually means

`MemoryLoad` is `sys.dm_os_sys_memory.system_memory_state_desc` / `system_memory_signal_state` — it's the **OS view** of physical memory used, not SQL's view. With Lock Pages in Memory enabled:

- SQL has locked `max server memory` worth of pages — those count toward OS MemoryLoad.
- Plus everything else in `sqlservr.exe` (the non-BPool growth).
- Plus the OS itself + agents.

On a 16 GB box with `max server memory = 11261 MB`, the locked region alone is 11 GB / 16 GB = 69%. Add 2 GB of non-BPool inside sqlservr + 2 GB of OS + agents and you're at 94%. That's not necessarily pathological — it's the *normal* state of a memory-tight host.

What matters is **whether it's stable or growing**. Use `get_memory_usage` over time, or `get_perfmon_counters` for the `Available MBytes` counter over the incident window, to distinguish "always close to the line" from "growing toward the line."

---

## 4. The `RESOURCE_SEMAPHORE` wait

When queries are waiting on memory grants, `RESOURCE_SEMAPHORE` shows up in `get_wait_stats`. Each query that needs memory (sort, hash, hash-join, columnstore build) requests a grant from a shared pool. If the pool is exhausted, new queries wait.

Investigate:
```sql
-- Queries currently waiting for a memory grant
SELECT
    s.session_id, r.command, r.wait_time, r.wait_resource,
    g.requested_memory_kb / 1024 AS requested_mb,
    g.granted_memory_kb / 1024 AS granted_mb,
    g.required_memory_kb / 1024 AS required_mb,
    g.ideal_memory_kb / 1024 AS ideal_mb,
    SUBSTRING(t.text, (r.statement_start_offset/2)+1,
        ((CASE WHEN r.statement_end_offset = -1
               THEN LEN(CONVERT(NVARCHAR(MAX), t.text)) * 2
               ELSE r.statement_end_offset END) - r.statement_start_offset)/2 + 1) AS query
FROM sys.dm_exec_query_memory_grants g
JOIN sys.dm_exec_requests r ON r.session_id = g.session_id
JOIN sys.dm_exec_sessions s ON s.session_id = g.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t;
```

Most-common cause: a single query asked for an oversized grant (e.g. estimate said 10M rows; reality is 100M). Fix by updating stats, adding a more selective index, or breaking the query into smaller batches.

---

## 5. Page Life Expectancy (PLE) interpretation

Conventional wisdom: "PLE should be > 300." That's a 2005 number, not relevant in 2026.

What matters in this fleet:
- **PLE dropping suddenly** = a query reading more pages than the working set holds. Find that query via `get_top_queries` for high logical reads. Fix the query, not the PLE.
- **PLE chronically low** (< 30 minutes) = working set genuinely doesn't fit in buffer pool. Either reduce the working set (better indexes, archive old data) or grow the buffer pool (provision more RAM).
- **PLE high and stable** (multiple hours) = good. Don't optimize what isn't broken.

`get_perfmon_counters` exposes the PLE counter. Plot it over time, not as a single number.

---

## 6. Lock Pages in Memory verification

If you suspect LPM isn't actually enabled (or was disabled by a recent OS change):

```sql
SELECT sql_memory_model_desc FROM sys.dm_os_sys_info;
-- Expect: 'LOCK_PAGES' on all production AG primaries
```

If it returns `CONVENTIONAL`, LPM is off — the buffer pool can now be paged out and memory pressure behavior changes fundamentally. Check that the SQL service account has the "Lock pages in memory" Windows user-right (`secpol.msc` → User Rights Assignment).

---

## What this runbook does *not* cover

- **Out-of-memory crashes** (`EXCEPTION_ACCESS_VIOLATION`) — see `sql-crash-investigation.md`. Memory pressure can correlate with crashes (the EDR agent heap incident) but the resolution path differs.
- **TempDB version store growth from RCSI/snapshot** — see `tempdb-contention.md` (when written).
- **Plan cache size tuning** — generally don't tune this; if it's growing pathologically, find the cause (ad-hoc workload).

---

## Cases

### Case 1 — "MemoryLoad 96% but server isn't slow"

**Symptom.** Monitoring alert on 96% MemoryLoad on `region3-node1`. No user complaints.

**Investigation.** Ran Q1: `sql_committed_mb` = 12200, `locked_pages_mb` = 11261. Delta is ~940 MB of non-BPool — entirely normal for this workload with linked servers and CLR loaded.

**Action.** Acknowledged the alert. No fix needed. Adjusted the monitoring threshold to 98% on hosts with LPM (where 95% is the resting baseline).

**Lesson.** Alert thresholds tuned for default SQL Server installs are wrong for this fleet. With LPM, baseline MemoryLoad sits much higher because most memory is locked-in-use rather than free.

### Case 2 — `RESOURCE_SEMAPHORE` blocking analytical queries

**Symptom.** Daily report failing with "Could not get memory grant" — actually `RESOURCE_SEMAPHORE` timeout.

**Investigation.** Memory grant DMV (§4) showed one query requesting 8 GB grant. Plan estimate was wildly off — said 50M rows for a hash aggregation, actual was 500M. Stats on the source table were a week stale due to a backfill that hadn't triggered an auto-update.

**Action.** Manual `UPDATE STATISTICS` on the source table; the next compile picked a smaller grant. Report completed in 90 seconds.

**Lesson.** "Out of memory" errors often trace back to bad cardinality estimates. Always check `get_statistics_health` and the actual plan's estimate vs actual rows before assuming the server lacks RAM.

### Case 3 — `CACHESTORE_SQLCP` exploding from ad-hoc SQL

**Symptom.** `CACHESTORE_SQLCP` clerk had grown to 6 GB over 3 days, evicting other plan cache. Compilations per second from `get_perfmon_counters` were 5× normal.

**Investigation.** Query Store showed thousands of single-execution plans differing only by hard-coded literals — the app was concatenating values into SQL instead of parameterizing.

**Action.** Immediate: `DBCC FREESYSTEMCACHE('SQL Plans')` to flush — but flushed back to 6 GB in 6 hours. Durable: app team rolled a parameterized version of the offending code path. Plan cache stabilized at 800 MB.

**Lesson.** Massive plan cache + many single-execution plans = non-parameterized SQL. The fix is in the app, not the database. `optimize for ad hoc workloads` (`sp_configure`) is a band-aid that hides this pattern.
