# Runbook — Blocking and deadlocks

**Use this when:** Sessions are waiting on locks; alerts mention "blocking chain detected"; `THREADPOOL` waits are climbing; the application reports timeouts that resolve when retried.

## TL;DR — first 5 minutes

1. `get_blocking_chains` — identify head blocker(s).
2. The head blocker's query, login, host and program are already in the `get_blocking_chains` rows (`blocker_*`). For `login_time`, `open_transaction_count`, `transaction_isolation_level` and `wait_resource`, run the §3 capture query via `execute_query`; `get_long_running_transactions` adds the log used (rollback cost).
3. Decide: kill, wait, or escalate. The decision depends on (a) what the head blocker is doing (open transaction with uncommitted work? long-running update?) and (b) the time pressure.
4. After resolving the immediate blocking, check for the *pattern* — was this a one-off, or a recurring shape?
5. Document the head blocker query and the resolving action in the running findings doc.

---

## 1. Reading a blocking chain correctly

`get_blocking_chains` returns one row per blocked request (`blocking_session_id > 0`), longest wait first. The columns to read:

| Column | What it tells you | Why it matters |
|---|---|---|
| `blocked_session_id` → `blocking_session_id` | One edge of the chain. The **head** is a `blocking_session_id` that never appears as a `blocked_session_id` | The head is the actual cause |
| *(count of rows per head)* | How many sessions are waiting downstream | Severity (5 vs 500 changes the urgency tier) |
| `wait_type`, `wait_seconds` | `LCK_M_S` / `LCK_M_X` / `LCK_M_IX` etc., and for how long | Read-on-write vs write-on-write |
| `database_name`, `blocked_statement`, `blocked_command` | What the waiter is trying to do | Which workload is hurting |
| `blocker_sql_text`, `blocker_last_request_start` | The head's most recent batch (read from its connection, so it works even when the head is sleeping) and when it started | An old, idle head with an open transaction is the most dangerous kind |
| `blocker_login`, `blocker_host`, `blocker_program` | Where the offending session came from | Tells you which app to talk to |

Not in this result: the lock resource (`wait_resource`), `transaction_isolation_level` (1=READ UNCOMMITTED,
2=READ COMMITTED, 3=REPEATABLE READ, 4=SERIALIZABLE, 5=SNAPSHOT — higher levels hold locks longer) and
`open_transaction_count`. The §3 capture query returns all three.

A common mistake is reading the *blocked* sessions list and trying to "fix" the blocked ones. The fix is always at the head.

### Identifying chain shape

- **Single head, many blocked** — one stuck transaction holding the line. Resolve at the head.
- **Multiple independent heads** — workload-wide locking pressure; likely a hot table being hit by both reads and writes without RCSI.
- **Chain length > 2 (A blocks B blocks C blocks D)** — usually means lock escalation; first head is holding a coarser lock than expected (table lock instead of row).

---

## 2. The kill / wait / escalate decision

For the head blocker, you have three choices. The right one depends on context.

### Kill the head blocker
- **When:** It's been running >5 minutes, the session is idle in a transaction (running query is `<NULL>` or trivial but `open_transaction_count > 0`), or the impact downstream is critical.
- **How:** `KILL <session_id>` (not exposed in this MCP — escalate to a DBA with that access).
- **Risk:** If the session has uncommitted writes, those roll back. Rollback can be slow. For a session that's been running 4 hours, the rollback can take ~30 minutes.
- **First check:** estimate rollback cost from the log the transaction has written — `get_long_running_transactions` (`log_mb_used`, `duration_seconds`), or `database_transaction_log_bytes_used` in `sys.dm_tran_database_transactions` joined through `sys.dm_tran_session_transactions` on `transaction_id`.

### Wait for it to finish naturally
- **When:** The head blocker is doing legitimate, important work — e.g. a known nightly batch update, or a deploy migration with `ALTER TABLE`.
- **How:** Communicate to the affected users that there's expected blocking until job X completes.
- **Risk:** Cascading timeouts in dependent services. Set a deadline; if the head blocker hasn't finished by then, escalate.

### Escalate to the application team
- **When:** The query came from a service the DBA team doesn't own, and killing would have data-integrity implications you can't assess.
- **How:** Capture (a) the query text, (b) host_name + login + program_name, (c) the affected business object/key from `wait_resource` (§3 capture query). Send to the service owner.

The right reflex during an active incident is **capture first, then decide**. Don't reflexively `KILL` without recording what was running.

---

## 3. Capture what the head blocker was doing

Before any kill, save this artifact:

```sql
SELECT
    s.session_id, s.login_name, s.host_name, s.program_name,
    s.login_time, s.last_request_start_time, s.last_request_end_time,
    s.open_transaction_count, s.transaction_isolation_level,
    r.command, r.status, r.cpu_time, r.total_elapsed_time, r.wait_type, r.wait_resource,
    SUBSTRING(t.text, (r.statement_start_offset/2)+1,
        ((CASE WHEN r.statement_end_offset = -1 THEN DATALENGTH(t.text)
               ELSE r.statement_end_offset END - r.statement_start_offset)/2) + 1) AS current_statement,
    t.text  AS full_batch,
    lt.text AS last_batch          -- the most recent batch; the only text when the session is sleeping
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r    ON r.session_id = s.session_id
LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) lt
WHERE s.session_id = <head_blocker_spid>;
```

If the node keeps a per-minute `sp_WhoIsActive` history, `get_hiq` (`blocking: 'blockers'`) has a record of this
too, including the minutes before you started looking — check there first.

---

## 4. Deadlocks

Deadlocks are a special case of blocking where two or more sessions form a cycle. SQL Server detects this in ~5 seconds and kills the cheapest one to roll back as the "deadlock victim."

### Investigating a recent deadlock

`get_deadlock_history` returns the `system_health` Extended Events deadlock graphs. Each graph (XDL) is XML containing:
- **Processes** — the sessions involved, with their queries
- **Resources** — the objects fought over (with `objectname` attribute)
- **Owners/waiters** — the lock-mode pattern

Read the resources first, then the queries. The fix is almost always one of:

1. **Acquire locks in consistent order across queries.** If `A` updates `tableX` then `tableY` and `B` updates `tableY` then `tableX`, change one to match.
2. **Shorten lock hold time** by adding a covering index so the query doesn't take a wider lock to find rows.
3. **Use SNAPSHOT isolation** for read-mostly transactions that don't need to block writers.
4. **Application retry logic** for unavoidable deadlocks. The deadlock victim has SQL error 1205 — apps should retry once before propagating to the user.

### Pattern: lookup deadlock
Two updates each take a key range lock for the key they're updating, but the index doesn't cover all referenced columns, so each query also takes a lock on the clustered index for the lookup. The lookup is the second lock, in inconsistent order → deadlock.

**Fix:** Make the index cover the lookup columns (an `INCLUDE` clause). Eliminates the second lock entirely.

### Pattern: parent-child deadlock
A foreign key relationship: process A updates parent then child, process B updates child then parent. Common in order/order-item shapes.

**Fix:** Standardize update order at the app layer. Make all writers go parent→child or child→parent consistently.

---

## 5. Lock escalation pattern

If `wait_resource` shows `OBJECT: ...` rather than `KEY: ...`, lock escalation has happened — SQL Server upgraded thousands of row/key locks to a single table lock because the threshold was exceeded.

Triggers for lock escalation:
- A single statement holds >5000 locks on a table.
- Memory pressure on the lock manager.

Mitigations:
- Update in batches (e.g. `UPDATE TOP (1000) ... WHILE @@ROWCOUNT > 0`).
- Disable escalation per-table: `ALTER TABLE T SET (LOCK_ESCALATION = DISABLE)` — but this just delays the problem if the update still wants 5M locks.
- Index correctly so the operation can use seeks and hold fewer locks.

---

## 6. THREADPOOL waits — the hidden blocking signal

If `get_wait_stats` shows `THREADPOOL` climbing, **drop everything and check `get_blocking_chains` immediately**. THREADPOOL means SQL Server has run out of worker threads, which usually means hundreds of sessions are blocked and waiting, exhausting the worker pool faster than it can be replenished.

When THREADPOOL is hit, even DBA logins may fail to connect (use the DAC — Dedicated Admin Connection — if needed). This is a near-outage state.

**Resolution sequence:**
1. Find and kill the head blocker (or the few heads). Threads will free as blocked sessions complete.
2. After recovery, investigate why so many sessions were blocked.
3. Consider whether `max worker threads` is configured appropriately for the instance's core count (SQL Server defaults are usually fine; only change with strong reason).

---

## 7. Repeat-offender analysis

If blocking is recurring (not a one-off), the question is "what pattern is creating it." `get_hiq` reads a
per-minute `sp_WhoIsActive` history (`DBA.dbo.HIQMonitor`) — 60 × 24 = 1,440 collections per day per node, kept for
as long as your capture job retains them. Aggregate the lead blockers over a few days via `execute_query`:

```sql
SELECT TOP (20)
    LEFT(CAST(sql_text AS nvarchar(max)), 200)                     AS sample_query,
    COUNT(*)                                                        AS samples_blocking,
    SUM(TRY_CONVERT(int, REPLACE(blocked_session_count, ',', '')))  AS total_downstream_blocked
FROM [DBA].[dbo].[HIQMonitor]
WHERE collection_time >= DATEADD(DAY, -3, SYSDATETIME())
  AND TRY_CONVERT(int, REPLACE(blocked_session_count, ',', '')) > 0   -- lead blockers only
GROUP BY LEFT(CAST(sql_text AS nvarchar(max)), 200)
ORDER BY total_downstream_blocked DESC;
```

Most production blocking comes from a small number of query shapes.

---

## 8. RCSI as the durable fix for read-vs-write blocking

If the pattern is "reads are being blocked by writes" (e.g. analytical reports timing out because OLTP updates are running), Read Committed Snapshot Isolation is the standard durable fix:

```sql
-- Per database (requires a moment without active connections to enable)
ALTER DATABASE <db> SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
```

Effects:
- Reads no longer take shared locks; they read row versions from tempdb.
- Writers still block writers (no change there).
- **TempDB cost:** version store grows; size tempdb accordingly.
- **App compatibility:** apps relying on read-committed-with-locks semantics (uncommon but exists) need testing.

Check whether it's already on: `SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = '<db>';`.

In this fleet, RCSI status varies by database. Verify before recommending enabling it.

---

## What this runbook does *not* cover

- **Engine-level crashes** — restore service first ([`service-restoration-first.md`](service-restoration-first.md)); the crash entry in [`diagnostic-patterns.md`](diagnostic-patterns.md) lists the forensic tools.
- **Pure performance** that's *not* blocking — see [`performance-investigation.md`](performance-investigation.md).
- **AG sync delays** that look like blocking — `get_ag_health` (`log_send_queue_kb`, `redo_queue_kb`) and the AG patterns in [`diagnostic-patterns.md`](diagnostic-patterns.md).

---

## Cases

### Case 1 — Idle-in-transaction app session blocking 200 readers

**Symptom.** Sales dashboards timing out. `get_blocking_chains` showed 200 blocked sessions, one head blocker (spid 1247).

**Investigation.** `get_active_sessions` (`include_sleeping: true`) showed spid 1247 `session_status = 'sleeping'` with a last request 2 hours old; the §3 capture query showed `open_transaction_count = 1`. Login was an app service account, host was an app VM. The app had opened a transaction, run one UPDATE, then hung waiting on an external API without committing.

**Action.** Captured the query, killed the spid (rollback was instant since the open work was one row). Notified the app team. Total time to mitigation: ~3 minutes.

**Durable fix.** App team added a transaction timeout in their ORM config. Pattern hasn't recurred.

**Lesson.** "Sleeping with an open transaction" is the most common chronic blocker. Always check `open_transaction_count` on idle-looking sessions before assuming they're benign.

### Case 2 — Recurring deadlock between two API endpoints

**Symptom.** Two specific app endpoints generating ~50 deadlocks per day, alerting fatigue.

**Investigation.** `get_deadlock_history` showed all victims hitting the same two tables (`Account`, `AccountCredit`), but the lock order differed between the endpoints — one updated `Account` first, the other updated `AccountCredit` first.

**Action.** App team standardized: both endpoints now acquire the `Account` row first. Zero deadlocks in the 30 days following.

**Lesson.** Deadlock graphs are very specific — they name the resources and the queries. Don't recommend "tuning" or "add an index" before reading the graph; the answer is usually "fix the lock order in the app."

### Case 3 — THREADPOOL exhaustion at 09:00 daily

**Symptom.** Daily 09:00 SQL Server appeared unresponsive for ~5 minutes; user reports flooded in.

**Investigation.** ERRORLOG showed `THREADPOOL` exhaustion. The per-minute `sp_WhoIsActive` history (`get_hiq`, `start`/`end` 08:59–09:01) showed a blocking storm: 600+ sessions all waiting on `LCK_M_S` against one table during a daily 09:00 cleanup job.

**Action.** Modified the cleanup job to batch its DELETE in chunks of 5000 rows with `WAITFOR DELAY '00:00:01'` between chunks. Eliminated the blocking storm; THREADPOOL hasn't reappeared.

**Lesson.** When a large operation can be batched, batching is almost always the right answer. Reduces lock duration *and* prevents lock escalation.
