# Service restoration first

**Read this before any other runbook when production is down.**

Every other playbook in this directory optimises for *understanding*. This one
optimises for *service*. When an application-facing database is unavailable, the
agent's job is to get it serving again and then investigate — not to complete a
root-cause analysis and then act.

The order is: **restore → preserve evidence → diagnose.** Not diagnose → restore.

---

## 0. "Login failed" during an incident is usually not a credentials problem

If the MCP cannot connect to the sick node, do **not** start debugging the login.
A fleet entry normally pins an initial catalog (for example `AppCatalog` or
`AppDb`) because read-only routing needs an AG database, so when *that one
database* is unavailable the login is refused and the node looks dead — while the
instance is up and serving everything else.

SQL reports this to the client as a plain **18456 login failure**, which is why
it reads as a password problem. It is not.

- **`ALTER LOGIN … WITH DEFAULT_DATABASE = master` does not fix it.** The
  connection string's initial catalog overrides the login default. It has been
  tried mid-incident and changed nothing.
- The server **retries against `master` automatically** (`SQL_CATALOG_FALLBACK`,
  on by default; `SQL_FALLBACK_DATABASE` names a different fallback catalog), so a
  node with one sick database stays reachable. The retry is
  **not** taken as proof that the database is sick: once connected, the server reads
  `sys.databases.state_desc` and says what it measured. Expect one of three labels in
  the warning — `CONFIRMED: … is SUSPECT/RECOVERY_PENDING/…` (the real one-sick-database
  case), `CONFIRMED: … is ONLINE` (the database is fine on the node reached — either
  the retry landed on the *other* replica, or your login cannot open it: check for an
  orphaned user after a failover), or `UNCONFIRMED` (the state could not be read, or
  this login can see only the system databases). A fleet entry naming a database that
  does not exist at all is **refused** rather than quietly served from `master` —
  provided the login can see the catalog; otherwise it is kept and labelled
  `UNCONFIRMED`.
- When the fallback fires, **every tool result** carries a `catalog_fallback` warning —
  not just `execute_query`. Heed it: the query context is `master`, so unqualified
  catalog views, `SCHEMA_NAME()`, `OBJECT_NAME()` and `OBJECT_DEFINITION()` resolve
  **there** — a cross-database lookup returns a *wrong* answer, not an error. Fully
  qualify everything. Read-only routing also did not engage, so you may be on the
  primary. `execute_write` carries it too, on both the success and the error path.
- The fallback connection is **retired after 60s** (`SQL_CATALOG_FALLBACK_TTL_MS`,
  clamped to 1s–2147483647ms) so the next call re-dials the configured database and
  picks up the recovery. Practical consequence during an incident: the warning can
  *disappear* mid-session once the database comes back — re-read it rather than
  assuming it persists.

The fallback firing is itself a **finding**: it means the configured catalog is not
openable on that node. Confirm with `sys.databases.state_desc` and go straight to
the failover gate below.

---

## 1. The failover gate

A database is unavailable on the primary (SUSPECT, RECOVERY_PENDING, OFFLINE, or
erroring on every call) and it belongs to an availability group. Run these four
checks against the **secondary**. They take under a minute in total.

```sql
-- On the SECONDARY
SELECT DB_NAME(drs.database_id)            AS db,
       drs.synchronization_state_desc,
       drs.database_state_desc,
       drs.is_suspended,
       drs.last_hardened_lsn,
       drs.last_commit_lsn,
       drs.last_hardened_time
FROM sys.dm_hadr_database_replica_states drs
WHERE drs.is_local = 1;

SELECT name, state_desc, page_verify_option_desc
FROM sys.databases WHERE name = '<db>';

SELECT COUNT(*) AS suspect_page_rows FROM msdb.dbo.suspect_pages;
```

```sql
-- On the PRIMARY (if it is still reachable)
SELECT DB_NAME(database_id) AS db, last_commit_lsn, last_commit_time, end_of_log_lsn
FROM sys.dm_hadr_database_replica_states WHERE is_local = 1;
```

| # | Check | Pass condition |
|---|---|---|
| 1 | Secondary `last_hardened_lsn` vs primary `last_commit_lsn` | secondary **at or ahead of** the primary's last commit → **zero committed-transaction loss** |
| 2 | Secondary `state_desc` | `ONLINE` |
| 3 | Secondary `is_suspended` | `0` |
| 4 | `msdb.dbo.suspect_pages` on the secondary | **0 rows** |

**All four pass → recommend the failover immediately.** State the measured LSN
comparison and the resulting data-loss figure in the same breath.

```sql
ALTER AVAILABILITY GROUP [<ag>] FORCE_FAILOVER_ALLOW_DATA_LOSS;
```

### Do not be stopped by these

- **SSMS labels the replica "Data Loss".** It says that because the replica left
  the SYNCHRONIZED set, not because loss was measured. Check 1 *is* the
  measurement. The label is not evidence.
- **`is_failover_ready = false`** on the secondary's copy. That is exactly why a
  graceful `FAILOVER` will be refused and `FORCE_FAILOVER_ALLOW_DATA_LOSS` is the
  correct verb. It is not a reason to wait.
- **"The primary is still up, so forcing risks split-brain."** Weigh it, say it,
  and move on. If the primary's databases are already dead and the secondary is
  provably clean, the primary being alive does not make the outage less real.
- **`required_synchronized_secondaries_to_commit`.** Check it (`sys.availability_groups`)
  — with RSSTC = 0 a synchronous-commit primary commits alone once the secondary
  drops out, so synchronous commit alone does **not** guarantee zero loss. Check 1
  does. Use the LSNs, not the availability mode.

### Before you force it, one cheap insurance step

A tail-log backup can only recover loss, never cause it. If the primary is
reachable, attempt it *before* the failover and move on within a minute if it
fails:

```sql
BACKUP LOG [<db>] TO DISK = '<path>\<db>_tail.trn'
WITH NO_TRUNCATE, COPY_ONLY, CHECKSUM, INIT;
```

Also check whether scheduled log backups have been **silently skipping** the sick
database while continuing for its AG siblings — that freezes the recovery point
without raising a job failure.

---

## 2. What the whole AG does, not just the broken database

`FORCE_FAILOVER_ALLOW_DATA_LOSS` moves the **availability group**, not one
database. Before recommending it, state in one line:

- every database in that AG and its sync state (healthy ones move too, cleanly);
- whether the target node holds the logins the application uses — AG logins live
  in `master` and are **not** replicated, so a SID mismatch turns a recovered
  database into "login failed";
- linked servers and Agent jobs that exist on the old primary but not the target;
- databases **not** in the AG that live only on the old primary.

Check the logins in the same pass:

```sql
SELECT name, type_desc, is_disabled, default_database_name
FROM sys.server_principals
WHERE type IN ('S','U','G') AND name LIKE 'app[_]%';   -- adjust to your application logins
```

---

## 3. Preserve evidence cheaply, in parallel

Restoration usually means a restart or a failover, and both destroy state. Spend
no more than a minute:

- `read_sql_dump action='list'` on the affected node — filenames and timestamps.
  This reads the filesystem over port 1433 and **survives restarts**.
- Note the dump directory and `ERRORLOG` path (`get_log_paths`).
- Do not block restoration on reading dump contents. Read them after.

---

## 4. Things that are not restoration

Never reach for these as a first move, and never at all without a human
explicitly authorising them:

- `DBCC CHECKDB ... REPAIR_ALLOW_DATA_LOSS`
- `ALTER DATABASE ... SET EMERGENCY`
- detaching a database
- `ALTER DATABASE ... SET ONLINE` on an AG member — it is rejected (Msg 5069 with
  a more specific error above it), so it costs a round trip and teaches nothing

If `suspect_pages` is empty and there are no 823/824/825 errors, there is very
likely nothing to repair — and a repair would destroy data for no reason.

**A restart is often the cheapest real fix.** A database marked SUSPECT because an
access violation killed its recovery worker is not corrupt; a clean instance
restart lets recovery finish. Weigh that against the AG consequence: if any
database in the AG is not SYNCHRONIZED, automatic failover will not fire and a
restart takes the healthy databases down with it — so fail over *first*, then
restart the old primary.

---

## 5. Worked example — the ordering, not the diagnosis

In one incident, two availability-group databases went SUSPECT on the primary
after access violations, and every application call against them failed.

All four gate checks were measured **early** and all passed — the secondary
`ONLINE`, page verify `CHECKSUM`, not suspended, `suspect_pages` empty, and the
secondary's `last_hardened_lsn` **ahead of** the primary's `last_commit_lsn`.

The agent had every one of those numbers and still kept investigating, then
argued *against* failover on split-brain grounds. A human forced the failover;
service returned with **zero committed transactions lost**. It could have
happened much earlier.

Afterwards a plain SQL service restart brought the old primary back with every
database ONLINE and the AG SYNCHRONIZED — the large reseed that had been proposed
was never needed.

**The lesson is the ordering, not the diagnosis.** The diagnosis was fine. It was
just delivered after the outage instead of during it.

See also: [`evidence-discipline.md`](evidence-discipline.md) ·
[`self-verification.md`](self-verification.md) ·
[`investigation-methodology.md`](investigation-methodology.md)
