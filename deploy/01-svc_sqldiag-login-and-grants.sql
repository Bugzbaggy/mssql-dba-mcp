/* ============================================================================
   svc_sqldiag — least-privilege login for automated health checks, diagnosis
                 and troubleshooting by the MCP server.
   ----------------------------------------------------------------------------
   WHY THIS EXISTS. The path of least resistance is to run the MCP server's login
   as sysadmin with bulk rights. This script is what lets you avoid that without
   losing a single check.

   WHAT THIS LOGIN CAN DO
     - Every DMV the MCP reads: sys.dm_os_*, sys.dm_exec_*, sys.dm_tran_*,
       sys.dm_db_*, sys.dm_io_virtual_file_stats, sys.dm_hadr_*, sys.dm_xe_*,
       sys.dm_server_services, sys.dm_server_memory_dumps, Query Store.
     - Enter ANY database to run per-database checks (index/stats/VLF/Query Store).
     - Read object definitions, the SQL ERRORLOG, Agent job history, backup
       history, suspect_pages, and the DBA monitoring views.

   WHAT IT CANNOT DO — by construction, not by convention
     - No sysadmin, no CONTROL SERVER, no securityadmin, no db_owner anywhere.
     - No ADMINISTER BULK OPERATIONS: that is an arbitrary-file-read primitive
       running as the SQL service account (which is often local admin on the box),
       so anyone holding this password could read the machine via sqlcmd. The MCP's
       read_sql_dump OPENROWSET path therefore does NOT work under this login.
       That is deliberate — see the note at the end for the replacement.
     - No db_datareader on any application database. Table data is not needed for
       health checks, so it is not granted; msg.MessageLog is unreachable.
     - No write anywhere: PART F adds explicit DENYs on the surfaces where a
       read-shaped role could otherwise act (Agent job control, Database Mail).

   HONEST LIMIT — read this before you write it up as a PII boundary.
   VIEW SERVER STATE is itself a customer-data read path, and no DENY closes it:
     - sys.dm_exec_sql_text / sys.dm_exec_input_buffer / sys.dm_exec_query_plan
       (ParameterCompiledValue) and sys.query_store_query_text expose the literal
       text of non-parameterised statements — phone numbers, message bodies and
       any other customer values included.
     - sys.fn_xe_file_target_read_file needs only VIEW SERVER STATE and can read
       any Extended Events / audit file the service account can reach (for example
       <AuditLogPath>\*.xel, if you already run a statement-level audit), whose
       content can be exactly the audited statement text.
   You cannot grant the diagnostic surface and withhold this. Treat svc_sqldiag as
   INSIDE the PII boundary for access review. The DENY in PART E is defence in
   depth against casual table reads; it is not a boundary.

   ORDER OF EXECUTION
     PART A  server: login (fixed SID) + role            -> EVERY NODE
     PART B  server: the four diagnostic grants          -> EVERY NODE
     PART C  master: ERRORLOG + connect                  -> EVERY NODE
     PART D  msdb:   jobs, backups, corruption history   -> EVERY NODE
     PART E  DBA:    monitoring views                    -> EVERY NODE
     PART F  server: the explicit DENYs                  -> EVERY NODE

   Everything here is server-scoped or lives in a NON-AG database (master, msdb,
   and - assumed here - the DBA utility database), so NOTHING in this script
   replicates. Run the whole file on every node: every replica of every
   availability group, primaries AND secondaries (for example both REGION1-NODE1
   and REGION1-NODE2). A node you skip fails 100% of calls, not just after a
   failover: the MCP's connections carry ApplicationIntent=ReadOnly and land on a
   readable SECONDARY.

   Verify with 02-Test-svc_sqldiag-grants.sql. It fails CLOSED — an unmeasured
   check reports UNMEASURED, never PASS.
   ============================================================================ */

/* ---------- PART A · LOGIN + ROLE — every node, IDENTICAL SID ------------- */
-- Run this statement VERBATIM on every node. A SQL login is a server principal and
-- does not travel inside the AG; the SID must match everywhere or any database user
-- bound to it orphans on the other replicas. Letting CREATE LOGIN generate the SID
-- per node gives every replica a different SID, which is exactly that failure - and
-- it stays hidden until the first read lands on a replica you did not test.
--
-- Generate the SID ONCE, on the first node, then paste the same literal below:
--   SELECT CONVERT(varchar(100), CRYPT_GEN_RANDOM(16), 1);
--
-- CHECK_POLICY = ON is deliberate but has a consequence worth knowing: it enables
-- lockout on repeated bad passwords, so a caller looping with a stale secret can
-- lock out the incident-response login at the worst moment. Keep the secret in one
-- place (your secret store -> the runner host's OS credential store) so there is
-- only one copy to go stale.
-- CREATE LOGIN needs literals, so the two values are injected here rather than typed
-- into the DDL. This shape is deliberate: an unedited copy of this script THROWS with an
-- instruction instead of failing with a syntax error, and it cannot half-create a login
-- with an accidental all-zero SID.
DECLARE @sid varbinary(16) = NULL;        -- <<< PASTE the SAME value on every node
DECLARE @pwd nvarchar(128) = N'';         -- <<< PASTE from your secret store

IF @sid IS NULL OR DATALENGTH(@sid) <> 16
    THROW 50001, 'Set @sid first. Generate it ONCE (SELECT CONVERT(varchar(100), CRYPT_GEN_RANDOM(16), 1)) and paste that SAME literal on every node. A per-node SID orphans the database users and fails every read on the secondaries.', 1;
IF @pwd = N''
    THROW 50002, 'Set @pwd from the secret store. Do not commit it, and do not issue it to a person.', 1;
-- Entropy is asserted HERE rather than delegated to CHECK_POLICY, for the reason in the
-- CHECK_EXPIRATION note below: this login must never be subject to password expiry, and a
-- machine-generated 32+ character secret already exceeds anything a complexity rule checks.
IF LEN(@pwd) < 32
    THROW 50004, 'Refusing to create svc_sqldiag with a password under 32 characters. This principal is never typed by a human - generate it in the secret store (e.g. 40+ chars, full character set). Short passwords are what make the lockout trade-off below actually matter.', 1;

IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'svc_sqldiag')
BEGIN
    PRINT 'svc_sqldiag already exists on this node - skipping CREATE LOGIN.';
    -- Parity check: a mismatched SID here is the failure that hides until a failover.
    IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = N'svc_sqldiag' AND sid = @sid)
        THROW 50003, 'svc_sqldiag exists on this node with a DIFFERENT SID than the one set above. Re-align it (ALTER USER ... WITH LOGIN = svc_sqldiag in each database) or drop and recreate with the canonical SID before going further.', 1;
END
ELSE
BEGIN
    -- CHECK_EXPIRATION = OFF is not laziness, it is the point: a diagnostic principal whose
    -- password expires stops working at a moment nobody chose, and the first symptom is the
    -- incident tooling failing during an incident. Expiry is a control for human passwords.
    --
    -- CHECK_POLICY = ON is kept for complexity + lockout, with one trade-off you should make
    -- deliberately rather than inherit: with it ON, SQL honours the Windows account-lockout
    -- policy, so anyone who knows this login NAME can lock it out with repeated bad passwords
    -- - denying you your incident-response login exactly when you need it. The 32-char
    -- assertion above is what buys the option to turn it off: if your AD lockout threshold is
    -- aggressive, change this to CHECK_POLICY = OFF and you lose nothing that a 40-character
    -- machine-generated secret was not already providing.
    DECLARE @sql nvarchar(max) =
        N'CREATE LOGIN svc_sqldiag WITH PASSWORD = ' + QUOTENAME(@pwd, '''') +
        N', SID = ' + CONVERT(varchar(100), @sid, 1) +
        N', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;';
    EXEC sys.sp_executesql @sql;
    PRINT 'Created svc_sqldiag.';
END
GO

-- Verify parity across the nodes — this must return an IDENTICAL value on every node:
--   SELECT CONVERT(varchar(100), sid, 1) FROM sys.sql_logins WHERE name = N'svc_sqldiag';
GO

-- A server role, so the grants are named and revocable as a unit.
-- Guarded so the whole file can be re-run on a node that already has it.
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'role_sqldiag' AND type = 'R')
    CREATE SERVER ROLE role_sqldiag;
ALTER SERVER ROLE role_sqldiag ADD MEMBER svc_sqldiag;   -- a no-op when already a member
GO

/* ---------- PART B · THE FOUR DIAGNOSTIC GRANTS — every node -------------- */
-- VIEW SERVER STATE   : every sys.dm_* the tool surface reads. Implies
--                       VIEW DATABASE STATE on every database, which is what makes
--                       the per-database index/stats/Query Store checks work
--                       WITHOUT granting db_datareader anywhere.
-- VIEW ANY DEFINITION : object definitions, sys.sql_modules, OBJECT_DEFINITION(),
--                       sys.availability_groups / sys.availability_replicas.
-- VIEW ANY DATABASE   : see every row in sys.databases. Load-bearing beyond the
--                       obvious: connectionManager.ts treats "no row in
--                       sys.databases" as evidence a fleet entry is misconfigured,
--                       and a login without this reports EVERY user database as
--                       absent — turning a healthy node into a false diagnosis.
-- CONNECT ANY DATABASE: the tools emit a literal USE [<db>]. Provisioning a user
--                       per database by name means every database NOT on that
--                       list (for example AppDb_Analytics, DBA, or anything
--                       created later) fails. This grants ENTRY, not data — with
--                       no db_datareader it cannot read a user table in any
--                       database it enters.
GRANT VIEW SERVER STATE    TO role_sqldiag;
GRANT VIEW ANY DEFINITION  TO role_sqldiag;
GRANT VIEW ANY DATABASE    TO role_sqldiag;
GRANT CONNECT ANY DATABASE TO role_sqldiag;
GO

/* ---------- PART C · master — ERRORLOG + connect — every node ------------- */
USE master;
GO
IF DATABASE_PRINCIPAL_ID(N'svc_sqldiag') IS NULL CREATE USER svc_sqldiag FOR LOGIN svc_sqldiag;
GO
-- The ERRORLOG is an early stop in any crash investigation and the ONLY place the
-- real state of a failed initial-catalog open is recorded (SQL hands the client an
-- opaque 18456).
--
-- Grant EXECUTE on the EXTENDED proc, not the wrapper: sys.sp_readerrorlog begins
-- with IS_SRVROLEMEMBER(N'securityadmin') and RAISERROR 15003 if you are not a
-- member, so using it would force securityadmin onto this login — a role that can
-- grant server permissions, i.e. a direct path back to the privilege we are
-- removing. sys.xp_readerrorlog honours a plain EXECUTE grant and needs no role.
GRANT EXECUTE ON sys.xp_readerrorlog TO svc_sqldiag;
GO
-- Instance/AG/dump-inventory helpers used by the health catalog.
GRANT EXECUTE ON sys.fn_hadr_backup_is_preferred_replica TO svc_sqldiag;
GO

/* ---------- PART D · msdb — jobs, backups, corruption — every node -------- */
USE msdb;
GO
IF DATABASE_PRINCIPAL_ID(N'svc_sqldiag') IS NULL CREATE USER svc_sqldiag FOR LOGIN svc_sqldiag;
GO
-- Read-only Agent visibility: every job, schedule and history row, for jobs this
-- login does not own. SQLAgentReaderRole is the read-only one of the three Agent
-- roles (User < Reader < Operator); Operator can START and STOP jobs, so it is the
-- wrong one and PART F denies that surface explicitly regardless.
ALTER ROLE SQLAgentReaderRole ADD MEMBER svc_sqldiag;
GO
-- SQLAgentReaderRole reaches Agent metadata through msdb's own views and procedures; it
-- grants NO direct SELECT on the base tables. The health checks read those tables directly
-- (job integrity and drift, the secrets scan, alert coverage), so without these grants they
-- fail with Msg 229 - measured. Read-only, and each one names a table the catalog reads.
GRANT SELECT ON OBJECT::dbo.sysjobs           TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysjobsteps       TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysjobschedules   TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysschedules      TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysjobservers     TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysjobhistory     TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysjobactivity    TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.syscategories     TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysalerts         TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysoperators      TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysnotifications  TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysmail_profile   TO svc_sqldiag;
GRANT EXECUTE ON OBJECT::dbo.agent_datetime   TO svc_sqldiag;   -- a pure date conversion
GO
-- Backup history (get_backup_status / the backup-age checks) and the corruption
-- ledger. suspect_pages is check 4 of the failover gate in
-- runbooks/service-restoration-first.md — without it the gate cannot be evaluated,
-- and an empty result there would otherwise be indistinguishable from "cannot look".
GRANT SELECT ON OBJECT::dbo.backupset          TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.backupmediafamily  TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.suspect_pages      TO svc_sqldiag;
-- Database Mail send history is read for "did the alert actually go out?" triage.
-- Reading the log is fine; SENDING is denied in PART F.
GRANT SELECT ON OBJECT::dbo.sysmail_event_log  TO svc_sqldiag;
GRANT SELECT ON OBJECT::dbo.sysmail_allitems   TO svc_sqldiag;
GO
-- Job-step output, the IN-DATABASE copy. sysjobhistory.message truncates at 3,998
-- characters and keeps the OLDEST end of a PowerShell step's output, so "the message
-- does not mention X" proves nothing. The usual remedy is "read the file at
-- sysjobsteps.output_file_name", which this login deliberately CANNOT do (no
-- filesystem access; see PART F and the notes at the end).
-- Turning on log-to-table for the step (sysjobsteps.flags bit 16) writes the full output here
-- instead, where a read-only principal can actually get at it. Grant the read now so the fix
-- works the day someone enables it.
GRANT SELECT ON OBJECT::dbo.sysjobstepslogs    TO svc_sqldiag;
GO

/* ---------- PART E · DBA — the monitoring views — every node -------------- */
-- Assumes the DBA utility database is local to each node (NOT in an availability
-- group), so this does not replicate. If yours is in an AG, run this part on the
-- primary only.
USE DBA;
GO
IF DATABASE_PRINCIPAL_ID(N'svc_sqldiag') IS NULL CREATE USER svc_sqldiag FOR LOGIN svc_sqldiag;
GO
-- Deny-by-default: name the objects, do NOT grant db_datareader. These are the two
-- tables the MCP actually reads here, each granted only if it exists:
--   dbo.HIQMonitor - the sp_WhoIsActive history that get_hiq reads;
--   dbo.CommandLog - the log table of Ola Hallengren's maintenance solution.
IF OBJECT_ID(N'dbo.HIQMonitor', N'U') IS NOT NULL
    GRANT SELECT ON OBJECT::dbo.HIQMonitor TO svc_sqldiag;   -- get_hiq
ELSE PRINT 'dbo.HIQMonitor not found in DBA - get_hiq will report it cannot read the history.';
-- CommandLog answers "when did CHECKDB last run, and did it ERROR?" — better than
-- the DBCC DBINFO route, which would need sysadmin (or a certificate-signed
-- wrapper whose signing login would itself have to be sysadmin: containment, not
-- elimination). It also records the outcome, which DBCC DBINFO does not.
IF OBJECT_ID(N'dbo.CommandLog', N'U') IS NOT NULL
    GRANT SELECT ON OBJECT::dbo.CommandLog TO svc_sqldiag;
ELSE PRINT 'dbo.CommandLog not found in DBA - CHECKDB history falls back to a human session.';
GO

/* ---------- PART F · THE EXPLICIT DENYs — every node ---------------------- */
-- A DENY outranks every GRANT, including one arriving later via a role. These close
-- the paths where a read-shaped principal could still ACT, so the read-only
-- property survives someone adding a convenience grant in six months.
USE msdb;
GO
-- Agent job control. Two MCP tools (get_host_event_log, generate_cluster_log)
-- create -> start -> drop an Agent job to reach the Windows host; they run as the
-- SQL Agent service account, so they are neither read-only nor attributable to
-- this login. Denied permanently and deliberately.
DENY EXECUTE ON OBJECT::dbo.sp_start_job        TO svc_sqldiag;
DENY EXECUTE ON OBJECT::dbo.sp_stop_job         TO svc_sqldiag;
DENY EXECUTE ON OBJECT::dbo.sp_add_job          TO svc_sqldiag;
DENY EXECUTE ON OBJECT::dbo.sp_add_jobstep      TO svc_sqldiag;
DENY EXECUTE ON OBJECT::dbo.sp_update_job       TO svc_sqldiag;
DENY EXECUTE ON OBJECT::dbo.sp_delete_job       TO svc_sqldiag;
-- Database Mail: the agent reports through the runner, never by sending mail as
-- itself. (sp_send_dbmail also requires DatabaseMailUserRole, which is not granted
-- — this is the belt to that braces.)
DENY EXECUTE ON OBJECT::dbo.sp_send_dbmail      TO svc_sqldiag;
GO

USE master;
GO
-- xp_cmdshell should be disabled anyway, but a DENY survives someone enabling it.
DENY EXECUTE ON OBJECT::sys.xp_cmdshell TO svc_sqldiag;
GO

-- The `public` surface. CREATE USER in master necessarily makes this principal a member of
-- `public`, and membership cannot be removed. On stock SQL Server `public` reaches a set of
-- undocumented extended procedures that read the FILESYSTEM and the REGISTRY as the SQL
-- service account — which is commonly local admin on the host. None of them is needed by any
-- check in the catalog (dump discovery uses sys.dm_os_enumerate_filesystem, which is covered
-- by VIEW SERVER STATE), so deny them explicitly.
--
-- Deliberately denied even where `public` may not currently hold EXECUTE: a DENY on an
-- unreachable proc costs nothing, and it is what makes this survive a future `GRANT ... TO
-- public` from a vendor script or a well-meaning fix. DENY outranks any later GRANT.
DECLARE @proc sysname, @sql nvarchar(400);
DECLARE denies CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM (VALUES
        -- filesystem
        (N'xp_dirtree'), (N'xp_subdirs'), (N'xp_fileexist'), (N'xp_availablemedia'),
        (N'xp_delete_file'), (N'xp_enumerrorlogs'), (N'xp_create_subdir'),
        -- registry
        (N'xp_regread'), (N'xp_regwrite'), (N'xp_regdeletekey'), (N'xp_regdeletevalue'),
        (N'xp_regenumvalues'), (N'xp_regenumkeys'), (N'xp_regaddmultistring'),
        (N'xp_instance_regread'), (N'xp_instance_regwrite'),
        -- OLE automation + service/network control
        (N'sp_OACreate'), (N'sp_OAMethod'), (N'sp_OAGetProperty'), (N'sp_OASetProperty'),
        (N'sp_OADestroy'), (N'xp_servicecontrol'), (N'xp_cmdshell')
    ) AS p(name)
    WHERE EXISTS (SELECT 1 FROM sys.system_objects o WHERE o.name = p.name AND o.schema_id = SCHEMA_ID('sys'));
OPEN denies;
FETCH NEXT FROM denies INTO @proc;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @sql = N'DENY EXECUTE ON OBJECT::sys.' + QUOTENAME(@proc) + N' TO svc_sqldiag;';
    BEGIN TRY EXEC sys.sp_executesql @sql; END TRY
    BEGIN CATCH PRINT '  could not DENY ' + @proc + ': ' + ERROR_MESSAGE(); END CATCH
    FETCH NEXT FROM denies INTO @proc;
END
CLOSE denies; DEALLOCATE denies;
PRINT 'Denied the public-reachable filesystem / registry / OLE extended procedures.';
GO

/* ============================================================================
   WHAT YOU GIVE UP, AND THE REPLACEMENT FOR EACH
   ----------------------------------------------------------------------------
   1. read_sql_dump (OPENROWSET BULK over the SQLDump files)
        Needs ADMINISTER BULK OPERATIONS — deliberately not granted (see header).
        REPLACEMENT: the DUMP INVENTORY still works. dumpPaths.ts resolves the dump
        directory through sys.dm_os_enumerate_filesystem, which VIEW SERVER STATE
        covers, so get_memory_dumps still returns the on-disk file list, counts and
        timestamps. Only reading a dump's TEXT requires a human session.
   2. Get-DbaLastGoodCheckDb (DBCC DBINFO)
        Needs sysadmin. REPLACEMENT: DBA.dbo.CommandLog (PART E).
   3. get_host_event_log / generate_cluster_log / get_host_dll_versions
        Windows-side, and the first two are writes. REPLACEMENT for the one that
        matters: sys.dm_os_loaded_modules answers the injected-DLL question with no
        file share at all, and it is covered by VIEW SERVER STATE.
   4. Reading a SQL Agent job step's on-disk output file
        This is the usual remedy for a truncated sysjobhistory.message, and it needs
        filesystem access, which is exactly what PART F removes. REPLACEMENT is
        log-to-table. Set bit 16 in sysjobsteps.flags for the step (SSMS: Advanced ->
        "Log to table") and the full, untruncated output lands in
        msdb.dbo.sysjobstepslogs, granted in PART D. Until that is enabled for a given
        job, a truncated sysjobhistory.message is ALL this login can see for it — which
        is a reason to treat its absence as "could not look", never as "did not happen".
   5. Get-DbaDiskSpace (all volumes)
        REPLACEMENT: sys.dm_os_volume_stats, which sees only volumes that HOLD
        DATABASE FILES — it covers the data, log and tempdb volumes and MISSES any
        volume with no database file on it (typically the backup target and C:\).
        State that blind spot wherever the check is surfaced; it is honest and still
        catches the incident-relevant case.
   6. Get-DbaAgentJob / the "SQL Agent jobs" check (SMO)
        Measured: SMO returns an EMPTY job list, with no error, to a non-sysadmin -
        even one in SQLAgentReaderRole whose T-SQL view of msdb shows every job. So that
        check reads Info (no rows), never Pass. REPLACEMENT: the job checks that read
        msdb in T-SQL (Agent job integrity, drift, the secrets scan) still see every job
        through the grants in PART D, and get_job_status falls back to msdb itself when
        SMO comes back empty.

   ROLLBACK (one statement, if this turns out to be too tight):
     ALTER SERVER ROLE [sysadmin] ADD MEMBER svc_sqldiag;
   Then open an issue with the check that failed rather than leaving it there.
   ============================================================================ */
