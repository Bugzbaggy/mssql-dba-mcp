/* ============================================================================
   02-Test-svc_sqldiag-grants.sql — prove the diagnostic login on THIS node.
   ----------------------------------------------------------------------------
   RUN AS svc_sqldiag ITSELF, on EVERY node, after 01-svc_sqldiag-login-and-grants.sql:
     sqlcmd -S <node>,1433 -U svc_sqldiag -P <pwd> -i 02-Test-svc_sqldiag-grants.sql

   Running it as yourself proves nothing — it tests what the CONNECTED principal
   can do.

   BEFORE YOU RUN IT: sections 6 and 7 probe example objects. AppDb_Analytics stands
   for any database the login was never given a user in, AppDb_Data.msg.MessageLog
   for any table holding customer data, and DBA.dbo.CommandLog is the log table of
   Ola Hallengren's maintenance solution. Replace them with objects that exist on
   YOUR nodes, or those rows can only ever report UNMEASURED (or FAIL, for
   CommandLog).

   THIS PROBE FAILS CLOSED. Three outcomes, never two:
     PASS       the capability was exercised and behaved as required
     FAIL       the capability was exercised and behaved WRONGLY — fix before use
     UNMEASURED the check could not be exercised here, so it proves NOTHING

   The distinction is the whole point. The obvious way to write a negative check —
   BEGIN TRY <the bad thing> ... END TRY BEGIN CATCH 'PASS (blocked)' END CATCH —
   scores PASS on ANY exception. On a node where AppDb_Data is a non-readable
   secondary (the normal state on a secondary replica, and exactly where
   ApplicationIntent=ReadOnly routes this login) the customer-data probe fails with
   976/978 "not accessible", and that spelling would certify a DENY it never
   exercised, on the nodes where it matters most. Only a real permission denial
   (229/230/297) scores PASS here. Everything else is UNMEASURED and says so.

   This is a common defect in health tooling: a check that maps "empty" and
   "error" onto the same verdict is not a measurement. See
   runbooks/self-verification.md.
   ============================================================================ */
SET NOCOUNT ON;

DECLARE @out TABLE (
    Seq        int IDENTITY(1,1),
    Area       nvarchar(24),
    Capability nvarchar(90),
    Result     nvarchar(12),
    Detail     nvarchar(500)
);
DECLARE @n int, @s nvarchar(max);

PRINT '=== svc_sqldiag capability probe on ' + @@SERVERNAME + ' as ' + SUSER_SNAME() + ' ===';

/* ---------- 1. Identity: it must NOT be privileged ------------------------ */
INSERT @out SELECT 'Identity', 'Is NOT sysadmin',
       CASE WHEN IS_SRVROLEMEMBER('sysadmin')     = 0 THEN 'PASS' ELSE 'FAIL' END,
       'IS_SRVROLEMEMBER(sysadmin) = ' + ISNULL(CAST(IS_SRVROLEMEMBER('sysadmin') AS nvarchar(3)), 'NULL');
INSERT @out SELECT 'Identity', 'Is NOT securityadmin',
       CASE WHEN IS_SRVROLEMEMBER('securityadmin') = 0 THEN 'PASS' ELSE 'FAIL' END, '';
INSERT @out SELECT 'Identity', 'Is NOT serveradmin / processadmin',
       CASE WHEN IS_SRVROLEMEMBER('serveradmin') = 0 AND IS_SRVROLEMEMBER('processadmin') = 0
            THEN 'PASS' ELSE 'FAIL' END, '';
INSERT @out SELECT 'Identity', 'Has NO CONTROL SERVER',
       CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
       'CONTROL SERVER grants found: ' + CAST(COUNT(*) AS nvarchar(10))
FROM sys.fn_my_permissions(NULL, 'SERVER') WHERE permission_name = 'CONTROL SERVER';
INSERT @out SELECT 'Identity', 'Has NO ADMINISTER BULK OPERATIONS',
       CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
       'arbitrary-file-read primitive as the SQL service account'
FROM sys.fn_my_permissions(NULL, 'SERVER') WHERE permission_name = 'ADMINISTER BULK OPERATIONS';

/* ---------- 2. The four diagnostic grants -------------------------------- */
INSERT @out SELECT 'Grants', 'Holds ' + p.permission_name, 'PASS', ''
FROM (VALUES ('VIEW SERVER STATE'),('VIEW ANY DEFINITION'),('VIEW ANY DATABASE'),('CONNECT ANY DATABASE')) AS p(permission_name)
WHERE EXISTS (SELECT 1 FROM sys.fn_my_permissions(NULL,'SERVER') m WHERE m.permission_name = p.permission_name);
INSERT @out SELECT 'Grants', 'Holds ' + p.permission_name, 'FAIL', 'MISSING - the checks that need it will return empty, not error'
FROM (VALUES ('VIEW SERVER STATE'),('VIEW ANY DEFINITION'),('VIEW ANY DATABASE'),('CONNECT ANY DATABASE')) AS p(permission_name)
WHERE NOT EXISTS (SELECT 1 FROM sys.fn_my_permissions(NULL,'SERVER') m WHERE m.permission_name = p.permission_name);

/* ---------- 3. Core DMV surface ------------------------------------------ */
BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_os_sys_info;
    INSERT @out VALUES ('DMV','sys.dm_os_sys_info (machine spec)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_os_sys_info (machine spec)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_exec_sessions;
    INSERT @out VALUES ('DMV','sys.dm_exec_sessions (who is active)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_exec_sessions (who is active)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_os_wait_stats;
    INSERT @out VALUES ('DMV','sys.dm_os_wait_stats','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_os_wait_stats','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_io_virtual_file_stats(NULL,NULL);
    INSERT @out VALUES ('DMV','sys.dm_io_virtual_file_stats (storage latency)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_io_virtual_file_stats (storage latency)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_server_services;
    INSERT @out VALUES ('DMV','sys.dm_server_services (service acct, IFI/LPIM)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_server_services (service acct, IFI/LPIM)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_os_loaded_modules;
    INSERT @out VALUES ('DMV','sys.dm_os_loaded_modules (injected-DLL check)','PASS','replaces get_host_dll_versions; needs no SMB share');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_os_loaded_modules (injected-DLL check)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_server_memory_dumps;
    INSERT @out VALUES ('DMV','sys.dm_server_memory_dumps','PASS','NB restart-scoped: zero here is NOT evidence of no crash');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_server_memory_dumps','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

/* Dump-file inventory without ADMINISTER BULK OPERATIONS — the replacement path. */
BEGIN TRY
    SELECT @s = CONVERT(nvarchar(4000), SERVERPROPERTY('ErrorLogFileName'));
    -- Separator-aware: the ERRORLOG path uses '/' on SQL Server on Linux.
    SELECT @n = COUNT(*) FROM sys.dm_os_enumerate_filesystem(
        LEFT(@s, LEN(@s) - CHARINDEX(CASE WHEN CHARINDEX(N'\', @s) > 0 THEN N'\' ELSE N'/' END, REVERSE(@s))), '*.*');
    INSERT @out VALUES ('DMV','sys.dm_os_enumerate_filesystem (dump inventory)','PASS','dump LIST works without bulk rights');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_os_enumerate_filesystem (dump inventory)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.master_files mf CROSS APPLY sys.dm_os_volume_stats(mf.database_id, mf.file_id);
    INSERT @out VALUES ('DMV','sys.dm_os_volume_stats (disk free)','PASS','BLIND SPOT: DB volumes only - misses the backup volume and C:\');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DMV','sys.dm_os_volume_stats (disk free)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

/* ---------- 4. HADR: the failover gate ----------------------------------- */
BEGIN TRY  SELECT @n = COUNT(*) FROM sys.dm_hadr_database_replica_states;
    INSERT @out VALUES ('HADR','dm_hadr_database_replica_states (LSN gate)','PASS','checks 1-3 of the failover gate');
END TRY BEGIN CATCH
    INSERT @out SELECT 'HADR','dm_hadr_database_replica_states (LSN gate)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM sys.availability_groups ag JOIN sys.availability_replicas ar ON ar.group_id = ag.group_id;
    INSERT @out VALUES ('HADR','availability_groups + replicas (failure policy)','PASS','needs VIEW ANY DEFINITION');
END TRY BEGIN CATCH
    INSERT @out SELECT 'HADR','availability_groups + replicas (failure policy)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM msdb.dbo.suspect_pages;
    INSERT @out VALUES ('HADR','msdb.dbo.suspect_pages','PASS','check 4 of the failover gate');
END TRY BEGIN CATCH
    INSERT @out SELECT 'HADR','msdb.dbo.suspect_pages','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE()+' -- the failover gate CANNOT be evaluated on this node'; END CATCH

/* ---------- 5. ERRORLOG, jobs, backups ----------------------------------- */
BEGIN TRY
    DECLARE @log TABLE (LogDate datetime, ProcessInfo nvarchar(100), Txt nvarchar(max));
    INSERT @log EXEC sys.xp_readerrorlog 0, 1, N'Server', NULL, NULL, NULL, N'DESC';
    INSERT @out SELECT 'ERRORLOG','sys.xp_readerrorlog','PASS', CAST(@@ROWCOUNT AS nvarchar(10))+' row(s) - no securityadmin needed';
END TRY BEGIN CATCH
    INSERT @out SELECT 'ERRORLOG','sys.xp_readerrorlog','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM msdb.dbo.sysjobs;
    INSERT @out SELECT 'Agent','msdb.dbo.sysjobs (job inventory)',
        CASE WHEN @n > 0 THEN 'PASS' ELSE 'UNMEASURED' END,
        CASE WHEN @n > 0 THEN CAST(@n AS nvarchar(10))+' job(s) visible'
             ELSE 'ZERO jobs visible - SQLAgentReaderRole filters silently, it does not error. Membership missing?' END;
END TRY BEGIN CATCH
    INSERT @out SELECT 'Agent','msdb.dbo.sysjobs (job inventory)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM msdb.dbo.backupset;
    INSERT @out VALUES ('Backup','msdb.dbo.backupset (backup age)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Backup','msdb.dbo.backupset (backup age)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

/* The both-replicas-skip-a-backup check. Backup jobs that honour the preferred-replica
   setting skip a database on every replica that does not consider itself preferred - and
   if NO replica does, the database is never backed up while every job reports success. A
   green job proves nothing, so this query IS the monitoring; if the login cannot run it,
   the gap stays invisible. */
BEGIN TRY
    SELECT @n = COUNT(*) FROM sys.databases d
    CROSS APPLY (SELECT sys.fn_hadr_backup_is_preferred_replica(d.name) AS p) x
    WHERE d.database_id > 4;
    INSERT @out VALUES ('Backup','fn_hadr_backup_is_preferred_replica (skipped backups)','PASS','the both-replicas-skipped check can run');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Backup','fn_hadr_backup_is_preferred_replica (skipped backups)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE()+' -- the silent-backup-gap check CANNOT run'; END CATCH

/* Agent token scan — finding job steps whose command carries a dollar-paren sequence, which SQL Agent
   tries to expand as a job token (a PowerShell subexpression in a step is the usual culprit).
   Written without the two characters themselves: sqlcmd would read them as a scripting variable
   and refuse to run this file. */
BEGIN TRY  SELECT @n = COUNT(*) FROM msdb.dbo.sysjobsteps;
    INSERT @out VALUES ('Agent','msdb.dbo.sysjobsteps (Agent job-token scan)','PASS','');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Agent','msdb.dbo.sysjobsteps (Agent job-token scan)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

/* Truncated job history — the replacement for reading the on-disk output file, which this
   login cannot do. Empty is EXPECTED until a job has log-to-table enabled (sysjobsteps.flags
   bit 16); what must not happen is a permission error, which would mean the remedy is
   unavailable. */
BEGIN TRY  SELECT @n = COUNT(*) FROM msdb.dbo.sysjobstepslogs;
    INSERT @out SELECT 'Agent','msdb.dbo.sysjobstepslogs (untruncated step output)','PASS',
        CASE WHEN @n = 0 THEN 'readable, currently empty - enable log-to-table (flags bit 16) on jobs whose output matters'
             ELSE CAST(@n AS nvarchar(10))+' row(s)' END;
END TRY BEGIN CATCH
    INSERT @out SELECT 'Agent','msdb.dbo.sysjobstepslogs (untruncated step output)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE()+' -- only the 3,998-char truncated sysjobhistory message remains'; END CATCH

/* ---------- 6. CONNECT ANY DATABASE — exercised, not assumed ------------- */
/* Enter a database the per-database grant loop never provisioned. Metadata only. */
BEGIN TRY
    SET @s = N'USE [AppDb_Analytics]; SELECT @c = COUNT(*) FROM sys.tables;';
    EXEC sys.sp_executesql @s, N'@c int OUTPUT', @c = @n OUTPUT;
    INSERT @out VALUES ('Reach','USE [AppDb_Analytics] (CONNECT ANY DATABASE)','PASS','entered a non-provisioned database');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Reach','USE [AppDb_Analytics] (CONNECT ANY DATABASE)',
        CASE WHEN ERROR_NUMBER() IN (911,976,978) THEN 'UNMEASURED' ELSE 'FAIL' END,
        CASE WHEN ERROR_NUMBER() IN (911,976,978)
             THEN 'db absent or not readable on THIS node - grant not exercised, retry on a node that hosts it'
             ELSE 'err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE() END; END CATCH

BEGIN TRY  SELECT @n = COUNT(*) FROM DBA.dbo.CommandLog;
    INSERT @out VALUES ('DBA db','DBA.dbo.CommandLog (CHECKDB history)','PASS','replaces Get-DbaLastGoodCheckDb / DBCC DBINFO');
END TRY BEGIN CATCH
    INSERT @out SELECT 'DBA db','DBA.dbo.CommandLog (CHECKDB history)','FAIL','err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE(); END CATCH

/* ---------- 7. NEGATIVE ASSERTIONS — only a real denial counts ----------- */
/* 229 = permission denied on object; 230 = permission denied on column;
   297 = no permission to perform this action. Anything else did NOT exercise the
   control, so it is UNMEASURED — never PASS. */
BEGIN TRY
    SET @s = N'SELECT TOP 1 1 FROM AppDb_Data.msg.MessageLog;';
    EXEC sys.sp_executesql @s;
    INSERT @out VALUES ('Boundary','CANNOT read customer data (msg.MessageLog)','FAIL','the login CAN read msg.MessageLog - remove db_datareader');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Boundary','CANNOT read customer data (msg.MessageLog)',
        CASE WHEN ERROR_NUMBER() IN (229,230,297) THEN 'PASS' ELSE 'UNMEASURED' END,
        CASE WHEN ERROR_NUMBER() IN (229,230,297) THEN 'denied (err '+CAST(ERROR_NUMBER() AS nvarchar(10))+')'
             ELSE 'NOT a permission denial - err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE()
                  +' -- the DENY was NEVER EXERCISED on this node. Re-run where AppDb_Data is readable.' END; END CATCH

/* Two write shapes, because CREATE and UPDATE fail for different reasons: a login
   that cannot CREATE but holds db_datawriter somewhere would pass a CREATE-only probe. */
BEGIN TRY
    SET @s = N'SELECT TOP 0 name INTO dbo.zz_sqldiag_probe FROM sys.objects;';
    EXEC sys.sp_executesql @s;
    INSERT @out VALUES ('Boundary','CANNOT create objects','FAIL','CREATE succeeded - DROP dbo.zz_sqldiag_probe and revoke');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Boundary','CANNOT create objects',
        CASE WHEN ERROR_NUMBER() IN (229,230,262,297) THEN 'PASS' ELSE 'UNMEASURED' END,
        CASE WHEN ERROR_NUMBER() IN (229,230,262,297) THEN 'denied (err '+CAST(ERROR_NUMBER() AS nvarchar(10))+')'
             ELSE 'NOT a permission denial - err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE() END; END CATCH

BEGIN TRY
    -- A non-identity column: SET ID = ID fails to compile (Msg 8102, identity) before any
    -- permission check, so it could only ever report UNMEASURED.
    SET @s = N'UPDATE DBA.dbo.CommandLog SET DatabaseName = DatabaseName WHERE 1 = 0;';
    EXEC sys.sp_executesql @s;
    INSERT @out VALUES ('Boundary','CANNOT update a table it can READ','FAIL','UPDATE succeeded on DBA.dbo.CommandLog - revoke');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Boundary','CANNOT update a table it can READ',
        CASE WHEN ERROR_NUMBER() IN (229,230,297) THEN 'PASS' ELSE 'UNMEASURED' END,
        CASE WHEN ERROR_NUMBER() IN (229,230,297) THEN 'denied (err '+CAST(ERROR_NUMBER() AS nvarchar(10))+')'
             ELSE 'NOT a permission denial - err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE() END; END CATCH

BEGIN TRY
    SET @s = N'EXEC msdb.dbo.sp_start_job @job_name = N''__no_such_job_sqldiag_probe__'';';
    EXEC sys.sp_executesql @s;
    INSERT @out VALUES ('Boundary','CANNOT start an Agent job','FAIL','sp_start_job was reachable - check the DENY in PART F');
END TRY BEGIN CATCH
    INSERT @out SELECT 'Boundary','CANNOT start an Agent job',
        CASE WHEN ERROR_NUMBER() IN (229,297) THEN 'PASS' ELSE 'UNMEASURED' END,
        CASE WHEN ERROR_NUMBER() IN (229,297) THEN 'denied (err '+CAST(ERROR_NUMBER() AS nvarchar(10))+')'
             ELSE 'NOT a permission denial - err '+CAST(ERROR_NUMBER() AS nvarchar(10))+': '+ERROR_MESSAGE()
                  +' -- a "job does not exist" error means the DENY was NOT exercised' END; END CATCH

/* ---------- Report ------------------------------------------------------- */
SELECT Seq, Area, Capability, Result, Detail FROM @out ORDER BY Seq;

DECLARE @fail int, @unmeasured int;
SELECT @fail = SUM(CASE WHEN Result = 'FAIL' THEN 1 ELSE 0 END),
       @unmeasured = SUM(CASE WHEN Result = 'UNMEASURED' THEN 1 ELSE 0 END)
FROM @out;

PRINT '';
PRINT 'FAIL       : ' + CAST(@fail AS nvarchar(10)) + '   (capability broken or a control missing - fix before use)';
PRINT 'UNMEASURED : ' + CAST(@unmeasured AS nvarchar(10)) + '   (NOT a pass - the check could not be exercised HERE)';
PRINT '';
IF @fail > 0
    PRINT '>>> NOT READY on ' + @@SERVERNAME + '. Resolve every FAIL.';
ELSE IF @unmeasured > 0
    PRINT '>>> PARTIALLY VERIFIED on ' + @@SERVERNAME + '. Every UNMEASURED row must be exercised on a node '
        + 'where that database is readable before this login is trusted on every node.';
ELSE
    PRINT '>>> VERIFIED on ' + @@SERVERNAME + '.';
GO
