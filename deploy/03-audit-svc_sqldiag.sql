/* ============================================================================
   03-audit-svc_sqldiag.sql — the detective control for the diagnostic login.
   ----------------------------------------------------------------------------
   RUN ON EVERY NODE, after 01-svc_sqldiag-login-and-grants.sql.
   Requires ALTER ANY SERVER AUDIT — run it as a DBA, NOT as svc_sqldiag.

   WHY A SERVER AUDIT AND NOT AN XE SESSION KEYED ON APP_NAME()
   The obvious design is to filter on the marker the agent sets in its connection
   string (program_name / APP_NAME()) or on a leading SQL comment. Both are
   CLIENT-SUPPLIED STRINGS. Anything connecting with that login can set, omit or
   forge them, so an audit keyed on them answers "what did sessions that chose to
   identify themselves as the agent do" — which is not the question. This audit
   binds to the SERVER PRINCIPAL (`svc_sqldiag`), which the client cannot choose.

   WHAT IT IS FOR
   The grants in 01-* are preventive: they stop things. This is detective: it
   tells you what actually happened, which is what an access review, an incident
   post-mortem, or a "did the agent do that?" question needs. Without it the
   answer is inference from the ERRORLOG, and there is no record at all of which
   objects were touched.

   COST: one audit, principal-filtered, so on a node where svc_sqldiag is idle it
   writes nothing. Budget ~2 GB (20 x 100 MB, rollover). Adjust MAXSIZE/MAX_ROLLOVER_FILES
   for your retention; see the sizing note at the bottom before changing them.
   ============================================================================ */

USE master;
GO

/* ---------- 1. The audit target ------------------------------------------ */
-- Path note: this writes into the ERRORLOG directory, whose location can differ from node to
-- node (the -e startup parameter often relocates it to a dedicated log volume while the
-- install tree stays on C:). Derive it rather than hardcoding a drive letter, for the same
-- reason dumpPaths.ts derives the dump directory instead of assuming the default install path.
-- The directory must already exist: CREATE SERVER AUDIT does not create it, so the ERRORLOG
-- directory (which always exists) is the default. The files are named Audit_SvcSqlDiag_*.sqlaudit.
-- Separator-aware, so the same script runs on SQL Server on Linux (/var/opt/mssql/log/).
DECLARE @log nvarchar(4000) = CONVERT(nvarchar(4000), SERVERPROPERTY('ErrorLogFileName'));
DECLARE @sep nchar(1) = CASE WHEN CHARINDEX(N'\', @log) > 0 THEN N'\' ELSE N'/' END;
DECLARE @auditDir nvarchar(4000) = LEFT(@log, LEN(@log) - CHARINDEX(@sep, REVERSE(@log)) + 1);
-- To keep the audit on its own volume instead, create the folder on the node first, then:
-- SET @auditDir = N'<AuditLogPath>';

DECLARE @sql nvarchar(max);

IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name = N'Audit_SvcSqlDiag')
BEGIN
    SET @sql = N'
    CREATE SERVER AUDIT [Audit_SvcSqlDiag]
      TO FILE ( FILEPATH = ' + QUOTENAME(@auditDir, '''') + N',
                MAXSIZE = 100 MB,
                MAX_ROLLOVER_FILES = 20,
                RESERVE_DISK_SPACE = OFF )
      WITH ( QUEUE_DELAY = 1000,
             -- CONTINUE, deliberately. ON_FAILURE = SHUTDOWN would let a full audit
             -- volume take the INSTANCE down, which converts a monitoring gap into an
             -- outage. This audit exists to explain incidents, not to cause them.
             ON_FAILURE = CONTINUE );';
    EXEC sys.sp_executesql @sql;
    PRINT 'Created server audit Audit_SvcSqlDiag -> ' + @auditDir;
END
ELSE PRINT 'Server audit Audit_SvcSqlDiag already exists - leaving it alone.';
GO

ALTER SERVER AUDIT [Audit_SvcSqlDiag] WITH (STATE = ON);
GO

/* ---------- 2. What to record, filtered to the principal ----------------- */
IF NOT EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = N'AuditSpec_SvcSqlDiag')
BEGIN
    CREATE SERVER AUDIT SPECIFICATION [AuditSpec_SvcSqlDiag]
      FOR SERVER AUDIT [Audit_SvcSqlDiag]
        -- Every connection: when the login is used, from where, and by what client.
        ADD (SUCCESSFUL_LOGIN_GROUP),
        -- Repeated failures here are the lockout signal for the CHECK_POLICY trade-off
        -- documented in 01-*: watch this before it locks out mid-incident.
        ADD (FAILED_LOGIN_GROUP),
        -- Anything DENIED. On a correctly-provisioned node this should be EMPTY; rows here
        -- mean either the grants are wrong or something is probing past them. Both are
        -- worth a look, and this is the row set to alert on.
        ADD (SCHEMA_OBJECT_ACCESS_GROUP),
        -- Changes to what this principal can do. If the login's own permissions change,
        -- the preventive control in 01-* has moved and this is the only place that says so.
        ADD (SERVER_PERMISSION_CHANGE_GROUP),
        ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
        ADD (DATABASE_PERMISSION_CHANGE_GROUP),
        ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
        -- Impersonation: the one way this principal could act as something else.
        ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP),
        ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP)
      WITH (STATE = OFF);
    PRINT 'Created AuditSpec_SvcSqlDiag.';
END
GO
ALTER SERVER AUDIT SPECIFICATION [AuditSpec_SvcSqlDiag] WITH (STATE = ON);
GO

/* ---------- 3. A read path for the audit, for humans --------------------- */
-- NOTE: if your DBA database is deployed from a database project (SSDT / dacpac), add this
-- view to that project as well, or it never deploys from source and a later publish that
-- drops objects not in the project will remove it.
USE DBA;
GO
CREATE OR ALTER VIEW dbo.AuditSqlDiag
AS
SELECT TOP 100 PERCENT
       a.event_time,
       a.server_principal_name,
       a.database_name,
       a.schema_name,
       a.object_name,
       a.statement,
       a.succeeded,
       a.client_ip,
       -- CLIENT-SUPPLIED, therefore UNTRUSTED. Useful for correlating a run, never for
       -- deciding whether something was the agent: the principal column above is the
       -- only non-forgeable answer to that.
       a.application_name       AS application_name_UNTRUSTED,
       a.action_id,
       a.class_type
FROM   sys.fn_get_audit_file(
           -- Same derivation as the audit target above.
           (SELECT LEFT(log_file_path, LEN(log_file_path)) + N'Audit_SvcSqlDiag*.sqlaudit'
            FROM   sys.server_file_audits WHERE name = N'Audit_SvcSqlDiag'),
           DEFAULT, DEFAULT) AS a
WHERE  a.server_principal_name = N'svc_sqldiag'
ORDER  BY a.event_time DESC;
GO

/* ---------- 4. Verify it is actually recording --------------------------- */
-- An audit that is configured but not running is worse than none, because it reads as
-- covered. Both columns must be 1.
SELECT sa.name                AS audit_name,
       sa.is_state_enabled    AS audit_on,
       spec.is_state_enabled  AS spec_on,
       fa.log_file_path
FROM   sys.server_audits sa
LEFT  JOIN sys.server_audit_specifications spec ON spec.audit_guid = sa.audit_guid
LEFT  JOIN sys.server_file_audits fa            ON fa.audit_id     = sa.audit_id
WHERE  sa.name = N'Audit_SvcSqlDiag';
GO

/* ============================================================================
   SIZING / OPERATING NOTES

   - 100 MB x 20 files = ~2 GB steady state, on the ERRORLOG volume. If that volume
     holds no database file, a disk check built on sys.master_files /
     sys.dm_os_volume_stats cannot see it, so add it to whatever watches free space,
     or the first symptom of it filling is audit loss with ON_FAILURE = CONTINUE.
   - SCHEMA_OBJECT_ACCESS_GROUP records DENIED access, not every SELECT, so the volume
     is driven by failures rather than by traffic. If you widen this spec to record
     successful reads, re-do the sizing first: the agent reads DMVs continuously.
   - ALERT ON: any FAILED_LOGIN for svc_sqldiag (lockout precursor), any
     SCHEMA_OBJECT_ACCESS denial (grants wrong, or probing), and any
     SERVER_PERMISSION_CHANGE / SERVER_ROLE_MEMBER_CHANGE naming this principal
     (someone widened it - including the sysadmin rollback in 01-*).

   ROLLBACK
     ALTER SERVER AUDIT SPECIFICATION [AuditSpec_SvcSqlDiag] WITH (STATE = OFF);
     ALTER SERVER AUDIT [Audit_SvcSqlDiag] WITH (STATE = OFF);
     DROP SERVER AUDIT SPECIFICATION [AuditSpec_SvcSqlDiag];
     DROP SERVER AUDIT [Audit_SvcSqlDiag];
   ============================================================================ */
