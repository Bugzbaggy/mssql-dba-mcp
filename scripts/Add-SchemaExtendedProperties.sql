/*============================================================================
  Add-SchemaExtendedProperties.sql

  Adds MS_Description extended properties to the non-obvious columns that the
  schema-doc review flagged, so their semantics surface directly in the MCP
  describe_object tool (which now reads sys.extended_properties) and in SSMS.

  WHY: describe_object returns names/types/nullability/indexes but cannot encode
  a column's DIRECTION, key-stability, or units. Those live only in stored-proc
  logic or tribal knowledge, so a correct schema read can still produce a wrong
  answer. These descriptions move that knowledge into discoverable metadata.

  WHERE TO RUN (read-only fleet caveat — run on the WRITABLE primary of each region):
    * Section A (route.ChannelFallback) -> the CONFIG/REFERENCE database:
        AppCatalog on the primary region, AppDb on the secondary regions.
      On the primary region this is the replication Publisher; let it propagate, OR run per region.
    * Section B (bi.*) -> AppDb_Analytics (region-local) on each region's primary.

  SAFE TO RE-RUN: each block drops the property if it already exists, then adds
  it. Each block is guarded by an OBJECT_ID/COLUMN existence check so running a
  section in the wrong database is a no-op rather than an error.

  This script is a DELIVERABLE for a DBA to run in a change window — it is DDL on
  the application databases and is intentionally OUTSIDE the MCP's read-only scope.
============================================================================*/
SET NOCOUNT ON;

/*--------------------------------------------------------------------------
  Section A — CONFIG database (AppCatalog on the primary region / AppDb on the secondary regions)
  Run in the context of that database (USE AppCatalog; or USE AppDb;).
--------------------------------------------------------------------------*/
IF OBJECT_ID(N'route.ChannelFallback', N'U') IS NOT NULL
BEGIN
    -- route.ChannelFallback.Priority — counter-intuitive ordering
    IF EXISTS (SELECT 1 FROM fn_listextendedproperty(N'MS_Description', N'SCHEMA', N'route', N'TABLE', N'ChannelFallback', N'COLUMN', N'Priority'))
        EXEC sys.sp_dropextendedproperty @name=N'MS_Description',
            @level0type=N'SCHEMA', @level0name=N'route',
            @level1type=N'TABLE',  @level1name=N'ChannelFallback',
            @level2type=N'COLUMN', @level2name=N'Priority';
    EXEC sys.sp_addextendedproperty @name=N'MS_Description',
        @value=N'Fallback-chain order. COUNTER-INTUITIVE: HIGHER value = tried FIRST (primary channel); LOWEST = final fallback. Chain is consumed Priority DESC (route.ChannelFallback_Get ... ORDER BY [Priority] DESC). Do NOT assume Priority 1 = primary. Primary = MAX(Priority) per subaccount; final fallback = MIN(Priority). SMS spans BOTH ChannelType codes SM and SS. Read via route.vwChannelFallback.',
        @level0type=N'SCHEMA', @level0name=N'route',
        @level1type=N'TABLE',  @level1name=N'ChannelFallback',
        @level2type=N'COLUMN', @level2name=N'Priority';
    PRINT 'Set MS_Description on route.ChannelFallback.Priority';
END
ELSE
    PRINT 'Skipped Section A: route.ChannelFallback not found in the current database.';

/*--------------------------------------------------------------------------
  Section B — AppDb_Analytics (region-local). Run with: USE AppDb_Analytics;
  SCD-2 surrogate-vs-natural-key trap on the manager dimension.
--------------------------------------------------------------------------*/
IF OBJECT_ID(N'bi.Manager', N'U') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM fn_listextendedproperty(N'MS_Description', N'SCHEMA', N'bi', N'TABLE', N'Manager', N'COLUMN', N'ManagerId'))
        EXEC sys.sp_dropextendedproperty @name=N'MS_Description', @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'Manager', @level2type=N'COLUMN',@level2name=N'ManagerId';
    EXEC sys.sp_addextendedproperty @name=N'MS_Description',
        @value=N'SURROGATE key (SCD-2 version id). bi.Manager is SCD-2, so the SAME person recurs under multiple ManagerIds. For DISTINCT owners, collapse on the natural key UserID (or Email), NOT ManagerId.',
        @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'Manager', @level2type=N'COLUMN',@level2name=N'ManagerId';
    PRINT 'Set MS_Description on bi.Manager.ManagerId';

    IF COL_LENGTH(N'bi.Manager', N'UserID') IS NOT NULL
    BEGIN
        IF EXISTS (SELECT 1 FROM fn_listextendedproperty(N'MS_Description', N'SCHEMA', N'bi', N'TABLE', N'Manager', N'COLUMN', N'UserID'))
            EXEC sys.sp_dropextendedproperty @name=N'MS_Description', @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'Manager', @level2type=N'COLUMN',@level2name=N'UserID';
        EXEC sys.sp_addextendedproperty @name=N'MS_Description',
            @value=N'STABLE natural identity of the manager (person). Use this (or Email) to identify a unique manager across SCD-2 versions; the surrogate ManagerId changes per version.',
            @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'Manager', @level2type=N'COLUMN',@level2name=N'UserID';
        PRINT 'Set MS_Description on bi.Manager.UserID';
    END
END
ELSE
    PRINT 'Skipped Section B (bi.Manager): not found in the current database.';

IF OBJECT_ID(N'bi.DimManager_Account', N'U') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM fn_listextendedproperty(N'MS_Description', N'SCHEMA', N'bi', N'TABLE', N'DimManager_Account', N'COLUMN', N'DimManagerId'))
        EXEC sys.sp_dropextendedproperty @name=N'MS_Description', @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'DimManager_Account', @level2type=N'COLUMN',@level2name=N'DimManagerId';
    EXEC sys.sp_addextendedproperty @name=N'MS_Description',
        @value=N'FK to bi.Manager.ManagerId (SURROGATE). bi.Manager is SCD-2, so one person spans multiple DimManagerIds; reading DISTINCT DimManagerId overstates owner changes. Collapse on bi.Manager.UserID for distinct owners, or use bi.vwDimManagerAccount.',
        @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'DimManager_Account', @level2type=N'COLUMN',@level2name=N'DimManagerId';
    PRINT 'Set MS_Description on bi.DimManager_Account.DimManagerId';
END
ELSE
    PRINT 'Skipped bi.DimManager_Account: not found in the current database.';

IF OBJECT_ID(N'bi.DimManager_Partner', N'U') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM fn_listextendedproperty(N'MS_Description', N'SCHEMA', N'bi', N'TABLE', N'DimManager_Partner', N'COLUMN', N'DimManagerId'))
        EXEC sys.sp_dropextendedproperty @name=N'MS_Description', @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'DimManager_Partner', @level2type=N'COLUMN',@level2name=N'DimManagerId';
    EXEC sys.sp_addextendedproperty @name=N'MS_Description',
        @value=N'FK to bi.Manager.ManagerId (SURROGATE). bi.Manager is SCD-2, so one person spans multiple DimManagerIds; reading DISTINCT DimManagerId overstates owner changes. Collapse on bi.Manager.UserID for distinct owners, or use bi.vwDimManagerPartner.',
        @level0type=N'SCHEMA',@level0name=N'bi', @level1type=N'TABLE',@level1name=N'DimManager_Partner', @level2type=N'COLUMN',@level2name=N'DimManagerId';
    PRINT 'Set MS_Description on bi.DimManager_Partner.DimManagerId';
END
ELSE
    PRINT 'Skipped bi.DimManager_Partner: not found in the current database.';
GO
