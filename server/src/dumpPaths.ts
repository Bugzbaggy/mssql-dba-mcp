// ─────────────────────────────────────────────────────────────────────────────
// Where SQLDump<NNNN>.txt actually lives — resolved, not guessed.
//
// Two independent things can move, and assuming either one is the reason a crash
// investigation finds "no dumps" on a node that has hundreds:
//
//   1. The ERRORLOG is relocated. `-e` puts it on a dedicated log volume
//      (e.g. D:\SQLLogs), while the dumps stay under the install
//      directory. So the ERRORLOG directory is NOT necessarily the dump directory.
//
//   2. The dump directory keeps the ORIGINAL major version across an in-place
//      upgrade. An instance upgraded from SQL 2019 can run sqlservr.exe out of
//      MSSQL16.MSSQLSERVER (SQL 2022) and still write its dumps to
//      **MSSQL15**.MSSQLSERVER\MSSQL\Log, leaving MSSQL16\MSSQL\Log empty. So
//      deriving the path from the RUNNING BINARY — the obvious "authoritative"
//      approach — can point at the wrong, empty directory.
//
// Because of (2) there is no single authoritative source to read: `ErrorDumpDir`
// lives in the registry under the instance's CPE key, and sys.dm_server_registry
// exposes only a whitelist that does not include it (it returns only InstallID for
// that key). So the resolution is: assemble every plausible candidate, then pick
// whichever one ACTUALLY CONTAINS SQLDump files, newest first. That is the part
// that is authoritative, and it is what the callers order by.
//
// What this replaces: a hardcoded `MSSQL15` / `MSSQL16` list on a hardcoded `C:`.
// That worked only by coincidence — it happened to contain the right version —
// and would have silently returned nothing on a SQL 2025 (MSSQL17) node or any
// install not on C:. Both hardcodings are now derived at query time.
//
// A site that keeps dumps somewhere none of the derived candidates reach (a
// relocated dump volume, say) lists those directories in SQL_EXTRA_DUMP_DIRS,
// separated by ';'. They are only probed, never trusted: like every other
// candidate, a directory wins only when it actually holds SQLDump files.
// ─────────────────────────────────────────────────────────────────────────────

/** Extra candidate directories from SQL_EXTRA_DUMP_DIRS (';'-separated), as T-SQL N'' literals. */
export function extraDumpDirLiterals(raw = process.env.SQL_EXTRA_DUMP_DIRS ?? ""): string[] {
  return raw
    .split(";")
    .map((d) => d.trim().replace(/[\\/]+$/, ""))
    .filter((d) => d.length > 0 && d.length <= 400)
    .map((d) => `N'${d.replace(/'/g, "''")}'`);
}

/**
 * DECLAREs the dump-directory candidate CTE depends on. Emit before {@link DUMP_DIR_CTE}.
 *
 * Derives, from the running sqlservr.exe path, the instance's own `…\MSSQL` directory and
 * the shared install root (`…\Microsoft SQL Server`) — so neither the drive letter nor the
 * MSSQL major version is hardcoded.
 */
export const DUMP_DIR_DECLARE =
  `DECLARE @log nvarchar(512)=CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(512));` +
  `DECLARE @errDir nvarchar(512)=LEFT(@log,LEN(@log)-CHARINDEX(CASE WHEN CHARINDEX('\\',@log)>0 THEN '\\' ELSE '/' END,REVERSE(@log)));` +
  // …\MSSQL16.MSSQLSERVER\MSSQL\Binn
  `DECLARE @binn nvarchar(512)=(SELECT TOP 1 LEFT(m.name,LEN(m.name)-CHARINDEX('\\',REVERSE(m.name)))` +
  ` FROM sys.dm_os_loaded_modules m WHERE m.name LIKE '%\\sqlservr.exe');` +
  // …\MSSQL16.MSSQLSERVER\MSSQL
  `DECLARE @mssql nvarchar(512)=CASE WHEN @binn IS NULL THEN NULL` +
  ` ELSE LEFT(@binn,LEN(@binn)-CHARINDEX('\\',REVERSE(@binn))) END;` +
  // …\MSSQL16.MSSQLSERVER
  `DECLARE @instDir nvarchar(512)=CASE WHEN @mssql IS NULL THEN NULL` +
  ` ELSE LEFT(@mssql,LEN(@mssql)-CHARINDEX('\\',REVERSE(@mssql))) END;` +
  // …\Microsoft SQL Server  (shared root holding EVERY MSSQL<nn>.<INSTANCE> directory)
  `DECLARE @root nvarchar(512)=ISNULL(CASE WHEN @instDir IS NULL THEN NULL` +
  ` ELSE LEFT(@instDir,LEN(@instDir)-CHARINDEX('\\',REVERSE(@instDir))) END,` +
  `N'C:\\Program Files\\Microsoft SQL Server');`;

/**
 * `;WITH cand(dir,pref) … d AS (…)` — every directory that could hold SQLDump files.
 * Consumers select `FROM d CROSS APPLY sys.dm_os_enumerate_filesystem(d.dir,'SQLDump*')`
 * and **order by last_write_time DESC**, so the directory actually holding the newest dump
 * wins regardless of candidate order. `pref` only breaks ties for identical paths.
 *
 * `sys.dm_os_enumerate_filesystem` returns 0 rows (not an error) for a missing directory,
 * so listing candidates that do not exist costs nothing.
 */
export function buildDumpDirCte(extra: string[] = extraDumpDirLiterals()): string {
  return (
    `;WITH cand(dir,pref) AS (` +
    // 0 — the ERRORLOG directory. Correct on nodes where -e was never relocated.
    `SELECT @errDir,0 ` +
    // 1 — the running instance's own Log directory.
    `UNION ALL SELECT @mssql+N'\\Log',1 ` +
    // 2 — EVERY sibling MSSQL<nn>.<INSTANCE> directory under the shared install root. This is
    //     what catches the in-place-upgrade case where a SQL 2022 instance still dumps into the
    //     SQL 2019 tree, and it covers named instances and future versions without a code change.
    //     The backslash-count test keeps it to direct children (the enumerator recurses).
    `UNION ALL SELECT f.full_filesystem_path+N'\\MSSQL\\Log',2 ` +
    `FROM sys.dm_os_enumerate_filesystem(@root,'MSSQL*') f ` +
    `WHERE f.is_directory=1 ` +
    `AND LEN(f.full_filesystem_path)-LEN(REPLACE(f.full_filesystem_path,'\\',''))` +
    `=LEN(@root)-LEN(REPLACE(@root,'\\',''))+1` +
    // 3 — site-specific directories from SQL_EXTRA_DUMP_DIRS, if any.
    extra.map((lit) => ` UNION ALL SELECT ${lit},3`).join("") +
    `),` +
    `d AS (SELECT dir,MIN(pref) AS pref FROM cand WHERE dir IS NOT NULL GROUP BY dir) `
  );
}

/** The candidate CTE for this process's configuration (SQL_EXTRA_DUMP_DIRS is read once, at load). */
export const DUMP_DIR_CTE = buildDumpDirCte();
