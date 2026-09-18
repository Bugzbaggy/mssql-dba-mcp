/**
 * Query safety validation — layer 3 of read-only defense-in-depth.
 *
 * The real guarantee is the SQL login's privilege set (CONNECT + VIEW SERVER STATE
 * + VIEW ANY DEFINITION + db_datareader/VIEW DATABASE STATE — no write rights) and
 * the ApplicationIntent=ReadOnly connection. This allowlist is the third,
 * independent layer: it rejects anything that is not a read before it ever reaches
 * the server, and gives the agent a clear error instead of a SQL permission failure.
 *
 * Only the free-form `execute_query` tool runs user-supplied SQL through here. The
 * 28 built-in DMV tools build fixed SQL internally and do not use this function.
 */

const MAX_QUERY_LENGTH = 20_000;

const ALLOWED_START = /^\s*(SELECT|WITH|DECLARE)\b/i;

// ── Sensitive / large transactional tables (data-governance guardrail) ─────────
// AppDb_Data holds the high-volume transactional data; its large partitioned tables
// (messageLog and friends) are business-critical, so an unbounded scan is both a
// performance and a sensitivity risk. For analysis the answer almost always lives in
// the pre-aggregated tables in AppDb_Analytics. This guard nudges that: a query that
// touches a sensitive table WITHOUT a bound (no WHERE / TOP / OFFSET) is rejected with
// a redirect to AppDb_Analytics, unless the caller explicitly opts in (allow_large_scan).
// Extend the list per region/schema via the SENSITIVE_TABLES env var (comma-separated).
const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SENSITIVE_TABLES = (process.env.SENSITIVE_TABLES ?? "messageLog")
  .split(",").map((s) => s.trim()).filter(Boolean);
const SENSITIVE_RE = SENSITIVE_TABLES.length
  ? new RegExp(`\\b(${SENSITIVE_TABLES.map(escapeRegex).join("|")})\\b`, "i")
  : null;

// Each pattern matches a write / DDL / DCL / state-changing operation anywhere in
// the (comment-stripped) query. Word boundaries keep these from matching column or
// alias names like "updated_at" or "created_date".
const BLOCKED_PATTERNS: Array<[RegExp, string]> = [
  // ── Data modification (DML) ────────────────────────────────────────────────
  [/\bINSERT\s+INTO\b/i,                          "INSERT"],
  [/\bUPDATE\s+\w/i,                              "UPDATE"],
  [/\bDELETE\s+(FROM|TOP|\w)/i,                   "DELETE"],
  [/\bMERGE\s+(INTO\s+)?\w/i,                     "MERGE"],
  [/\bTRUNCATE\s+TABLE\b/i,                       "TRUNCATE"],
  [/\bSELECT\b[\s\S]*?\bINTO\s+[^@#]/i,           "SELECT ... INTO (permanent table; #temp / @table only)"],
  [/\bBULK\s+INSERT\b/i,                          "BULK INSERT"],
  // ── Schema / object DDL ──────────────────────────────────────────────────────
  [/\b(CREATE|ALTER|DROP)\s+(TABLE|DATABASE|INDEX|VIEW|PROC|PROCEDURE|FUNCTION|TRIGGER|SCHEMA|SEQUENCE|TYPE|ROLE|LOGIN|USER|SERVER|ENDPOINT|AVAILABILITY|CERTIFICATE|MASTER|CREDENTIAL|ASSEMBLY|PARTITION|SYNONYM|AGGREGATE|QUEUE|SERVICE|XML|FULLTEXT)\b/i, "CREATE/ALTER/DROP DDL"],
  [/\bALTER\s+ANY\b/i,                            "ALTER ANY"],
  // ── Security / permissions (DCL) ─────────────────────────────────────────────
  [/\b(GRANT|REVOKE|DENY)\b/i,                    "GRANT/REVOKE/DENY"],
  // ── Backups, restores, recovery ──────────────────────────────────────────────
  [/\bBACKUP\s+(DATABASE|LOG|CERTIFICATE)\b/i,    "BACKUP"],
  [/\bRESTORE\s+(DATABASE|LOG|VERIFYONLY|HEADERONLY|FILELISTONLY)\b/i, "RESTORE"],
  // ── Server / session control ─────────────────────────────────────────────────
  [/\bRECONFIGURE\b/i,                            "RECONFIGURE"],
  [/\bSP_CONFIGURE\b/i,                           "sp_configure"],
  [/\bSHUTDOWN\b/i,                               "SHUTDOWN"],
  [/\bKILL\b\s+\d|\bKILL\s+UOW\b/i,               "KILL"],
  [/\bDBCC\b/i,                                   "DBCC"],
  [/\bWAITFOR\b/i,                                "WAITFOR (would pin a connection)"],
  [/\bRESTORE\b/i,                                "RESTORE"],
  // ── Dangerous extended / OLE / agent / FS procedures ─────────────────────────
  [/\bXP_CMDSHELL\b/i,                            "xp_cmdshell"],
  [/\bXP_\w+/i,                                   "xp_ extended procedure"],
  [/\bSP_OA\w+/i,                                 "sp_OA* OLE automation"],
  [/\bSP_ADD\w+/i,                                "sp_add* (agent/job/operator)"],
  [/\bSP_EXECUTESQL\b/i,                          "sp_executesql (dynamic SQL)"],
  [/\bOPENROWSET\b/i,                             "OPENROWSET"],
  [/\bOPENDATASOURCE\b/i,                         "OPENDATASOURCE"],
  [/\bOPENQUERY\b/i,                              "OPENQUERY"],
  // ── Statement-batching tricks to smuggle a second command past ALLOWED_START ─
  [/;\s*(EXEC|EXECUTE|INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|GRANT|REVOKE|DENY|BACKUP|RESTORE|TRUNCATE)\b/i, "second statement after ';'"],
];

/**
 * Remove string literals, line comments and block comments so that blocked
 * keywords cannot be hidden inside `/* ... *\/`, `-- ...`, or quoted text, and so
 * that a column literal like 'DROP TABLE' in a WHERE clause is not a false match.
 */
function stripNoise(query: string): string {
  return query
    .replace(/'(?:[^']|'')*'/g, "''")   // collapse string literals
    .replace(/--[^\n\r]*/g, " ")        // line comments
    .replace(/\/\*[\s\S]*?\*\//g, " ");  // block comments
}

export function validateQuery(
  query: string,
  opts?: { allowLargeScan?: boolean }
): { valid: boolean; reason?: string } {
  if (query.length > MAX_QUERY_LENGTH) {
    return {
      valid: false,
      reason: `Query exceeds the ${MAX_QUERY_LENGTH}-character limit (${query.length}).`,
    };
  }

  const cleaned = stripNoise(query).trim();

  if (!ALLOWED_START.test(cleaned)) {
    return {
      valid: false,
      reason:
        "Only SELECT, WITH (CTE), or DECLARE statements are allowed. Received: " +
        cleaned.substring(0, 60),
    };
  }

  for (const [pattern, label] of BLOCKED_PATTERNS) {
    if (pattern.test(cleaned)) {
      return {
        valid: false,
        reason: `Query is not read-only — blocked operation detected: ${label}.`,
      };
    }
  }

  // Data-governance: don't scan a large/critical transactional table unbounded.
  if (!opts?.allowLargeScan && SENSITIVE_RE) {
    const m = cleaned.match(SENSITIVE_RE);
    if (m) {
      const bounded = /\bWHERE\b/i.test(cleaned) || /\bTOP\b/i.test(cleaned) || /\bOFFSET\b/i.test(cleaned);
      if (!bounded) {
        return {
          valid: false,
          reason:
            `"${m[1]}" is a large, business-critical transactional table in AppDb_Data. ` +
            `For analysis (counts, trends, reporting) query the PRE-AGGREGATED tables in AppDb_Analytics ` +
            `(e.g. the msg.StatMessageLog* tables) instead of scanning it. For a row-level lookup, scope the query ` +
            `with a WHERE on the key (e.g. message id / account / a narrow time range) and a TOP N. ` +
            `To run this scan anyway, set allow_large_scan:true.`,
        };
      }
    }
  }

  return { valid: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// validateWriteQuery — for the OPT-IN engineering write tool (execute_write) only.
//
// Allows data DML (INSERT/UPDATE/DELETE/MERGE) and EXEC of (application) stored
// procedures. SQL Server's per-user role grants remain the real authorization
// boundary; this is an additional hard guardrail so that — even for an
// over-privileged login — the AI can NEVER:
//   • drop a database or run any DDL (CREATE/ALTER/DROP of objects/logins/users/roles);
//   • change server or database settings (sp_configure/RECONFIGURE/ALTER SERVER/ALTER DATABASE);
//   • create/alter principals (logins/users/roles) or grant permissions (DCL);
//   • touch backups or SQL Agent jobs (BACKUP/RESTORE, any reference to msdb, job procs);
//   • run dynamic SQL (sp_executesql / EXEC()) that would smuggle the above past this gate;
//   • run an unqualified UPDATE/DELETE (no WHERE) unless explicitly allowed.
// ─────────────────────────────────────────────────────────────────────────────
const WRITE_ALLOWED_START = /^\s*(SELECT|WITH|DECLARE|INSERT|UPDATE|DELETE|MERGE|EXEC|EXECUTE)\b/i;

const WRITE_BLOCKED_PATTERNS: Array<[RegExp, string]> = [
  // No DDL of any kind (covers DROP/ALTER DATABASE, CREATE/ALTER/DROP LOGIN|USER|ROLE, ALTER SERVER, etc.)
  [/\b(CREATE|ALTER|DROP)\s+(TABLE|DATABASE|INDEX|VIEW|PROC|PROCEDURE|FUNCTION|TRIGGER|SCHEMA|SEQUENCE|TYPE|ROLE|LOGIN|USER|SERVER|ENDPOINT|AVAILABILITY|CERTIFICATE|MASTER|CREDENTIAL|ASSEMBLY|PARTITION|SYNONYM|AGGREGATE|QUEUE|SERVICE|XML|FULLTEXT|WORKLOAD)\b/i, "DDL (CREATE/ALTER/DROP) is not allowed"],
  [/\bALTER\s+ANY\b/i,                            "ALTER ANY"],
  [/\bTRUNCATE\s+TABLE\b/i,                       "TRUNCATE (use DELETE … WHERE)"],
  // No DCL / principals
  [/\b(GRANT|REVOKE|DENY)\b/i,                    "GRANT/REVOKE/DENY"],
  [/\bSP_(ADD|DROP)(SRV)?ROLEMEMBER\b/i,          "role membership change"],
  [/\bSP_(ADD|DROP)ROLE\b/i,                      "role create/drop"],
  [/\bSP_(ADD|DROP)LOGIN\b/i,                     "login create/drop"],
  [/\bSP_PASSWORD\b/i,                            "sp_password"],
  [/\bADD\s+MEMBER\b/i,                           "ALTER ROLE … ADD MEMBER"],
  // No settings / server / session control
  [/\bRECONFIGURE\b/i,                            "RECONFIGURE"],
  [/\bSP_CONFIGURE\b/i,                           "sp_configure"],
  [/\bSHUTDOWN\b/i,                               "SHUTDOWN"],
  [/\bKILL\b\s+\d|\bKILL\s+UOW\b/i,               "KILL"],
  [/\bDBCC\b/i,                                   "DBCC"],
  [/\bWAITFOR\b/i,                                "WAITFOR"],
  // No backups / restore / agent jobs (these live in msdb)
  [/\bBACKUP\s+(DATABASE|LOG|CERTIFICATE)\b/i,    "BACKUP"],
  [/\bRESTORE\b/i,                                "RESTORE"],
  [/\bMSDB\b/i,                                   "msdb (backups / SQL Agent jobs) is off-limits to writes"],
  [/\bSP_[A-Z_]*JOB\w*/i,                         "SQL Agent job procedure"],
  [/\bSP_[A-Z_]*SCHEDULE\w*/i,                    "SQL Agent schedule procedure"],
  [/\bSP_ADD_OPERATOR\b/i,                        "sp_add_operator"],
  // No dynamic SQL (would smuggle the above past this gate) or OLE / cmd / linked servers
  [/\bSP_EXECUTESQL\b/i,                          "sp_executesql (dynamic SQL)"],
  [/\bEXEC(UTE)?\s*\(/i,                          "dynamic EXEC()"],
  [/\bXP_\w+/i,                                   "xp_ extended procedure"],
  [/\bSP_OA\w+/i,                                 "sp_OA* OLE automation"],
  [/\bSP_ADDLINKED\w+/i,                          "linked server procedure"],
  [/\bOPENROWSET\b/i,                             "OPENROWSET"],
  [/\bOPENDATASOURCE\b/i,                         "OPENDATASOURCE"],
  [/\bOPENQUERY\b/i,                              "OPENQUERY"],
  // Smuggling a forbidden statement after ';'
  [/;\s*(CREATE|ALTER|DROP|GRANT|REVOKE|DENY|BACKUP|RESTORE|SHUTDOWN|DBCC|TRUNCATE|RECONFIGURE)\b/i, "forbidden statement after ';'"],
];

export function validateWriteQuery(
  query: string,
  opts?: { allowUnfiltered?: boolean }
): { valid: boolean; reason?: string } {
  if (query.length > MAX_QUERY_LENGTH) {
    return { valid: false, reason: `Query exceeds the ${MAX_QUERY_LENGTH}-character limit (${query.length}).` };
  }

  const cleaned = stripNoise(query).trim();

  if (!WRITE_ALLOWED_START.test(cleaned)) {
    return {
      valid: false,
      reason:
        "Only data writes are allowed here: INSERT / UPDATE / DELETE / MERGE / EXEC (or a leading SELECT/WITH/DECLARE). " +
        "Received: " + cleaned.substring(0, 60),
    };
  }

  for (const [pattern, label] of WRITE_BLOCKED_PATTERNS) {
    if (pattern.test(cleaned)) {
      return { valid: false, reason: `Blocked by the write guardrail (${label}). This stays read-only-ish: DML + EXEC only; SQL Server still enforces your login's grants.` };
    }
  }

  // Guard against table-wide UPDATE/DELETE (the classic "forgot the WHERE") unless opted in.
  if (!opts?.allowUnfiltered) {
    if (/\bUPDATE\s+[\w.\[\]]+\s+SET\b/i.test(cleaned) && !/\bWHERE\b/i.test(cleaned)) {
      return { valid: false, reason: "UPDATE without a WHERE clause is blocked (would affect every row). Add a WHERE, or pass allow_unfiltered:true." };
    }
    if (/\bDELETE\s+(FROM\s+)?[\w.\[\]]+/i.test(cleaned) && !/\bWHERE\b/i.test(cleaned)) {
      return { valid: false, reason: "DELETE without a WHERE clause is blocked (would delete every row). Add a WHERE, or pass allow_unfiltered:true." };
    }
  }

  return { valid: true };
}
