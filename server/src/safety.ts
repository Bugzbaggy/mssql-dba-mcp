/**
 * Query safety validation — layer 3 of read-only defense-in-depth.
 *
 * The real guarantee is the SQL login's privilege set (CONNECT + VIEW SERVER STATE
 * + VIEW ANY DEFINITION + db_datareader/VIEW DATABASE STATE — no write rights) and
 * the ApplicationIntent=ReadOnly connection. This allowlist is the third,
 * independent layer: it rejects anything that is not a read before it ever reaches
 * the server, and gives the agent a clear error instead of a SQL permission failure.
 *
 * Only the tools that take user-supplied SQL run it through here: `execute_query` and
 * `fan_out_query` (validateQuery), and the opt-in `execute_write` (validateWriteQuery).
 * The 32 built-in DMV tools build fixed SQL internally and do not use these functions.
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
  // Bare verb: INTO is OPTIONAL in T-SQL, so `INSERT dbo.Foo VALUES (1)` is legal and an
  // INTO-anchored pattern lets a write straight through. Same reasoning as the DDL verb
  // below — anchoring on the token you expect next is how a denylist leaks.
  // Safe against column names: `_` is a word character, so \b does not match inside
  // inserted_at / insert_time.
  [/\bINSERT\b/i,                                 "INSERT"],
  [/\bUPDATE\s+\w/i,                              "UPDATE"],
  [/\bDELETE\s+(FROM|TOP|\w)/i,                   "DELETE"],
  [/\bMERGE\s+(INTO\s+)?\w/i,                     "MERGE"],
  [/\bTRUNCATE\s+TABLE\b/i,                       "TRUNCATE"],
  [/\bSELECT\b[\s\S]*?\bINTO\s+[^@#]/i,           "SELECT ... INTO (permanent table; #temp / @table only)"],
  [/\bBULK\s+INSERT\b/i,                          "BULK INSERT"],
  // ── Schema / object DDL ──────────────────────────────────────────────────────
  // The VERB, not an enumeration of object keywords. The enumerated form that used to live
  // here listed 24 object types and still missed, verifiably:
  //   ALTER AUTHORIZATION ON DATABASE::x TO y   (hands over ownership)
  //   ALTER EVENT SESSION [...] STATE = STOP    (switches the audit OFF)
  //   ALTER RESOURCE GOVERNOR DISABLE / RESET STATISTICS
  // An allowlist of objects is unmaintainable — every SQL Server release adds more, and the
  // one you forget is the one that matters. No read query needs CREATE/ALTER/DROP at all
  // (a table VARIABLE is DECLARE @t TABLE, which is untouched), so block the verb.
  // `\b` will not match inside create_date / modify_date / drop_count: `_` is a word
  // character, so there is no boundary after the keyword. Pinned by tests/adversarial.ts.
  [/\b(CREATE|ALTER|DROP)\b/i,                    "CREATE/ALTER/DROP — not a read"],
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
  // Bare verb: the literal-spid form missed `KILL @s` and `KILL '<uow-guid>'`, both legal.
  // kill_count / killed_at keep a word character after the keyword, so no false match.
  [/\bKILL\b/i,                                   "KILL"],
  [/\bCHECKPOINT\b/i,                             "CHECKPOINT (forces dirty pages to disk)"],
  // RAISERROR at severity >= 20 WITH LOG terminates the connection, and if the MCP login is
  // sysadmin - common for a DBA tool - that is exactly the membership that makes that form available.
  [/\bRAISERROR\b/i,                              "RAISERROR"],
  // A read has no business opening or ending a transaction; one left open on a struggling
  // instance pins the log and the version store. "SET TRANSACTION ISOLATION LEVEL" is NOT
  // matched - this needs BEGIN/COMMIT/ROLLBACK in front of TRAN.
  [/\b(BEGIN|COMMIT|ROLLBACK)\s+TRAN(SACTION)?\b/i, "explicit transaction control"],
  // Service Broker moves data off-box without using any DML verb at all.
  [/\bSEND\s+ON\s+CONVERSATION\b/i,               "Service Broker SEND"],
  [/\bBEGIN\s+DIALOG\b/i,                         "Service Broker BEGIN DIALOG"],
  // Changes what later statements in the batch mean, and is read by row-level security.
  [/\bSET\s+CONTEXT_INFO\b/i,                     "SET CONTEXT_INFO"],
  // Would switch the server's own row cap off for the rest of the batch (connectionManager.applyRowLimit).
  [/\bSET\s+ROWCOUNT\b/i,                         "SET ROWCOUNT (the server sets the row cap)"],
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
  // Procedure execution in ANY form. This is not redundant with the line above, and the
  // gap it closes was a real bypass of the whole read-only guarantee:
  //   • ALLOWED_START permits `DECLARE`, which opens a multi-statement batch;
  //   • T-SQL does not require `;` between statements, so the guard above never matches;
  //   • stripNoise() collapses string literals BEFORE these patterns run, so the payload
  //     inside EXEC('...') is invisible to every pattern here.
  // Net effect, verified by running validateQuery() against it:
  //   DECLARE @x INT EXEC('ALTER AVAILABILITY GROUP [ag] FORCE_FAILOVER_ALLOW_DATA_LOSS')
  // was ACCEPTED as a read-only query. When the login is sysadmin (see dbatools.ts), the
  // tool layer is the only thing standing in front of it —
  // and the per-user identity design (DEPLOYMENT.md §2) stakes the read-only guarantee precisely on this layer holding
  // "regardless of how privileged the login is".
  // There is no legitimate EXEC in a read: execute_query accepts SELECT/WITH/DECLARE, and
  // the built-in tools that legitimately call procedures bypass validateQuery by design.
  [/\bEXEC(UTE)?\b/i,                              "EXEC / EXECUTE — not a read; use the built-in tool for that procedure"],
];

// A carriage return that is not part of CRLF is refused by both guards: stripNoise() ends a `--` comment
// there, and the guards must never depend on reading line ends differently from the server. Clients send
// LF or CRLF.
const BARE_CR = /\r(?!\n)/;
const BARE_CR_REASON = "A carriage return that is not part of a CRLF line ending is not accepted — send LF or CRLF.";

/**
 * Remove string literals, line comments and block comments so that blocked
 * keywords cannot be hidden inside `/* ... *\/`, `-- ...`, or quoted text, and so
 * that a column literal like 'DROP TABLE' in a WHERE clause is not a false match.
 *
 * One left-to-right pass, the way T-SQL's own lexer reads the batch: whichever of `--`, `/*`, `'`,
 * `[` or `"` comes first decides what the characters after it are. It used to be three regexes,
 * strings first, so an apostrophe inside a comment or a delimited identifier (`-- don't`, `[it's]`,
 * `"it's"`) opened a phantom string that ran to the next quote anywhere in the batch, and every
 * pattern skipped the code in between: `SELECT 1 -- don't⏎; DROP TABLE x --'` was ACCEPTED, by the
 * write guard as well as this one. Delimited identifiers are copied through verbatim, so the guards
 * still see `[msg].[MessageLog]`. Anything left unterminated swallows the rest of the batch — which SQL
 * Server then refuses to compile, so nothing hidden that way can run.
 */
// Exported so connectionManager.applyRowLimit judges its row-cap exemption on the same normalised text.
export function stripNoise(query: string): string {
  const n = query.length;
  // Index just past the closing `close` (doubled = escaped), or n when it is never closed.
  const endOf = (from: number, close: string): number => {
    for (let j = from; j < n; j++) {
      if (query[j] !== close) continue;
      if (query[j + 1] === close) { j++; continue; }
      return j + 1;
    }
    return n;
  };
  let out = "";
  let i = 0;
  while (i < n) {
    const c = query[i], next = query[i + 1];
    if (c === "-" && next === "-") {
      // Line comment, to the next CR or LF. Both guards refuse a CR outside CRLF before calling this,
      // so for them it only ever ends at the CR of a CRLF.
      while (i < n && query[i] !== "\n" && query[i] !== "\r") i++;
      out += " ";
    } else if (c === "/" && next === "*") {
      // Block comment. T-SQL nests them, so `/* a /* b */ c */` is one comment.
      let depth = 0;
      while (i < n) {
        if (query[i] === "/" && query[i + 1] === "*") { depth++; i += 2; }
        else if (query[i] === "*" && query[i + 1] === "/") { depth--; i += 2; if (depth === 0) break; }
        else i++;
      }
      out += " ";
    } else if (c === "'") {
      i = endOf(i + 1, "'");                     // string literal ('' escapes a quote): collapse it
      out += "''";
    } else if (c === "[" || c === '"') {
      const j = endOf(i + 1, c === "[" ? "]" : '"');  // delimited identifier: keep it as written
      out += query.slice(i, j);
      i = j;
    } else {
      out += c;
      i++;
    }
  }
  return out;
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
  if (BARE_CR.test(query)) return { valid: false, reason: BARE_CR_REASON };

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
  // Bare verb, for the same reason as the read list: the enumerated form here listed 25 object
  // types and still let through ALTER AUTHORIZATION (hands over ownership), ALTER EVENT SESSION
  // (switches an audit off) and ALTER RESOURCE GOVERNOR. This profile permits DML and EXEC of an
  // application procedure - never DDL - so the verb itself is the right thing to reject.
  // A procedure whose NAME contains the word is unaffected: EXEC dbo.CreateOrder has no word
  // boundary after "Create".
  [/\b(CREATE|ALTER|DROP)\b/i,                    "DDL (CREATE/ALTER/DROP) is not allowed"],
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
  if (BARE_CR.test(query)) return { valid: false, reason: BARE_CR_REASON };

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
