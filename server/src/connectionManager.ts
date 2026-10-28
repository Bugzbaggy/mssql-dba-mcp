import sql from "mssql";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { readOsCredential, type OsCredential } from "./credentialStore.js";
import { isPlaintextPasswordLiteral, PLAINTEXT_PASSWORD_ERROR } from "./credentialPolicy.js";
import { stripNoise } from "./safety.js";
// Live tls module object (import=require, not `import *`, so the reference is the real
// builtin and a checkServerIdentity override propagates to tedious's own require('tls')).
import nodeTls = require("node:tls");

export type ApplicationIntent = "ReadOnly" | "ReadWrite";

// ─────────────────────────────────────────────────────────────────────────────
// Per-user identity. The SQL login/password that a query runs under come from the
// CALLER, never from a shared service account:
//   • stdio transport → the process env (SQL_USER / SQL_PASSWORD), resolved into
//     each InstanceConfig at load time.
//   • HTTP transport  → the caller's own credentials arrive per request as the
//     X-DB-User / X-DB-Password headers and are placed in this AsyncLocalStorage
//     context for the duration of the request. They are never written to disk.
// The request context (when present) always wins, so on the shared HTTP service
// every user connects as — and is audited as — themselves.
// ─────────────────────────────────────────────────────────────────────────────
export interface DbCredentials {
  user: string;
  password: string;
  /**
   * Verified Microsoft Entra identity for this request (present only when the HTTP
   * transport has OAuth enabled — MCP_AUTH_MODE != off). `token` is the user's own
   * access token, reused as the On-Behalf-Of user-assertion to mint a SQL access
   * token (Path A) for instances flagged `entraAuth:true`. `oid`/`upn` audit who ran
   * the query even when the SQL connection itself still uses a SQL login (Path B).
   */
  entra?: { token: string; oid?: string; upn?: string; tid?: string };
}
export const credentialContext = new AsyncLocalStorage<DbCredentials>();

// ─────────────────────────────────────────────────────────────────────────────
// Path A (per-instance, opt-in): On-Behalf-Of exchange of the caller's Entra token
// for a *SQL* access token, so the connection authenticates to SQL Server 2022 as
// the real human (no SQL login/password). Requires Microsoft Entra authentication
// enabled on the instance (Azure Arc + Entra admin) AND ENTRA_SQL_OBO_ENABLED=1 AND
// the instance's fleet entry carrying `entraAuth:true`. Off by default; check a node first
// with the readiness query in AAD-ENTRA-SETUP.md §3.
// ─────────────────────────────────────────────────────────────────────────────
const ENTRA_SQL_OBO_ENABLED = process.env.ENTRA_SQL_OBO_ENABLED === "1";
const SQL_OBO_SCOPE = process.env.ENTRA_SQL_SCOPE ?? "https://database.windows.net/.default";
// Cache OBO-minted SQL tokens per user (keyed by oid) until ~2 min before expiry.
const oboTokenCache: Map<string, { token: string; expiresAt: number }> = new Map();

async function getOboSqlToken(entra: NonNullable<DbCredentials["entra"]>): Promise<string> {
  const cacheKey = entra.oid ?? entra.token.slice(-32);
  const cached = oboTokenCache.get(cacheKey);
  if (cached && cached.expiresAt - 120_000 > Date.now()) return cached.token;

  const tenantId = process.env.ENTRA_TENANT_ID ?? "00000000-0000-0000-0000-000000000000";
  const clientId = process.env.ENTRA_CLIENT_ID ?? "";
  const clientSecret = process.env.ENTRA_CLIENT_SECRET ?? "";
  if (!clientId || !clientSecret) {
    throw new Error("Entra-SQL OBO is enabled but ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET are not set.");
  }
  // Imported lazily so the dependency is only loaded when Path A is actually switched on.
  const { OnBehalfOfCredential } = await import("@azure/identity");
  const cred = new OnBehalfOfCredential({ tenantId, clientId, clientSecret, userAssertionToken: entra.token });
  const tok = await cred.getToken(SQL_OBO_SCOPE);
  if (!tok?.token) throw new Error("OBO exchange returned no SQL access token.");
  oboTokenCache.set(cacheKey, { token: tok.token, expiresAt: tok.expiresOnTimestamp });
  return tok.token;
}

export interface InstanceConfig {
  name: string;
  /** Region grouping, e.g. "sg" | "id" | "uk" | "us". Used by list_instances and fan_out_query. */
  region?: string;
  /** Cloud/infra grouping, e.g. "aws" | "gcp". Lets the agent compare a node against PEERS
   *  on the SAME infrastructure when diagnosing instability/crashes. */
  cloud?: string;
  /**
   * Topology role of this host.
   *   "sql"     (default) — a SQL Server instance: SQL tools target it; user/password/port required.
   *   "witness"           — a WSFC file-share witness (no SQL service). Surfaced by list_instances
   *                          so host-level/cluster tools can address it by name; SQL tools refuse it.
   */
  kind?: "sql" | "witness";
  /** Windows computer name (e.g. "REGION2-WITNESS"). Useful for witnesses where the fleet entry
   *  is reached by IP but Cluster/AD operations need the NetBIOS name. */
  computer_name?: string;
  host: string;
  /** TCP port for SQL connections. Required for kind="sql"; ignored for witnesses. */
  port: number;
  user: string;
  password: string;
  /**
   * Initial catalog. For AG read-only routing to work, this MUST be a database
   * that is in the availability group (e.g. "AppCatalog"), NOT "master" —
   * the listener only routes ApplicationIntent=ReadOnly connections to a
   * readable secondary when the requested database belongs to the AG.
   */
  database?: string;
  /** ReadOnly (default) sets the TDS read-only intent flag + routes to a readable secondary. */
  applicationIntent?: ApplicationIntent;
  encrypt?: boolean;
  trustServerCertificate?: boolean;
  /**
   * Multi-subnet AG listeners (e.g. staging listener.example.com) resolve to one VIP per
   * subnet, but only the VIP in the current primary's subnet has the SQL port open.
   * With this false (default) the driver probes the VIPs serially and stalls on the
   * offline one until connectionTimeout. Set true on a multi-subnet listener so the
   * driver attempts all resolved IPs in parallel and takes the first that answers.
   */
  multiSubnetFailover?: boolean;
  /**
   * Per-instance OS credential-store entry (local/stdio installs only). Names a Generic
   * credential holding BOTH the login and the password for THIS node, for a host that does
   * not share the fleet login (e.g. a managed AWS RDS instance with its own admin). It
   * overrides the process-wide SQL_CRED_TARGET for this instance only. The password still
   * never comes from disk - a literal in the fleet file is refused exactly as before; this
   * just lets a second login live in the OS store alongside the fleet one. Create it with:
   *   Windows : cmdkey /generic:<target> /user:<login> /pass:<password>
   *   macOS   : security add-generic-password -U -s <target> -a <login> -w <password>
   *   Linux   : secret-tool store --label=<target> service <target> account <login>
   */
  credTarget?: string;
  /**
   * Path A opt-in: authenticate to this instance with a Microsoft Entra access token
   * (minted via OBO from the caller's identity) instead of a SQL login/password.
   * Requires Entra auth configured on the SQL Server 2022 instance and
   * ENTRA_SQL_OBO_ENABLED=1. Default false - see the readiness check in AAD-ENTRA-SETUP.md §3.
   */
  entraAuth?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging — in stdio transport mode anything written to stdout corrupts the MCP
// JSON-RPC framing, so all diagnostics go to stderr.
// ─────────────────────────────────────────────────────────────────────────────
function log(message: string): void {
  console.error(message);
}

// Read-only is the default everywhere. An instance must explicitly opt in to
// ReadWrite (which this deployment never does) for the intent flag to be cleared.
const DEFAULT_DATABASE = process.env.DEFAULT_DATABASE ?? "AppCatalog";

/** True on the shared HTTP service, where a credential MUST arrive per request. */
const HTTP_TRANSPORT = (process.env.MCP_TRANSPORT ?? "stdio").toLowerCase() === "http";
export const DEFAULT_INSTANCE = process.env.DEFAULT_INSTANCE ?? "nlb";

// ─────────────────────────────────────────────────────────────────────────────
// Initial-catalog fallback — "the MCP must always be able to connect".
//
// Every fleet entry pins an initial catalog (AppCatalog / AppDb) because
// read-only routing only engages when the initial catalog is an AG database. The
// cost of that is a single point of failure: if THAT database is unavailable, the
// login is refused and the node becomes unreachable — even when the instance is
// perfectly healthy and serving every other database.
//
// That is not hypothetical: when the pinned catalog goes SUSPECT, every MCP connection
// to that node fails to log in, during exactly the incident where reaching the node
// matters most — while the engine is up the whole time. Changing the login's
// DEFAULT_DATABASE does not help — the connection string's initial catalog overrides it.
//
// So: if the configured catalog cannot be opened, retry once against `master`, which
// cannot be SUSPECT on a running instance. Connectivity beats routing in an incident.
// Set SQL_CATALOG_FALLBACK=0 to disable.
// ─────────────────────────────────────────────────────────────────────────────
const CATALOG_FALLBACK_ENABLED = (process.env.SQL_CATALOG_FALLBACK ?? "1") !== "0";
const FALLBACK_DATABASE = process.env.SQL_FALLBACK_DATABASE ?? "master";

// Error numbers meaning "the server is reachable, but the INITIAL CATALOG could not be
// opened". 926 is the SUSPECT case. 18456 is included because SQL reports a failed default-
// database open to clients as a plain login failure — which is why such an incident looks
// like a credentials problem and costs time chasing the wrong thing.
const CATALOG_UNAVAILABLE_ERRORS = new Set([
  905,   // Database not available (contained AG)
  911,   // Database does not exist, or you do not have permission
  926,   // Database cannot be opened. It has been marked SUSPECT by recovery
  927,   // Database is in the middle of a restore
  942,   // Database cannot be opened because it is offline
  945,   // Database cannot be opened due to inaccessible files / insufficient memory
  4060,  // Cannot open database "X" requested by the login
  18456, // Login failed for user (server-side surface of a failed initial-catalog open)
]);

/** Collect every SQL error number reachable from a tedious/mssql error, however nested. */
function sqlErrorNumbers(e: unknown): number[] {
  const out: number[] = [];
  const seen = new Set<unknown>();
  const walk = (x: unknown, depth: number): void => {
    if (!x || typeof x !== "object" || depth > 6 || seen.has(x)) return;
    seen.add(x);
    const o = x as Record<string, unknown>;
    if (typeof o.number === "number") out.push(o.number);
    if (o.info && typeof o.info === "object") walk(o.info, depth + 1);
    if (o.originalError) walk(o.originalError, depth + 1);
    if (Array.isArray(o.errors)) for (const sub of o.errors) walk(sub, depth + 1);
  };
  walk(e, 0);
  return out;
}

function isCatalogUnavailable(e: unknown): boolean {
  if (sqlErrorNumbers(e).some((n) => CATALOG_UNAVAILABLE_ERRORS.has(n))) return true;
  // Driver builds that do not surface a number still carry the text.
  const msg = e instanceof Error ? e.message : String(e);
  return /cannot open database|marked suspect|is offline|not available|login failed for user/i.test(msg);
}

/** What catalog a pool actually ended up on, and why, when it differs from the configured one. */
export type CatalogInfo = {
  configured: string;
  actual: string;
  /** Present only when the fallback fired — the original failure, verbatim. */
  fallbackReason?: string;
};
const poolCatalogInfo = new WeakMap<sql.ConnectionPool, CatalogInfo>();

/**
 * Catalog context for a pool. When `fallbackReason` is set the connection is NOT on the
 * configured database, so unqualified catalog views, SCHEMA_NAME(), OBJECT_NAME() and
 * OBJECT_DEFINITION() resolve in `master` instead — fully qualify, or the answer is wrong
 * rather than empty. Callers that report findings should surface this.
 */
export function getCatalogInfo(pool: sql.ConnectionPool): CatalogInfo | undefined {
  return poolCatalogInfo.get(pool);
}

/** A pool's catalog-fallback warning, or undefined when the connection is on the configured
 *  database. Single source of the wording, because it has to be identical everywhere it appears:
 *  every tool result carries it (see `withCatalogFallback` in tools.ts), so a reader who learns to
 *  recognise it on `execute_query` recognises it on `get_ag_health` too. `kind` exists only because
 *  the read consequence ("routing did not engage, so this may be the PRIMARY") is meaningless on a
 *  write pool, which clears read-only intent and aims at the primary on purpose. */
/**
 * Per-tool-call collection of catalog-fallback warnings.
 *
 * The warning has to reach EVERY tool result, not just `execute_query`. The server instructions
 * sent to every client at initialize say "if a result carries catalog_fallback the connection is
 * on master" — which a reader correctly inverts to "no catalog_fallback means the connection is
 * fine". That inversion is only safe if the field genuinely rides on everything, and there are
 * ~50 query call sites across tools.ts and dbatools.ts that destructure `{ rows }` and would drop
 * it. Rather than edit all of them (and rely on every future one remembering), the two `roTool`
 * registration helpers run each handler inside this scope and attach whatever was collected.
 *
 * AsyncLocalStorage rather than a module-level variable because the HTTP transport serves
 * concurrent tool calls: a plain global would leak one caller's warning onto another's result.
 * Keyed by instance so a fan-out across the fleet reports each node once.
 *
 * The same scope carries row-cap notices (noteRowCap), for the same reason: a result cut at its
 * row cap is just as invisible to a handler that keeps only `{ rows }`.
 */
const catalogFallbackScope = new AsyncLocalStorage<Map<string, string>>();

/** Run a tool handler inside a fresh collection scope. */
export function runInCatalogFallbackScope<T>(fn: () => T): T {
  return catalogFallbackScope.run(new Map<string, string>(), fn);
}

/** Record that a query on `instanceName` ran on a fallback catalog. No-op outside a scope.
 *  Exported for the scope tests — production callers reach it through `catalogFallback`. */
export function noteCatalogFallback(instanceName: string, warning: string): void {
  catalogFallbackScope.getStore()?.set(instanceName, warning);
}

/** Record that a query on `instanceName` was cut at its row cap. No-op outside a scope. One notice
 *  per instance and cap, kept apart from that instance's catalog-fallback warning. */
export function noteRowCap(instanceName: string, maxRows: number): void {
  catalogFallbackScope.getStore()?.set(
    `rowcap|${instanceName}|${maxRows}`,
    `RESULT CUT AT ${maxRows} ROWS on "${instanceName}": a query produced more rows than this tool returns, ` +
      `so counts, totals and "not found" conclusions drawn from these rows are incomplete. Narrow the call ` +
      `(a filter, a database, a smaller window) before relying on what is absent.`,
  );
}

/** Record that a user batch returned more result sets than the first one this tool shows. */
export function noteResultSets(instanceName: string, count: number): void {
  catalogFallbackScope.getStore()?.set(
    `resultsets|${instanceName}`,
    `ONLY THE FIRST OF ${count} RESULT SETS on "${instanceName}" is shown; the rest of the batch's output was ` +
      `discarded. Run each SELECT on its own, or put the one you need first.`,
  );
}

/**
 * Prepend any collected fallback warnings to a tool result, so the caller sees them before the
 * data they qualify. Returns the result untouched when nothing was collected (the normal case)
 * or when it is not a content-shaped object.
 */
export function attachCatalogFallbacks<T>(result: T): T {
  const store = catalogFallbackScope.getStore();
  if (!store?.size) return result;
  const r = result as { content?: Array<{ type: string; text: string }> };
  if (!Array.isArray(r.content)) return result;
  const banner = [...store.values()].map((w) => `*** ${w} ***`).join("\n\n");
  return { ...result, content: [{ type: "text" as const, text: banner }, ...r.content] };
}

export function catalogFallback(
  pool: sql.ConnectionPool,
  instanceName: string,
  kind: "read" | "write" = "read",
): (CatalogInfo & { warning: string }) | undefined {
  const cat = getCatalogInfo(pool);
  if (!cat?.fallbackReason) return undefined;
  const warning =
      `CONNECTED TO "${cat.actual}", NOT "${cat.configured}" — that database could not be opened on ` +
      `"${instanceName}" (${cat.fallbackReason}). ` +
      (kind === "write"
        ? `Consequences: (1) this statement ran with "${cat.actual}" as its session context, so any object ` +
          `name not fully qualified as [Database].[schema].[object] resolved THERE — a dry run can look ` +
          `clean, or a commit land, against the wrong database; (2) "${cat.configured}" being unopenable is ` +
          `itself a finding — a sick database, or a login that cannot open it. Check sys.databases ` +
          `state_desc for "${cat.configured}" on this node before writing anything to it.`
        : `Consequences: (1) unqualified catalog views, SCHEMA_NAME(), OBJECT_NAME() and OBJECT_DEFINITION() ` +
          `resolve in "${cat.actual}", so a cross-database lookup returns a WRONG answer rather than an error — ` +
          `fully qualify as [Database].[schema].[object]; (2) read-only routing did not engage, so this may be ` +
          `the PRIMARY. Check sys.databases state_desc for "${cat.configured}" before treating any result as normal.`);
  // Register it for the enclosing tool call, so it reaches the result even when the caller
  // destructures only `{ rows }` — which ~50 of the ~53 query call sites do.
  noteCatalogFallback(instanceName, warning);
  return { ...cat, warning };
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS posture. The connection is ALWAYS encrypted; what follows controls whether
// the SQL Server's certificate is actually VERIFIED. Modes, in priority order:
//
//   per-instance  fleet.json "trustServerCertificate" — wins for that node.
//   trust-all     SQL_TRUST_SERVER_CERT=1 — explicit global opt-OUT of verification
//                 (encrypt only; a MITM cert is accepted). Escape hatch.
//   CA-verify     verify the server cert chain against a CA bundle: SQL_CA_FILE, or a site
//                 root+intermediate PEM (e.g. for CN=sql.example.internal) placed at
//                 server/ca/AppDb_SQL_CA_bundle.pem. None ships with the repository (*.pem is
//                 git-ignored). Leaf certs issued without SANs are common on private CAs, so
//                 the hostname check is RELAXED by default (chain still enforced — proves the
//                 cert was issued by that CA); set SQL_CA_RELAX_HOSTNAME=0 to force strict.
//   verify-public no CA bundle and trust-all off — verifies against the OS store, which
//                 fails for certificates from a private or self-signed CA.
//
const TRUST_ALL = process.env.SQL_TRUST_SERVER_CERT === "1";

// A site CA bundle (public certs, no private key) is resolved next to dist/ like
// schema-docs. SQL_CA_FILE overrides it. The typeof guard keeps this safe under ESM.
function bundledCaPath(): string {
  const here = typeof __dirname !== "undefined" ? __dirname : process.cwd();
  return join(here, "..", "ca", "AppDb_SQL_CA_bundle.pem");
}
// Resolve which CA file to use: explicit env wins, else the bundled default if present.
// Skipped entirely when trust-all is set (explicit verification opt-out).
function resolveCaFile(): string | undefined {
  if (TRUST_ALL) return undefined;
  const env = process.env.SQL_CA_FILE?.trim();
  if (env) return env;
  const bundled = bundledCaPath();
  return existsSync(bundled) ? bundled : undefined;
}
const ACTIVE_CA_FILE = resolveCaFile();
let CA_BUNDLE_PEM: string | undefined;
if (ACTIVE_CA_FILE) {
  try {
    CA_BUNDLE_PEM = readFileSync(ACTIVE_CA_FILE, "utf8");
  } catch (e) {
    CA_BUNDLE_PEM = undefined;
    log(`[db][tls] CA bundle "${ACTIVE_CA_FILE}" could not be read: ${(e as Error).message}. Falling back to verify-public (set SQL_TRUST_SERVER_CERT=1 to bypass).`);
  }
}
// Hostname check is RELAXED by default whenever a CA bundle is active (private-CA leaf
// certs often have no SANs). Set SQL_CA_RELAX_HOSTNAME=0 to force strict (certs with SANs).
const SQL_CA_RELAX_HOSTNAME = !!CA_BUNDLE_PEM && process.env.SQL_CA_RELAX_HOSTNAME !== "0";

// Resolve the effective trustServerCertificate for an instance (per-instance wins).
function resolveTrustServerCert(cfg: InstanceConfig): boolean {
  if (typeof cfg.trustServerCertificate === "boolean") return cfg.trustServerCertificate;
  if (TRUST_ALL) return true;                // explicit global opt-out of verification
  if (CA_BUNDLE_PEM) return false;           // CA-verify (default)
  return false;                              // verify-public (no bundle, no trust-all)
}
// Install a hostname-check override scoped to the configured fleet hosts. Node validates
// the chain against our CA (rejectUnauthorized=true from trustServerCertificate:false) BEFORE
// calling checkServerIdentity, so the chain-to-CA guarantee is intact; we only skip the
// name match, and ONLY for hosts we connect to (any other TLS — e.g. the Entra JWKS fetch —
// keeps the real identity check via the original function). Idempotent.
let hostnameRelaxInstalled = false;
function installRelaxedHostnameCheck(): void {
  if (hostnameRelaxInstalled || !CA_BUNDLE_PEM || !SQL_CA_RELAX_HOSTNAME) return;
  const fleetHosts = new Set<string>();
  for (const i of instances.values()) {
    if (i.host) fleetHosts.add(i.host.toLowerCase());
  }
  const tlsMod = nodeTls as unknown as {
    checkServerIdentity: (host: string, cert: nodeTls.PeerCertificate) => Error | undefined;
  };
  const orig = tlsMod.checkServerIdentity;
  tlsMod.checkServerIdentity = (host, cert) =>
    fleetHosts.has((host || "").toLowerCase()) ? undefined : orig(host, cert);
  hostnameRelaxInstalled = true;
  log(`[db][tls] hostname check RELAXED for ${fleetHosts.size} fleet hosts (chain still verified against the CA bundle). Drop SQL_CA_RELAX_HOSTNAME once leaf certs carry SANs.`);
}

// One-time, explicit posture log + a loud warning when nothing is configured (the mode
// that breaks this fleet), so the operational requirement (#1) can't be missed.
function logTlsPosture(): void {
  if (TRUST_ALL) {
    log(`[db][tls] trust-all mode (SQL_TRUST_SERVER_CERT=1) — connections are encrypted but the server cert is NOT verified. Explicit opt-out; the default (bundled CA-verify) is stronger.`);
  } else if (CA_BUNDLE_PEM) {
    const src = process.env.SQL_CA_FILE?.trim() ? "SQL_CA_FILE" : "bundled default";
    log(
      `[db][tls] CA-verify mode (DEFAULT) — verifying server cert chains against ${src} (${ACTIVE_CA_FILE}); ` +
      (SQL_CA_RELAX_HOSTNAME
        ? `hostname check RELAXED for fleet hosts (current certs have no SANs; chain to the CA still enforced). Set SQL_CA_RELAX_HOSTNAME=0 for strict once certs carry SANs.`
        : `STRICT hostname (SQL_CA_RELAX_HOSTNAME=0) — requires leaf certs with matching SANs.`)
    );
  } else {
    log(`[db][tls] WARNING: no CA bundle found and trust-all is off — verifying against the public trust store, which FAILS for certificates from a private or self-signed CA. Place your CA bundle at server/ca/AppDb_SQL_CA_bundle.pem, set SQL_CA_FILE, or set SQL_TRUST_SERVER_CERT=1 to bypass.`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Load instance list from INSTANCES env var (JSON array) or fall back to the
// single-instance env vars for backwards compatibility.
//
// Multi-instance format (INSTANCES env var):
//   [
//     { "name":"nlb", "host":"listener.region1.example.com", "port":1433,
//       "user":"<ro_login>", "password":"<from SQL_PASSWORD>", "database":"AppCatalog",
//       "applicationIntent":"ReadOnly" }
//   ]
// The password may be the literal "${SQL_PASSWORD}" / "$SQL_PASSWORD" or empty,
// in which case it is filled from the SQL_PASSWORD env var so the secret never
// has to live inside the INSTANCES JSON.
//
// Single-instance fallback (env vars):
//   SQL_SERVER, SQL_PORT, SQL_USER, SQL_PASSWORD, SQL_DATABASE
// ─────────────────────────────────────────────────────────────────────────────
// Local/stdio credential source. The PASSWORD never comes from disk (enforced):
//   • password → OS credential store or the SQL_PASSWORD env var ONLY, in this order: the
//     instance's own "credTarget" entry (for a node that does not share the fleet login),
//     else SQL_CRED_TARGET, else SQL_PASSWORD. A literal password in the fleet file is
//     REFUSED at startup (see resolvePassword), so the secret can never sit in
//     ~/.claude.json / INSTANCES(_FILE) as plaintext.
//   • user (not a secret) → a literal in the fleet file is allowed, else the instance's
//     "credTarget" entry, else SQL_CRED_TARGET, else SQL_USER.
// SQL_CRED_TARGET is the preferred local path — the password lives in Windows Credential
// Manager / macOS Keychain / libsecret, never on disk. Read once at load.
// (The HTTP transport ignores all of this; those creds arrive per request in the headers.)
const SQL_CRED_TARGET = process.env.SQL_CRED_TARGET?.trim();

// Read on FIRST USE, not at module load, and memoized (including the miss).
//
// readOsCredential shells out to powershell.exe SYNCHRONOUSLY. Measured on a slow workstation:
// a single powershell.exe start costs 10-13 s (pwsh ~6 s, a cmdkey probe 20 s) — process startup
// on such a box can be pathologically slow. With two reads (SQL_CRED_TARGET plus one
// instance credTarget), ~20-26 s of blocking ran at module scope, i.e. BEFORE
// server.connect() and therefore before the MCP initialize handshake could be answered. Against
// a 30 s client connect timeout that is a coin flip, and it is what produced
// "MCP server appdb-sql connection timed out after 30000ms" with an empty stderr — the server
// had not reached its own "ready" log line yet. Deferring keeps startup instant and moves the
// cost to the first query that actually needs a credential.
let osCredCache: OsCredential | undefined;
let osCredRead = false;
function getOsCred(): OsCredential | undefined {
  if (osCredRead) return osCredCache;
  if (!SQL_CRED_TARGET) { osCredRead = true; return undefined; }
  osCredCache = readOsCredential(SQL_CRED_TARGET);
  // Memoise only a SUCCESS. A failed read is usually a slow box missing the
  // subprocess timeout, not a missing entry — caching that would poison every later connection
  // for the life of the process, turning a transient stall into "credentials not configured"
  // until someone restarts the server. Retrying costs one subprocess on the next attempt.
  if (osCredCache) osCredRead = true;
  if (osCredCache)
    log(`[db][cred] Using OS credential store "${SQL_CRED_TARGET}" for SQL login "${osCredCache.user}" (password not logged).`);
  else
    log(`[db][cred] SQL_CRED_TARGET="${SQL_CRED_TARGET}" is set but no matching entry was found in the OS credential store — falling back to SQL_USER/SQL_PASSWORD env.`);
  return osCredCache;
}
// Env-var password is allowed, but a config file / env block is a weaker place for a secret than
// the OS store — nudge local installs toward SQL_CRED_TARGET without blocking it.
if (!SQL_CRED_TARGET && process.env.SQL_PASSWORD) {
  log(`[db][cred] Using SQL_PASSWORD from the environment. Prefer SQL_CRED_TARGET so the password lives in the OS credential store, not a config file.`);
}

// Secrets and the login name are filled so the same fleet topology file can be shared by
// both profiles (the DBA-monitor login and the ops login) — each install just sets its own
// SQL_CRED_TARGET (preferred) or SQL_USER / SQL_PASSWORD.
function resolveFromEnv(raw: string | undefined, token: string, envName: string, osValue?: string): string {
  if (!raw || raw === `\${${token}}` || raw === `$${token}`) {
    return osValue ?? process.env[envName] ?? "";
  }
  return raw; // explicit literal in the fleet file wins (per-instance override)
}
const resolveUser = (raw: string | undefined, cred?: OsCredential) =>
  resolveFromEnv(raw, "SQL_USER", "SQL_USER", cred?.user);
// The password may NOT be a literal on disk. A non-placeholder value in the fleet file is refused
// outright, so a secret can never be committed/stored in INSTANCES / INSTANCES_FILE / ~/.claude.json;
// it must come from the OS credential store (the instance's own credTarget, or SQL_CRED_TARGET)
// or the SQL_PASSWORD env var.
function resolvePassword(raw: string | undefined, cred?: OsCredential): string {
  if (isPlaintextPasswordLiteral(raw)) throw new Error(PLAINTEXT_PASSWORD_ERROR);
  return cred?.password ?? process.env.SQL_PASSWORD ?? "";
}

// Per-instance credential targets (fleet.json "credTarget"), for a node that does NOT share the
// fleet login - e.g. a managed AWS RDS instance with its own admin. Without this, such a host could
// only be reached by putting a literal password in the fleet file, which resolvePassword refuses.
// Each distinct target is read from the OS store once and memoized; a missing entry logs and falls
// back to the process-wide SQL_CRED_TARGET / SQL_USER / SQL_PASSWORD chain, so a typo in a
// credTarget degrades to the fleet login instead of hard-failing startup for every instance.
const instanceCredCache: Map<string, OsCredential | undefined> = new Map();
function credentialFor(inst: InstanceConfig): OsCredential | undefined {
  const target = inst.credTarget?.trim();
  if (!target) return getOsCred();
  if (!instanceCredCache.has(target)) {
    const cred = readOsCredential(target);
    if (cred) {
      log(`[db][cred] Instance "${inst.name}": using OS credential store "${target}" for SQL login "${cred.user}" (password not logged).`);
      // Only a SUCCESS is cached — see getOsCred() for why a failed read must stay retryable.
      instanceCredCache.set(target, cred);
    } else {
      log(`[db][cred] Instance "${inst.name}": credTarget="${target}" did not resolve - falling back to the fleet credentials. (readOsCredential logs whether it was ABSENT or UNREADABLE; those are different problems.)`);
    }
  }
  return instanceCredCache.get(target) ?? getOsCred();
}

function normalize(parsed: InstanceConfig[]): InstanceConfig[] {
  return parsed.map((inst) => {
    // The plaintext-password REFUSAL stays EAGER. It is a security check — a secret sitting in
    // the fleet file must be rejected when the server starts, not on the first query that
    // happens to touch that node. It needs no credential-store read, so it costs nothing here.
    if (isPlaintextPasswordLiteral(inst.password)) throw new Error(PLAINTEXT_PASSWORD_ERROR);

    const cfg = { ...inst, applicationIntent: inst.applicationIntent ?? "ReadOnly" } as InstanceConfig;

    // user/password resolve on FIRST ACCESS, not here. credentialFor()/getOsCred() memoize, so
    // the OS store is read at most once per target for the life of the process. See getOsCred()
    // for why this matters: the read shells out to powershell.exe synchronously and cost ~20-26 s
    // at module scope on a slow workstation, which is before server.connect() and therefore before the
    // MCP initialize handshake — the 30 s client timeout was losing that race.
    Object.defineProperty(cfg, "user", {
      enumerable: true, configurable: true,
      get: () => resolveUser(inst.user, credentialFor(inst)),
    });
    // NON-enumerable, deliberately: the secret can then never be picked up by a spread or a
    // JSON.stringify of a config object. The only reader is getPool, which accesses
    // cfg.password explicitly.
    Object.defineProperty(cfg, "password", {
      enumerable: false, configurable: true,
      get: () => resolvePassword(inst.password, credentialFor(inst)),
    });
    return cfg;
  });
}

function loadInstances(): InstanceConfig[] {
  // 1. INSTANCES_FILE — a JSON file holding the fleet topology (no secrets;
  //    user/password resolve from SQL_USER/SQL_PASSWORD). Preferred at fleet scale.
  const file = process.env.INSTANCES_FILE;
  if (file) {
    let parsed: InstanceConfig[];
    try {
      parsed = JSON.parse(readFileSync(file, "utf8")) as InstanceConfig[];
    } catch (e) {
      throw new Error(`INSTANCES_FILE (${file}) could not be read/parsed: ${e}`);
    }
    return normalize(parsed);
  }

  // 2. INSTANCES — inline JSON array (same shape).
  const raw = process.env.INSTANCES;
  if (raw) {
    let parsed: InstanceConfig[];
    try {
      parsed = JSON.parse(raw) as InstanceConfig[];
    } catch (e) {
      throw new Error(`INSTANCES env var is not valid JSON: ${e}`);
    }
    return normalize(parsed);
  }

  // 3. Backwards-compatible single instance — read-only by default.
  return [
    {
      name:              DEFAULT_INSTANCE,
      host:              process.env.SQL_SERVER ?? "listener.region1.example.com",
      port:              parseInt(process.env.SQL_PORT ?? "1433", 10),
      // Lazy, for the same startup reason as the fleet path above — see getOsCred().
      get user()     { return getOsCred()?.user     ?? process.env.SQL_USER     ?? ""; },
      get password() { return getOsCred()?.password ?? process.env.SQL_PASSWORD ?? ""; },
      database:          process.env.SQL_DATABASE ?? DEFAULT_DATABASE,
      applicationIntent: "ReadOnly",
    },
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection pool map — pools are created lazily on first use
// ─────────────────────────────────────────────────────────────────────────────
const instances: Map<string, InstanceConfig> = new Map();
const pools: Map<string, sql.ConnectionPool> = new Map();

// ─────────────────────────────────────────────────────────────────────────────
// AG-primary alias resolution
//
// Callers can pass a synthetic instance name "<region>-primary" (e.g. "region2-primary")
// to ANY tool and it gets routed to the current PRIMARY node of that region's
// local (non-distributed) AG at query time. Failovers move the primary; pinning a
// node by name across a conversation is a footgun. This solves that.
//
// Mechanism:
//   serverNameCache  – instance_name → @@SERVERNAME, learned lazily on first use
//   primaryCache     – region → resolved instance_name, with a short TTL so a
//                      failover during a session refreshes within a minute
// ─────────────────────────────────────────────────────────────────────────────
const PRIMARY_ALIAS_SUFFIX = "-primary";
const PRIMARY_CACHE_TTL_MS = parseInt(process.env.PRIMARY_CACHE_TTL_MS ?? "60000", 10);
const serverNameCache: Map<string, string> = new Map();
const primaryCache: Map<string, { instanceName: string; expiresAt: number }> = new Map();

export function invalidatePrimaryCache(region?: string): void {
  if (region) primaryCache.delete(region);
  else primaryCache.clear();
}

export function initInstances(): void {
  for (const inst of loadInstances()) {
    instances.set(inst.name, inst);
  }
  const byRegion = [...instances.values()].reduce<Record<string, string[]>>((acc, i) => {
    (acc[i.region ?? "-"] ??= []).push(i.name);
    return acc;
  }, {});
  log(`[db] Registered ${instances.size} instances by region: ${JSON.stringify(byRegion)}`);
  log(`[db] Default instance: ${DEFAULT_INSTANCE} (read-only)`);
  installRelaxedHostnameCheck();   // needs the instance hosts; must run before any connection
  logTlsPosture();
}

export function listInstances(): InstanceConfig[] {
  return [...instances.values()];
}

// getPool(name) returns the read-only pool (ApplicationIntent=ReadOnly). getPool(name, {write:true})
// returns a SEPARATE ReadWrite pool (no read-only intent → the listener routes it to the PRIMARY)
// used solely by the opt-in engineering write tool. The two are keyed independently.
export async function getPool(instanceName = DEFAULT_INSTANCE, opts?: { write?: boolean }): Promise<sql.ConnectionPool> {
  const write = opts?.write ?? false;

  // Resolve "<region>-primary" aliases to the live AG primary instance name.
  // The resolved node is what the pool is actually keyed on, so a failover during
  // the session causes the next call (after cache TTL) to switch to the new primary.
  if (instanceName.endsWith(PRIMARY_ALIAS_SUFFIX)) {
    const region = instanceName.slice(0, -PRIMARY_ALIAS_SUFFIX.length);
    instanceName = await resolveRegionPrimary(region);
  }

  const cfg = instances.get(instanceName);
  if (!cfg) {
    throw new Error(
      `Unknown instance "${instanceName}". Available: ${[...instances.keys()].join(", ")}`
    );
  }
  if (cfg.kind === "witness") {
    throw new Error(
      `Instance "${instanceName}" is a WSFC file-share witness, not a SQL Server — no SQL endpoint to connect to. ` +
      `Use host-level tools (e.g. read_cluster_reports for cluster nodes) or pick a sibling SQL node in region "${cfg.region}".`
    );
  }

  // Per-user identity: the caller's own login wins. In HTTP mode it comes from the
  // X-DB-User / X-DB-Password request headers (credentialContext); in stdio mode it
  // was resolved from the process env into cfg.user/cfg.password at load.
  const ctx = credentialContext.getStore();

  // Read pools use ApplicationIntent=ReadOnly (route to a readable secondary). A write
  // pool must NOT set read-only intent — otherwise a readable secondary physically rejects
  // writes — so it clears it and the listener sends it to the primary.
  const readOnly = write ? false : cfg.applicationIntent !== "ReadWrite";

  // Path A: authenticate to SQL with an Entra access token (OBO) as the real human.
  const useEntra = ENTRA_SQL_OBO_ENABLED && cfg.entraAuth === true && !!ctx?.entra?.token;

  // Identity label used to key the pool AND audit the connection. Two callers never
  // share a pool — each pooled connection is authenticated as, and audited to, one
  // principal (a SQL login, or an Entra user under Path A).
  const identity = useEntra ? `entra:${ctx!.entra!.oid ?? ctx!.entra!.upn ?? "?"}` : (ctx?.user || cfg.user);

  let user = "";
  let password = "";
  if (!useEntra) {
    // On the shared HTTP service the per-request credential is the ONLY acceptable source.
    // Falling back to the process credential here would hand the server's own standing login
    // to any caller who simply omits the headers — and Entra auth is off by default, so there
    // is no other gate in front of /mcp. That is benign only while the process credential is
    // some individual's; it stops being benign the moment a fleet-wide service principal is
    // configured on a host that also serves HTTP. Fail closed instead: per-user identity
    // (DEPLOYMENT.md §2) is not a default here, it is the contract.
    if (HTTP_TRANSPORT && !(ctx?.user && ctx?.password)) {
      throw new Error(
        "No X-DB-User / X-DB-Password on this request. The HTTP transport never falls back to " +
        "the server's own credential — every query runs as the caller's own SQL login (per-user identity, DEPLOYMENT.md §2)."
      );
    }
    user = ctx?.user || cfg.user;
    password = ctx?.password || cfg.password;
    if (!user || !password) {
      throw new Error(
        "DB credentials not configured. HTTP transport: send X-DB-User and X-DB-Password " +
        "headers with your own SQL login. stdio transport: set SQL_USER and SQL_PASSWORD."
      );
    }
  }

  // Pools are keyed by (identity, instance, intent) so two principals never share a pool.
  const key = `${identity}::${write ? `${instanceName}#rw` : instanceName}`;
  const existing = pools.get(key);
  if (existing?.connected) return existing;

  // Common driver options for both auth modes.
  const baseConfig = {
    server:   cfg.host,
    port:     cfg.port,
    // Initial catalog must be an AG database for read-only routing to engage.
    database: cfg.database ?? DEFAULT_DATABASE,
    options: {
      encrypt:                cfg.encrypt ?? true,
      // TLS posture (see TRUST_SERVER_CERT_DEFAULT / SQL_CA_FILE above): per-instance wins,
      // else CA-verify when a bundle is loaded, else the trust-all/verify-public default.
      trustServerCertificate: resolveTrustServerCert(cfg),
      // When a CA bundle is configured, hand it to the TLS layer so the chain can be
      // verified (cryptoCredentialsDetails -> tls.createSecureContext.ca). Harmless/ignored
      // in trust-all mode. Not in @types/mssql, so the poolConfig is cast below.
      ...(CA_BUNDLE_PEM ? { cryptoCredentialsDetails: { ca: CA_BUNDLE_PEM } } : {}),
      // TDS read-only intent: tells the AG listener this connection wants a
      // readable secondary. This is layer 2 of read-only enforcement (the login
      // privilege and the query allowlist are the other two).
      readOnlyIntent:         readOnly,
      // Parallel-probe all VIPs of a multi-subnet AG listener (off by default).
      multiSubnetFailover:    cfg.multiSubnetFailover ?? false,
      appName:                write ? "appdb-sql-mcp (engineering write)" : "appdb-sql-mcp (read-only monitoring)",
    },
    connectionTimeout: parseInt(process.env.SQL_CONNECT_TIMEOUT_MS ?? "15000", 10),
    requestTimeout:    parseInt(process.env.SQL_REQUEST_TIMEOUT_MS ?? "60000", 10),
    pool: { max: 5, min: 0, idleTimeoutMillis: 30_000 },
  };

  // SQL auth (Path B / stdio) carries user+password; Entra auth (Path A) carries an
  // OBO-minted access token instead. @types/mssql types `authentication` only as the
  // generic union, so the access-token shape needs a cast — runtime support is in tedious.
  const poolConfig: sql.config = useEntra
    ? ({
        ...baseConfig,
        authentication: {
          type: "azure-active-directory-access-token",
          options: { token: await getOboSqlToken(ctx!.entra!) },
        },
      } as sql.config)
    : ({ ...baseConfig, user, password } as sql.config);

  const configuredDb = cfg.database ?? DEFAULT_DATABASE;
  let pool: sql.ConnectionPool;
  let catalog: CatalogInfo = { configured: configuredDb, actual: configuredDb };

  try {
    pool = await new sql.ConnectionPool(poolConfig).connect();
  } catch (e: unknown) {
    const first = e instanceof Error ? e.message : String(e);
    const sameDb = configuredDb.toLowerCase() === FALLBACK_DATABASE.toLowerCase();
    if (!CATALOG_FALLBACK_ENABLED || sameDb || !isCatalogUnavailable(e)) throw e;

    log(
      `[db] "${instanceName}": initial catalog "${configuredDb}" could not be opened ` +
      `(${first}). Retrying against "${FALLBACK_DATABASE}" — the instance may be healthy ` +
      `with only that one database sick.`
    );
    try {
      pool = await new sql.ConnectionPool({ ...poolConfig, database: FALLBACK_DATABASE } as sql.config).connect();
    } catch (e2: unknown) {
      const second = e2 instanceof Error ? e2.message : String(e2);
      // Both attempts failed — report BOTH, so the real cause isn't hidden behind the retry.
      throw new Error(
        `Could not connect to "${instanceName}" (${cfg.host}:${cfg.port}) as ${identity}. ` +
        `Initial catalog "${configuredDb}": ${first} || Fallback catalog "${FALLBACK_DATABASE}": ${second}`
      );
    }
    catalog = { configured: configuredDb, actual: FALLBACK_DATABASE, fallbackReason: first };
  }

  // Attached before any I/O below. mssql's tedious pool emits "error" from inside a tedious
  // callback, and an EventEmitter with no "error" listener THROWS from there — which would take
  // the shared HTTP server down. The identity guard matters because a pool can now outlive its
  // map entry (the fallback retirement below drops it without closing it), and a late error from
  // a retired pool must not evict the healthy pool that has since taken its place.
  const thisPool = pool;
  pool.on("error", (err: Error) => {
    log(`[db] Pool error on "${key}": ${err.message}`);
    if (pools.get(key) === thisPool) pools.delete(key);
  });

  if (catalog.fallbackReason) {
    // The claim "only that one database is sick" has to be EARNED, not assumed. The client-side
    // error cannot tell an unavailable database from a misconfigured one — SQL hands the client
    // the same opaque 4060/18456 whether the catalog is SUSPECT, misspelled in the fleet entry, or
    // simply not openable by this login (the real state stays in the ERRORLOG, which is exactly
    // why a SUSPECT catalog reads as a credentials problem). So the error numbers above are
    // only a cheap pre-filter for "is a retry worth attempting"; now that we ARE connected, ask
    // the server — and then SAY what was found instead of asserting it.
    //
    // Two limits bound what that answer may DECIDE:
    //  • It describes the node THIS connection landed on, which is usually NOT the one that
    //    failed: the first attempt carries readOnlyIntent + an AG catalog and is routed to a
    //    readable secondary, while this one carries `master`, so routing cannot engage and it
    //    lands on the primary. SUSPECT is per-replica — a database can be sick on one replica while
    //    its partner is fine — so "ONLINE" here may only mean we asked the healthy node. That is not
    //    grounds to refuse a connection this fallback exists to keep alive.
    //  • "No such database" IS replica-independent: a typo in the fleet entry reads as missing on
    //    either replica. That one we refuse — but only once we know we could actually SEE the
    //    catalog, because a login without VIEW ANY DATABASE reports every user database as absent.
    //    Absent and could-not-look are different answers (same rule as get_memory_dumps).
    const first = catalog.fallbackReason;
    const probe = await pool.request()
      .input("db", sql.NVarChar(128), configuredDb)
      .query<{ state_desc: string | null; visible: number }>(
        // READ UNCOMMITTED for the same reason every other request uses it: never block, least of
        // all on an instance that is already in trouble.
        "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;\n" +
        "SELECT (SELECT TOP 1 d.state_desc FROM sys.databases d WHERE d.name = @db) AS state_desc, " +
        "(SELECT COUNT(*) FROM sys.databases) AS visible"
      )
      .catch(() => undefined);   // could not ask → keep the connection; connectivity beats routing
    const row = probe?.recordset[0];
    const state = row ? (row.state_desc ?? null) : undefined;   // null = no row for that name
    const canSeeCatalog = (row?.visible ?? 0) > 4;              // more than the 4 system databases

    if (state === null && canSeeCatalog) {
      await pool.close().catch(() => { /* never registered in `pools`; nothing else to unwind */ });
      throw new Error(
        `Could not connect to "${instanceName}" (${cfg.host}:${cfg.port}) as ${identity} with initial ` +
        `catalog "${configuredDb}": ${first}. sys.databases on the node reached has no row for ` +
        `"${configuredDb}" (and this login can see the catalog), so this is NOT the one-sick-database ` +
        `case — fix "database" in the fleet entry for "${instanceName}". Not falling back to ` +
        `"${FALLBACK_DATABASE}": that would hide a configuration error behind a connection whose ` +
        `unqualified names silently resolve somewhere else.`
      );
    }

    // Everything else KEEPS the connection — connectivity beats routing in an incident. What
    // changes is that the reason now reports a measurement instead of a guess, and it rides into
    // the catalog_fallback warning on every result.
    catalog = {
      ...catalog,
      fallbackReason:
        state === undefined
          ? `${first} [UNCONFIRMED: state_desc for "${configuredDb}" could not be read on the node ` +
            `reached, so whether the database is sick or merely unopenable by this login is unknown.]`
          : state === null
            ? `${first} [UNCONFIRMED: no row for "${configuredDb}" in sys.databases, but this login ` +
              `sees only the system databases — absence is NOT established. Check the fleet entry's ` +
              `"database" and whether ${identity} has VIEW ANY DATABASE.]`
            : state === "ONLINE"
              ? `${first} [CONFIRMED: "${configuredDb}" is ONLINE on the node reached, so it is NOT ` +
                `sick there — either this retry landed on a different replica than the one that ` +
                `failed, or ${identity} cannot open it (orphaned user/SID after a failover, missing ` +
                `mapping, or SINGLE_USER/RESTRICTED_USER access). Confirm per-node before calling ` +
                `this a one-sick-database incident.]`
              : `${first} [CONFIRMED: "${configuredDb}" is ${state} on the node reached — the ` +
                `instance is up and one database is not.]`,
    };
  }

  poolCatalogInfo.set(pool, catalog);
  pools.set(key, pool);

  // The pool key carries identity + instance + intent but NOT the catalog, so a pool that fell
  // back is cached under the same key as a healthy one. `pool.connected` never self-clears (tarn
  // reaps the underlying connections but does not mark the pool disconnected), and nothing else
  // evicts, so without this the fallback pool would be handed to every later caller for the life
  // of the process — still pinned to "master" long after the configured database recovered, with
  // every unqualified name resolving in the wrong one and read-only routing never re-engaging.
  // Retire it after a short window so the next caller re-dials and picks the recovery up; reusing
  // it until then is what keeps a long outage from paying a failed connect on every query. It is
  // dropped from the map rather than closed, exactly as the pool-error handler above does: an
  // in-flight request must not be killed, and it holds its own reference, so getCatalogInfo still
  // returns the fallback warning for that request.
  if (catalog.fallbackReason) {
    // Clamped, because setTimeout turns NaN, <= 0 and > 2^31-1 all into ~1ms. An unclamped bad
    // value ("60s", 0, or a seconds/ms mix-up) would retire the pool before the next call, so
    // EVERY query during the outage would pay a full SQL_CONNECT_TIMEOUT_MS failed connect plus a
    // fallback connect — and getPool has no in-flight dedup, so concurrent callers each pay it:
    // a self-inflicted connect storm against the already-sick instance, from one bad env value.
    const parsedTtl = parseInt(process.env.SQL_CATALOG_FALLBACK_TTL_MS ?? "", 10);
    const fallbackTtlMs = Number.isFinite(parsedTtl)
      ? Math.min(Math.max(parsedTtl, 1_000), 2_147_483_647)
      : 60_000;
    setTimeout(() => {
      if (pools.get(key) !== thisPool) return;
      pools.delete(key);
      log(
        `[db] "${instanceName}": retiring the "${FALLBACK_DATABASE}" fallback pool after ` +
        `${fallbackTtlMs}ms — the next call re-dials "${configuredDb}" to see if it recovered.`
      );
    }, fallbackTtlMs).unref();
  }
  log(
    `[db] Connected to instance "${instanceName}" (${cfg.host}:${cfg.port}, ` +
    `db=${catalog.actual}, intent=${readOnly ? "ReadOnly" : "ReadWrite"}, ` +
    `auth=${useEntra ? "entra" : "sql"}, as=${identity})` +
    (catalog.fallbackReason
      ? ` [CATALOG FALLBACK: "${catalog.configured}" is unavailable on this node. ` +
        `Query context is "${catalog.actual}", so unqualified catalog views resolve THERE — ` +
        `fully qualify cross-database reads. Read-only routing did not engage.]`
      : "")
  );
  return pool;
}

// ─────────────────────────────────────────────────────────────────────────────
// Send an HTML email via the target instance's Database Mail (msdb.sp_send_dbmail).
// Used by the headless weekly health-report job to deliver the report to the Slack
// channel, reusing the fleet's existing Database Mail (the mail relay) + Slack operator — no
// SMTP credentials live in the MCP. Uses a ReadWrite (primary) connection because
// sp_send_dbmail writes to msdb and is rejected on a readable secondary; the connecting
// login needs msdb DatabaseMailUserRole (or sysadmin). Parameterised — no injection.
// ─────────────────────────────────────────────────────────────────────────────
export async function sendDbMail(
  instanceName: string,
  m: { profileName: string; recipients: string; subject: string; htmlBody: string; importance?: string },
): Promise<void> {
  const pool = await getPool(instanceName, { write: true });
  await pool.request()
    .input("profile",    sql.NVarChar(128),      m.profileName)
    .input("recipients", sql.NVarChar(sql.MAX),  m.recipients)
    .input("subject",    sql.NVarChar(255),      m.subject)
    .input("body",       sql.NVarChar(sql.MAX),  m.htmlBody)
    .input("importance", sql.VarChar(6),         m.importance ?? "Normal")
    .query("EXEC msdb.dbo.sp_send_dbmail @profile_name=@profile, @recipients=@recipients, @subject=@subject, @body=@body, @body_format='HTML', @importance=@importance");
}

// ─────────────────────────────────────────────────────────────────────────────
// Learn @@SERVERNAME for an instance and cache it. Required so we can map an AG
// replica's reported server name (e.g. "REGION3-NODE2") back to a fleet
// instance_name (e.g. "region3-node2") without depending on the host being a DNS-resolvable
// hostname (many fleet entries use IP).
// ─────────────────────────────────────────────────────────────────────────────
async function getServerName(instanceName: string): Promise<string> {
  const cached = serverNameCache.get(instanceName);
  if (cached) return cached;
  const pool = await getPool(instanceName);
  const r = await pool.request().query<{ server_name: string }>(
    "SELECT CAST(SERVERPROPERTY('ServerName') AS sysname) AS server_name"
  );
  const name = (r.recordset[0]?.server_name ?? "").toString();
  if (name) serverNameCache.set(instanceName, name);
  return name;
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve "<region>-primary" → the current primary's instance_name.
//
// Picks a candidate node in the region, asks SQL for the live AG primary's
// server name (sys.dm_hadr_availability_replica_states with role = 1, excluding
// distributed AGs), then matches that server name against the fleet via the
// @@SERVERNAME cache. Result is cached for PRIMARY_CACHE_TTL_MS so a failover
// during a session refreshes within a minute. Callers should `invalidatePrimaryCache(region)`
// on connection errors that might indicate the cached primary just failed over.
//
// Used by `getPool` so the "<region>-primary" alias is transparent to every tool,
// and by the `get_current_primary` MCP tool for explicit lookups.
// ─────────────────────────────────────────────────────────────────────────────
export async function resolveRegionPrimary(region: string): Promise<string> {
  const cached = primaryCache.get(region);
  if (cached && cached.expiresAt > Date.now()) return cached.instanceName;

  // Candidates: real nodes in the region. Skip NLB listeners (they route through the
  // AG and can land on a secondary under ApplicationIntent=ReadOnly) and skip any
  // synthetic "<region>-primary" alias entry that might be present in the fleet file.
  const candidates = [...instances.values()].filter(
    (i) => i.region === region
      && i.kind !== "witness"
      && !i.name.endsWith("-nlb")
      && !i.name.endsWith(PRIMARY_ALIAS_SUFFIX)
  );
  if (candidates.length === 0) {
    throw new Error(`No nodes configured for region "${region}". Check fleet config.`);
  }

  // Try each candidate until one responds, then query AG state.
  let lastErr: unknown;
  for (const cand of candidates) {
    try {
      const pool = await getPool(cand.name);
      const r = await pool.request().query<{ primary_server_name: string }>(`
        SELECT TOP 1 ar.replica_server_name AS primary_server_name
        FROM sys.availability_groups ag
        JOIN sys.availability_replicas ar
          ON ag.group_id = ar.group_id
        JOIN sys.dm_hadr_availability_replica_states ars
          ON ar.replica_id = ars.replica_id
        WHERE ars.role = 1            -- 1 = PRIMARY
          AND ag.is_distributed = 0   -- ignore cross-region distributed AGs
        ORDER BY ag.name
      `);
      const primary = r.recordset[0]?.primary_server_name?.toString();
      if (!primary) {
        throw new Error(`No PRIMARY replica found via "${cand.name}" — region "${region}" may not have an AG configured here.`);
      }

      // Map the AG-reported server name back to an instance_name by comparing @@SERVERNAME.
      for (const c of candidates) {
        const sn = await getServerName(c.name).catch(() => "");
        if (sn && sn.toLowerCase() === primary.toLowerCase()) {
          primaryCache.set(region, { instanceName: c.name, expiresAt: Date.now() + PRIMARY_CACHE_TTL_MS });
          log(`[ag] Region "${region}" primary resolved to "${c.name}" (server name "${sn}")`);
          return c.name;
        }
      }
      throw new Error(
        `AG reports primary "${primary}" for region "${region}" but no matching instance is in the fleet config. Known: ${candidates.map((c) => c.name).join(", ")}.`
      );
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(
    `Could not resolve primary for region "${region}": ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// queryInstance — routes to the named instance's pool.
//
// Every request runs under READ UNCOMMITTED so monitoring queries take no shared
// locks. On a readable secondary snapshot isolation is forced regardless; this
// matters only when a query lands on the primary (e.g. the per-node instances),
// where it keeps the monitoring tool from ever blocking the production workload.
//
// The cap asks the server for ONE row more than the caller keeps: getting maxRows + 1
// back is the only proof that rows were cut. It used to cap at exactly maxRows, so
// `rows.length > maxRows` could never be true and every query without its own
// `TOP (…)` lost the rows past the cap with no truncation note (measured on a test instance:
// a 2,630-row execute_query returned 500 rows and said nothing).
// ─────────────────────────────────────────────────────────────────────────────
export function applyRowLimit(sqlText: string, maxRows: number, opts: { userSql?: boolean } = {}): string {
  // A built-in batch that bounds itself with TOP (…) or its own SET ROWCOUNT is left unwrapped, judged on
  // its text without comments or string literals: a `TOP (` in either used to switch the cap off for the
  // whole batch. User SQL is always capped — it never needs the exemption (the read guard refuses INSERT
  // and SET ROWCOUNT), and a `TOP (` in a subquery would otherwise leave its outer SELECT unbounded.
  const code = stripNoise(sqlText);
  if (!opts.userSql && (/\bTOP\s*\(/i.test(code) || /\bSET\s+ROWCOUNT\b/i.test(code))) {
    return sqlText;
  }
  return `SET ROWCOUNT ${maxRows + 1};\n${sqlText}\nSET ROWCOUNT 0;`;
}

export function capRows<T>(rows: T[], maxRows: number): { rows: T[]; truncated: boolean } {
  const truncated = rows.length > maxRows;
  return { rows: truncated ? rows.slice(0, maxRows) : rows, truncated };
}

/** queryInstance's step after the query returns, kept pure so a test can prove each loss reaches the result. */
export function finishQuery<T>(
  instanceName: string,
  recordsets: T[][] | undefined,
  maxRows: number,
  opts: { noteTruncation?: boolean; userSql?: boolean } = {}
): { rows: T[]; truncated: boolean } {
  // A batch with no result set (a lone DECLARE, or SELECT … INTO #t) has no first set; it used to crash.
  const { rows, truncated } = capRows(recordsets?.[0] ?? [], maxRows);
  // Most callers keep only `rows`, which would drop `truncated`; noting it puts the cut on the tool
  // result. A caller that already reports `truncated` in its own output passes noteTruncation: false.
  if (truncated && opts.noteTruncation !== false) noteRowCap(instanceName, maxRows);
  // Only the first result set is returned. Built-in tools know their own batches; user SQL is told.
  const sets = recordsets?.length ?? 0;
  if (opts.userSql && sets > 1) noteResultSets(instanceName, sets);
  return { rows, truncated };
}

export async function queryInstance(
  instanceName: string,
  sqlText: string,
  maxRows = 200,
  opts: { noteTruncation?: boolean; userSql?: boolean } = {}
): Promise<{ rows: Record<string, unknown>[]; truncated: boolean; catalog_fallback?: CatalogInfo & { warning: string } }> {
  const pool = await getPool(instanceName);
  const guarded = `SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;\n${applyRowLimit(sqlText, maxRows, opts)}`;
  const result = await pool.request().query(guarded);
  const { rows, truncated } = finishQuery(
    instanceName, result.recordsets as unknown as Record<string, unknown>[][] | undefined, maxRows, opts);

  // A silent catalog fallback would change what every unqualified catalog query MEANS,
  // so it rides along with the rows rather than living only in the server log.
  const catalog_fallback = catalogFallback(pool, instanceName);

  return { rows, truncated, ...(catalog_fallback ? { catalog_fallback } : {}) };
}

// ─────────────────────────────────────────────────────────────────────────────
// executeWrite — used ONLY by the opt-in engineering write tool (execute_write).
//
// Runs the statement inside an explicit transaction on a ReadWrite (primary)
// connection AS THE CALLER'S OWN LOGIN, so SQL Server enforces that login's grants.
//   commit=false (dry-run) → ROLLBACK; returns the rows that WOULD change.
//   commit=true            → COMMIT.
// SET XACT_ABORT ON ensures any error aborts the whole transaction.
//
// Note: a dry-run rolls back the transaction, but a stored proc that performs
// non-transactional side effects (xp_cmdshell, email, or its own COMMIT) cannot be
// fully undone — this is a clean preview for DML, best-effort for such procs.
// ─────────────────────────────────────────────────────────────────────────────
export async function executeWrite(
  instanceName: string,
  sqlText: string,
  commit: boolean
): Promise<{
  rowsAffected: number;
  committed: boolean;
  recordset: Record<string, unknown>[];
  catalog_fallback?: CatalogInfo & { warning: string };
}> {
  const pool = await getPool(instanceName, { write: true });

  // Same reason as queryInstance, but it decides what gets WRITTEN rather than what gets read, so
  // it must not live only in the server log. The write pool is keyed separately from the read pool
  // (`#rw`), so it can be on the fallback catalog while reads are not.
  const catalog_fallback = catalogFallback(pool, instanceName, "write");

  const tx = new sql.Transaction(pool);
  await tx.begin();
  try {
    const result = await new sql.Request(tx).query(`SET XACT_ABORT ON;\n${sqlText}`);
    const rowsAffected = Array.isArray(result.rowsAffected)
      ? result.rowsAffected.reduce((a, b) => a + b, 0)
      : 0;
    const recordset = (result.recordset as Record<string, unknown>[] | undefined) ?? [];
    if (commit) await tx.commit();
    else await tx.rollback();
    return { rowsAffected, committed: commit, recordset, ...(catalog_fallback ? { catalog_fallback } : {}) };
  } catch (e) {
    try { await tx.rollback(); } catch { /* already aborted */ }
    // ATTACH rather than wrap. On a fallback pool the likeliest outcome of an unqualified
    // statement is exactly this path — "Invalid object name" / "Could not find stored procedure",
    // because the object lives in the configured database and the session is on `master` — so the
    // warning matters more here than on success. Wrapping in a new Error would flatten the nested
    // originalError/errors[] chain that sqlErrorNumbers()/isCatalogUnavailable() walk.
    if (catalog_fallback && e instanceof Error) {
      (e as Error & { catalog_fallback?: CatalogInfo & { warning: string } }).catalog_fallback = catalog_fallback;
    }
    throw e;
  }
}
