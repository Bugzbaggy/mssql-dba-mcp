import sql from "mssql";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { readOsCredential, type OsCredential } from "./credentialStore.js";
import { isPlaintextPasswordLiteral, PLAINTEXT_PASSWORD_ERROR } from "./credentialPolicy.js";
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
// the instance's fleet entry carrying `entraAuth:true`. Off everywhere today — the
// fleet probe (2026-06) found zero Entra principals on any node.
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
   * ENTRA_SQL_OBO_ENABLED=1. Default false everywhere — the fleet is not Entra-ready.
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
export const DEFAULT_INSTANCE = process.env.DEFAULT_INSTANCE ?? "nlb";

// ─────────────────────────────────────────────────────────────────────────────
// TLS posture. The connection is ALWAYS encrypted; what follows controls whether
// the SQL Server's certificate is actually VERIFIED. Modes, in priority order:
//
//   per-instance  fleet.json "trustServerCertificate" — wins for that node.
//   trust-all     SQL_TRUST_SERVER_CERT=1 — explicit global opt-OUT of verification
//                 (encrypt only; a MITM cert is accepted). Escape hatch.
//   CA-verify     verify the server cert chain against a CA bundle. This is the DEFAULT:
//                 a public root+intermediate bundle (CN=wc) ships in the repo under
//                 server/ca/, so every install verifies out of the box with no config.
//                 SQL_CA_FILE overrides the path. Because the fleet's leaf certs have NO
//                 SANs, the hostname check is RELAXED by default (chain still enforced —
//                 proves the cert was issued by CN=wc); set SQL_CA_RELAX_HOSTNAME=0 to
//                 force strict once the leaf certs are re-issued with SANs.
//   verify-public only if no CA bundle is found and trust-all is off — verifies against
//                 the OS store (fails on this self-signed fleet). Should not happen in a
//                 normal install since the bundle ships with the code.
//
const TRUST_ALL = process.env.SQL_TRUST_SERVER_CERT === "1";

// The CA bundle ships with the build (public cert, no private key), resolved next to dist/
// like schema-docs. SQL_CA_FILE overrides it. The typeof guard keeps this safe under ESM.
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
// Hostname check is RELAXED by default whenever a CA bundle is active (the fleet's certs
// have no SANs). Set SQL_CA_RELAX_HOSTNAME=0 to force strict (after certs carry SANs).
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
// calling checkServerIdentity, so the chain-to-CN=wc guarantee is intact; we only skip the
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
  log(`[db][tls] hostname check RELAXED for ${fleetHosts.size} fleet hosts (chain still verified against CN=wc). Drop SQL_CA_RELAX_HOSTNAME once leaf certs carry SANs.`);
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
        ? `hostname check RELAXED for fleet hosts (current certs have no SANs; chain to CN=wc still enforced). Set SQL_CA_RELAX_HOSTNAME=0 for strict once certs carry SANs.`
        : `STRICT hostname (SQL_CA_RELAX_HOSTNAME=0) — requires leaf certs with matching SANs.`)
    );
  } else {
    log(`[db][tls] WARNING: no CA bundle found and trust-all is off — verifying against the public trust store, which FAILS on this self-signed fleet. The CA bundle should ship at server/ca/; reinstall, set SQL_CA_FILE, or set SQL_TRUST_SERVER_CERT=1 to bypass.`);
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
const osCred = SQL_CRED_TARGET ? readOsCredential(SQL_CRED_TARGET) : undefined;
if (SQL_CRED_TARGET) {
  if (osCred)
    log(`[db][cred] Using OS credential store "${SQL_CRED_TARGET}" for SQL login "${osCred.user}" (password not logged).`);
  else
    log(`[db][cred] SQL_CRED_TARGET="${SQL_CRED_TARGET}" is set but no matching entry was found in the OS credential store — falling back to SQL_USER/SQL_PASSWORD env.`);
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
  if (!target) return osCred;
  if (!instanceCredCache.has(target)) {
    const cred = readOsCredential(target);
    if (cred)
      log(`[db][cred] Instance "${inst.name}": using OS credential store "${target}" for SQL login "${cred.user}" (password not logged).`);
    else
      log(`[db][cred] Instance "${inst.name}": credTarget="${target}" was not found in the OS credential store - falling back to the fleet credentials.`);
    instanceCredCache.set(target, cred);
  }
  return instanceCredCache.get(target) ?? osCred;
}

function normalize(parsed: InstanceConfig[]): InstanceConfig[] {
  return parsed.map((inst) => {
    const cred = credentialFor(inst);
    return {
      ...inst,
      user:              resolveUser(inst.user, cred),
      password:          resolvePassword(inst.password, cred),
      applicationIntent: inst.applicationIntent ?? "ReadOnly",
    };
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
      user:              osCred?.user     ?? process.env.SQL_USER ?? "",
      password:          osCred?.password ?? process.env.SQL_PASSWORD ?? "",
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

  const pool = await new sql.ConnectionPool(poolConfig).connect();

  pool.on("error", (err: Error) => {
    log(`[db] Pool error on "${key}": ${err.message}`);
    pools.delete(key);
  });

  pools.set(key, pool);
  log(
    `[db] Connected to instance "${instanceName}" (${cfg.host}:${cfg.port}, ` +
    `db=${cfg.database ?? DEFAULT_DATABASE}, intent=${readOnly ? "ReadOnly" : "ReadWrite"}, ` +
    `auth=${useEntra ? "entra" : "sql"}, as=${identity})`
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
// ─────────────────────────────────────────────────────────────────────────────
function applyRowLimit(sqlText: string, limit: number): string {
  if (/\bTOP\s*\(/i.test(sqlText) || /\bSET\s+ROWCOUNT\b/i.test(sqlText)) {
    return sqlText;
  }
  return `SET ROWCOUNT ${limit};\n${sqlText}\nSET ROWCOUNT 0;`;
}

export async function queryInstance(
  instanceName: string,
  sqlText: string,
  maxRows = 200
): Promise<{ rows: Record<string, unknown>[]; truncated: boolean }> {
  const pool = await getPool(instanceName);
  const guarded = `SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;\n${applyRowLimit(sqlText, maxRows)}`;
  const result = await pool.request().query(guarded);
  const all = result.recordset as Record<string, unknown>[];
  const truncated = all.length > maxRows;
  return { rows: truncated ? all.slice(0, maxRows) : all, truncated };
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
): Promise<{ rowsAffected: number; committed: boolean; recordset: Record<string, unknown>[] }> {
  const pool = await getPool(instanceName, { write: true });
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
    return { rowsAffected, committed: commit, recordset };
  } catch (e) {
    try { await tx.rollback(); } catch { /* already aborted */ }
    throw e;
  }
}
