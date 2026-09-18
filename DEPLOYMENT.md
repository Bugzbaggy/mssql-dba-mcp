# AppDb SQL MCP — Deployment & Administration

For DBAs / platform admins. Covers the fleet, the read-only login permissions, build, registration, the four
profiles (three read-only + one opt-in write), and verification. End users should follow [USER-GUIDE.md](USER-GUIDE.md).

> No Docker. Native Node.js for the server; Windows PowerShell + the `dbatools` module for the health check.

## 1. Fleet configuration

The server is driven entirely by `fleet.json` — a list of instances it may
connect to. There is no hardcoded topology; the example below is illustrative,
not a description of any particular deployment.

```jsonc
[
  {
    "name": "region1-listener",     // <region>-<role> is the convention
    "region": "region1",
    "host": "listener.region1.example.com",
    "port": 1433,
    "user": "${SQL_USER}",
    "password": "${SQL_PASSWORD}",
    "database": "AppCatalog",
    "applicationIntent": "ReadOnly"
  },
  {
    "name": "region1-node1",
    "region": "region1",
    "host": "192.0.2.20",
    "port": 1433,
    "database": "AppCatalog",
    "applicationIntent": "ReadOnly"
  }
]
```

Start from `fleet.example.json`, copy it to `fleet.json` (which is gitignored
and must never be committed), and describe your own instances.

**Connection behaviour.** Every instance connects with
`ApplicationIntent=ReadOnly; Encrypt=True`. Set `TrustServerCertificate=True`
only where you connect by IP and cannot present a matching certificate name.
The server connects **lazily** per instance, and fan-out uses
`Promise.allSettled`, so an unreachable instance fails only on use rather than
breaking the whole call.

**Listeners vs. nodes.** List the AG listener for normal work, and the
individual nodes as well when you need node-local data — error logs, dumps,
cluster reports, and per-replica health all live on a specific node, not
behind the listener.

**Distributed availability groups.** If some databases replicate across
regions via distributed AGs, point `get_distributed_ag_health` at the instance
holding the global primary role; `get_ag_health` covers the local AG within a
region. Which databases replicate, and which are region-local, is a property
of your deployment — the server discovers it rather than assuming it.

**Adding instances:** add an object with a new `name`, `region`, `host`, and
`port`. Leave `user`/`password` as `"${SQL_USER}"`/`"${SQL_PASSWORD}"` so
credentials resolve from the environment or the OS credential store. Restart
the client — no rebuild required.

## 2. Per-user identity — every operation runs as the calling user

**There is no shared service account.** Each person connects with **their own SQL login**, so SQL Server enforces
their permissions and audits every statement to them (see ADR-001-per-user-identity.md).
The tooling never creates or alters principals — a DBA provisions logins/roles once.

**DBAs (`sql-dba` + `run_health_check`):** grant read-only DBA rights to a **role**, then add each DBA's own login
to it. Run once on each primary; AG-database grants replicate to secondaries. (DBA-run, review first.)

```sql
-- Server scope (master): one read-only DBA role; add each DBA's login as a member.
CREATE SERVER ROLE [role_dba_readonly];                       -- once
GRANT VIEW SERVER STATE   TO [role_dba_readonly];             -- DMVs: waits, sessions, I/O, memory, AG
GRANT VIEW ANY DEFINITION TO [role_dba_readonly];             -- object/index metadata, schema
GRANT VIEW ANY DATABASE   TO [role_dba_readonly];             -- sys.databases visibility
ALTER SERVER ROLE [role_dba_readonly] ADD MEMBER [DOMAIN_or_login_of_each_DBA];

-- Per database (each AG DB + msdb): read + per-DB DMV state, granted to the role.
USE [AppCatalog];
  CREATE USER [<dba_login>] FOR LOGIN [<dba_login>];          -- per DBA login
  ALTER ROLE db_datareader ADD MEMBER [<dba_login>];
  GRANT VIEW DATABASE STATE TO [<dba_login>];
-- repeat for AppDb, AppDb_Data, AppDb_Routing, and msdb (msdb covers backup & job status).
```

- **Ops (`msg-ops`)** uses each ops user's **own** `user_ops*` login (member of `role_team_ops_l1/_l2/_tim/_channels`)
  — scoped to the specific objects those roles grant.
- **Engineering (`msg-eng`)** uses each engineer's **own** `user_dev_*` login, which has **read access to all
  databases** — so engineers can query across the whole estate (`list_databases` lists every database; reach any
  with `[Database].[schema].[object]`). The AI is still strictly read-only regardless of that broader privilege.

  Both are the same SELECT-only app-data profile; SQL Server scopes each user to exactly what *their own* login can
  read, and every query is attributable. The tooling never creates these logins — ops/engineers already have them.
- **`run_health_check`** runs under the DBA's own login (`HEALTHCHECK_SQL_USER`, else `SQL_USER`) — never a shared
  `sa`. It is read-only because it runs only read cmdlets — see [HEALTH-CHECK.md](HEALTH-CHECK.md).
- **Engineering writes (`eng-write`)** — the realized "edit operations" path foreseen in the ADR. It is a
  **separate, opt-in profile** (`TOOLSET=eng-write`) that adds one explicitly-destructive tool, `execute_write`,
  on top of the 6 read tools. It connects **ReadWrite** as the engineer's *own* `user_dev_*` login, so SQL
  Server's role grants are the authorization boundary — the server never confers privilege. A DBA grants the
  write rights on the role (e.g. `db_datawriter` and/or `EXECUTE` on the relevant schemas/procedures); a login
  without those grants simply gets a permission error. See *"Write operations"* below and the ADR.

Verify a login end-to-end **before** wiring up any client:
```powershell
$env:SQL_USER='<your-own-login>'; $env:SQL_PASSWORD='<password>'
.\scripts\Test-SqlMcp.ps1 -Server listener.region1.example.com,1433 -Database AppCatalog -User $env:SQL_USER
# Expect: PASS read OK, PASS VIEW SERVER STATE, PASS write blocked.
```

## 3. Build
```powershell
cd appdb-sql-mcp\server
npm install
npm run build      # -> dist\index.js
```

## 4. The four profiles

| Profile | `TOOLSET` | Connects as | Intent | Tools |
|---|---|---|---|---|
| **sql-dba** | `dba` | your own login (read-only DBA role) | ReadOnly | 31 DMV tools + 6 dbatools tools + the app-data tools |
| **msg-ops** | `ops` | your own `user_ops*` login | ReadOnly | `list_instances`, `list_databases`, `list_tables`, `describe_object`, `fan_out_query`, `execute_query` — SELECT-only |
| **msg-eng** | `eng` | your own `user_dev_*` login | ReadOnly | same six SELECT-only app-data tools as `msg-ops` |
| **eng-write** | `eng-write` | your own `user_dev_*` login | ReadWrite | the six read tools **+ `execute_write`** (DML / `EXEC` proc, bounded by the login's SQL role) |

`msg-ops` and `msg-eng` are the identical SELECT-only profile — they differ only by the login each user connects
as, so the database's own roles scope what each can see. `eng-write` is `msg-eng` plus the one write tool, and is
the only profile that connects `ApplicationIntent=ReadWrite` (so writes route to the primary). All four read the
same `fleet.json`; each sets its own `SQL_USER`/`SQL_PASSWORD` (and `SERVER_NAME`/`TOOLSET`). Register them in the
AI client per [USER-GUIDE.md](USER-GUIDE.md). Configuration reference is in `.env.example`.

### 4a. Write operations (`eng-write`) — opt-in, role-bounded

`eng-write` exists so engineering can make **data** changes through the AI when they choose to, without weakening
the read-only posture of every other profile. It is safe because authority comes from SQL Server, not the tool:

- **The login's SQL role is the boundary.** `execute_write` connects as the engineer's *own* `user_dev_*` login
  with `ApplicationIntent=ReadWrite`. A statement only succeeds if that login already holds the grant (e.g.
  `db_datawriter`, or `EXECUTE` on a schema/procedure). Provision those grants on the role the same way as the
  read grants in §2 — the tooling never creates or alters principals or grants.
- **Dry-run by default.** Each call runs inside a transaction. With `confirm:false` (default) the work is executed
  then **rolled back**, returning the row count that *would* change; re-running with `confirm:true` commits.
- **A second guardrail still hard-blocks the *strictly forbidden* categories**, regardless of what the login could
  do: DDL (`CREATE`/`ALTER`/`DROP`), server/database settings (`sp_configure`/`RECONFIGURE`/`ALTER … SET`),
  principals (`CREATE/ALTER/DROP LOGIN|USER|ROLE`, role membership), backups (`BACKUP`/`RESTORE`), SQL Agent jobs
  (`msdb`, `sp_*job*`), `DBCC`, `KILL`, `SHUTDOWN`, `WAITFOR`, and **ad-hoc dynamic SQL** (`sp_executesql`,
  `EXEC(<string>)`, `xp_*`, `sp_OA*`, linked-server openers). Allowed: `INSERT`/`UPDATE`/`DELETE`/`MERGE` and
  `EXEC <procedure>`. (`UPDATE`/`DELETE` without a `WHERE` are rejected unless `allow_unfiltered:true`.)
- **Engineering's dynamic-SQL procedures are reached by calling them** (`EXEC <proc>`), which is allowed; raw
  dynamic SQL submitted directly to `execute_write` stays blocked.

To grant write on a role (DBA-run, review first) — example for one database:
```sql
USE [AppCatalog];
  -- data writes:
  ALTER ROLE db_datawriter ADD MEMBER [<engineer_login>];
  -- and/or procedure execution (preferred for the dynamic-SQL procs):
  GRANT EXECUTE ON SCHEMA::[cp] TO [<engineer_login>];
```
Leave `eng-write` unregistered for anyone who should stay read-only — read access does not imply the write tool.

## 5. Security recap
1. **Login** — least-privilege read-only (write grants only where a DBA explicitly adds them, for `eng-write`).
2. **Connection** — `ApplicationIntent=ReadOnly`, `Encrypt=True`, read-uncommitted isolation (no locks on the
   workload). *Exception:* the `eng-write` profile's `execute_write` connects `ReadWrite` so writes route to the
   primary; all read tools and all other profiles stay `ReadOnly`.
3. **Allowlist** — T-SQL `SELECT`/`WITH`/`DECLARE` only; dbatools `Get-/Test-/Measure-/Find-` only. Everything
   else denied. *Carve-out:* in `eng-write`, `execute_write` additionally accepts
   `INSERT`/`UPDATE`/`DELETE`/`MERGE`/`EXEC <proc>` but still hard-blocks DDL, settings, principals, backups, jobs
   (`msdb`), and ad-hoc dynamic SQL (see §4a). The read allowlist is unchanged.

**Passwords are never stored in plaintext — this is enforced.** `fleet.json` / `INSTANCES` use the `${SQL_PASSWORD}` placeholder (or leave `password` empty); a literal password baked into the config is **refused at startup** — the server will not run with a secret on disk. The secret comes only from the OS credential store (below) or the `SQL_PASSWORD` env var.

**Local (stdio) secrets → OS credential store (preferred).** Instead of a plaintext `SQL_PASSWORD` in
`~/.claude.json`, store your login once in the OS credential store and reference it by name with
`SQL_CRED_TARGET`. The server reads the login **and** password at startup from Windows Credential Manager /
macOS Keychain / libsecret — nothing sensitive touches disk, and the model never sees it.

```bash
# create the entry once (name it whatever you set in SQL_CRED_TARGET; SqlServerFleet here)
# Windows :  cmdkey /generic:SqlServerFleet /user:<login> /pass:<password>
# macOS   :  security add-generic-password -U -s SqlServerFleet -a <login> -w <password>
# Linux   :  secret-tool store --label=SqlServerFleet service SqlServerFleet account <login>
```

Then the `mcpServers` env carries **no secret** — only `SQL_CRED_TARGET`:
```json
{ "mcpServers": { "appdb-sql": { "type": "stdio", "command": "node",
  "args": ["<repo>/appdb-sql-mcp/server/dist/index.js"],
  "env": { "TOOLSET": "dba", "INSTANCES_FILE": "<repo>/appdb-sql-mcp/fleet.json",
           "SQL_CRED_TARGET": "SqlServerFleet" } } } }
```
Rotate the credential by re-running the create command (it overwrites). The `SQL_PASSWORD` **environment variable**
is the only accepted alternative when `SQL_CRED_TARGET` is unset — set it as a real env var, **not** as a literal in
`fleet.json` or the client `env` block (a password on disk there is refused; see above). This is the interim
hardening until ADR-002's OAuth + vault design removes local static SQL passwords entirely.

`.gitignore` excludes `fleet.json` and `.mcp.json`.

## 6. Verification (automated — 222 checks)
```powershell
cd appdb-sql-mcp\server
node tests\validate.mjs                                   # 152 checks: build, profiles, safety, allowlist, fleet, script
powershell -ExecutionPolicy Bypass -File tests\validate-healthcheck.ps1   # 70 checks: cmdlets, params, report shape/order
```
`validate.mjs` proves the exact tool sets, the full read-only matrix, the dbatools allowlist (incl. the
write-in-disguise denylist), the fleet topology, and the generated health-check script structure.
`validate-healthcheck.ps1` proves every health-check cmdlet exists with valid parameters and that the report JSON
captures all checks in the correct category order and field format.

## 7. Platform deployment (`mcp.example.com` — shared HTTP)

The server runs two ways. Everything above is **stdio** (each user launches their own process locally). It also
runs as a **single shared HTTP service** on the MCP platform, registered once and used by everyone — *without*
giving up per-user identity.

**How per-user identity survives a shared service.** There is still **no shared SQL account**. Each user's client
sends their *own* SQL login on every request as the `X-DB-User` / `X-DB-Password` headers; the server uses them
only for that request (an `AsyncLocalStorage` context; pools keyed per user) and **never persists them** — the
credentials live solely in the user's local client config, exactly like the stdio password env var. SQL Server
still authenticates and audits each query to the real person, and database grants stay the authorization boundary
(see ADR-001 §3a). The platform restricts reachability (internal DNS + VPN) and
terminates HTTPS.

### 7.1 Register on the platform

| Field | Value |
|---|---|
| **Name** | `appdb-sql` *(URL becomes `https://mcp-appdb-sql-latest.mcp.example.com/mcp`)* |
| **Description** | Read-only-by-default AI access to the AppDb/AppCatalog SQL Server estate (app-data queries across all configured regions); engineering writes are role-bounded and dry-run by default. The MCP runs every query as **your own** SQL login — the database grants decide what you can read or change. |
| **Category** | `data` |
| **Transport** | `http` |
| **Port** | `8080` |
| **Health check path** | `/health` |
| **MCP endpoint path** | `/mcp` |
| **Cluster** | `ops-01` |

### 7.2 Deployment environment (set on the platform, not in headers)

```
MCP_TRANSPORT=http
PORT=8080
TOOLSET=eng-write          # 6 read tools + execute_write. Use "eng" for a read-only-only deployment.
SERVER_NAME=appdb-sql
INSTANCES_FILE=./fleet.json # fleet topology only — NO credentials (user/password come from headers)
DEFAULT_INSTANCE=region1-listener
DEFAULT_DATABASE=AppCatalog
DBATOOLS_ENABLED=false      # the dbatools health check needs PowerShell on the host; not available on the cluster
MCP_BIND_HOST=0.0.0.0       # platform only: bind all interfaces to receive proxied traffic (default is 127.0.0.1)
MCP_TRUST_PROXY=1           # behind the platform's reverse proxy, so req.ip uses X-Forwarded-For (rate limit keying)
MCP_RATE_LIMIT_PER_MIN=120  # per-minute /mcp cap, keyed by source IP + caller login (0 disables)
```
`SQL_USER` / `SQL_PASSWORD` are **deliberately unset** — in HTTP mode they come per request from the headers. If a
request arrives without them the server returns a clear *"DB credentials not configured"* error.

**HTTP security contract.** The server defaults to binding **`127.0.0.1`** — it only listens on all interfaces when
you set `MCP_BIND_HOST=0.0.0.0` (the platform does, behind its reverse proxy). **TLS terminates at the platform
proxy**; the app sends `Strict-Transport-Security` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` and
rate-limits `/mcp` per IP + login. Credentials travel only in the `X-DB-User`/`X-DB-Password` headers over the
proxy's HTTPS and are **never written to disk**. Do **not** expose the port without the TLS-terminating proxy in front.

### 7.3 Prerequisites (platform / DBA)

- **Network:** the `ops-01` cluster must have routes to every regional NLB it should serve (all regions — see §1).
  A region the cluster can't reach simply errors on use; others keep working.
- **Per-user SQL logins:** each user needs their own login on the instance(s) they query (`user_ops*` / `user_dev_*`
  / DBA login), with the appropriate grants. The platform/tooling never creates these.
- **Profile choice:** one deployment exposes one `TOOLSET`. `eng-write` shows `execute_write` to everyone, but a
  user without the write grant just gets a permission error (grants decide — consistent with the read model). For a
  hard split, run **two** registrations: `appdb-sql` (`TOOLSET=eng`, read-only) and `appdb-sql-write`
  (`TOOLSET=eng-write`). DMV/dbatools DBA tooling stays on the local stdio `sql-dba` profile (it needs host
  PowerShell), not the cluster.

### 7.4 How users add it (per-user credentials in headers)

Claude Code (CLI):
```bash
claude mcp add appdb-sql --transport http --scope user https://mcp-appdb-sql-latest.mcp.example.com/mcp
```
Then add your own DB login to that entry in `~/.claude.json` (Claude Desktop: `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "appdb-sql": {
      "type": "http",
      "url": "https://mcp-appdb-sql-latest.mcp.example.com/mcp",
      "headers": {
        "X-DB-User": "your_sql_login",
        "X-DB-Password": "your_sql_password"
      }
    }
  }
}
```
Fully quit and reopen the client (config is read on restart). Requires the example VPN (internal DNS only). The
credentials stay in your local config and are never stored on the server.