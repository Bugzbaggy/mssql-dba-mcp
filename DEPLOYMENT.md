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
and must never be committed), and describe your own instances. Point the server
at it with `INSTANCES_FILE`, or pass the same array inline as `INSTANCES`
(`INSTANCES_FILE` wins when both are set). With neither, the server registers a
single instance named `DEFAULT_INSTANCE` (default `nlb`) at `SQL_SERVER`:`SQL_PORT`
(default port 1433) on `SQL_DATABASE`. Set `DEFAULT_INSTANCE` to the entry tools
should use when `instance_name` is omitted (the examples use `region1-listener`).

Keys a fleet entry can carry (`InstanceConfig` in `server/src/connectionManager.ts`):

| Key | Default | Meaning |
|---|---|---|
| `name` | — (required) | The `instance_name` every tool takes |
| `region` | — | Groups entries for `list_instances`, `fan_out_query`, `run_health_check region:` and the `<region>-primary` alias |
| `cloud` | — | Infrastructure label (e.g. `aws`, `gcp`) reported by `list_instances`, for picking same-cloud peers |
| `kind` | `sql` | `witness` marks a file-share witness: SQL tools refuse it, host-level tools can still address it |
| `computer_name` | — | Windows computer name, for a witness or node reached by IP |
| `host`, `port` | — (required; `port` for `kind: sql`) | Where to connect |
| `user` | `SQL_USER` / credential store | A literal login is allowed; `"${SQL_USER}"` (or empty) resolves from the credential store or environment |
| `password` | `SQL_PASSWORD` / credential store | Only `"${SQL_PASSWORD}"`, `"$SQL_PASSWORD"` or empty — a literal is refused at startup |
| `credTarget` | `SQL_CRED_TARGET` | A per-instance OS credential-store entry, for a node that does not share the fleet login |
| `database` | `DEFAULT_DATABASE`, else `AppCatalog` | Initial catalog; must be an AG database for read-only routing to engage |
| `applicationIntent` | `ReadOnly` | `ReadWrite` clears the read-only intent flag |
| `encrypt` | `true` | TLS on the connection |
| `trustServerCertificate` | resolved globally (see `.env.example`, *TLS to SQL Server*) | Per-instance override of certificate verification |
| `multiSubnetFailover` | `false` | Probe every IP of a multi-subnet listener in parallel |
| `entraAuth` | `false` | Path A only: connect with an Entra token minted via OBO (see [AAD-ENTRA-SETUP.md](AAD-ENTRA-SETUP.md)) |

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
their permissions and audits every statement to them.
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

> **Two gaps in the block above, if you are provisioning a login today.**
> 1. **`CONNECT ANY DATABASE` is missing.** Several tools emit a literal `USE [<db>]`, so a login provisioned only
>    for the databases named here silently fails on every other database, including any created later. It grants
>    *entry, not data*.
> 2. **Server-scoped grants do NOT replicate.** "Run once on each primary" is correct for the per-database grants
>    only. The server role and its grants must be created on **every replica**, or every call to a skipped node
>    fails — connections carry `ApplicationIntent=ReadOnly` and land on a readable *secondary*.

**Automated / non-human diagnosis (`svc_sqldiag`):** for an unattended health-check, diagnosis and troubleshooting
principal — one that must reach the whole catalog **without `sysadmin`** — use
[`deploy/01-svc_sqldiag-login-and-grants.sql`](deploy/01-svc_sqldiag-login-and-grants.sql) rather than adapting the
block above. It is SID-pinned across every replica, grants no `db_datareader` on any application database (health
checks need metadata, not rows), and carries explicit `DENY`s on the Agent-job and Database Mail surfaces. Verify
each node with [`deploy/02-Test-svc_sqldiag-grants.sql`](deploy/02-Test-svc_sqldiag-grants.sql), which **fails
closed** — a check it could not exercise reports `UNMEASURED`, never `PASS` — and audit what the login actually
does with [`deploy/03-audit-svc_sqldiag.sql`](deploy/03-audit-svc_sqldiag.sql).

> Note the honest limit stated in that script's header: `VIEW SERVER STATE` is itself a customer-data read path
> (query text and plan literals, and `sys.fn_xe_file_target_read_file` over any XEL audit logs), so any diagnostic
> principal is **inside** the PII boundary for access review. No `DENY` closes that.

- **Ops (`msg-ops`)** uses each ops user's **own** `user_ops*` login (member of your `role_team_ops_*` roles)
  — scoped to the specific objects those roles grant.
- **Engineering (`msg-eng`)** uses each engineer's **own** `user_dev_*` login, which has **read access to all
  databases** — so engineers can query across the whole estate (`list_databases` lists every database; reach any
  with `[Database].[schema].[object]`). The AI is still strictly read-only regardless of that broader privilege.

  Both are the same SELECT-only app-data profile; SQL Server scopes each user to exactly what *their own* login can
  read, and every query is attributable. The tooling never creates these logins — ops/engineers already have them.
- **`run_health_check`** runs under the DBA's own login (`HEALTHCHECK_SQL_USER`, else `SQL_USER`) — never a shared
  `sa`. It is read-only because it runs only read cmdlets — see [HEALTH-CHECK.md](HEALTH-CHECK.md).
- **Engineering writes (`eng-write`)** — the "edit operations" path. It is a
  **separate, opt-in profile** (`TOOLSET=eng-write`) that adds one explicitly-destructive tool, `execute_write`,
  on top of the read tools. It connects **ReadWrite** as the engineer's *own* `user_dev_*` login, so SQL
  Server's role grants are the authorization boundary — the server never confers privilege. A DBA grants the
  write rights on the role (e.g. `db_datawriter` and/or `EXECUTE` on the relevant schemas/procedures); a login
  without those grants simply gets a permission error. See *"Write operations"* below.

Verify a login end-to-end **before** wiring up any client:
```powershell
$env:SQL_USER='<your-own-login>'; $env:SQL_PASSWORD='<password>'
.\scripts\Test-SqlMcp.ps1 -Server 'listener.region1.example.com,1433' -Database AppCatalog -User $env:SQL_USER
# Quote host,port: unquoted, PowerShell passes it as a two-element array and the connection string breaks.
# Expect: PASS read OK, PASS VIEW SERVER STATE, PASS write blocked.
```

## 3. Build
```powershell
cd mssql-dba-mcp\server
npm install
npm run build      # -> dist\index.js
```

## 4. The four profiles

| Profile | `TOOLSET` | Connects as | Intent | Tools |
|---|---|---|---|---|
| **sql-dba** | `dba` | your own login (read-only DBA role) | ReadOnly | 55: 32 DMV tools + 12 PowerShell/dbatools tools (incl. `run_health_check`; off with `DBATOOLS_ENABLED=false`) + the 11 app-data tools |
| **msg-ops** | `ops` | your own `user_ops*` login | ReadOnly | 11: `list_instances`, `list_databases`, `list_tables`, `describe_object`, `get_current_primary`, `fan_out_query`, `execute_query` — SELECT-only — plus the 4 schema-docs tools (`describe_schema`, `describe_doc_object`, `list_schema_docs`, `search_schema_docs`; off with `SCHEMA_DOCS_ENABLED=false`) |
| **msg-eng** | `eng` | your own `user_dev_*` login | ReadOnly | the same 11 SELECT-only app-data tools as `msg-ops` |
| **eng-write** | `eng-write` + `ENG_WRITE_ENABLED=1` | your own `user_dev_*` login | ReadWrite (`execute_write` only) | the same 11 read tools **+ `execute_write`** (DML / `EXEC` proc, bounded by the login's SQL role). Without `ENG_WRITE_ENABLED=1` it registers only the 11 read tools |

The counts are pinned by `tests/profileToolsets.test.ts`, which registers every profile and asserts its exact tool
list, so they cannot drift unnoticed.

`DBATOOLS_ENABLED=false` removes the 12 PowerShell tools only. Nine of the 32 DMV-group tools — `get_ag_health`,
`get_backup_status`, `get_database_files`, `get_database_info`, `get_job_status`, `get_machine_spec`,
`get_server_info`, `get_tempdb_usage`, `get_vlf_count` — and the AG confirmation inside `get_current_primary` call a
dbatools cmdlet through a long-lived PowerShell worker. They stay registered, need PowerShell + dbatools on the host
to return data, and authenticate with the environment credential described in §5 rather than `SQL_CRED_TARGET`.

`msg-ops` and `msg-eng` are the identical SELECT-only profile — they differ only by the login each user connects
as, so the database's own roles scope what each can see. `eng-write` is `msg-eng` plus the one write tool, and is
the only profile that connects `ApplicationIntent=ReadWrite` (so writes route to the primary). All four read the
same `fleet.json`; each sets its own `SQL_USER`/`SQL_PASSWORD` (and `SERVER_NAME`/`TOOLSET`). Register them in the
AI client per [USER-GUIDE.md](USER-GUIDE.md). Configuration reference is in `.env.example`.

### 4a. Write operations (`eng-write`) — opt-in, role-bounded

`eng-write` exists so engineering can make **data** changes through the AI when they choose to, without weakening
the read-only posture of every other profile. It takes two switches: `TOOLSET=eng-write` **and** the kill-switch
`ENG_WRITE_ENABLED=1` (exactly `1`). With only the first, the server logs a warning, does not register
`execute_write`, and is read-only. It is safe because authority comes from SQL Server, not the tool:

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
  GRANT EXECUTE ON SCHEMA::[core] TO [<engineer_login>];
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

**Passwords are never stored in the fleet definition — this is enforced.** `fleet.json` / `INSTANCES` use the `${SQL_PASSWORD}` placeholder (or leave `password` empty); a literal password in a fleet entry is **refused at startup**. The secret comes only from the OS credential store (below) or the `SQL_PASSWORD` env var. The server cannot see where an environment variable came from, so a literal `SQL_PASSWORD` in an MCP client's `env` block is not refused — keep it out of those files yourself.

**Local (stdio) secrets → OS credential store (preferred).** Instead of a plaintext `SQL_PASSWORD` in
`~/.claude.json`, store your login once in the OS credential store and reference it by name with
`SQL_CRED_TARGET`. The server reads the login **and** password from Windows Credential Manager / macOS Keychain /
libsecret the first time a connection needs them (not at startup, so the server answers the MCP client's connect
handshake first) — nothing sensitive touches disk, and the model never sees it. The read has a 60 s budget
(`SQL_CRED_TIMEOUT_MS`); a read that times out or fails is logged as **could not read**, distinct from an entry that
does not exist.

```bash
# create the entry once (name it whatever you set in SQL_CRED_TARGET; SqlServerFleet here)
# Windows :  cmdkey /generic:SqlServerFleet /user:<login> /pass:<password>
# macOS   :  security add-generic-password -U -s SqlServerFleet -a <login> -w <password>
# Linux   :  secret-tool store --label=SqlServerFleet service SqlServerFleet account <login>
```

Then the `mcpServers` env carries **no secret** — only `SQL_CRED_TARGET`:
```json
{ "mcpServers": { "appdb-sql": { "type": "stdio", "command": "node",
  "args": ["<path>/mssql-dba-mcp/server/dist/index.js"],
  "env": { "TOOLSET": "dba", "INSTANCES_FILE": "<path>/mssql-dba-mcp/fleet.json",
           "SQL_CRED_TARGET": "SqlServerFleet" } } } }
```
Rotate the credential by re-running the create command (it overwrites). The `SQL_PASSWORD` **environment variable**
is the only alternative when `SQL_CRED_TARGET` is unset or its entry is missing — set it as a real env var, **not**
as a literal in `fleet.json` (refused at startup) or in the client `env` block (not refused, but a secret on disk).
This is interim hardening until an OAuth + vault design removes local static SQL passwords entirely.

`SQL_CRED_TARGET` is read by the T-SQL tools only. Everything that runs through PowerShell builds its credential
from the environment — `HEALTHCHECK_SQL_USER`/`HEALTHCHECK_SQL_PASSWORD` for the health check, else
`SQL_USER`/`SQL_PASSWORD` — and uses Windows authentication when those are unset. That covers the 12 PowerShell
tools, the `DBATOOLS_FIRST` paths, and the DMV-group tools that call a dbatools cmdlet (see §4).

`.gitignore` excludes `fleet.json` and `.mcp.json`.

## 6. Verification (automated)
```powershell
cd mssql-dba-mcp\server
npm install         # not `npm ci`: server/package-lock.json is git-ignored, so a fresh clone has none
npm run typecheck
npm test            # node:test suite (tests/*.test.ts)
```
`npm test` runs the read-only and write guards against adversarial SQL (`adversarial`, `safety`), the row cap and
its truncation banner, the catalog-fallback scope, the on-disk credential policy and lazy credential resolution, the
health-check catalog structure and evaluator grading, the details and remediation text (a fix may only name
databases and nodes the check returned), the site configuration of the health check (`siteConfig`), and the
generated health-check PowerShell — including a parse with Windows PowerShell's own parser where it is installed.
It also pins each profile's exact tool set (`profileToolsets`) and, on a Windows machine with dbatools installed,
checks that every dbatools cmdlet and parameter the generated scripts call exists in that dbatools
(`dbatoolsCmdlets`; skipped elsewhere). `tests/parity/` holds a live-instance field-presence harness that `npm test`
does not run (see its README).

## 7. Platform deployment (`mcp.example.com` — shared HTTP)

The server runs two ways. Everything above is **stdio** (each user launches their own process locally). It also
runs as a **single shared HTTP service** on the MCP platform, registered once and used by everyone — *without*
giving up per-user identity.

**How per-user identity survives a shared service.** There is still **no shared SQL account**. Each user's client
sends their *own* SQL login on every request as the `X-DB-User` / `X-DB-Password` headers; the server uses them
only for that request (an `AsyncLocalStorage` context; pools keyed per user) and **never persists them** — the
credentials live solely in the user's local client config, exactly like the stdio password env var. SQL Server
still authenticates and audits each query to the real person, and database grants stay the authorization boundary
(see §2). The platform restricts reachability (internal DNS + VPN) and
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
| **Cluster** | `<your-cluster>` |

### 7.2 Deployment environment (set on the platform, not in headers)

```
MCP_TRANSPORT=http
PORT=8080
TOOLSET=eng-write          # the read tools + execute_write. Use "eng" for a read-only-only deployment.
ENG_WRITE_ENABLED=1        # required with eng-write; without it execute_write is not registered
SERVER_NAME=appdb-sql
INSTANCES_FILE=./fleet.json # fleet topology only — NO credentials (user/password come from headers)
DEFAULT_INSTANCE=region1-listener
DEFAULT_DATABASE=AppCatalog
DBATOOLS_ENABLED=false      # the dbatools health check needs PowerShell on the host; not available on the cluster
MCP_BIND_HOST=0.0.0.0       # platform only: bind all interfaces to receive proxied traffic (default is 127.0.0.1)
MCP_TRUST_PROXY=1           # behind the platform's reverse proxy, so req.ip uses X-Forwarded-For (rate limit keying)
MCP_RATE_LIMIT_PER_MIN=120  # per-minute /mcp cap, keyed by source IP only (0 disables)
```
`SQL_USER` / `SQL_PASSWORD` are **deliberately unset** — in HTTP mode they come per request from the headers, and the
server never falls back to its own credential: a request without both `X-DB-User` and `X-DB-Password` fails with
*"No X-DB-User / X-DB-Password on this request"*. The PowerShell-backed tools are never registered on the HTTP
transport, whatever `TOOLSET` and `DBATOOLS_ENABLED` say, because they would run as the server's own credential.

**HTTP security contract.** The server defaults to binding **`127.0.0.1`** — it only listens on all interfaces when
you set `MCP_BIND_HOST=0.0.0.0` (the platform does, behind its reverse proxy). **TLS terminates at the platform
proxy**; the app sends `Strict-Transport-Security` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` +
`Referrer-Policy: no-referrer` and rate-limits `/mcp` per source IP (the login header is attacker-controlled, so it
is not part of the key). Host/Origin (DNS-rebinding) validation turns on only when `MCP_ALLOWED_HOSTS` and/or
`MCP_ALLOWED_ORIGINS` are set. Credentials travel only in the `X-DB-User`/`X-DB-Password` headers over the
proxy's HTTPS and are **never written to disk**. Do **not** expose the port without the TLS-terminating proxy in front.

### 7.3 Prerequisites (platform / DBA)

- **Network:** the `<your-cluster>` cluster must have routes to every regional NLB it should serve (all regions — see §1).
  A region the cluster can't reach simply errors on use; others keep working.
- **Per-user SQL logins:** each user needs their own login on the instance(s) they query (`user_ops*` / `user_dev_*`
  / DBA login), with the appropriate grants. The platform/tooling never creates these.
- **Profile choice:** one deployment exposes one `TOOLSET`. `eng-write` shows `execute_write` to everyone, but a
  user without the write grant just gets a permission error (grants decide — consistent with the read model). For a
  hard split, run **two** registrations: `appdb-sql` (`TOOLSET=eng`, read-only) and `appdb-sql-write`
  (`TOOLSET=eng-write` + `ENG_WRITE_ENABLED=1`). DMV/dbatools DBA tooling stays on the local stdio `sql-dba` profile (it needs host
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