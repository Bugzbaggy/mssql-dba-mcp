# AppDb SQL MCP — End-to-End User Guide

Ask your production SQL Servers questions in plain English and get real answers — safely, read-only.
Pick your app, copy one config, click start, and chat. ~10 minutes the first time.

Paths below assume the repo is at `./appdb-dba-db`. Adjust if yours differs.
The server folder is `appdb-sql-mcp/server`.

---

## Part A — One-time prep (everyone)

1. **Install Node.js 18+** → https://nodejs.org (run installer, click Next). Check: open a terminal, `node --version`.
2. **Build the server once:**
   ```powershell
   cd C:/path/to/appdb-sql-mcp/server
   npm install
   npm run build
   ```
   You should now have `server\dist\index.js`.
3. **Make your server list:** copy `appdb-sql-mcp\fleet.example.json` to `appdb-sql-mcp\fleet.json`.
4. **Know two things:** your **login** and its **password**.
   - DBAs: your own login, a member of a read-only DBA role.
   - Ops: **your own** SQL login (the one already in your `role_team_ops_*` role).
   - For the dbatools health check, use your own DBA login (a read-only DBA role) — never a shared `sa`.

> 🔒 You **never paste the password into a file — and the server enforces it**: it refuses to start if it finds a
> plaintext password in `fleet.json` / `~/.claude.json`. Store your login in your OS credential store (Part B); a real
> environment variable, or the editor's own secret prompt, is the only accepted alternative.

---

## Part B — Set your credentials safely (once)

**Recommended — OS credential store.** Store your login **and** password once under a name (e.g. `SqlServerFleet`) and
reference it with `SQL_CRED_TARGET`; the server reads it at startup, so no secret sits on disk and nothing lives in
`~/.claude.json`. Then set `"SQL_CRED_TARGET": "SqlServerFleet"` in the config `env` (Part C) and omit
`SQL_USER`/`SQL_PASSWORD`. Rotate any time by re-running the command (it overwrites).

```powershell
# Windows — Credential Manager
cmdkey /generic:SqlServerFleet /user:<your-login> /pass:<your-password>
```
```bash
# macOS — Keychain
security add-generic-password -U -s SqlServerFleet -a <your-login> -w <your-password>
# Linux — libsecret
secret-tool store --label=SqlServerFleet service SqlServerFleet account <your-login>
```

**Fallback — environment variable.** If you can't use the credential store, keep `SQL_USER` in the config and set the
password as a **real** env var (persists for your Windows user; apps started afterward pick it up) — **not** as a
literal in the config `env` block or `fleet.json`, which is a file on disk and is refused:
```powershell
[Environment]::SetEnvironmentVariable('SQL_PASSWORD','<your-password>','User')
```
VS Code users can skip both — VS Code will prompt for the password and store it securely (shown below).

---

## Part C — Connect your AI app

All four apps run the **same** server with the **same** settings; only the file location and one key name differ.
The shared settings block (you'll paste it per app):

```jsonc
"command": "node",
"args": ["C:/path/to/appdb-sql-mcp/server/dist/index.js"],
"env": {
  "MCP_TRANSPORT": "stdio",
  "TOOLSET": "dba",                 // DBAs: "dba" • Ops: "ops" • Eng: "eng" • Eng+write: "eng-write"
  "DEFAULT_INSTANCE": "region1-listener",
  "DEFAULT_DATABASE": "AppCatalog",
  "INSTANCES_FILE": "C:/path/to/appdb-sql-mcp/fleet.json",
  "SQL_CRED_TARGET": "SqlServerFleet"   // RECOMMENDED — login+password from your OS credential store (Part B)
  // Fallback instead of SQL_CRED_TARGET:  "SQL_USER": "<your-login>"  (+ SQL_PASSWORD in your environment)
}
```

### 1) Claude Code  *(recommended)*
Create `.mcp.json` in your working folder:
```json
{ "mcpServers": { "sql-dba": { <paste the shared block> } } }
```
Using `SQL_CRED_TARGET` (Part B)? Skip this — the login+password come from your OS credential store. Otherwise set
the password in your terminal (`$env:SQL_PASSWORD="..."`) and omit it from the file — Claude Code inherits it.
Run `claude`, type `/mcp` to confirm `sql-dba` is connected, then ask.

### 2) VS Code + GitHub Copilot  *(closest to "SSMS with AI")*
Install the **GitHub Copilot** + **Copilot Chat** extensions and sign in. Open the repo folder. Create
`.vscode/mcp.json` — VS Code uses the key **`servers`** and can prompt for the password (nothing stored in the file):
```json
{
  "inputs": [
    { "id": "sql-password", "type": "promptString", "description": "SQL password", "password": true }
  ],
  "servers": {
    "sql-dba": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/path/to/appdb-sql-mcp/server/dist/index.js"],
      "env": {
        "MCP_TRANSPORT": "stdio", "TOOLSET": "dba",
        "DEFAULT_INSTANCE": "region1-listener", "DEFAULT_DATABASE": "AppCatalog",
        "INSTANCES_FILE": "C:/path/to/appdb-sql-mcp/fleet.json",
        "SQL_USER": "<your-login>", "SQL_PASSWORD": "${input:sql-password}"
      }
    }
  }
}
```
Click **▶ Start** above `"sql-dba"`, type the password once → open Copilot Chat → switch the dropdown to **Agent** →
click the 🔧 tools icon and make sure the tools are enabled → ask.

### 3) Claude Desktop
Edit `%APPDATA%\Claude\claude_desktop_config.json`:
```json
{ "mcpServers": { "sql-dba": { <paste the shared block; add "SQL_PASSWORD": "<your-password>"> } } }
```
Quit and reopen Claude Desktop → click the 🔨 tools icon → ask. (Desktop doesn't inherit your terminal, so the
password goes in this local file — keep it on your machine only.)

### 4) Cursor (and other MCP apps)
Create `.cursor/mcp.json` with key **`mcpServers`** (same shape as Claude). Settings → MCP shows a green dot when
connected. Use the Agent/Composer to ask.

> **Ops & Engineering:** identical steps with the SELECT-only profile.
> - Ops — `"TOOLSET": "ops"`, `"SERVER_NAME": "msg-ops"`, `"SQL_USER": "<your-own-user_ops*-login>"`.
> - Engineering — `"TOOLSET": "eng"`, `"SERVER_NAME": "msg-eng"`, `"SQL_USER": "<your-own-user_dev_*-login>"`.
>
> Both give the same 6 read-only tools and show only the data your own roles allow. Engineering logins may have
> higher privileges, but the AI still cannot write — read-only is enforced by the tools, not by your login.
>
> **Engineering — optional write mode (`eng-write`):** if your DBA has granted your `user_dev_*` login write
> rights and you want the AI to make data changes too, use `"TOOLSET": "eng-write"` and
> `"SERVER_NAME": "msg-eng-write"` (same login). You get the 6 read tools **plus** one write tool,
> `execute_write`. It is **dry-run by default**: the first call previews how many rows would change and rolls
> back; ask the agent to "confirm" (it re-runs with `confirm:true`) to actually commit. It can run
> `INSERT/UPDATE/DELETE/MERGE` and `EXEC <stored procedure>` only as far as your own SQL role allows — it cannot
> change schema, settings, logins, backups, or jobs. Leave `TOOLSET` as `eng` if you want to stay read-only.

#### Engineering write example (`eng-write`)
```
You:  Set the status to 'PAUSED' for campaign 4711 in AppCatalog.
AI:   (runs execute_write, confirm:false) → "Dry run: 1 row would be updated. Re-run to commit?"
You:  Yes, commit it.
AI:   (runs execute_write, confirm:true) → "Committed: 1 row updated."
```
If your login lacks the grant, SQL Server returns a permission error and nothing changes — that is the boundary
working as designed.

---

## Part D — Ask questions (plain English)

The agent picks the tools and chains them. The first time it runs a tool you'll click **Allow**.

**DBAs:**
- "Is anything blocking right now on the the primary region primary? Show the head blocker and its SQL."
- "Check AG health across all regions — any sync or redo-queue concerns?"
- "Which databases have stale or missing backups?"
- "Top 10 CPU queries on the secondary, with missing-index suggestions."
- "Run a full health check on `region1-node2` and summarise the failures by category."
- "Compare wait stats across every region."

**Ops / Engineering (app data):**
- "Which `svc` views can I read in AppCatalog?"
- "Show the columns of `svc.vwVerifyPricingPlanSubAccount`."
- "Find the account record for customer 12345."
- "SMS volume and delivery rate for India last 7 days." *(answered from the AppDb_Analytics aggregates)*
- "Count today's pending SMS in every region at once."

> **How it reads the data (built-in, you don't have to ask):** the assistant knows the data model —
> **AppCatalog / AppDb** = configuration, **AppDb_Data** = high-volume transactional (large tables like
> `messageLog` are critical), **AppDb_Analytics** = pre-aggregated reporting. For analysis it uses the **AppDb_Analytics
> aggregates**, and it checks each table's size + indexes (via `list_tables` / `describe_object`) so it filters on an
> indexed/partition key with `TOP` rather than scanning. An unbounded scan of a critical table like `messageLog` is
> blocked with a redirect to the aggregates — so you can ask freely without worrying about hammering production.

Say "on region3" / "on `region4-node1`" / "on the primary" to target a specific region or node. Default is `region1-listener`.

> **Experimental: `DBATOOLS_FIRST` for live diagnostics.** `get_wait_stats`, `get_latch_stats`,
> `get_active_sessions`, and `get_statistics_health` normally query the DMVs directly — that's the
> default, no config needed. Set `"DBATOOLS_FIRST": "1"` in the server's `env` (exactly the string
> `"1"` — `DBATOOLS_FIRST=false`, or anything else, correctly leaves it off) to route those tools
> through `dbatools` instead. If the dbatools call fails for any reason, the tool logs why and falls
> back to the DMV path rather than erroring — the experiment can never be the reason a diagnostics
> tool is unavailable mid-incident.
> Warm, against a live SQL 2022 CU14 container: wait stats ran 336ms via dbatools vs 401ms via DMV
> (0.8×, *faster*), latch stats 239ms vs 148ms (1.6×), and active sessions 1428ms vs 473ms (3.0×). Take
> those numbers with a grain of salt: the DMV baseline was measured through `Invoke-DbaQuery` — itself
> PowerShell — while the server's own DMV path queries through the Node `mssql` driver, so this
> understates the true gap between the two paths. The intent is to compare both against real fleet
> traffic and delete whichever loses.
>
> **The flag changes the output schema, not just the source.** The dbatools path returns different
> field names than the DMV path it replaces — e.g. `get_active_sessions`' `session_id` becomes `Spid`,
> `get_wait_stats`' `wait_type` becomes `WaitType`, and `get_latch_stats`' `latch_class` becomes
> `WaitType` as well (dbatools' own field name for both). `exclude_benign` also filters a *different*
> set of wait types on each path (the DMV path uses the Brent Ozar First Responder Kit's
> `#IgnorableWaits` list; the dbatools path uses `Get-DbaWaitStatistic`'s own `Ignorable` field) — the
> two are not guaranteed to agree row-for-row. And because the dbatools call can fail and fall back to
> the DMV path mid-request, **a single request can come back in either shape** — don't assume the
> field names from one call still apply to the next one. `get_statistics_health`'s dbatools path is a
> different case: it has no modification-counter field at all, so `min_modification_pct` is silently
> not applied there (see that tool's own description).

> **Following the live AG primary:** every tool accepts a synthetic `instance_name` of the form `<region>-primary`
> (e.g. `region1-primary`, `region2-primary`, … one per region). The MCP resolves it to the **current** primary
> node at query time and re-resolves after failovers (60-second cache). Use it when you want "the primary right
> now" — the plain `<region>-nlb` listener may route read-only queries to a readable secondary instead. Call
> `get_current_primary region:<x>` if you also want to know which physical node was chosen.

---

## Part E — If something's off

| You see | Do this |
|---|---|
| App doesn't list the server | Did `npm run build` succeed? Is the `args` path correct? Restart the app in a **new** terminal so `SQL_PASSWORD` is present |
| "Login failed for user" | Wrong password (re-enter / re-set the env var) or wrong `SQL_USER` |
| "permission denied on object …" (ops) | Your role wasn't granted that object — expected; use one you can read |
| "VIEW SERVER STATE permission denied" (DBA) | The login needs that grant — see [DEPLOYMENT.md](DEPLOYMENT.md) §login permissions |
| "Query is not read-only" / "not allowed" | Working as designed — only reads are permitted |
| A region times out | Your workstation can't reach that region's NLB (VPN/peering); other regions still work |
| Health-check OS items (power plan/firewall) show errors | Those need Windows access to the node — see [HEALTH-CHECK.md](HEALTH-CHECK.md) |

---

**You cannot break anything.** Every connection is read-only at three independent layers; the AI is physically
incapable of changing data, objects, or configuration.