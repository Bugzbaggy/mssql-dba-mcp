# mssql-dba-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server
that gives an AI agent safe, structured access to SQL Server diagnostics
across a fleet — DMVs, wait stats, Query Store, Always On health, deadlock
history, and `dbatools` health checks.

[![Node 22+](https://img.shields.io/badge/Node-22%2B-339933)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why this exists

Giving a language model a raw SQL connection is a bad idea: it can write, it
can block, and it can run something expensive on a primary at peak. But the
*diagnostic* questions an agent is good at — "what changed", "what is waiting
on what", "which plan regressed" — are all read-only.

This server exposes exactly those, as typed tools, with the write path closed
by construction rather than by prompt instruction.

**Design rules:**

- **Read-only by construction.** Statement inspection rejects anything that
  isn't a read; connections default to `ApplicationIntent=ReadOnly`.
- **Credentials never reach the model.** They come from the OS credential
  store (Windows Credential Manager, Keychain, libsecret) via a
  `SQL_CRED_TARGET` name, not from config the agent can read.
- **Fleet-aware.** One declarative `fleet.json` describes every instance;
  tools take an instance name, not a connection string.
- **Fan-out.** Region-local questions get asked across every node at once.

## Tool surface

| Area | Tools |
|---|---|
| Triage | `get_hiq`, `get_active_sessions`, `get_blocking_chains`, `get_wait_stats`, `get_long_running_transactions` |
| Queries | `get_top_queries`, `get_query_store_regressions`, `get_plan_cache_pollution`, `get_missing_indexes`, `get_statistics_health` |
| Availability | `get_ag_health`, `get_distributed_ag_health`, `get_current_primary`, `get_backup_status`, `get_job_status` |
| Resources | `get_memory_usage`, `get_cpu_history`, `get_tempdb_usage`, `get_file_io_stats`, `get_latch_stats`, `get_buffer_pool_by_object`, `get_perfmon_counters` |
| Storage | `get_database_files`, `get_database_info`, `get_index_fragmentation`, `get_index_usage_stats`, `get_columnstore_health`, `get_vlf_count` |
| Instance & host | `get_server_info`, `get_machine_spec`, `get_log_paths`, `get_host_dll_versions`, `get_host_event_log` |
| Forensics | `get_deadlock_history`, `get_memory_dumps`, `read_error_log`, `read_sql_dump`, `read_cluster_reports`, `generate_cluster_log` |
| App data & schema | `list_databases`, `list_tables`, `describe_object`, `execute_query`, `list_schema_docs`, `describe_schema`, `describe_doc_object`, `search_schema_docs` |
| Fleet | `list_instances`, `fan_out_query` |
| dbatools | `run_health_check`, `run_diagnostic_query`, `run_dbatools_command`, `list_dbatools_commands`, `get_dbatools_command_help`, `check_dbatools_environment` |

The `dba` profile registers all 55 tools above (32 DMV, 12 PowerShell/dbatools, 11 app-data); the `ops` and `eng`
profiles register only the 11 SELECT-only app-data tools (the *App data & schema* and *Fleet* rows plus
`get_current_primary`). The opt-in `eng-write` profile adds one write tool, `execute_write`, and only when
`ENG_WRITE_ENABLED=1` is also set. `server/tests/profileToolsets.test.ts` pins each list.

`run_health_check` is a 66-check graded report (Availability, Performance, Recoverability, Reliability, Security,
Configuration, Host): findings triaged by consequence, every fix grounded in the node's own rows, and a run that
could not look marked INCOMPLETE rather than reported as healthy. See [HEALTH-CHECK.md](HEALTH-CHECK.md).

## Quick start

```bash
git clone https://github.com/Bugzbaggy/mssql-dba-mcp.git
cd mssql-dba-mcp/server
npm install
npm run build
```

Describe your instances:

```bash
cp ../fleet.example.json ../fleet.json   # gitignored — never commit this
```

```jsonc
[
  {
    "name": "region1-node1",
    "region": "region1",
    "host": "192.0.2.20",
    "port": 1433,
    "user": "${SQL_USER}",
    "password": "${SQL_PASSWORD}",
    "database": "AppCatalog",
    "applicationIntent": "ReadOnly"
  }
]
```

Store the credential in the OS keychain rather than in a file:

```powershell
# Windows
cmdkey /generic:SqlServerFleet /user:svc_readonly /pass
```

```bash
export SQL_CRED_TARGET=SqlServerFleet
```

Register with your MCP client:

```jsonc
{
  "mcpServers": {
    "mssql-dba": {
      "command": "node",
      "args": ["/path/to/mssql-dba-mcp/server/dist/index.js"],
      "env": { "SQL_CRED_TARGET": "SqlServerFleet" }
    }
  }
}
```

## Safety model

| Control | Where |
|---|---|
| Statement inspection rejects non-read statements — the batch is read the way T-SQL's lexer reads it, and the denylist is anchored on the verb | `src/safety.ts` |
| Every result cut at the row cap says so (`RESULT CUT AT n ROWS`) | `src/connectionManager.ts` |
| A sick initial catalog falls back to `master` with a warning on every result, instead of making a healthy node unreachable | `src/connectionManager.ts` |
| Host-derived text (ERRORLOG, events, dumps) is fenced as untrusted data; operating rules are sent at initialize | `src/dbatools.ts`, `src/index.ts` |
| PowerShell-backed tools are refused on the shared HTTP transport (they would run as the server's credential) | `src/dbatools.ts` |
| Credentials resolved from OS store on first use, never logged; "could not read" is not "absent" | `src/credentialStore.ts`, `src/credentialPolicy.ts` |
| A least-privilege diagnostic login (no sysadmin), with a fail-closed verification | [`deploy/`](deploy/), [DEPLOYMENT.md](DEPLOYMENT.md) |
| Read-only intent + connect/request timeouts (`SQL_CONNECT_TIMEOUT_MS`, `SQL_REQUEST_TIMEOUT_MS`) | `src/connectionManager.ts` |
| Optional Entra ID / AAD auth | `src/auth.ts`, [AAD-ENTRA-SETUP.md](AAD-ENTRA-SETUP.md) |

Run the test suite (guards against adversarial SQL, the row cap, credential resolution, the health-check catalog,
grading and remediation text, the generated PowerShell, and each profile's exact tool set):

```bash
npm test
```

## Runbooks

[`runbooks/`](runbooks/) holds investigation methodology written to be loaded
as agent context — how to triage under time pressure, how to tell correlation
from mechanism, and how to write up a finding. Start at
[`runbooks/README.md`](runbooks/README.md).

## Documentation

- [USER-GUIDE.md](USER-GUIDE.md) — day-to-day use
- [DEPLOYMENT.md](DEPLOYMENT.md) — running it for a team
- [HEALTH-CHECK.md](HEALTH-CHECK.md) — the scheduled health report
- [AAD-ENTRA-SETUP.md](AAD-ENTRA-SETUP.md) — Entra ID authentication

> Every host, database, and account name in this repo is a **placeholder**
> (`region1-node1`, `AppCatalog`, `svc_*`, `192.0.2.x`). Substitute your own.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
