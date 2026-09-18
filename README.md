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
| Triage | `get_hiq`, `get_active_sessions`, `get_blocking_chains`, `get_wait_stats` |
| Queries | `get_top_queries`, `get_query_store_regressions`, `get_plan_cache_pollution`, `get_missing_indexes` |
| Availability | `get_ag_health`, `get_distributed_ag_health`, `get_current_primary`, `get_backup_status` |
| Resources | `get_memory_usage`, `get_cpu_history`, `get_tempdb_usage`, `get_file_io_stats`, `get_latch_stats` |
| Storage | `get_database_files`, `get_index_fragmentation`, `get_index_usage_stats`, `get_vlf_count` |
| Forensics | `get_deadlock_history`, `get_memory_dumps`, `read_error_log`, `read_sql_dump` |
| Schema | `describe_object`, `describe_schema`, `list_tables`, `search_schema_docs` |
| Fleet | `list_instances`, `fan_out_query`, `run_health_check` |

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
| Statement inspection rejects non-read statements | `src/safety.ts` |
| Credentials resolved from OS store, never logged | `src/credentialStore.ts`, `src/credentialPolicy.ts` |
| Read-only intent + per-tool timeouts | `src/connectionManager.ts` |
| Optional Entra ID / AAD auth | `src/auth.ts`, [AAD-ENTRA-SETUP.md](AAD-ENTRA-SETUP.md) |

Run the credential-policy tests:

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
> (`region1-node1`, `AppCatalog`, `svc_*`, `10.0.x.x`). Substitute your own.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
