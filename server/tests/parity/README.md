# dbatools field-presence harness

## What this checks

Several MCP tools were moved off hand-written DMV queries and onto dbatools
cmdlets. The danger in that kind of move is not a tool that breaks loudly —
that gets noticed immediately. It is a field that got renamed between dbatools
versions, so the agent consuming the tool keeps working but silently reasons
over a missing column.

For each case, `run-parity.mjs` calls the dbatools **cmdlet** directly (via
`callDbatools`, the same guarded entry point the server itself uses) against a
live instance and asserts that at least one row came back and that the first
row carries every field named in the case's `keyFields`.

That is the whole check, despite the directory name. It does **not**:

- run the DMV query the tool used to use, so it says nothing about whether the
  two paths agree, on values or on which rows exist;
- check field **values** — a field that is always null still passes;
- call the tool handler in `src/tools.ts`, so a bug in a tool's own filtering,
  mapping or `withFallback` wiring is invisible to it;
- read `DBATOOLS_FIRST` — every case always exercises the cmdlet.

The dbatools result may carry extra columns or a different row order; only the
fields in `keyFields` are checked. The header comment of `run-parity.mjs` says
the same, and is the authority if the two ever differ.

## Why it needs a live instance, and why `npm test` does not run it

Every case calls a real SQL Server instance through `callDbatools`, which
spawns the supervised `pwsh` worker and runs an actual dbatools cmdlet. There
is nothing to compare without a database to query.

`npm test` runs `tests/*.test.ts` only. This harness lives at
`tests/parity/run-parity.mjs` — a `.mjs` file, not a `.test.ts` file — so it
is **not** picked up by that glob and does **not** run in CI. This is
intentional, not an oversight: it needs a live database, and CI does not
provision one. Do not assume a green `npm test` run means the parity harness
passed, or even ran.

## How to run it

The harness imports TypeScript (`callDbatools` from `../../src/dbatools.ts`)
directly, so it must be run under `tsx`. A bare `node` invocation fails on
that import.

```bash
node --import tsx tests/parity/run-parity.mjs --instance <name>
```

`--instance` defaults to `local`. Its value is passed **unchanged** as the
cmdlet's `-SqlInstance` — it is a SQL Server address dbatools understands
(`host`, `host,port`, `host\instance`), not a fleet `name` from `fleet.json`.
Run it from `server/`; the pwsh worker authenticates with `SQL_USER` /
`SQL_PASSWORD` from the environment, or with Windows authentication when they
are unset:

```bash
node --import tsx tests/parity/run-parity.mjs --instance localhost,1433
```

Exit code is `0` when every registered case returns its expected fields, `1` if
any case fails **or if no cases are registered at all**. Output is one line per
case, then a summary line:

```
ok   get_backup_status: Get-DbaLastBackup (12 row(s), expected fields present by NAME — values/DMV-parity/tool-handler/DBATOOLS_FIRST not checked)
FAIL get_backup_status: Get-DbaLastBackup is missing field(s): LastFullBackup
FAIL get_tempdb_usage: Get-DbaTempdbUsage returned no rows
```

A case that returns no rows fails. Some cmdlets legitimately return nothing on
an idle instance (`Get-DbaTempdbUsage` needs active tempdb allocations,
`Get-DbaDbccStatistic` needs user statistics) — create that activity and re-run
rather than weakening the case.

## The empty-case guard

`CASES` holds one entry per migrated tool. Running the harness with `CASES`
empty must **fail**, not silently pass:

```
::error::no field-presence cases registered - this harness proves nothing
```
exit code `1`.

This is not a hypothetical concern: a test suite that reported success while
the code under test had been deleted has already shipped once on this
project. A harness with zero cases is the same failure mode wearing a
different hat, so it is guarded against explicitly rather than left to an
empty loop that would exit 0 by default.

## Adding a case

When a change moves a tool onto a dbatools cmdlet, it **must** add a
corresponding entry to the `CASES` array in the same pull request:

```js
{ tool: "get_backup_status", cmdlet: "Get-DbaLastBackup", params: {}, keyFields: ["Database", "LastFullBackup", "LastDiffBackup", "LastLogBackup"] }
```

- `tool` — the MCP tool name being migrated.
- `cmdlet` — the dbatools cmdlet name, passed straight to `callDbatools`.
- `params` — extra params merged into the `{ SqlInstance, ...params }` call
  (a cmdlet that takes `-ComputerName` instead sets `SqlInstance: undefined`).
- `keyFields` — the field names that must be present on the first returned
  row. Use the property names the cmdlet really emits, verified against a live
  instance — not the column names of the DMV query it replaces.

A migrated tool with no case is not considered migrated: the case is what
catches a dbatools field rename before the agent silently loses the field.
