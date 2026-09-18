# dbatools/DMV parity harness

## What this proves

Task 5 onward moves MCP tools off hand-written DMV queries and onto dbatools
cmdlets, one tool at a time. The danger in that migration is not a tool that
breaks loudly — that gets noticed immediately. It is a column that got
renamed, or a unit that quietly changed (seconds vs. milliseconds, MB vs.
pages), so the agent consuming the tool keeps working but silently reasons
over different data.

This harness is the check that catches that. For each migrated tool it runs
the new dbatools cmdlet (via `callDbatools`, the same guarded entry point the
server itself uses) and the old DMV query side by side, then asserts that the
**named key fields are present, with matching values** on the dbatools result.

"Parity" here means *same key fields, same values* — it does **not** mean
identical shapes. The dbatools result is allowed to carry extra columns, a
different row order, or a different property casing; only the fields listed
in a case's `keyFields` are checked. That is deliberate: dbatools output
shapes are wider than the DMV projections they replace, and asserting full
shape equality would make the harness brittle without making it any more
honest.

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

`--instance` defaults to `local`. Point it at whatever instance name your
`connectionManager` config resolves — for example, the demo stack:

```bash
node --import tsx tests/parity/run-parity.mjs --instance local
```

Exit code is `0` when every registered case matches, `1` if any case fails
**or if no cases are registered at all**. Output is one line per case:

```
ok   get_backup_status: Get-DbaLastBackup (12 row(s), fields present)
FAIL get_backup_status: Get-DbaLastBackup is missing field(s): LastFull
```

## The empty-case guard

`CASES` starts empty (Task 5 fills it in as each tool is migrated). Running
the harness with `CASES` empty must **fail**, not silently pass:

```
::error::no parity cases registered - this harness proves nothing
```
exit code `1`.

This is not a hypothetical concern: a test suite that reported success while
the code under test had been deleted has already shipped once on this
project. A harness with zero cases is the same failure mode wearing a
different hat, so it is guarded against explicitly rather than left to an
empty loop that would exit 0 by default.

## Adding a case

When Task 5 (or any later migration) moves a tool onto a dbatools cmdlet, it
**must** add a corresponding entry to the `CASES` array in the same PR:

```js
{ tool: "get_backup_status", cmdlet: "Get-DbaLastBackup", params: {}, dmvSql: "...", keyFields: ["Database", "LastFull"] }
```

- `tool` — the MCP tool name being migrated.
- `cmdlet` — the dbatools cmdlet name, passed straight to `callDbatools`.
- `params` — extra params merged into the `{ SqlInstance, ...params }` call.
- `dmvSql` — the DMV query the cmdlet is replacing, kept alongside the case
  for a human to diff against when a case fails.
- `keyFields` — the field names that must be present (and, when verifying by
  hand, must match) on the first returned row.

A migrated tool with no parity case is not considered migrated — the case is
what proves the harness (and future readers of it) that the swap was faithful.
