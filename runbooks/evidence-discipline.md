# Runbook — Evidence discipline

This runbook is about *how to know* you're right before you recommend a change, in this fleet. It's the most-violated principle in our crash and performance investigations. The rules below are not abstract — every one of them comes from a specific instance where it was broken and cost time.

## The rule

> Before you recommend any change as a **fix** (not as hygiene), you must be able to fill in three sentences:
>
> 1. **Mechanism.** "X causes the observed failure because *<concrete chain of events>*."
> 2. **Control-group differential.** "X is present (or different) on the failing servers and not on *<named non-failing peer>*."
> 3. **Reversibility.** "If this is wrong, recovery is *<short / service restart / fail-back / data-bearing>*."
>
> If sentence (1) or (2) can't be filled in honestly, the recommendation is **hygiene**, not a fix. Label it that way so the user can prioritize accordingly.

## Common ways evidence goes wrong here

### Confusing presence with cause
A DLL in `sys.dm_os_loaded_modules` is **loaded** — it isn't necessarily implicated. The dump's exception address tells you which module's code raised the AV; everything else in the module list is inventory. The instinct to chase the most exotic-looking DLL ("what is `ctiuser.dll`?") is sometimes correct but is never *evidence by itself*.

**How to test:** run the same `sys.dm_os_loaded_modules` query on a server that isn't crashing. If the suspicious DLL is on both, it isn't the differentiator.

### Base-rate bias in the input buffer
Queries that run every N seconds (sp_WhoIsActive, DMV-polling monitors, heartbeat checks) will appear in the input buffer at crash time *by base rate alone* — the more often something runs, the more likely it's running when a crash happens. This is not evidence of causation.

**How to test:** ask whether the same query appears in the input buffer on the non-crashing peer's normal session sample. If yes, base-rate. Demand a mechanism (e.g. heap-allocating UDFs, large memory grants, plan-cache pollution) before treating a frequent query as suspect.

### "Memory pressure causes crashes" without LPM awareness
With Lock Pages in Memory enabled (it is, on all four production AG primaries), the buffer pool is pinned and cannot grow or shrink. So a high `MemoryLoad` figure does not mean the buffer pool is fighting for memory — it means the **non-BPool region** of `sqlservr.exe` plus the OS is squeezed. Lowering `max server memory` does not help; it just shrinks the locked pool further.

**How to test:** check `sys.dm_os_process_memory.locked_page_allocations_kb` vs `physical_memory_in_use_kb`. If `locked = max server memory` and the process is committing significantly more than locked, the growth is non-BPool. Identify the consumer via `sys.dm_os_memory_clerks` excluding `MEMORYCLERK_SQLBUFFERPOOL`.

### "Hygiene fix worked therefore was the cause" (post hoc)
Page file separation, disabling auto-shrink, raising `cost threshold for parallelism`, adding a missing index — all good hygiene, none of which fix engine crashes. If you apply a hygiene change at the same time as the actual fix, you can't attribute the result. Apply changes one at a time when an investigation is active.

**How to test:** can a non-crashing peer have the "wrong" hygiene config and still not crash? If yes, the hygiene config isn't causal.

### Patching SQL Server as a mitigation
Two CU upgrades did not stop a 2026 EDR-related crashes. A CU upgrade is hygiene plus a forced service restart. The restart itself is sometimes the actual fix (e.g. drops an in-memory DLL mapping), not the new SQL bits. Don't conflate the two.

**How to test:** if the prior CU also had a clean fleet, the CU change isn't the fix. If a non-patched fleet member is also stable, the CU change isn't the fix.

---

## The fan-out comparison, applied

In practice, the discipline collapses to one repeated move:

> Whatever query, DMV reading, or sensor reading you're about to use to make a claim about a problem server, **run it via `fan_out_query` across the problem servers and at least one non-problem peer first**. If the values are the same, that thing isn't the differentiator; move on.

For the messaging fleet, **`region1-node2`** has historically been the most useful control instance for messaging-DB issues because it runs the same workload, the same linked-server providers, the same EDR sensor, and the same dbatools-recommended memory configuration — but on the older Windows Server 2022 (Build 20348) rather than 26100. If a hypothesis explains the WS2025 hosts crashing but doesn't predict `region1-node2`'s stability, the hypothesis is incomplete.

## Demote-to-hygiene examples (from real investigations)

| Originally proposed as | Demoted to | Why |
|---|---|---|
| "Set `MSDASQL AllowInProcess=0` to stop the crashes" | Not even hygiene — actively wrong | `region1-node2` has identical third-party ODBC in-process and doesn't crash. Also breaks the cloud data warehouse linked servers. |
| "Lower `max server memory`" | Not applicable | Already tuned per dbatools recommendation on every server. |
| "Separate page file from tempdb drive" | Hygiene (worth doing for I/O contention) | Every fleet member has the same layout; only WS2025 hosts crash. |
| "Pause `dbo.CaptureWhoIsActive` Agent job" | Withdrawn | Read-only DMV query; no plausible heap-corruption mechanism; pausing it removes diagnostic data. |
| "Align all four to the latest CU" | Hygiene | Two hosts crashed *after* the CU24-GDR upgrade. CU mismatch is bad for HADR catalog reasons but isn't the crash cause. |
| "the EDR agent process bypass on `sqlservr.exe`" | **Fix** (cleared all three sentences) | Mechanism: removes the heap hooks. Differential: not present on `region1-node2` since it doesn't crash to begin with. Reversibility: short — restore the policy if it breaks something else. |

## How to handle ambiguity in a response

If you don't yet have a control-group reading, **say so explicitly** before recommending a change. Format:

> "I haven't yet confirmed against a non-crashing peer. Best current hypothesis is *X*. Before I recommend changes, I want to fan-out *Q* across *[problem servers] + region1-node2*. Run that and I'll have a fix or a demotion to hygiene."

This is more useful than guessing. The fleet is small enough (12 instances) that the comparison query is cheap.

## Related

- `../CLAUDE.md` §1 — the core principles that this runbook expands on.
- `sql-crash-investigation.md` — the canonical case where five hypotheses were demoted before the right one was identified.
- `known-fleet-quirks.md` — the specific things that forbid otherwise-reasonable recommendations.
