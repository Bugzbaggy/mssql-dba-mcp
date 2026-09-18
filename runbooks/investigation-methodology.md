# Runbook — Investigation methodology

This is the *meta-skill* — how to investigate, not what to look at. The other runbooks tell you what tools to use for specific symptoms. This one tells you how to think while you're using them, how to know when you're done, and how to choose between investigating further or shipping a fix now.

It builds on [`evidence-discipline.md`](evidence-discipline.md), which is about hypothesis-testing rigor. This one is about the broader flow.

---

## 1. The five-question opener

Before running any tool, get these five answers from the user (or from the MCP in one round). They determine everything downstream:

1. **What's the symptom in their words?** Quote it back. "Queries are slow" vs. "this one query is slow" vs. "the server is unresponsive" route very differently.
2. **When did it start?** A specific timestamp turns vague "wait analysis" into bounded "between 14:00 and 14:20" filtering. Without this, every diagnostic returns months of noise.
3. **Which instance(s)?** `list_instances` + the user's answer. Don't fan-out across 12 instances by default; pick the affected ones plus a control peer.
4. **What changed recently?** Patches, deployments, schema changes, config changes, scheduled job changes, agent upgrades, certificate rotations, DNS changes. The closer this is in time to "when did it start," the more weight it carries.
5. **What's the business impact right now?** "Customer-facing degradation" routes to a different decision tree than "noisy alert on a dev box." Time pressure changes what counts as enough evidence.

If the user can't answer "when did it start," that's the first thing to recover — usually from ERRORLOG (`xp_readerrorlog`), the metrics platform/PagerDuty timestamps, or `get_cpu_history`.

---

## 2. Time-pressure tiers (when to stop investigating and act)

Match the depth of investigation to the urgency:

| Tier | Time budget | What you do |
|---|---|---|
| **Critical — customer impact now** | Minutes | Skip exhaustive analysis. Take the **smallest reversible action** that is most likely to mitigate (failover off a sick node, kill a runaway spid, rollback the last deploy). Investigate root cause after stabilization. Document the rollback so the next responder can repeat. |
| **High — degradation, not outage** | 30 min – 2 hrs | Single-hypothesis investigation. Form a hypothesis from the fastest signal (`get_blocking_chains`, `get_wait_stats` filtered to the window, `get_active_sessions`), validate via control-group, apply mitigation. Save broader analysis for after. |
| **Standard — ongoing issue or recurring incident** | Hours – days | Full investigation per the relevant runbook. Build the comparison-with-control. Demote weak hypotheses explicitly. Write findings. |
| **Forensic — past incident, no current impact** | Whatever it takes | Dumps, ERRORLOG, query store regressions, Extended Events history. Goal is the *correct* answer, not the *fast* answer. |

**Common failure mode:** treating a Standard issue with Critical urgency (acting without evidence) or a Critical issue with Standard rigor (running the full investigation while the database is down). Match the tier.

The 2026 EDR-related investigation was treated as Standard for 11 weeks when it should have been High after the first storm — the cost was three more storms and one AG failover. Don't let an issue downgrade just because it's chronic.

---

## 3. Choosing the first tool to call

A common mistake is to start with `run_health_check` (the 39-check dbatools sweep) for every symptom. The health check is excellent for **unfamiliar instances** and **weekly review**, but it's noisy for targeted investigation. For a specific symptom, the right first tool is the **narrowest one that will confirm or deny the most likely hypothesis**.

| Symptom shape | First tool — *not* `run_health_check` |
|---|---|
| "Queries are blocked right now" | `get_blocking_chains` |
| "Wait stats are weird" | `get_wait_stats` **filtered to the incident window** (raw waits since startup are noise) |
| "This server feels slow" | `get_cpu_history` first, then route based on whether CPU is the bottleneck |
| "TempDB is hot" | `get_latch_stats` (look for PAGELATCH on `2:1:*` pages) + `get_tempdb_usage` |
| "Plans regressed after deploy" | `get_query_store_regressions` |
| "AG sent us an alert" | `get_ag_health` |

Run `run_health_check` when you don't know the symptom — when the user says "is this server healthy?" rather than "this specific thing is broken."

---

## 4. The "tell me what I know" pattern

Before recommending anything, list what's verified vs inferred. Format:

> **Verified (from tool calls in this session):**
> - SQL build `16.0.4250.1` on `region4-node2`, OS Build `26100`, uptime 38h (`get_server_info`)
> - `ctiuser.dll` not in `sys.dm_os_loaded_modules` after restart (`execute_query`)
> - No `EXCEPTION_ACCESS_VIOLATION` entries in last 24h ERRORLOG (`xp_readerrorlog`)
>
> **Inferred / not verified:**
> - The bypass policy actually rolled out — I haven't confirmed this from the EDR agent's side.
> - The 14-day validation window is intact — assumes no other restarts happened.

This forces honesty and exposes gaps. If "inferred" is doing too much work, run another tool call before recommending.

---

## 5. Hypothesis economics: pick what's cheap to test

When you have multiple hypotheses, test the cheapest-to-disprove one first, not the most exotic. A 30-second SELECT against a control instance beats a 4-hour memory dump analysis.

| Hypothesis | Cost to disprove |
|---|---|
| "It's a config X difference" | One `fan_out_query` against control. **~30 seconds.** |
| "It's a recent deploy" | Check `sys.dm_db_index_usage_stats` first-access timestamps + git log. **~5 minutes.** |
| "It's a workload pattern change" | `get_top_queries` for current vs prior window. **~10 minutes.** |
| "It's a SQL Server engine bug" | Stack from dump + Microsoft KB search. **~30 minutes – hours.** |
| "It's a memory leak somewhere" | Trend `physical_memory_in_use_kb` over hours/days. **~hours – days.** |
| "It's hardware degradation" | AWS Health Dashboard / GCP Cloud Monitoring + IO latency over weeks. **~days.** |

Start at the top. Most production issues are config drift, recent deploys, or workload changes — the cheap hypotheses. The exotic ones (engine bugs, hardware) are rare and shouldn't be your first guess unless the cheap ones are explicitly ruled out.

---

## 6. The "what would prove me wrong" check

For each active hypothesis, write down what observation would falsify it. If you can't name a falsifier, the hypothesis is too vague — sharpen it.

Examples:

| Hypothesis | Falsifier |
|---|---|
| "the EDR agent is causing the crashes" | An identical sensor version is loaded on a non-crashing peer in the same fleet under similar workload. → If found, hypothesis is wrong. |
| "Index `IX_X` is missing causes the regression" | The slow query's actual plan doesn't show a scan against the column the missing index targets. → If shown, hypothesis is wrong. |
| "TempDB allocation contention" | Latch waits in the incident window are *not* on `2:1:*` GAM/SGAM/PFS pages. → If confirmed, hypothesis is wrong. |
| "Network latency to the AG secondary" | Log-send rate in `get_ag_health` is normal and HADR_SYNC_COMMIT waits aren't elevated. → If shown, hypothesis is wrong. |

Putting falsifiers in writing makes you (or the user) check them before recommending. It's the single highest-leverage discipline in this entire methodology.

---

## 7. The smallest-fix-first principle

When multiple fixes are plausible, prefer the most reversible one. The cost ordering, easiest to hardest to reverse:

1. **Session-level fix** — kill a spid, change `SET` options for a session. Reverses on next reconnect.
2. **Database-scoped config** — `ALTER DATABASE SCOPED CONFIGURATION SET X = Y`. Per-DB, easily reversed.
3. **Instance-level config via `sp_configure`** — RECONFIGURE'd. Reversible, may need restart.
4. **Service restart** — drops all sessions, ~30 seconds of unavailability per host (covered by AG failover).
5. **AG failover** — reroutes traffic; mostly transparent but observable to clients.
6. **Schema change** — adding/dropping indexes, statistics changes. May require migration coordination.
7. **Application config change** — connection string, retry policy. Coordination with app team.
8. **OS / driver / EDR change** — multi-team, reboot, change windows.
9. **Hardware / instance type change** — provider tickets, downtime.

If a level-3 fix works, you don't need level-7. If a level-5 fix works during a critical incident, you don't need to spend a week getting the level-8 fix scheduled. Match the fix tier to the urgency tier (§2).

---

## 8. Validating that a fix worked

The fix isn't done when the change is applied — it's done when you've **observed the symptom not recur** for a window matched to the historical cadence.

Validation patterns by symptom class:

| Symptom class | What "validated" looks like |
|---|---|
| Crash / fatal exception | No new dumps for a window ≥ longest historical inter-crash interval. For a 2026 EDR-related case, that was 14 days. |
| Blocking storm | `get_blocking_chains` returns empty for >1 normal business cycle (typically a workday). |
| Wait pattern | Top-N waits in `get_wait_stats` filtered to the post-fix window match historical baseline, not the incident shape. |
| Memory pressure | `sys.dm_os_process_memory.memory_utilization_percentage` stable over multiple peak windows. |
| Query regression | The specific query's `last_elapsed_time` / `last_logical_reads` in `sys.dm_exec_query_stats` matches pre-regression baseline. |
| AG sync issue | `get_ag_health` shows synchronization_health = HEALTHY for the lag window we care about (typically <10s redo). |
| Backup failure | The next scheduled full + log backups land successfully (`get_backup_status`). |

The validation window must be at least as long as the **slowest path to recur** the symptom in your environment. If a problem manifests weekly, "stable for 2 hours" doesn't validate.

**Live-process verification** when the fix involves anything injected into `sqlservr.exe` (EDR, ODBC drivers, CLR assemblies): `sys.dm_os_loaded_modules` `base_address` after restart should differ from before, and `file_version` should match the new version. See `sql-crash-investigation.md` §C.

---

## 9. When to escalate vs continue solo

Escalate to another team if **any** of the following is true:

- **Security/EDR involvement** — anything touching the EDR agent, antivirus exclusions, certificates, network policies → SecOps.
- **OS-level changes** — driver upgrades, kernel patches, Windows servicing channels → Platform team.
- **Vendor bug suspected** — if the crash stack is in `sqlmin.dll` / `sqllang.dll` / `qds.dll` and reproduces across CUs → Microsoft via AWS support (for AWS-licensed) or direct Microsoft case (for BYOL).
- **Cross-region change required** — AG topology, distributed AG reseed, listener changes → DBA team + Application owners.
- **Application logic involved** — connection string, ORM behavior, retry policy → engineering owners of the calling service.
- **The investigation has run >1 day without progress** — fresh eyes. Write what you have so far (see §10) and hand off.

Continue solo if it's a single-instance, DBA-scoped, known-class-of-problem with cheap-to-test hypotheses still available.

---

## 10. Writing findings as you go

Even mid-investigation, keep a running summary that any peer (or the next agent) could read cold and pick up. Minimum structure:

```
Symptom: <one line, in user's words>
Started: <timestamp UTC>
Scope: <instances affected>
Verified so far:
  - <fact 1 with tool call that proved it>
  - <fact 2 with tool call that proved it>
Hypotheses (active):
  - <hypothesis 1> — falsifier: <X>; status: <untested|disproved|supported>
  - <hypothesis 2> — falsifier: <Y>; status: ...
Demoted (and why):
  - <hypothesis> — disproved because <observation against control>
Next step: <single concrete action>
```

This is the artifact you'd hand off if escalating, or the seed of the postmortem if it becomes one. See [`writing-findings-and-escalation.md`](writing-findings-and-escalation.md) for the full template.

---

## 11. Recognizing when you're stuck

You're stuck if **any** of these is true:

- You've run the same diagnostic twice with no change in plan.
- You're recommending something you can't fill in the 3-sentence bar for (see [`evidence-discipline.md`](evidence-discipline.md)).
- You're proposing exotic causes (engine bugs, hardware faults) before testing config drift, recent deploys, and workload changes.
- The user is asking the same clarifying question for the third time.
- You haven't run a control-group comparison yet, and the symptom isn't a one-instance thing.

When stuck: run `fan_out_query` of A1 from `sql-crash-investigation.md` (or the equivalent for your symptom class) against affected + control. If still stuck after the comparison, escalate per §9 with the running findings doc from §10.

---

## 12. After the incident — capture the lesson

If an investigation produced a generalizable lesson, add it to the right runbook **in the same PR as the fix**. Specifically:

- A new fleet quirk → `known-fleet-quirks.md`
- A new diagnostic pattern (symptom → hypothesis) → [`diagnostic-patterns.md`](diagnostic-patterns.md)
- A new symptom class with no existing runbook → new file under `runbooks/`, indexed in [`README.md`](README.md)
- An incident-specific case → append to "Cases" in the matching runbook

The repo accumulates intelligence over time only if this discipline is observed. The 2026 EDR-related investigation produced lessons across all four categories above; updating the repo is what makes the *next* investigation faster.
