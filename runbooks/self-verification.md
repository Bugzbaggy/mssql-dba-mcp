# Self-verification — challenge your own first answer

The first explanation an agent produces is usually the most *available* one, not
the most correct one. It is assembled from whatever was in the last tool result,
and it arrives with unearned confidence because nothing has contradicted it yet.

This runbook is the standing instruction to **attack your own answer before
presenting it**. It is not general caution — it is a specific, cheap set of tests,
every one of which has caught a real wrong answer in a production investigation.

> [`evidence-discipline.md`](evidence-discipline.md) says what counts as evidence.
> This file says what to do with an answer you have already formed.

---

## The rule

Before presenting a cause, a recommendation, or a number, run the gate below
**twice**. If a test fails, say so in the response rather than quietly dropping
it — a retracted hypothesis is a finding, and it stops the next person
re-proposing it.

Two passes, and they must differ in kind. One pass is not enough, because the
second answer inherits the first one's framing:

| Pass | Question | What you do |
|------|----------|-------------|
| **1 — reasoning** | Does the conclusion follow from the evidence? | Run tests 1–10 below against the evidence you already have. |
| **2 — premise** | Is the evidence itself what I think it is? | Attack what Pass 1 took for granted. Re-measure from a **different source**, not the same one re-read. Ask what you'd see if the framing — the user's or your own — were wrong, then go check that. |

Pass 2 is where the answer actually changes. Worked example: a "hundreds of
dumps on one node vs about a dozen on its partner" asymmetry passed Pass 1
cleanly — control group present, units fine, like-for-like. Pass 2 asked *what
is a "dump"?* and found the big number was a **file** count that included
`.log` files. Counted as dump events, and then as crash episodes, the numbers
fell by an order of magnitude and the asymmetry shrank sharply; most of what
remained came from a few burst cascades, on a node that had been **silent for
months** before the incident. The "chronically bad node" framing that Pass 1
preserved was wrong.

A claim that survives both passes ships. A claim that survives only one does
not. Say which evidence changed between the passes.

State the outcome in the response as one of:

- **Measured** — reproduced from a tool call in this session.
- **Inferred** — reasoned, not observed. Say what would confirm it.
- **Withdrawn** — proposed, then falsified. Say by what.

---

## The gate

### 1. Find the control group and run the test

[`evidence-discipline.md`](evidence-discipline.md) requires a control group; this
is the check that you actually ran one. An explanation that does not distinguish
the failing node from a healthy peer is not an explanation.

Ask literally: *if my cause were real, which other server would also be failing?*
Then check that server. If it has the same condition and is healthy, the cause is
**not sufficient** — say so.

> **Caught:** "host memory exhaustion causes the access violations." A peer node
> ran at *higher* memory pressure (less free memory, a higher percentage in use)
> than the crashing node and produced zero dumps over the same months. The cause
> did not survive its own control.

### 2. Check the base rate before blaming what you found running

Anything that runs on a schedule will be present at the time of any incident. Get
its history before calling it a trigger.

```sql
SELECT CAST(StartTime AS date) AS run_date, COUNT(*) AS commands,
       SUM(DATEDIFF(SECOND, StartTime, EndTime)) AS total_secs,
       SUM(CASE WHEN ErrorNumber <> 0 THEN 1 ELSE 0 END) AS errors
FROM DBA.dbo.CommandLog
WHERE DatabaseName = '<db>' AND ObjectName = '<object>'
GROUP BY CAST(StartTime AS date) ORDER BY run_date DESC;
```

> **Caught:** "the weekly statistics job triggered the crash." It had run
> identically for months (same statistics, same window, no errors), the concurrent
> workload that day was *lighter* than prior weeks, the faults were on **different
> spids** than the job's, and they continued hours after it finished.

### 3. Match the session, not just the minute

Co-occurrence in time is not causation. A dump names a **spid**; `get_hiq` names
the session running the suspect work. If they differ, the suspect is a witness.

### 4. Compare like with like

- **Same hours of day.** Load on most OLTP systems is strongly diurnal; a
  daytime-vs-overnight comparison manufactures a result.
- **Same workload size.** Normalise by work done — reads per row, reads per batch
  row — not totals.
- **One comparator for all subjects.** Using an hour-matched window for the
  subject and a full-day window for the controls is comparator shopping.

### 5. Recompute every number

Units are the usual defect: Query Store durations are **microseconds**;
performance-counter values are sometimes **pages**, not KB; `run_duration` in
`sysjobhistory` is **HHMMSS**, not seconds; a `DATE` column silently discards a
time filter. Recompute each ratio and percentage before it ships.

### 6. Distinguish "absent" from "could not look"

A probe that cannot reach a host reports *nothing found*, which reads like a
finding. Treat an empty result as evidence only when you have confirmed the probe
worked.

> **Caught:** `get_host_dll_versions` returned `not-found` for every pattern on
> two nodes — including `ntdll.dll`, which always exists. SMB was blocked. Read
> as a finding, it would have "proved" the EDR agent was not installed. The tool
> probes `ntdll.dll` first for exactly this reason: when it cannot be read, the
> result carries `host_reachable: false` and `Status='unreachable'` on every row.

### 7. Know what a DMV does not cover

- `sys.dm_server_memory_dumps` is **restart-scoped** — it reports zero precisely
  when a crash forced a restart. Enumerate dumps on disk instead
  (`read_sql_dump action='list'`), which survives restarts.
- Query Store bins runtime stats by execution **end** time, so joining a slow
  statement to another statement on `runtime_stats_interval_id` mis-pairs it with
  a later run, and an inner join silently drops the longest executions.
- `QUERY_CAPTURE_MODE = AUTO` makes Query Store a **sample**, not a census — never
  claim an exact execution count or "zero errors" from it.
- Ola job steps can report **success** while skipping a database.

### 8. Check that the mechanism is possible, not just plausible

A story that fits the timeline can still be mechanically impossible.

> **Caught:** "synchronous commit guarantees the secondary has every committed
> transaction." With `required_synchronized_secondaries_to_commit = 0` the primary
> commits alone the moment the secondary leaves the synchronized set. The LSN
> comparison was the real test; the availability mode was not.

### 9. Ask what your recommendation costs if it is wrong

State reversibility explicitly. Irreversible actions (forced failover, repair,
detach, a large reseed) need the measurement *before*, not the confidence.

> **Caught:** a reseed of several hundred gigabytes was recommended for a
> database that came back ONLINE on its own after a SQL service restart.

### 10. Check it against the site's own documented standard

Before recommending a change, read whatever records this estate's deliberate
deviations from generic best practice — a site runbook, a known-quirks list, the
agent's project instructions. If your recommendation contradicts one, that is a
finding either way — **say which**, and resolve it with evidence rather than
silently overriding the documented standard.

---

## When the answer changes

Say it plainly, once, with the evidence that changed it, and move on. Do not bury
a correction, and do not stack apologies on it. A wrong answer that is corrected
quickly costs far less than a wrong answer delivered confidently — and in
practice the corrections are often the most valuable part of the investigation.

See also: [`evidence-discipline.md`](evidence-discipline.md) ·
[`service-restoration-first.md`](service-restoration-first.md) ·
[`investigation-methodology.md`](investigation-methodology.md)
