# Runbooks

Investigation methodology for SQL Server incidents, written to be read by a
human or loaded as context by an AI agent driving the MCP server.

These are deliberately **method** rather than **recipe**. They describe how to
form and test a hypothesis under time pressure, not which button to press on
one particular fleet.

## Where to start

```
Production is DOWN (a database SUSPECT / OFFLINE, the app cannot connect)?
└── service-restoration-first.md   restore first: the four-check failover gate

Something is broken and you don't know what?
└── diagnostic-patterns.md        symptom → likely cause → the tool that confirms it

You know the symptom class?
├── Slow queries / plan regressions      → performance-investigation.md
├── Blocking chains / deadlocks          → blocking-and-deadlocks.md
└── Memory pressure / low PLE            → memory-pressure.md

Working out whether your hypothesis is good enough?
├── evidence-discipline.md
└── self-verification.md          attack your own answer, twice, before presenting it

Ready to write it up or escalate?
└── writing-findings-and-escalation.md
```

## Index

### Methodology — how to investigate

| Runbook | What it teaches |
|---|---|
| [`service-restoration-first.md`](service-restoration-first.md) | **Production is down.** Read before any other runbook: restore → preserve evidence → diagnose, the four-check failover gate on the secondary, what moves with the whole AG, cheap evidence preservation, and what is never a first move. |
| [`self-verification.md`](self-verification.md) | The gate for attacking your own conclusion before you present it — two passes that differ in kind (is the reasoning sound? is the premise sound?), and labelling each claim Measured / Inferred / Withdrawn. |
| [`investigation-methodology.md`](investigation-methodology.md) | The meta-skill: time-pressure tiers (Critical / High / Standard / Forensic), choosing the first tool, hypothesis economics, smallest-fix-first, the "what would prove me wrong" check, validating that a fix actually worked, and when to escalate. |
| [`evidence-discipline.md`](evidence-discipline.md) | Hypothesis-testing rigor: distinguishing presence from cause, base-rate bias, and the three-sentence bar (Mechanism / Differential / Reversibility) a recommendation must clear before it stops being hygiene and becomes a fix. |
| [`writing-findings-and-escalation.md`](writing-findings-and-escalation.md) | Communication: the running findings template, the findings report, the postmortem, and what evidence to bring to each escalation path. |

### Per-symptom playbooks

| Runbook | When to use |
|---|---|
| [`diagnostic-patterns.md`](diagnostic-patterns.md) | Pattern cookbook — symptom to most-likely cause, with the specific tool that confirms or denies it. Read this first when triaging something unfamiliar. |
| [`performance-investigation.md`](performance-investigation.md) | Slow queries, plan regressions, "the server feels slow." Branches on one-query vs. whole-server, and includes the wait-stat snapshot diff. |
| [`blocking-and-deadlocks.md`](blocking-and-deadlocks.md) | Blocking chains, `THREADPOOL` exhaustion, deadlock graphs, RCSI trade-offs, and the kill / wait / escalate decision. |
| [`memory-pressure.md`](memory-pressure.md) | High memory load, falling page life expectancy, `RESOURCE_SEMAPHORE` waits, and plan-cache pollution from ad-hoc SQL. |

## A note on what is *not* here

The original private version of this set included fleet-specific runbooks —
the local quirks, topology, and migration state that override generic best
practice in one particular environment. Those are omitted here because they
described real infrastructure.

If you adopt these runbooks, that gap is the one worth filling yourself: a
`known-quirks.md` capturing the constraints that make *your* environment
different from the textbook is usually the highest-value document in the set.

## How to extend

When an investigation produces a generalizable lesson:

1. Decide whether it is **method** (goes in a methodology runbook) or
   **symptom** (goes in a playbook).
2. State the mechanism, not just the correlation — see
   [`evidence-discipline.md`](evidence-discipline.md).
3. Keep environment-specific values out. Use placeholders.
