# Runbook — Writing findings & escalation

Investigations have to **end somewhere** — in a recommendation, a postmortem, an escalation, or a hand-off. This runbook is about how to write that artifact so it's actually useful, and how to choose the right escalation path when the issue is outside the DBA team's scope.

It builds on [`investigation-methodology.md`](investigation-methodology.md) §10 (the running summary you keep while investigating) and §9 (when to escalate).

---

## 1. The running findings template (use this during the investigation)

A live document — updated as new tool calls produce facts. Format:

```
INCIDENT: <one-line description in user's words>
STARTED: <UTC timestamp, or "first detected at <X>; symptom may have started earlier">
SCOPE: <instances affected, e.g. "region3-node1, region3-node2; region1-node2 is the control">
URGENCY TIER: <Critical / High / Standard / Forensic — see methodology §2>

VERIFIED FACTS
  - <Fact 1> [tool: get_server_info; ran 14:02]
  - <Fact 2> [tool: fan_out_query / sys.dm_os_loaded_modules; ran 14:08]
  - <Fact 3> [external: AWS support response, ticket #12345]

CURRENT HYPOTHESES
  H1: <hypothesis>
      falsifier: <what would prove this wrong>
      status: <untested | supported by X | falsified by Y>
  H2: ...

DEMOTED HYPOTHESES
  - <hypothesis> — disproved because <observation>

DECISIONS TAKEN
  - 14:15 UTC: Applied <change> on <host>. Rationale: <one line>. Rollback: <plan>.
  - 14:42 UTC: ...

OPEN QUESTIONS
  - <something we still need but don't have>

NEXT STEP (single concrete action)
  - <what the next person should do>
```

This is the *only* artifact that should exist by default. The other documents below are derived from this.

**Why this format.** It's hand-off ready. Any team member or agent can read it cold and pick up. It separates what you *know* from what you *believe*. It captures decisions with timestamps and rationale (useful for the postmortem). And it has a single "next step" so handoffs don't lose momentum.

---

## 2. The findings report (when the investigation is done)

Write this when the incident is resolved or the investigation produced an actionable conclusion. Audience: whoever owns the system (DBA lead, app team, SecOps) plus any leadership stakeholders. Length: one page.

```markdown
# Findings — <one-line title>

**Date:** <YYYY-MM-DD>  **Author:** <name>  **Status:** <Resolved | Mitigated | Root cause identified, fix in flight>

## Symptom
<2–3 sentences: what the user / customer experienced, when it started, scope>

## Root cause
<2–4 sentences: what specifically caused it. Cite the evidence that proves it (which tool, which observation).>

## Resolution
<Action(s) taken or planned. Include rollback paths.>

## Why this took the time it did
<Honest assessment: what hypotheses were tested and discarded; what would have shortened diagnosis if known earlier.>

## Follow-ups
- [ ] <task> — owner: <person>, target: <date>
- [ ] ...

## Evidence appendix
- <Tool output excerpt 1, with timestamp>
- <Tool output excerpt 2>
- <Vendor case / Microsoft KB / etc.>
```

**Tone.** Direct, not defensive. "We tested X. X turned out to be wrong because Y. The actual cause is Z." Investigations have wrong turns — documenting them is the value, not the embarrassment.

A findings report from a long-running engine-crash investigation is the canonical example of this format applied: symptom timeline, the differential that isolated the cause, the mechanism, and the reversibility of the proposed fix.

---

## 3. The postmortem (when the incident had user impact)

Postmortems are a heavier artifact than findings reports. Write one when:
- Customer-facing impact occurred (downtime, degradation visible to external users).
- A SEV-2 or higher was opened.
- The incident class is likely to recur.
- Leadership has asked for a write-up.

Use the team's standard postmortem template (in Confluence). The 13 sections in the AppDb template:

1. Leadup
2. Fault
3. Impact (include support case count, revenue impact if known)
4. Detection
5. Response
6. Recovery
7. Timeline (UTC)
8. Five whys (drive past the technical cause to the structural one)
9. Blameless root cause
10. Backlog check (was the prevention item already a known issue?)
11. Related incidents
12. Lessons learned
13. Follow-up tasks (with JIRA IDs, owners, dates)

A postmortem for a recurring engine-crash incident is the canonical example: impact window, contributing factors, what was ruled out and why, and the follow-up actions with owners.

**Key rules:**
- Postmortems are blameless. Name systems and decisions, not individuals. ("The OS-upgrade runbook lacked an EDR compatibility gate," not "Person X forgot to update the runbook.")
- Five whys drives to the *structural* cause. Stopping at the technical root cause misses the prevention opportunity. ("Why did the EDR break SQL?" → ... → "Why didn't we catch it?" → "Because we don't validate third-party agents on new OS builds.")
- Follow-ups are JIRA-tracked with owners and dates. Postmortem items without those tend to never happen.

---

## 4. Escalation paths

When to engage which team. Listed alongside what *evidence* they'll need from you to act.

### SecOps
**Engage when:** EDR (the EDR agent) behavior, antivirus exclusions, network policy changes, certificate rotations, AD-managed identity changes.

**Bring:** Specific DLL name and version, host names, what the SQL ERRORLOG / dump shows, whether the issue reproduces with the EDR bypass applied. SecOps cannot help with "SQL is slow"; they can help with "<edr-driver>.dll v<version> is causing heap corruption on Build <os-build>; here's the dump signature."

### Platform team
**Engage when:** OS-level changes, driver updates, Windows servicing channel decisions, instance-type changes, OS upgrade pipeline issues.

**Bring:** OS build numbers, the specific change you need, the workload's compatibility requirements. For "We need WS2025 hosts to run sensor 4.1+", give them the JIRA ticket with the sensor compatibility evidence.

### Microsoft / Broadcom / vendor
**Engage when:** Crash stack inside vendor code; an engine bug suspected; reproducible failure with no workaround.

**Bring:** Crash dumps (full memory dump preferred — set `SQLDUMPER_FULL_DUMP=1` before next repro), SQL build numbers, OS build numbers, narrow reproduction steps if available, the question you want answered (not "fix this for us" but "is build X validated against OS Y?").

For SQL Server engine bugs on AWS-licensed instances, escalation flows through AWS Enterprise Support. That adds multi-day latency — plan for it.

### Application teams
**Engage when:** Query coming from their service is misbehaving; deploy regressed plans; connection pooling looks misconfigured; deadlock pattern needs ordering changes.

**Bring:** Query text, host_name, login_name, program_name (all available from `get_active_sessions`), what the query is doing wrong, what a fix shape would look like. Application teams can act fast on specific evidence ("this endpoint generates a 60-second query because of an N+1 pattern") and slowly on vague reports ("queries from your service are slow sometimes").

### Cluster / Infrastructure
**Engage when:** Cluster quorum issues, network partitions, hardware faults, AG topology changes.

**Bring:** Cluster log excerpts, the time range of the issue, what the cluster events show (`Get-ClusterLog`).

---

## 5. Hand-off pattern

If you have to hand off mid-investigation (shift change, escalation), the running findings doc from §1 is the artifact. Plus a 60-second verbal/Slack briefing:

```
Symptom: <one line>
What I've confirmed: <3 bullets>
Best current hypothesis: <one sentence>
What I haven't been able to test: <one bullet>
Next action: <single action>
Where the findings live: <link>
```

The receiving person should be able to take the next action without asking you any questions. If they need to ask questions, the running findings doc isn't complete enough.

---

## 6. The "we don't know yet" response

When the user asks for a recommendation and the evidence isn't there, the right response is to say so. Format:

> Best current read: <hypothesis>, but I haven't run the comparison against <peer> yet — that takes ~5 minutes via `fan_out_query`. Do you want me to run that before I commit to a fix, or do you have a different time pressure?

This is more useful than guessing. The user can choose:
- "Run it" — you do the right thing.
- "Skip it, just give your best guess" — you respond clearly labeled as a guess, with the rollback plan.
- "I need a fix now and I'll roll back if it doesn't work" — you give the smallest-fix-first option ([`investigation-methodology.md`](investigation-methodology.md) §7).

Either way, the user makes an informed decision. Pretending to have certainty you don't have is the wrong answer.

---

## 7. After the resolution — capture the lesson

Per [`investigation-methodology.md`](investigation-methodology.md) §12: any generalizable lesson from an investigation should land in the runbook directory **in the same PR as the fix**, not as an "I'll write it up later" item that never happens.

Specifically:
- New fleet quirk → `known-fleet-quirks.md`
- New diagnostic pattern → [`diagnostic-patterns.md`](diagnostic-patterns.md)
- A new incident class → new runbook + index entry in [`README.md`](README.md)
- A case worth remembering → append to "Cases" in the matching runbook

The runbook directory is the team's institutional memory. Treat updates to it as a deliverable on every investigation, not a courtesy.

---

## What this runbook does *not* cover

- Specific technical investigation steps — those are in the per-symptom runbooks.
- Tooling for postmortem document generation — the team uses Confluence; the structure is in §3.
- Internal team communication norms (Slack channels, on-call escalation matrices) — those are in the org-internal runbooks, not in this repo.
