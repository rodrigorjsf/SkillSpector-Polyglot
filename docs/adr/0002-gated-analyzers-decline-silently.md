# Gated Analyzers decline silently

Status: accepted

An Analyzer that only applies to one Framework must decline when the Scan is of another Framework.
We decided it declines by returning no Findings and emitting **nothing** to the Inspection Ledger —
no ledger event, no analyzer status event — so a Scan of an Agent Skills Skill is byte-for-byte
unchanged by the existence of a LangChain4j or Deep Agents Analyzer.

**A second gate is accepted on the same reasoning: a configuration gate whose default is the absence
of a request.** `structure_agent_skills_spec` runs only when `--spec-checks` is given a value other
than its default `off`, and with the flag absent it declines in exactly this shape — no Finding, no
Work Item, no Analyzer Status. See [§3.5 of
`docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`](../MULTI_FRAMEWORK_SKILL_ANALYSIS.md#35-spec-conformance-rules-and-scoring)
for the catalogue this gate covers.

The distinction that admits it, and that keeps the case narrow, is between a gate that is a *request*
and a gate that is the *absence* of one. `--no-llm` is a request: the semantic Analyzers would have
run, the user turned them off, and that is a configuration worth reporting — which is why they answer
it with `disabled` and `LedgerReason.DISABLED_BY_CONFIGURATION`, and why this record does **not**
widen to cover them. `--spec-checks off` is not a request at all; it is the default of a flag nobody
passed. A row saying so would appear on every Scan ever run, and would report the default of a flag
rather than a limitation of a Scan.

The Ledger reconciliation is the one written below, unchanged: a Work Item is a *planned*
unit of inspection, and a gate that does not open plans none. The measured cost is the same as the
one that decided the original case — an Analyzer Status lands in
`analysis_completeness.analyzer_statuses`, which the Behavior Snapshot projects, and `disabled` sits
outside `NON_LIMITING_STATUSES`, so a `disabled` row on every Scan would move every committed
snapshot *and* take `is_complete` down with it.

What this does **not** license is a gate that skips work the Scan was asked for. Past the gate the
Analyzer reports on every input, which is where [ADR 0006](0006-langchain4j-applicability-is-what-it-opens.md)
binds: an Analyzer that opens nothing reports `not_applicable` rather than falling silent.

This reads like a violation of the Inspection Ledger's purpose, which is why it is recorded here.
The Ledger exists so that an absence of Findings is distinguishable from an absence of inspection,
and a silent decline looks exactly like the thing it guards against. The reconciliation is in the
definition of Work Item: it is a *planned* unit of inspection, and an Analyzer whose gate
does not open plans none. There is no unaccounted work, because there was no work. A gap presupposes
something that was meant to be inspected and was not. This holds for both gates alike — the
Framework mismatch this record was written for, and the default-off configuration gate amended in
above — because neither of them plans a Work Item it then declines to do.

## Considered Options

Emitting a `not_applicable` analyzer status was the faithful-to-the-Ledger alternative, and it was
rejected on cost. `finalize_ledger` builds `analyzer_statuses` from every status event
(`src/skillspector/inspection_ledger.py:765`), so a `not_applicable` row would appear in
`analysis_completeness` for **every existing Scan** the moment any Framework Analyzer is registered.
That churns the report and the behavior snapshot on every input, for every Analyzer added, forever —
and it would mean no phase of the multi-framework work could claim to preserve behavior.

A third option — decline silently on the wrong Framework, but emit `not_applicable` when the
Framework matches and there was still nothing applicable — was considered and deferred rather than
rejected. It is the right shape for reporting a LangChain4j repository with no readable Java, and it
does not conflict with this decision: that case has planned work.

**That deferral is now closed, and it closed to something narrower than this framing.**
[ADR 0006](0006-langchain4j-applicability-is-what-it-opens.md) redefined applicability as the set of
Components an Analyzer opens, and under that definition "the Framework matches and there was still
nothing applicable" turned out to be two cases rather than one. A LangChain4j repository holding a
build file with no shell declaration is a repository whose build file the Analyzer *reads*, line by
line, looking for the shell artifact id — so it now reports `completed` with a Work Item and no
Findings, not `not_applicable`. Only a tree the Analyzer opens nothing in — Skills reached through
the classpath layout, or a Kotlin-only import — reports `not_applicable`. The framing above assumed
the two were one case because the code's own gate conflated them; that conflation was the defect
ADR 0006 fixed. This record's own decision, silence on a Framework mismatch, is unaffected and
remains accepted.

## Consequences

`docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md` §3.1 asserted the opposite — that gated Analyzers "still run
through `guard_analyzer_node` and emit ledger status events". That was incorrect as written:
`guard_analyzer_node` only synthesizes events when the Analyzer *raises*. §3.1 was corrected in the
same change that landed this record, and now points here.

The gate is now a convention with no enforcement. A Framework Analyzer that returns a status event by
habit silently breaks the behavior snapshot for every fixture, and the failure surfaces as an
unrelated-looking snapshot diff. The snapshot test is what catches it.
