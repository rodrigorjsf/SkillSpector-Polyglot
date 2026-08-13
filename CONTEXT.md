# SkillSpector

Security analysis of AI agent skills. This context holds the vocabulary for deciding whether a
published skill is safe to install.

## Language

### Subject of analysis

**Skill**:
A distributable unit of agent capability, published as a directory that an agent loads and trusts.
The thing SkillSpector scans.
_Avoid_: plugin, extension, package, tool

**Component**:
One file inside a Skill. Carries its own type, size, and executable status.
_Avoid_: asset, resource, artifact

**Manifest**:
The declared metadata of a Skill — its name, description, and the tools it claims it may use.
_Avoid_: frontmatter, header, config

**Manifest Status**:
Why a Scan's Manifest holds what it holds — present, empty, unparseable, unreadable, or absent
because the scanned directory holds no Skill at all. Reported beside the Manifest, never inside it.
_Avoid_: manifest state, parse result, manifest error

**Framework**:
The convention a Skill is written against, which determines how its definition is located and
parsed. Agent Skills, LangChain4j, and Deep Agents are different Frameworks.
_Avoid_: format, flavour, dialect

**Scan**:
One complete pass over a Skill, from resolving the input to emitting a Recommendation.
_Avoid_: run, check, inspection

**Repository Scan**:
A single pass over an entire repository that finds every Skill within it and Scans each, as opposed
to a Scan of one already-identified Skill directory.
_Avoid_: repo scan, recursive scan, project scan, full scan

**Registry Scan**:
A pass over MCP Registry records — the metadata a server owner published about an MCP server — as
opposed to a Scan, which reads a Skill's own Components. It assesses what the owner asserted, so it
opens no Component and emits no Recommendation; it shares only the 0–100 shape of the Risk Score.
What it applies is a Posture Check, not a Rule, and what a Posture Check emits is not a Finding —
neither is bound to a Component, so neither carries a Finding's identity.
_Avoid_: registry check, server scan, registry audit

**Posture Check**:
One named check a Registry Scan applies to what a published record asserts. Deliberately not a
Rule: it reads an assertion rather than a Component. Where it is applied and the field it needs is
absent, it says so rather than passing silently — but that is a property of the individual Posture
Check, not of all of them, and each states its own scope.
_Avoid_: registry rule, posture rule

### Detection

**Analyzer**:
A unit that inspects Components and emits Findings. Every Analyzer runs on every Scan; one that
should only apply to some inputs gates on its own, and reports an Analyzer Status on every input it
does not Decline.
_Avoid_: checker, detector, scanner, plugin

**Rule**:
The named check an Analyzer applies, and the identity a Finding is attributed to.
_Avoid_: pattern, signature, check

**Refusal**:
A Component naming a capability in order to state that it is *not* taken. The opposite of declaring
it, and never a Finding: reporting one would flag the reader for the action that removes the risk.
Defined by that intent alone — each build system spells it its own way, and the spellings are syntax
rather than synonyms of the term.

**Finding**:
One instance of a Rule matching at a location in a Component. The atomic claim SkillSpector makes.
_Avoid_: vulnerability, issue, alert, detection

**Analyzer Finding**:
The shape an Analyzer emits, before it is converted into a Finding for graph state and reporting.
Distinct from Finding on purpose — only the latter has a stable identity.

**Severity**:
How damaging a Finding would be if real — LOW, MEDIUM, HIGH, or CRITICAL. Independent of how
certain the Finding is.
_Avoid_: priority, criticality, impact

### Verdict

**Risk Score**:
A 0–100 aggregate over the surviving Findings of a Scan. Suppressed Findings never contribute.
_Avoid_: rating, grade, risk level

**Recommendation**:
The installable verdict a Scan produces — SAFE, CAUTION, or DO_NOT_INSTALL.
_Avoid_: result, outcome, decision

### Accepting known findings

**Baseline**:
A file of Findings that have been reviewed and accepted, so re-scans surface only new ones.
_Avoid_: allowlist, ignore file, exceptions

**Suppression Rule**:
A glob-based Baseline entry that suppresses any Finding matching its rule, path, or message.
_Avoid_: filter, exclusion, mute

**Fingerprint**:
A Baseline entry bound to the exact evidence of one Finding, so any change to the source or the
scanner invalidates it. The precise alternative to a Suppression Rule.
_Avoid_: hash, checksum, signature

**Suppressed Finding**:
A Finding matched by a Baseline. Excluded from the Risk Score and from the report, but never
silently discarded — it is retained with the reason it was accepted.

### Accountability

**Inspection Ledger**:
The record of what a Scan actually inspected and what it did not, with a reason for every gap. It
is what makes an absence of Findings distinguishable from an absence of inspection.
_Avoid_: log, audit trail, trace

**Work Item**:
One planned unit of inspection in the Inspection Ledger. Every Work Item must reach exactly one
terminal outcome; unaccounted work is itself a reportable defect.
_Avoid_: task, job, unit

**Analyzer Status**:
What one Analyzer reports it did on one Scan. Six values — `completed`, `not_applicable`,
`degraded`, `failed`, `disabled` and `unavailable` — and only the first two leave a Scan complete;
every other value becomes a stated limitation.
_Avoid_: analyzer result, run status

**Applicability**:
Which Components an Analyzer opens. One Analyzer has one Applicability, so a Component it opens is
always a Component it reports.
_Avoid_: eligibility, purview

**Decline**:
Return nothing at all — no Finding, no Work Item, no Analyzer Status. Two cases: an Analyzer whose
Framework gate does not open, and one whose configuration gate sits at a default nobody asked for.
Both plan no inspection and so leave no gap. An Analyzer that a user's own request switched off
reports `disabled` instead, and one that opens nothing on a Framework it *does* own reports
`not_applicable`.
_Avoid_: abstain, bail out, opt out

### Changing the scanner safely

**Behavior Snapshot**:
A committed, canonical projection of one Scan, compared by a blocking test, so that a change to
behavior on an existing input surfaces as a reviewable file diff and a change that preserves
behavior produces none. Not a Baseline: a Baseline accepts known Findings, a Behavior Snapshot
freezes everything a Scan observably produces.
_Avoid_: baseline, golden file, regression fixture

**Spec**:
A parent issue and the Tickets it decomposes into, published to the tracker together.
_Avoid_: epic, plan, design doc

**Ticket**:
One child issue of a Spec — a slice implementable end to end on its own branch and closed by a
single merge. Unrelated to a Work Item, which is a unit of inspection inside a Scan.
_Avoid_: task, subtask, card, work item

**Umbrella Branch**:
The single branch carrying an entire Spec. Every Ticket branch is cut from it and merged back into
it, and it is the only branch that opens a pull request against the default branch.
_Avoid_: feature branch, integration branch, release branch
