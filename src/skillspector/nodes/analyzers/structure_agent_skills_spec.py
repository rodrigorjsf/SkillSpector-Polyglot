# SPDX-FileCopyrightText: Copyright (c) 2026 SkillSpector-Polyglot contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Agent Skills specification conformance Analyzer node.

Seventeen deterministic Rules -- a string comparison, a length, a path lookup --
over every ``SKILL.md`` of a Scan. No LLM, no network, nothing probabilistic
except the one token estimate :mod:`skillspector.agent_skills_spec` names as
such. That module holds the catalogue and the verdicts; this one is the gate, the
Inspection Ledger accounting, and the two things a Scan publishes about the mode.

**The gate is ``--spec-checks``, and its default returns nothing at all.** Off is
not a mode this Analyzer runs quietly in: it plans no inspection, opens no
Component and emits no Analyzer Status. That is what makes the flag's absence
byte-for-byte identical to this module not existing, which is the whole of the
behavior-preservation argument.
``docs/adr/0002-gated-analyzers-decline-silently.md`` accepts this as its second
case -- a configuration gate whose default is the absence of a request -- beside
the Framework mismatch it was written for.

**Why silence rather than ``disabled``, which is the other precedent.** The
semantic Analyzers answer ``--no-llm`` with an Analyzer Status of ``disabled``
and ``LedgerReason.DISABLED_BY_CONFIGURATION``, and copying that here was
measured and rejected on two counts. The first is arithmetic: an Analyzer Status
lands in ``analysis_completeness.analyzer_statuses``, which is one of the state
keys the Behavior Snapshot projects, and ``disabled`` sits outside
``NON_LIMITING_STATUSES``, so every Scan that never asked for this Analyzer would
gain a row *and* lose ``is_complete``. The second is what the two gates mean.
``--no-llm`` is a request a user made -- the Analyzer would have run, and the
user turned it off, which is a configuration worth reporting. ``--spec-checks
off`` is the *absence* of a request; there is no configuration to report, and a
row saying so on every Scan ever run would be reporting the default of a flag
rather than a limitation of a Scan. Both arguments are carried in the ADR, which
is where a third gate has to be argued rather than here.

Past that gate the Analyzer reports on every input, and Applicability is one
predicate: the ``SKILL.md`` Components of the Scan, at any depth. A Scan with
none of them -- a directory declaring no Skill, which ``manifest_status`` already
reports as ``absent`` -- reports ``not_applicable`` with
``LedgerReason.NO_APPLICABLE_FILES`` and no ledger event, the shape
``docs/adr/0006-langchain4j-applicability-is-what-it-opens.md`` fixes.

**Which invocation shapes can reach ``SPEC-17``.** It is the one Rule that
reasons across skill directories, and it can only see what one ``graph.invoke``
was given. The shape that reaches it is an ordinary Scan of a directory that
declares no Skill of its own and holds several that do -- the fall-through the
CLI already warns about -- where ``build_context`` walks the whole tree and every
nested ``SKILL.md`` lands in one Scan. ``--recursive`` and ``--repo-scan`` invoke
the graph once per discovered Skill *directory*, so each invocation sees that one
directory's tree: a collision between two discovered Skills is out of reach on
both paths, and one between a Skill and a Skill nested inside it is not.

**"Reported but not scored" is a property of the run, not of a Finding.** Every
Finding here is emitted at its Rule's own ``confidence`` in every mode, and the
Rule ids ``advisory`` declines to score are published separately, in the
``unscored_rule_ids`` state key that ``report._compute_risk_score`` reads as an
opaque set. Saying it in ``confidence`` instead -- the design this Analyzer was
first written to, and rejected before release -- would have made one defect
fingerprint two ways in ``suppression.finding_fingerprint``, so a Baseline taken
in ``advisory`` would have suppressed nothing in ``strict``.
``agent_skills_spec.unscored_rule_ids`` carries the argument, and the invariant it
serves is stated in ``suppression.finding_fingerprint``: a Baseline fingerprint
depends on the evidence, never on how the run was configured.

**The flag works the same with the LLM and without it, and is inert to the LLM
stage.** ``meta_analyzer._model_visible`` withholds every id of this catalogue
from the prompt, from the token budget that prompt is charged against, and from
the decision to call at all -- so a Manifest whose only Findings are conformance
Findings costs no chat-model invocation, and turning this flag on cannot move an
unrelated Finding into a different chunk. ``meta_analyzer.apply_filter`` then
skips these ids rather than looking up a confirmation none of them can have:
that filter keeps a MEDIUM or LOW Finding only when the model confirmed it, so
filtering on confirmation made ``--spec-checks`` report almost nothing unless it
was paired with ``--no-llm`` (issue #120). The ``--no-llm`` path needs no
exemption at all: ``_fallback_filtered`` drops below confidence 0.4, and the
lowest confidence in this catalogue is ``SPEC-13``'s 0.7.

**No Rule reads ``allowed-tools``.** ``.claude/rules/allowed-tools-separator.md``
records the comma/space deviation as deliberate, and the catalogue stays off that
field entirely rather than depending on it or correcting it in passing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from skillspector.agent_skills_spec import (
    CATEGORY,
    RULES,
    UNSCORED_NOTE,
    Declaration,
    ManifestComponent,
    ScanScope,
    SpecChecks,
    SpecViolation,
    duplicate_name_violations,
    in_bundled_directory,
    is_manifest,
    manifest_precedence,
    read_declaration,
    unscored_rule_ids,
    violations_of,
)
from skillspector.inspection_ledger import (
    AnalyzerStatus,
    InspectionLedgerEvent,
    LedgerOutcome,
    LedgerReason,
    analyzer_status_event,
    analyzer_status_for_events,
    ledger_event,
)
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

ANALYZER_ID = "structure_agent_skills_spec"
logger = get_logger(__name__)

_PHASE = "static"

# No tag. Every other Analyzer here tags its Findings with the OWASP Agent
# Security Initiative category they belong to, and these belong to none: a
# conformance Rule states that a declaration disagrees with the specification,
# not that a risk category applies. Claiming one would put this catalogue into a
# risk taxonomy it was not measured against, so a Rule with no honest row gets
# none rather than the nearest one.
_TAGS: list[str] = []


def _decline() -> AnalyzerNodeResponse:
    """Return the empty response the ``off`` gate answers with."""
    return {"findings": []}


def _root_directory(state: SkillspectorState) -> str | None:
    """The directory name ``SPEC-4`` compares the root Manifest against.

    ``None`` where the Scan cannot observe it. An input that was cloned,
    downloaded, unzipped or wrapped sits under a directory this tool named --
    ``repo``, ``extracted``, a ``mkdtemp`` suffix -- and ``temp_dir_for_cleanup``
    is exactly the flag that says so. Comparing a declared name against one of
    those would put a scored Finding on every conforming Skill Scanned from a Git
    URL.
    """
    if state.get("temp_dir_for_cleanup"):
        return None
    skill_path = state.get("skill_path")
    if not isinstance(skill_path, str) or not skill_path.strip():
        return None
    return Path(skill_path).name or None


def _scan_scope(state: SkillspectorState) -> ScanScope:
    """What this Scan walked, and what it recorded itself declining to walk.

    ``SPEC-15`` is scored, so it may only report a path the Scan was actually in a
    position to find. Two of the three answerable blind spots are already written
    down by the Scan itself: ``build_context._walk_skill_files`` emits an
    ``out_of_scope`` scope boundary for every hidden file it drops and every
    ``_SKIP_DIRS`` directory it prunes, and those events reach this Analyzer
    through ``inspection_ledger`` -- an ``operator.add`` channel ``build_context``
    has already written by the time the Analyzers fan out. Reading them here is
    what keeps one report from saying both that a path is out of scope and that
    the path was not found.

    The third is the single-file input, which carries no tree to walk. It is
    ``temp_dir_for_cleanup`` **and** a lone Component together, never the
    temporary directory alone: a clone, a download and a Zip extraction all set
    that key and all carry the Skill's tree, and a genuinely broken reference in
    any of them still has to be reported.
    """
    components = frozenset(
        entry["path"]
        for entry in state.get("component_metadata") or []
        if isinstance(entry.get("path"), str)
    )
    excluded = frozenset(
        event["path"].rstrip("/")
        for event in state.get("inspection_ledger") or []
        if event.get("outcome") == LedgerOutcome.OUT_OF_SCOPE and event.get("path")
    )
    wrapped_single_file = bool(state.get("temp_dir_for_cleanup")) and len(components) == 1
    return ScanScope(
        components=components,
        excluded=excluded,
        tree_observed=not wrapped_single_file,
    )


def _manifests(state: SkillspectorState) -> list[ManifestComponent]:
    """One Manifest per skill directory of the Scan, in path order.

    Built from ``component_metadata`` rather than from ``file_cache`` because
    ``SPEC-14`` needs the size the Component has on disk, and that is the only
    place a Scan carries it. A Manifest whose content never reached the cache is
    kept here and skipped below, so a Manifest that could not be read is
    reported as uninspected rather than as conforming.

    **The unit is the directory, not the file, and that is the Applicability
    predicate this Analyzer plans work from.** ``MANIFEST_FILENAMES`` holds two
    spellings because ``build_context._parse_manifest`` reads two, but it reads
    them *in precedence order and stops at the first*: a directory shipping both
    ``SKILL.md`` and ``skill.md`` is one Skill whose Manifest is ``SKILL.md``.
    Treating the shadowed spelling as a second Manifest reported every Rule
    twice and invented a ``SPEC-17`` collision -- a scored Rule -- between a
    directory and itself. The shadowed file is not inspected and no Work Item is
    planned for it, so the ledger has nothing to account for.

    **A Manifest a Skill bundles is not a skill directory either.** The three
    directories the specification defines for what a Skill *ships* --
    ``scripts/``, ``references/``, ``assets/`` -- are excluded here, in the one
    place applicability is decided, rather than by teaching two Rules to ignore
    them: a Skill shipping a template ``references/SKILL.md`` earned twenty
    scored points, ``SPEC-4`` against the directory name ``references`` and
    ``SPEC-17`` against the Skill that ships it. **This narrows the gap without
    closing it.** Applicability is still a filename plus a path segment, not a
    loader's notion of a skill directory, so a Manifest parked somewhere the
    specification does not name -- ``docs/examples/SKILL.md`` -- is still read as
    a skill directory and can still collide with the Skill around it. Issue #121
    carries the residue.
    """
    file_cache: Mapping[str, str] = state.get("file_cache") or {}
    root_directory = _root_directory(state)
    by_directory: dict[str, ManifestComponent] = {}
    for entry in state.get("component_metadata") or []:
        path = entry.get("path")
        if not isinstance(path, str) or not is_manifest(path) or in_bundled_directory(path):
            continue
        size = entry.get("size_bytes")
        directory = path.rsplit("/", 2)[-2] if "/" in path else root_directory
        key = path.rsplit("/", 1)[0] if "/" in path else ""
        incumbent = by_directory.get(key)
        if incumbent is not None and manifest_precedence(incumbent.path) <= manifest_precedence(
            path
        ):
            continue
        by_directory[key] = ManifestComponent(
            path=path,
            content=file_cache.get(path),
            size_bytes=size if isinstance(size, int) else 0,
            directory=directory,
        )
    return sorted(by_directory.values(), key=lambda manifest: manifest.path)


def _finding(violation: SpecViolation) -> Finding:
    """One Finding of one Rule, at the Rule's own confidence -- in every mode.

    **The mode is not in here, and that is the fix.** ``confidence`` means how
    certain this Analyzer is that the Finding is real, and every Rule of this
    catalogue is a measurement, so the answer does not depend on which mode asked
    for it. The first implementation said "advisory" by emitting the Finding at
    ``confidence = 0.0``, which made one defect fingerprint two ways in
    ``suppression.finding_fingerprint`` and rendered as a false ``Confidence:
    0%``. Which Rules a run declines to score is published by ``node`` into
    ``unscored_rule_ids`` instead; ``agent_skills_spec.unscored_rule_ids`` carries
    the argument in full.
    """
    rule = RULES[violation.rule_id]
    return Finding(
        rule_id=rule.rule_id,
        message=violation.message,
        severity=rule.severity,
        confidence=rule.confidence,
        file=violation.path,
        start_line=violation.line,
        category=CATEGORY,
        pattern=rule.name,
        tags=list(_TAGS),
        explanation=rule.explanation,
        remediation=rule.remediation,
    )


def _skipped(path: str) -> InspectionLedgerEvent:
    """The row a Manifest gets when its content never reached the cache."""
    return ledger_event(
        outcome=LedgerOutcome.SKIPPED,
        phase=_PHASE,
        analyzer_id=ANALYZER_ID,
        path=path,
        reason=LedgerReason.MISSING_FILE_CACHE,
    )


def _completed(path: str, findings: Sequence[Finding]) -> InspectionLedgerEvent:
    """The row a Manifest gets when every Rule ran over it."""
    return ledger_event(
        outcome=LedgerOutcome.COMPLETED,
        phase=_PHASE,
        analyzer_id=ANALYZER_ID,
        path=path,
        emitted_finding_ids=[finding.finding_id for finding in findings],
    )


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Report the specification conformance of every Manifest, when asked to."""
    mode = SpecChecks.parse(state.get("spec_checks"))
    if mode is SpecChecks.OFF:
        return _decline()

    # Written on every path past the gate, including the one that reports
    # nothing: the key says what this *run* was configured to score, which is
    # answerable whether or not the Scan held a Manifest. Only `off` leaves it
    # absent, which is what makes the flag's default byte-identical to this
    # module not existing.
    #
    # The note travels with the ids because it names `--spec-checks`, and this
    # module is the one that owns that flag's catalogue. `report` renders it
    # verbatim, so the report keeps the ids opaque and still prints a remedy a
    # reader can act on.
    unscored = unscored_rule_ids(mode)

    manifests = _manifests(state)
    if not manifests:
        logger.info("%s: no skill manifest in this scan, reporting not_applicable", ANALYZER_ID)
        return {
            "findings": [],
            "unscored_rule_ids": unscored,
            "unscored_rule_note": UNSCORED_NOTE,
            "analyzer_status_events": [
                analyzer_status_event(
                    analyzer_id=ANALYZER_ID,
                    status=AnalyzerStatus.NOT_APPLICABLE,
                    reason=LedgerReason.NO_APPLICABLE_FILES,
                )
            ],
        }

    scope = _scan_scope(state)
    declarations: list[tuple[ManifestComponent, Declaration]] = [
        (manifest, read_declaration(manifest.content))
        for manifest in manifests
        if manifest.content is not None
    ]

    # `SPEC-17` is computed across Manifests and then attributed back to the one
    # it names, so a Finding still lands on a Component this Analyzer said it
    # opened and the ledger still accounts for every Finding it emitted.
    per_path: dict[str, list[SpecViolation]] = {
        manifest.path: violations_of(manifest, declaration, scope)
        for manifest, declaration in declarations
    }
    for violation in duplicate_name_violations(declarations):
        per_path[violation.path].append(violation)

    findings: list[Finding] = []
    events: list[InspectionLedgerEvent] = []
    for manifest in manifests:
        if manifest.content is None:
            events.append(_skipped(manifest.path))
            continue
        manifest_findings = [_finding(violation) for violation in per_path[manifest.path]]
        findings.extend(manifest_findings)
        events.append(_completed(manifest.path, manifest_findings))

    logger.info(
        "%s: %d findings across %d manifests (mode=%s)",
        ANALYZER_ID,
        len(findings),
        len(events),
        mode.value,
    )
    return {
        "findings": findings,
        "unscored_rule_ids": unscored,
        "unscored_rule_note": UNSCORED_NOTE,
        "inspection_ledger": events,
        "analyzer_status_events": [analyzer_status_for_events(ANALYZER_ID, events)],
    }
