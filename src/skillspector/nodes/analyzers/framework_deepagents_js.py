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

"""Deep Agents for JavaScript Framework analyzer node.

Gated on the ``DEEPAGENTS_JS`` Framework. On every other input it returns no
Findings and emits nothing at all: no ledger event, no analyzer status. That
silence is the decision in
``docs/adr/0002-gated-analyzers-decline-silently.md``, and it is what keeps a Scan
of every input that existed before this module byte-for-byte unchanged by its
existence.

**The four Rules are the Python track's, unchanged.** ``DA-UNRESOLVED``,
``DA-SKILL-WRITABLE``, ``DA-SHADOW`` and ``DA-SUBAGENT-SKILLS`` mean here exactly
what ``framework_deepagents`` makes them mean, because they judge the same
upstream framework expressed in a second language. Read that module's docstring
for what each Rule concludes and why; this one records only what is different.
Reusing the rule ids rather than minting ``DAJS-*`` is deliberate: a reviewer who
has baselined "this agent may rewrite its Skills" should not have to baseline it
twice because the application was written in TypeScript, and the catalogue in
``pattern_defaults`` stays one entry per question rather than one per language.

**What is different is the parser and the shapes it reads**, and
``docs/adr/0009-tree-sitter-for-typescript-parsing.md`` records all of it: an
options object instead of keyword arguments, a plain object literal instead of a
``FilesystemPermission`` construction, a positional route map instead of a
``routes`` keyword, and ``interruptOn`` instead of ``interrupt_on``. The gate is
asked over the **same two** write tools in both tracks, so no configuration is
judged differently on account of its language.

**What the reuse does not share is the prose.** ``pattern_defaults`` writes
those entries in Python -- ``FilesystemPermission``, ``operations=["write"]``,
``mode="deny"``, ``interrupt_on``, ``skills=[...]`` -- because the Python track
is what it was written for. Emitted verbatim on a TypeScript Scan, that text
tells a reader to construct a class the JavaScript distribution does not export
and to write a key the captured reference annotates as an *upstream prose
defect*. Two of those spellings appear nowhere on the JavaScript page at all. So
this module overrides the affected strings per rule id, below, while the
catalogue keeps one entry per question: the shared thing is the *question* a rule
asks, not the sentence that answers it in one language's syntax. Attribution
accuracy in a Finding message is §4 substance rather than polish --
``.claude/rules/license-compliance.md`` names presenting one project's behavior
as another's outright -- which is why this is fixed here rather than deferred.

What this Analyzer opens is one predicate, ``signals.applicable_files``: the
JavaScript and TypeScript modules, the ``package.json`` files and the Agent Skills
manifests of the Scan. Both the gate and the planned work derive from that single
result, so the Analyzer cannot open a Component it does not report --
``docs/adr/0006-langchain4j-applicability-is-what-it-opens.md`` records why.

**A parse error does not skip a Component here, and it does on the Python
track.** ``framework_deepagents`` skips a module whose ``ast.parse`` raised,
because a Python file either parses or does not. tree-sitter has no such
boundary: it always returns a tree, and the grammar's last release predates
roughly two years of TypeScript syntax, so ``has_error`` is as likely to mean
"newer than the grammar" as "broken". A Component is therefore always read, and
the option keys that survived the error still yield their configuration. The cost
is stated rather than discovered: a genuinely malformed module is reported as
completed, having contributed whatever partial tree it had.

**Only the parser-free module is imported at the top.** The registry imports this
module on every Scan, and :mod:`skillspector.deepagents_js.host_config` and
:mod:`skillspector.deepagents_js.parser` reach tree-sitter. Importing them here
would put the native dependency on the import path of every Scan of every input,
including the ones this Analyzer declines. So Applicability is decided with
``signals`` alone -- which imports nothing -- and the parser is reached for
lazily, inside the functions that use it, under a ``# noqa`` a later cleanup
might otherwise read as an invitation. ``TestParserFree`` in
``tests/unit/test_deepagents_js_vocabulary.py`` is what makes hoisting that
import fail: it imports :mod:`skillspector.nodes.analyzers` -- the registry, which
is the path a Scan actually takes -- in a subprocess and asserts ``tree_sitter``
never landed in ``sys.modules``. The LangChain4j guard does **not** cover this
module; it names only its own package, and no path from there reaches the
analyzer registry. :mod:`skillspector.langchain4j` states
the same ordering and ``tests/unit/test_langchain4j_vocabulary.py`` enforces it
for detection.

**The ``not_applicable`` branch cannot be reached through the graph.** Every
signal :mod:`skillspector.framework` detects this Framework by is a module source
or a ``package.json``, and both are exactly what this Analyzer opens. The branch is
kept because ADR 0006 makes it the shape of an Applicability gate rather than an
observed case, and it is exercised from synthetic state.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from skillspector.deepagents_js import signals
from skillspector.framework import Framework
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
from skillspector.nodes.analyzers.pattern_defaults import (
    get_category,
    get_explanation,
    get_pattern_name,
    get_remediation,
)
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

if TYPE_CHECKING:  # pragma: no cover - typing only
    from skillspector.deepagents_js.host_config import AgentConfiguration
    from skillspector.deepagents_js.skill_sources import Shadowing

ANALYZER_ID = "framework_deepagents_js"
logger = get_logger(__name__)

_PHASE = "static"

_UNRESOLVED_RULE_ID = "DA-UNRESOLVED"
_UNRESOLVED_SEVERITY = "MEDIUM"
_WRITABLE_RULE_ID = "DA-SKILL-WRITABLE"
_SHADOW_RULE_ID = "DA-SHADOW"
_SUBAGENT_RULE_ID = "DA-SUBAGENT-SKILLS"
_TAGS = ["ASI02"]

# Every severity and confidence below is the Python track's, and deliberately so:
# the same Rule id must not carry two risk statements because the application was
# written in a second language. `framework_deepagents.py` is where each is argued.
_UNRESOLVED_CONFIDENCE = 1.0
_WRITABLE_CONFIDENCE = 0.9
_WRITABLE_SEVERITY = "MEDIUM"
_WRITABLE_MITIGATED_SEVERITY = "LOW"
_SHADOW_SEVERITY = "HIGH"
_SHADOW_CONFIDENCE = 0.9
_SUBAGENT_SEVERITY = "LOW"
_SUBAGENT_CONFIDENCE = 0.9

# One message per surface the Scan can stop at. A report that said the same
# sentence about an unknown Skill list and an unknown backend would leave a
# reviewer to work out which surface went unexamined, which is the work this Rule
# exists to save.
_UNRESOLVED_SKILL_LIST = (
    "The Skill source list is assembled at runtime, so the Scan cannot say which Skill "
    "directories this agent was given and examined none of them."
)
_UNRESOLVED_BACKEND = (
    "The backend is built somewhere this Scan cannot follow, so whether the agent's Skill files "
    "are on disk at all -- and whether anything can write to them -- was not determined."
)
_UNRESOLVED_PERMISSIONS = (
    "The filesystem permission rules are not statically resolvable, so what this agent is allowed "
    "to do to its Skill files was not determined."
)
_UNREADABLE_PERMISSION_RULE = (
    "A filesystem permission rule is written in a shape this Scan does not recognize, so which "
    "rule decides a Skill path -- and therefore what the agent may do to it -- was not determined."
)
_UNRESOLVED_SUBAGENTS = (
    "The subagent definitions are not statically resolvable, so which of this agent's custom "
    "subagents were given Skills of their own was not determined."
)
_UNRESOLVED_BACKEND_ROOT = (
    "The filesystem backend's root directory is not statically resolvable, so the agent's Skill "
    "source paths could not be mapped onto files this Scan can open and no Skill name was read "
    "from them."
)
_SUBAGENT_MESSAGE = (
    "This custom subagent is defined without Skills of its own. A custom subagent does not inherit "
    "the main agent's Skills, so it runs without the Skills the application around it was given."
)


# Where the shared catalogue entry answers the question in Python's syntax, or
# names a symbol the JavaScript distribution does not have. Each string below is
# the catalogue's own advice with its spellings taken from the captured code
# blocks -- the reasoning is unchanged, and deliberately so, because the same
# rule id must not carry two arguments. A rule id absent from these maps has a
# catalogue entry that reads correctly in both languages; ``DA-UNRESOLVED`` is
# the one that does, because it names no API at all.
#
# ``docs/references/deepagents-js-skills.md`` is the authority for every
# spelling here: a permission rule is a plain object literal, `interruptOn` is
# the gate, and `FilesystemPermission` does not appear on the JavaScript page.
_REMEDIATION: Final[Mapping[str, str]] = {
    _WRITABLE_RULE_ID: (
        'Add a permission rule { operations: ["write"], mode: "deny" } whose paths pattern covers '
        "this Skill source, placing any more specific rule before it. Where the agent is meant to "
        "refine its own Skills, keep the writable source separate from the shared library and "
        'require approval for the writes with mode: "interrupt" or interruptOn.'
    ),
    _SHADOW_RULE_ID: (
        "Give the two Skills distinct names, or drop the duplicate from the source that is not "
        "meant to provide it. Where the override is deliberate, order skills: [...] so the source "
        "that is meant to win is written last and say so beside the call -- the list order is the "
        "only thing that decides it. Where it is not, keep a per-user or otherwise writable Skill "
        "source out of the same name space as the curated library."
    ),
}
_EXPLANATION: Final[Mapping[str, str]] = {
    _SHADOW_RULE_ID: (
        "Two Skill sources one Deep Agents application passes to skills: [...] both declare a "
        "Skill of the same name. Later sources override earlier ones -- last one wins -- so the "
        "Skill the agent loads is the one in the later source and the earlier one never runs. "
        "Where the later source is writable, or is where a per-user directory lives, that is a "
        "supply-chain substitution expressed entirely in configuration: nothing in either Skill "
        "directory read on its own shows it, and a reviewer who vetted the shared library vetted "
        "a Skill the agent does not use."
    ),
}


def _shadow_message(shadowing: Shadowing) -> str:
    """The ``DA-SHADOW`` message for one confirmed collision."""
    return (
        f"The Skill {shadowing.name} is declared in both the Skill source {shadowing.shadowed} and "
        f"the later source {shadowing.shadowing}. Later sources override earlier ones for Skills "
        f"of the same name, so the agent loads {shadowing.loaded} and the earlier one never runs."
    )


def _writable_message(path: str, mitigated: bool) -> str:
    """The ``DA-SKILL-WRITABLE`` message for one Skill source path."""
    if mitigated:
        return (
            f"The agent is given the Skill source path {path} and nothing denies it write access, "
            "so it can rewrite the instructions it runs on. A human is asked to approve the write."
        )
    return (
        f"The agent is given the Skill source path {path} and nothing denies it write access, so "
        "it can rewrite the instructions it runs on and no human is asked."
    )


def _unresolved_route_message(path: str) -> str:
    """The ``DA-UNRESOLVED`` message for a resolved path routed into a store."""
    return (
        f"The Skill source path {path} resolves, but it is routed to a store whose contents are "
        "computed per request, so its writability was not determined."
    )


def _decline() -> AnalyzerNodeResponse:
    """Return the empty response a Framework-mismatched Analyzer declines with."""
    return {"findings": []}


def _finding(
    rule_id: str, severity: str, confidence: float, path: str, start_line: int, message: str
) -> Finding:
    """Build one Finding of any of the four Rules.

    Category and name are read from ``pattern_defaults`` rather than restated
    here -- the same catalogue the Python track reads, which is what makes the
    shared rule ids mean one thing. The explanation and the remediation are read
    from there too, *except* where the catalogue answers in the other language's
    syntax; see :data:`_REMEDIATION` and the module docstring.
    """
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=severity,
        confidence=confidence,
        file=path,
        start_line=start_line,
        category=get_category(rule_id),
        pattern=get_pattern_name(rule_id),
        tags=list(_TAGS),
        explanation=_EXPLANATION.get(rule_id) or get_explanation(rule_id),
        remediation=_REMEDIATION.get(rule_id) or get_remediation(rule_id),
    )


def _unresolved(path: str, start_line: int, message: str) -> Finding:
    """Build one ``DA-UNRESOLVED`` Finding."""
    return _finding(
        _UNRESOLVED_RULE_ID, _UNRESOLVED_SEVERITY, _UNRESOLVED_CONFIDENCE, path, start_line, message
    )


def _boundary_findings(path: str, configuration: AgentConfiguration) -> list[Finding]:
    """Every place one host configuration stopped resolving.

    A setting that is absent is not a boundary: no ``skills`` is no Skills, no
    ``permissions`` is no rules, no ``backend`` is the default one, and no
    ``subagents`` is no custom subagents. Each of those is a configuration a
    verdict judges, not a silence this one reports.

    A ``rootDir`` this Scan cannot read is a boundary for the same reason as the
    others: resolution stopped. It is raised only where the Skill list itself
    resolved; where it did not, that is already reported and saying it twice in two
    vocabularies would describe one silence as two.
    """
    findings = [
        _unresolved(path, resolution.line, message)
        for resolution, message in (
            (configuration.skill_paths, _UNRESOLVED_SKILL_LIST),
            (configuration.backend, _UNRESOLVED_BACKEND),
            (configuration.permission_rules, _UNRESOLVED_PERMISSIONS),
            (configuration.subagents, _UNRESOLVED_SUBAGENTS),
        )
        if resolution is not None and resolution.unresolved
    ]
    findings.extend(
        _unresolved(path, route.line, _unresolved_route_message(route.path))
        for route in configuration.opaque_routes
    )
    skills = configuration.skill_paths
    root = configuration.filesystem_root
    if skills is not None and not skills.unresolved and root is not None and root.unresolved:
        findings.append(_unresolved(path, root.line, _UNRESOLVED_BACKEND_ROOT))
    return findings


def _configuration_findings(
    path: str, configuration: AgentConfiguration, manifests: Mapping[str, str]
) -> list[Finding]:
    """All four Rules over one ``createDeepAgent({...})`` call.

    The boundary is reported first because it is what the verdict falls back to:
    :func:`skillspector.deepagents_js.writability.assess` returns nothing for a
    configuration whose Skill list, backend or permission rules did not resolve, so
    the two Rules partition the call rather than overlapping on it.

    The other two are orthogonal to that partition and to each other.
    ``DA-SHADOW`` asks what the sources *contain* rather than what the call
    permits; *manifests* is the ``SKILL.md`` half of the same Applicability result
    the ledger rows are built from, so the collision is confirmed out of files this
    Analyzer has already said it opened. ``DA-SUBAGENT-SKILLS`` asks what the
    call's subagent definitions were given, which is decided inside one definition.
    """
    from skillspector.deepagents_js import skill_sources, subagents, writability  # noqa: PLC0415

    findings = _boundary_findings(path, configuration)
    assessment = writability.assess(configuration)
    findings.extend(
        _unresolved(path, line, _UNREADABLE_PERMISSION_RULE)
        for line in assessment.unreadable_rule_lines
    )
    findings.extend(
        _finding(
            _WRITABLE_RULE_ID,
            _WRITABLE_MITIGATED_SEVERITY if writable.mitigated else _WRITABLE_SEVERITY,
            _WRITABLE_CONFIDENCE,
            path,
            writable.line,
            _writable_message(writable.path, writable.mitigated),
        )
        for writable in assessment.writable
    )
    findings.extend(
        _finding(
            _SHADOW_RULE_ID,
            _SHADOW_SEVERITY,
            _SHADOW_CONFIDENCE,
            path,
            shadowing.line,
            _shadow_message(shadowing),
        )
        for shadowing in skill_sources.find_shadowing(configuration, manifests)
    )
    findings.extend(
        _finding(
            _SUBAGENT_RULE_ID,
            _SUBAGENT_SEVERITY,
            _SUBAGENT_CONFIDENCE,
            path,
            definition.line,
            _SUBAGENT_MESSAGE,
        )
        for definition in subagents.without_own_skills(configuration)
    )
    return findings


def _open(
    path: str, source: str, manifests: Mapping[str, str]
) -> tuple[InspectionLedgerEvent, list[Finding]]:
    """Open one applicable Component and record what came of it.

    A module source is parsed; anything else applicable is a ``package.json`` or a
    Skill manifest, and neither carries a Finding of its own. A manifest is
    nonetheless *read* -- by ``DA-SHADOW``, through *manifests*, whose Findings land
    on the module that configured the sources -- so the row a manifest gets is a row
    for a file that was genuinely used.

    There is no skip branch. The module docstring records why: tree-sitter always
    returns a tree, so there is no parse failure to report, and a partial tree still
    yields the settings the Rules read.
    """
    from skillspector.deepagents_js import host_config, parser  # noqa: PLC0415

    if signals.is_module_source(path):
        tree = parser.parse(source, path)
        findings = [
            finding
            for configuration in host_config.find_agent_configurations(tree)
            for finding in _configuration_findings(path, configuration, manifests)
        ]
    else:
        findings = []
    return (
        ledger_event(
            outcome=LedgerOutcome.COMPLETED,
            phase=_PHASE,
            analyzer_id=ANALYZER_ID,
            path=path,
            emitted_finding_ids=[finding.finding_id for finding in findings],
        ),
        findings,
    )


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Report what this Analyzer opened on a Deep Agents for JavaScript Scan; decline on any other."""
    if state.get("framework") != Framework.DEEPAGENTS_JS:
        return _decline()

    file_cache: Mapping[str, str] = state.get("file_cache") or {}

    applicable = signals.applicable_files(file_cache)
    if not applicable:
        logger.info("%s: nothing applicable, reporting not_applicable", ANALYZER_ID)
        return {
            "findings": [],
            "analyzer_status_events": [
                analyzer_status_event(
                    analyzer_id=ANALYZER_ID,
                    status=AnalyzerStatus.NOT_APPLICABLE,
                    reason=LedgerReason.NO_APPLICABLE_FILES,
                )
            ],
        }

    # Every file opened gets a row, whether or not it yielded a Finding. Once this
    # Analyzer runs, an absence of Findings must be distinguishable from an absence
    # of inspection.
    #
    # Narrowed from the same result the gate tested, never recomputed from
    # `file_cache`: two definitions of "applicable" a few lines apart are what ADR
    # 0006 exists to prevent recurring, and `DA-SHADOW` must confirm a collision
    # out of exactly the manifests the ledger says this Analyzer opened.
    manifests = {
        path: source for path, source in applicable.items() if signals.is_skill_manifest(path)
    }
    opened = [_open(path, source, manifests) for path, source in sorted(applicable.items())]
    events = [event for event, _findings in opened]
    findings = [finding for _event, file_findings in opened for finding in file_findings]

    # The status is derived from these events rather than written here.
    # `analyzer_status_for_events` owns the cascade; see
    # `.claude/rules/analyzer-status.md`.
    logger.info("%s: %d findings across %d components", ANALYZER_ID, len(findings), len(events))
    return {
        "findings": findings,
        "inspection_ledger": events,
        "analyzer_status_events": [analyzer_status_for_events(ANALYZER_ID, events)],
    }
