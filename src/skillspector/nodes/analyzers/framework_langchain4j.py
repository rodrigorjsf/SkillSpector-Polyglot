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

"""LangChain4j Framework analyzer node.

Gated on the LangChain4j Framework. On every other input it returns no Findings
and emits nothing at all: no ledger event, no analyzer status. That silence is
the decision in ``docs/adr/0002-gated-analyzers-decline-silently.md`` -- an
Analyzer whose gate does not open plans no Work Item, so there is no unaccounted
work -- and it is what keeps a Scan of an Agent Skills Skill byte-for-byte
unchanged by this module's existence.

On a LangChain4j Scan it always reports exactly one Analyzer Status, and what it
opens is one predicate: ``signals.applicable_files``, the Java compilation units
and JVM build files of the Scan. Both the gate and the planned work derive from
that single result, so the Analyzer cannot open a Component it does not report.
``docs/adr/0006-langchain4j-applicability-is-what-it-opens.md`` records why.

Five Rules today.

``L4J-SHELL`` (HIGH). LangChain4j's shell mode hands the model a single
``run_shell_command`` tool that runs in the host process with no sandboxing,
containerization or privilege restriction; upstream documents it as unsafe. It
is the risk that scheduled the Java track ahead of Deep Agents in
``docs/adr/0004-langchain4j-before-deepagents.md``. It fires on the wiring that
reaches shell mode, and on a build file that declares the shell module -- either
one alone, because neither implies the other. The declaration half matches any
``langchain4j-`` artifact id containing ``shell`` rather than the one spelling
published to date, so the graduation release that drops ``experimental`` from
the artifact's name does not silently retire it; the Finding names the spelling
the build file used. ``docs/adr/0007-l4j-shell-survives-the-graduation-rename.md``
records the decision and what it deliberately does not solve.

``L4J-UNRESOLVED`` (MEDIUM). A Java-defined Skill's content, name, description,
loader path or attached tool set can be assembled at runtime, and then the
surface the model reaches exists in no file this Scan can open. Resolving
arbitrary Java dataflow is out of scope; reporting the boundary is not. Silence
there would let the report read as clean on the one surface that was never
examined.

``L4J-TOOL-DESC`` (MEDIUM). A ``@Tool`` description that instructs the model
rather than describing the tool is a prompt-injection surface sitting in an
annotation. Reported wherever the annotation is declared, and named with the
Skill that attached the class whenever the Scan can join the two without
guessing -- see :func:`_tool_attribution` for the guard, which is the whole of
the difference between attribution and misattribution here.

``L4J-MCP-FILTER`` (MEDIUM). An ``McpToolProvider`` built without a tool filter
hands the agent every tool its MCP server exposes rather than a scoped subset.

``L4J-WORKDIR`` (MEDIUM). A shell command configuration built without a working
directory runs commands wherever the JVM happens to be -- usually the
application root.

Only the first is about shell mode; the other four apply to any LangChain4j
application, Tool mode included.

What *is* resolvable -- a text block, a string literal, a same-unit constant --
is scanned by the existing content Analyzers, so a Skill body written in Java
gets the scrutiny a ``SKILL.md`` body gets.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from types import ModuleType
from typing import TYPE_CHECKING

from skillspector.framework import Framework
from skillspector.inspection_ledger import (
    AnalyzerStatus,
    LedgerOutcome,
    LedgerReason,
    PlannedWorkTarget,
    analyzer_status_event,
    inspection_work_id,
    ledger_event,
)
from skillspector.langchain4j import signals, vocabulary
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.nodes.analyzers.pattern_defaults import (
    get_category,
    get_explanation,
    get_pattern_name,
    get_remediation,
)
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

if TYPE_CHECKING:  # Importing it at runtime would pull tree-sitter in at module top.
    from skillspector.langchain4j.skill_definitions import BuilderArgument

ANALYZER_ID = "framework_langchain4j"
logger = get_logger(__name__)

_RULE_ID = "L4J-SHELL"
_UNRESOLVED_RULE_ID = "L4J-UNRESOLVED"
_TOOL_DESC_RULE_ID = "L4J-TOOL-DESC"
_MCP_FILTER_RULE_ID = "L4J-MCP-FILTER"
_WORKDIR_RULE_ID = "L4J-WORKDIR"
_TAGS = ["ASI02"]
_SEVERITY = "HIGH"
_UNRESOLVED_SEVERITY = "MEDIUM"
_TOOL_SURFACE_SEVERITY = "MEDIUM"

# Each of the three is a fact about the shape of the source -- an annotation
# carrying prose, a setter never called -- rather than an inference from it.
_TOOL_SURFACE_CONFIDENCE = 0.9

_TOOL_DESC_MESSAGE = (
    "A @Tool description carries instructions rather than describing the tool. The model reads "
    "this text as guidance, so it is a prompt-injection surface sitting in an annotation."
)
# Appended to the message above when, and only when, the Scan can say which
# Skill the annotated class reaches. The attachment site is named alongside any
# Skill name because the published spelling attaches tools to an already-built
# Skill, whose name was set in some other chain: `skill.toBuilder().tools(new
# OrderTools())` names no Skill at all, and a sentence that could only name one
# would stay silent on the very shape the Rule was reported against.
_TOOL_DESC_ATTRIBUTION = "The class {owner} is attached to {targets}."
_MCP_FILTER_MESSAGE = (
    "McpToolProvider is built without a filter or filterToolNames, so every tool the MCP server "
    "exposes reaches the agent rather than a scoped subset."
)
_WORKDIR_MESSAGE = (
    "RunShellCommandToolConfig is built without a workingDirectory, so commands run in the JVM's "
    "own working directory -- usually the application root."
)

# What a non-literal argument means depends on which one it is, so the Finding
# says so rather than making every unresolved argument read the same.
_UNRESOLVED_MESSAGES = {
    vocabulary.CONTENT_SETTER: (
        "Skill content is not statically resolvable, so the instruction surface the model reads "
        "was not scanned. It exists in no file this Scan could open."
    ),
    vocabulary.NAME_SETTER: (
        "The Skill name is built dynamically, so the Scan cannot say which Skill this definition "
        "declares."
    ),
    vocabulary.DESCRIPTION_SETTER: (
        "The Skill description is built dynamically, so the text that decides when this Skill "
        "activates was not scanned."
    ),
}
_UNRESOLVED_TOOLS_MESSAGE = (
    "A tool set is attached to this Skill without naming the classes it holds, so the Scan cannot "
    "say what capability the Skill was granted. The tools are assembled somewhere it cannot follow."
)
_UNRESOLVED_CONFIDENCE = 1.0

# The wiring is the decision; the declaration only puts the capability within
# reach. Both are HIGH -- an application that ships the shell module can reach
# shell mode -- but the wiring is the one there is nothing left to doubt about.
_WIRING_CONFIDENCE = 0.95
_DECLARATION_CONFIDENCE = 0.85

_WIRING_MESSAGE = (
    "LangChain4j shell mode is wired here: the agent is given a run_shell_command tool that "
    "executes arbitrary commands in the host process with no sandboxing or privilege restriction."
)


def _declaration_message(artifact_id: str) -> str:
    """The ``L4J-SHELL`` message for a build file that declares the shell module.

    Names the spelling *that build file* used rather than the inventoried one.
    The two are identical for every release published to date; they part company
    the day the artifact graduates out of ``experimental``, and a Finding naming
    an artifact id the reader cannot find in their own build file is a Finding
    they have to second-guess.
    """
    return (
        f"The build file declares {artifact_id}, putting LangChain4j's unsandboxed "
        "shell mode on the classpath where any wiring can reach it."
    )


def _finding(
    rule_id: str,
    path: str,
    start_line: int,
    message: str,
    confidence: float,
    severity: str = _SEVERITY,
) -> Finding:
    """Build one Finding for this Analyzer.

    Category, name, explanation and remediation are read from
    ``pattern_defaults`` rather than restated here. They are the same strings a
    report would fall back to anyway, and a second copy in this module would be
    free to drift from the catalogue the README and the AST10 crosswalk cite.
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
        explanation=get_explanation(rule_id),
        remediation=get_remediation(rule_id),
    )


def _content_pattern_modules() -> list[ModuleType]:
    """The static pattern modules that examine Skill instruction text.

    Derived from the registry rather than listed, so a pattern family added
    upstream examines resolved Java content too without anyone remembering to
    come back here. Imported lazily: the registry imports this module, so naming
    it at module top would close an import cycle.
    """
    from importlib import import_module  # noqa: PLC0415

    from skillspector.nodes.analyzers import ANALYZER_NODE_IDS  # noqa: PLC0415

    return [
        import_module(f"skillspector.nodes.analyzers.{node_id}")
        for node_id in ANALYZER_NODE_IDS
        if node_id.startswith("static_patterns_")
    ]


def _scan_resolved_content(
    path: str, source: str, skill_name: str | None, argument: BuilderArgument
) -> list[Finding]:
    """Run the content Analyzers over one resolved Skill body.

    The text is scanned under a synthetic ``<skill>/SKILL.md`` path, not under
    the Java file's, because that is what it *is*: a Skill declaration body. The
    static runner's file-type filters treat a ``SKILL.md`` differently from an
    unrecognized extension -- code-example downweighting, documentation-prose
    exemptions -- so scanning it as Java would grade the same text on the wrong
    curve. The synthetic path never leaves this function.

    Each Finding is then relocated onto the Java file and line it really came
    from, so the report sends a reviewer to the source and SARIF points at a
    file that exists.

    A Finding whose matched text sits verbatim on that same raw line is dropped.
    Java sources are in ``file_cache`` and the ordinary static pass reads them,
    so a text block written inline is scanned twice -- once as Java, once as
    resolved content -- and reporting both would be the same string at the same
    location, twice. What survives is what reading the file directly would not
    have shown: text pulled from a constant declared elsewhere in the unit, or
    text whose escapes only become line structure once resolved.
    """
    from skillspector.nodes.analyzers.static_runner import run_static_patterns  # noqa: PLC0415

    body = argument.value
    if not body:
        return []
    synthetic_path = f"{skill_name or 'skill'}/SKILL.md"
    raw_lines = source.splitlines()

    relocated: list[Finding] = []
    for finding in run_static_patterns(
        {"components": [synthetic_path], "file_cache": {synthetic_path: body}},
        _content_pattern_modules(),
    ):
        java_line = argument.value_start_line + finding.start_line - 1
        raw_line = raw_lines[java_line - 1] if 0 < java_line <= len(raw_lines) else ""
        if finding.matched_text and finding.matched_text in raw_line:
            continue
        finding.file = path
        finding.start_line = java_line
        finding.end_line = None
        relocated.append(finding)
    return relocated


def _carries_instructions(text: str) -> bool:
    """Whether *text* reads as instructions to a model rather than as description.

    Judged by the content Rules already in the catalogue rather than by a new
    list of phrases here. "Instruction-like" is exactly the thing those Rules
    were written to recognize, and a second definition of it would drift from
    theirs and disagree with the report.
    """
    from skillspector.nodes.analyzers.static_runner import run_static_patterns  # noqa: PLC0415

    return bool(
        run_static_patterns(
            {"components": ["tool/SKILL.md"], "file_cache": {"tool/SKILL.md": text}},
            _content_pattern_modules(),
        )
    )


def _tool_desc_message(owner: str | None, attribution: Mapping[str, str]) -> str:
    """The ``L4J-TOOL-DESC`` message, attributed when the Scan can attribute it."""
    sentence = attribution.get(owner) if owner is not None else None
    return f"{_TOOL_DESC_MESSAGE} {sentence}" if sentence else _TOOL_DESC_MESSAGE


def _tool_attribution(java_sources: Mapping[str, str]) -> dict[str, str]:
    """Which Skill each attached tool class reaches, for the classes that is knowable for.

    Keyed by the class's simple name, valued by the sentence
    ``L4J-TOOL-DESC`` appends. A class absent from the mapping gets no
    attribution and the Rule reads exactly as it did before.

    A class is absent unless the Scan declares its simple name **exactly once**.
    That is the guard, and it is the reason this join exists at the Scan level
    rather than per file. ``.tools(new OrderTools())`` names a simple name, not a
    type: two packages may each declare an ``OrderTools``, and a join that
    ignored that would tell a reader the poisoned tool reaches a Skill it never
    reaches -- worse than the silence it replaced. Zero declarations is the same
    answer for the other reason ``docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`` §3.6
    gives: resolution stops at the edge of the Scan, and a class held in no
    scanned file is one this Scan cannot speak about. It also raises nothing
    there, because a class the Scan does not hold declares no annotation for
    ``L4J-TOOL-DESC`` to have reported in the first place.

    Several attachment sites for one unambiguous class are not ambiguity -- they
    are two true facts -- so all of them are named, ordered by path so a Finding
    does not read differently depending on which file the Scan opened first.
    """
    from skillspector.langchain4j import skill_definitions, tool_surface  # noqa: PLC0415

    declared: Counter[str] = Counter()
    attachments: dict[str, list[str]] = {}
    for path, source in sorted(java_sources.items()):
        declared.update(tool_surface.find_declared_types(source))
        for tools in skill_definitions.find_attached_tools(source):
            for type_name in tools.type_names:
                if type_name is None:
                    continue
                site = f"{path}:{tools.line}"
                attachments.setdefault(type_name, []).append(
                    f'the Skill "{tools.skill_name}" at {site}'
                    if tools.skill_name
                    else f"a Skill at {site}"
                )

    return {
        owner: _TOOL_DESC_ATTRIBUTION.format(owner=owner, targets=", ".join(dict.fromkeys(targets)))
        for owner, targets in attachments.items()
        if declared[owner] == 1
    }


def _tool_surface_findings(path: str, source: str, attribution: Mapping[str, str]) -> list[Finding]:
    """The three Rules over an application's tool wiring."""
    from skillspector.langchain4j import tool_surface  # noqa: PLC0415

    findings = [
        _finding(
            _TOOL_DESC_RULE_ID,
            path,
            annotation.line,
            _tool_desc_message(annotation.owner, attribution),
            _TOOL_SURFACE_CONFIDENCE,
            severity=_TOOL_SURFACE_SEVERITY,
        )
        for annotation in tool_surface.find_tool_annotations(source)
        if _carries_instructions(annotation.description)
    ]

    for rule_id, receiver, setters, message in (
        (
            _MCP_FILTER_RULE_ID,
            vocabulary.MCP_TOOL_PROVIDER,
            vocabulary.TOOL_FILTER_SETTERS,
            _MCP_FILTER_MESSAGE,
        ),
        (
            _WORKDIR_RULE_ID,
            vocabulary.SHELL_COMMAND_CONFIG,
            (vocabulary.WORKING_DIRECTORY_SETTER,),
            _WORKDIR_MESSAGE,
        ),
    ):
        findings.extend(
            _finding(
                rule_id,
                path,
                chain.line,
                message,
                _TOOL_SURFACE_CONFIDENCE,
                severity=_TOOL_SURFACE_SEVERITY,
            )
            for chain in tool_surface.find_chains_missing_setters(source, receiver, setters)
        )
    return findings


def _skill_definition_findings(path: str, source: str) -> list[Finding]:
    """``L4J-UNRESOLVED`` for what Java hides, content Findings for what it shows."""
    from skillspector.langchain4j import skill_definitions  # noqa: PLC0415

    findings: list[Finding] = []
    for definition in skill_definitions.find_skill_definitions(source):
        name_argument = definition.argument(vocabulary.NAME_SETTER)
        skill_name = name_argument.value if name_argument else None
        for argument in definition.arguments:
            if argument.value is None:
                findings.append(
                    _finding(
                        _UNRESOLVED_RULE_ID,
                        path,
                        argument.line,
                        _UNRESOLVED_MESSAGES[argument.setter],
                        _UNRESOLVED_CONFIDENCE,
                        severity=_UNRESOLVED_SEVERITY,
                    )
                )
            elif argument.setter == vocabulary.CONTENT_SETTER:
                findings.extend(_scan_resolved_content(path, source, skill_name, argument))

    # A loader whose path is not a literal is the same silence in another shape:
    # the Skills it reads are not in view, and no content Analyzer saw them.
    for call in skill_definitions.find_skill_loader_calls(source):
        if call.directory is None:
            findings.append(
                _finding(
                    _UNRESOLVED_RULE_ID,
                    path,
                    call.line,
                    (
                        f"{call.loader}.{call.method} is called with a path that is not a literal, "
                        "so the Skills it loads were not located or scanned."
                    ),
                    _UNRESOLVED_CONFIDENCE,
                    severity=_UNRESOLVED_SEVERITY,
                )
            )

    # A third shape of the same silence. `L4J-TOOL-DESC` already reads every
    # `@Tool` annotation in a scanned file, so a tool class written out in full
    # is examined wherever it sits -- what is unreadable is a tool set assembled
    # at runtime, where the Scan cannot say what capability the Skill was given.
    for tools in skill_definitions.find_attached_tools(source):
        if tools.opaque:
            findings.append(
                _finding(
                    _UNRESOLVED_RULE_ID,
                    path,
                    tools.line,
                    _UNRESOLVED_TOOLS_MESSAGE,
                    _UNRESOLVED_CONFIDENCE,
                    severity=_UNRESOLVED_SEVERITY,
                )
            )
    return findings


def _planned_target(path: str) -> PlannedWorkTarget:
    """The work target for one inspected file, keyed exactly as its event will be.

    Derived from the same ``(analyzer_id, path, start_line, end_line)`` tuple the
    event's ``work_id`` comes from, so status and ledger cannot drift into the
    unaccounted-work error ``finalize_ledger`` raises when they disagree.
    """
    return {
        "work_id": inspection_work_id(ANALYZER_ID, path, None, None),
        "path": path,
        "start_line": None,
        "end_line": None,
    }


def _decline() -> AnalyzerNodeResponse:
    """Return the empty response a Framework-mismatched Analyzer declines with.

    Decline is now this one case. A LangChain4j Scan never reaches here: when
    there is nothing applicable it reports ``not_applicable`` instead, which
    states something that happened rather than saying nothing.
    """
    return {"findings": []}


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Report what this Analyzer opened on a LangChain4j Scan; decline on any other."""
    if state.get("framework") != Framework.LANGCHAIN4J:
        return _decline()

    file_cache: Mapping[str, str] = state.get("file_cache") or {}

    # Applicability, second and last gate, and the one predicate the accounting
    # below is derived from. A Component this Analyzer opens is a Java
    # compilation unit or a JVM build file; a LangChain4j tree holding neither
    # -- Skills reached through the classpath layout, or a Kotlin-only import --
    # is one it opens nothing in.
    #
    # It says so rather than falling silent. Silence here is the confusion the
    # Inspection Ledger exists to eliminate, on exactly the input it was built
    # to disambiguate: a reader could not tell whether the Analyzer ran and
    # approved the repository or never engaged with it. ADR 0002's silence is
    # for the Framework mismatch above, where there is no planned work at all;
    # ADR 0006 closes the deferral it left open here.
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

    # Narrowed from the same result the gate tested, never recomputed from
    # `file_cache`: two definitions of "applicable" eight lines apart are what
    # ADR 0006 exists to prevent recurring.
    java_sources = signals.java_sources(applicable)
    shell_declarations = signals.shell_artifact_declarations(applicable)

    # Every file opened gets a row, whether or not it yielded a Finding: once
    # this Analyzer runs, an absence of Findings must be distinguishable from an
    # absence of inspection.
    inspected: dict[str, list[Finding]] = {path: [] for path in applicable}

    # The parser enters here and nowhere earlier. At module top an absent
    # tree-sitter would break importing the analyzer registry itself; inside the
    # node it reaches `guard_analyzer_node`, which records the Analyzer as
    # `failed` with a fatal ledger exception -- so the Scan exits non-zero and
    # says why, rather than reporting an empty Finding list as a clean result.
    # It is deliberately not wrapped: swallowing the ImportError here is exactly
    # the silent failure this ordering exists to prevent.
    from skillspector.langchain4j import shell_skills  # noqa: PLC0415

    # Built once, from every Java source at once, because it is the one question
    # here a single compilation unit cannot answer: the `.tools(...)` call that
    # grants a tool class and the `@Tool` annotation inside it are ordinarily in
    # different files.
    attribution = _tool_attribution(java_sources)

    for path, source in java_sources.items():
        usage_line = shell_skills.find_shell_skills_usage(source)
        if usage_line is not None:
            inspected[path].append(
                _finding(_RULE_ID, path, usage_line, _WIRING_MESSAGE, _WIRING_CONFIDENCE)
            )
        inspected[path].extend(_skill_definition_findings(path, source))
        inspected[path].extend(_tool_surface_findings(path, source, attribution))

    # Indexed rather than `setdefault`: a declaring build file is an applicable
    # file, so it already has a row. A KeyError here would mean the two had
    # drifted apart again.
    for path, declaration in shell_declarations.items():
        inspected[path].append(
            _finding(
                _RULE_ID,
                path,
                declaration.line,
                _declaration_message(declaration.artifact_id),
                _DECLARATION_CONFIDENCE,
            )
        )

    ordered = sorted(inspected.items())
    events = [
        ledger_event(
            analyzer_id=ANALYZER_ID,
            outcome=LedgerOutcome.COMPLETED,
            phase="static",
            path=path,
            emitted_finding_ids=[finding.finding_id for finding in findings],
        )
        for path, findings in ordered
    ]
    findings = [finding for _path, file_findings in ordered for finding in file_findings]

    logger.info("%s: %d findings across %d files", ANALYZER_ID, len(findings), len(ordered))
    return {
        "findings": findings,
        "inspection_ledger": events,
        "analyzer_status_events": [
            analyzer_status_event(
                analyzer_id=ANALYZER_ID,
                status=AnalyzerStatus.COMPLETED,
                planned_work=[_planned_target(path) for path, _findings in ordered],
            )
        ],
    }
