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

"""``AnalyzerStatus`` is the only home for a status an Analyzer reports.

Why the set has to be closed is #47. Why closing it needs a test of its own is
that ``mypy`` is configured and invoked by nothing here, so an annotation is
documentation: a typo passes every enforced check. Two things run instead --
``analyzer_status_event`` validating at runtime, and this module reading the
source.

**Scope of the assertion.** A spelling is caught where it is *used as a status*,
never merely where it is written. That distinction is the whole design.
``AnalyzerStatus`` and :class:`~skillspector.inspection_ledger.LedgerOutcome`
share the spellings ``completed`` and ``failed``, and ``inspection_ledger``
writes the outcome vocabulary as bare strings on purpose::

    outcome_counts = {"completed": 0, "skipped": 0, "failed": 0, "unaccounted": 0}
    outcome_name = str(matches[0].get("outcome", "failed"))

Both are correct code. A guard matching the spelling alone would flag them, so
this one reads three usage shapes instead:

1. the ``status=`` argument of an ``analyzer_status_event`` call,
2. an assignment to a name called ``status``,
3. a dict entry keyed ``"status"`` -- the hand-built event shape that produced
   the ``"unknown"`` fallback ``finalize_ledger`` still carries.

**What it therefore misses**, stated rather than left to be discovered: a status
routed through a differently named variable and not written at the call site, a
spelling embedded in a longer literal, and a status reaching the ledger from
outside ``src/skillspector``. Runtime validation covers the first two for
*invalid* values; for valid ones they are a style leak this guard does not see.

The consuming side is missed too: a set literal re-inlining the non-limiting
pair, as ``finalize_ledger`` once held, is not a status *usage* in any of the
three shapes. Reading set literals would catch it and would also flag any
future ``{"enabled", "disabled"}`` in an unrelated vocabulary, so
:class:`TestNonLimitingSubset` asserts that subset directly instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from skillspector.inspection_ledger import (
    NON_LIMITING_STATUSES,
    AnalyzerStatus,
    analyzer_status_event,
    finalize_ledger,
)

_SRC = Path(__file__).resolve().parents[2] / "src" / "skillspector"

# The factory every status is supposed to pass through, and the name a status
# is bound to when it is not written at the call site.
_FACTORY = "analyzer_status_event"
_STATUS = "status"

# The whole package, so a module that starts emitting statuses is guarded the
# moment it exists rather than when someone remembers to list it here. Reading
# is scoped by usage, not by file, which is what makes globbing safe.
_GUARDED_FILES: tuple[Path, ...] = tuple(sorted(_SRC.rglob("*.py")))

# Every module writing a status when #47 was picked up, relative to the package
# root. Named so a glob that silently stops matching fails loudly instead of
# guarding nothing.
_EMITTING_MODULES = frozenset(
    {
        "inspection_ledger.py",
        "llm_analyzer_base.py",
        "nodes/meta_analyzer.py",
        "nodes/analyzers/behavioral_ast.py",
        "nodes/analyzers/behavioral_taint_tracking.py",
        "nodes/analyzers/framework_langchain4j.py",
        "nodes/analyzers/mcp_least_privilege.py",
        "nodes/analyzers/mcp_rug_pull.py",
        "nodes/analyzers/mcp_tool_poisoning.py",
        "nodes/analyzers/semantic_developer_intent.py",
        "nodes/analyzers/semantic_quality_policy.py",
        "nodes/analyzers/semantic_security_discovery.py",
        "nodes/analyzers/static_yara.py",
    }
)


def _spellings() -> dict[str, str]:
    """Every status spelling, mapped to the member that declares it."""
    return {member.value: member.name for member in AnalyzerStatus}


def _callee(call: ast.Call) -> str:
    """The bare name a call invokes, through an attribute access or not."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


# The spellings of the *inspection completeness* vocabulary that ``AnalyzerStatus``
# does not declare. Upstream writes that vocabulary into a local named ``status``
# too -- ``report._analysis_completeness`` and ``cli._multi_skill_analysis_completeness``
# both do -- and it shares the spelling ``failed`` with this enum. The two are
# homonyms, so the discriminator is the company the spelling keeps: an expression
# offering ``complete`` or ``partial`` is choosing among completeness statuses,
# and no Analyzer Status expression can contain either. Scoping by that rather
# than exempting the whole module is what keeps a *real* leak in those files
# reportable -- the same resolution ``test_max_file_chars_naming`` uses for its
# own homonym.
_COMPLETENESS_ONLY_SPELLINGS = frozenset({"complete", "partial"})


def _is_completeness_vocabulary(expression: ast.AST) -> bool:
    """True when *expression* chooses among inspection-completeness statuses."""
    return any(
        isinstance(node, ast.Constant) and node.value in _COMPLETENESS_ONLY_SPELLINGS
        for node in ast.walk(expression)
    )


def _status_expressions(tree: ast.Module) -> list[ast.AST]:
    """Every expression this guard reads as an Analyzer Status."""
    expressions: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _callee(node) == _FACTORY:
            expressions.extend(keyword.value for keyword in node.keywords if keyword.arg == _STATUS)
        elif isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == _STATUS for target in node.targets
            ):
                expressions.append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == _STATUS and node.value:
                expressions.append(node.value)
        elif isinstance(node, ast.Dict):
            expressions.extend(
                value
                for key, value in zip(node.keys, node.values, strict=True)
                if isinstance(key, ast.Constant) and key.value == _STATUS
            )
    return expressions


def leaks(path: Path) -> list[str]:
    """Every status spelling *path* writes out instead of importing."""
    spellings = _spellings()
    reported: dict[tuple[int, int], str] = {}
    for expression in _status_expressions(ast.parse(path.read_text(encoding="utf-8"))):
        if _is_completeness_vocabulary(expression):
            continue
        for node in ast.walk(expression):
            if not isinstance(node, ast.Constant) or node.value not in spellings:
                continue
            # A status can be reached through more than one shape at once --
            # an assignment holding the call that carries it -- so a site is
            # keyed by position and reported once.
            reported[(node.lineno, node.col_offset)] = (
                f"{path.name}:{node.lineno} uses {node.value!r} as an Analyzer Status; "
                f"it belongs to skillspector.inspection_ledger.AnalyzerStatus."
                f"{spellings[node.value]} -- import it from there"
            )
    return [reported[position] for position in sorted(reported)]


class TestScope:
    """The guard covers what it claims to, so a pass is not vacuous."""

    def test_the_status_set_is_closed(self) -> None:
        # Asserted by value and in order rather than by count: an enum mutated
        # toward emptiness would make every assertion below pass for free,
        # because a guard with no spelling to match reports no leak.
        assert [member.value for member in AnalyzerStatus] == [
            "completed",
            "not_applicable",
            "degraded",
            "failed",
            "disabled",
            "unavailable",
        ]

    def test_every_emitting_module_is_guarded(self) -> None:
        guarded = {path.relative_to(_SRC).as_posix() for path in _GUARDED_FILES}
        assert _EMITTING_MODULES <= guarded, (
            f"the glob no longer reaches {sorted(_EMITTING_MODULES - guarded)}"
        )

    def test_a_status_argument_is_reported(self, tmp_path: Path) -> None:
        leaked = tmp_path / "argument.py"
        leaked.write_text(
            'analyzer_status_event(analyzer_id="a", status="completed")\n', encoding="utf-8"
        )
        reported = leaks(leaked)
        assert len(reported) == 1
        assert "COMPLETED" in reported[0]
        assert "argument.py:1" in reported[0]

    def test_a_conditional_status_argument_is_reported_once_per_branch(
        self, tmp_path: Path
    ) -> None:
        leaked = tmp_path / "conditional.py"
        leaked.write_text(
            "status = analyzer_status_event(\n"
            '    analyzer_id="a",\n'
            '    status="failed" if broken else "completed",\n'
            ")\n",
            encoding="utf-8",
        )
        # Two shapes reach the same two literals -- the call keyword and the
        # enclosing assignment. Deduplication is what keeps that at two.
        assert len(leaks(leaked)) == 2

    def test_a_status_bound_to_a_name_is_reported(self, tmp_path: Path) -> None:
        leaked = tmp_path / "bound.py"
        leaked.write_text('status = "degraded"\n', encoding="utf-8")
        assert "DEGRADED" in "".join(leaks(leaked))

    def test_a_hand_built_status_event_is_reported(self, tmp_path: Path) -> None:
        leaked = tmp_path / "handbuilt.py"
        leaked.write_text(
            'event = {"analyzer_id": "a", "status": "unavailable", "planned_work": []}\n',
            encoding="utf-8",
        )
        assert "UNAVAILABLE" in "".join(leaks(leaked))

    def test_the_outcome_vocabulary_is_not_reported(self, tmp_path: Path) -> None:
        # The control for the whole scoping decision: these two lines are
        # ``inspection_ledger``'s own ``LedgerOutcome`` handling, and a guard
        # matching the spelling instead of the usage would flag both.
        allowed = tmp_path / "outcomes.py"
        allowed.write_text(
            'outcome_counts = {"completed": 0, "skipped": 0, "failed": 0, "unaccounted": 0}\n'
            'outcome_name = str(matches[0].get("outcome", "failed"))\n',
            encoding="utf-8",
        )
        assert leaks(allowed) == []

    def test_the_completeness_vocabulary_is_not_reported(self, tmp_path: Path) -> None:
        # Upstream's own shape, verbatim in structure: a local named ``status``
        # choosing among ``complete``/``failed``/``partial``. ``failed`` is a
        # spelling this enum also declares, and reporting it would ask upstream
        # to import an Analyzer Status for a value that is not one.
        homonym = tmp_path / "completeness.py"
        homonym.write_text(
            'status = "failed" if not ok else "complete" if done else "partial"\n',
            encoding="utf-8",
        )
        assert leaks(homonym) == []

    def test_a_real_leak_beside_the_completeness_vocabulary_is_still_reported(
        self, tmp_path: Path
    ) -> None:
        # The control for the exemption above, and the reason it is scoped to the
        # expression rather than to the file: ``report.py`` and ``cli.py`` write
        # both vocabularies, so exempting either module wholesale would hide the
        # next genuine leak in it.
        mixed = tmp_path / "mixed.py"
        mixed.write_text(
            'status = "failed" if not ok else "complete" if done else "partial"\n'
            'event = analyzer_status_event(analyzer_id="a", status="degraded")\n',
            encoding="utf-8",
        )
        reported = leaks(mixed)
        assert len(reported) == 1
        assert "DEGRADED" in reported[0]
        assert "mixed.py:2" in reported[0]

    def test_an_unrelated_status_argument_is_not_reported(self, tmp_path: Path) -> None:
        # ``mcp_registry`` passes a registry server's own status under the same
        # keyword. Scoping by callee is what keeps that vocabulary separate.
        allowed = tmp_path / "registry.py"
        allowed.write_text(
            'entry = ServerEntry(name="s", status="unavailable")\n', encoding="utf-8"
        )
        assert leaks(allowed) == []


class TestSingleHome:
    """No module writes a status spelling instead of importing the member."""

    @pytest.mark.parametrize("path", _GUARDED_FILES, ids=lambda path: path.name)
    def test_no_module_writes_a_status_inline(self, path: Path) -> None:
        assert leaks(path) == []


class TestRuntimeValidation:
    """The factory rejects what the annotation only documents."""

    def test_an_undeclared_status_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="AnalyzerStatus"):
            analyzer_status_event(analyzer_id="behavioral_ast", status="complete")  # type: ignore[arg-type]

    def test_a_declared_spelling_becomes_its_member(self) -> None:
        event = analyzer_status_event(analyzer_id="behavioral_ast", status="completed")  # type: ignore[arg-type]
        assert event["status"] is AnalyzerStatus.COMPLETED

    def test_a_member_is_carried_through(self) -> None:
        event = analyzer_status_event(
            analyzer_id="behavioral_ast", status=AnalyzerStatus.NOT_APPLICABLE
        )
        assert event["status"] is AnalyzerStatus.NOT_APPLICABLE


class TestNonLimitingSubset:
    """The subset that leaves a Scan complete is drawn from the closed set."""

    def test_the_subset_names_the_two_non_limiting_members(self) -> None:
        assert NON_LIMITING_STATUSES == {
            AnalyzerStatus.COMPLETED,
            AnalyzerStatus.NOT_APPLICABLE,
        }

    def test_the_subset_is_proper(self) -> None:
        assert NON_LIMITING_STATUSES < set(AnalyzerStatus)

    @pytest.mark.parametrize(
        "status", sorted(set(AnalyzerStatus) - NON_LIMITING_STATUSES, key=lambda s: s.value)
    )
    def test_every_other_member_states_a_limitation(self, status: AnalyzerStatus) -> None:
        completeness, _ = finalize_ledger(
            {
                "components": [],
                "analyzer_status_events": [
                    analyzer_status_event(analyzer_id="behavioral_ast", status=status)
                ],
            }
        )
        assert completeness["limitations"] == [f"Analyzer behavioral_ast status: {status.value}."]
        assert completeness["is_complete"] is False

    @pytest.mark.parametrize("status", sorted(NON_LIMITING_STATUSES, key=lambda s: s.value))
    def test_a_member_of_the_subset_states_nothing(self, status: AnalyzerStatus) -> None:
        # The control for the assertion above, and the only test of the one
        # comparison this change altered -- ``finalize_ledger`` now reads a
        # ``str`` against a ``frozenset`` of members. Without it, a
        # finalization calling *every* status limiting would look just as
        # green.
        completeness, _ = finalize_ledger(
            {
                "components": [],
                "analyzer_status_events": [
                    analyzer_status_event(analyzer_id="behavioral_ast", status=status)
                ],
            }
        )
        assert completeness["limitations"] == []
        assert completeness["is_complete"] is True


class TestMalformedStatus:
    """``"unknown"`` is deliberately not a member -- the decision #47 asked for.

    Why it is not, and why raising was rejected, is recorded beside
    ``_MALFORMED_ANALYZER_STATUS`` in ``skillspector.inspection_ledger``. What
    follows is what the decision does.
    """

    def test_a_status_less_event_is_limiting_rather_than_fatal(self) -> None:
        completeness, _ = finalize_ledger(
            {
                "components": [],
                "analyzer_status_events": [{"analyzer_id": "behavioral_ast", "planned_work": []}],
            }
        )
        assert completeness["analyzer_statuses"][0]["status"] == "unknown"
        assert completeness["limitations"] == ["Analyzer behavioral_ast status: unknown."]
        assert completeness["is_complete"] is False
        assert completeness["execution_successful"] is True

    def test_the_fallback_is_not_a_declared_status(self) -> None:
        assert "unknown" not in {member.value for member in AnalyzerStatus}
