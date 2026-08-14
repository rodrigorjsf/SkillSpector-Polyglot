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

"""``skillspector.deepagents_js.vocabulary`` is the only home for a JavaScript Deep Agents spelling.

Why the inventory exists is
``docs/adr/0009-tree-sitter-for-typescript-parsing.md``, which copies
``docs/adr/0005-langchain4j-upstream-vocabulary.md``'s argument a third time. Why
it needs a test of its own is that the property -- "this literal exists nowhere
else" -- has no behavioral manifestation, so no existing seam can observe it.

Read as source text rather than as imported values for the same reason: a
contributor writing ``"createDeepAgent"`` inline produces working code, and
nothing about the running system looks different.

**Scope of the sweep.** The whole of ``src/skillspector``, minus three files, and
each exclusion mirrors one the Python guard makes.

* This module's inventory is the home rather than a leak site.
* ``framework.py`` holds detection's own copy, which ADR 0008 made a deliberate
  second copy rather than a shared one, and it is where ``Framework.DEEPAGENTS_JS``
  lives.
* ``deepagents/vocabulary.py`` is the **Python** track's home. The two
  distributions are both named ``deepagents`` and share a dozen spellings, so
  each inventory necessarily writes literals the other owns. Folding them into one
  constant is what ADR 0005 forbids: the npm package and the PyPI package ship on
  different clocks, and a rename in one must not silently move the other's Rules.
  ``tests/unit/test_deepagents_vocabulary.py`` excludes this module reciprocally.

Every other module under ``deepagents_js/`` **is** swept, and passes by importing
its spellings rather than writing them.

**Scope of the assertion.** A spelling is caught when it is written as a literal
of its own -- the shape a matcher takes. A spelling embedded in a longer literal
is not caught, because a Finding message legitimately quotes an upstream name in
prose and containment cannot tell the two apart. Regex-escaped forms *are*
caught.

**Homonyms are exempt from the sweep by call site, not by spelling.** Four of the
inventory's spellings are ordinary English words this repository already writes
inline for reasons that have nothing to do with Deep Agents. Demanding those call
sites import a Deep Agents constant would be wrong rather than strict. Exempting
the *word* everywhere would be a hole sitting exactly where it matters, so the
exemption is scoped by call site and ``_DEEPAGENTS_JS_MODULES`` is where it does
not apply.

``_own_literals`` is imported from the LangChain4j guard rather than copied. "A
literal of its own" is one definition, and three AST readers of it would drift
into three guards that disagree about what a leak looks like.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from skillspector.deepagents_js import vocabulary
from tests.unit.test_langchain4j_vocabulary import _own_literals

_SRC = Path(__file__).resolve().parents[2] / "src" / "skillspector"

# The module under guard is excluded: it is the home, not a leak site.
_VOCABULARY = _SRC / "deepagents_js" / "vocabulary.py"

# Detection keeps its own copy, by ADR 0008. See the module docstring.
_DETECTION = _SRC / "framework.py"

# The Python track's inventory is its own home. See the module docstring: ADR
# 0009 keeps the two separate on purpose, and the Python guard excludes this
# module in the same way.
_PYTHON_VOCABULARY = _SRC / "deepagents" / "vocabulary.py"

_EXCLUDED: frozenset[Path] = frozenset({_VOCABULARY, _DETECTION, _PYTHON_VOCABULARY})

_GUARDED_FILES: tuple[Path, ...] = tuple(
    sorted(path for path in _SRC.rglob("*.py") if path not in _EXCLUDED)
)

# Released versions, not spellings a Rule matches on. Left out so the inventory
# stays derived from the module rather than restated here.
_NOT_A_SPELLING = frozenset({"OBSERVED_VERSION_RANGE"})

# Every spelling this inventory holds today, as an exact set. Asserted rather
# than counted loosely: a loop over a silently emptied inventory would pass every
# assertion below while guarding nothing.
#
# Two spellings the Python inventory carries are deliberately **absent** --
# ``FilesystemPermission`` and ``routes`` -- because the captured JavaScript
# reference publishes neither anywhere and its resolver reads a different shape
# for each. The vocabulary module's docstring records both;
# `TestTheTwoInventoriesDiffer` pins it here so a later "consistency" edit that
# adds one has to argue with a test.
#
# ``edit_file`` is deliberately **present**, and was once absent. Omitting it did
# not narrow the mitigation check, it widened it -- the gate is satisfied by a
# superset, so a smaller required set is easier to satisfy, and upstream's own
# published ``interruptOn`` block then read as a mitigation here and as none in
# the Python track. `TestTheTwoInventoriesDiffer` pins the shared pair.
_EXPECTED_SPELLINGS = {
    "createDeepAgent",
    "deepagents",
    "backend",
    "CompositeBackend",
    "StoreBackend",
    "StateBackend",
    "FilesystemBackend",
    "rootDir",
    "subagents",
    "operations",
    "paths",
    "deny",
    "interrupt",
    "interruptOn",
    "write_file",
    "edit_file",
    "skills",
    "permissions",
    "mode",
    "write",
}

# The four homonyms. Owned by the inventory, and skipped by the sweep everywhere
# except the modules below.
_HOMONYMS = {"skills", "permissions", "mode", "write"}

# Where a homonym is not a homonym: the package that reads the JavaScript host
# configuration and the Analyzer that drives it.
_ANALYZER = _SRC / "nodes" / "analyzers" / "framework_deepagents_js.py"
_DEEPAGENTS_JS_MODULES: tuple[Path, ...] = tuple(
    sorted(path for path in _GUARDED_FILES if path.is_relative_to(_SRC / "deepagents_js"))
) + (_ANALYZER,)


def _read_inventory(module: ModuleType = vocabulary) -> tuple[dict[str, str], list[str]]:
    """Every inventoried spelling by declaring constant, and what could not be read.

    The second return value is the point. A constant holding something this reader
    does not understand contributes no spelling, so nothing guards it -- and a
    guard that quietly covers less than it claims is worse than none.
    """
    spellings: dict[str, str] = {}
    unreadable: list[str] = []
    for constant, value in vars(module).items():
        if constant not in module.__annotations__ or constant in _NOT_A_SPELLING:
            continue
        if isinstance(value, str):
            members: tuple[object, ...] = (value,)
        elif isinstance(value, frozenset | tuple | set | list):
            members = tuple(value)
        else:
            unreadable.append(constant)
            continue
        held = [member for member in members if isinstance(member, str)]
        if not held:
            unreadable.append(constant)
        for member in held:
            spellings.setdefault(member, constant)
    return spellings, unreadable


def _spellings() -> dict[str, str]:
    """Every inventoried spelling, mapped to the constant that declares it."""
    return _read_inventory()[0]


def _swept_spellings(path: Path) -> dict[str, str]:
    """The inventory the sweep enforces in *path*."""
    spellings = _spellings()
    if path in _DEEPAGENTS_JS_MODULES:
        return spellings
    return {
        spelling: constant for spelling, constant in spellings.items() if spelling not in _HOMONYMS
    }


def leaks(path: Path, spellings: dict[str, str] | None = None) -> list[str]:
    """Every inventoried spelling *path* writes out instead of importing.

    *spellings* is injectable so the mutation proofs below can run the real reader
    against a planted inventory, rather than trusting that a guard which reports
    nothing is a guard that looked.
    """
    spellings = _swept_spellings(path) if spellings is None else spellings
    escaped = {re.escape(spelling): spelling for spelling in spellings}
    reported = []
    for line, literal in _own_literals(path):
        spelling = literal if literal in spellings else escaped.get(literal)
        if spelling is None:
            continue
        reported.append(
            f"{path.name}:{line} writes {literal!r} inline; it belongs to "
            f"skillspector.deepagents_js.vocabulary.{spellings[spelling]} -- import it from there"
        )
    return reported


class TestScope:
    """The guard covers what it claims to, so a pass is not vacuous."""

    def test_the_inventory_holds_exactly_the_spellings_it_claims(self) -> None:
        assert set(_spellings()) == _EXPECTED_SPELLINGS

    def test_every_declared_constant_is_readable(self) -> None:
        _found, unreadable = _read_inventory()
        assert unreadable == [], (
            f"{unreadable} hold no spelling this guard can read, so nothing guards them. "
            "The reader understands a string, or a tuple, set, list or frozenset of them "
            "-- teach _read_inventory to read the new shape."
        )

    def test_an_unreadable_constant_is_reported(self) -> None:
        # The control for the assertion above: without it, a reader that returned
        # an empty list unconditionally would look just as green.
        stub = ModuleType("stub_vocabulary")
        stub.__annotations__ = {"CALL": "Final[str]", "RETRY_LIMIT": "Final[int]"}
        stub.CALL = "createDeepAgent"
        stub.RETRY_LIMIT = 3

        spellings, unreadable = _read_inventory(stub)
        assert unreadable == ["RETRY_LIMIT"]
        assert spellings == {"createDeepAgent": "CALL"}

    def test_the_swept_set_names_the_analyzer_and_the_package(self) -> None:
        # Named by full path rather than by basename: `signals.py` and
        # `__init__.py` exist under `langchain4j/` and `deepagents/` too, so a
        # basename check would pass on a sweep that never reached this package.
        assert {
            _SRC / "nodes" / "analyzers" / "framework_deepagents_js.py",
            _SRC / "deepagents_js" / "signals.py",
            _SRC / "deepagents_js" / "parser.py",
            _SRC / "deepagents_js" / "__init__.py",
        } <= set(_GUARDED_FILES)

    def test_the_sweep_excludes_only_the_two_homes_and_detection(self) -> None:
        every = set(_SRC.rglob("*.py"))
        assert every - set(_GUARDED_FILES) == {_VOCABULARY, _DETECTION, _PYTHON_VOCABULARY}

    def test_the_python_package_is_swept_apart_from_its_inventory(self) -> None:
        """The exclusion is one file, not a package.

        Only the Python inventory is a second home; every module beside it writes
        its spellings by importing them, so each stays under this guard. Without
        this assertion the exclusion could quietly widen to the whole package and
        nothing would turn red.
        """
        package = _SRC / "deepagents"
        swept = {path for path in _GUARDED_FILES if path.is_relative_to(package)}
        assert swept == set(package.rglob("*.py")) - {_PYTHON_VOCABULARY}
        assert swept


def _every_rule_state() -> dict[str, object]:
    """A synthetic Scan whose one module fires all four Rules at once.

    Two calls rather than one, because a configuration whose ``permissions`` did
    not resolve has no writability verdict by design -- the boundary Rule and the
    verdict Rules partition a call rather than overlapping on it. The first call
    names two sources that both declare ``triage`` (``DA-SHADOW``), that no rule
    denies write to (``DA-SKILL-WRITABLE``), and one subagent defined without
    Skills of its own (``DA-SUBAGENT-SKILLS``). The second builds its permission
    rules in a helper the resolver will not follow (``DA-UNRESOLVED``).
    """
    from skillspector.framework import Framework

    module = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: "./library" });
export const agent = await createDeepAgent({
  backend,
  skills: ["/skills/shared/", "/skills/personal/"],
  subagents: [{ name: "reviewer", description: "d", systemPrompt: "p" }],
});
export const other = await createDeepAgent({
  backend,
  skills: ["/skills/shared/"],
  permissions: buildPermissions(),
});
"""
    manifest = "---\nname: triage\ndescription: A Skill.\n---\n\n# triage\n"
    return {
        "framework": Framework.DEEPAGENTS_JS,
        "file_cache": {
            "src/agent.ts": module,
            "library/skills/shared/triage/SKILL.md": manifest,
            "library/skills/personal/triage/SKILL.md": manifest,
        },
    }


class TestTheTwoInventoriesDiffer:
    """The JavaScript inventory is a measurement, not a copy of the Python one."""

    def test_the_two_python_only_spellings_are_absent(self) -> None:
        """Neither is published by the JavaScript capture, in code or in prose.

        The JavaScript resolver reads a plain object literal where the Python one
        reads a ``FilesystemPermission`` construction, and a positional route map
        where the Python one reads a ``routes=`` keyword. A later edit that
        "restores consistency" by adding one would be matching a spelling upstream
        never publishes in JavaScript, so it has to argue with this test first.
        """
        from skillspector.deepagents import vocabulary as python_vocabulary

        declared = set(_spellings())
        for spelling in (
            python_vocabulary.FILESYSTEM_PERMISSION,
            python_vocabulary.ROUTES,
        ):
            assert spelling not in declared

    def test_both_write_tools_are_shared_with_the_python_inventory(self) -> None:
        """``DA-SKILL-WRITABLE``'s mitigation gate asks the same question in both tracks.

        This is the direction the earlier revision got backwards. The gate is
        satisfied when a configuration gates *every* inventoried write tool, so
        dropping one makes the check **easier** to satisfy, not narrower -- and
        upstream's own published ``interruptOn`` block then cleared the Finding
        here while leaving it standing in Python. One rule id, one risk statement.
        """
        from skillspector.deepagents import vocabulary as python_vocabulary
        from skillspector.deepagents import writability as python_writability
        from skillspector.deepagents_js import writability as js_writability

        assert {vocabulary.WRITE_FILE, vocabulary.EDIT_FILE} == {
            python_vocabulary.WRITE_FILE,
            python_vocabulary.EDIT_FILE,
        }
        assert js_writability._WRITE_TOOLS == python_writability._WRITE_TOOLS

    def test_no_emitted_finding_names_a_python_only_spelling(self) -> None:
        """A Finding must not tell a TypeScript reader to construct a Python class.

        The four Rule ids are shared with the Python track, and so is the
        ``pattern_defaults`` catalogue they read their explanation and
        remediation from -- which is written in Python's syntax, because the
        Python track is what it was written for. Emitted verbatim here it names
        ``FilesystemPermission``, a class the JavaScript distribution does not
        export and which the captured reference records as appearing nowhere on
        the JavaScript page, and ``interrupt_on``, which that same capture
        annotates as an upstream *prose defect*.

        ``.claude/rules/license-compliance.md`` calls presenting one project's
        behavior as another's in a Finding message a §4 failure rather than a
        cosmetic one, which is why this is a guard and not a style note. It
        checks every field a reader sees, so an override that fixes the
        remediation and forgets the explanation still fails.
        """
        from skillspector.deepagents import vocabulary as python_vocabulary
        from skillspector.nodes.analyzers import framework_deepagents_js as js_analyzer

        python_only = (
            python_vocabulary.FILESYSTEM_PERMISSION,
            python_vocabulary.INTERRUPT_ON,
            python_vocabulary.CREATE_DEEP_AGENT,
            python_vocabulary.ROUTES,
            f"{vocabulary.SKILLS}=[",
            f"{vocabulary.MODE}=",
            f"{vocabulary.OPERATIONS}=",
        )
        findings = js_analyzer.node(_every_rule_state())["findings"]

        assert {finding.rule_id for finding in findings} == {
            "DA-UNRESOLVED",
            "DA-SKILL-WRITABLE",
            "DA-SHADOW",
            "DA-SUBAGENT-SKILLS",
        }
        for finding in findings:
            prose = f"{finding.message}\n{finding.explanation}\n{finding.remediation}"
            for spelling in python_only:
                assert spelling not in prose, (
                    f"{finding.rule_id} writes {spelling!r}, which is the Python track's "
                    "spelling; override the catalogue string in framework_deepagents_js"
                )

    def test_the_two_inventories_are_separate_objects(self) -> None:
        """Neither module imports the other, so a rename in one cannot move the other.

        The point of two inventories is that they can diverge. If this one ever
        re-exported the other's constants, an upstream rename on one distribution
        would silently retarget the other Framework's Rules -- the failure ADR 0005
        exists to prevent, arriving through the back door of a shared object.
        """
        from skillspector.deepagents import vocabulary as python_vocabulary

        assert vocabulary is not python_vocabulary
        assert vocabulary.CREATE_DEEP_AGENT != python_vocabulary.CREATE_DEEP_AGENT
        assert vocabulary.ROOT_DIR != python_vocabulary.ROOT_DIR
        assert vocabulary.INTERRUPT_ON != python_vocabulary.INTERRUPT_ON

    def test_the_measured_range_is_bounded_by_the_documented_skills_floor(self) -> None:
        """The range starts at the release upstream says Skills arrive in.

        Sweeping below it would measure the feature's absence rather than a
        rename, which is a different claim from the one this constant makes.
        """
        oldest, newest = vocabulary.OBSERVED_VERSION_RANGE
        assert oldest == "1.7.0"
        assert tuple(int(part) for part in newest.split(".")) > (1, 7, 0)


class TestHomonyms:
    """The exemption is scoped by call site, and only while the word is a homonym."""

    def test_every_homonym_is_inventoried(self) -> None:
        assert _HOMONYMS <= set(_spellings())

    def test_the_modules_are_the_ones_that_read_the_configuration(self) -> None:
        """Named by full path: a basename check would pass on a sweep of ``deepagents/``."""
        assert {
            _SRC / "deepagents_js" / "host_config.py",
            _SRC / "deepagents_js" / "parser.py",
            _SRC / "deepagents_js" / "signals.py",
            _SRC / "deepagents_js" / "skill_sources.py",
            _SRC / "deepagents_js" / "subagents.py",
            _SRC / "deepagents_js" / "writability.py",
            _SRC / "deepagents_js" / "__init__.py",
            _ANALYZER,
        } == set(_DEEPAGENTS_JS_MODULES)

    def test_a_module_of_the_package_is_held_to_the_whole_inventory(self) -> None:
        for path in _DEEPAGENTS_JS_MODULES:
            assert set(_swept_spellings(path)) == set(_spellings())

    def test_every_other_module_is_held_to_the_inventory_minus_the_homonyms(self) -> None:
        outside = next(path for path in _GUARDED_FILES if path not in _DEEPAGENTS_JS_MODULES)
        assert set(_swept_spellings(outside)) == set(_spellings()) - _HOMONYMS

    @pytest.mark.parametrize("spelling", sorted(_HOMONYMS))
    def test_a_homonym_really_occurs_inline_outside_the_enforced_set(self, spelling: str) -> None:
        """The evidence for the exemption, rather than the claim.

        If no unrelated module writes the word any more, the exemption is a hole
        rather than a homonym, and this is where that is noticed.
        """
        writers = [
            path
            for path in _GUARDED_FILES
            if path not in _DEEPAGENTS_JS_MODULES
            and any(literal == spelling for _line, literal in _own_literals(path))
        ]
        assert writers, (
            f"{spelling!r} is exempted from the sweep as a homonym, but no module outside the "
            "Deep Agents for JavaScript ones writes it inline any more. Drop it from _HOMONYMS "
            "so the guard enforces it everywhere like every other spelling."
        )

    @pytest.mark.parametrize("spelling", sorted(_HOMONYMS))
    def test_a_homonym_planted_in_a_package_module_is_still_reported(
        self, spelling: str, tmp_path: Path
    ) -> None:
        """The half a spelling-wide exemption would lose."""
        leaked = tmp_path / "host_config.py"
        leaked.write_text(f"ARGUMENT = {spelling!r}\n", encoding="utf-8")

        assert leaks(leaked) == []
        assert leaks(leaked, spellings=_swept_spellings(_ANALYZER))


class TestTheGuardFails:
    """Mutation proofs, in both directions."""

    def test_a_spelling_written_inline_is_reported(self, tmp_path: Path) -> None:
        leaked = tmp_path / "leaked.py"
        leaked.write_text(
            '"""A module whose docstring names createDeepAgent harmlessly."""\n'
            "CALL = 'createDeepAgent'\n",
            encoding="utf-8",
        )
        reported = leaks(leaked)
        assert len(reported) == 1
        assert "CREATE_DEEP_AGENT" in reported[0]
        assert "leaked.py:2" in reported[0]

    def test_a_regex_escaped_spelling_is_reported(self, tmp_path: Path) -> None:
        leaked = tmp_path / "escaped.py"
        leaked.write_text('CALL = re.compile(r"createDeepAgent")\n', encoding="utf-8")
        assert "CREATE_DEEP_AGENT" in "".join(leaks(leaked))

    def test_an_emptied_inventory_reports_nothing_and_fails_the_scope_test(
        self, tmp_path: Path
    ) -> None:
        """The direction a count assertion alone would miss."""
        leaked = tmp_path / "leaked.py"
        leaked.write_text("CALL = 'createDeepAgent'\n", encoding="utf-8")

        assert leaks(leaked, spellings={}) == []

        empty = ModuleType("empty_vocabulary")
        empty.__annotations__ = {}
        assert set(_read_inventory(empty)[0]) != _EXPECTED_SPELLINGS


class TestSingleHome:
    """No module outside the inventory writes a JavaScript Deep Agents spelling."""

    @pytest.mark.parametrize("path", _GUARDED_FILES, ids=lambda path: str(path))
    def test_no_module_writes_a_spelling_inline(self, path: Path) -> None:
        assert leaks(path) == []


class TestParserFree:
    """The gate is decided before tree-sitter is ever imported.

    The registry imports every Analyzer module on every Scan, including the ones
    that decline. So the modules on that import path -- the Analyzer itself and
    the ``signals`` predicate it gates on -- must not reach the native parser,
    or a Scan of an ordinary Agent Skill pays for a dependency it never uses.
    The Analyzer states the ordering and imports ``host_config`` and ``parser``
    inside the functions that need them, under ``# noqa: PLC0415``; nothing
    enforced it, which is an invitation to a later cleanup that hoists the
    import back to the top.

    ``tests/unit/test_langchain4j_vocabulary.py`` has the same guard and does
    **not** cover this: its three assertions name only that package's inventory,
    ``skillspector.framework`` and its own control, and ``framework`` imports
    nothing that reaches ``skillspector.nodes.analyzers``.
    """

    @staticmethod
    def _imports_tree_sitter(module: str) -> bool:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                f"import importlib, sys; importlib.import_module('{module}'); "
                "print('tree_sitter' in sys.modules)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() == "True"

    def test_importing_the_analyzer_registry_does_not_import_the_parser(self) -> None:
        assert not self._imports_tree_sitter("skillspector.nodes.analyzers")

    def test_importing_the_applicability_predicate_does_not_import_the_parser(self) -> None:
        assert not self._imports_tree_sitter("skillspector.deepagents_js.signals")

    def test_importing_the_inventory_does_not_import_the_parser(self) -> None:
        assert not self._imports_tree_sitter("skillspector.deepagents_js.vocabulary")

    def test_a_resolver_module_does_import_the_parser(self) -> None:
        # The control. Without it the three assertions above would also pass if
        # the subprocess never imported anything at all.
        assert self._imports_tree_sitter("skillspector.deepagents_js.host_config")
