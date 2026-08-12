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

"""Every redistributed dependency the distribution declares is named in the notices.

``THIRD_PARTY_NOTICES.md`` is hand-maintained and read by nothing else, so a
dependency added to ``pyproject.toml`` without its entry used to be caught by
nobody -- see issue #102, which is the second time the file drifted.

The comparison is by **set membership** on normalised names, not by substring:
``tree-sitter`` is a substring of ``tree-sitter-java``, so a containment check
still passes after the ``tree-sitter`` entry is deleted.

Each declaration is compared against **its own** section of the notices, so that
neither comparison sees the other's names as stale entries:

- ``project.dependencies`` against ``## Runtime Dependencies``.
- every disclosed extra of ``project.optional-dependencies`` against its
  ``## Optional Dependencies (<extra> extra)`` section -- issue #109. Asking for
  such an extra is how a consumer obtains capability the distribution provides,
  so §4 disclosure reaches it. An extra may compose another with a
  **self-reference** -- ``skillspector[mcp]``, the idiom ``dev`` already uses --
  and that names another extra of this same distribution rather than a third
  party, so no section owes it an entry; the composed extra's own section
  discloses what it pulls in.

Which extras those are is **read out of the notices**, not listed here: the
sections present in ``THIRD_PARTY_NOTICES.md`` are the disclosed set, and the
per-extra comparisons are generated from them. An extra the disclosure policy
keeps out -- ``dev``, which declares tooling for working *on* this project
rather than capability a consumer installs to *use* the distribution -- has no
section and is named in ``_NOT_REDISTRIBUTED_EXTRAS`` instead. The two places
are **exclusive**, and either error fails: an extra in neither ships
undisclosed, and an extra in both carries a section contradicting the record
that says it has none. Passing therefore takes exactly one of writing the
section -- which is what generates the comparisons -- or recording the exclusion
explicitly; silence alone no longer passes, which is the shape of the gap #109
itself was filed for, and doing both is not a cautious way to satisfy it.

Every section is located by the **line index** of the heading that opens it, and
a duplicated heading is rejected outright: every reader here takes the first
match, so entries under a second copy of a heading would be compared against
nothing and would escape both directions at once.

Every comparison covers **directly declared** names only, which is the
granularity the notices file has always used: it discloses what this
distribution declares. What each of those names in turn pulls in is resolved by
the installer, varies with resolver, lockfile and platform, and is disclosed by
that dependency's own notices. The distribution's own name is the one declared
name that is not disclosed, for the same reason: it is not a third party, and
what it composes is disclosed by the section of the extra it names.

Dropping it also settles what the stale direction makes of a ``### skillspector``
entry. Under an extra that composes another, that entry used to be *accepted* --
the self-reference was a declared name, so the entry read as disclosing it.
Subtracted, it is stale under every extra alike, so the distribution cannot end
up listed inside its own third-party notices.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_NOTICES = _REPO_ROOT / "THIRD_PARTY_NOTICES.md"

#: The heading that opens the section covering ``project.dependencies``.
_RUNTIME_HEADING = "## Runtime Dependencies"

#: The heading that opens a disclosed extra's section of the notices.
_EXTRA_HEADING = re.compile(r"^## Optional Dependencies \((?P<extra>[^)]+) extra\)$")

#: Extras the notices deliberately leave out, and the criterion for leaving one
#: out: the extra declares tooling for working *on* this project rather than
#: capability a consumer installs to *use* the distribution, so listing it would
#: overstate what the distribution contains. ``dev`` is the only such extra.
#:
#: This is a **disclosure policy, not a claim about installability**. The built
#: distribution publishes ``Provides-Extra: dev`` like any other extra, so
#: ``pip install skillspector[dev]`` resolves for anyone; what it resolves to is
#: the project's own toolchain, which is not part of what the distribution
#: delivers to a user of it.
_NOT_REDISTRIBUTED_EXTRAS = {"dev"}


def _normalise(name: str) -> str:
    """PEP 503 name normalisation: ``PyYAML`` and ``pyyaml`` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_names(requirements: list[str]) -> set[str]:
    """Strip the version specifier and any extras: ``langgraph-cli[inmem]>=0.4``."""
    return {_normalise(re.split(r"[><=!~\[; ]", req, maxsplit=1)[0]) for req in requirements}


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return data["project"].get("optional-dependencies", {})


def _declared_runtime_dependencies() -> set[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return _requirement_names(data["project"]["dependencies"])


def _declared_extras() -> dict[str, str]:
    """Normalised extra name -> the key ``pyproject.toml`` declares it under."""
    return {_normalise(extra): extra for extra in _optional_dependencies()}


def _distribution_name() -> str:
    """This distribution's own normalised name, read rather than hardcoded.

    The repository is ``SkillSpector-Polyglot`` while the distribution stays
    ``skillspector``; ``project.name`` is the one that appears in a requirement.
    """
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return _normalise(data["project"]["name"])


def _declared_extra_dependencies(extra: str) -> set[str]:
    key = _declared_extras().get(extra, extra)
    # An extra composes another by naming this distribution back --
    # ``skillspector[mcp]``, which ``dev`` already does. That is a third party
    # to nobody, and the extra it names is disclosed by its own section (or
    # recorded in ``_NOT_REDISTRIBUTED_EXTRAS``), so it owes no entry here.
    # Only extras get this: a self-reference in ``project.dependencies`` would
    # be circular and no installer resolves it, so the runtime comparison has
    # nothing to subtract.
    return _requirement_names(_optional_dependencies().get(key, [])) - {_distribution_name()}


def _notices_lines() -> list[str]:
    """One read of the notices; every line index below is an index into this."""
    return _NOTICES.read_text(encoding="utf-8").splitlines()


def _section_headings(lines: list[str]) -> list[tuple[str, int]]:
    """``(section key, line index)`` for every heading the comparisons read.

    The key is ``_RUNTIME_HEADING`` for the runtime section and the *normalised*
    extra name for an extra's section, so an extra's section is found by the
    name it discloses rather than by the literal spelling of its heading. A
    repeated key therefore means a duplicated section, which
    ``test_no_notices_section_heading_is_duplicated`` rejects.
    """
    headings: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        if line == _RUNTIME_HEADING:
            headings.append((_RUNTIME_HEADING, index))
        elif match := _EXTRA_HEADING.match(line):
            headings.append((_normalise(match.group("extra")), index))
    return headings


def _documented_extras() -> set[str]:
    """The normalised extras ``THIRD_PARTY_NOTICES.md`` gives a section to."""
    return {key for key, _ in _section_headings(_notices_lines()) if key != _RUNTIME_HEADING}


def _entries_under(lines: list[str], start: int) -> set[str]:
    """The ``###`` entries of the section opened at line ``start``."""
    # The list ends at the next top-level section.
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    return {
        _normalise(line.removeprefix("### ").strip())
        for line in lines[start:end]
        if line.startswith("### ")
    }


def _documented_dependencies(key: str) -> set[str]:
    lines = _notices_lines()
    starts = [index for heading, index in _section_headings(lines) if heading == key]
    if not starts:
        raise AssertionError(f"THIRD_PARTY_NOTICES.md carries no section for {key!r}.")
    return _entries_under(lines, starts[0])


def _documented_runtime_dependencies() -> set[str]:
    return _documented_dependencies(_RUNTIME_HEADING)


def _documented_extra_dependencies(extra: str) -> set[str]:
    return _documented_dependencies(extra)


def test_every_runtime_dependency_has_a_notices_entry() -> None:
    missing = _declared_runtime_dependencies() - _documented_runtime_dependencies()
    assert not missing, (
        f"pyproject.toml declares {sorted(missing)} as runtime dependencies with no "
        "entry in THIRD_PARTY_NOTICES.md. Read the license and copyright line from the "
        "installed dist-info, not from memory."
    )


def test_no_notices_entry_outlives_its_dependency() -> None:
    stale = _documented_runtime_dependencies() - _declared_runtime_dependencies()
    assert not stale, (
        f"THIRD_PARTY_NOTICES.md documents {sorted(stale)}, which pyproject.toml no "
        "longer declares as a runtime dependency."
    )


@pytest.mark.parametrize("extra", sorted(_documented_extras()))
def test_every_redistributed_extra_dependency_has_a_notices_entry(extra: str) -> None:
    missing = _declared_extra_dependencies(extra) - _documented_extra_dependencies(extra)
    assert not missing, (
        f"pyproject.toml declares {sorted(missing)} under the redistributed {extra!r} extra "
        f"with no entry in the 'Optional Dependencies ({extra} extra)' section of "
        "THIRD_PARTY_NOTICES.md. Read the license and copyright line from the installed "
        "dist-info, not from memory."
    )


@pytest.mark.parametrize("extra", sorted(_documented_extras()))
def test_no_redistributed_extra_notices_entry_outlives_its_dependency(extra: str) -> None:
    stale = _documented_extra_dependencies(extra) - _declared_extra_dependencies(extra)
    assert not stale, (
        f"THIRD_PARTY_NOTICES.md documents {sorted(stale)} under the {extra!r} extra, which "
        "pyproject.toml no longer declares there."
    )


def test_an_extra_composing_another_demands_no_entry_for_this_distribution() -> None:
    """A self-reference names another extra of this distribution, not a third party.

    ``dev`` carries the only self-reference in the tree -- ``skillspector[mcp]``
    -- and ``_requirement_names`` splits it at the ``[``, so without the
    subtraction the first *consumer-facing* extra written the same way would
    demand a ``### skillspector`` entry: the distribution listed inside its own
    third-party notices.
    """
    own = _distribution_name()
    key = _declared_extras().get("dev")
    raw = _requirement_names(_optional_dependencies().get(key, [])) if key else set()
    assert own in raw, (
        f"The 'dev' extra no longer declares a self-reference -- it was renamed, dropped, "
        f"or rewritten -- so {own!r} never reaches the subtraction and this test proves "
        "nothing. Re-anchor it on whichever extra composes another, or delete it along "
        "with the subtraction it covers."
    )

    declared = _declared_extra_dependencies("dev")
    assert own not in declared, (
        f"_declared_extra_dependencies keeps {own!r}, so an extra composing another "
        "would demand a notices entry for this distribution itself."
    )
    assert "pytest" in declared, (
        "The subtraction dropped a genuine third-party name from the same extra; it "
        "must remove the self-reference only."
    )


def test_no_notices_section_heading_is_duplicated() -> None:
    keys = [key for key, _ in _section_headings(_notices_lines())]
    duplicated = sorted({key for key in keys if keys.count(key) > 1})
    assert not duplicated, (
        f"THIRD_PARTY_NOTICES.md opens a section more than once for {duplicated}. Every "
        "comparison in this file reads the first heading that matches, so the entries "
        "under a second copy are compared against nothing: a name disclosed there is "
        "invisible to the missing-entry check and to the stale-entry check alike. Merge "
        "the duplicated sections into one."
    )


def test_every_declared_extra_is_disclosed_or_recorded_as_not_redistributed() -> None:
    declared = set(_declared_extras())
    documented = _documented_extras()
    classified = documented | _NOT_REDISTRIBUTED_EXTRAS
    undecided = declared - classified
    dropped = classified - declared
    both = documented & _NOT_REDISTRIBUTED_EXTRAS
    assert not undecided and not dropped and not both, (
        f"pyproject.toml declares the extras {sorted(declared)}; THIRD_PARTY_NOTICES.md "
        f"discloses {sorted(documented)} and this file records "
        f"{sorted(_NOT_REDISTRIBUTED_EXTRAS)} as kept out of the notices. Undecided: "
        f"{sorted(undecided)}. No longer declared: {sorted(dropped)}. Both disclosed and "
        f"recorded as kept out: {sorted(both)}. The per-extra comparisons above are "
        "generated from the sections the notices carry, so an extra in neither place would "
        "ship undisclosed with every comparison green, and an extra in both would carry a "
        "section contradicting the very record that says it has none. Every declared extra "
        "belongs to exactly one of the two. Decide whether the extra delivers capability to "
        "a consumer of the distribution. If it does, give it its own '## Optional "
        "Dependencies (<extra> extra)' section in THIRD_PARTY_NOTICES.md -- which is what "
        "generates its comparisons -- and name it in the 'Contributing, and keeping these "
        "docs true' row of README.md. If it instead declares tooling for working on this "
        "project, like 'dev', add it to _NOT_REDISTRIBUTED_EXTRAS and write no section; "
        "that constant records a disclosure policy, so do not put there an extra a consumer "
        "installs to use the distribution. Doing both is not the cautious answer: for an "
        "extra listed in _NOT_REDISTRIBUTED_EXTRAS, remove the section; for one that "
        "belongs in the notices, remove the line from the constant."
    )
