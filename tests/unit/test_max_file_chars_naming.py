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

"""The per-file analysis cap is named ``MAX_FILE_CHARS``, everywhere it is named.

The constant was renamed from ``MAX_FILE_BYTES`` when its meaning changed from
bytes to characters. The rename came with a guard -- ``test_skip_log_reports_char_metric``
in ``tests/nodes/analyzers/test_static_runner_filtering.py`` -- but that guard
reads one log message, so prose was free to keep the retired name. It did, in
``README.md`` and in ``input_handler.py``, for as long as it took someone to
audit the two against the source (issue #42).

The unit is why the drift mattered rather than merely read badly. A character
count and a byte count are the same number only for ASCII: 1 000 000 CJK
characters occupy roughly 3 MB, so a reader told the cap is "1 MB" has been told
the wrong thing about which files a Scan reads, not just the wrong name.

**What this guard therefore does not catch.** It matches the retired *name*, and
the unit rides along only because the two went wrong together. Prose reading
``MAX_FILE_CHARS`` (1 MB)`` passes clean, and no cheap textual rule separates
that from the legitimate prose that compares the two units side by side -- which
is what ``README.md`` and ``input_handler.py`` now do deliberately. Guarding the
unit is a reading, not a match.

**The spelling is now a homonym.** Upstream reintroduced ``MAX_FILE_BYTES`` after
the fork's merge-base, for a genuinely different cap: the *read* cap in
``constants.py``, compared against ``file_path.stat().st_size`` in
``build_context.py``. That is bytes on disk, so the name is right there. The two
modules are therefore exempt by call site, with ``TestReadCap`` asserting the
reason still holds -- the guard reports the retired spelling used for the
*analysis* cap, which is what it always meant.

**Scope.** Tracked ``.md`` and ``.py`` files, which is where a Python constant
is named. A mention in a build file, a workflow or a notebook is not caught, and
a file that cannot be read or decoded as UTF-8 is skipped rather than reported --
``TestScope`` asserts the corpus is large enough that a wholesale read failure
cannot pass as a clean sweep, but a single unreadable file would go unnoticed.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterable
from functools import cache
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

_RETIRED_NAME = "MAX_FILE_BYTES"
_CURRENT_NAME = "MAX_FILE_CHARS"

# Where the live constant is defined. Named here rather than inline in the
# failure message so ``TestScope`` can prove the reference has not gone stale --
# an unguarded path inside the guard against stale references is the defect
# this module exists to catch.
_CAP_MODULE = "src/skillspector/nodes/analyzers/static_runner.py"

# Where the homonym lives: upstream's read cap, which the failure message names
# so a reader is not told the retired spelling has no legitimate use left.
_READ_CAP_MODULE = "src/skillspector/constants.py"

_SEARCHED_SUFFIXES = (".md", ".py")

# The files that may write the retired name, in two groups with two reasons.
#
# ``test_static_runner_filtering.py`` holds the assertion that the skip log does
# *not* say it -- the guard the rename shipped with. This module is the guard's
# own home: it names the retired spelling in order to retire it, the way
# ``vocabulary.py`` is excluded from the LangChain4j spelling guard.
_GUARD_EXEMPT: tuple[str, ...] = ("tests/unit/test_max_file_chars_naming.py",)

# Upstream reused the retired spelling for a different cap, so the name is now a
# homonym rather than drift. ``MAX_FILE_BYTES`` in these two modules is the
# *read* cap -- ``file_path.stat().st_size``, genuinely bytes on disk -- which
# upstream introduced after the fork's merge-base and named correctly. The
# exemption is by call site rather than by dropping the guard, which is how this
# repository handles a homonym spelling.
#
# ``TestReadCap`` is the control: these modules must not also name the analysis
# cap, because a fork edit that brought that meaning here is the drift the guard
# exists to catch and the exemption would otherwise hide it.
_READ_CAP_EXEMPT: tuple[str, ...] = (
    "src/skillspector/constants.py",
    "src/skillspector/nested_artifacts.py",
    "src/skillspector/nodes/build_context.py",
)

# The exemption is per file rather than per assertion, so a *second* occurrence
# inside an exempt file would not be reported. ``TestScope`` asserts each still
# contains the name, so an exemption that has outlived its file fails the build
# rather than silently widening what the guard permits.
_EXEMPT: tuple[str, ...] = _GUARD_EXEMPT + _READ_CAP_EXEMPT


@cache
def _tracked_files() -> tuple[str, ...]:
    """Every tracked ``.md`` and ``.py`` path, relative to the repository root.

    Read from ``git ls-files`` rather than a filesystem walk so a generated
    report, a virtualenv or a local scratch file cannot fail an unrelated
    change. Paths come back with forward slashes on every platform, which is
    what ``_EXEMPT`` is written in.

    Cached: four tests ask for the corpus and two of them read every file in it.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return tuple(
        path
        for path in result.stdout.split("\0")
        if path.endswith(_SEARCHED_SUFFIXES) and path not in _EXEMPT
    )


def naming_drift(paths: Iterable[str], root: Path = _REPO_ROOT) -> list[str]:
    """Every ``path:line`` under *root* that writes the retired constant name."""
    reported: list[str] = []
    for path in paths:
        try:
            content = (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(content.splitlines(), start=1):
            if _RETIRED_NAME in line:
                reported.append(
                    f"{path}:{number} writes {_RETIRED_NAME}, which no longer names the "
                    f"per-file analysis cap. That cap is {_CURRENT_NAME} in {_CAP_MODULE}, "
                    "and it counts characters of decoded text. The one thing "
                    f"{_RETIRED_NAME} still names is the read cap in {_READ_CAP_MODULE}, "
                    "which is bytes on disk -- use that spelling only for that cap."
                )
    return reported


class TestScope:
    """The guard covers what it claims to, so a pass is not vacuous."""

    def test_the_searched_corpus_is_not_empty(self) -> None:
        # A `git ls-files` that returned nothing -- wrong cwd, no repository --
        # would make the assertion below pass while reading no file at all.
        assert len(_tracked_files()) > 100

    def test_the_current_name_is_present_in_the_corpus(self) -> None:
        # The positive control for the sweep: the same corpus that yields no
        # retired name does yield the one that replaced it. Read strictly rather
        # than through `naming_drift`, which swallows an unreadable file -- a
        # control that tolerated the same failure would prove less than it looks.
        found = [
            path
            for path in _tracked_files()
            if _CURRENT_NAME in (_REPO_ROOT / path).read_text(encoding="utf-8")
        ]
        assert len(found) >= 5, f"expected the live constant to be named widely, found {found}"

    def test_the_referenced_definition_still_defines_the_cap(self) -> None:
        # The failure message sends a reader to this file. If it moves, the
        # guard against stale references starts carrying one.
        content = (_REPO_ROOT / _CAP_MODULE).read_text(encoding="utf-8")
        assert f"{_CURRENT_NAME} = " in content, (
            f"{_CAP_MODULE} no longer defines {_CURRENT_NAME} -- update _CAP_MODULE."
        )

    @pytest.mark.parametrize("path", _EXEMPT)
    def test_every_exemption_still_writes_the_retired_name(self, path: str) -> None:
        content = (_REPO_ROOT / path).read_text(encoding="utf-8")
        assert _RETIRED_NAME in content, (
            f"{path} no longer writes {_RETIRED_NAME}, so its exemption permits drift it was "
            "never meant to cover -- drop the entry from _EXEMPT."
        )

    def test_a_file_writing_the_retired_name_is_reported(self, tmp_path: Path) -> None:
        drifted = tmp_path / "README.md"
        drifted.write_text(
            f"The per-file 1 MB analysis cap (`{_RETIRED_NAME}`) is downstream.\n",
            encoding="utf-8",
        )
        reported = naming_drift(["README.md"], root=tmp_path)
        assert len(reported) == 1
        assert "README.md:1" in reported[0]
        assert _CURRENT_NAME in reported[0]

    def test_a_file_writing_the_current_name_is_not_reported(self, tmp_path: Path) -> None:
        # The control for the control: the search matches the retired spelling,
        # not any mention of the cap.
        clean = tmp_path / "README.md"
        clean.write_text(f"The per-file analysis cap is `{_CURRENT_NAME}`.\n", encoding="utf-8")
        assert naming_drift(["README.md"], root=tmp_path) == []


class TestReadCap:
    """The homonym exemption covers upstream's read cap and nothing wider."""

    @pytest.mark.parametrize("path", _READ_CAP_EXEMPT)
    def test_the_read_cap_modules_do_not_name_the_analysis_cap(self, path: str) -> None:
        # The discriminator for the exemption. These modules are allowed the
        # retired spelling because the only cap they name is the read cap. A fork
        # edit that brought the analysis cap here would make the exemption hide
        # exactly the drift this module exists to report.
        content = (_REPO_ROOT / path).read_text(encoding="utf-8")
        assert _CURRENT_NAME not in content, (
            f"{path} now names {_CURRENT_NAME} as well, so its exemption no longer covers "
            f"only the read cap -- move the {_CURRENT_NAME} usage out or drop the exemption."
        )

    def test_the_read_cap_is_a_byte_count_of_the_file_on_disk(self) -> None:
        # The reason the spelling is correct there rather than merely tolerated.
        # If upstream's cap stops measuring bytes on disk, the homonym stops
        # being legitimate and the exemption stops being the right resolution.
        content = (_REPO_ROOT / "src/skillspector/nodes/build_context.py").read_text(
            encoding="utf-8"
        )
        assert f"file_path.stat().st_size > {_RETIRED_NAME}" in content, (
            f"{_RETIRED_NAME} is no longer compared against a size on disk, so it is no "
            "longer a read cap -- revisit _READ_CAP_EXEMPT."
        )


class TestSingleName:
    """No tracked prose or source outside the two exemptions names the retired constant."""

    def test_the_retired_name_appears_nowhere(self) -> None:
        assert naming_drift(_tracked_files()) == []
