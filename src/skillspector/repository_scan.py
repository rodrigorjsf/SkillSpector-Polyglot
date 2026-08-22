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

"""Finding every Skill inside a repository, for a Repository Scan.

A Repository Scan is one pass over a whole repository that finds every Skill
within it and Scans each. It exists because pointing the scanner at a repository
root does not fail visibly -- it succeeds wrongly. The root holds no `SKILL.md`,
so the entire tree Scans as one anonymous Skill with an empty Manifest, its
components spanning everything including compiled output, and a Risk Score
computed over that mixture. The report looks complete and is not.

Discovery here is deliberately convention-bound rather than exhaustive. It looks
under a fixed list of directory patterns, each matched as a **path suffix at any
depth**, so a multi-module repository declaring the same layout twice yields both
without any configuration. Inferring roots from the location of `pom.xml` or
`pyproject.toml` was considered and rejected as machinery ahead of need; the
`--repo-scan-root` flag covers a layout the list does not.

Nothing here runs unless `--repo-scan` is passed. An ordinary Scan does not call
into this module, which is what lets the JVM build directories below be skipped:
adding them to the ordinary walk's skip set would change `components` and the
Inspection Ledger's excluded-directory events for Scans that exist today.

One narrow exception, added by issue #39. `cli` calls `discover_skills` on a Scan
of a directory that declares no `SKILL.md` -- the fall-through that is about to
report the whole tree as one anonymous Skill -- purely to say how many Skills
`--repo-scan` would find, instead of naming both flags and leaving the reader to
guess which discovery rule matches their layout. It reads the tree and returns a
list; it does not touch `components`, the Ledger, the Manifest, the Findings or
the Risk Score, so the reason the paragraph above exists is untouched. A Scan of
a directory that *does* declare a Skill -- the overwhelmingly common input --
still never reaches this module.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from skillspector.logging_config import get_logger

# Imported rather than restated. A directory the ordinary walk refuses to read
# must not be searched for Skills either, and two copies of that list would
# drift apart the first time either was extended.
from skillspector.multi_skill import (
    MAX_MULTI_SKILL_RUNTIME_SECONDS,
    _DetectionBudget,
    _DetectionIncompleteError,
    _extract_skill_name,
    _has_skill_md,
)
from skillspector.nodes.build_context import _SKIP_DIRS

logger = get_logger(__name__)

# Where Skills conventionally live. Each is matched as a path suffix at any
# depth, so ``modules/billing/src/main/resources/skills`` matches the Maven
# pattern exactly as a root-level one does.
DISCOVERY_ROOTS: Final[tuple[str, ...]] = (
    "skills",
    "src/main/resources/skills",
    ".deepagents/skills",
    ".agents/skills",
)

# Skipped on this path and this path only. On the ordinary walk they would
# change `components` and the ledger's excluded-directory events for every
# existing Scan of a tree holding one, which the behavior gate forbids.
JVM_BUILD_DIRECTORIES: Final[frozenset[str]] = frozenset(
    {"target", "build", ".gradle", ".mvn", "out"}
)

# How far below the repository root discovery will walk. A bound rather than a
# tuning knob: it stops a symlinked or pathological tree from turning one Scan
# into an unbounded one, and it sits well past any real Skill layout.
MAX_DISCOVERY_DEPTH: Final[int] = 12


@dataclass(frozen=True)
class DiscoveredSkill:
    """One Skill found inside a repository."""

    path: Path
    relative_path: str
    name: str


def _hidden_directories_to_enter(roots: tuple[str, ...]) -> frozenset[str]:
    """The dot-directories discovery must descend into, read off *roots*.

    ``.deepagents/skills`` is unreachable if every dot-directory is skipped, so
    the exceptions are derived from the patterns themselves rather than listed
    again beside them -- adding a dotted pattern cannot then forget to add its
    exception.
    """
    return frozenset(root.split("/")[0] for root in roots if root.startswith(".") and "/" in root)


def _is_under_discovery_root(relative_path: str, roots: tuple[str, ...]) -> bool:
    """Whether *relative_path* is a discovery root or sits beneath one.

    Every ancestor is tested, and each pattern is matched as a whole path suffix
    -- so ``skills`` matches ``modules/a/skills`` but not ``my-skills``.
    """
    parts = relative_path.split("/")
    for depth in range(1, len(parts) + 1):
        ancestor = "/".join(parts[:depth])
        if any(ancestor == root or ancestor.endswith(f"/{root}") for root in roots):
            return True
    return False


def discover_skills(
    repository_root: Path,
    roots: tuple[str, ...] = DISCOVERY_ROOTS,
    max_depth: int = MAX_DISCOVERY_DEPTH,
) -> list[DiscoveredSkill]:
    """Every Skill inside *repository_root*, in path order.

    A directory is a Skill when it declares one -- it holds a ``SKILL.md`` -- and
    when it sits at or beneath one of *roots*. Both halves matter: the first
    alone would pick up a `SKILL.md` shipped as documentation or test data, and
    the second alone would report a directory that declares nothing.
    """
    if not repository_root.is_dir():
        return []

    enterable_hidden = _hidden_directories_to_enter(roots)
    skipped = _SKIP_DIRS | JVM_BUILD_DIRECTORIES
    discovered: list[DiscoveredSkill] = []
    # The same shared runtime ceiling multi-skill detection charges its manifest
    # reads against, because this walk calls the same two helpers. Discovery
    # stops at the deadline and reports what it found: a Repository Scan that
    # runs out of budget has fewer Skills to scan, not a traceback.
    clock = time.monotonic
    started_at = clock()
    budget = _DetectionBudget(
        started_at=started_at,
        deadline=started_at + MAX_MULTI_SKILL_RUNTIME_SECONDS,
        clock=clock,
    )

    for current, directory_names, _files in os.walk(repository_root):
        current_path = Path(current)
        relative = current_path.relative_to(repository_root)
        depth = 0 if relative == Path(".") else len(relative.parts)

        if depth >= max_depth:
            directory_names[:] = []
        else:
            directory_names[:] = sorted(
                name
                for name in directory_names
                if name not in skipped and (not name.startswith(".") or name in enterable_hidden)
            )

        if relative == Path("."):
            continue
        relative_path = relative.as_posix()
        if not _is_under_discovery_root(relative_path, roots):
            continue
        try:
            if not _has_skill_md(current_path, budget=budget):
                continue
            name = _extract_skill_name(current_path, budget=budget)
        except _DetectionIncompleteError:
            logger.warning(
                "Repository Scan discovery stopped at its runtime bound under %s",
                repository_root,
            )
            break
        discovered.append(
            DiscoveredSkill(
                path=current_path,
                relative_path=relative_path,
                name=name,
            )
        )

    logger.info("Repository Scan discovered %d Skills under %s", len(discovered), repository_root)
    return sorted(discovered, key=lambda skill: skill.relative_path)
