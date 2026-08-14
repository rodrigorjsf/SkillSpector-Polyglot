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

"""Which Components of a Scan the Deep Agents for JavaScript Analyzer opens.

One predicate, :func:`applicable_files`, and the narrowings taken from *its*
result. ``docs/adr/0006-langchain4j-applicability-is-what-it-opens.md`` is why
there is one rather than two: the gate tests this result for emptiness and the
planned work derives from the same result, so a Component the Analyzer opens is
always a Component it reports.

The file predicates mirror :mod:`skillspector.framework`'s rather than importing
them, for the reason :mod:`skillspector.deepagents.signals` states: detection
asks "is this tree Deep Agents for JavaScript at all"; this module asks "which of
its files do I open". The ``SKILL.md`` set is already a difference.

None of the three file kinds is Deep Agents vocabulary, so none of them is
inventoried in :mod:`skillspector.deepagents_js.vocabulary`. The module suffixes
and ``package.json`` move on the JavaScript ecosystem's clock, ``SKILL.md`` on
the Agent Skills specification's; ADR 0005 drew the same line for the Java suffix
and the Maven build file names.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

# Every suffix a Deep Agents for JavaScript application writes its host code in.
# ``.tsx`` is here because a host configuration is routinely built in the same
# module as a React entry point, and :mod:`skillspector.deepagents_js.parser`
# gives it the grammar that reads JSX.
MODULE_SUFFIXES: Final[tuple[str, ...]] = (
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".mjs",
    ".cjs",
)

# The manifest that can declare a Node dependency. Matched on basename at any
# depth: a JavaScript monorepo declares its dependencies in a workspace package's
# own ``package.json``, not only at the scan root.
_PACKAGE_MANIFEST: Final[str] = "package.json"

# The Agent Skills manifest. A Deep Agents Skill directory *is* an Agent Skills
# directory, and the ``name`` the shadowing Rule reads lives in its frontmatter.
_SKILL_MANIFEST: Final[str] = "SKILL.md"


def _basename(path: str) -> str:
    """Return the final segment of a component path.

    ``file_cache`` keys always use forward slashes -- ``build_context``
    normalizes them so they stay portable as dict keys and SARIF locations.
    """
    return path.rsplit("/", 1)[-1]


def is_module_source(path: str) -> bool:
    """Whether *path* names a JavaScript or TypeScript module."""
    return path.endswith(MODULE_SUFFIXES)


def is_package_manifest(path: str) -> bool:
    """Whether *path* names a file that can declare a Node dependency."""
    return _basename(path) == _PACKAGE_MANIFEST


def is_skill_manifest(path: str) -> bool:
    """Whether *path* names an Agent Skills manifest."""
    return _basename(path) == _SKILL_MANIFEST


def applicable_files(file_cache: Mapping[str, str]) -> dict[str, str]:
    """The Components this Analyzer opens, by path.

    Applicability is this one predicate: a JavaScript or TypeScript module, a
    ``package.json``, or an Agent Skills manifest.

    ``SKILL.md`` is in the set because the shadowing Rule confirms a duplicate
    Skill ``name`` across the sources of one ``skills`` list, and that name is in
    the manifest's frontmatter. ADR 0008 §3 decided it for the Python track and
    states the price, which is unchanged here: on a Scan whose Skill source paths
    cannot be mapped to disk -- the default backend being the likeliest case --
    every ``SKILL.md`` is still opened, still reported, and still yields no
    verdict.

    Reads ``file_cache`` rather than ``components`` on purpose: a component listed
    but unreadable has nothing to open.

    Named for the word the Ledger already uses: an Analyzer with none of these
    reports ``no_applicable_files``, so the code and the report describe
    applicability in one vocabulary rather than two.
    """
    return {
        path: content
        for path, content in file_cache.items()
        if is_module_source(path) or is_package_manifest(path) or is_skill_manifest(path)
    }
