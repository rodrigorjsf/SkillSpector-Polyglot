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

"""Whether a later Skill source silently replaces a Skill in an earlier one.

Upstream states the substitution primitive in one sentence: *"Later sources
override earlier ones for skills with the same name (last one wins)"*
(``docs/references/deepagents-js-skills.md``). So
``skills: ["/skills/shared/", "/skills/personal/"]`` means a Skill named
``ticket-triage`` in the writable personal directory replaces the vetted one in
the shared library, and every later run reads the replacement. Nothing in a Scan
of either directory alone can see it -- the collision exists only in the source
*list*, which is host-side configuration.

**A confirmed collision, never the mere presence of two sources.** Layering is a
pattern upstream documents as intentional, so firing on
``len(skills) > 1`` would alert on correct configuration. ADR 0008 §3 rejected
that outright. Confirming means reading the ``name`` out of each source
directory's ``SKILL.md`` frontmatter, which is why the Analyzer's Applicability
reaches past JavaScript into every manifest in the Scan.

Mapping, and what it means when it fails
----------------------------------------

A configured Skill source path is relative to the **backend root**, not to the
Scan root, so the mapping is computed rather than assumed: it needs a
``FilesystemBackend`` whose ``rootDir`` resolved, and it is that root joined
with the configured path that names a prefix of this Scan's own Component paths.

Three things can stop it, and ADR 0008 §3 -- carried over by ADR 0009 --
separates them rather than treating them as one:

* **The root did not resolve.** ``new FilesystemBackend({ rootDir: process.cwd() })``.
  Resolution stopped, which is §1's boundary exactly, and the Analyzer reports
  ``DA-UNRESOLVED``.
* **The files are not on disk.** A ``StoreBackend``, or the default
  ``StateBackend`` written or omitted. Nothing failed to resolve here: the Scan
  read the configuration and what it read is that the Skills live in agent state.
  Reporting a boundary would contradict the invariant the rest of this package
  states three times -- *an absent argument is a configuration, not a boundary* --
  and would put a Finding on ``createDeepAgent({ model, skills })``, the shape
  the upstream tutorial teaches. It raises nothing.
* **The mapping lands nowhere.** The prefix is well formed and this Scan holds no
  manifest under it -- the backend roots outside the scanned tree, or the Scan is
  a subdirectory. No names were read, so no collision is confirmed, and an
  unconfirmed collision is not one.

In all three the Analyzer has still opened every ``SKILL.md`` and given each one
a Work Item. That is ADR 0006's rule and ADR 0008 §3's stated price: the
alternative would be reading those files without reporting them.

Provenance
----------

Captured from ``docs/references/deepagents-js-skills.md`` (upstream
<https://docs.langchain.com/oss/javascript/deepagents/skills>).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

import yaml

from skillspector.deepagents_js.host_config import AgentConfiguration

# The manifest field the override is keyed on, and the frontmatter fence it lives
# behind. Both are Agent Skills specification vocabulary rather than Deep Agents
# vocabulary -- see :mod:`skillspector.deepagents_js.vocabulary` -- so they are
# spelled here, beside the reader that needs them.
_NAME_FIELD: Final[str] = "name"
_FRONTMATTER_FENCE: Final[str] = "---"
_FRONTMATTER_END: Final[re.Pattern[str]] = re.compile(r"\n---\s*\n")


@dataclass(frozen=True)
class Shadowing:
    """One confirmed name collision between two of a call's Skill sources.

    *shadowed* is the earlier configured source and *shadowing* the later one, in
    the order the ``skills=[...]`` list was written -- which is the order that
    decides the outcome, so it is read from the list rather than from the
    filesystem. *loaded* is the manifest the agent ends up reading, named so the
    Finding can point at a file rather than only at a directory.
    """

    name: str
    shadowed: str
    shadowing: str
    loaded: str
    line: int


def find_shadowing(
    configuration: AgentConfiguration, manifests: Mapping[str, str]
) -> tuple[Shadowing, ...]:
    """Every Skill name one of this call's sources takes over from an earlier one.

    *manifests* is the Scan's ``SKILL.md`` Components by path, which is what the
    Analyzer's Applicability already opened.

    Returns nothing where the collision cannot be confirmed -- an unresolved or
    absent Skill list, no filesystem root, a root that did not resolve, or a
    mapping that lands on no manifest. Each of those is spelled out in the module
    docstring, and only the unresolved root is a boundary the Analyzer reports.

    One result per *shadowed* source rather than one per name, so three sources
    holding one name produce two Findings and a reviewer can accept one
    substitution without also accepting the other. It matches the per-path
    granularity ``DA-SKILL-WRITABLE`` chose for the same reason.
    """
    skills = configuration.skill_paths
    if skills is None or skills.unresolved:
        return ()
    root = configuration.filesystem_root
    if root is None or root.root is None:
        return ()

    named = [
        (source, _names_under(_prefix(root.root, source), manifests))
        for source in _configured_paths(skills.value)
    ]

    shadowings: list[Shadowing] = []
    for index, (source, names) in enumerate(named):
        for name in sorted(names):
            later = [
                (other_source, other_names[name])
                for other_source, other_names in named[index + 1 :]
                if name in other_names
            ]
            if not later:
                continue
            # Last one wins, so the source that decides is the final later one
            # rather than the next one along.
            winner, loaded = later[-1]
            shadowings.append(
                Shadowing(
                    name=name,
                    shadowed=source,
                    shadowing=winner,
                    loaded=loaded,
                    line=skills.line,
                )
            )
    return tuple(shadowings)


def _configured_paths(value: object) -> tuple[str, ...]:
    """The resolved Skill source paths, however the resolver spelled its result."""
    if not isinstance(value, tuple):
        return ()
    return tuple(path for path in value if isinstance(path, str))


def _prefix(root: str, source: str) -> str:
    """The Scan-relative path prefix a configured Skill source maps onto.

    Both halves are normalized to the shape ``file_cache`` keys use -- forward
    slashes, no leading ``./``, no leading or doubled separator -- and joined
    with a trailing separator, so the prefix matches a directory rather than a
    sibling whose name merely starts the same way.
    """
    segments = [
        segment
        for part in (root, source)
        for segment in part.replace("\\", "/").split("/")
        if segment not in ("", ".")
    ]
    return "".join(f"{segment}/" for segment in segments)


def _names_under(prefix: str, manifests: Mapping[str, str]) -> dict[str, str]:
    """The Skill names one source directory holds, mapped to the manifest each came from.

    Two manifests under one source declaring one name is a collision *inside* a
    source rather than across two, which is not what this Rule judges; the first
    in path order is kept so the result stays deterministic.
    """
    names: dict[str, str] = {}
    for path in sorted(manifests):
        if not path.startswith(prefix):
            continue
        name = _skill_name(manifests[path])
        if name is not None and name not in names:
            names[name] = path
    return names


def _skill_name(content: str) -> str | None:
    """The ``name`` an Agent Skills manifest declares, or ``None``.

    A manifest with no frontmatter fence, unparseable YAML, or no string ``name``
    contributes nothing rather than a placeholder. A placeholder shared by two
    such files would read as a collision, which is the direction that invents a
    Finding.

    Reads the cached content rather than a path, so the Analyzer confirms the
    collision from the same bytes its ledger row says it opened. That is also
    what makes it a **deliberate** third copy of the frontmatter shape rather
    than an oversight: ``build_context._parse_manifest`` and
    ``multi_skill._skill_name`` both take a ``Path`` and both read the whole
    Manifest, and folding the three together would mean editing two functions
    whose output is in every committed snapshot -- the diff this fork keeps
    append-only. Extract them only with a behavior-preserving change of its own.
    """
    if not content.startswith(_FRONTMATTER_FENCE):
        return None
    end = _FRONTMATTER_END.search(content[3:])
    if end is None:
        return None
    try:
        data = yaml.safe_load(content[3 : end.start() + 3])
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    name = data.get(_NAME_FIELD)
    return name if isinstance(name, str) else None
