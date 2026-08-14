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

"""Whether a Deep Agents for JavaScript agent can rewrite the Skill files it was given.

One question, asked once per resolved Skill source path, over the three settings
upstream says decide it: *"By default, agents can write to skill files if the
backend permits it and no permission rule blocks the path"*
(``docs/references/deepagents-js-skills.md``). So the unsafe configuration is the
one a developer gets by following the tutorial, and ADR 0008 §2 -- carried over by
``docs/adr/0009-tree-sitter-for-typescript-parsing.md`` -- is why that is one
composed Rule rather than three.

**Rule order is semantics, so the verdict is computed rather than matched.**
Upstream: *"Place more specific rules before broader deny rules"*. Each path
therefore walks the rules in the order they were written and the **first** rule
that governs writing *and* covers the path decides it. A predicate asking "is
there any ``deny`` anywhere in the list" would read the same in a test and be
wrong on exactly the configuration upstream tells people to write.

**A rule that does not govern writing does not end the walk.** A ``read`` rule
covering the path says nothing about whether the path can be rewritten, so the
walk continues past it to whatever does.

**The backend contributes unknowability, never a verdict.** The captured
reference documents four backends and none of them is read-only; the only
read-only-ness it describes is a ``deny`` rule. What the backend really
contributes is whether the Scan can see what a path holds at all, and that is
answered one layer down: a Skill path routed into a store whose contents are
computed per request is an
:class:`~skillspector.deepagents_js.host_config.OpaqueRoute`, reported as
``DA-UNRESOLVED``, and it reaches no verdict here.

**Files that are not on disk are still writable.** Agent state is exactly what a
self-modifying agent rewrites, and letting "not on disk" clear the verdict would
silence this Rule on ``createDeepAgent({ model, skills })`` -- the configuration
the tutorial teaches, and the one this Rule exists to report.

**The mitigation asks for exactly what the Python track's asks for.** Both gates
require ``write_file`` *and* ``edit_file``, because both distributions ship both
tools and either one rewrites a Skill file. Requiring both is also the direction
that under-reports the mitigation: an application gating only one of them is
reported at full severity, which a reviewer can correct, rather than reported as
mitigated on evidence that covers half the ways a Skill file is rewritten.

An earlier revision of this module asked for ``write_file`` alone, on the ground
that the captured page's single ``interruptOn`` code block spells no
``edit_file``. That was wrong in the direction nobody would notice. The gate is
satisfied by a **superset**, so a smaller required set is *more* permissive, not
narrower: upstream's own published ``interruptOn`` block --
``{ read_file: true, write_file: true, delete_file: true }`` -- then read as a
mitigation here and as none in the Python track, which is one Rule id carrying
two risk statements because the application was written in a second language.
:mod:`skillspector.deepagents_js.vocabulary` records why the page is not evidence
for the narrower set.

Provenance
----------

Captured from ``docs/references/deepagents-js-skills.md`` (upstream
<https://docs.langchain.com/oss/javascript/deepagents/skills>).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache

from skillspector.deepagents_js import vocabulary
from skillspector.deepagents_js.host_config import AgentConfiguration, PermissionRule

# The two tools that rewrite a Skill file. Identical to the Python track's set,
# and the module docstring records why asking for less than both was a defect
# rather than a narrowing.
_WRITE_TOOLS: frozenset[str] = frozenset({vocabulary.WRITE_FILE, vocabulary.EDIT_FILE})

_MODES: frozenset[str] = frozenset({vocabulary.DENY, vocabulary.INTERRUPT})


@dataclass(frozen=True)
class WritablePath:
    """One resolved Skill source path nothing denies the agent write access to.

    *mitigated* says a human is put in front of the write -- by the deciding rule's
    ``mode: "interrupt"``, or by an ``interruptOn`` gate over the write tool. That
    is a severity of this verdict rather than a Rule of its own: an approval prompt
    is not the same as a denial, and a configuration carrying one has still handed
    the agent its own instructions to rewrite.
    """

    path: str
    line: int
    mitigated: bool


@dataclass(frozen=True)
class Assessment:
    """What one ``createDeepAgent({...})`` call's Skill paths came to.

    The two lists are exclusive by construction. *unreadable_rule_lines* being
    non-empty empties *writable*: a permission rule written in a shape this Scan
    cannot read leaves the whole ordered walk undecided, because the part it could
    not read may be the ``paths`` that would have decided every one of them.
    """

    writable: tuple[WritablePath, ...]
    unreadable_rule_lines: tuple[int, ...]


def assess(configuration: AgentConfiguration) -> Assessment:
    """Judge one call's Skill source paths, or return nothing where a boundary was reported.

    Returns an empty assessment when the Skill list, the permission rules or the
    backend did not resolve. Each of those is already a ``DA-UNRESOLVED`` Finding,
    and a writability verdict computed over a configuration the Scan admits it
    could not read would be a guess wearing the same severity as a measurement.

    An *absent* setting is not a boundary and is judged: no ``permissions`` is no
    rules, and no ``backend`` is the default one. Those are configurations, and
    they are the ones this Rule most exists to judge.
    """
    skills = configuration.skill_paths
    if skills is None or skills.unresolved:
        return Assessment(writable=(), unreadable_rule_lines=())
    if configuration.backend is not None and configuration.backend.unresolved:
        return Assessment(writable=(), unreadable_rule_lines=())
    if configuration.permission_rules is not None and configuration.permission_rules.unresolved:
        return Assessment(writable=(), unreadable_rule_lines=())

    rules = _rules(configuration)
    unreadable = tuple(rule.line for rule in rules if not _readable(rule))
    if unreadable:
        return Assessment(writable=(), unreadable_rule_lines=unreadable)

    # A path routed into a store whose contents are computed per request is already
    # reported as `DA-UNRESOLVED`, and this is where that boundary is honoured
    # rather than talked about: it reaches no verdict.
    #
    # Matched by prefix rather than by `_covers`, and the asymmetry is upstream's:
    # a route key is a path *prefix*, while a permission rule's `paths` is a glob.
    # One relation each.
    opaque = {route.path for route in configuration.opaque_routes}
    gated = _interrupts_every_write(configuration)

    writable: list[WritablePath] = []
    for path in _paths(skills.value):
        if any(path.startswith(prefix) for prefix in opaque):
            continue
        deciding = _deciding_rule(rules, path)
        if deciding is not None and deciding.settings[vocabulary.MODE] == vocabulary.DENY:
            continue
        mitigated = gated or (
            deciding is not None and deciding.settings[vocabulary.MODE] == vocabulary.INTERRUPT
        )
        writable.append(WritablePath(path=path, line=skills.line, mitigated=mitigated))
    return Assessment(writable=tuple(writable), unreadable_rule_lines=())


def _paths(value: object) -> tuple[str, ...]:
    """The resolved Skill source paths, however the resolver spelled its result."""
    if not isinstance(value, tuple):
        return ()
    return tuple(path for path in value if isinstance(path, str))


def _rules(configuration: AgentConfiguration) -> tuple[PermissionRule, ...]:
    """The permission rules the call declared, in the order they were written."""
    rules = configuration.permission_rules
    if rules is None or not isinstance(rules.value, tuple):
        return ()
    return tuple(rule for rule in rules.value if isinstance(rule, PermissionRule))


def _readable(rule: PermissionRule) -> bool:
    """Whether a rule is written in the shape upstream documents.

    All three properties present, ``operations`` and ``paths`` sequences of
    strings, and a ``mode`` this Scan knows the meaning of. A rule failing any of
    that is not a rule this module guesses at: an unrecognized ``mode`` could be a
    denial or a permission, and reading it either way would be wrong in the
    direction nobody would notice.
    """
    settings = rule.settings
    return (
        _string_sequence(settings.get(vocabulary.OPERATIONS)) is not None
        and _string_sequence(settings.get(vocabulary.PATHS)) is not None
        and settings.get(vocabulary.MODE) in _MODES
    )


def _string_sequence(value: object) -> tuple[str, ...] | None:
    """*value* as a sequence of strings, or ``None`` if it is not one.

    A bare string is refused rather than read as a one-element sequence: it would
    iterate into characters, and upstream writes both properties as arrays.
    """
    if isinstance(value, str) or not isinstance(value, Sequence):
        return None
    if not all(isinstance(member, str) for member in value):
        return None
    return tuple(str(member) for member in value)


def _deciding_rule(rules: Sequence[PermissionRule], path: str) -> PermissionRule | None:
    """The first rule that governs writing and covers *path*, if any."""
    return next(
        (
            rule
            for rule in rules
            if vocabulary.WRITE in (_string_sequence(rule.settings[vocabulary.OPERATIONS]) or ())
            and _covers(rule, path)
        ),
        None,
    )


def _covers(rule: PermissionRule, path: str) -> bool:
    """Whether any of a rule's path patterns matches *path*.

    Glob matching, case-sensitively on every platform: these are agent-visible
    backend paths rather than paths on the machine running the Scan, so folding
    case where the host happens to would make one configuration read two ways.

    The match is deliberately literal. A rule written ``/skills/**`` does not cover
    a Skill source written ``skills/`` -- upstream's paths are absolute and its own
    examples pair the two spellings exactly. Treating a near-miss as a match would
    clear a Finding on a rule that does not apply, which is the failure direction
    nothing downstream can recover from.
    """
    patterns = _string_sequence(rule.settings[vocabulary.PATHS]) or ()
    return any(_pattern(pattern).fullmatch(path) is not None for pattern in patterns)


@cache
def _pattern(pattern: str) -> re.Pattern[str]:
    """One path pattern as a regular expression, with ``*`` stopping at a separator.

    ``fnmatch`` is the obvious reader and it is the wrong one here: its ``*``
    crosses ``/``, so a rule written ``/skills/*`` would be read as covering
    ``/skills/personal/notes/`` and would clear a Finding on a path it never named.
    Upstream's own examples are all ``**``, which is exactly the distinction
    ``fnmatch`` cannot make -- so this reader makes it: ``**`` crosses separators,
    ``*`` and ``?`` stop at one.

    Everything else is matched literally, character classes included. A pattern this
    reader does not give a meaning to therefore matches less rather than more, and
    matching less leaves a Finding standing -- the direction a reviewer can correct.
    """
    expression: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            crossing = pattern.startswith("**", index)
            expression.append(".*" if crossing else "[^/]*")
            index += 2 if crossing else 1
        elif character == "?":
            expression.append("[^/]")
            index += 1
        else:
            expression.append(re.escape(character))
            index += 1
    return re.compile("".join(expression))


def _interrupts_every_write(configuration: AgentConfiguration) -> bool:
    """Whether ``interruptOn`` puts a human in front of the write tool.

    Wider than ``mode: "interrupt"`` on purpose, because upstream is: it *"requires
    approval for all filesystem writes, not only skills paths"*, so where it is
    present it mitigates every path this call was given rather than one rule's.

    An ``interruptOn`` this Scan could not read is **no** mitigation, and that
    asymmetry is deliberate. An unconfirmed mitigation left in place would lower the
    severity of a real Finding on evidence nobody has; refused, it leaves the
    Finding at full severity, which is the direction a reviewer can correct.
    """
    gate = configuration.interrupt_on
    if gate is None or gate.unresolved or not isinstance(gate.value, frozenset):
        return False
    return _WRITE_TOOLS <= gate.value
