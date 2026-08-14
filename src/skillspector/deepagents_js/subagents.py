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

"""Which custom subagents of one call were given no Skills of their own.

Upstream states it plainly: *"Custom subagents -- do not inherit the main
agent's skills. Add a `skills` parameter to each subagent definition."* So a
definition written without one runs without the capability the application
around it was built on, and nothing at runtime says so.

The verdict is small, and it lives here rather than in the Analyzer for the
reason the two judging modules beside it do: what a Rule concludes is read out
of what :mod:`skillspector.deepagents_js.host_config` resolved, and the node that
reports Findings decides nothing about Deep Agents itself. It is also the only
place outside that resolver that has to know a subagent definition is written
with keys at all.

**The general-purpose subagent is excluded structurally, not by name.** Upstream
describes it as built in and inheriting automatically, so no ``subagents`` element
declares it and nothing here can reach it. Matching an identifier
instead would mean asserting a spelling the captured reference never writes as
one -- the silent-rename failure ADR 0005 exists to prevent -- and would be
pinned by a test that passes whether or not the check is there.

Provenance
----------

Captured from ``docs/references/deepagents-js-skills.md`` (upstream
<https://docs.langchain.com/oss/javascript/deepagents/skills>).
"""

from __future__ import annotations

from skillspector.deepagents_js import vocabulary
from skillspector.deepagents_js.host_config import AgentConfiguration, SubagentDefinition


def without_own_skills(configuration: AgentConfiguration) -> tuple[SubagentDefinition, ...]:
    """The custom subagents of one call that carry no ``skills`` key of their own.

    Nothing here is a fallback of anything else: a subagent definition is read
    out of the same call as every other Rule's input and decided inside it, so
    this verdict is orthogonal to the writability one rather than partitioned
    against it.

    Where the list itself did not resolve, this returns nothing and the
    Analyzer's boundary Rule has already said so. Reporting an absent ``skills``
    in a list that was never read would be the guess this package is built not to
    make.
    """
    subagents = configuration.subagents
    if subagents is None or subagents.unresolved:
        return ()
    definitions = subagents.value
    if not isinstance(definitions, tuple):
        return ()
    return tuple(
        definition
        for definition in definitions
        if isinstance(definition, SubagentDefinition) and vocabulary.SKILLS not in definition.keys
    )
