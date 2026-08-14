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

"""Every Deep Agents for JavaScript spelling SkillSpector's Rules match on.

The reason is ``docs/adr/0005-langchain4j-upstream-vocabulary.md``'s, copied
first by ``docs/adr/0008-deepagents-analyzer-resolves-one-module-deep.md`` for
the Python track and now by
``docs/adr/0009-tree-sitter-for-typescript-parsing.md`` for this one: when
upstream renames an option key or a class, a Rule that matches it stops producing
Findings and **nothing says so**. The Scan still succeeds, the Analyzer still
reports itself as having run, and the report reads as clean. So the spellings
live in one file, and ``tests/unit/test_deepagents_js_vocabulary.py`` fails the
build when one is written inline anywhere else in the source tree.

**This is a separate inventory from the Python one, and that is the whole
point.** :mod:`skillspector.deepagents.vocabulary` inventories the PyPI
distribution ``deepagents``; this module inventories the npm distribution of the
same name, published from ``langchain-ai/deepagentsjs``. Many spellings are
byte-identical -- ``skills``, ``permissions``, ``operations``, ``paths``,
``mode``, ``deny``, ``interrupt``, ``write``, ``subagents``, ``backend`` and the
four backend classes -- and sharing one constant for them would be exactly the
failure ADR 0005 exists to prevent: the two distributions ship on different
clocks, and a rename in one must not silently move the Rules of the other. So the
duplication is deliberate, each guard exempts the other's home, and ADR 0009
records the decision.

**Two spellings the Python inventory carries are deliberately absent, because
the JavaScript capture does not support them.** ``docs/references/README.md``
requires code over prose where the two disagree, and
``docs/references/deepagents-js-skills.md`` disagrees with itself in two places:

* ``FilesystemPermission`` does not appear on the JavaScript page **at all**. A
  permission rule there is a plain object literal --
  ``{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }`` -- so there
  is no class to name and :mod:`skillspector.deepagents_js.host_config` reads the
  shape rather than a constructor.
* ``routes`` is not an option key. ``CompositeBackend`` takes its default backend
  and its route map as two **positional** arguments --
  ``new CompositeBackend(new StateBackend(), { "/skills/": ... })`` -- so the map
  is read by position and no keyword is matched on.

``edit_file`` is **not** one of them, and the reasoning is worth stating because
an earlier revision of this module got it wrong. The code-over-prose rule settles
a *disagreement*, and here there is none: the page's only ``interruptOn`` code
block gates ``read_file``, ``write_file`` and ``delete_file``, which is one
example of a gate rather than an enumeration of the tools that can be gated, so
it contradicts nothing. Nor is the prose that names ``edit_file`` a Python
spelling leak -- every leak the capture annotates is a *syntax* leak, and
``edit_file`` is snake_case in both distributions, so *"Both pause before*
``write_file`` *or* ``edit_file`` *runs"* is a sentence about JavaScript
behaviour in JavaScript tool vocabulary. The sweep settles it outright: the
distribution's own published artifacts ship the name in all 32 releases of the
measured range.

Deferring to the prose here would not have been the cautious reading either. The
mitigation gate is satisfied when the configuration gates **every** tool in this
inventory, so a *smaller* inventory is *easier* to satisfy -- omitting
``edit_file`` made upstream's own published ``interruptOn`` block read as a
mitigation on the JavaScript side and not on the Python side, which is one Rule
id carrying two risk statements. Both tracks now ask for both tools.

**A section of its own, because four of these spellings are ordinary English
words.** ``skills`` and ``permissions`` are also an Agent Skills manifest field,
a repository directory name and a CLI report key; ``mode`` is the keyword
argument of a call to ``open``; ``write`` is a capability in an MCP tool map. The
guard's sweep exempts those four by call site, on the same evidence the Python
guard demands: each exempted spelling must really occur inline elsewhere in the
tree, so an exemption that stops being a homonym stops being allowed.

Deliberately import-free, so nothing here can fail to load.

Provenance
----------

Captured from ``docs/references/deepagents-js-skills.md`` (upstream
<https://docs.langchain.com/oss/javascript/deepagents/skills>), and cross-checked
against the published npm distributions.
"""

from __future__ import annotations

from typing import Final

# The releases the sweep covered, oldest and newest. Measured on 2026-08-13
# against the npm registry: every final release of the npm distribution
# ``deepagents`` at or above the Skills floor upstream states on the captured
# page (*"Skills require deepagents>=1.7.0"*) was downloaded and its packed
# ``.js``, ``.cjs``, ``.mjs``, ``.ts`` and ``.json`` files searched for each
# spelling below as a whole word. 32 releases, ``1.7.0`` through ``1.12.3``, read
# out of the tarballs rather than off the documentation.
#
# Releases below ``1.7.0`` were deliberately not swept: upstream states Skills do
# not exist there, so a spelling's absence would measure the feature's absence
# rather than a rename. That bound is the honest one to publish, and it is the
# same reasoning the Python inventory's "practical floor" paragraph uses.
#
# Two spellings are not present across the whole range:
#
#   1.8.0   permissions
#   1.9.1   deny
#
# Everything else spans ``1.7.0`` to ``1.12.3``. The practical floor for the
# whole inventory is therefore **1.9.1**, the release where the permission
# vocabulary is complete and every spelling here exists together.
#
# One annotation is a human's correction rather than the sweep's raw output, and
# it is the same one ``docs/VOCABULARY_REMEASUREMENT.md`` names as the step a
# re-measurement cannot leave to the tool. ``interrupt`` is a bare string value,
# and a sweep for one cannot tell the ``mode`` value from any other use of the
# word -- the distribution ships an unrelated interrupt vocabulary throughout.
# It is recorded as spanning the range because that is what was measured, and the
# floor above rests on ``deny``, its sibling in the same cluster, which is
# unambiguous.
OBSERVED_VERSION_RANGE: Final[tuple[str, str]] = ("1.7.0", "1.12.3")


# -- The Framework itself ---------------------------------------------------- #

# The constructor every host-side setting is passed to. Upstream names it in the
# first line of every code block on the captured page. Its Python sibling is
# spelled ``create_deep_agent``, and the JavaScript page's *prose* leaks that
# spelling twice -- see the capture's annotation.
CREATE_DEEP_AGENT: Final[str] = "createDeepAgent"

# The distribution that provides it, as a ``package.json`` spells it. Identical
# to the PyPI name, which is why every signal that matches it is extension-gated
# in :mod:`skillspector.framework`.
DISTRIBUTION: Final[str] = "deepagents"

# -- What the constructor is configured with --------------------------------- #

# Which operations a permission rule governs, which paths it governs them on, and
# what it does where it applies. Upstream writes all three on every rule it
# publishes, as keys of a plain object literal.
OPERATIONS: Final[str] = "operations"
PATHS: Final[str] = "paths"

# The two `mode` values upstream documents. A covering rule written with any
# other value decides nothing this Scan can read, and reaches the boundary Rule
# rather than a verdict.
DENY: Final[str] = "deny"
INTERRUPT: Final[str] = "interrupt"

# The tool-level approval gate, and the two tools that rewrite a Skill file.
# Unlike `mode: "interrupt"`, which mitigates only its own rule's paths, this one
# "requires approval for all filesystem writes, not only skills paths".
#
# Both tool names are byte-identical to the Python inventory's, and both were read
# out of the swept npm tarballs rather than off the page -- `edit_file` is in
# every one of the 32 releases of `OBSERVED_VERSION_RANGE`, including the
# `edit_file` tool factory itself. The module docstring records why the page's
# single `interruptOn` code block is not evidence against it.
INTERRUPT_ON: Final[str] = "interruptOn"
WRITE_FILE: Final[str] = "write_file"
EDIT_FILE: Final[str] = "edit_file"

# The option key that decides whether the Skill files are on disk at all, and
# therefore whether any writability verdict is knowable.
BACKEND: Final[str] = "backend"

# The four backends upstream ships. All four are constructed with `new`. Only
# `CompositeBackend` is walked into, through its second positional argument; the
# other three are recognized so that naming one is a resolved backend rather than
# an unreadable expression.
COMPOSITE_BACKEND: Final[str] = "CompositeBackend"
STORE_BACKEND: Final[str] = "StoreBackend"
STATE_BACKEND: Final[str] = "StateBackend"
FILESYSTEM_BACKEND: Final[str] = "FilesystemBackend"

# The directory a `FilesystemBackend` roots its agent-visible paths at. It is the
# only option that turns a configured Skill source path into a place a Scan can
# open, so `DA-SHADOW` cannot confirm a name collision without it. Spelled
# `root_dir` in the Python distribution, and in this page's prose.
ROOT_DIR: Final[str] = "rootDir"

# The list of subagent definitions the agent delegates to. A custom subagent does
# not inherit the main agent's Skills, so a definition written without a `SKILLS`
# key of its own runs without them.
#
# Unlike the Python capture, the JavaScript page *does* publish a code block
# showing a definition's shape -- `name`, `description`, `systemPrompt`, `tools`,
# `skills`. Those keys are nonetheless not inventoried, and ADR 0009 records why:
# `DA-SUBAGENT-SKILLS` is one Rule with one meaning across both Frameworks, and
# naming the subagent on one side only would make the same Rule id report two
# different things. Widening it is tracked rather than done here.
SUBAGENTS: Final[str] = "subagents"

# -- Homonyms: owned here, exempt from the sweep ------------------------------ #
#
# All four are ordinary English words this repository already writes inline for
# unrelated reasons -- an Agent Skills manifest field, a discovery directory
# name, a CLI report key, the ``mode=`` of a call to ``open``, the ``write`` of
# an MCP capability map. See the module docstring: the exemption is asserted
# against real occurrences elsewhere in the tree, not merely declared.

# The Skill source paths the agent is given.
SKILLS: Final[str] = "skills"

# The declarative rules that decide what the agent may do to those paths.
PERMISSIONS: Final[str] = "permissions"

# What a permission rule does where it applies.
MODE: Final[str] = "mode"

# The operation a Skill file is rewritten by, and therefore the only one
# ``DA-SKILL-WRITABLE`` asks a rule about.
WRITE: Final[str] = "write"
