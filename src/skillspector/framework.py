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

"""Which Framework a scanned tree is written against.

Phase 1 of ``docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md``. Detection is pure over
``components`` and ``file_cache`` (§3.2): it does no I/O and cannot fail a Scan.
The key exists so a gated Analyzer has something to gate on, and so the Behavior
Snapshot can prove detection never drifts on an input scanned today.

``framework_langchain4j`` reads it (#23). ``LANGCHAIN4J`` is therefore no longer
inert: what this function returns now decides whether five Rules run.

Enum rather than the bare ``str`` the design document writes, mirroring
``skillspector.manifest_status``: a misspelled literal in a later Analyzer's
gate would fail by never opening the gate, and ADR 0002 has that gate decline
without a ledger event -- so the failure would be silent. The serialized values
are §3.1's, unchanged.

**Ambiguity resolves to** ``AGENT_SKILLS``. When the signals of two Frameworks
are both present -- a polyglot repository whose ``pom.xml`` names
``dev.langchain4j`` and whose ``pyproject.toml`` names ``deepagents`` -- two
matches is doubt, and §3.2's conservative rule ("when in doubt,
``agent_skills``") applies literally. With three Frameworks the rule is stated
once rather than pairwise: **exactly one signal fires, or ``AGENT_SKILLS``.**
With two signals that reads identically to the pairwise form it replaces, so no
input that detected as a Framework before can detect as something else now.

The bad consequence is known rather than discovered later: a genuinely
LangChain4j repository that happens to carry ``deepagents`` in a test dependency
loses Framework analysis entirely, and loses it *in silence*, because the gate
declines without a ledger event.

**That cost is now real, and a third Framework has raised it.** It was accepted
while no Analyzer read the key, when nothing was lost by getting the answer
wrong. Since #23 an ambiguous detection costs a repository all five LangChain4j
Rules, including ``L4J-SHELL``. Since the JavaScript track it costs something
new: the two Deep Agents distributions share the name ``deepagents``, so a
monorepo shipping a Python agent beside a TypeScript one is not an exotic
polyglot repository but the *ordinary* shape of that project -- and it now fires
two signals, detects ``AGENT_SKILLS``, and loses the same four Rules twice over.
The signals below are extension-gated so the two never cross-fire on one file,
but nothing can stop a repository from genuinely containing both.

**Reopen trigger:** unchanged in form and closer in practice -- the first real
repository observed to detect ambiguously. Of the two alternatives, one is still
rejected on the same ground: a fixed precedence between Frameworks is
deterministic, but an arbitrary order becomes silent law. The other is no longer
rejected on *its* original ground. Returning a set of Frameworks was called
speculative generality "when only one Framework Analyzer exists"; three exist --
one per Framework other than ``AGENT_SKILLS``, which has no Analyzer -- and two
of them read the same upstream framework in two languages, so a set is now
the answer this module would give if it were being designed today. It is not
adopted here because the change reaches every gate and every Behavior Snapshot
that projects the key, which is a change of its own rather than a clause of a new
Framework's.

Detection is textual and reads only the files a signal names. It therefore does
not distinguish code from comments inside a ``.py``, ``.java`` or ``.ts`` file --
a whole import statement commented out on its own line is still a signal --
while a mention in prose, a ``README.md`` naming ``deepagents``, is not a signal
at all, because no signal names markdown.

Several signals are read more narrowly than §3.2's table spells them, always in
the conservative direction the same section mandates. Two are named here and the
JavaScript ones have their own paragraphs below. A requirement naming
``deepagents-contrib`` is a *different* distribution and is not a Deep Agents
signal; and an import is matched at the start of a line, so ``vendor.deepagents``
and a package named inside a string are not signals either. Both narrowings can
only ever return ``AGENT_SKILLS`` where a looser reading would return a
Framework, so they cannot make an existing Scan detect as something new.

**The JavaScript import signal is line-anchored and line-bounded, with one
alternative that crosses a newline inside braces and nowhere else.** A
JavaScript named import is routinely written over several lines and the captured
reference publishes it that way, so a pattern that stopped at the first newline
would miss the form upstream itself teaches. The way to read that form is *not*
to let every lead cross a newline: an earlier revision did, and JavaScript
supplied the counter-example immediately. ``export function f() {`` opens a
brace-delimited body carrying no statement terminator, so a lead excluding only
``;`` and quotes ran from that ``export`` across the newline into a ``//``
comment naming the package on the next line -- and a Python Deep Agents
repository shipping one such ``.ts`` file then fired two signals, detected
``AGENT_SKILLS``, and lost all four ``DA-*`` Rules in silence. Automatic
semicolon insertion means most JavaScript statements carry no terminator at all,
so ``;`` was never the statement boundary the revision took it for.

So the lead is bounded by the newline, and the multi-line form is matched by an
alternative that may cross one only *inside* the import list's braces --
``import {\n  createDeepAgent,\n} from "deepagents"`` -- with the braces' own
contents excluding braces and quotes. The remaining cost is the one the paragraph
above already records and is unchanged by this: a whole import statement
commented out on its own line still reads as code.

**Which signals are comment-proof, stated rather than assumed.** Every
*manifest* signal is: a ``package.json`` is parsed, and a Maven or Python
requirement is read from a file whose comment syntax carries no framework
spelling this module matches. Every *import* signal is anchored at the start of a
line, so a mention in a comment tail or inside a string is not one. The two
*constructor* signals are the ones that had to be argued rather than asserted,
and they are argued differently. ``createDeepAgent`` is now matched only where a
statement could start, because JavaScript prose that the scanner also reads --
a help string quoting the SDK, a ``//`` line, a JSDoc ``*`` line -- otherwise
fired the JavaScript signal inside a Python Deep Agents repository, which then
detected ``AGENT_SKILLS`` and lost all four ``DA-*`` Rules.

**The anchor excludes a comment; it does not exclude a template literal, and
that cost is recorded here rather than fixed.** The three shapes above each open
their line with something no statement opens -- a quote, a ``*``, a ``//``. A
backtick-delimited string opens no line at all: it carries whole *lines*, so an
SDK example embedded in a prompt string has a line reading exactly
``const agent = await createDeepAgent({...});`` and fires the signal. Excluding
it means tracking backtick state across the file, which is a lexer's work rather
than a regular expression's, and a stray backtick in a comment flipping that
parity would silence a genuine JavaScript repository instead. So the shape is
pinned by a test rather than patched by a wider pattern, and issue #127 carries
the ways out. ``create_deep_agent``
is **not** so anchored: it matches the name anywhere in a ``.py`` file, a
docstring and a comment tail included. That asymmetry is deliberate. The Python
signal predates the JavaScript track, and narrowing it would turn some input that
detects ``DEEPAGENTS`` today into ``AGENT_SKILLS`` -- a change to existing
behavior on existing input, which a new Framework's change is not allowed to
make. The cost is the mirror of the case above and is real: a JavaScript Deep
Agents repository shipping one ``.py`` file that names ``create_deep_agent`` in
prose fires two signals and loses its Rules. It is recorded here rather than
fixed here, because fixing it is a change to the Python Framework's detection and
belongs to that change.

**Every Deep Agents signal is gated on a file extension, and that is what keeps
the two Deep Agents Frameworks apart.** The PyPI distribution and the npm
distribution are both spelled ``deepagents``, byte for byte, so the distribution
name alone cannot tell them apart. What can is the file it is written in: a
Python requirement file or a ``.py`` module on one side, a ``package.json`` or a
JavaScript/TypeScript module on the other. Neither set of files overlaps the
other, so a repository that is only one of the two detects as that one -- and a
repository that is genuinely both fires two signals and falls to ``AGENT_SKILLS``
by the rule above, which is the ambiguity paragraph's subject rather than a
cross-fire.

One signal is read more widely: a build file is matched on its basename at any
depth, because a multi-module Maven build declares the dependency in a child
module's ``pom.xml`` rather than at the scan root, and §3.2's table says nothing
about depth. Unlike the narrowings, this direction *could* make an input detect
as a Framework, so it rests on evidence rather than argument -- every input
scanned before this module existed is asserted to detect ``AGENT_SKILLS``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Final

# Detection and Analyzer applicability stay separate *predicates* -- "is this
# tree LangChain4j at all" versus "which of its files do I open" -- and
# ``skillspector.langchain4j.signals`` records why. They do not stay separate
# vocabularies: the spelling of a group id is one fact, and a rename reaching
# only one of the two would leave the other matching nothing in silence. The
# module is parser-free, so importing it here costs detection nothing.
from skillspector.langchain4j.vocabulary import (
    CLASSPATH_SKILL_LAYOUT,
    GROUP_COORDINATE,
    IMPORT_PREFIX,
)


class Framework(StrEnum):
    """The Framework a scanned tree is written against.

    ``AGENT_SKILLS`` is both a real answer and the conservative default: it is
    what every input scanned before this module existed detects as.
    """

    AGENT_SKILLS = "agent_skills"
    LANGCHAIN4J = "langchain4j"
    DEEPAGENTS = "deepagents"
    DEEPAGENTS_JS = "deepagents_js"


# -- LangChain4j signals ---------------------------------------------------- #

# Matched on basename at any depth: a multi-module Maven build declares the
# dependency in a child module's ``pom.xml``, not only at the scan root.
_JVM_BUILD_FILES: Final[tuple[str, ...]] = ("pom.xml",)
_JVM_BUILD_PREFIX: Final[str] = "build.gradle"
_JVM_SOURCE_SUFFIXES: Final[tuple[str, ...]] = (".java", ".kt")

# The Maven group id, as it appears in a build file's dependency block. Composed
# from the inventoried spelling rather than written out, so a rename is a
# one-file edit and the enforcement test can prove no second copy exists.
_LANGCHAIN4J_COORDINATE: Final[re.Pattern[str]] = re.compile(re.escape(GROUP_COORDINATE))
# An import of the library, Java (optionally static) or Kotlin. Anchored to the
# start of a line so a mention inside a string or a comment tail is not a
# signal.
_LANGCHAIN4J_IMPORT: Final[re.Pattern[str]] = re.compile(
    rf"^\s*import\s+(?:static\s+)?{re.escape(IMPORT_PREFIX)}", re.MULTILINE
)
# The layout a LangChain4j project keeps its Skills in.
_LANGCHAIN4J_SKILL_LAYOUT: Final[str] = CLASSPATH_SKILL_LAYOUT


# -- Deep Agents signals ---------------------------------------------------- #

_PYTHON_REQUIREMENT_FILES: Final[tuple[str, ...]] = ("pyproject.toml",)
_PYTHON_REQUIREMENT_PREFIX: Final[str] = "requirements"
_PYTHON_REQUIREMENT_SUFFIX: Final[str] = ".txt"
_PYTHON_SOURCE_SUFFIX: Final[str] = ".py"

# The distribution name, bounded so ``deepagents-contrib`` is not a match: a
# different distribution is a different Framework question.
_DEEPAGENTS_DISTRIBUTION: Final[re.Pattern[str]] = re.compile(r"(?<![\w.-])deepagents(?![\w-])")
# A top-level import of the package. ``import vendor.deepagents`` is not one.
_DEEPAGENTS_IMPORT: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:from|import)\s+deepagents\b", re.MULTILINE
)
# The constructor the framework is used through.
_DEEPAGENTS_CALL: Final[re.Pattern[str]] = re.compile(r"\bcreate_deep_agent\s*\(")


# -- Deep Agents for JavaScript signals -------------------------------------- #

# The Node manifest that can declare the dependency, and the module suffixes the
# host code is written in. Both are what gate the shared distribution name: see
# the module docstring.
_NODE_MANIFEST_FILES: Final[tuple[str, ...]] = ("package.json",)
_NODE_SOURCE_SUFFIXES: Final[tuple[str, ...]] = (
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".mjs",
    ".cjs",
)

# The blocks a ``package.json`` declares a dependency in. Read by name rather
# than matched textually: the manifest is JSON, so parsing it is exact, and it is
# what makes the signal mean what §3.2 and the README both say it means -- a
# *dependency block* naming ``deepagents``, not the word appearing anywhere in
# the file. A key spelled ``deepagents`` under ``overrides``, ``resolutions`` or
# an arbitrary config object is not a declaration that this project depends on
# the package, and a hand-written regex read all three as one.
_NODE_DEPENDENCY_BLOCKS: Final[tuple[str, ...]] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)

# The npm distribution's own name, written here rather than imported from
# ``skillspector.deepagents_js.vocabulary``. Detection keeps its own copy of every
# spelling it matches on, by ADR 0008 and again by ADR 0009, so one upstream
# rename does not move detection and the Rules together -- which is also why both
# vocabulary guards exclude this module.
_NPM_DISTRIBUTION: Final[str] = "deepagents"

# What a JavaScript statement may carry between its keyword and its module
# specifier. It excludes the statement terminator so a match cannot run past the
# statement it started in, quotes and backticks so it cannot run *through* an
# earlier specifier to reach a later one, and the newline so it cannot leave the
# line it was anchored at. That last exclusion is not optional: without it the
# ``export`` of ``export function f() {`` matched across the newline into a
# comment naming the package on the next line, and a Python Deep Agents
# repository shipping one such ``.ts`` file lost all four ``DA-*`` Rules in
# silence.
_JS_SPECIFIER_LEAD: Final[str] = r"[^\n;'\"`]*?"
# A braced binding list -- an import list or a destructuring pattern. It is the
# one construct routinely written over several lines, and the captured reference
# publishes it that way, so it is what carries the licence to cross a newline
# rather than every lead carrying it. What it may cross is its own contents, and
# those exclude braces and quotes, so the crossing stops at the matching brace.
_JS_BRACED: Final[str] = r"\s*\{[^{}'\"`]*\}\s*"
# `= require(...)` and `= await import(...)`, the tail both call forms share.
_JS_REQUIRE_CALL: Final[str] = r"=[ \t]*(?:await[ \t]+)?(?:require|import)[ \t]*\([ \t]*"
# An import, a re-export, a ``require`` or a dynamic ``import()`` of the
# package. Every alternative is anchored at the start of a line, so the word
# appearing in a comment tail or inside a string is not a signal.
_DEEPAGENTS_JS_IMPORT: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\n)[ \t]*(?:"
    # `import ... from "deepagents"`, and the `export ... from` re-export, both
    # written on one line.
    rf"(?:import|export)\b{_JS_SPECIFIER_LEAD}from[ \t]*|"
    # The same two with a braced import list, which may be written over several
    # lines.
    rf"(?:import|export)\b{_JS_BRACED}from\s*|"
    # The side-effect import, which names no binding: `import "deepagents"`.
    r"import[ \t]*|"
    # `const x = require("deepagents")` and `const x = await import("deepagents")`.
    rf"(?:const|let|var)\b{_JS_SPECIFIER_LEAD}{_JS_REQUIRE_CALL}|"
    # The same two destructured, which is also written over several lines.
    rf"(?:const|let|var)\b{_JS_BRACED}{_JS_REQUIRE_CALL}"
    r")['\"]deepagents['\"]"
)
# The constructor the framework is used through, matched only where a statement
# could start. A bare ``\bcreateDeepAgent\s*\(`` reads the name wherever it
# appears, and JavaScript source is full of places that are not code: a help
# string quoting the SDK, a ``//`` line, a JSDoc ``*`` line. Each of those made a
# Python Deep Agents repository shipping one ``.ts`` file fire two signals and
# lose all four ``DA-*`` Rules in silence -- the same damage the import lead's
# newline bound was added for, arriving through the other door.
#
# So the call is anchored at the start of a line and may be preceded only by the
# leads the captured reference publishes: a declarator with its ``=``, whose lead
# excludes quotes so a string on the same line cannot reach the name; a
# ``return``; an ``await``; or nothing at all. Prose does not open a line that
# way, and ``*``, ``//`` and a quote all fail every alternative -- with the one
# exception the module docstring records, a template literal, whose contents are
# whole lines and so open one exactly as code does.
_DEEPAGENTS_JS_CALL: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\n)[ \t]*"
    r"(?:(?:export[ \t]+)?(?:const|let|var)\b[^\n;'\"`]*?=[ \t]*)?"
    r"(?:return[ \t]+)?"
    r"(?:await[ \t]+)?"
    r"createDeepAgent[ \t]*\("
)


def _basename(path: str) -> str:
    """Return the final segment of a component path.

    ``components`` always uses forward slashes -- ``build_context`` normalizes
    them so the paths stay portable as dict keys and SARIF locations.
    """
    return path.rsplit("/", 1)[-1]


def _is_jvm_build_file(path: str) -> bool:
    name = _basename(path)
    return name in _JVM_BUILD_FILES or name.startswith(_JVM_BUILD_PREFIX)


def _is_python_requirement_file(path: str) -> bool:
    name = _basename(path)
    return name in _PYTHON_REQUIREMENT_FILES or (
        name.startswith(_PYTHON_REQUIREMENT_PREFIX) and name.endswith(_PYTHON_REQUIREMENT_SUFFIX)
    )


def _signals_langchain4j(components: Iterable[str], file_cache: Mapping[str, str]) -> bool:
    """Whether any §3.2 LangChain4j signal is present."""
    for path in components:
        if _LANGCHAIN4J_SKILL_LAYOUT in path:
            return True
    for path, content in file_cache.items():
        if _is_jvm_build_file(path) and _LANGCHAIN4J_COORDINATE.search(content):
            return True
        if path.endswith(_JVM_SOURCE_SUFFIXES) and _LANGCHAIN4J_IMPORT.search(content):
            return True
    return False


def _signals_deepagents(file_cache: Mapping[str, str]) -> bool:
    """Whether any §3.2 Deep Agents signal is present.

    Takes no ``components``: every Deep Agents signal is a content one, unlike
    LangChain4j's Maven resource layout, which is a path.
    """
    for path, content in file_cache.items():
        if _is_python_requirement_file(path) and _DEEPAGENTS_DISTRIBUTION.search(content):
            return True
        if path.endswith(_PYTHON_SOURCE_SUFFIX) and (
            _DEEPAGENTS_IMPORT.search(content) or _DEEPAGENTS_CALL.search(content)
        ):
            return True
    return False


def _is_node_manifest(path: str) -> bool:
    return _basename(path) in _NODE_MANIFEST_FILES


def _declares_node_dependency(content: str) -> bool:
    """Whether a ``package.json`` names ``deepagents`` in a dependency block.

    Parsed rather than matched, which is what makes the signal the one §3.2 and
    the README describe. A manifest that does not parse carries no signal: an
    unreadable file states nothing, the same answer this module gives a signal
    file it cannot read at all.
    """
    try:
        manifest = json.loads(content)
    except (ValueError, RecursionError):
        return False
    if not isinstance(manifest, dict):
        return False
    return any(
        isinstance(block := manifest.get(name), dict) and _NPM_DISTRIBUTION in block
        for name in _NODE_DEPENDENCY_BLOCKS
    )


def _signals_deepagents_js(file_cache: Mapping[str, str]) -> bool:
    """Whether any Deep Agents for JavaScript signal is present.

    Takes no ``components``: every signal here is a content one, and every one is
    gated on the file's extension so it can never fire on the Python
    distribution's files -- see the module docstring.
    """
    for path, content in file_cache.items():
        if _is_node_manifest(path) and _declares_node_dependency(content):
            return True
        if path.endswith(_NODE_SOURCE_SUFFIXES) and (
            _DEEPAGENTS_JS_IMPORT.search(content) or _DEEPAGENTS_JS_CALL.search(content)
        ):
            return True
    return False


def detect_framework(components: Iterable[str], file_cache: Mapping[str, str]) -> Framework:
    """Detect the Framework of one scanned tree.

    ``components`` carries every discovered path; ``file_cache`` carries the
    content of the ones that could be read. The two are not interchangeable -- a
    signal file listed but unreadable carries no signal, because there is
    nothing to read.

    Returns ``AGENT_SKILLS`` when no signal fires *and* when more than one does.
    The rule is stated once over every Framework rather than pairwise between two,
    which is what a third Framework needs; with two it is the same function. The
    module docstring records why the ambiguous case is not a precedence rule.

    Every signal predicate is evaluated, never short-circuited on the first hit:
    "exactly one" is a fact about all of them, and stopping early would return the
    first Framework in this tuple's order -- which is the arbitrary precedence the
    docstring rejects.
    """
    detected = [
        framework
        for framework, fires in (
            (Framework.LANGCHAIN4J, _signals_langchain4j(components, file_cache)),
            (Framework.DEEPAGENTS, _signals_deepagents(file_cache)),
            (Framework.DEEPAGENTS_JS, _signals_deepagents_js(file_cache)),
        )
        if fires
    ]
    return detected[0] if len(detected) == 1 else Framework.AGENT_SKILLS
