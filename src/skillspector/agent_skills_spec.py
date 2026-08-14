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

"""Machine-checkable conformance constraints for an Agent Skills Skill, as Rules.

Seventeen Rules, ``SPEC-1`` through ``SPEC-17``, each a string comparison, a
length, or a path lookup. No LLM, no inference, no heuristic beyond the one this
module names out loud (``SPEC-13``'s token estimate). The Analyzer that emits
them is :mod:`skillspector.nodes.analyzers.structure_agent_skills_spec`; the
catalogue, the parse and the verdicts live here so the Analyzer node is the graph
plumbing and nothing else.

**Fifteen come from the captured specification; two do not, and the difference is
stated rather than blurred.** ``docs/references/agent-skills-specification.md`` is
the source for every Rule about a declared field and for the two progressive
disclosure budgets. ``SPEC-14`` is **Deep Agents loader behavior** -- the 10 MB
manifest skip is observed there, not written in the specification. ``SPEC-17`` is
**loader behavior with no clause behind it at all**: the captured page states no
skill-name uniqueness constraint, and its only cross-directory constraint on
``name`` is the parent-directory match ``SPEC-4`` already covers. ``SPEC-17`` is
scored because whichever loader consumes two directories of one name has to pick
between them and the choice is invisible from the tree -- which is a reason to
report it, and not a reason to call it a requirement of a page that does not
contain it. Attribution accuracy is an Apache-2.0 §4 obligation here, not a
stylistic preference; see ``.claude/rules/license-compliance.md``.

**The Manifest this module reads is its own.** ``build_context._parse_manifest``
keeps six keys and drops the rest, so ``compatibility`` and ``metadata`` -- two
fields with constraints of their own -- never reach graph state at all, and a
nested ``SKILL.md`` is never parsed by it. Reading the declaration block here is
therefore not duplication but the only way to reach what the Rules are about.
The two agree on where a declaration block begins and ends, deliberately: the
delimiters below are ``_parse_manifest``'s, so a Manifest that state reports as
``unparseable`` is exactly a Manifest ``SPEC-1`` fires on.

**No Rule reads ``allowed-tools``, and that is deliberate.**
``.claude/rules/allowed-tools-separator.md`` records that this project splits the
field on commas where the specification says spaces, as a deviation kept on
purpose because correcting it changes Findings on inputs Scanned today. A
conformance Rule reading that field would either depend on the deviation or
quietly correct it, and the specification's own note calls the field
experimental. The catalogue therefore stops at the fields whose constraints are
not in dispute.

Two Rules under-match on purpose, because each is scored and a false positive on
a scored Rule costs a Risk Score:

- ``SPEC-15`` and ``SPEC-16`` read **Markdown link targets only**. The
  specification shows a second shape -- a bare ``scripts/extract.py`` on its own
  line -- and telling that apart from prose naming a path is not a string
  comparison. A reference written that way is missed rather than guessed at.
- Link targets inside a fenced code block are skipped. A fence is where a
  specification-conformance example lives, and a Skill that documents
  ``[a](missing.md)`` as an example of what not to write is not referencing
  ``missing.md``.

``SPEC-15`` under-matches for four further reasons, and every one of them is the
same defect answered once. The Rule reads "not in the set of Components this Scan
walked" and reports "not there", so **any** reason a real file is absent from that
set is a scored false positive. :class:`ScanScope` is where the distinction lives:
``resolves`` answers *found*, ``observed`` answers *could this Scan have found
it*, and a target that is not observed is passed over rather than reported. The
four shapes, each measured against the real CLI:

- **The Scan holds nothing but the Manifest.** A single-file input is copied
  alone into a tool-created temporary directory, so a fully conforming Skill had
  every one of its references reported. ``tree_observed`` is false exactly there
  -- a temporary directory holding one Component -- and deliberately not wider: a
  Git clone, a URL fetch and a Zip extraction all sit in a temporary directory too
  but carry the Skill's whole tree, and ``SPEC-15`` keeps firing on all three.
- **A hidden file.** ``build_context._walk_skill_files`` drops a leading-dot file
  and records ``LedgerReason.HIDDEN_FILE``.
- **A pruned directory.** The same walk prunes ``_SKIP_DIRS`` -- ``node_modules``
  and its neighbours -- and records ``LedgerReason.EXCLUDED_DIRECTORY``.
- **A directory reached through a symlink.** ``os.walk`` runs with
  ``followlinks=False``, so the tree beneath one is never entered.

The first three are answered here. The last is **not**: declining to descend a
symlink records no ledger event, so there is nothing for ``observed`` to consult
and a Skill whose ``references/`` is a symlink still earns one scored Finding per
reference. Recording an event for it belongs in ``build_context``, where it would
land in ``analysis_completeness.scope_exclusions`` for every Scan of every tree
holding a directory symlink -- Behavior Snapshot movement that a default-off
feature cannot pay for. Issue #123 carries it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from posixpath import normpath
from urllib.parse import unquote

import yaml

from skillspector.llm_analyzer_base import estimate_tokens


class SpecChecks(StrEnum):
    """Which conformance Rules run on a Scan, and which of them score.

    ``OFF`` is the default and the whole behavior-preservation argument: the
    Analyzer returns nothing at all, so every input Scanned before this flag
    existed produces exactly what it produced before.
    """

    OFF = "off"
    ADVISORY = "advisory"
    STRICT = "strict"

    @classmethod
    def parse(cls, value: object) -> SpecChecks:
        """Return the mode *value* names, or ``OFF`` for anything else.

        Graph state is untyped and reachable without the CLI -- an API caller
        invokes the graph directly -- so an absent key and an unrecognized
        spelling both mean the mode nobody asked for.
        """
        try:
            return cls(str(value))
        except ValueError:
            return cls.OFF


@dataclass(frozen=True)
class SpecRule:
    """One Rule of the catalogue: what it is called, and what a Finding of it costs.

    *scored_by_default* is the ``advisory``/``strict`` split. A Rule that is not
    scored by default still runs in ``advisory``, still reports, and still
    carries the ``confidence`` declared here; what it does not do is contribute
    to the Risk Score.

    **That split is a property of the run, not of a Finding.** It is published as
    :func:`unscored_rule_ids` and carried in graph state, never folded into a
    field of the Finding itself -- see that function for why the distinction is
    load-bearing rather than stylistic.
    """

    rule_id: str
    name: str
    severity: str
    confidence: float
    scored_by_default: bool
    explanation: str
    remediation: str


CATEGORY = "Specification Conformance"

# Every Rule but one is a measurement -- a length, a spelling, a path that is
# either there or not -- so there is nothing left to be uncertain about.
_MEASURED = 1.0

# `SPEC-13` is the exception and the only estimate in the catalogue: token counts
# depend on a tokenizer this project does not run. It carries a lower confidence
# so that a `strict` Scan weighs it as the approximation it is.
_ESTIMATED = 0.7

_RULES: tuple[SpecRule, ...] = (
    SpecRule(
        rule_id="SPEC-1",
        name="Missing Or Unparseable Declaration",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "SKILL.md carries no YAML declaration block, or the block does not parse as a "
            "mapping. Every field the specification defines is declared there, so a loader "
            "reads no name, no description and no tool declaration from this skill."
        ),
        remediation=(
            "Open SKILL.md with a --- delimited YAML block declaring at least name and "
            "description, and close it with a second --- on its own line."
        ),
    ),
    SpecRule(
        rule_id="SPEC-2",
        name="Missing Name",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification requires a name field of 1 to 64 characters. Absent, empty or "
            "not text, a loader has no identity to register the skill under."
        ),
        remediation="Declare name, matching the skill's own directory name.",
    ),
    SpecRule(
        rule_id="SPEC-3",
        name="Missing Description",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification requires a description field. It is what an agent reads to "
            "decide whether the skill applies, so without it the skill is loaded and never "
            "chosen."
        ),
        remediation=("Declare description, saying both what the skill does and when to use it."),
    ),
    SpecRule(
        rule_id="SPEC-4",
        name="Name Does Not Match Directory",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=True,
        explanation=(
            "The specification requires name to match the parent directory name. Loaders that "
            "resolve same-name overrides by name rather than by path will treat this skill as "
            "the one its declaration names, not the one its directory names, which is a "
            "substitution primitive rather than a style slip."
        ),
        remediation=(
            "Rename the directory to the declared name, or the declared name to the directory."
        ),
    ),
    SpecRule(
        rule_id="SPEC-5",
        name="Name Charset",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification allows only lowercase letters, digits and hyphens in name."
        ),
        remediation="Rewrite name using only a-z, 0-9 and hyphens.",
    ),
    SpecRule(
        rule_id="SPEC-6",
        name="Name Hyphenation",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification forbids a leading hyphen, a trailing hyphen and consecutive "
            "hyphens in name."
        ),
        remediation="Remove the leading, trailing or doubled hyphen from name.",
    ),
    SpecRule(
        rule_id="SPEC-7",
        name="Name Length",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation="The specification caps name at 64 characters.",
        remediation="Shorten name to 64 characters or fewer.",
    ),
    SpecRule(
        rule_id="SPEC-8",
        name="Empty Description",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "description is declared but holds nothing, which tells an agent as little as "
            "omitting it."
        ),
        remediation="Write a description saying what the skill does and when to use it.",
    ),
    SpecRule(
        rule_id="SPEC-9",
        name="Description Length",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=True,
        explanation=(
            "The specification caps description at 1024 characters. The description goes into "
            "the system prompt, so everything past the cut is dropped without warning and the "
            "agent decides on a description its author never read back."
        ),
        remediation="Shorten description to 1024 characters or fewer.",
    ),
    SpecRule(
        rule_id="SPEC-10",
        name="Compatibility Length",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation="The specification caps compatibility at 500 characters.",
        remediation="Shorten compatibility to 500 characters or fewer.",
    ),
    SpecRule(
        rule_id="SPEC-11",
        name="Metadata Shape",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification defines metadata as a map from string keys to string values. "
            "A client reading it as one will not find what this declaration holds."
        ),
        remediation="Declare metadata as a mapping whose keys and values are all strings.",
    ),
    SpecRule(
        rule_id="SPEC-12",
        name="Body Line Budget",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification recommends keeping SKILL.md under 500 lines and moving detail "
            "into referenced files, because the whole body is loaded once the skill activates."
        ),
        remediation=(
            "Move reference material into files under references/ and link to them from the body."
        ),
    ),
    SpecRule(
        rule_id="SPEC-13",
        name="Body Token Budget",
        severity="LOW",
        confidence=_ESTIMATED,
        scored_by_default=False,
        explanation=(
            "The specification recommends keeping the activated body under about 5000 tokens. "
            "This count is estimated from character length, not measured with a tokenizer."
        ),
        remediation=(
            "Move reference material into files under references/ and link to them from the body."
        ),
    ),
    SpecRule(
        rule_id="SPEC-14",
        name="Manifest Size Limit",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=True,
        explanation=(
            "Deep Agents skips a SKILL.md of 10 MB or more while loading skills. The skill "
            "looks installed, is never loaded, and nothing at runtime says so."
        ),
        remediation="Split the file so SKILL.md stays well under 10 MB.",
    ),
    SpecRule(
        rule_id="SPEC-15",
        name="Missing File Reference",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=True,
        explanation=(
            "SKILL.md links a relative path that is not in the scanned tree. The instructions "
            "tell the agent to open or run something that is not there, and an agent that "
            "cannot find it improvises."
        ),
        remediation="Add the referenced file, or correct the link.",
    ),
    SpecRule(
        rule_id="SPEC-16",
        name="Deep File Reference",
        severity="LOW",
        confidence=_MEASURED,
        scored_by_default=False,
        explanation=(
            "The specification asks that file references stay one level deep from SKILL.md, so "
            "that what a skill can pull in stays legible."
        ),
        remediation=(
            "Move the target directly under scripts/, references/ or assets/, and link it there."
        ),
    ),
    SpecRule(
        rule_id="SPEC-17",
        name="Duplicate Skill Name",
        severity="MEDIUM",
        confidence=_MEASURED,
        scored_by_default=True,
        explanation=(
            "Two skill directories in this scan declare the same name. Whichever loader "
            "consumes them has to pick one, and which one it picks is not visible from the tree."
        ),
        remediation="Give each skill directory a name of its own, matching its directory.",
    ),
)

RULES: Mapping[str, SpecRule] = {rule.rule_id: rule for rule in _RULES}

# The five scored without asking, each because it has a runtime consequence
# rather than a stylistic one. Derived from the catalogue so the two cannot
# disagree.
SCORED_BY_DEFAULT: frozenset[str] = frozenset(
    rule.rule_id for rule in _RULES if rule.scored_by_default
)


def unscored_rule_ids(mode: SpecChecks) -> list[str]:
    """The Rule ids *mode* reports without letting them reach the Risk Score.

    In catalogue order, so the value a Scan writes into state is deterministic.
    ``strict`` and ``off`` both return an empty list -- ``strict`` because every
    Rule scores, ``off`` because no Rule runs -- and the two are distinguished by
    whether the Analyzer writes the key at all, not by what it holds.

    **Why this is a list of Rule ids rather than a field of the Finding.** The
    first implementation said "reported but not scored" by emitting the Finding
    at ``confidence = 0.0``, which worked only because
    ``report._compute_risk_score`` already skipped a non-positive confidence.
    ``confidence`` means *how certain the Scanner is that this Finding is real*,
    and overloading it with *whether this run was configured to score it* leaked
    in three directions at once: ``suppression.finding_fingerprint`` hashes
    ``confidence``, so one defect fingerprinted two ways and a Baseline taken in
    ``advisory`` suppressed nothing in ``strict``; the report rendered
    ``Confidence: 0%``, a false claim about certainty (issue #119); and the
    ``--no-llm`` meta filter reads a low confidence as a reason to drop (issue
    #120).

    A tag would have moved the collision rather than fixed it --
    ``finding_fingerprint`` hashes ``tags`` as well -- which is what rules out
    every carrier that lives on the Finding. **A Baseline fingerprint may depend
    only on the evidence: what was found, and where. Never on how the run was
    configured.** That invariant is stated where it is enforced, in
    ``suppression.finding_fingerprint``, and in ``.claude/rules/suppression.md``.
    """
    if mode is SpecChecks.ADVISORY:
        return [rule.rule_id for rule in _RULES if not rule.scored_by_default]
    return []


# The sentence a report prints beside a Finding of one of those Rule ids, and it
# lives **here** because it names ``--spec-checks``. The ids reach
# ``report._compute_risk_score`` as an opaque set precisely so the report never
# learns what a SPEC Rule is; a remedy hard-coded there would have undone that in
# the one place a reader actually looks, and a second gated catalogue publishing
# its own ids would have inherited this catalogue's flag. The report renders
# whatever it is handed and falls back to a generic statement when handed
# nothing, so the coupling runs one way only.
UNSCORED_NOTE = "not scored — run with --spec-checks strict to include"


_NAME_MAX = 64
_DESCRIPTION_MAX = 1024
_COMPATIBILITY_MAX = 500
_BODY_LINE_MAX = 500
_BODY_TOKEN_MAX = 5000

# 10 MB, read as mebibytes. The captured upstream page says "under 10 MB" and
# names no unit convention, so the larger of the two readings is used: it is the
# one that cannot report a file the loader would in fact have accepted.
MANIFEST_BYTE_LIMIT = 10 * 1024 * 1024

# `\Z` rather than `$`, which matches before a trailing newline and would let a
# name declared as a YAML block scalar carry one past the charset Rule. The
# quantifier stays `*` because a zero-length name is reported by `SPEC-2` before
# this pattern is ever asked: "holds a character the specification forbids" is
# the wrong sentence to say about a name that holds no characters at all.
_NAME_CHARSET = re.compile(r"^[a-z0-9-]*\Z")

# `[text](target)`, with the angle-bracket form the CommonMark spec allows for a
# target carrying spaces. The target stops at the first `)` or whitespace, which
# is what keeps a link inside a sentence from swallowing the rest of it.
_MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)>\s]+)>?\s*\)")

# A target naming somewhere other than this Skill's own tree: a URL, a protocol,
# an in-page anchor, or an absolute path.
_NOT_A_RELATIVE_PATH = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|/)")

_FENCE = re.compile(r"^\s*(?:```|~~~)")

# In ``build_context._parse_manifest``'s own order, which is what makes it a
# precedence rather than a set: a directory shipping both spellings is one Skill
# whose Manifest is `SKILL.md`, because that is the file the rest of the scanner
# read. The set below is derived from it so the two cannot disagree.
MANIFEST_PRECEDENCE: tuple[str, ...] = ("SKILL.md", "skill.md")
MANIFEST_FILENAMES: frozenset[str] = frozenset(MANIFEST_PRECEDENCE)

# The three directories the specification defines for what a Skill *bundles*
# rather than for where a Skill lives -- see `in_bundled_directory`, the only
# reader.
BUNDLED_DIRECTORIES: frozenset[str] = frozenset({"scripts", "references", "assets"})


@dataclass(frozen=True)
class ManifestComponent:
    """One ``SKILL.md`` of a Scan, with the two facts outside its own text.

    *directory* is the name ``SPEC-4`` compares against, and is ``None`` where
    the Scan cannot observe it: the root Manifest of an input that was cloned,
    downloaded, unzipped or wrapped into a temporary directory sits in a
    directory this tool named, not one the Skill's author did. Comparing against
    it would report every conforming Skill Scanned from a Git URL.

    *size_bytes* is the Component's size as ``build_context`` measured it on
    disk, which is what ``SPEC-14`` is about. The decoded text is not a
    substitute: it is read with ``errors="replace"``, so its length is not the
    file's.

    *content* is ``None`` only where the Scan could not read the Component at
    all -- never merely because the file is empty. An empty ``SKILL.md`` is a
    Manifest that declares nothing, which ``SPEC-1`` is about; an unreadable one
    is a Manifest nobody inspected, which the Inspection Ledger is about.
    """

    path: str
    content: str | None
    size_bytes: int
    directory: str | None


@dataclass(frozen=True)
class ScanScope:
    """What a Scan walked, and what it declined to walk.

    ``SPEC-15`` is scored, so the difference between the two is the difference
    between a Finding and a false positive. *components* is every path the Scan
    holds; *excluded* is every path it recorded a scope boundary for, as
    ``build_context`` spells them -- a hidden file bare (``.env.example``), a
    pruned directory with a trailing slash (``node_modules/``), both relative to
    the Scan root and therefore directly comparable with a resolved target.

    *tree_observed* is false for the one input shape that carries no tree at all:
    a single file, which the tool copies alone into a temporary directory. It is
    **not** simply "this Scan used a temporary directory" -- a clone, a download
    and a Zip extraction all do, and all keep the Skill's tree, so all three must
    keep reporting a genuinely broken reference.
    """

    components: frozenset[str]
    excluded: frozenset[str] = frozenset()
    tree_observed: bool = True

    def resolves(self, target: str, directory: str) -> bool:
        """Whether *target*, read from a Manifest in *directory*, names something scanned.

        A directory answers as well as a file: a target naming ``references/``
        with no trailing slash is satisfied by any Component beneath it.
        """
        resolved = self._resolve(target, directory)
        return resolved in self.components or any(
            component.startswith(f"{resolved}/") for component in self.components
        )

    def observed(self, target: str, directory: str) -> bool:
        """Whether this Scan was in a position to find *target* at all.

        False means the Scan never looked, which is not the same fact as the file
        not being there -- and only one of the two is what ``SPEC-15`` reports.
        """
        if not self.tree_observed:
            return False
        resolved = self._resolve(target, directory)
        return not any(
            resolved == boundary or resolved.startswith(f"{boundary}/")
            for boundary in self.excluded
        )

    @staticmethod
    def _resolve(target: str, directory: str) -> str:
        return normpath(f"{directory}/{target}" if directory else target)


@dataclass(frozen=True)
class Declaration:
    """The parsed declaration block of one Manifest, and where its keys are.

    *parsed* is false exactly when ``SPEC-1`` fires; *fields* is then empty and
    every Rule that reads a field stays silent, because a Rule reporting a
    missing ``name`` in a block that never parsed says the same thing twice.
    """

    parsed: bool
    fields: Mapping[str, object]
    key_lines: Mapping[str, int]
    body: str
    body_line: int


@dataclass(frozen=True)
class SpecViolation:
    """One Rule matching in one Manifest, before it becomes a Finding."""

    rule_id: str
    path: str
    line: int
    message: str


def read_declaration(content: str) -> Declaration:
    """Parse one Manifest into its declared fields and its body.

    The delimiters are ``build_context._parse_manifest``'s, so the two never
    disagree about whether a Manifest declared anything.
    """
    if not content.startswith("---"):
        return Declaration(False, {}, {}, content, 1)
    end = re.search(r"\n---[ \t]*\n", content[3:])
    if end is None:
        return Declaration(False, {}, {}, content, 1)
    block = content[3 : end.start() + 3]
    try:
        data = yaml.safe_load(block)
    except yaml.YAMLError:
        return Declaration(False, {}, {}, "", 1)
    if not isinstance(data, dict):
        return Declaration(False, {}, {}, "", 1)

    key_lines: dict[str, int] = {}
    for offset, line in enumerate(block.splitlines()):
        match = re.match(r"([A-Za-z0-9_-]+)\s*:", line)
        if match is not None and match.group(1) not in key_lines:
            # `content[3:]` starts at the newline closing the opening `---`, so
            # the block's first split element is the tail of line 1 and element
            # *offset* is source line ``offset + 1``.
            key_lines[match.group(1)] = offset + 1
    body = content[end.end() + 3 :]
    body_line = content[: end.end() + 3].count("\n") + 1
    fields = {str(key): value for key, value in data.items()}
    return Declaration(True, fields, key_lines, body, body_line)


def _line_of(declaration: Declaration, key: str) -> int:
    """The line *key* is declared on, or the line the declaration block opens on."""
    return declaration.key_lines.get(key, 1)


def _text(value: object) -> str | None:
    """*value* as declared text, or ``None`` when it is not text at all.

    YAML gives a bare number or date its own type, and a Rule about character
    length has nothing to say about those. They are left to the client that
    reads the field.
    """
    return value if isinstance(value, str) else None


def usable_name(value: object) -> str | None:
    """*value* as a declared name a loader could register, or ``None``.

    One predicate for "this declaration names the Skill", because two of them
    drifted apart: ``SPEC-2`` read a name of blanks as absent while ``SPEC-17``
    read it as a name, so two directories declaring ``name: "   "`` were told
    both that they declare no usable name *and* that they collide on it. What
    the specification's 1-character lower bound is about is a name with
    something in it, and that is asked here once.
    """
    text = _text(value)
    return text if text is not None and text.strip() else None


def _name_violations(
    path: str, declaration: Declaration, directory: str | None
) -> list[SpecViolation]:
    """``SPEC-2`` and ``SPEC-4`` through ``SPEC-7`` -- everything about ``name``."""
    line = _line_of(declaration, "name")
    if "name" not in declaration.fields:
        return [
            SpecViolation(
                "SPEC-2",
                path,
                line,
                "This skill declares no name, which the specification requires.",
            )
        ]
    name = _text(declaration.fields["name"])
    if name is None:
        # A non-text declaration ends the walk, and that is where the boundary
        # sits: every remaining Rule about `name` compares *strings*, and a bare
        # number or date is not one. An empty string is, so it keeps walking
        # below.
        return [
            SpecViolation(
                "SPEC-2",
                path,
                line,
                "The declared name is not text, so this skill declares no usable name.",
            )
        ]

    violations: list[SpecViolation] = []
    declared = usable_name(name)
    if declared is None:
        # The specification's lower bound -- "must be 1-64 characters" -- and the
        # one direction the upper bound cannot cover. It is `SPEC-2` rather than
        # `SPEC-5` for the same reason `SPEC-8` is not `SPEC-9`: a declaration
        # that holds nothing is an absent declaration, not a malformed one.
        #
        # Reported *beside* the directory comparison below rather than instead of
        # it. Ending the walk here suppressed `SPEC-4`, the one scored Rule about
        # `name`, so `name: ""` in `foo/` scored nothing while the milder
        # `name: bar` in `foo/` scored -- the more broken declaration costing
        # less. A name of nothing is not the name of its directory either.
        violations.append(
            SpecViolation(
                "SPEC-2",
                path,
                line,
                "The declared name is empty, so this skill declares no usable name.",
            )
        )
    if directory is not None and name != directory:
        violations.append(
            SpecViolation(
                "SPEC-4",
                path,
                line,
                f"The declared name {name!r} is not the name of its own directory "
                f"{directory!r}, which the specification requires them to share.",
            )
        )
    if declared is None:
        # The three Rules below are about the characters a name holds, and a name
        # holding none is not what any of them is asking: "holds a character the
        # specification forbids" is the wrong sentence to say about it.
        return violations
    if not _NAME_CHARSET.match(name):
        violations.append(
            SpecViolation(
                "SPEC-5",
                path,
                line,
                f"The declared name {name!r} holds characters outside the lowercase letters, "
                "digits and hyphens the specification allows.",
            )
        )
    if name.startswith("-") or name.endswith("-") or "--" in name:
        violations.append(
            SpecViolation(
                "SPEC-6",
                path,
                line,
                f"The declared name {name!r} opens or closes with a hyphen, or doubles one, "
                "which the specification forbids.",
            )
        )
    if len(name) > _NAME_MAX:
        violations.append(
            SpecViolation(
                "SPEC-7",
                path,
                line,
                f"The declared name is {len(name)} characters, past the {_NAME_MAX} the "
                "specification allows.",
            )
        )
    return violations


def _description_violations(path: str, declaration: Declaration) -> list[SpecViolation]:
    """``SPEC-3``, ``SPEC-8`` and ``SPEC-9``."""
    line = _line_of(declaration, "description")
    if "description" not in declaration.fields:
        return [
            SpecViolation(
                "SPEC-3",
                path,
                line,
                "This skill declares no description, which the specification requires.",
            )
        ]
    description = _text(declaration.fields["description"])
    if description is None or not description.strip():
        return [
            SpecViolation(
                "SPEC-8",
                path,
                line,
                "The declared description is empty, so nothing tells an agent when this skill "
                "applies.",
            )
        ]
    if len(description) > _DESCRIPTION_MAX:
        return [
            SpecViolation(
                "SPEC-9",
                path,
                line,
                f"The declared description is {len(description)} characters, past the "
                f"{_DESCRIPTION_MAX} the specification allows. Everything after the cut is "
                "dropped before the agent reads it.",
            )
        ]
    return []


def _optional_field_violations(path: str, declaration: Declaration) -> list[SpecViolation]:
    """``SPEC-10`` and ``SPEC-11`` -- the two optional fields with a shape of their own."""
    violations: list[SpecViolation] = []
    compatibility = _text(declaration.fields.get("compatibility"))
    if compatibility is not None and len(compatibility) > _COMPATIBILITY_MAX:
        violations.append(
            SpecViolation(
                "SPEC-10",
                path,
                _line_of(declaration, "compatibility"),
                f"The declared compatibility is {len(compatibility)} characters, past the "
                f"{_COMPATIBILITY_MAX} the specification allows.",
            )
        )
    if "metadata" in declaration.fields:
        metadata = declaration.fields["metadata"]
        if not isinstance(metadata, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in metadata.items()
        ):
            violations.append(
                SpecViolation(
                    "SPEC-11",
                    path,
                    _line_of(declaration, "metadata"),
                    "The declared metadata is not a mapping from text keys to text values, "
                    "which is the only shape the specification defines for it.",
                )
            )
    return violations


def _body_violations(path: str, declaration: Declaration) -> list[SpecViolation]:
    """``SPEC-12`` and ``SPEC-13`` -- the two progressive-disclosure budgets."""
    violations: list[SpecViolation] = []
    lines = len(declaration.body.splitlines())
    if lines > _BODY_LINE_MAX:
        violations.append(
            SpecViolation(
                "SPEC-12",
                path,
                declaration.body_line,
                f"The body is {lines} lines, past the {_BODY_LINE_MAX} the specification asks "
                "a skill to stay under. All of it loads at once when the skill activates.",
            )
        )
    tokens = estimate_tokens(declaration.body)
    if tokens > _BODY_TOKEN_MAX:
        violations.append(
            SpecViolation(
                "SPEC-13",
                path,
                declaration.body_line,
                f"The body is roughly {tokens} tokens, past the {_BODY_TOKEN_MAX} the "
                "specification recommends. The count is estimated from character length.",
            )
        )
    return violations


def _size_violations(manifest: ManifestComponent) -> list[SpecViolation]:
    """``SPEC-14``, the one Rule that reads the Component rather than its text."""
    if manifest.size_bytes < MANIFEST_BYTE_LIMIT:
        return []
    return [
        SpecViolation(
            "SPEC-14",
            manifest.path,
            1,
            f"This SKILL.md is {manifest.size_bytes} bytes. Deep Agents skips a skill manifest "
            f"of {MANIFEST_BYTE_LIMIT} bytes or more, so the skill looks installed and never "
            "loads.",
        )
    ]


def _link_targets(body: str, body_line: int) -> list[tuple[str, int]]:
    """Every Markdown link target in *body* that names a path inside the Skill.

    Fenced blocks are skipped: a fence is where an example lives, and an example
    of a broken reference is not a broken reference.
    """
    targets: list[tuple[str, int]] = []
    fenced = False
    for offset, line in enumerate(body.splitlines()):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in _MARKDOWN_LINK.finditer(line):
            target = match.group(1).split("#", 1)[0].strip()
            if not target or _NOT_A_RELATIVE_PATH.match(target):
                continue
            targets.append((target, body_line + offset))
    return targets


def _spellings_of(target: str) -> tuple[str, ...]:
    """Every spelling of *target* a Component on disk could answer to.

    A Markdown target carrying a space is written percent-encoded at least as
    often as it is written in angle brackets, and ``references/User%20Guide.md``
    names the same Component as ``references/User Guide.md``. Both spellings are
    tried, and the decoded one is tried *as well as* rather than *instead of* the
    raw one, because a Component whose name really does hold a ``%`` answers only
    to the raw spelling. ``SPEC-15`` is scored, so the union is the direction that
    cannot report a file that is there.
    """
    decoded = unquote(target)
    return (target,) if decoded == target else (target, decoded)


def _reference_violations(
    manifest: ManifestComponent, declaration: Declaration, scope: ScanScope
) -> list[SpecViolation]:
    """``SPEC-15`` and ``SPEC-16`` over the Manifest's Markdown link targets.

    A target that climbs out of the Skill with ``..`` is left alone by both:
    neither "does it exist" nor "how deep is it" has an answer this Scan can
    give for a path outside the tree it walked, and inventing one would put a
    scored Finding on a guess.

    **Only ``SPEC-15`` consults :meth:`ScanScope.observed`.** Depth is a property
    of the target string -- ``a/b/c/d.md`` is three levels deep whether or not the
    Scan walked there -- so ``SPEC-16`` stays answerable on a tree nobody opened,
    and it is unscored besides. ``SPEC-15`` is the Rule that asserts something
    about the disk, and it is the one that has to stay quiet when the Scan cannot
    see the disk.
    """
    directory = manifest.path.rsplit("/", 1)[0] if "/" in manifest.path else ""
    violations: list[SpecViolation] = []
    for target, line in _link_targets(declaration.body, declaration.body_line):
        if ".." in target.split("/"):
            continue
        # Depth is measured on the raw spelling, so a `%2F` is a character of one
        # path component rather than a separator. Decoding it here would let an
        # encoded target report a depth its author never wrote, and `SPEC-16`
        # already under-matches by design.
        depth = len([part for part in target.split("/") if part not in ("", ".")])
        if depth > 2:
            violations.append(
                SpecViolation(
                    "SPEC-16",
                    manifest.path,
                    line,
                    f"The reference {target!r} is more than one level deep, which the "
                    "specification asks a skill to avoid.",
                )
            )
        if target.endswith("/"):
            continue
        if any(scope.resolves(spelling, directory) for spelling in _spellings_of(target)):
            continue
        if not any(scope.observed(spelling, directory) for spelling in _spellings_of(target)):
            # The Scan never walked there, so "not found" is a fact about this
            # Scan's reach rather than about the Skill. Reporting it put a scored
            # Finding on a conforming Skill and made one report say both that the
            # path is out of scope and that the path is missing.
            continue
        violations.append(
            SpecViolation(
                "SPEC-15",
                manifest.path,
                line,
                f"The reference {target!r} names a path this scan did not find, so the "
                "instructions point at a file that is not there.",
            )
        )
    return violations


def violations_of(
    manifest: ManifestComponent, declaration: Declaration, scope: ScanScope
) -> list[SpecViolation]:
    """Every Rule of the catalogue but ``SPEC-17``, over one Manifest.

    ``SPEC-14`` is asked first and asked always: a Manifest too large to load is
    not a Manifest whose declared fields matter, but its size is a fact about the
    Component rather than about its text, so it is reported beside them rather
    than instead of them.

    A declaration block that did not parse ends the walk at ``SPEC-1``. Every
    remaining field Rule would otherwise report the absence of a field in a block
    nobody could read, which describes one defect as eight.
    """
    violations = _size_violations(manifest)
    if not declaration.parsed:
        violations.append(
            SpecViolation(
                "SPEC-1",
                manifest.path,
                1,
                "This SKILL.md opens with no YAML declaration block, or with one that does not "
                "parse as a mapping, so nothing about this skill is declared.",
            )
        )
        return violations
    violations.extend(_name_violations(manifest.path, declaration, manifest.directory))
    violations.extend(_description_violations(manifest.path, declaration))
    violations.extend(_optional_field_violations(manifest.path, declaration))
    violations.extend(_body_violations(manifest.path, declaration))
    violations.extend(_reference_violations(manifest, declaration, scope))
    return violations


def duplicate_name_violations(
    declarations: Sequence[tuple[ManifestComponent, Declaration]],
) -> list[SpecViolation]:
    """``SPEC-17``, the one Rule that reasons across skill directories.

    Reported on the *later* Manifest of each colliding pair, in path order, and
    naming the earlier one. One Finding per collision rather than two: a
    reviewer who accepts it accepts one fact, and a Baseline entry per side would
    make accepting it twice possible.

    A Manifest declaring no usable name is not a side of a collision --
    :func:`usable_name` is the same predicate ``SPEC-2`` asks, so a name of
    blanks cannot be reported as absent and as colliding in one report. The key
    is the declared spelling rather than a stripped one: ``SPEC-17`` is scored,
    and folding ``foo`` together with ``foo `` would put a scored Finding on a
    normalisation no loader was observed to perform -- while ``SPEC-5`` already
    reports the blank the second spelling carries.
    """
    seen: dict[str, str] = {}
    violations: list[SpecViolation] = []
    for manifest, declaration in declarations:
        name = usable_name(declaration.fields.get("name")) if declaration.parsed else None
        if name is None:
            continue
        first = seen.get(name)
        if first is None:
            seen[name] = manifest.path
            continue
        violations.append(
            SpecViolation(
                "SPEC-17",
                manifest.path,
                _line_of(declaration, "name"),
                f"The skill name {name!r} is declared here and in {first}. Two skill "
                "directories of one name leave the loader to pick between them.",
            )
        )
    return violations


def is_manifest(path: str) -> bool:
    """Whether *path* names an Agent Skills Manifest, at any depth of the Scan."""
    return path.rsplit("/", 1)[-1] in MANIFEST_FILENAMES


def in_bundled_directory(path: str) -> bool:
    """Whether *path* sits beneath one of the three directories a Skill bundles.

    ``docs/references/agent-skills-specification.md`` names exactly three, and
    names them as what a Skill *bundles* rather than as places a Skill lives:
    ``scripts/`` for executable code, ``references/`` for documentation,
    ``assets/`` for templates. A ``SKILL.md`` under one of them is a template or
    an example a Skill ships, not a skill directory -- and reading it as one put
    twenty scored points on a conforming Skill, ``SPEC-4`` for a name that does
    not match ``references`` plus ``SPEC-17`` for colliding with the Skill that
    ships it.

    Only the segments *above* the file are read, so a Scan rooted at a directory
    of one of those names is unaffected: its own Manifest is ``SKILL.md``, with
    no segment above it at all.
    """
    return any(segment in BUNDLED_DIRECTORIES for segment in path.split("/")[:-1])


def manifest_precedence(path: str) -> int:
    """Where *path*'s filename sits in ``MANIFEST_PRECEDENCE``; lower wins.

    Only meaningful for a path :func:`is_manifest` accepts. It is the tie-break
    for a directory shipping both spellings, and it is the loader's tie-break
    rather than one invented here.
    """
    return MANIFEST_PRECEDENCE.index(path.rsplit("/", 1)[-1])
