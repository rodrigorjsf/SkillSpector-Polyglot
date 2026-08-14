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

"""The tool surface a LangChain4j application hands its agent.

Three ways the wiring gives an agent more capability than the author meant:

* an ``@Tool`` description that carries instructions rather than describing a
  tool -- the tool-poisoning surface written in Java instead of in an MCP
  manifest, sitting in an annotation nobody reviews as prose;
* an ``McpToolProvider`` built without a tool filter, so every tool the server
  exposes reaches the agent instead of a scoped subset;
* a ``RunShellCommandToolConfig`` with no working directory, so commands run
  wherever the JVM happened to start -- usually the application root.

Each is a fact about the shape of a builder chain or an annotation, which is why
all three are statically visible.

The first of them is reported wherever the annotation sits, which is rarely the
file that hands the class to a Skill. So this module also reports the two halves
of that attribution a single compilation unit can see: which type owns an
annotation, and which types a unit declares. Joining them across a Scan is the
Analyzer's job, not this module's.

Importing this module imports the tree-sitter parser -- see
:mod:`skillspector.langchain4j.java_parser`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from tree_sitter import Node

from skillspector.langchain4j import builder_chains, java_parser

# The upstream spelling this module matches on. The types and setters the
# Analyzer passes to :func:`find_chains_missing_setters` are spelled there too -- this
# module takes a receiver and its setters as arguments and does not name them.
from skillspector.langchain4j.vocabulary import TOOL_ANNOTATION

_ANNOTATION_TYPES: Final[frozenset[str]] = frozenset({"annotation", "marker_annotation"})

# Every shape a Java type declaration takes. A ``@Tool`` method can sit in any of
# them -- an interface declares default methods, a record declares ordinary ones
# -- and each is a name a ``.tools(new X())`` call could construct, so the
# ambiguity guard has to count them all rather than classes alone.
_TYPE_DECLARATIONS: Final[frozenset[str]] = frozenset(
    {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
    }
)


@dataclass(frozen=True)
class ToolAnnotation:
    """One ``@Tool`` annotation and the text it hands the model.

    ``owner`` is the simple name of the type whose body holds the annotation, or
    ``None`` when it sits outside any -- which a partially-invalid file can
    produce, since the parser is error-tolerant by design. It is the only half
    of a tool-class attribution this module can see: which Skill was granted the
    class is a question about another file, and is joined by the Analyzer.
    """

    line: int
    description: str
    owner: str | None


@dataclass(frozen=True)
class UnconfiguredChain:
    """A builder chain that called none of the setters it should have."""

    receiver: str
    line: int


def _annotation_strings(annotation: Node) -> list[str]:
    """Every string literal an annotation passes, in source order.

    ``@Tool("text")`` and ``@Tool(name = "x", value = "text")`` are both real
    spellings, and an array form passes several. Collecting the literals rather
    than reading one named element keeps all three readable without deciding
    which element is the description -- every literal in a ``@Tool`` is text the
    model may be shown.
    """
    arguments = annotation.child_by_field_name("arguments")
    if arguments is None:
        return []
    return [
        java_parser.text(node)[1:-1]
        for node in java_parser.walk(arguments)
        if node.type == "string_literal" and not java_parser.text(node).startswith('"""')
    ]


def _declared_name(node: Node) -> str | None:
    """The simple name a type declaration declares, if it has one."""
    name = node.child_by_field_name("name")
    return java_parser.text(name) if name is not None else None


def _owning_type(node: Node) -> str | None:
    """The simple name of the innermost type declaration holding *node*.

    Innermost rather than outermost, because that is what ``new X()`` names: an
    inner class is constructed by its own simple name, and attributing its tools
    to the enclosing class would report a tool surface the enclosing class never
    declared.
    """
    current: Node | None = node.parent
    while current is not None:
        if current.type in _TYPE_DECLARATIONS:
            return _declared_name(current)
        current = current.parent
    return None


def find_declared_types(source: str) -> list[str]:
    """The simple name of every type *source* declares, nested ones included.

    Simple names, and deliberately not qualified ones: a ``.tools(new X())``
    call names a type the same way, so this is the vocabulary a Scan-wide join
    has to match on. It is also why the join needs a guard -- two files can
    declare the same simple name in different packages, and this function
    reports both, so a caller can tell that the name resolves to more than one
    thing rather than silently picking one.
    """
    root = java_parser.parse(source).root_node
    return [
        name
        for node in java_parser.walk(root)
        if node.type in _TYPE_DECLARATIONS
        for name in (_declared_name(node),)
        if name is not None
    ]


def find_tool_annotations(source: str) -> list[ToolAnnotation]:
    """Every ``@Tool`` annotation in *source* that carries text.

    A bare ``@Tool`` with no arguments carries none and is skipped: there is no
    prose to examine, and the tool's risk is then a question about its body
    rather than about its description.
    """
    root = java_parser.parse(source).root_node

    annotations: list[ToolAnnotation] = []
    for node in java_parser.walk(root):
        if node.type not in _ANNOTATION_TYPES:
            continue
        name = node.child_by_field_name("name")
        if name is None or java_parser.text(name) != TOOL_ANNOTATION:
            continue
        strings = _annotation_strings(node)
        if not strings:
            continue
        annotations.append(
            ToolAnnotation(
                line=java_parser.line(node),
                description="\n".join(strings),
                owner=_owning_type(node),
            )
        )
    return annotations


def find_chains_missing_setters(
    source: str, receiver: str, setters: Sequence[str]
) -> list[UnconfiguredChain]:
    """Every ``<receiver>.builder()`` chain in *source* that called none of *setters*.

    Several spellings rather than one, because a builder can offer more than one
    way to configure the same thing -- ``McpToolProvider`` narrows its tool set
    through either ``filter`` or ``filterToolNames``, and a chain that called
    either is configured. A single-spelling caller passes a one-element
    sequence.

    The absence is the finding, so the whole chain has to be in view before it
    can be judged -- a chain is reported once, at its first line, however many
    other setters it called.
    """
    if isinstance(setters, str):
        # A ``str`` is a ``Sequence[str]`` of its own characters, so passing one
        # spelling instead of a sequence of them would look for six setters
        # named ``f``, ``i``, ``l`` ... and report every chain. Nothing type-checks
        # this repo, so the mistake is caught here or not at all.
        raise TypeError(
            f"setters is a sequence of spellings, not one spelling: pass ({setters!r},)"
        )
    return [
        UnconfiguredChain(receiver=receiver, line=chain.line)
        for chain in builder_chains.find_builder_chains(source, receiver)
        if not any(chain.called(setter) for setter in setters)
    ]
