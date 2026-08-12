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

"""Where a LangChain4j Skill is defined in Java, and what its text actually says.

A LangChain4j Skill does not have to be a directory on disk. It can be built in
Java -- ``Skill.builder().content(...)`` -- from a string literal, a text block,
a constant, or from a database, a remote call, or anything else the application
does at runtime. The instruction text a model reads is whatever that argument
evaluates to.

This module resolves the arguments it can and, just as importantly, says which
ones it cannot. Resolving arbitrary Java dataflow is explicitly out of scope
(``docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`` §3.6); the boundary is the product.
A Skill whose content is assembled at runtime has instruction text that exists
in no scanned file, and reporting nothing there would let a Scan read as clean
on the one surface it never examined.

Importing this module imports the tree-sitter parser -- see
:mod:`skillspector.langchain4j.java_parser`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from tree_sitter import Node

from skillspector.langchain4j import builder_chains, java_parser

# Every upstream spelling this module matches on -- the builders that define a
# Skill, the loaders that find one, and the arguments each takes -- lives in
# ``vocabulary``, which is the one file a LangChain4j upgrade is read against.
from skillspector.langchain4j.vocabulary import (
    CLASSPATH_SKILL_LOADER,
    LOADER_METHODS,
    NAME_SETTER,
    SKILL_BUILDER,
    SKILL_BUILDERS,
    SKILL_LOADERS,
    TEXT_SETTERS,
    TOOLS_SETTER,
)

# Maven's, not LangChain4j's: ``ClassPathSkillLoader.loadSkills("skills")``
# resolves against the resource root, so the same literal names a different
# directory than the filesystem loader's would. It changes on Maven's clock,
# which is why it stays here rather than joining the inventory.
_CLASSPATH_ROOT: Final[str] = "src/main/resources/"

_TEXT_BLOCK_DELIMITER: Final[str] = '"""'
_ESCAPES: Final[tuple[tuple[str, str], ...]] = (
    ("\\\\", "\x00"),
    ("\\n", "\n"),
    ("\\t", "\t"),
    ('\\"', '"'),
    ("\\'", "'"),
)


@dataclass(frozen=True)
class BuilderArgument:
    """One ``.name(...)`` / ``.description(...)`` / ``.content(...)`` argument.

    ``value`` is the resolved text, or ``None`` when the argument is not
    statically resolvable. ``None`` is the reportable case, not a failure to
    record: it is what ``L4J-UNRESOLVED`` exists to name.

    ``value_start_line`` is where the *first line of the value* sits in the Java
    file, which is not always where the argument starts: a text block's content
    begins on the line after its opening delimiter. A content Rule matching line
    3 of a resolved body has to be reported against the right Java line, and the
    two differ by exactly this.
    """

    setter: str
    line: int
    value: str | None
    value_start_line: int


@dataclass(frozen=True)
class SkillDefinition:
    """One ``Skill.builder()`` or ``SkillResource.builder()`` chain."""

    builder: str
    line: int
    arguments: tuple[BuilderArgument, ...]

    def argument(self, setter: str) -> BuilderArgument | None:
        """The argument passed to *setter*, if the chain set it."""
        for argument in self.arguments:
            if argument.setter == setter:
                return argument
        return None


@dataclass(frozen=True)
class SkillLoaderCall:
    """One ``FileSystemSkillLoader`` or ``ClassPathSkillLoader`` call.

    ``directory`` is the Scan-relative directory the call reads, or ``None``
    when the argument was not a literal path -- a custom class loader, or a path
    built at runtime, is a definition site whose Skills were never examined.
    """

    loader: str
    method: str
    line: int
    directory: str | None


@dataclass(frozen=True)
class AttachedTools:
    """One ``.tools(...)`` call on a builder chain.

    ``type_names`` holds one entry per argument, in source order: the class whose
    ``@Tool`` methods the Skill gains when that argument is a plain ``new X()``,
    and ``None`` when it is anything else -- a map, a variable, a call. Reading
    it per argument rather than per call is what separates the two cases a Rule
    must not confuse: ``.tools(new A(), new B())`` names every class it attaches,
    while ``.tools(someVariable)`` names none. An empty tuple is a call that
    attaches nothing.

    ``skill_name`` is the name the same chain gave the Skill, when it set one to
    a resolvable literal. Usually it did not: the published spelling attaches
    tools to an already-built Skill -- ``skill.toBuilder().tools(new X())`` --
    where the name was set wherever that Skill was built. A report that has to
    say which Skill gained a tool therefore cannot rely on this, and names the
    attachment site as well.
    """

    line: int
    type_names: tuple[str | None, ...]
    skill_name: str | None

    @property
    def opaque(self) -> bool:
        """Whether any argument failed to name the tool class it attaches.

        Precisely that, and not the broader "the tool set is out of view": a
        class the Scan *can* name is still only a name. ``new ToolBag(runtime)``
        reads as resolvable here, because ``ToolBag`` is a class whose ``@Tool``
        methods ``L4J-TOOL-DESC`` reads wherever its file is scanned, and what
        was passed to its constructor is the arbitrary dataflow §3.6 declines.
        """
        return None in self.type_names


def _unescape(text: str) -> str:
    for escaped, plain in _ESCAPES:
        text = text.replace(escaped, plain)
    return text.replace("\x00", "\\")


def _text_block_value(raw: str) -> str:
    """The value of a Java text block, with incidental indentation removed.

    Follows JLS 3.10.6: the line holding the opening delimiter contributes
    nothing, and the common indentation of the content lines *and the closing
    delimiter's line* is stripped from all of them. Getting this wrong would
    shift every line of a resolved Skill body by a few spaces, which changes
    what a content Rule matches.
    """
    body = raw[len(_TEXT_BLOCK_DELIMITER) : -len(_TEXT_BLOCK_DELIMITER)]
    first_newline = body.find("\n")
    body = body[first_newline + 1 :] if first_newline >= 0 else body

    lines = body.split("\n")
    # The closing delimiter's line is always significant, blank or not; content
    # lines are significant only when they hold something.
    measured = [line for line in lines[:-1] if line.strip()]
    measured.append(lines[-1])
    indent = min((len(line) - len(line.lstrip()) for line in measured), default=0)

    stripped = [line[indent:] if line[:indent].strip() == "" else line.lstrip() for line in lines]
    if stripped and not stripped[-1].strip():
        stripped = stripped[:-1]
        return "\n".join(stripped) + "\n" if stripped else ""
    return "\n".join(stripped)


def _string_value(node: Node) -> str | None:
    """The text a string-literal node holds, or ``None`` if it is not one."""
    if node.type != "string_literal":
        return None
    raw = java_parser.text(node)
    if raw.startswith(_TEXT_BLOCK_DELIMITER):
        return _text_block_value(raw)
    return _unescape(raw[1:-1])


def _string_constants(root: Node) -> dict[str, str]:
    """Every ``String NAME = "literal"`` in the compilation unit, by name.

    Same-unit constants only. §3.6 calls a constant "usually" resolvable and
    means exactly this: the declaration has to be in the file being read, since
    following it anywhere else is the arbitrary dataflow that is out of scope.
    """
    constants: dict[str, str] = {}
    for node in java_parser.walk(root):
        if node.type not in ("field_declaration", "local_variable_declaration"):
            continue
        for declarator in node.children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None or value is None:
                continue
            resolved = _string_value(value)
            if resolved is not None:
                constants[java_parser.text(name)] = resolved
    return constants


def _resolve(argument: Node, constants: dict[str, str]) -> str | None:
    """The text an argument evaluates to, or ``None`` when that is not knowable."""
    literal = _string_value(argument)
    if literal is not None:
        return literal
    if argument.type == "identifier":
        return constants.get(java_parser.text(argument))
    return None


def _skill_builder(invocation: Node) -> str | None:
    """Which Skill builder the chain holding *invocation* starts from, if any.

    ``skill.toBuilder()`` receives an already-built Skill, so the builder's type
    comes from the value rather than from the name the variable happens to be
    spelled with -- which is why the generic walk reports the receiver text and
    this function, not that walk, decides what it means.
    """
    entry = builder_chains.chain_entry(invocation)
    if entry is None:
        return None
    receiver, entry_method = entry
    if entry_method == "toBuilder":
        return SKILL_BUILDER
    return receiver if receiver in SKILL_BUILDERS else None


def _chain_key(invocation: Node) -> tuple[int, int]:
    """The identity of the chain *invocation* belongs to, within one unit.

    Chains are keyed by their own start position, so two Skills built in one
    statement stay two Skills. One spelling rather than two, because reading a
    ``.tools(...)`` call and a ``.name(...)`` call as one chain has to mean
    exactly what grouping two setters into one Skill means.
    """
    return (invocation.start_point[0], builder_chains.chain_start(invocation))


def find_skill_definitions(source: str) -> list[SkillDefinition]:
    """Every Skill-builder chain in *source*, with each text argument resolved."""
    root = java_parser.parse(source).root_node
    constants = _string_constants(root)

    by_root: dict[tuple[int, int], list[BuilderArgument]] = {}
    builders: dict[tuple[int, int], str] = {}
    for node in java_parser.walk(root):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or java_parser.text(name_node) not in TEXT_SETTERS:
            continue
        builder = _skill_builder(node)
        if builder is None:
            continue
        argument = builder_chains.sole_argument(node)
        if argument is None:
            continue
        key = _chain_key(node)
        builders[key] = builder
        argument_line = java_parser.line(argument)
        is_text_block = java_parser.text(argument).startswith(_TEXT_BLOCK_DELIMITER)
        by_root.setdefault(key, []).append(
            BuilderArgument(
                setter=java_parser.text(name_node),
                line=argument_line,
                value=_resolve(argument, constants),
                value_start_line=argument_line + 1 if is_text_block else argument_line,
            )
        )

    return [
        SkillDefinition(
            builder=builders[key],
            line=min(argument.line for argument in arguments),
            arguments=tuple(sorted(arguments, key=lambda item: (item.line, item.setter))),
        )
        for key, arguments in sorted(by_root.items())
    ]


def find_skill_loader_calls(source: str) -> list[SkillLoaderCall]:
    """Every filesystem or classpath Skill-loader call in *source*."""
    root = java_parser.parse(source).root_node
    constants = _string_constants(root)

    calls: list[SkillLoaderCall] = []
    for node in java_parser.walk(root):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        target = node.child_by_field_name("object")
        if name_node is None or target is None:
            continue
        method = java_parser.text(name_node)
        loader = java_parser.text(target)
        if method not in LOADER_METHODS or loader not in SKILL_LOADERS:
            continue
        calls.append(
            SkillLoaderCall(
                loader=loader,
                method=method,
                line=java_parser.line(node),
                directory=_loader_directory(loader, node, constants),
            )
        )
    return calls


def _loader_directory(loader: str, invocation: Node, constants: dict[str, str]) -> str | None:
    """The Scan-relative directory a loader call reads, when it is a literal.

    ``Path.of("skills/")`` is unwrapped: the filesystem loader takes a ``Path``,
    so the literal is one call deeper than the classpath loader's.
    """
    argument = builder_chains.sole_argument(invocation)
    if argument is None:
        return None
    if argument.type == "method_invocation":
        argument = builder_chains.sole_argument(argument)
        if argument is None:
            return None
    literal = _resolve(argument, constants)
    if literal is None:
        return None
    directory = literal.rstrip("/")
    if loader == CLASSPATH_SKILL_LOADER:
        return f"{_CLASSPATH_ROOT}{directory}"
    return directory


def _chain_skill_names(root: Node, constants: dict[str, str]) -> dict[tuple[int, int], str]:
    """The Skill name each builder chain in the unit set, where it set a readable one."""
    names: dict[tuple[int, int], str] = {}
    for node in java_parser.walk(root):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or java_parser.text(name_node) != NAME_SETTER:
            continue
        if _skill_builder(node) is None:
            continue
        argument = builder_chains.sole_argument(node)
        if argument is None:
            continue
        value = _resolve(argument, constants)
        if value is not None:
            names.setdefault(_chain_key(node), value)
    return names


def find_attached_tools(source: str) -> list[AttachedTools]:
    """Every ``.tools(...)`` call on a Skill-builder chain in *source*."""
    root = java_parser.parse(source).root_node
    skill_names = _chain_skill_names(root, _string_constants(root))

    attached: list[AttachedTools] = []
    for node in java_parser.walk(root):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or java_parser.text(name_node) != TOOLS_SETTER:
            continue
        if _skill_builder(node) is None:
            continue
        attached.append(
            AttachedTools(
                line=java_parser.line(node),
                type_names=tuple(
                    name
                    for argument in builder_chains.argument_list(node)
                    for name in _attached_types(argument)
                ),
                skill_name=skill_names.get(_chain_key(node)),
            )
        )
    return attached


def _attached_types(argument: Node) -> list[str | None]:
    """The tool classes *argument* attaches, one entry each, ``None`` where unnamed.

    Usually one entry. ``.tools(...)`` is varargs, so an explicit array is a legal
    -- if unidiomatic -- way to pass the same set: ``new OrderTools[]{new
    OrderTools()}`` names its classes exactly as ``.tools(new OrderTools())``
    does, and reading it as one unnameable argument would report an unresolved
    tool set over source that hides nothing.

    A sized array with no initializer -- ``new Object[n]`` -- stays unnamed. Its
    contents are filled in somewhere else, which is the case this Rule exists
    for; ``new Object[0]`` is caught by the same reading, and nobody writes it.
    """
    if argument.type == "array_creation_expression":
        initializer = next(
            (child for child in argument.children if child.type == "array_initializer"), None
        )
        if initializer is None:
            return [None]
        elements = [child for child in initializer.children if child.type not in {"{", "}", ","}]
        return [_constructed_type(element) for element in elements] or [None]
    return [_constructed_type(argument)]


def _constructed_type(argument: Node) -> str | None:
    """The class name *argument* constructs, or ``None`` if it is not a ``new X()``."""
    if argument.type != "object_creation_expression":
        return None
    for child in argument.children:
        if child.type == "type_identifier":
            return java_parser.text(child)
    return None
