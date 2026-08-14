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

"""How far a Deep Agents for JavaScript host configuration resolves, and where it stops.

``createDeepAgent({...})`` is where a Deep Agents for JavaScript application says
which Skill sources the agent is given, what it may do to them, and whether they
are on disk at all. This module reads that call and resolves **a literal and a
constant declared at the top level of the same module. Nothing else.**

That boundary is not new and is not this module's invention.
``docs/adr/0008-deepagents-analyzer-resolves-one-module-deep.md`` §1 copies it
from the Java track, and ``docs/adr/0009-tree-sitter-for-typescript-parsing.md``
copies it again here, so the project keeps one resolution rule rather than one per
Framework.

**Where the port is not a copy.** The Python resolver reads *keyword arguments*
and states as a limit that a positionally passed configuration is not seen at
all. That inverts here, because the JavaScript API has no keyword arguments: every
setting is a property of **one options object** passed as the first argument. So
this module reads the first argument *if it is an object literal* and refuses
everything else -- ``createDeepAgent(buildOptions())`` resolves to nothing and
raises no boundary, exactly as the positional Python call does. Two more shapes
differ, and both are read from the captured code blocks rather than from the
Python module:

* A permission rule is a **plain object literal**, not a
  ``FilesystemPermission(...)`` construction. There is no class to name.
* ``CompositeBackend`` takes its default backend and its route map as two
  **positional** arguments. There is no ``routes`` key, so the map is read by
  position -- the one place this module reads a value by position, and it does so
  because upstream publishes no other spelling for it.

So a value assembled at runtime resolves to nothing, and nothing is the answer
this module returns -- never a guess. The Analyzer turns each of those into a
``DA-UNRESOLVED`` Finding that names *which* thing was unresolvable.

**What this module deliberately does not decide.** It says whether the backend
was readable, which literal Skill source paths are routed somewhere whose contents
are computed per request, and which permission rules and interrupt gates were
written -- in the order they were written, because that order is semantics. It
does **not** say whether any path is writable, whether a rule covers it, or which
rule wins: that verdict is :mod:`skillspector.deepagents_js.writability`.

Known limits, stated rather than discovered:

* An aliased import -- ``import { createDeepAgent as makeAgent }`` -- is not
  matched. Recognizing it means tracking import bindings, which is the same
  interprocedural reach §3.6 declined.
* A backend nested inside another backend's route is recognized by name and not
  walked further. One level is what the captured reference documents.
* A name declared more than once at the top level resolves to nothing, because
  which declaration reaches the call is control flow this module does not model.
* A string written with an escape sequence, or a template literal carrying a
  substitution, resolves to nothing. Upstream's Skill paths are plain quoted
  strings, and decoding JavaScript escapes correctly is a second parser this
  module declines to be.
* ``process.cwd()`` is not a literal, so upstream's own headline example --
  ``new FilesystemBackend({ rootDir: process.cwd() })`` -- reaches the boundary
  rather than a root. That is the honest answer: the directory the process starts
  in is not a fact in any scanned file.
* A property of the ``createDeepAgent`` options object that this module cannot
  read -- a spread, ``{ ...base, skills: [...] }``, or a method shorthand, a
  getter, a computed key -- is dropped and the properties written beside it are
  still read. For the spread that mirrors the Python resolver, which drops the
  ``**`` entry and keeps the named keywords; for the rest it is the same
  argument, since refusing the whole object made a configuration written out in
  full report nothing at all. A setting the dropped property carried is
  invisible, and where it was the one that *clears* a Finding the result is an
  over-report. :func:`_options` argues the direction, and the refusal is kept at
  every other object, where dropping a property would instead clear something.
* A transparent wrapper around a value -- ``x as T``, ``x satisfies T``, ``x!``,
  ``<T>x``, ``(x)`` -- is unwrapped rather than refused. Each is erased by the
  compiler, so reading through it resolves more without guessing at anything;
  :func:`_effective` records what stopping at one cost.

Comments are not read anywhere. tree-sitter reports one as a named child of the
node that encloses it, so a note written inside the options object sits among the
properties and a note before an argument sits ahead of it; :func:`_significant`
drops them at every reader. This is not a nicety -- upstream's own published
example writes a ``//`` note inside ``createDeepAgent({...})``, and reading it as
syntax silenced all four Rules on the very configuration the page teaches.

Provenance
----------

Captured from ``docs/references/deepagents-js-skills.md`` (upstream
<https://docs.langchain.com/oss/javascript/deepagents/skills>).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from tree_sitter import Node, Tree

from skillspector.deepagents_js import parser, vocabulary

# `None` is a value a literal can legitimately resolve to -- JavaScript's `null`
# is one -- so "did not resolve" needs a marker of its own rather than borrowing
# it.
_UNRESOLVED: Final[object] = object()

_BACKENDS: Final[frozenset[str]] = frozenset(
    {
        vocabulary.COMPOSITE_BACKEND,
        vocabulary.STORE_BACKEND,
        vocabulary.STATE_BACKEND,
        vocabulary.FILESYSTEM_BACKEND,
    }
)

# The node types this module reads. Grouped here rather than spelled at each use
# so the set a grammar upgrade could move is visible in one place. None of them
# is upstream vocabulary -- they are tree-sitter's names for JavaScript syntax --
# so none belongs in the inventory module.
_OBJECT: Final[str] = "object"
_ARRAY: Final[str] = "array"
_PAIR: Final[str] = "pair"
_SHORTHAND: Final[str] = "shorthand_property_identifier"
_IDENTIFIER: Final[str] = "identifier"
_STRING: Final[str] = "string"
_TEMPLATE_STRING: Final[str] = "template_string"
_STRING_FRAGMENT: Final[str] = "string_fragment"
_NUMBER: Final[str] = "number"
_TRUE: Final[str] = "true"
_FALSE: Final[str] = "false"
_NULL: Final[str] = "null"
_UNDEFINED: Final[str] = "undefined"
_CALL: Final[str] = "call_expression"
_NEW: Final[str] = "new_expression"
_MEMBER: Final[str] = "member_expression"
_DECLARATIONS: Final[tuple[str, ...]] = ("lexical_declaration", "variable_declaration")
_DECLARATOR: Final[str] = "variable_declarator"
_COMMENT: Final[str] = "comment"
_EXPORT: Final[str] = "export_statement"
_AWAIT: Final[str] = "await_expression"

# Expressions that wrap a value and change nothing about it. Three are
# TypeScript's ways of saying something about a value's *type* -- ``x as T``,
# ``x satisfies T``, ``x!`` -- and the fourth is a pair of parentheses. Every one
# of them is invisible at runtime, so a reader that stopped at one reported a
# literal written in front of it as though it were not there: on
# ``createDeepAgent({ skills: [...] } satisfies CreateDeepAgentOptions)`` all
# four Rules fell silent while every setting was written at the call site. The
# value is the wrapper's first significant child in each.
_TRANSPARENT: Final[frozenset[str]] = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
    }
)

# The one transparent wrapper written the other way round. ``<T>value`` puts the
# type *first*, so its value is the last significant child rather than the first,
# and it is unwrapped separately for that reason alone.
_TYPE_ASSERTION: Final[str] = "type_assertion"


def _significant(node: Node) -> list[Node]:
    """*node*'s named children, with the comments dropped.

    tree-sitter reports a comment as a **named child** of whatever encloses it,
    so an object literal written the way upstream writes it -- with a note above
    the setting it explains -- has a ``comment`` sitting among its ``pair``
    nodes, and an argument list with a note before its first argument has one
    ahead of that argument. Every reader below walks named children looking for
    syntax, and a comment is not syntax: it carries no value, shifts no
    argument's position, and changes no configuration. Reading it as one made a
    single ``//`` anywhere inside ``createDeepAgent({...})`` silence all four
    Rules, which is why this exists.

    Deliberately **not** used by :func:`_string_value`. That function's refusal
    of any child which is not a ``string_fragment`` is the escape-sequence
    boundary this module states, not an oversight about comments -- a string has
    no comments inside it.
    """
    return [child for child in node.named_children if child.type != _COMMENT]


@dataclass(frozen=True)
class Resolution:
    """One property of the ``createDeepAgent({...})`` options object, as far as it resolved.

    *line* is where the property's value is written, so a Finding sends a reviewer
    to the setting rather than to the top of a multi-line call. *value* is ``None``
    when the expression is one this module refuses to guess at -- the boundary, not
    an empty configuration. A property that is simply absent is represented by the
    absence of a ``Resolution`` at all.
    """

    line: int
    value: object | None

    @property
    def unresolved(self) -> bool:
        """Whether the expression fell on the boundary side."""
        return self.value is None


@dataclass(frozen=True)
class PermissionRule:
    """One permission rule object whose every property resolved.

    *settings* is keyed by the property as written. This module requires all of
    them to resolve without caring which they are;
    :mod:`skillspector.deepagents_js.writability` is where they are read by name,
    and it is the only place that knows what a ``mode`` means.
    """

    line: int
    settings: Mapping[str, object]


@dataclass(frozen=True)
class OpaqueRoute:
    """A resolved Skill source path routed somewhere the Scan cannot look into.

    Upstream's own namespaced-skills example is the shape: a literal route key
    mapping a Skill path onto a ``StoreBackend`` whose namespace is a function of
    the request. The *path* resolves; what lives at it does not, so the writability
    verdict has nowhere to land.
    """

    path: str
    line: int


@dataclass(frozen=True)
class FilesystemRoot:
    """Where a ``FilesystemBackend`` roots the agent-visible paths it is given.

    A configured Skill source path is relative to the backend root rather than to
    the Scan root, so this is the one value that turns ``/skills/shared/`` into a
    place this Scan can open. It is a **channel of its own** rather than a state of
    :class:`Resolution` on ``backend``: an unreadable ``rootDir`` leaves the
    backend perfectly well identified, and folding the two together would silence
    the writability verdict -- which asks only *which* backend this is -- on a
    configuration it can decide.

    *root* is ``None`` only when ``rootDir`` is written and does not resolve. An
    **absent** ``rootDir`` is not that: it resolves to the Scan root, on the stated
    limit below, because absent is a configuration rather than a boundary.

    Known limit, stated rather than discovered: a ``rootDir`` is read as relative
    to the Scan root. Upstream's is relative to the process working directory,
    which is not a fact in any scanned file, and reading it as the Scan root is
    what makes the common layout map at all. Where the two differ, the mapping
    finds no manifest under the path and the Rule stays silent, which is the
    direction that under-reports rather than the one that invents a collision.
    """

    root: str | None
    line: int

    @property
    def unresolved(self) -> bool:
        """Whether a written ``rootDir`` fell on the boundary side."""
        return self.root is None


@dataclass(frozen=True)
class SubagentDefinition:
    """One element of a ``subagents`` list, read as far as its keys.

    *keys* is every property the definition is written with, and the values are not
    read at all. A realistic definition binds tools to objects no Scan can
    evaluate, so requiring the whole object to resolve would send every one of them
    to the boundary and the Rule that reads this would never fire.

    *line* is where the definition opens, which is what tells two of them apart.
    The JavaScript capture *does* publish a definition's shape, so naming the
    subagent would be possible here -- and is deliberately not done, because
    ``DA-SUBAGENT-SKILLS`` is one Rule across both Frameworks and must report one
    thing. ADR 0009 records it.
    """

    line: int
    keys: frozenset[str]


@dataclass(frozen=True)
class AgentConfiguration:
    """One ``createDeepAgent({...})`` call, read as far as this module resolves.

    Each of these settings is ``None`` when it is not written at all, which is a
    different statement from a ``Resolution`` that did not resolve. Absent is a
    configuration -- no Skills, no permission rules, the default backend -- and the
    Analyzer says nothing about it. Unresolved is a boundary.
    """

    line: int
    skill_paths: Resolution | None
    permission_rules: Resolution | None
    backend: Resolution | None
    opaque_routes: tuple[OpaqueRoute, ...]

    # Read for the writability verdict, and deliberately *not* reported as a
    # boundary of its own. An `interruptOn` this module cannot read is a mitigation
    # that cannot be confirmed, and an unconfirmed mitigation is no mitigation --
    # which raises the severity of a Finding rather than removing one.
    interrupt_on: Resolution | None = None

    # Where the backend roots the paths above, when it is a ``FilesystemBackend``
    # and therefore the only one whose files a Scan can ever open. ``None`` says
    # the Skill files are not on disk under this configuration.
    filesystem_root: FilesystemRoot | None = None

    # The custom subagents this call defines, or the boundary. Absent is a
    # configuration here as everywhere else.
    subagents: Resolution | None = None


def find_agent_configurations(tree: Tree) -> list[AgentConfiguration]:
    """Every ``createDeepAgent({...})`` in one module, read one module deep.

    Walks the whole tree rather than its top level: upstream's own dynamic example
    builds the agent inside a factory function, and a call this module could not
    see is a configuration nobody would be told about.

    Constants are collected from the module's top level only. A name bound inside a
    function or a class body resolves to nothing, and so does a function parameter
    -- which is the right answer for a per-request value, not a limitation to work
    around.
    """
    constants = _module_constants(tree.root_node)
    return [
        _configuration(node, constants)
        for node in parser.walk(tree.root_node)
        if node.type == _CALL and _called_name(node) == vocabulary.CREATE_DEEP_AGENT
    ]


def _configuration(call: Node, constants: Mapping[str, Node]) -> AgentConfiguration:
    """Read one call's options object, and the routes that cover its Skill paths."""
    options = _options(call, constants)

    skills = options.get(vocabulary.SKILLS)
    skill_paths = (
        None
        if skills is None
        else Resolution(parser.line(skills), _string_sequence(skills, constants))
    )

    permissions = options.get(vocabulary.PERMISSIONS)
    permission_rules = (
        None
        if permissions is None
        else Resolution(parser.line(permissions), _permission_rules(permissions, constants))
    )

    backend_property = options.get(vocabulary.BACKEND)
    backend, routes, filesystem_root = (
        (None, (), None) if backend_property is None else _backend(backend_property, constants)
    )

    # A route is only a boundary for a Skill path that resolved. Where the Skill
    # list itself did not resolve, that is already reported and saying it twice in
    # two vocabularies would describe one silence as two.
    resolved_paths = skill_paths.value if skill_paths is not None else None
    covered = (
        ()
        if not isinstance(resolved_paths, tuple)
        else tuple(route for route in routes if _covers_any(route.path, resolved_paths))
    )

    interrupt_property = options.get(vocabulary.INTERRUPT_ON)
    interrupt_on = (
        None
        if interrupt_property is None
        else Resolution(
            parser.line(interrupt_property), _interrupt_tools(interrupt_property, constants)
        )
    )

    subagent_property = options.get(vocabulary.SUBAGENTS)
    subagents = (
        None
        if subagent_property is None
        else Resolution(
            parser.line(subagent_property), _subagent_definitions(subagent_property, constants)
        )
    )

    return AgentConfiguration(
        line=parser.line(call),
        skill_paths=skill_paths,
        permission_rules=permission_rules,
        backend=backend,
        opaque_routes=covered,
        interrupt_on=interrupt_on,
        filesystem_root=filesystem_root,
        subagents=subagents,
    )


def _options(call: Node, constants: Mapping[str, Node]) -> dict[str, Node]:
    """The settings a ``createDeepAgent`` call was written with, by property name.

    Empty when the first argument is not an object literal this module can read
    -- ``createDeepAgent(buildOptions())``. That is a silence rather than a
    boundary: an options object built elsewhere carries no setting this Scan can
    attribute to any name, so there is nothing to report *about*, because
    ``DA-UNRESOLVED`` names a setting and here no setting was named.

    **A property this module cannot read is tolerated here and nowhere else.**
    This is the one call site that passes ``tolerate_unreadable``. For a spread
    it does so to match the Python track: ``skillspector.deepagents.host_config``
    reads ``call.keywords`` and drops the entry whose ``arg`` is ``None``, so
    ``create_deep_agent(**base, skills=[...])`` still resolves its ``skills``.
    One rule id must not mean two things because the application was written in
    a second language, and refusing the whole object here made the JavaScript
    spelling of that call report nothing at all. The same argument carries the
    other unreadable shapes -- a method shorthand, a getter, a computed key --
    which are not JavaScript's spelling of anything the Python resolver reads,
    but which had the identical effect: one ``hook() {}`` beside a literal
    ``skills: ["/skills/"]`` silenced all four Rules on a configuration written
    out in full.

    Tolerating is monotone here, which is what makes it safe rather than merely
    convenient: a dropped property reads as *absent*, and the refusal it replaces
    made **every** property absent. So this call site can only ever read more
    settings than before, never fewer, and no Finding this function used to
    support can disappear because of it.

    Known limit, stated rather than discovered: what the dropped property carried
    is invisible either way, and where it was the setting that *clears* a Finding
    -- a ``permissions`` rule denying write -- the verdict reads the remaining
    properties as the whole configuration and reports a write nothing denies.
    That is an over-report where the refusal was a total silence, and it is the
    direction this scanner prefers; a reviewer sees a Finding to dismiss rather
    than nothing to notice. The refusal is kept everywhere a dropped property
    could instead *clear* something -- a permission rule, an ``interruptOn``
    gate, a ``rootDir``, a route map, a subagent definition -- because there
    silence would be the under-report.
    """
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return {}
    positional = _significant(arguments)
    if not positional:
        return {}
    entries = _entries(positional[0], constants, tolerate_unreadable=True)
    return {} if entries is None else entries


def _entries(
    node: Node, constants: Mapping[str, Node], *, tolerate_unreadable: bool = False
) -> dict[str, Node] | None:
    """An object literal's properties by name, or ``None``.

    A property this module cannot read makes the whole object unreadable: a
    spread carries settings it will not guess at, and a method shorthand, a
    getter or a computed key each bind a name it cannot name. Any of them may be
    the very setting a Rule looks for, so the object is refused rather than
    reported short. *tolerate_unreadable* keeps the properties that **were**
    readable and drops the rest, and only :func:`_options` asks for it -- see
    there for why the two answers differ by call site rather than by syntax. A
    shorthand property -- ``{ backend }`` -- maps its name onto the identifier
    node, which the constant follower then resolves like any other name.
    """
    effective = _effective(node, constants)
    if effective is None or effective.type != _OBJECT:
        return None
    entries: dict[str, Node] = {}
    for child in _significant(effective):
        readable = _property(child)
        if readable is None:
            if tolerate_unreadable:
                continue
            return None
        name, value = readable
        entries[name] = value
    return entries


def _property(child: Node) -> tuple[str, Node] | None:
    """One object property as a name and the expression bound to it, or ``None``.

    ``None`` covers everything this module has no name-to-value reading for: a
    spread element, a method shorthand, a getter or setter, and a computed key.
    They are one answer rather than four because every caller does the same thing
    with them, and :func:`_entries` is where that thing differs.
    """
    if child.type == _SHORTHAND:
        return parser.text(child), child
    if child.type != _PAIR:
        return None
    key = child.child_by_field_name("key")
    value = child.child_by_field_name("value")
    if key is None or value is None:
        return None
    name = _key_name(key)
    return None if name is None else (name, value)


def _key_name(key: Node) -> str | None:
    """The name a property key spells, or ``None`` for one computed at runtime."""
    if key.type in (_STRING, _TEMPLATE_STRING):
        return _string_value(key)
    if key.type in ("property_identifier", _IDENTIFIER, _SHORTHAND):
        return parser.text(key)
    return None


def _subagent_definitions(
    node: Node, constants: Mapping[str, Node]
) -> tuple[SubagentDefinition, ...] | None:
    """The subagents a ``subagents`` list defines, or ``None``.

    Every element must be an object literal readable here. One element this module
    cannot read makes the whole list unresolved, for ``_string_sequence``'s reason:
    a partially read list of definitions would be reported as a complete one, and
    the Rule that reads it reports an *absence*.
    """
    effective = _effective(node, constants)
    if effective is None or effective.type != _ARRAY:
        return None
    definitions: list[SubagentDefinition] = []
    for element in _significant(effective):
        mapping = _effective(element, constants)
        if mapping is None or mapping.type != _OBJECT:
            return None
        keys = _entries(mapping, constants)
        if keys is None:
            return None
        definitions.append(SubagentDefinition(line=parser.line(mapping), keys=frozenset(keys)))
    return tuple(definitions)


def _interrupt_tools(node: Node, constants: Mapping[str, Node]) -> frozenset[str] | None:
    """The tool names an ``interruptOn`` object gates, or ``None``.

    Only the names mapped to a value that is truthy at resolution time are
    returned: upstream writes ``{ read_file: true, write_file: true }``, and a key
    written ``false`` is the developer turning the gate off.
    """
    value = _literal(node, constants)
    if not isinstance(value, Mapping):
        return None
    return frozenset(str(tool) for tool, gated in value.items() if isinstance(tool, str) and gated)


def _covers_any(prefix: str, paths: tuple[object, ...]) -> bool:
    """Whether a route prefix routes any of *paths*.

    A route map keys path *prefixes* onto backends, so a route covers a Skill
    source path when the path starts with it. The equal case -- upstream's own
    example routes exactly the path it passes -- is covered by the same test.
    """
    return any(isinstance(path, str) and path.startswith(prefix) for path in paths)


def _module_constants(root: Node) -> dict[str, Node]:
    """The module's top-level names, mapped to the expression each was declared with.

    A name declared more than once is dropped rather than resolved to its last
    declaration: which one reaches the call is control flow, and guessing is the
    thing this module exists not to do.

    Only the top level is read. ``var``, ``let`` and ``const`` are all collected --
    the declaration keyword says nothing about whether the value is readable, and
    upstream's own examples use ``const`` throughout.

    **An exported declaration is a top-level declaration.** ``export const`` is
    the dominant TypeScript module idiom, and the grammar wraps its declaration
    in an ``export_statement`` rather than placing it at the root, so reading the
    root's children alone made the single word ``export`` the difference between
    a name that resolves and one that does not. Unwrapping the statement is what
    keeps the promise the paragraph above makes. A form that binds no
    declaration -- ``export default foo``, a bare ``export { x }``, a
    ``export * from`` re-export -- has no ``declaration`` child and is skipped:
    the first declares nothing new, and the other two rename a binding whose
    value is in another module, which is a reach past this module's one-module
    boundary.
    """
    declared: dict[str, Node] = {}
    redeclared: set[str] = set()
    for statement in root.named_children:
        declaration = statement
        if declaration.type == _EXPORT:
            exported = declaration.child_by_field_name("declaration")
            if exported is None:
                continue
            declaration = exported
        if declaration.type not in _DECLARATIONS:
            continue
        for declarator in declaration.named_children:
            # A comment among the declarators needs no filtering here: it is not
            # a ``variable_declarator``, and this test already drops it. The
            # readers that index or count their children are the ones that need
            # ``_significant``.
            if declarator.type != _DECLARATOR:
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None or value is None or name.type != _IDENTIFIER:
                continue
            spelled = parser.text(name)
            if spelled in declared:
                redeclared.add(spelled)
            declared[spelled] = value
    return {name: value for name, value in declared.items() if name not in redeclared}


def _effective(node: Node, constants: Mapping[str, Node]) -> Node | None:
    """Follow a name to the expression it was declared with, or return the node itself.

    Names chain -- ``const BACKEND = DEFAULT_BACKEND`` -- so this follows them
    until it reaches something that is not a name. A name it cannot resolve, and a
    cycle, both return ``None``: the boundary.

    A ``shorthand_property_identifier`` is followed too: ``{ backend }`` names the
    constant ``backend``, and reading it any other way would make the shorthand a
    boundary where the longhand is not.

    **A transparent wrapper is unwrapped rather than refused.** ``x as T``,
    ``x satisfies T``, ``x!``, ``<T>x`` and ``(x)`` all evaluate to ``x``, so
    stopping at one reported a value written in plain sight as unreadable --
    ``createDeepAgent({ skills: [...] } satisfies CreateDeepAgentOptions)``
    silenced all four Rules, and ``skills: ["/s/"] as const`` raised
    ``DA-UNRESOLVED`` on a fully literal list. Unwrapping resolves *more* rather
    than guessing at anything: the wrapper is erased by the compiler and none of
    them is a value this module then has to invent.

    The loop terminates: following a name is bounded by *seen*, and unwrapping
    strictly descends the tree.
    """
    seen: set[str] = set()
    current = node
    while True:
        if current.type in (_IDENTIFIER, _SHORTHAND):
            spelled = parser.text(current)
            if spelled in seen:
                return None
            seen.add(spelled)
            declared = constants.get(spelled)
            if declared is None:
                return None
            current = declared
            continue
        if current.type in _TRANSPARENT or current.type == _TYPE_ASSERTION:
            inner = _significant(current)
            if not inner:
                return None
            current = inner[-1] if current.type == _TYPE_ASSERTION else inner[0]
            continue
        return current


def _called_name(call: Node) -> str | None:
    """The name a call or construction is written with, whether bare or qualified.

    **The callee is unwrapped before it is read**, and ``await`` is the reason.
    Upstream writes ``await createDeepAgent({...})``, and where that call also
    carries a type argument -- ``await createDeepAgent<State>({...})`` -- the
    grammar parses it as a ``call_expression`` whose *function* field is the
    ``await_expression``, not the other way round. Reading the field literally
    therefore found nothing on that one shape, and a configuration nobody is told
    about is indistinguishable from a clean scan: the Analyzer still opens the
    file and still reports ``completed``. The transparent wrappers are unwrapped
    here for the same reason they are in :func:`_effective` -- ``(f)(x)`` and
    ``f!(x)`` call ``f``.
    """
    function = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    if function is None:
        return None
    while function.type in _TRANSPARENT or function.type == _AWAIT:
        inner = _significant(function)
        if not inner:
            return None
        function = inner[0]
    if function.type == _IDENTIFIER:
        return parser.text(function)
    if function.type == _MEMBER:
        property_node = function.child_by_field_name("property")
        return None if property_node is None else parser.text(property_node)
    return None


def _string_value(node: Node) -> str | None:
    """A quoted or template string's value, or ``None`` where it is not a plain one.

    An escape sequence and a template substitution both refuse: decoding
    JavaScript escapes correctly is a second parser, and a substitution is a value
    computed at runtime. Upstream's Skill paths are plain quoted strings, so the
    refusal costs nothing it documents and under-reports where it applies.
    """
    fragments: list[str] = []
    for child in node.named_children:
        if child.type != _STRING_FRAGMENT:
            return None
        fragments.append(parser.text(child))
    return "".join(fragments)


def _literal(node: Node, constants: Mapping[str, Node]) -> object:
    """The literal value of an expression, or ``_UNRESOLVED``.

    Reads the JavaScript literals upstream writes: strings, numbers, ``true``,
    ``false``, ``null``, ``undefined``, arrays and objects of those. Anything else
    -- a call, a function, a member expression such as ``process.cwd()`` -- is the
    boundary.
    """
    effective = _effective(node, constants)
    if effective is None:
        return _UNRESOLVED
    kind = effective.type
    if kind in (_STRING, _TEMPLATE_STRING):
        value = _string_value(effective)
        return _UNRESOLVED if value is None else value
    if kind == _TRUE:
        return True
    if kind == _FALSE:
        return False
    if kind in (_NULL, _UNDEFINED):
        return None
    if kind == _NUMBER:
        return _number(parser.text(effective))
    if kind == _ARRAY:
        members = [_literal(element, constants) for element in _significant(effective)]
        return _UNRESOLVED if any(member is _UNRESOLVED for member in members) else tuple(members)
    if kind == _OBJECT:
        entries = _entries(effective, constants)
        if entries is None:
            return _UNRESOLVED
        values = {name: _literal(value, constants) for name, value in entries.items()}
        return _UNRESOLVED if any(value is _UNRESOLVED for value in values.values()) else values
    return _UNRESOLVED


def _number(spelled: str) -> object:
    """A JavaScript numeric literal as a Python number, or ``_UNRESOLVED``.

    Separators are stripped because JavaScript allows them and Python's readers do
    not agree on where. Nothing this module decides turns on a number's value -- it
    is read so that an options object holding one still resolves as a whole.
    """
    cleaned = spelled.replace("_", "")
    for reader in (int, float):
        try:
            return reader(cleaned)
        except ValueError:
            continue
    return _UNRESOLVED


def _string_sequence(node: Node, constants: Mapping[str, Node]) -> tuple[str, ...] | None:
    """The Skill source paths a ``skills`` property names, or ``None``.

    Each element is resolved on its own rather than the whole array at once, so an
    array literal holding a same-module constant still resolves. One element that
    does not resolve makes the whole list unresolved: a partially known Skill list
    would be reported as a complete one.
    """
    effective = _effective(node, constants)
    if effective is None or effective.type != _ARRAY:
        return None
    paths: list[str] = []
    for element in _significant(effective):
        value = _literal(element, constants)
        if not isinstance(value, str):
            return None
        paths.append(value)
    return tuple(paths)


def _permission_rules(
    node: Node, constants: Mapping[str, Node]
) -> tuple[PermissionRule, ...] | None:
    """The permission rules a ``permissions`` property declares, or ``None``.

    Every element must be an object literal whose every property resolves. Unlike
    the Python track there is no constructor to check: upstream's JavaScript writes
    these as bare objects, and requiring a ``FilesystemPermission`` call would match
    a spelling the capture never publishes.
    """
    effective = _effective(node, constants)
    if effective is None or effective.type != _ARRAY:
        return None
    rules: list[PermissionRule] = []
    for element in _significant(effective):
        mapping = _effective(element, constants)
        if mapping is None or mapping.type != _OBJECT:
            return None
        entries = _entries(mapping, constants)
        if entries is None:
            return None
        settings: dict[str, object] = {}
        for name, value in entries.items():
            resolved = _literal(value, constants)
            if resolved is _UNRESOLVED:
                return None
            settings[name] = resolved
        rules.append(PermissionRule(line=parser.line(mapping), settings=settings))
    return tuple(rules)


def _backend(
    node: Node, constants: Mapping[str, Node]
) -> tuple[Resolution, tuple[OpaqueRoute, ...], FilesystemRoot | None]:
    """Which backend a ``backend`` property names, which routes stay opaque, and where it roots.

    Recognizing the backend is naming it: the four upstream backends resolve to
    their own spelling, and anything else -- a helper call, a name bound elsewhere
    -- resolves to nothing. Only a ``CompositeBackend`` is walked into, because it
    is the only one that maps paths onto other backends; a backend nested inside one
    of its routes is recognized by name and not walked again.

    The third value is the root only a ``FilesystemBackend`` has. The other three
    backends return ``None`` for it, which says their files are not on disk rather
    than that anything failed to resolve. A ``FilesystemBackend`` reached through a
    ``CompositeBackend`` route returns ``None`` too: that is the one-level limit this
    module already states, and reading a root out of a route without also reading
    which prefix it applies to would map the wrong paths.
    """
    resolution = Resolution(parser.line(node), None)
    construction = _effective(node, constants)
    if construction is None or construction.type not in (_NEW, _CALL):
        return resolution, (), None
    name = _called_name(construction)
    if name not in _BACKENDS:
        return resolution, (), None
    resolved = Resolution(parser.line(node), name)
    if name == vocabulary.FILESYSTEM_BACKEND:
        return resolved, (), _filesystem_root(construction, constants)
    if name != vocabulary.COMPOSITE_BACKEND:
        return resolved, (), None

    # The route map is the *second* positional argument. Upstream publishes no
    # keyword for it, so there is nothing else to read it by.
    arguments = construction.child_by_field_name("arguments")
    positional = [] if arguments is None else _significant(arguments)
    if len(positional) < 2:
        return resolved, (), None
    entries = _entries(positional[1], constants)
    if entries is None:
        return resolution, (), None

    opaque: list[OpaqueRoute] = []
    for path, target in entries.items():
        routed = _effective(target, constants)
        if routed is None or routed.type not in (_NEW, _CALL):
            return resolution, (), None
        routed_name = _called_name(routed)
        if routed_name not in _BACKENDS:
            return resolution, (), None
        if routed_name == vocabulary.STORE_BACKEND and _is_computed(routed, constants):
            opaque.append(OpaqueRoute(path=path, line=parser.line(target)))
    return resolved, tuple(opaque), None


# What an absent ``rootDir`` is read as. See :class:`FilesystemRoot` for why the
# absence is a configuration rather than a boundary, and for the limit that makes
# a written relative root read the same way.
_SCAN_ROOT: Final[str] = "."


def _filesystem_root(construction: Node, constants: Mapping[str, Node]) -> FilesystemRoot:
    """Where a ``FilesystemBackend({...})`` roots the paths it is given."""
    arguments = construction.child_by_field_name("arguments")
    positional = [] if arguments is None else _significant(arguments)
    entries = None if not positional else _entries(positional[0], constants)
    if entries is None:
        # No options object at all is an absent ``rootDir``; one this module could
        # not read is a written setting it could not resolve, and only the second
        # is a boundary. A comment is neither, which is why the emptiness is
        # tested against the significant children rather than every named one.
        return FilesystemRoot(
            root=None if positional else _SCAN_ROOT, line=parser.line(construction)
        )
    argument = entries.get(vocabulary.ROOT_DIR)
    if argument is None:
        return FilesystemRoot(root=_SCAN_ROOT, line=parser.line(construction))
    value = _literal(argument, constants)
    return FilesystemRoot(
        root=value if isinstance(value, str) else None, line=parser.line(argument)
    )


def _is_computed(construction: Node, constants: Mapping[str, Node]) -> bool:
    """Whether a store is configured with something evaluated per request.

    Upstream's example is a namespace arrow function over the request context, and
    its consequence is that what lives at the routed path differs per caller. Asked
    of the arguments as a whole rather than of the namespace by name: any argument
    this module cannot resolve leaves the store's contents unknowable in the same
    way, and asking generally means no keyword spelling is matched on here.
    """
    arguments = construction.child_by_field_name("arguments")
    if arguments is None:
        return False
    return any(_literal(argument, constants) is _UNRESOLVED for argument in _significant(arguments))
