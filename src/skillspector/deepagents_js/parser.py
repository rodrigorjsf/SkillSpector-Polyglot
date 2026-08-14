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

"""The tree-sitter binding for TypeScript and JavaScript, and nothing else.

Importing this module imports tree-sitter. That is the point: it is the single
place the dependency enters, so a Rule module can depend on a parser by importing
one name. ``langchain4j/java_parser.py`` is the shape this copies, and
``docs/adr/0009-tree-sitter-for-typescript-parsing.md`` is why the dependency was
accepted at all.

**Two grammars, not one.** ``tree-sitter-typescript`` ships
``language_typescript()`` and ``language_tsx()``, and they are not
interchangeable: JSX fails to parse under the TypeScript grammar, which reads
``<div/>`` as a type parameter list and produces an ``ERROR`` node. So a ``.tsx``
Component is parsed with the TSX grammar, and everything else is parsed with the
TypeScript grammar -- with a retry, described on :func:`parse`, for the one case
the suffix cannot decide.

**A parse error is tolerated rather than refused.** The grammar's last release
predates roughly two years of TypeScript syntax, so a modern file can carry a
construct it does not know. tree-sitter is error tolerant -- an unparseable
region becomes an ``ERROR`` node and its siblings still parse -- and the option
keys every Rule here reads are ordinary object properties that survive an error
elsewhere in the file. Refusing a file for ``has_error`` would therefore lose
whole configurations to a syntax the grammar merely has not caught up with, which
is the direction that reports nothing and says nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

import tree_sitter_typescript
from tree_sitter import Language, Node, Parser, Tree

# The suffix that decides the grammar. Every other JavaScript and TypeScript
# suffix this project opens is parsed as TypeScript, which is a superset of
# JavaScript and reads a plain ``.js`` module unchanged.
TSX_SUFFIX: Final[str] = ".tsx"

_TYPESCRIPT: Language | None = None
_TSX: Language | None = None


def _typescript() -> Language:
    """The TypeScript grammar, built once per process.

    ``Language`` compiles the grammar pointer into a lookup table, so building
    one per file would repeat that work on every Component of every Scan.
    """
    global _TYPESCRIPT
    if _TYPESCRIPT is None:
        _TYPESCRIPT = Language(tree_sitter_typescript.language_typescript())
    return _TYPESCRIPT


def _tsx() -> Language:
    """The TSX grammar, built once per process."""
    global _TSX
    if _TSX is None:
        _TSX = Language(tree_sitter_typescript.language_tsx())
    return _TSX


def parse(source: str, path: str) -> Tree:
    """Parse *source* into a syntax tree, choosing the grammar from *path*.

    Never raises on malformed input: an unparseable region becomes an ``ERROR``
    node and its siblings still parse, so a Rule reading the result sees the parts
    of a broken file that were valid.

    A ``.tsx`` Component goes straight to the TSX grammar. Anything else is parsed
    as TypeScript first, and **only if that fails** is the TSX grammar tried --
    which is what covers JSX written in a plain ``.js`` file, a shape the suffix
    cannot distinguish from ordinary JavaScript. The retry is kept only when it
    parses cleanly and the first attempt did not, so a file that genuinely uses
    TypeScript type parameters is never re-read as JSX.
    """
    encoded = source.encode("utf-8")
    if path.endswith(TSX_SUFFIX):
        return Parser(_tsx()).parse(encoded)
    tree = Parser(_typescript()).parse(encoded)
    if not tree.root_node.has_error:
        return tree
    retried = Parser(_tsx()).parse(encoded)
    return retried if not retried.root_node.has_error else tree


def walk(node: Node) -> Iterator[Node]:
    """Yield *node* and every node beneath it, in source order.

    Pre-order and left to right, so the first match a caller accepts is also the
    earliest one in the file.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def text(node: Node) -> str:
    """The source text *node* spans."""
    raw = node.text
    return "" if raw is None else raw.decode("utf-8", errors="replace")


def line(node: Node) -> int:
    """The 1-based line *node* starts on.

    tree-sitter counts rows from zero; Findings, SARIF and every human reading
    the report count from one.
    """
    return node.start_point[0] + 1
