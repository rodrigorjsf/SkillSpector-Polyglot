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

"""``unscored_rule_ids`` and ``unscored_rule_note`` have exactly one publisher.

Both are **bare** channels on :class:`~skillspector.state.SkillspectorState` --
no ``Annotated`` reducer -- while ``graph.build_graph`` fans every Analyzer node
out from ``build_context`` in parallel. LangGraph accepts one write per bare
channel per superstep, so a second Analyzer publishing either key raises
``InvalidUpdateError`` *while applying the channel update*. That is outside any
node, and therefore past where ``guard_analyzer_node`` converts an Analyzer's
exception into ``{"findings": []}``: the whole Scan dies rather than one
Analyzer degrading. :func:`test_a_second_publisher_would_kill_the_scan` measures
exactly that, so the cost is a fact here and not an argument.

Adding a second publisher is allowed -- it just has to choose a reducer for
**both** keys first, and the note is the harder half: two remedies cannot
concatenate into one sentence, so the honest shape is a mapping from rule id to
its note rather than ``operator.add``. This module forces that choice at test
time instead of in a crash.

**What counts as publishing.** A write is a dict *literal* keyed by the name --
the shape every Analyzer's ``AnalyzerNodeResponse`` return takes. A read is
``state.get("unscored_rule_ids")``, a call, which ``report`` and ``cli`` both
do legitimately. Matching the literal rather than the bare string is what keeps
those readers out of the count; a substring grep would flag them and force the
guard to be loosened into uselessness.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import cast

import pytest
from langgraph.graph import END, START, StateGraph

from skillspector.state import SkillspectorState

SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "skillspector"

# The keys that travel together and share the single-publisher constraint.
UNSCORED_KEYS = ("unscored_rule_ids", "unscored_rule_note")

# Path relative to ``SOURCE_ROOT``. Changing this means changing the design, not
# fixing the test -- read the module docstring first.
SOLE_PUBLISHER = "nodes/analyzers/structure_agent_skills_spec.py"


def _modules_writing(key: str) -> set[str]:
    """Every module under ``src/skillspector`` with a dict literal keyed *key*."""
    writers: set[str] = set()
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            if any(
                isinstance(literal, ast.Constant) and literal.value == key
                for literal in node.keys
                if literal is not None
            ):
                writers.add(path.relative_to(SOURCE_ROOT).as_posix())
                break
    return writers


@pytest.mark.parametrize("key", UNSCORED_KEYS)
def test_exactly_one_module_publishes_the_key(key: str) -> None:
    """A second publisher must decide a reducer before it can be written."""
    assert _modules_writing(key) == {SOLE_PUBLISHER}


def test_the_reader_is_not_mistaken_for_a_publisher() -> None:
    """The control: ``report`` reads both keys and must stay out of the count.

    Without it a green result above could mean the matcher finds nothing at all.
    """
    source = (SOURCE_ROOT / "nodes" / "report.py").read_text(encoding="utf-8")
    for key in UNSCORED_KEYS:
        assert f'state.get("{key}")' in source
    assert "nodes/report.py" not in _modules_writing("unscored_rule_ids")


@pytest.mark.parametrize("key", UNSCORED_KEYS)
def test_a_second_publisher_would_kill_the_scan(key: str) -> None:
    """The measurement behind the rule, and its control.

    Two parallel writers of a bare key raise; the same graph shape writing a key
    that carries a reducer merges instead. The difference is the annotation, not
    the graph.
    """

    def _graph(update_key: str, values: tuple[object, object]) -> StateGraph:
        builder = StateGraph(SkillspectorState)
        for name, value in zip(("first", "second"), values, strict=True):
            builder.add_node(name, lambda _state, _value=value: {update_key: _value})
            builder.add_edge(START, name)
            builder.add_edge(name, END)
        return builder

    bare = _graph(key, (["A"], ["B"]) if key.endswith("ids") else ("a", "b"))
    with pytest.raises(Exception, match="only one value per step"):
        bare.compile().invoke(cast("SkillspectorState", {}))

    reduced = _graph("analyzer_status_events", ([{"analyzer_id": "a"}], [{"analyzer_id": "b"}]))
    merged = reduced.compile().invoke(cast("SkillspectorState", {}))
    assert [event["analyzer_id"] for event in merged["analyzer_status_events"]] == ["a", "b"]
