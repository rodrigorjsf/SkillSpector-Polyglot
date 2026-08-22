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

"""What the two machine-readable writers say, beyond which Findings they carry.

Three defects, one pair of writers. Each class below is one of them.

Every assertion here is a **literal**, never a second call to the reader the
production code calls. Asserting ``shortDescription == get_pattern_name(rule_id)``
would restate the call site character for character and stay green through any
mutation of it; asserting the sentence the catalogue actually holds does not.

The scans run through the CLI rather than through ``report``'s helpers, because
what these issues are about is what a *consumer* of ``-f json`` and ``-f sarif``
receives. ``result.stdout`` is read apart from ``result.stderr``: the folded
``result.output`` would pass with the report on the wrong stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).parents[1] / "fixtures"

# A LangChain4j Skill whose Rules write per-instance messages: ``L4J-TOOL-DESC``
# names the class and the attachment site, and ``L4J-UNRESOLVED`` fires three
# times with three different sentences. That is what makes it the reproducer for
# a defect about instance text -- a fixture whose Rules all write one sentence
# could not tell the two fields apart.
LANGCHAIN4J_SHELL_SKILL = FIXTURES / "langchain4j_shell_skill"

# Verbatim from the Rules, not rebuilt from the analyzer's format string.
TOOL_DESC_INSTANCE_SENTENCE = (
    "The class OrderTools is attached to a Skill at src/main/java/com/example/ToolWiring.java:33."
)
UNRESOLVED_INSTANCE_SENTENCES = (
    "The Skill name is built dynamically, so the Scan cannot say which Skill this "
    "definition declares.",
    "Skill content is not statically resolvable, so the instruction surface the model "
    "reads was not scanned. It exists in no file this Scan could open.",
    "FileSystemSkillLoader.loadSkills is called with a path that is not a literal, so "
    "the Skills it loads were not located or scanned.",
)
# The catalogue paragraph for that same rule id -- rule-level, one per Rule.
UNRESOLVED_RULE_EXPLANATION_OPENING = (
    "A Java-defined Skill carries text that is not statically resolvable"
)


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop rich folding a long path, which no assertion in this file survives.

    A non-terminal rich ``Console`` defaults to 80 columns and folds inside an
    over-long unbreakable token, so whether an assertion matches would otherwise
    be a property of how long this checkout's path is.
    """
    monkeypatch.setenv("COLUMNS", "400")


def _scan_json(*extra: str, target: Path = LANGCHAIN4J_SHELL_SKILL) -> dict[str, object]:
    """The JSON report a consumer receives on stdout for one scan of *target*."""
    result = runner.invoke(app, ["scan", str(target), "--no-llm", "-f", "json", *extra])
    assert result.exit_code in (0, 1), result.stderr
    return json.loads(result.stdout)


def _issues(report: dict[str, object], rule_id: str) -> list[dict[str, object]]:
    """Every JSON issue attributed to *rule_id*, in report order."""
    issues = report["issues"]
    assert isinstance(issues, list)
    return [issue for issue in issues if issue.get("id") == rule_id]


class TestAJsonIssueCarriesItsOwnSentence:
    """Issue #117: the JSON report aliased ``message`` into ``explanation``.

    ``explanation`` says what the Rule means and is identical for every Finding
    of that Rule; ``message`` says what *this* Finding found. Projecting only the
    first, with the second as its fall-back, left a JSON consumer unable to tell
    two Findings of one Rule apart -- while SARIF and Markdown consumers could.
    """

    def test_the_instance_sentence_reaches_a_json_consumer(self) -> None:
        report = _scan_json()
        (tool_desc,) = _issues(report, "L4J-TOOL-DESC")
        assert TOOL_DESC_INSTANCE_SENTENCE in tool_desc["message"]

    def test_two_findings_of_one_rule_carry_two_different_sentences(self) -> None:
        report = _scan_json()
        unresolved = _issues(report, "L4J-UNRESOLVED")
        messages = [issue["message"] for issue in unresolved]
        assert len(messages) == len(set(messages)) == len(UNRESOLVED_INSTANCE_SENTENCES)
        assert set(messages) == set(UNRESOLVED_INSTANCE_SENTENCES)

    def test_explanation_stays_rule_level_across_those_same_instances(self) -> None:
        report = _scan_json()
        unresolved = _issues(report, "L4J-UNRESOLVED")
        explanations = {issue["explanation"] for issue in unresolved}
        assert len(explanations) == 1
        assert UNRESOLVED_RULE_EXPLANATION_OPENING in explanations.pop()
        # The separation is only real if the two fields disagree somewhere.
        assert all(issue["explanation"] != issue["message"] for issue in unresolved)
