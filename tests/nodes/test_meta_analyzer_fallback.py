# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

"""Tests for meta_analyzer heuristic fallback filter (--no-llm mode)."""

from __future__ import annotations

from unittest.mock import patch

from skillspector.agent_skills_spec import RULES
from skillspector.models import Finding
from skillspector.nodes.analyzers.structure_agent_skills_spec import node as spec_node
from skillspector.nodes.meta_analyzer import (
    _NO_LLM_CONFIDENCE_THRESHOLD,
    _fallback_filtered,
    _passthrough_with_defaults,
    meta_analyzer,
)


def _finding(
    rule_id: str = "TM1",
    confidence: float = 0.8,
    severity: str = "HIGH",
    context: str | None = "import subprocess\nsubprocess.run(cmd, shell=True)",
    matched_text: str = "subprocess.run(cmd, shell=True)",
    file: str = "tool.py",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"Test {rule_id}",
        severity=severity,
        confidence=confidence,
        file=file,
        start_line=1,
        context=context,
        matched_text=matched_text,
    )


class TestConfidenceThreshold:
    """Findings below confidence threshold are dropped (unless high severity)."""

    def test_low_confidence_low_severity_dropped(self) -> None:
        """LOW severity finding with confidence 0.3 is below threshold and dropped."""
        findings = [_finding(confidence=0.3, severity="LOW")]
        result = _fallback_filtered(findings)
        assert len(result) == 0

    def test_low_confidence_medium_severity_dropped(self) -> None:
        """MEDIUM severity finding with confidence 0.3 is dropped."""
        findings = [_finding(confidence=0.3, severity="MEDIUM")]
        result = _fallback_filtered(findings)
        assert len(result) == 0

    def test_at_threshold_kept(self) -> None:
        """Finding with confidence exactly 0.4 is kept (>= 0.4)."""
        findings = [_finding(confidence=0.4)]
        result = _fallback_filtered(findings)
        assert len(result) == 1

    def test_high_confidence_kept(self) -> None:
        """Finding with high confidence passes through."""
        findings = [_finding(confidence=0.9)]
        result = _fallback_filtered(findings)
        assert len(result) == 1


class TestConformanceFindingsNeedNoExemption:
    """The ``--no-llm`` filter carries conformance findings on their own confidence.

    This class used to pin an exemption, because ``--spec-checks advisory``
    encoded "reported but not scored" as ``confidence = 0.0`` and the 0.4
    threshold read that as a weak guess. The mode is now carried in the
    ``unscored_rule_ids`` state key and every conformance finding arrives at its
    rule's honest confidence, so the exemption was removed rather than left
    standing beside the mechanism that replaced it.

    What holds the removal up is a measurement, and it is asserted here rather
    than argued: the lowest confidence in the catalogue is above the threshold.
    """

    def test_every_catalogue_confidence_clears_the_threshold(self) -> None:
        """The measurement the removed exemption rested on, held to the catalogue.

        Lowering any rule below 0.4 -- or halving one past it with a
        code-example context -- would silently delete that rule from every
        ``--no-llm`` scan, which is the failure the exemption used to mask.
        """
        assert min(rule.confidence for rule in RULES.values()) >= _NO_LLM_CONFIDENCE_THRESHOLD

    def test_the_lowest_confidence_rule_survives_the_filter(self) -> None:
        """``SPEC-13``'s 0.7 estimate is the catalogue's floor, and LOW severity."""
        lowest = min(RULES.values(), key=lambda rule: rule.confidence)
        result = _fallback_filtered(
            [_finding(rule_id=lowest.rule_id, confidence=lowest.confidence, severity="LOW")]
        )

        assert [f.rule_id for f in result] == [lowest.rule_id]
        assert result[0].confidence == lowest.confidence

    def test_the_analyzer_emits_no_context_for_the_downweight_to_halve(self) -> None:
        """The one way the floor above could still be crossed, closed at the source.

        ``_CODE_EXAMPLE_DOWNWEIGHT`` multiplies by 0.5 when a finding carries a
        code-example ``context``, which would put ``SPEC-13``'s 0.7 at 0.35 and
        under the threshold. The analyzer sets no ``context`` at all, so the
        branch is unreachable for this catalogue -- asserted against the real
        analyzer rather than assumed.
        """
        response = spec_node(
            {
                "spec_checks": "advisory",
                "skill_path": "/scan/weather-report",
                "component_metadata": [{"path": "SKILL.md", "size_bytes": 40}],
                "file_cache": {"SKILL.md": "---\nname: bad--name\ndescription: x\n---\n\nBody.\n"},
            }  # type: ignore[arg-type]
        )

        assert response["findings"]
        assert all(f.context is None for f in response["findings"])

    def test_a_zero_confidence_conformance_finding_is_no_longer_special(self) -> None:
        """No rule id is exempt here any more, which is the shape of the removal.

        A ``SPEC-`` finding arriving at zero confidence cannot come from the
        analyzer -- every rule's confidence is 0.7 or 1.0 -- so the only way to
        build one is by hand, and it is dropped like any other weak LOW finding.
        Keeping it would be a second mechanism for a decision that already has
        one.
        """
        assert (
            _fallback_filtered([_finding(rule_id="SPEC-6", confidence=0.0, severity="LOW")]) == []
        )

    def test_the_band_below_the_threshold_still_drops(self) -> None:
        """Unchanged for every analyzer: 0.3 at LOW is a weak guess and goes."""
        assert _fallback_filtered([_finding(confidence=0.3, severity="LOW")]) == []

    def test_a_zero_confidence_finding_outside_the_catalogue_still_drops(self) -> None:
        """The verdict on inputs scanned today, unchanged in both rounds.

        A user YARA rule declaring ``confidence = "0"`` at MEDIUM or LOW reaches
        this filter as data -- ``static_yara._parse_meta`` reads the value from
        rule metadata -- and it was dropped before ``--spec-checks`` existed. No
        committed Behavior Snapshot runs with a custom rules directory, so only
        an assertion covers it.
        """
        assert (
            _fallback_filtered([_finding(rule_id="YARA-CUSTOM", confidence=0.0, severity="MEDIUM")])
            == []
        )
        assert _fallback_filtered([_finding(rule_id="TM1", confidence=0.0, severity="LOW")]) == []


class TestSeverityFloor:
    """HIGH and CRITICAL findings are never dropped on confidence alone."""

    def test_critical_below_threshold_retained(self) -> None:
        """CRITICAL finding at 0.35 confidence is retained (severity floor)."""
        findings = [_finding(confidence=0.35, severity="CRITICAL")]
        result = _fallback_filtered(findings)
        assert len(result) == 1
        assert result[0].severity == "CRITICAL"

    def test_high_below_threshold_retained(self) -> None:
        """HIGH finding at 0.2 confidence is retained (severity floor)."""
        findings = [_finding(confidence=0.2, severity="HIGH")]
        result = _fallback_filtered(findings)
        assert len(result) == 1
        assert result[0].severity == "HIGH"

    def test_low_severity_below_threshold_still_dropped(self) -> None:
        """LOW finding at 0.2 confidence is still dropped (no severity protection)."""
        findings = [_finding(confidence=0.2, severity="LOW")]
        result = _fallback_filtered(findings)
        assert len(result) == 0

    def test_none_severity_treated_as_low(self) -> None:
        """Finding with None severity does not crash — treated as LOW."""
        findings = [_finding(confidence=0.8, severity=None)]
        result = _fallback_filtered(findings)
        assert len(result) == 1

    def test_none_severity_below_threshold_dropped(self) -> None:
        """None severity at low confidence is dropped (no severity floor protection)."""
        findings = [_finding(confidence=0.3, severity=None)]
        result = _fallback_filtered(findings)
        assert len(result) == 0


class TestCodeExampleFiltering:
    """Findings in code example context are downweighted, not hard-dropped."""

    def test_fenced_code_block_context_downweighted(self) -> None:
        """Finding whose context contains ``` gets confidence halved."""
        findings = [
            _finding(
                context="```bash\ncurl -k https://api.example.com\n```",
                confidence=0.8,
            )
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.4

    def test_example_keyword_context_downweighted(self) -> None:
        """Finding whose context contains 'example:' gets downweighted."""
        findings = [
            _finding(
                context="Example: how to use subprocess\nsubprocess.run(cmd)",
                confidence=0.8,
            )
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 1
        assert result[0].confidence == 0.4

    def test_code_example_low_confidence_low_severity_dropped(self) -> None:
        """LOW severity finding at 0.6 conf in code-example context: 0.6*0.5=0.3 < 0.4, dropped."""
        findings = [
            _finding(
                context="```\ncurl -k https://api.example.com\n```",
                confidence=0.6,
                severity="LOW",
            )
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 0

    def test_code_example_high_severity_retained(self) -> None:
        """HIGH severity finding in code-example context at low conf: retained by severity floor."""
        findings = [
            _finding(
                context="```\ncurl -k https://api.example.com\n```",
                confidence=0.6,
                severity="HIGH",
            )
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 1

    def test_normal_code_context_kept(self) -> None:
        """Finding with regular code context (no example indicators) passes."""
        findings = [
            _finding(
                context="import subprocess\nresult = subprocess.run(cmd, shell=True)",
                confidence=0.8,
            )
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 1

    def test_no_context_kept(self) -> None:
        """Finding with no context (None) passes through."""
        findings = [_finding(context=None, confidence=0.8)]
        result = _fallback_filtered(findings)
        assert len(result) == 1


class TestCombinedFiltering:
    """Both filters work together."""

    def test_mixed_findings_filtered(self) -> None:
        """Mix of low-confidence, code-example, and genuine findings."""
        findings = [
            _finding(confidence=0.2, severity="LOW"),  # dropped: low conf + low sev
            _finding(
                confidence=0.8,
                context="```\ncurl -k https://example.com\n```",
            ),  # kept but downweighted (HIGH severity protects)
            _finding(confidence=0.8),  # kept: genuine finding
            _finding(confidence=0.6),  # kept: above threshold, normal context
        ]
        result = _fallback_filtered(findings)
        assert len(result) == 3

    def test_remediation_applied(self) -> None:
        """Kept findings get default remediation if none set."""
        findings = [_finding(confidence=0.8)]
        result = _fallback_filtered(findings)
        assert len(result) == 1
        assert result[0].remediation is not None
        assert len(result[0].remediation) > 0

    def test_empty_input(self) -> None:
        """Empty findings list returns empty."""
        assert _fallback_filtered([]) == []


class TestLLMFailurePassthrough:
    """On LLM failure, all findings pass through (fail-closed)."""

    def test_passthrough_preserves_all_findings(self) -> None:
        """_passthrough_with_defaults keeps all findings regardless of confidence."""
        findings = [
            _finding(confidence=0.1, severity="LOW"),
            _finding(confidence=0.3, severity="MEDIUM"),
            _finding(confidence=0.9, severity="CRITICAL"),
        ]
        result = _passthrough_with_defaults(findings)
        assert len(result) == 3

    def test_passthrough_adds_default_remediation(self) -> None:
        """Passthrough adds default remediation to findings without one."""
        findings = [_finding(confidence=0.8)]
        result = _passthrough_with_defaults(findings)
        assert len(result) == 1
        assert result[0].remediation is not None

    def test_meta_analyzer_llm_failure_uses_passthrough(self) -> None:
        """When LLM call raises, meta_analyzer passes all findings through."""
        findings = [
            _finding(confidence=0.2, severity="LOW"),
            _finding(confidence=0.8, severity="HIGH"),
        ]
        state = {
            "findings": findings,
            "use_llm": True,
            "file_cache": {"tool.py": "import subprocess"},
            "manifest": {},
            "model_config": {},
        }
        with patch("skillspector.nodes.meta_analyzer.LLMMetaAnalyzer") as mock_cls:
            mock_cls.return_value.get_batches.side_effect = RuntimeError("API timeout")
            result = meta_analyzer(state)
        assert len(result["findings"]) == 2
        assert "filtered_findings" not in result
