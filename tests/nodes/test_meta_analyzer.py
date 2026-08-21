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

"""Tests for the meta_analyzer node.

Covers ``LLMMetaAnalyzer`` filtering and partial-batch-failure handling, plus
the LLM-call telemetry and fail-closed construction that drive the report's
degradation signal.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

from skillspector.inspection_ledger import LedgerOutcome, LedgerReason, finalize_ledger
from skillspector.llm_analyzer_base import Batch, BatchExecutionResult, BatchFailure
from skillspector.llm_utils import run_async
from skillspector.models import Finding
from skillspector.nodes.analyzers import static_patterns_anti_refusal
from skillspector.nodes.analyzers.static_runner import analyzer_finding_to_finding
from skillspector.nodes.meta_analyzer import (
    LLMMetaAnalyzer,
    _meta_ledger_response,
    meta_analyzer,
)
from skillspector.nodes.report import _build_metadata, report
from skillspector.state import SkillspectorState

MOCK_PATCH_TARGET = "skillspector.llm_analyzer_base.get_chat_model"


def _mock_get_chat_model(*_args, **_kwargs):
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = MagicMock()
    return mock_llm


def _analyzer() -> LLMMetaAnalyzer:
    # Skip __init__ so no LLM client / API key is needed; apply_filter is pure.
    return LLMMetaAnalyzer.__new__(LLMMetaAnalyzer)


def _finding(
    rule_id: str,
    start_line: int,
    end_line: int | None = None,
    severity: str = "CRITICAL",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"static finding {rule_id}",
        severity=severity,
        confidence=0.9,
        file="requirements.txt",
        start_line=start_line,
        end_line=end_line,
    )


def _llm_item(rule_id: str, start_line: int, **kw: object) -> dict[str, object]:
    item: dict[str, object] = {
        "pattern_id": rule_id,
        "is_vulnerability": True,
        "confidence": 1.0,
        "start_line": start_line,
        "_file": "requirements.txt",
    }
    item.update(kw)
    return item


def _documentation_framed_ar2() -> Finding:
    raw = static_patterns_anti_refusal.analyze(
        content="For example, do not apologize.",
        file_path="SKILL.md",
        file_type="markdown",
    )
    return analyzer_finding_to_finding(next(finding for finding in raw if finding.rule_id == "AR2"))


def _assert_preserved_ar2(result: dict[str, object], original: Finding) -> None:
    findings = result["findings"]
    assert isinstance(findings, list)
    preserved = next(finding for finding in findings if finding.rule_id == "AR2")
    assert preserved.finding_id == original.finding_id
    assert preserved.severity == original.severity
    assert preserved.confidence >= original.confidence


def test_documentation_framed_finding_survives_provider_outcome_matrix() -> None:
    original = _documentation_framed_ar2()
    state: SkillspectorState = {
        "findings": [original],
        "use_llm": False,
        "file_cache": {"SKILL.md": "For example, do not apologize."},
        "llm_file_cache": {"SKILL.md": "For example, do not apologize."},
        "manifest": {},
        "model_config": {},
    }

    _assert_preserved_ar2(meta_analyzer(state), original)

    batch = Batch(
        file_path="SKILL.md", content=state["file_cache"]["SKILL.md"], findings=[original]
    )
    denial = {
        "pattern_id": "AR2",
        "is_vulnerability": False,
        "confidence": 0.1,
        "start_line": original.start_line,
        "_file": "SKILL.md",
    }
    confirmed = {
        "pattern_id": "AR2",
        "is_vulnerability": True,
        "confidence": 0.95,
        "start_line": original.start_line,
        "_file": "SKILL.md",
        "explanation": "confirmed",
        "remediation": "review",
    }
    for response in ([denial], [confirmed]):
        filtered = _analyzer().apply_filter([original], [(batch, response)])
        _assert_preserved_ar2({"findings": filtered}, original)

    llm_state = dict(state)
    llm_state["use_llm"] = True
    for error in (TimeoutError("provider timeout"), RuntimeError("provider failure")):
        with patch("skillspector.nodes.meta_analyzer.LLMMetaAnalyzer") as mock_cls:
            mock_cls.return_value.get_batches.return_value = [batch]
            mock_cls.return_value.arun_batches = AsyncMock(side_effect=error)
            mock_cls.return_value.response_received = False
            mock_cls.return_value.inference_usage = []
            _assert_preserved_ar2(meta_analyzer(llm_state), original)

    with patch("skillspector.nodes.meta_analyzer.LLMMetaAnalyzer") as mock_cls:
        mock_cls.return_value.get_batches.return_value = [batch]
        mock_cls.return_value.arun_batches = AsyncMock(
            side_effect=ValueError("malformed structured response")
        )
        mock_cls.return_value.response_received = True
        mock_cls.return_value.inference_usage = []
        _assert_preserved_ar2(meta_analyzer(llm_state), original)


def test_confirmed_finding_kept_when_model_returns_end_line() -> None:
    """Regression: a static finding with end_line=None must still match a
    confirmation whose end_line is populated (e.g. end_line == start_line, as
    some models return). Previously these confirmed findings were silently
    dropped. See issue #67."""
    findings = [_finding("SC4", 4), _finding("SC4", 5)]
    items = [_llm_item("SC4", 4, end_line=4), _llm_item("SC4", 5, end_line=5)]
    batch = Batch(file_path="requirements.txt", content="", findings=findings)

    kept = _analyzer().apply_filter(findings, [(batch, items)])

    assert {f.start_line for f in kept} == {4, 5}
    assert len(kept) == 2


def test_rejected_finding_is_retained_as_unconfirmed() -> None:
    """LLM disagreement may annotate but cannot erase deterministic evidence."""
    findings = [_finding("SC4", 4, severity="MEDIUM")]
    items = [_llm_item("SC4", 4, end_line=4, is_vulnerability=False)]
    batch = Batch(file_path="requirements.txt", content="", findings=findings)

    kept = _analyzer().apply_filter(findings, [(batch, items)])

    assert len(kept) == 1
    assert "llm-unconfirmed" in kept[0].tags


def test_low_confidence_finding_is_retained_as_unconfirmed() -> None:
    """A low-confidence LLM verdict cannot erase deterministic evidence."""
    findings = [_finding("SC4", 4, severity="MEDIUM")]
    items = [_llm_item("SC4", 4, end_line=4, confidence=0.3)]
    batch = Batch(file_path="requirements.txt", content="", findings=findings)

    kept = _analyzer().apply_filter(findings, [(batch, items)])

    assert len(kept) == 1
    assert "llm-unconfirmed" in kept[0].tags


def test_finding_clones_preserve_security_metadata_and_confidence() -> None:
    """Confirmed and unconfirmed clones retain deterministic finding identity."""
    original = Finding(
        rule_id="SC4",
        message="static finding SC4",
        severity="MEDIUM",
        confidence=0.9,
        file="requirements.txt",
        start_line=4,
        intent="malicious",
        evidence={"source": "static", "nested": {"kind": "deterministic"}},
        match_fingerprint="sha256:deterministic",
        occurrences=[{"file": "requirements.txt", "start_line": 4, "end_line": 4}],
    )
    batch = Batch(file_path="requirements.txt", content="", findings=[original])
    outcomes = (
        [_llm_item("SC4", 4, end_line=4, confidence=0.7)],
        [_llm_item("SC4", 4, end_line=4, is_vulnerability=False)],
    )

    for items in outcomes:
        [returned] = _analyzer().apply_filter([original], [(batch, items)])
        assert returned.confidence == original.confidence
        assert returned.intent == original.intent
        assert returned.evidence == original.evidence
        assert returned.match_fingerprint == original.match_fingerprint
        assert returned.occurrences == original.occurrences


def test_exact_end_line_match_still_works() -> None:
    """Existing behaviour: when both sides carry the same concrete end_line,
    the finding is kept (no regression from the new fallback)."""
    findings = [_finding("AST1", 21, end_line=21)]
    items = [_llm_item("AST1", 21, end_line=21)]
    batch = Batch(file_path="requirements.txt", content="", findings=findings)

    kept = _analyzer().apply_filter(findings, [(batch, items)])

    assert len(kept) == 1
    assert kept[0].rule_id == "AST1"


def _confirm(pattern_id: str, file: str, start_line: int) -> dict[str, object]:
    """LLM item confirming a finding, as parse_response would emit it."""
    return {
        "pattern_id": pattern_id,
        "is_vulnerability": True,
        "confidence": 0.9,
        "explanation": "confirmed by llm",
        "remediation": "fix it",
        "_file": file,
        "start_line": start_line,
        "end_line": None,
    }


def _lineage_finding(finding_id: str, file: str, start_line: int) -> Finding:
    """Build a finding with an explicit ID for ledger-lineage assertions."""
    return Finding(
        rule_id=finding_id.upper(),
        message=f"static finding {finding_id}",
        finding_id=finding_id,
        severity="MEDIUM",
        confidence=0.9,
        file=file,
        start_line=start_line,
    )


class TestMetaLedgerResponse:
    """Direct contract tests for meta-analysis finding lineage."""

    def test_mixed_batches_distinguish_retained_and_filtered_findings(self) -> None:
        retained = _lineage_finding("retained", "complete.py", 1)
        filtered = _lineage_finding("filtered", "complete.py", 2)
        passed_through = _lineage_finding("passed-through", "failed.py", 3)
        completed_batch = Batch(
            file_path="complete.py",
            content="complete",
            findings=[retained, filtered],
        )
        failed_batch = Batch(
            file_path="failed.py",
            content="failed",
            findings=[passed_through],
        )

        events, status = _meta_ledger_response(
            [completed_batch, failed_batch],
            BatchExecutionResult(
                successful=[(completed_batch, [])],
                failures=[BatchFailure(batch=failed_batch, error_class="TimeoutError")],
            ),
            [retained, passed_through],
        )

        completed, failed = events
        assert completed["outcome"] == "completed"
        assert completed["input_finding_ids"] == ["retained", "filtered"]
        assert completed["emitted_finding_ids"] == ["retained"]
        assert failed["outcome"] == "failed"
        assert failed["input_finding_ids"] == ["passed-through"]
        assert failed["emitted_finding_ids"] == ["passed-through"]
        assert failed["reason_code"] == "llm_batch_failed"
        assert failed["error_class"] == "TimeoutError"
        assert status["status"] == "failed"
        assert status["planned_work"] == [
            {
                "work_id": event["work_id"],
                "path": event["path"],
                "start_line": event["start_line"],
                "end_line": event["end_line"],
            }
            for event in events
        ]

    def test_connection_failure_remains_fatal(self) -> None:
        failed = _lineage_finding("failed", "failed.py", 3)
        failed_batch = Batch(file_path="failed.py", content="failed", findings=[failed])

        events, status = _meta_ledger_response(
            [failed_batch],
            BatchExecutionResult(
                failures=[
                    BatchFailure(
                        batch=failed_batch,
                        error_class="APIConnectionError",
                        reason=LedgerReason.LLM_CONNECTION_RETRIES_EXHAUSTED,
                    )
                ]
            ),
            [failed],
        )

        assert events[0]["outcome"] is LedgerOutcome.FAILED
        assert events[0]["reason_code"] == LedgerReason.LLM_CONNECTION_RETRIES_EXHAUSTED
        assert events[0]["message"] == "LLM connection failed after bounded retries."
        assert status["status"] == "failed"

        completeness, _ = finalize_ledger(
            {
                "components": ["failed.py"],
                "findings": [failed],
                "effective_finding_ids": [failed.finding_id],
                "inspection_ledger": events,
                "analyzer_status_events": [status],
            }
        )

        assert completeness["execution_successful"] is False
        assert completeness["ledger_exceptions"][0]["fatal"] is True

    def test_structured_response_failure_is_nonfatal_and_degraded(self) -> None:
        failed = _lineage_finding("failed", "failed.py", 3)
        failed_batch = Batch(file_path="failed.py", content="failed", findings=[failed])

        events, status = _meta_ledger_response(
            [failed_batch],
            BatchExecutionResult(
                failures=[
                    BatchFailure(
                        batch=failed_batch,
                        error_class="ValidationError",
                        reason=LedgerReason.LLM_STRUCTURED_RESPONSE_INVALID,
                    )
                ]
            ),
            [failed],
        )

        assert events[0]["outcome"] is LedgerOutcome.SKIPPED
        assert events[0]["input_finding_ids"] == [failed.finding_id]
        assert events[0]["emitted_finding_ids"] == [failed.finding_id]
        assert status["status"] == "degraded"

        completeness, _ = finalize_ledger(
            {
                "components": ["failed.py"],
                "findings": [failed],
                "effective_finding_ids": [failed.finding_id],
                "inspection_ledger": events,
                "analyzer_status_events": [status],
            }
        )

        assert completeness["execution_successful"] is True
        assert completeness["is_complete"] is False
        assert completeness["ledger_exceptions"][0]["fatal"] is False

    def test_overlapping_batches_do_not_reaccount_completed_finding(self) -> None:
        shared = _lineage_finding("shared", "complete.py", 1)
        failed_only = _lineage_finding("failed-only", "failed.py", 2)
        completed_batch = Batch(file_path="complete.py", content="complete", findings=[shared])
        failed_batch = Batch(
            file_path="failed.py",
            content="failed",
            findings=[shared, failed_only],
        )

        events, _ = _meta_ledger_response(
            [completed_batch, failed_batch],
            BatchExecutionResult(
                successful=[(completed_batch, [])],
                failures=[BatchFailure(batch=failed_batch, error_class="ProviderError")],
            ),
            [shared, failed_only],
        )

        completed, failed = events
        assert completed["input_finding_ids"] == ["shared"]
        assert completed["emitted_finding_ids"] == ["shared"]
        assert failed["input_finding_ids"] == ["failed-only"]
        assert failed["emitted_finding_ids"] == ["failed-only"]

    def test_fully_accounted_failed_batch_does_not_degrade_meta_status(self) -> None:
        shared = _lineage_finding("shared", "complete.py", 1)
        completed_batch = Batch(file_path="complete.py", content="complete", findings=[shared])
        failed_batch = Batch(file_path="complete.py", content="retry", findings=[shared])

        events, status = _meta_ledger_response(
            [completed_batch, failed_batch],
            BatchExecutionResult(
                successful=[(completed_batch, [])],
                failures=[BatchFailure(batch=failed_batch, error_class="ProviderError")],
            ),
            [shared],
        )

        assert len(events) == 1
        assert events[0]["outcome"] == "completed"
        assert status["status"] == "completed"

    def test_empty_failed_batch_does_not_degrade_meta_status(self) -> None:
        empty_batch = Batch(file_path="empty.py", content="empty", findings=[])

        events, status = _meta_ledger_response(
            [empty_batch],
            BatchExecutionResult(
                failures=[BatchFailure(batch=empty_batch, error_class="ProviderError")]
            ),
            [],
        )

        assert events == []
        assert status["status"] == "completed"

    def test_failed_batch_passes_all_findings_through_when_none_are_retained(self) -> None:
        first = _lineage_finding("first", "failed.py", 1)
        second = _lineage_finding("second", "failed.py", 2)
        failed_batch = Batch(
            file_path="failed.py",
            content="failed",
            findings=[first, second],
        )

        events, status = _meta_ledger_response(
            [failed_batch],
            BatchExecutionResult(
                failures=[BatchFailure(batch=failed_batch, error_class="ConnectionError")]
            ),
            [],
        )

        assert events[0]["input_finding_ids"] == ["first", "second"]
        assert events[0]["emitted_finding_ids"] == ["first", "second"]
        assert status["status"] == "failed"


@patch(MOCK_PATCH_TARGET, _mock_get_chat_model)
class TestMetaAnalyzerPartialBatchFailure:
    def _state(self, findings: list[Finding]) -> dict[str, object]:
        return {
            "findings": findings,
            "use_llm": True,
            "file_cache": {"a.py": "code a", "b.py": "code b"},
            "manifest": {},
            "model_config": {},
        }

    def test_unanalysed_findings_survive_a_failed_batch(self) -> None:
        """Findings whose batch failed are kept (no verdict != rejection)."""
        f_confirmed = Finding(rule_id="R1", message="m", file="a.py", start_line=1)
        f_rejected = Finding(rule_id="R2", message="m", file="a.py", start_line=5)
        f_unseen = Finding(rule_id="R1", message="m", file="b.py", start_line=3)

        batch_a = Batch(file_path="a.py", content="code a", findings=[f_confirmed, f_rejected])
        batch_b = Batch(file_path="b.py", content="code b", findings=[f_unseen])

        # batch_b never returned (timeout/429): only batch_a's verdicts exist,
        # and the LLM confirmed R1 but stayed silent on R2 (= rejection).
        partial_results = [(batch_a, [_confirm("R1", "a.py", 1)])]

        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch_a, batch_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=partial_results,
            ),
        ):
            result = meta_analyzer(self._state([f_confirmed, f_rejected, f_unseen]))

        filtered = result["findings"]
        kept = {(f.file, f.rule_id) for f in filtered}

        # LLM analysis can enrich findings but cannot remove either returned
        # or unseen deterministic results.
        assert ("a.py", "R1") in kept
        assert ("a.py", "R2") in kept
        assert ("b.py", "R1") in kept
        assert result["effective_finding_ids"] == [
            f_confirmed.finding_id,
            f_rejected.finding_id,
            f_unseen.finding_id,
        ]
        assert result["analyzer_status_events"][0]["status"] == "failed"
        assert "filtered_findings" not in result

        confirmed = next(f for f in filtered if f.file == "a.py")
        assert confirmed.explanation == "confirmed by llm"

    def test_selection_does_not_persist_filtered_findings(self) -> None:
        finding = _lineage_finding("retained", "a.py", 1)
        state = self._state([finding])
        state["use_llm"] = False

        result = meta_analyzer(state)

        assert [returned.finding_id for returned in result["findings"]] == [finding.finding_id]
        assert result["effective_finding_ids"] == [finding.finding_id]
        assert "filtered_findings" not in result

    def test_all_batches_failed_keeps_everything_via_fallback(self) -> None:
        f1 = Finding(rule_id="R1", message="m", file="a.py", start_line=1)
        f2 = Finding(rule_id="R2", message="m", file="b.py", start_line=2)
        batch_a = Batch(file_path="a.py", content="code a", findings=[f1])
        batch_b = Batch(file_path="b.py", content="code b", findings=[f2])

        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch_a, batch_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = meta_analyzer(self._state([f1, f2]))

        kept = {(f.file, f.rule_id) for f in result["findings"]}
        assert kept == {("a.py", "R1"), ("b.py", "R2")}
        assert "filtered_findings" not in result

    def test_reconstructed_partial_result_uses_canonical_batch_and_finding_ids(self) -> None:
        rejected = _lineage_finding("rejected", "a.py", 1)
        unseen = _lineage_finding("unseen", "b.py", 2)
        submitted_a = Batch(file_path="a.py", content="code a", findings=[rejected])
        submitted_b = Batch(file_path="b.py", content="code b", findings=[unseen])
        returned_a = Batch(
            file_path="a.py",
            content="code a",
            findings=[_lineage_finding("rejected", "a.py", 1)],
        )

        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[submitted_a, submitted_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=[(returned_a, [])],
            ),
        ):
            result = meta_analyzer(self._state([rejected, unseen]))

        assert result["effective_finding_ids"] == [rejected.finding_id, unseen.finding_id]
        assert [finding.finding_id for finding in result["findings"]] == [
            rejected.finding_id,
            unseen.finding_id,
        ]
        assert result["analyzer_status_events"][0]["status"] == "failed"

    def test_duplicate_return_does_not_account_for_a_missing_batch(self) -> None:
        confirmed = _lineage_finding("confirmed", "a.py", 1)
        unseen = _lineage_finding("unseen", "b.py", 2)
        submitted_a = Batch(file_path="a.py", content="code a", findings=[confirmed])
        submitted_b = Batch(file_path="b.py", content="code b", findings=[unseen])
        returned_a = Batch(
            file_path="a.py",
            content="code a",
            findings=[_lineage_finding("confirmed", "a.py", 1)],
        )

        # A malformed/custom executor can return the same batch twice while
        # omitting another submitted batch. The missing batch must still use
        # fallback filtering; matching result-list lengths is insufficient.
        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[submitted_a, submitted_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=[
                    (returned_a, [_confirm("CONFIRMED", "a.py", 1)]),
                    (returned_a, [_confirm("CONFIRMED", "a.py", 1)]),
                ],
            ),
        ):
            result = meta_analyzer(self._state([confirmed, unseen]))

        assert [finding.finding_id for finding in result["findings"]] == [
            confirmed.finding_id,
            unseen.finding_id,
        ]
        assert result["analyzer_status_events"][0]["status"] == "failed"

    def test_empty_meta_batches_are_not_submitted(self) -> None:
        finding = _lineage_finding("retained", "a.py", 1)
        empty_batch = Batch(file_path="a.py", content="context", findings=[])
        finding_batch = Batch(file_path="a.py", content="finding", findings=[finding])

        with (
            patch.object(
                LLMMetaAnalyzer,
                "get_batches",
                return_value=[empty_batch, finding_batch],
            ),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=[(finding_batch, [_confirm("RETAINED", "a.py", 1)])],
            ) as arun_batches,
        ):
            result = meta_analyzer(self._state([finding]))

        assert arun_batches.await_args.args[0] == [finding_batch]
        assert result["effective_finding_ids"] == [finding.finding_id]

    def test_no_failures_still_preserve_deterministic_findings(self) -> None:
        """Even complete LLM coverage cannot suppress deterministic findings."""
        f_confirmed = Finding(rule_id="R1", message="m", file="a.py", start_line=1)
        f_rejected = Finding(rule_id="R2", message="m", file="b.py", start_line=2)
        batch_a = Batch(file_path="a.py", content="code a", findings=[f_confirmed])
        batch_b = Batch(file_path="b.py", content="code b", findings=[f_rejected])

        full_results = [
            (batch_a, [_confirm("R1", "a.py", 1)]),
            (batch_b, []),
        ]

        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch_a, batch_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=full_results,
            ),
        ):
            result = meta_analyzer(self._state([f_confirmed, f_rejected]))

        kept = {(f.file, f.rule_id) for f in result["findings"]}
        assert kept == {("a.py", "R1"), ("b.py", "R2")}

    def test_effective_ids_follow_final_finding_order(self) -> None:
        a_pattern = _lineage_finding("pattern-a", "a.py", 1)
        b_pattern = _lineage_finding("pattern-b", "b.py", 2)
        a_entity = _lineage_finding("entity-a", "a.py", 3)
        b_entity = _lineage_finding("entity-b", "b.py", 4)
        batch_a = Batch(file_path="a.py", content="code a", findings=[a_pattern, a_entity])
        batch_b = Batch(file_path="b.py", content="code b", findings=[b_pattern, b_entity])
        findings = [a_pattern, b_pattern, a_entity, b_entity]

        with (
            patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch_a, batch_b]),
            patch.object(
                LLMMetaAnalyzer,
                "arun_batches",
                new_callable=AsyncMock,
                return_value=[
                    (batch_a, [_confirm("PATTERN-A", "a.py", 1), _confirm("ENTITY-A", "a.py", 3)]),
                    (batch_b, [_confirm("PATTERN-B", "b.py", 2), _confirm("ENTITY-B", "b.py", 4)]),
                ],
            ),
        ):
            result = meta_analyzer(self._state(findings))

        assert result["effective_finding_ids"] == [
            "pattern-a",
            "pattern-b",
            "entity-a",
            "entity-b",
        ]
        completeness, effective_ids = finalize_ledger(
            {
                "components": ["a.py", "b.py"],
                "findings": result["findings"],
                "effective_finding_ids": result["effective_finding_ids"],
                "inspection_ledger": result["inspection_ledger"],
                "analyzer_status_events": result["analyzer_status_events"],
            }
        )

        assert effective_ids == ["pattern-a", "pattern-b", "entity-a", "entity-b"]
        assert completeness["execution_successful"] is True
        assert completeness["ledger_exceptions"] == []


def test_local_only_high_finding_never_constructs_llm_analyzer() -> None:
    finding = Finding(
        rule_id="SC9",
        message="concealed executable",
        finding_id="local-finding",
        severity="HIGH",
        file=".hidden.docx!/payload.sh",
        tags=[],
        evidence={"outer_path": ".hidden.docx"},
    )
    state = {
        "findings": [finding],
        "file_cache": {"SKILL.md": "sentinel-visible-content"},
        "component_metadata": [{"path": ".hidden.docx!/payload.sh", "local_only": True}],
        "use_llm": True,
    }

    with patch("skillspector.nodes.meta_analyzer.LLMMetaAnalyzer") as analyzer_cls:
        result = meta_analyzer(state)

    analyzer_cls.assert_not_called()
    assert result["effective_finding_ids"] == ["local-finding"]
    assert result["findings"][0].severity == "HIGH"
    assert result["inspection_ledger"][0]["path"] == ".hidden.docx!/payload.sh"
    assert result["inspection_ledger"][0]["emitted_finding_ids"] == ["local-finding"]


@patch(MOCK_PATCH_TARGET, _mock_get_chat_model)
def test_provider_receives_only_cache_safe_non_local_findings() -> None:
    safe = _lineage_finding("safe", "safe.py", 1)
    missing = _lineage_finding("missing", "missing.py", 2)
    metadata_local = _lineage_finding("metadata-local", "metadata.py", 3)
    tagged_local = _lineage_finding("tagged-local", "tagged.py", 4)
    tagged_local.tags.append("local-only")
    evidence_local = _lineage_finding("evidence-local", "evidence.py", 5)
    evidence_local.evidence["local_only"] = True
    findings = [safe, missing, metadata_local, tagged_local, evidence_local]
    safe_batch = Batch(file_path="safe.py", content="safe", findings=[safe])
    llm_file_cache = {
        "safe.py": "safe",
        "metadata.py": "must stay local",
        "tagged.py": "must stay local",
        "evidence.py": "must stay local",
    }
    state: SkillspectorState = {
        "findings": findings,
        "use_llm": True,
        "file_cache": {**llm_file_cache, "missing.py": "not provider safe"},
        "llm_file_cache": llm_file_cache,
        "component_metadata": [{"path": "metadata.py", "local_only": True}],
        "manifest": {},
        "model_config": {},
    }

    with (
        patch.object(LLMMetaAnalyzer, "get_batches", return_value=[safe_batch]) as get_batches,
        patch.object(
            LLMMetaAnalyzer,
            "arun_batches",
            new_callable=AsyncMock,
            return_value=[(safe_batch, [])],
        ),
    ):
        result = meta_analyzer(state)

    files, provider_cache, submitted_findings = get_batches.call_args.args
    assert files == ["safe.py"]
    assert provider_cache is llm_file_cache
    assert submitted_findings == [safe]
    assert {finding.finding_id for finding in result["findings"]} == {
        finding.finding_id for finding in findings
    }
    assert result["effective_finding_ids"] == [finding.finding_id for finding in result["findings"]]
    assert {event["path"] for event in result["inspection_ledger"]} == {
        "safe.py",
        "missing.py",
        "metadata.py",
        "tagged.py",
        "evidence.py",
    }


@patch(MOCK_PATCH_TARGET, _mock_get_chat_model)
def test_local_only_event_survives_provider_failure() -> None:
    eligible = _lineage_finding("eligible", "safe.py", 1)
    local = _lineage_finding("local", "local.py", 2)
    local.tags.append("local-only")
    batch = Batch(file_path="safe.py", content="safe", findings=[eligible])
    state: SkillspectorState = {
        "findings": [eligible, local],
        "use_llm": True,
        "llm_file_cache": {"safe.py": "safe", "local.py": "must stay local"},
        "manifest": {},
        "model_config": {},
    }

    with (
        patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch]),
        patch.object(
            LLMMetaAnalyzer,
            "arun_batches",
            new_callable=AsyncMock,
            side_effect=RuntimeError("provider unavailable"),
        ),
    ):
        result = meta_analyzer(state)

    assert [finding.finding_id for finding in result["findings"]] == ["eligible", "local"]
    assert result["effective_finding_ids"] == ["eligible", "local"]
    assert [event["path"] for event in result["inspection_ledger"]] == ["local.py"]
    assert result["inspection_ledger"][0]["emitted_finding_ids"] == ["local"]
    assert result["analyzer_status_events"][0]["status"] == "unavailable"


# ---------------------------------------------------------------------------
# LLM-call telemetry + fail-closed construction (drives the report's
# degradation signal).
# ---------------------------------------------------------------------------


def _degr_finding(rule_id: str = "P1", severity: str = "HIGH") -> Finding:
    return Finding(
        rule_id=rule_id,
        message="test",
        severity=severity,
        confidence=0.8,
        file="SKILL.md",
        start_line=1,
    )


def _degr_state(**overrides: object) -> SkillspectorState:
    state: SkillspectorState = {
        "findings": [_degr_finding()],
        "use_llm": True,
        "file_cache": {"SKILL.md": "# Skill"},
        "manifest": {},
        "model_config": {},
    }
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


def test_records_ok_true_on_success() -> None:
    finding = _degr_finding()
    batch = Batch(file_path="SKILL.md", content="# Skill", findings=[finding])
    with (
        patch("skillspector.llm_analyzer_base.get_chat_model", return_value=MagicMock()),
        patch.object(LLMMetaAnalyzer, "get_batches", return_value=[batch]),
        patch(
            "skillspector.nodes.meta_analyzer.LLMMetaAnalyzer.arun_batches",
            new_callable=AsyncMock,
            return_value=[(batch, [])],
        ),
    ):
        result = meta_analyzer(_degr_state(findings=[finding]))
    assert result["llm_call_log"] == [{"node": "meta_analyzer", "ok": True, "error": None}]
    assert "filtered_findings" not in result


def test_construction_failure_is_caught_not_raised() -> None:
    """Regression: the chat model is constructed INSIDE the try, so a construction
    failure degrades (records ok=False, preserves findings) instead of crashing
    the whole graph."""
    with patch(
        "skillspector.llm_analyzer_base.get_chat_model",
        side_effect=RuntimeError("provider construction failed"),
    ):
        result = meta_analyzer(_degr_state())  # must not raise
    # Findings are preserved via the fallback path...
    assert len(result["findings"]) == 1
    assert "filtered_findings" not in result
    # ...and the failure is recorded so the report can flag degradation.
    log = result["llm_call_log"]
    assert log[0]["node"] == "meta_analyzer"
    assert log[0]["ok"] is False
    assert "provider construction failed" in log[0]["error"]
    status = result["analyzer_status_events"][0]
    assert status["status"] == "unavailable"
    assert "reason_code" not in status


def test_credential_error_propagates_instead_of_being_labelled_unavailable() -> None:
    """Only actual credential failures propagate; provider failures have no guessed cause."""
    with patch(
        "skillspector.llm_analyzer_base.get_chat_model",
        side_effect=ValueError("No LLM API key configured."),
    ):
        try:
            meta_analyzer(_degr_state())
        except ValueError as error:
            assert "API key" in str(error)
        else:
            raise AssertionError("credential failure must not be reported as unavailable")


def test_use_llm_false_records_nothing() -> None:
    result = meta_analyzer(_degr_state(use_llm=False))
    assert "llm_call_log" not in result
    assert "filtered_findings" not in result


def test_no_findings_records_nothing() -> None:
    result = meta_analyzer(_degr_state(findings=[]))
    assert "llm_call_log" not in result
    assert "filtered_findings" not in result


def _spec_finding(rule_id: str = "SPEC-6", confidence: float = 1.0) -> Finding:
    """A conformance finding in the shape ``structure_agent_skills_spec`` emits.

    Every rule of the catalogue is MEDIUM or LOW, which is why the severity floor
    above cannot reach one. The confidence is the rule's own and does **not**
    depend on the ``--spec-checks`` mode: which rules a run declines to score is
    carried in the ``unscored_rule_ids`` state key, not in a field of the finding.
    """
    return Finding(
        rule_id=rule_id,
        message=f"conformance finding {rule_id}",
        severity="LOW",
        confidence=confidence,
        file="SKILL.md",
        start_line=3,
    )


class TestConformanceFindingsBypassTheFilter:
    """A string comparison is not something a security model confirms or denies.

    Every rule of ``agent_skills_spec`` is MEDIUM or LOW and no SPEC id ever
    reaches the prompt (``_model_visible``, asserted below), so filtering them on
    confirmation computed seventeen rules and reported almost none of them --
    making ``--spec-checks`` a flag that did nothing unless paired with
    ``--no-llm``, the flag that turns off the semantic analysis the rest of the
    tool exists for. This class covers the second half of that decision: what
    happens to a response that names a SPEC id anyway.
    """

    def test_an_unconfirmed_conformance_finding_survives(self) -> None:
        """The defect itself: the model says nothing, and the finding was dropped."""
        findings = [_spec_finding()]
        batch = Batch(file_path="SKILL.md", content="", findings=findings)

        kept = _analyzer().apply_filter(findings, [(batch, [])])

        assert [f.rule_id for f in kept] == ["SPEC-6"]

    def test_an_unconfirmed_finding_outside_the_catalogue_is_kept_and_tagged(
        self,
    ) -> None:
        """The scoping, at the site where it used to decide a verdict.

        This asserted a *drop* until upstream's ``73dd1f1`` made ``apply_filter``
        fail-closed at every severity, so an unconfirmed MEDIUM finding is now
        kept and tagged ``llm-unconfirmed`` like any other. That makes the
        conformance exemption's first half -- "a SPEC id is never dropped for
        want of confirmation" -- true of everything rather than of SPEC ids
        alone. What the exemption still decides on its own is the second half,
        which the next test holds: a response naming a SPEC id must not enrich
        one.
        """
        findings = [_finding("SC4", 4, severity="MEDIUM")]
        batch = Batch(file_path="requirements.txt", content="", findings=findings)

        kept = _analyzer().apply_filter(findings, [(batch, [])])

        assert [f.rule_id for f in kept] == ["SC4"]
        assert "llm-unconfirmed" in kept[0].tags

    def test_a_confirmed_conformance_finding_keeps_its_own_confidence(self) -> None:
        """The load-bearing half: bypassing must not mean passing through enrichment.

        The enrichment branch overwrites ``confidence`` with the model's own, and
        ``suppression.finding_fingerprint`` hashes ``confidence`` -- so a
        "confirmed" conformance finding would fingerprint differently from the
        identical defect on a ``--no-llm`` run, and a baseline taken on one path
        would suppress nothing on the other. The finding is returned unchanged
        instead, message and all.
        """
        findings = [_spec_finding(confidence=0.7)]
        item = {
            "pattern_id": "SPEC-6",
            "is_vulnerability": True,
            "confidence": 0.95,
            "start_line": 3,
            "_file": "SKILL.md",
            "explanation": "model prose",
        }
        batch = Batch(file_path="SKILL.md", content="", findings=findings)

        kept = _analyzer().apply_filter(findings, [(batch, [item])])

        assert [f.confidence for f in kept] == [0.7]
        assert kept[0].message == "conformance finding SPEC-6"

    def test_a_conformance_finding_is_not_tagged_unconfirmed(self) -> None:
        """``llm-unconfirmed`` says the model was asked and declined; here it was never asked."""
        findings = [_spec_finding()]
        batch = Batch(file_path="SKILL.md", content="", findings=findings)

        kept = _analyzer().apply_filter(findings, [(batch, [])])

        assert "llm-unconfirmed" not in kept[0].tags

    def test_a_scored_conformance_finding_keeps_its_score(self) -> None:
        """Both modes emit the same rules at the same measured confidence."""
        findings = [_spec_finding(rule_id="SPEC-15", confidence=1.0)]
        batch = Batch(file_path="SKILL.md", content="", findings=findings)

        kept = _analyzer().apply_filter(findings, [(batch, [])])

        assert [(f.rule_id, f.confidence) for f in kept] == [("SPEC-15", 1.0)]


def _spec_at(rule_id: str, line: int) -> Finding:
    """A conformance finding on ``SKILL.md`` at a chosen line."""
    return Finding(
        rule_id=rule_id,
        message=f"conformance finding {rule_id}",
        severity="LOW",
        confidence=1.0,
        file="SKILL.md",
        start_line=line,
    )


def _other_at(rule_id: str, line: int) -> Finding:
    """A finding from outside the conformance catalogue, on the same component."""
    return Finding(
        rule_id=rule_id,
        message=f"static finding {rule_id}",
        severity="MEDIUM",
        confidence=0.8,
        file="SKILL.md",
        start_line=line,
    )


@patch(MOCK_PATCH_TARGET, _mock_get_chat_model)
class TestTheModelIsNeverAskedAboutASpecId:
    """The sentence four files state, asserted rather than argued.

    Skipping SPEC ids in ``apply_filter`` alone left them in ``batch.findings``,
    so ``build_prompt`` formatted every one of them into the prompt and sent it:
    the model *was* asked, and only its answer was thrown away. That also charged
    them to ``_estimate_extra_overhead``, which shrinks the per-file content
    budget and so moves chunk boundaries -- handing the enrichment branch a
    different answer about an *unrelated* co-located finding, whose ``message``,
    ``confidence``, ``remediation`` and ``explanation`` are all hashed into the
    baseline fingerprint.
    """

    _CONTENT = "\n".join(f"line {i} of the scanned manifest" for i in range(1, 400))

    def _live_analyzer(self, budget: int | None = None) -> LLMMetaAnalyzer:
        analyzer = LLMMetaAnalyzer(model="gpt-4o-mini")
        if budget is not None:
            analyzer._input_budget = budget
        return analyzer

    def test_a_conformance_finding_is_not_in_the_prompt(self) -> None:
        """The claim itself: no SPEC id reaches the text the model reads."""
        findings = [_other_at("SC2", 3), _spec_at("SPEC-4", 1), _spec_at("SPEC-15", 7)]
        batch = Batch(file_path="SKILL.md", content=self._CONTENT, findings=findings)

        prompt = self._live_analyzer().build_prompt(batch, metadata_text="m")

        assert "SPEC-4" not in prompt
        assert "SPEC-15" not in prompt
        assert "SC2" in prompt

    def test_the_prompt_is_byte_identical_with_and_without_the_flag(self) -> None:
        """The control the previous assertion needs: only the SPEC ids differ."""
        without = [_other_at("SC2", 3)]
        with_spec = [*without, _spec_at("SPEC-4", 1), _spec_at("SPEC-15", 7)]
        analyzer = self._live_analyzer()

        rendered = [
            analyzer.build_prompt(
                Batch(file_path="SKILL.md", content=self._CONTENT, findings=findings),
                metadata_text="m",
            )
            for findings in (without, with_spec)
        ]

        assert rendered[0] == rendered[1]

    def test_a_conformance_finding_is_charged_no_prompt_overhead(self) -> None:
        """What decides the content budget, and so where a large file is split."""
        analyzer = self._live_analyzer()
        without = [_other_at("SC2", 3)]

        assert analyzer._estimate_extra_overhead(
            [*without, _spec_at("SPEC-4", 1), _spec_at("SPEC-15", 7)]
        ) == analyzer._estimate_extra_overhead(without)
        assert analyzer._estimate_extra_overhead([_spec_at("SPEC-4", 1)]) == 0

    def test_the_submitted_batches_are_identical_with_and_without_the_flag(self) -> None:
        """The flag is inert to the LLM stage -- same chunks, same calls, same input.

        Asserted at a forced-small input budget so the manifest chunks at all:
        that is the shape where a shifted content budget relocates a *non*-SPEC
        finding into a different chunk. A chunk carrying only conformance
        findings is dropped without the flag (it has no findings) and declined
        with it (``should_submit``), so the two runs submit the same work.
        """
        without = [_other_at("SC2", 40), _other_at("SC4", 300)]
        with_spec = [*without, _spec_at("SPEC-4", 1), _spec_at("SPEC-15", 200)]

        def submitted(findings: list[Finding]) -> list[tuple[int | None, int | None, str]]:
            analyzer = self._live_analyzer(budget=1200)
            batches = analyzer.get_batches(["SKILL.md"], {"SKILL.md": self._CONTENT}, findings)
            return [
                # The prompt, not the batch: a declined SPEC finding still rides
                # `batch.findings` so the ledger can account for it, and what the
                # flag must not move is what the model is shown.
                (batch.start_line, batch.end_line, analyzer.build_prompt(batch, metadata_text="m"))
                for batch in batches
                if batch.findings and analyzer.should_submit(batch)
            ]

        assert submitted(with_spec) == submitted(without)
        assert len(submitted(without)) > 1, "the control needs a file that actually chunks"

    def test_a_batch_of_only_conformance_findings_is_declined(self) -> None:
        """Nothing to ask about, so nothing is sent -- the whole file included."""
        analyzer = self._live_analyzer()

        assert not analyzer.should_submit(
            Batch(file_path="SKILL.md", content=self._CONTENT, findings=[_spec_at("SPEC-4", 1)])
        )
        assert analyzer.should_submit(
            Batch(
                file_path="SKILL.md",
                content=self._CONTENT,
                findings=[_spec_at("SPEC-4", 1), _other_at("SC2", 3)],
            )
        )

    def test_a_declined_batch_costs_no_chat_model_invocation(self) -> None:
        """Through the real executor, so the hook is exercised where it runs."""
        analyzer = self._live_analyzer()
        batch = Batch(file_path="SKILL.md", content=self._CONTENT, findings=[_spec_at("SPEC-4", 1)])

        with patch.object(
            LLMMetaAnalyzer, "_ainvoke_batch_with_retries", new_callable=AsyncMock
        ) as invoke:
            outcome = run_async(analyzer.arun_batches_detailed([batch], metadata_text="m"))

        invoke.assert_not_awaited()
        assert outcome.successful == [(batch, [])]
        assert outcome.failures == []

    def test_a_declined_batch_is_still_a_completed_batch(self) -> None:
        """Declining must not drop the batch: the report is selected from the ledger.

        ``_meta_ledger_response`` builds the Inspection Ledger rows from
        ``BatchExecutionResult.successful``, and ``effective_finding_ids`` -- the
        key ``report.report`` selects the reported findings from -- is derived
        from those rows. A batch removed from the submitted list instead would
        take its findings out of the report, and ``finalize_ledger`` would refuse
        to let them be added back.
        """
        spec = _spec_at("SPEC-4", 1)
        batch = Batch(file_path="SKILL.md", content=self._CONTENT, findings=[spec])

        events, status = _meta_ledger_response([batch], BatchExecutionResult([(batch, [])]), [spec])

        assert [event["outcome"] for event in events] == [LedgerOutcome.COMPLETED]
        assert events[0]["emitted_finding_ids"] == [spec.finding_id]
        assert status["status"] == "completed"


@patch(MOCK_PATCH_TARGET, _mock_get_chat_model)
class TestAConformanceOnlyScanMakesNoLLMCall:
    """A manifest whose only findings are conformance findings, end to end."""

    def _state(self, findings: list[Finding]) -> SkillspectorState:
        return cast(
            "SkillspectorState",
            {
                "findings": findings,
                "use_llm": True,
                "file_cache": {"SKILL.md": "# manifest\n"},
                "manifest": {},
                "model_config": {},
            },
        )

    def test_no_batch_is_sent_and_the_findings_survive(self) -> None:
        spec = _spec_at("SPEC-4", 1)

        with patch.object(
            LLMMetaAnalyzer, "_ainvoke_batch_with_retries", new_callable=AsyncMock
        ) as invoke:
            result = meta_analyzer(self._state([spec]))

        invoke.assert_not_awaited()
        assert [f.rule_id for f in result["findings"]] == ["SPEC-4"]
        assert result["effective_finding_ids"] == [spec.finding_id]

    def test_the_scan_claims_no_llm_call_that_never_happened(self) -> None:
        """``llm_call_log`` drives ``llm_calls_attempted``/``llm_calls_succeeded``.

        A declined batch lands in ``BatchExecutionResult.successful`` on purpose,
        so the ``ok=bool(detailed.successful)`` telemetry would have recorded a
        successful chat-model invocation for a scan that made none. An empty log
        is already this node's "no LLM call happened" state -- it is what the
        no-findings early return leaves behind.
        """
        with patch.object(LLMMetaAnalyzer, "_ainvoke_batch_with_retries", new_callable=AsyncMock):
            result = meta_analyzer(self._state([_spec_at("SPEC-4", 1)]))

        assert result["llm_call_log"] == []
        assert (
            _build_metadata(False, True, result["llm_call_log"]).get("llm_calls_attempted") is None
        )

    def test_a_single_other_finding_is_enough_to_make_the_call(self) -> None:
        """The control: the decline is about the findings, not about the flag."""
        with patch.object(
            LLMMetaAnalyzer, "_ainvoke_batch_with_retries", new_callable=AsyncMock
        ) as invoke:
            invoke.return_value = (
                Batch(file_path="SKILL.md", content="# manifest\n", findings=[]),
                [],
            )
            result = meta_analyzer(self._state([_spec_at("SPEC-4", 1), _other_at("SC2", 3)]))

        invoke.assert_awaited()
        assert result["llm_call_log"] != []

    def _mixed_state(self) -> SkillspectorState:
        """One file whose batch is declined, one whose batch is submitted.

        The ordinary shape for this feature: a `SKILL.md` carrying only
        conformance findings beside any other file carrying a real one.
        """
        return cast(
            "SkillspectorState",
            {
                "findings": [
                    _spec_at("SPEC-4", 1),
                    Finding(
                        rule_id="SC2",
                        message="static finding SC2",
                        severity="MEDIUM",
                        confidence=0.8,
                        file="install.sh",
                        start_line=3,
                    ),
                ],
                "use_llm": True,
                "file_cache": {
                    "SKILL.md": "# manifest\n",
                    "install.sh": "#!/bin/sh\ncurl x | sh\n",
                },
                "manifest": {},
                "model_config": {},
            },
        )

    def test_a_declined_batch_cannot_vouch_for_a_submitted_one_that_failed(self) -> None:
        """The only real call failed, so the scan must not claim a successful one.

        A declined batch is filed in ``BatchExecutionResult.successful`` on
        purpose, so ``ok=bool(detailed.successful)`` read the decline as proof
        that the chat model had answered -- even though the one batch actually
        submitted raised. The all-declined and all-succeeding arms above both
        miss it; only the mixed shape reaches it.
        """
        with patch.object(
            LLMMetaAnalyzer,
            "_ainvoke_batch_with_retries",
            new_callable=AsyncMock,
            side_effect=RuntimeError("provider 500"),
        ) as invoke:
            result = meta_analyzer(self._mixed_state())

        assert invoke.await_count == 1  # the declined batch was never sent
        assert result["llm_call_log"] == [
            {"node": "meta_analyzer", "ok": False, "error": None},
        ]

    def test_that_failure_still_floors_the_recommendation_at_caution(self) -> None:
        """The safety property the telemetry feeds, asserted end to end.

        ``report._llm_runtime_status`` calls a run whose every LLM call failed
        *degraded*, and ``report.report`` refuses to let a degraded scan report
        ``SAFE``. With the decline counted as a success the run looked healthy,
        so a scan whose only real LLM call failed reported ``SAFE`` -- a
        false-safety signal, which is what makes the telemetry bug security
        relevant rather than cosmetic.
        """
        with patch.object(
            LLMMetaAnalyzer,
            "_ainvoke_batch_with_retries",
            new_callable=AsyncMock,
            side_effect=RuntimeError("provider 500"),
        ):
            meta_result = meta_analyzer(self._mixed_state())

        report_state = cast(
            "SkillspectorState",
            {
                "filtered_findings": [],  # static score 0 -> would be SAFE
                "component_metadata": [],
                "has_executable_scripts": False,
                "manifest": {},
                "output_format": "json",
                "use_llm": True,
                "llm_call_log": meta_result["llm_call_log"],
            },
        )
        result = report(report_state)

        assert result["risk_score"] == 0
        assert result["risk_recommendation"] == "CAUTION"
