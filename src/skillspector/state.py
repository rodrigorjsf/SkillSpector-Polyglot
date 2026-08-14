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

"""State schema for the Skillspector LangGraph workflow."""

from __future__ import annotations

import operator
from typing import Annotated, NotRequired

from typing_extensions import TypedDict

from skillspector.framework import Framework
from skillspector.inference_usage import InferenceUsageRecord
from skillspector.inspection_ledger import (
    AnalysisCompleteness,
    AnalyzerStatusEvent,
    InspectionLedgerEvent,
)
from skillspector.manifest_status import ManifestStatus
from skillspector.models import Finding


def merge_findings_by_id(existing: list[Finding], updates: list[Finding]) -> list[Finding]:
    """Merge findings by opaque ID, replacing enriched instances in place."""
    merged = list(existing)
    positions = {finding.finding_id: index for index, finding in enumerate(merged)}
    for finding in updates:
        position = positions.get(finding.finding_id)
        if position is None:
            positions[finding.finding_id] = len(merged)
            merged.append(finding)
        else:
            merged[position] = finding
    return merged


class SkillspectorState(TypedDict, total=False):
    """Graph state shared by all nodes."""

    # Input: resolve_input node consumes input_path or skill_path, sets skill_path
    input_path: str | None
    skill_path: str | None
    # Set by resolve_input when a temp dir was created (git/url/zip/file); caller should clean up
    temp_dir_for_cleanup: str | None
    zip_bytes: bytes | None
    mode: str

    # build_context node populates these
    components: list[str]
    file_cache: dict[str, str]
    # Retained for compatibility with the persisted workflow-state schema.
    ast_cache: dict[str, str]
    # Key for the process-local parsed-AST cache.  The ASTs themselves stay
    # outside state because they are not checkpoint-serializable.
    python_ast_cache_key: str | None
    manifest: dict[str, object]
    # Why `manifest` holds what it holds: an empty dict alone cannot say whether
    # the Skill declared nothing, failed to parse, or was never there at all.
    # Additive -- `manifest` keeps its type and contents. See
    # skillspector.manifest_status.
    manifest_status: ManifestStatus
    # Which Framework the scanned tree is written against, detected by a pure
    # function under `build_context` -- no new graph node. Read by one gated
    # Analyzer per Framework -- `framework_langchain4j`, `framework_deepagents`
    # and `framework_deepagents_js` -- each returning no findings unless the key
    # holds its own member. `AGENT_SKILLS` has no Analyzer: it is what every
    # input scanned before this key existed detects as. See
    # skillspector.framework.
    framework: Framework
    # Which Agent Skills specification conformance Rules run, and which of them
    # contribute to the Risk Score: "off", "advisory" or "strict". Set by
    # `scan --spec-checks`; an absent key means "off", which is what every Scan
    # predating the flag carries and why the flag's absence changes nothing. Read
    # by the gated `structure_agent_skills_spec` Analyzer, which returns nothing
    # at all unless it holds one of the other two. See
    # skillspector.agent_skills_spec.
    spec_checks: str
    # Rule ids this run was configured to report without scoring. Written by
    # `structure_agent_skills_spec` past its gate, from the mode and the
    # catalogue it owns, and read by `report._compute_risk_score` as an opaque
    # set -- the report never learns what a SPEC Rule is.
    #
    # It is a property of the *run*, not of a Finding, and that is the whole
    # reason it is here rather than on `Finding`: every field of a Finding is
    # hashed into the v2 Baseline fingerprint, so a Finding carrying "this run
    # did not score me" would fingerprint one defect two ways. An absent key
    # means nothing is exempt, which is what every Scan predating the flag
    # carries. See skillspector.agent_skills_spec.unscored_rule_ids.
    #
    # **Exactly one Analyzer publishes it, and both keys below are unreducible
    # until that changes.** `graph.build_graph` fans every Analyzer node out from
    # `build_context` in parallel, and a bare key -- one carrying no `Annotated`
    # reducer -- accepts a single write per superstep: a second publisher raises
    # `InvalidUpdateError` while applying the channel update, which is *outside*
    # any node and so past where `guard_analyzer_node` could turn it into an
    # empty result. The whole Scan dies. Adding a second publisher therefore
    # means deciding a reducer for **both** keys first, and the note is the hard
    # half: two remedies cannot concatenate into one sentence, so the honest
    # shape is a mapping from rule id to its note rather than `operator.add`.
    # `tests/unit/test_unscored_rule_ids_single_publisher.py` fails as soon as a
    # second module anywhere in `src/skillspector` writes either key.
    unscored_rule_ids: list[str]
    # The sentence the report prints beside a finding of one of those rule ids,
    # supplied by the one Analyzer that published them. It is here rather than in
    # `report` because it names the flag that would score them, and the flag
    # belongs to the catalogue: the report keeps the ids opaque and renders this
    # verbatim. See skillspector.agent_skills_spec.UNSCORED_NOTE.
    unscored_rule_note: str
    previous_manifest: dict[str, object] | None

    # Accumulated canonical findings. Same-ID meta updates replace in place.
    findings: Annotated[list[Finding], merge_findings_by_id]
    inspection_ledger: Annotated[list[InspectionLedgerEvent], operator.add]
    analyzer_status_events: Annotated[list[AnalyzerStatusEvent], operator.add]
    effective_finding_ids: list[str]
    analysis_completeness: AnalysisCompleteness
    execution_successful: bool

    # Compatibility projection emitted only by the report after effective-ID
    # selection. Meta analysis never stores a second filtered collection.
    filtered_findings: list[Finding]

    # LLM runtime telemetry: each LLM-backed node appends one record (built with
    # ``llm_call_record``) so the report can detect a *silent degradation* — the
    # case where use_llm was requested but every LLM call failed at runtime
    # (transport/parse/auth error). Without this, such a failure would quietly
    # turn a requested deep scan into a static-only one while still reporting
    # llm_available=true. Reducer is operator.add so records concatenate across
    # the parallel analyzer nodes (same pattern as ``findings``).
    llm_call_log: Annotated[list[LLMCallRecord], operator.add]

    # Exact provider-response token counters. Each LLM-backed node appends its
    # per-call records; the report exposes the sanitized projection under
    # metadata.inference_usage. Missing records mean "not observable", never
    # an estimated zero.
    inference_usage: Annotated[list[InferenceUsageRecord], operator.add]

    # Baseline / false-positive suppression. `baseline` is a loaded
    # skillspector.suppression.Baseline (set by CLI/API); the report node drops
    # matching findings before scoring. `show_suppressed` keeps them in the
    # report (marked) for review; `suppressed_findings` is the report output.
    baseline: object | None
    # Absolute path selected by `scan --baseline` or targeted by `baseline -o`.
    # When it is inside the scan target, build_context excludes only that file
    # so waiver text cannot scan itself or enter regenerated fingerprints.
    baseline_path: str | None
    show_suppressed: bool
    suppressed_findings: list[object]

    # Model IDs per LLM-using node: e.g. {"default": "...", "meta_analyzer": "..."}
    model_config: dict[str, str]

    # Component metadata for reporting and risk scoring (from build_context)
    component_metadata: list[dict[str, object]]
    has_executable_scripts: bool

    # Output: report node writes formatted string here
    output_format: str
    report_body: str

    # LLM: when False, LLM-based nodes (meta_analyzer, mcp_tool_poisoning's TP4,
    # and the semantic_* analyzers) return immediately without calling the LLM.
    # Each such node checks use_llm itself; there is no graph-level routing.
    use_llm: bool

    # Risk: report node sets these from risk_score
    risk_severity: str
    risk_recommendation: str

    sarif_report: dict[str, object]
    risk_score: int

    # Additional YARA rules directory (user-specified via --yara-rules-dir)
    yara_rules_dir: str | None


class LLMCallRecord(TypedDict):
    """One LLM-stage telemetry record (an entry in ``llm_call_log``)."""

    node: str
    ok: bool
    error: str | None


def llm_call_record(node_id: str, *, ok: bool, error: str | None = None) -> LLMCallRecord:
    """Build one telemetry record for ``SkillspectorState['llm_call_log']``.

    LLM-backed nodes append a record on each run so the report can tell whether
    the LLM stage actually produced results. ``ok=False`` marks a runtime
    failure where the node fell back to empty/static findings (so the failure is
    not mistaken for "the LLM ran and found nothing").
    """
    return {"node": node_id, "ok": ok, "error": error}


class AnalyzerNodeResponse(TypedDict):
    """Strict analyzer update payload for graph state."""

    findings: list[Finding]
    inspection_ledger: NotRequired[list[InspectionLedgerEvent]]
    analyzer_status_events: NotRequired[list[AnalyzerStatusEvent]]
    # Which of the publishing analyzer's own rule ids this run must not score.
    # `NotRequired` because every other analyzer omits it -- **not** because a
    # second analyzer may add itself. `structure_agent_skills_spec` is the only
    # writer, and both keys are bare channels that reject a concurrent second
    # write; see the same keys on `SkillspectorState` for why the signal lives on
    # the run rather than on a Finding, and for what a second publisher would
    # have to settle first.
    unscored_rule_ids: NotRequired[list[str]]
    # ...and the sentence a report should print beside them. Rendered verbatim,
    # so the publisher keeps the flag name it owns and the report keeps the ids
    # opaque. Absent means the report falls back to a generic statement.
    unscored_rule_note: NotRequired[str]
    # LLM-backed analyzers also report one telemetry record; static analyzers
    # omit it (NotRequired keeps the key optional for them).
    llm_call_log: NotRequired[list[LLMCallRecord]]
    inference_usage: NotRequired[list[InferenceUsageRecord]]


class MetaAnalyzerResponse(TypedDict):
    """Meta-analyzer payload with canonical findings and ID selection."""

    findings: NotRequired[list[Finding]]
    effective_finding_ids: NotRequired[list[str]]
    inspection_ledger: NotRequired[list[InspectionLedgerEvent]]
    analyzer_status_events: NotRequired[list[AnalyzerStatusEvent]]
    llm_call_log: NotRequired[list[LLMCallRecord]]
    inference_usage: NotRequired[list[InferenceUsageRecord]]
