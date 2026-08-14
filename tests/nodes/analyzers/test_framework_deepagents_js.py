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

"""Tests for the gated ``framework_deepagents_js`` Analyzer and its TypeScript parser.

Every test enters through ``node(state)`` with a synthetic state, for the reason
``test_framework_deepagents.py`` states: a resolution decision that cannot be
observed as a Finding is a decision that should not exist.

Many assertions read the ledger rows and status rather than the Finding list. A
green suite is not evidence the Analyzer ran: ``guard_analyzer_node`` turns any
exception into an empty Finding list plus a ``"failed"`` status, and an empty
Finding list is also the correct answer on a configuration that fully resolves --
so a test that only checked ``findings == []`` would pass on a completely broken
Analyzer.

**Every Rule is asserted in both directions.** Each one fires on a violating input
*and* is pinned silent on the conforming one beside it, because all four fail by
firing on configuration that is already correct.
"""

from __future__ import annotations

from typing import Any

import pytest

from skillspector.framework import Framework
from skillspector.inspection_ledger import LedgerOutcome, LedgerReason
from skillspector.nodes.analyzers import framework_deepagents_js as analyzer

PACKAGE_JSON = """{
  "name": "ops-agent",
  "dependencies": { "deepagents": "^1.9.1" }
}
"""

# The shape the upstream tutorial teaches: a Skill source and nothing that denies
# writing to it.
WRITABLE_TS = """import { createDeepAgent } from "deepagents";

export const agent = await createDeepAgent({
  model: "claude-sonnet-5",
  skills: ["/skills/"],
});
"""

# The same call with the rule upstream's read-only example publishes.
DENIED_TS = """import { createDeepAgent } from "deepagents";

export const agent = await createDeepAgent({
  model: "claude-sonnet-5",
  skills: ["/skills/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""

SKILL_MD = """---
name: ops-runbook
description: Walks an operator through a routine deployment.
---

# Ops runbook

Read the change list, then apply it one service at a time.
"""


def make_state(
    file_cache: dict[str, str],
    framework: Framework = Framework.DEEPAGENTS_JS,
) -> dict[str, Any]:
    """Build the slice of Scan state the Analyzer reads."""
    return {
        "framework": framework,
        "file_cache": dict(file_cache),
        "components": sorted(file_cache),
    }


def rule_ids(result: dict[str, Any]) -> list[str]:
    """The rule ids a node result carries, in order."""
    return [finding.rule_id for finding in result["findings"]]


class TestTheFrameworkGate:
    """The gate is the first statement, and a declining Analyzer emits nothing."""

    @pytest.mark.parametrize(
        "framework", [member for member in Framework if member is not Framework.DEEPAGENTS_JS]
    )
    def test_another_framework_produces_no_findings_and_no_ledger(
        self, framework: Framework
    ) -> None:
        """Every Framework but this one, so a Framework added later is covered too.

        ADR 0002: a gate that does not open plans no Work Item, so it writes no
        ledger row and no analyzer status. Asserting the *keys* are absent rather
        than empty is the point -- an empty status list would still reach
        ``analysis_completeness`` and move every snapshot in the corpus.
        """
        result = analyzer.node(make_state({"src/agent.ts": WRITABLE_TS}, framework))
        assert result == {"findings": []}

    def test_the_python_deep_agents_framework_is_declined(self) -> None:
        """The one mismatch a shared distribution name makes easy to get wrong.

        Both distributions are spelled ``deepagents``. If this Analyzer's gate
        tested anything looser than the exact Framework member, a Python Deep
        Agents Scan would run the TypeScript parser over its modules.
        """
        assert analyzer.node(make_state({"src/agent.ts": WRITABLE_TS}, Framework.DEEPAGENTS)) == {
            "findings": []
        }


class TestApplicability:
    """One predicate decides the gate and the planned work alike (ADR 0006)."""

    def test_nothing_applicable_reports_not_applicable_without_a_ledger_row(self) -> None:
        result = analyzer.node(make_state({"README.md": "# Ops agent\n"}))
        assert result["findings"] == []
        assert "inspection_ledger" not in result
        events = result["analyzer_status_events"]
        assert len(events) == 1
        assert events[0]["status"] == "not_applicable"
        assert events[0]["reason_code"] == LedgerReason.NO_APPLICABLE_FILES

    def test_every_applicable_component_gets_a_row_even_with_no_finding(self) -> None:
        """An absence of Findings must be distinguishable from an absence of inspection."""
        result = analyzer.node(
            make_state(
                {
                    "package.json": PACKAGE_JSON,
                    "src/agent.ts": DENIED_TS,
                    "skills/ops/SKILL.md": SKILL_MD,
                    "README.md": "# Ops agent\n",
                }
            )
        )
        assert result["findings"] == []
        paths = sorted(event["path"] for event in result["inspection_ledger"])
        assert paths == ["package.json", "skills/ops/SKILL.md", "src/agent.ts"]
        assert all(
            event["outcome"] == LedgerOutcome.COMPLETED for event in result["inspection_ledger"]
        )

    @pytest.mark.parametrize(
        "path",
        ["a.ts", "a.tsx", "a.mts", "a.cts", "a.js", "a.mjs", "a.cjs", "src/deep/a.ts"],
    )
    def test_every_module_suffix_is_opened(self, path: str) -> None:
        result = analyzer.node(make_state({path: WRITABLE_TS}))
        assert rule_ids(result) == ["DA-SKILL-WRITABLE"]
        assert result["findings"][0].file == path

    @pytest.mark.parametrize("path", ["a.txt", "a.py", "a.java", "a.json", "a.tsxx"])
    def test_a_file_of_another_kind_is_not_opened(self, path: str) -> None:
        """The control for the parametrization above.

        Without it, a predicate that opened *everything* would satisfy every
        suffix assertion and nothing would notice.
        """
        result = analyzer.node(make_state({path: WRITABLE_TS}))
        assert result["findings"] == []
        assert [event["path"] for event in result.get("inspection_ledger", [])] != [path]


class TestSkillWritable:
    """``DA-SKILL-WRITABLE``: can this agent rewrite the instructions it runs on?"""

    def test_it_fires_on_the_shape_the_tutorial_teaches(self) -> None:
        result = analyzer.node(make_state({"src/agent.ts": WRITABLE_TS}))
        assert rule_ids(result) == ["DA-SKILL-WRITABLE"]
        finding = result["findings"][0]
        assert finding.severity == "MEDIUM"
        assert "/skills/" in finding.message
        assert "no human is asked" in finding.message

    def test_it_is_silent_when_a_rule_denies_the_path(self) -> None:
        assert analyzer.node(make_state({"src/agent.ts": DENIED_TS}))["findings"] == []

    def test_one_finding_per_path_and_a_deny_clears_only_its_own(self) -> None:
        """The per-path granularity, and its control in the same call.

        A reviewer who accepts a writable personal directory must still be told
        about a writable shared library, so the verdict is per path rather than
        per call -- and the covered sibling proves the rule really decided rather
        than the Rule simply never firing.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/shared/", "/skills/personal/"],
  permissions: [{ operations: ["write"], paths: ["/skills/shared/**"], mode: "deny" }],
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-SKILL-WRITABLE"]
        assert "/skills/personal/" in findings[0].message
        assert "/skills/shared/" not in findings[0].message

    def test_a_read_rule_does_not_end_the_walk(self) -> None:
        """A rule that does not govern writing says nothing about writing."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  permissions: [{ operations: ["read"], paths: ["/skills/**"], mode: "deny" }],
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_rule_order_decides_and_a_later_deny_does_not_reach_back(self) -> None:
        """Upstream tells people to place specific rules before broad ones.

        A predicate asking "is there any deny in the list" would read the same in
        a test and be wrong on exactly the configuration upstream recommends.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/personal/"],
  permissions: [
    { operations: ["write"], paths: ["/skills/personal/**"], mode: "interrupt" },
    { operations: ["write"], paths: ["/skills/**"], mode: "deny" },
  ],
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.severity for finding in findings] == ["LOW"]
        assert "A human is asked to approve the write." in findings[0].message

    def test_an_interrupt_on_gate_over_both_write_tools_lowers_the_severity(self) -> None:
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  interruptOn: { read_file: true, write_file: true, edit_file: true },
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.severity for finding in findings] == ["LOW"]

    def test_a_gate_over_one_write_tool_is_not_a_mitigation(self) -> None:
        """The control, and the shape upstream's own JavaScript page publishes.

        ``{ read_file: true, write_file: true, delete_file: true }`` gates one of
        the two tools that rewrite a Skill file, so it is not confirmed as a
        mitigation. It once was, which made this exact configuration report ``LOW``
        here and ``MEDIUM`` in the Python track -- the same rule id carrying two
        risk statements because the application was written in TypeScript.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  interruptOn: { read_file: true, write_file: true, delete_file: true },
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [(f.rule_id, f.severity) for f in findings] == [("DA-SKILL-WRITABLE", "MEDIUM")]
        assert "no human is asked" in findings[0].message

    def test_a_gate_over_the_other_write_tool_alone_is_not_a_mitigation_either(self) -> None:
        """The mirror of the case above, so neither direction is the special one."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  interruptOn: { edit_file: true },
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [(f.rule_id, f.severity) for f in findings] == [("DA-SKILL-WRITABLE", "MEDIUM")]

    def test_a_gate_turned_off_is_no_mitigation(self) -> None:
        """The control for the assertion above: ``false`` is the developer opting out."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  interruptOn: { write_file: false },
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.severity for finding in findings] == ["MEDIUM"]

    def test_a_star_does_not_cross_a_separator(self) -> None:
        """``fnmatch`` would read this rule as covering the path, and clear a real Finding."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/personal/notes/"],
  permissions: [{ operations: ["write"], paths: ["/skills/*"], mode: "deny" }],
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]


class TestUnresolved:
    """``DA-UNRESOLVED``: the Rule reports where the Scan stopped looking."""

    @pytest.mark.parametrize(
        ("setting", "phrase"),
        [
            ("skills: sourcesFor(role)", "Skill source list is assembled at runtime"),
            ("backend: backendFor(role)", "backend is built somewhere this Scan cannot follow"),
            ("permissions: rulesFor(role)", "filesystem permission rules are not statically"),
            ("subagents: subagentsFor(role)", "subagent definitions are not statically"),
        ],
    )
    def test_each_surface_gets_its_own_message(self, setting: str, phrase: str) -> None:
        """One message per surface, so a reviewer knows *which* went unexamined."""
        source = f"""import {{ createDeepAgent }} from "deepagents";
export const agent = await createDeepAgent({{ {setting} }});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-UNRESOLVED"]
        assert phrase in findings[0].message
        assert findings[0].confidence == 1.0

    def test_an_absent_setting_is_a_configuration_and_not_a_boundary(self) -> None:
        """The control that separates "unresolved" from "not written".

        Without it, a resolver that reported every absent setting would satisfy
        every assertion above and would put four Findings on the shape the
        tutorial teaches.
        """
        assert rule_ids(analyzer.node(make_state({"a.ts": WRITABLE_TS}))) == ["DA-SKILL-WRITABLE"]

    def test_an_unresolvable_backend_root_is_reported_once_the_list_resolves(self) -> None:
        """Upstream's own headline example: ``rootDir: process.cwd()``."""
        source = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: process.cwd() });
export const agent = await createDeepAgent({ backend, skills: ["/skills/"] });
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert sorted({finding.rule_id for finding in findings}) == [
            "DA-SKILL-WRITABLE",
            "DA-UNRESOLVED",
        ]
        unresolved = next(f for f in findings if f.rule_id == "DA-UNRESOLVED")
        assert "root directory is not statically resolvable" in unresolved.message

    def test_a_written_root_that_resolves_raises_nothing(self) -> None:
        source = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: "./library" });
export const agent = await createDeepAgent({ backend, skills: ["/skills/"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_store_route_computed_per_request_reaches_the_boundary(self) -> None:
        """Upstream's namespaced-skills example: the path resolves, its contents do not."""
        source = """import { createDeepAgent, CompositeBackend, StateBackend, StoreBackend } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  backend: new CompositeBackend(new StateBackend(), {
    "/skills/": new StoreBackend({ namespace: (ctx) => [ctx.userId] }),
  }),
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-UNRESOLVED"]
        assert "routed to a store whose contents are computed per request" in findings[0].message

    def test_a_store_route_with_a_literal_namespace_does_not(self) -> None:
        """The control: what makes the route opaque is the computation, not the store."""
        source = """import { createDeepAgent, CompositeBackend, StateBackend, StoreBackend } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  backend: new CompositeBackend(new StateBackend(), {
    "/skills/": new StoreBackend({ namespace: ["curated"] }),
  }),
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_an_unreadable_permission_rule_undecides_every_path(self) -> None:
        """A ``mode`` this Scan cannot give a meaning to could be either verdict."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/a/", "/skills/b/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "audit" }],
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-UNRESOLVED"]
        assert "shape this Scan does not recognize" in findings[0].message

    def test_a_bare_string_where_upstream_writes_an_array_is_not_iterated(self) -> None:
        """``paths: "/skills/**"`` is refused rather than read character by character.

        Upstream writes ``operations`` and ``paths`` as arrays on every rule it
        publishes. Reading a bare string as a one-element sequence is not the
        forgiving choice -- Python would iterate it into characters, and a rule
        whose patterns were ``/``, ``s``, ``k`` covers nothing, so a ``deny``
        written this way would silently stop denying.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/a/"],
  permissions: [{ operations: ["write"], paths: "/skills/**", mode: "deny" }],
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-UNRESOLVED"]
        assert "shape this Scan does not recognize" in findings[0].message

    def test_the_array_form_of_the_same_rule_is_read(self) -> None:
        """The control: what is refused is the bare string, not the rule."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/a/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""
        assert analyzer.node(make_state({"a.ts": source}))["findings"] == []

    def test_a_route_covers_a_path_that_starts_with_it_and_not_only_an_equal_one(self) -> None:
        """A route key is a path *prefix*, which is upstream's own layout.

        ``/skills/`` routed to a per-request store makes ``/skills/personal/``
        opaque, because that is where the path resolves to. Reading the relation
        as equality instead would leave the longer path apparently on disk and
        put a writability verdict on contents no Scan can see.
        """
        source = """import { createDeepAgent, CompositeBackend, StateBackend, StoreBackend } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/personal/"],
  backend: new CompositeBackend(new StateBackend(), {
    "/skills/": new StoreBackend({ namespace: (ctx) => [ctx.userId] }),
  }),
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-UNRESOLVED"]
        assert "routed to a store whose contents are computed per request" in findings[0].message

    def test_a_route_that_is_not_a_prefix_of_the_path_covers_nothing(self) -> None:
        """The control: the relation is a prefix, not a match on any shared segment."""
        source = """import { createDeepAgent, CompositeBackend, StateBackend, StoreBackend } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/personal/"],
  backend: new CompositeBackend(new StateBackend(), {
    "/library/": new StoreBackend({ namespace: (ctx) => [ctx.userId] }),
  }),
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]


class TestShadow:
    """``DA-SHADOW``: a later source silently replaces a Skill in an earlier one."""

    LAYERED = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: "./library" });
export const agent = await createDeepAgent({
  backend,
  skills: ["/skills/shared/", "/skills/personal/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""

    @staticmethod
    def manifest(name: str) -> str:
        return f"---\nname: {name}\ndescription: A Skill.\n---\n\n# {name}\n"

    def test_a_confirmed_collision_fires(self) -> None:
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW"]
        finding = result["findings"][0]
        assert finding.severity == "HIGH"
        assert "/skills/shared/" in finding.message
        assert "/skills/personal/" in finding.message
        assert "library/skills/personal/triage/SKILL.md" in finding.message

    def test_layering_without_a_collision_is_silent(self) -> None:
        """Upstream documents layering as intentional.

        A Rule that read the source list without confirming the names would fire
        on every application that follows the advice.
        """
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/notes/SKILL.md": self.manifest("notes"),
                }
            )
        )
        assert result["findings"] == []

    def test_a_collision_cannot_be_confirmed_without_a_filesystem_root(self) -> None:
        """No backend means the Skills are in agent state, and no name is readable."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/shared/", "/skills/personal/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""
        result = analyzer.node(
            make_state(
                {
                    "a.ts": source,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert result["findings"] == []
        # The manifests were still opened and still reported: ADR 0008 §3's price.
        assert len(result["inspection_ledger"]) == 3

    THREE_SOURCES = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: "./library" });
export const agent = await createDeepAgent({
  backend,
  skills: ["/skills/base/", "/skills/team/", "/skills/personal/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""

    def test_the_source_that_decides_is_the_last_one_not_the_next(self) -> None:
        """Upstream's rule is *last one wins*, so a middle source decides nothing.

        With three sources holding one name, the two Findings must both name the
        **final** source as what the agent actually loads. Reading the next
        source along instead would tell a reviewer that the team library wins,
        and they would go and fix the wrong directory.
        """
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.THREE_SOURCES,
                    "library/skills/base/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/team/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW", "DA-SHADOW"]
        shadowed = [f.message for f in result["findings"]]
        assert "/skills/base/" in shadowed[0] and "/skills/team/" in shadowed[1]
        for message in shadowed:
            assert "/skills/personal/" in message
            assert "library/skills/personal/triage/SKILL.md" in message

    def test_two_manifests_of_one_name_inside_one_source_read_deterministically(self) -> None:
        """A collision *inside* a source is not what this Rule judges.

        The source still contributes the name once, taken from the first manifest
        in path order, so the Finding names one file rather than whichever the
        walk happened to reach last.
        """
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/alpha/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/zulu/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW"]
        assert "library/skills/personal/alpha/SKILL.md" in result["findings"][0].message

    def test_a_manifest_with_no_frontmatter_fence_contributes_no_name(self) -> None:
        """Two unreadable manifests must not collide on a placeholder.

        A manifest this reader cannot take a ``name`` out of contributes nothing.
        Giving it a stand-in would make every pair of such files a confirmed
        collision, which is the direction that invents a Finding.
        """
        unfenced = "name: triage\ndescription: A Skill.\n\n# triage\n"
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": unfenced,
                    "library/skills/personal/triage/SKILL.md": unfenced,
                }
            )
        )
        assert result["findings"] == []

    def test_the_same_two_manifests_fenced_do_collide(self) -> None:
        """The control for the fence: what silenced the Rule was the missing fence."""
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW"]

    def test_a_sibling_directory_sharing_a_name_prefix_is_not_the_source(self) -> None:
        """``/skills/shared/`` maps onto a directory, never onto ``shared-archive/``.

        The mapped prefix carries a trailing separator for this reason. Without
        it, the source would collect every Skill in a sibling whose name merely
        starts the same way, and the Finding would report a collision between two
        directories the configuration never layered.
        """
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared-archive/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert result["findings"] == []

    def test_the_same_manifest_inside_the_source_does_collide(self) -> None:
        """The control for the separator: only the sibling's name kept it silent."""
        result = analyzer.node(
            make_state(
                {
                    "a.ts": self.LAYERED,
                    "library/skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "library/skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW"]

    def test_a_filesystem_backend_with_no_root_dir_roots_at_the_scan_root(self) -> None:
        """An absent ``rootDir`` is a configuration, not a boundary.

        Reading the absence as unresolvable would raise ``DA-UNRESOLVED`` on a
        backend that resolved perfectly well and would stop ``DA-SHADOW`` from
        confirming a collision the Scan can see, so the miss would arrive wearing
        a boundary's clothes.
        """
        source = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ maxBytes: 1 });
export const agent = await createDeepAgent({
  backend,
  skills: ["/skills/shared/", "/skills/personal/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
});
"""
        result = analyzer.node(
            make_state(
                {
                    "a.ts": source,
                    "skills/shared/triage/SKILL.md": self.manifest("triage"),
                    "skills/personal/triage/SKILL.md": self.manifest("triage"),
                }
            )
        )
        assert rule_ids(result) == ["DA-SHADOW"]
        assert "skills/personal/triage/SKILL.md" in result["findings"][0].message


class TestSubagentSkills:
    """``DA-SUBAGENT-SKILLS``: a custom subagent inherits nothing."""

    SOURCE = """import { createDeepAgent } from "deepagents";

const reviewer = { name: "reviewer", description: "d", skills: ["/skills/shared/"] };
const summarizer = { name: "summarizer", description: "d" };

export const agent = await createDeepAgent({
  skills: ["/skills/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], mode: "deny" }],
  subagents: [reviewer, summarizer],
});
"""

    def test_a_definition_without_its_own_skills_fires_and_its_sibling_does_not(self) -> None:
        findings = analyzer.node(make_state({"a.ts": self.SOURCE}))["findings"]
        assert [finding.rule_id for finding in findings] == ["DA-SUBAGENT-SKILLS"]
        assert findings[0].severity == "LOW"
        # The definition's own line, which is what tells two of them apart.
        assert findings[0].start_line == 4

    def test_no_subagents_at_all_is_silent(self) -> None:
        """The general-purpose subagent inherits, so an absent list reports nothing."""
        assert analyzer.node(make_state({"a.ts": DENIED_TS}))["findings"] == []


class TestTheParser:
    """The two grammars, and the error tolerance the analyzer depends on."""

    # JSX that *encloses* the call, rather than merely sitting beside it. The
    # distinction is the whole point of carrying two grammars: tree-sitter's error
    # tolerance already recovers a call written on a later line than some JSX, so a
    # fixture of that shape would pass under the TypeScript grammar alone and prove
    # nothing. Here the TypeScript grammar reads `<Panel>` as a type parameter list
    # and swallows the call with it, so the configuration is found only by the TSX
    # grammar. Measured before it was written: under `language_typescript()` this
    # source yields zero configurations.
    JSX_WRAPPED = """import { createDeepAgent } from "deepagents";

export function App() {
  return <Panel>{createDeepAgent({ skills: ["/skills/"] })}</Panel>;
}
"""

    def test_a_tsx_component_parses_and_its_configuration_is_read(self) -> None:
        assert rule_ids(analyzer.node(make_state({"app.tsx": self.JSX_WRAPPED}))) == [
            "DA-SKILL-WRITABLE"
        ]

    def test_jsx_in_a_plain_js_module_is_recovered_by_the_retry(self) -> None:
        """The suffix cannot tell JSX-in-``.js`` from ordinary JavaScript.

        ``.js`` is parsed as TypeScript first, which loses this call entirely, so
        the parser retries with the TSX grammar and keeps the clean parse.
        """
        assert rule_ids(analyzer.node(make_state({"app.js": self.JSX_WRAPPED}))) == [
            "DA-SKILL-WRITABLE"
        ]

    def test_the_typescript_grammar_alone_really_loses_that_call(self) -> None:
        """The evidence for the two assertions above, rather than the claim.

        Without this, both would pass on a parser that only ever used one grammar
        -- which is exactly what a mutation run found before it was added.
        """
        from tree_sitter import Parser

        from skillspector.deepagents_js import host_config
        from skillspector.deepagents_js import parser as ts_parser

        typescript_only = Parser(ts_parser._typescript()).parse(self.JSX_WRAPPED.encode("utf-8"))
        assert typescript_only.root_node.has_error
        assert host_config.find_agent_configurations(typescript_only) == []

    def test_a_typescript_generic_is_not_re_read_as_jsx(self) -> None:
        """The control for the retry: it must only apply where the first attempt failed."""
        source = """import { createDeepAgent } from "deepagents";
function identity<T>(value: T): T { return value; }
export const agent = await createDeepAgent({ skills: ["/skills/"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_syntax_error_elsewhere_does_not_lose_the_configuration(self) -> None:
        """tree-sitter is error tolerant, and this Analyzer relies on it.

        The grammar predates roughly two years of TypeScript, so refusing a file
        for ``has_error`` would silently drop whole configurations.
        """
        source = """import { createDeepAgent } from "deepagents";
const broken = @@@ ;
export const agent = await createDeepAgent({ skills: ["/skills/"] });
"""
        result = analyzer.node(make_state({"a.ts": source}))
        assert rule_ids(result) == ["DA-SKILL-WRITABLE"]
        assert result["inspection_ledger"][0]["outcome"] == LedgerOutcome.COMPLETED


class TestTheResolutionBoundary:
    """Where the resolver refuses to guess, observed through the Findings."""

    @pytest.mark.parametrize("keyword", ["const", "let", "var", "export const", "export let"])
    def test_a_top_level_constant_resolves(self, keyword: str) -> None:
        """``export const`` is a top-level declaration, and the dominant module idiom.

        The grammar wraps an exported declaration in an ``export_statement``
        rather than leaving it at the root, so reading the root's children alone
        made the single word ``export`` the difference between a module that
        reports and one that degrades to ``DA-UNRESOLVED``. Python has no such
        wrapper, so the two tracks answered the same configuration differently.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
{keyword} SOURCES = ["/skills/"];
export const agent = await createDeepAgent({{ skills: SOURCES }});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    @pytest.mark.parametrize(
        "statement",
        [
            "export default SOURCES;",
            'export { SOURCES } from "./sources";',
            'export * from "./sources";',
        ],
    )
    def test_an_export_that_declares_nothing_is_skipped(self, statement: str) -> None:
        """An export form binding no declaration must not be mistaken for one.

        Each of these has no ``declaration`` child: the first re-exports a name,
        and the other two rename a binding whose value lives in another module,
        which is past this resolver's one-module boundary.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
{statement}
export const agent = await createDeepAgent({{ skills: SOURCES }});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-UNRESOLVED"]

    def test_a_name_bound_inside_a_function_does_not(self) -> None:
        source = """import { createDeepAgent } from "deepagents";
export function build() {
  const SOURCES = ["/skills/"];
  return createDeepAgent({ skills: SOURCES });
}
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-UNRESOLVED"]

    def test_a_name_declared_twice_does_not(self) -> None:
        """Which declaration reaches the call is control flow this module does not model."""
        source = """import { createDeepAgent } from "deepagents";
let SOURCES = ["/skills/a/"];
SOURCES = ["/skills/b/"];
let SOURCES = ["/skills/c/"];
export const agent = await createDeepAgent({ skills: SOURCES });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-UNRESOLVED"]

    def test_a_shorthand_property_resolves_like_its_longhand(self) -> None:
        source = """import { createDeepAgent, FilesystemBackend } from "deepagents";
const backend = new FilesystemBackend({ rootDir: "./library" });
const skills = ["/skills/"];
export const agent = await createDeepAgent({ backend, skills });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_spread_among_the_options_keeps_the_settings_written_beside_it(self) -> None:
        """The Python track drops the ``**`` entry and keeps the named keywords; so does this.

        Refusing the whole object here made ``createDeepAgent({ ...defaults,
        skills: [...] })`` -- one line different from the passing case -- report
        nothing at all, while the same configuration spelled
        ``create_deep_agent(**defaults, skills=[...])`` reported
        ``DA-SKILL-WRITABLE``. One rule id must not mean two things because the
        application was written in a second language.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({ ...defaults, skills: ["/skills/"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_spread_is_still_refused_everywhere_it_could_clear_a_finding(self) -> None:
        """Tolerance is an options-object policy, not a spread policy.

        At every other object a dropped spread would *remove* a verdict rather
        than add one -- the ``deny`` rule, the approval gate, the backend root,
        the route map and the subagent's own ``skills`` are each a setting whose
        absence is read as permission. So each of these stays a boundary, and
        each says so with ``DA-UNRESOLVED`` rather than with silence.
        """
        header = (
            'import { createDeepAgent, FilesystemBackend, CompositeBackend } from "deepagents";\n'
        )
        for options in (
            'skills: ["/s/"], permissions: [{ ...rule, mode: "deny" }]',
            'skills: ["/s/"], backend: new FilesystemBackend({ ...opts })',
            'skills: ["/s/"], backend: new CompositeBackend(base, { ...routes })',
            "subagents: [{ ...reviewer }]",
        ):
            source = f"{header}export const agent = await createDeepAgent({{ {options} }});\n"

            assert analyzer._UNRESOLVED_RULE_ID in rule_ids(
                analyzer.node(make_state({"a.ts": source}))
            )

    def test_a_spread_inside_the_approval_gate_loses_the_mitigation_not_the_finding(self) -> None:
        """An ``interruptOn`` that does not resolve is an unconfirmed mitigation.

        The gate is the one refused site whose loss does not raise
        ``DA-UNRESOLVED`` -- the Analyzer states why -- so it is pinned by the
        severity instead: the write is still reported, and reported unmitigated.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({ skills: ["/s/"], interruptOn: { ...gates } });
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]

        assert [(f.rule_id, f.severity) for f in findings] == [("DA-SKILL-WRITABLE", "MEDIUM")]

    @pytest.mark.parametrize(
        ("name", "options"),
        [
            ("a line comment above a setting", '// note\n  skills: ["/skills/"],'),
            ("a trailing line comment", 'skills: ["/skills/"], // note'),
            ("a block comment above a setting", '/* note */\n  skills: ["/skills/"],'),
            ("a comment inside the array", 'skills: [/* note */ "/skills/"],'),
        ],
    )
    def test_a_comment_among_the_options_changes_nothing(self, name: str, options: str) -> None:
        """A comment is not syntax, and reading it as syntax silenced every Rule.

        tree-sitter reports a comment as a named child, so a single ``//``
        anywhere inside ``createDeepAgent({...})`` used to make the whole
        configuration unreadable -- and report *nothing*, not even
        ``DA-UNRESOLVED``. Upstream's own published example carries this exact
        shape, and the Python track is immune because ``ast`` discards comments
        before the resolver ever sees them.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
export const agent = await createDeepAgent({{
  {options}
}});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"], name

    def test_a_comment_does_not_shift_an_argument_position(self) -> None:
        """A note before the first argument must not be read as the first argument."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent(
  // the options this agent runs on
  { skills: ["/skills/"] },
);
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_comment_does_not_lose_a_permission_rule(self) -> None:
        """Two comment sites at once, and both would *remove* a Finding's mitigation.

        The note between the two rule objects is read by the rules list; the note
        inside ``operations`` is read by the literal reader that every array of
        values goes through. Losing either sends the whole ``permissions``
        property to the boundary, which turns a denied path back into a reported
        write.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  permissions: [
    // the shared library is read-only
    { operations: [/* only writes */ "write"], paths: ["/skills/**"], mode: "deny" },
    { operations: ["write"], paths: ["/tmp/**"], mode: "deny" },
  ],
});
"""
        assert analyzer.node(make_state({"a.ts": source}))["findings"] == []

    def test_a_comment_does_not_lose_a_subagent_definition(self) -> None:
        """A note between two subagent definitions must not make the list unreadable.

        Losing the list is not a silence here: it raises ``DA-UNRESOLVED`` where
        the truth is that one of the two subagents genuinely has no Skills of its
        own, which is the ``DA-SUBAGENT-SKILLS`` this pins instead.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  subagents: [
    // checks a drafted reply
    { name: "reviewer", skills: ["/skills/"] },
    { name: "summarizer" },
  ],
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SUBAGENT-SKILLS"]

    def test_a_comment_inside_a_declaration_does_not_lose_the_constant(self) -> None:
        """The comment sits beside the declarator, not inside the value."""
        source = """import { createDeepAgent } from "deepagents";
const /* the shared library */ SOURCES = ["/skills/"];
export const agent = await createDeepAgent({ skills: SOURCES });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    @pytest.mark.parametrize(
        ("name", "backend"),
        [
            (
                # Read by position, so a comment ahead of the options object
                # would be read as the options object.
                "the backend root",
                'new FilesystemBackend(/* rooted at the library */ { rootDir: "./library" })',
            ),
            (
                # The route map is the *second* positional argument, so a
                # comment before the first shifts the map out of reach.
                "the composite route map",
                "new CompositeBackend(/* the default */ new FilesystemBackend"
                '({ rootDir: "." }), { "/skills/": new StoreBackend({ namespace: ["s"] }) })',
            ),
            (
                # Every argument must resolve for the store to count as
                # computed per request; a comment is not an argument.
                "the store's own arguments",
                'new CompositeBackend(new FilesystemBackend({ rootDir: "." }), { "/skills/": '
                'new StoreBackend(/* one namespace for everyone */ { namespace: ["s"] }) })',
            ),
        ],
    )
    def test_a_comment_does_not_shift_a_backend_argument(self, name: str, backend: str) -> None:
        """Three places a backend is read by *position*, where a comment is not a position.

        Each of these fails in the direction that invents a boundary: the note
        becomes the argument the reader wanted, and the configuration it was
        actually written with is reported as unresolvable.
        """
        source = (
            "import { createDeepAgent, FilesystemBackend, CompositeBackend, StoreBackend } "
            'from "deepagents";\n'
            f"export const agent = await createDeepAgent({{\n"
            f"  backend: {backend},\n"
            f'  skills: ["/skills/"],\n'
            f"}});\n"
        )

        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"], name

    def test_a_comment_does_not_lose_the_approval_gate(self) -> None:
        """The one comment site whose failure removed a *mitigation* rather than a Finding."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  interruptOn: { /* pause before a write */ write_file: true, edit_file: true },
});
"""
        findings = analyzer.node(make_state({"a.ts": source}))["findings"]

        assert [(f.rule_id, f.severity) for f in findings] == [("DA-SKILL-WRITABLE", "LOW")]

    def test_an_options_object_built_elsewhere_is_a_silence(self) -> None:
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent(buildOptions());
"""
        assert analyzer.node(make_state({"a.ts": source}))["findings"] == []

    def test_a_plain_template_literal_resolves_and_an_interpolated_one_does_not(self) -> None:
        plain = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({ skills: [`/skills/`] });
"""
        interpolated = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({ skills: [`/skills/${tenant}/`] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": plain}))) == ["DA-SKILL-WRITABLE"]
        assert rule_ids(analyzer.node(make_state({"a.ts": interpolated}))) == ["DA-UNRESOLVED"]

    def test_an_escape_sequence_refuses_rather_than_being_decoded(self) -> None:
        """Decoding JavaScript escapes correctly is a second parser, declined."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({ skills: ["/skills\\u002f"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-UNRESOLVED"]

    def test_a_call_that_is_not_awaited_is_still_found(self) -> None:
        """Upstream writes the call both ways, so the reader must not assume either."""
        source = """import { createDeepAgent } from "deepagents";
export const agent = createDeepAgent({ skills: ["/skills/"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    def test_a_call_inside_a_factory_is_still_found(self) -> None:
        """A call the resolver could not see is a configuration nobody would hear about."""
        source = """import { createDeepAgent } from "deepagents";
export function agentFor(role: string) {
  return createDeepAgent({ skills: ["/skills/"] });
}
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    # Both grammars, because ``<State>`` is the exact token they disagree about:
    # the TypeScript grammar reads it as a type argument and TSX has to decide
    # against JSX to do the same. A fix measured under one of them is a fix for
    # one file extension, and ``.tsx`` is the one a React-hosted agent uses.
    BOTH_GRAMMARS = pytest.mark.parametrize("path", ["a.ts", "App.tsx"])

    @BOTH_GRAMMARS
    @pytest.mark.parametrize(
        ("name", "call"),
        [
            ("await and a type argument", "await createDeepAgent<State>({ skills: SKILLS })"),
            ("a type argument alone", "createDeepAgent<State>({ skills: SKILLS })"),
            ("parentheses around the callee", "await (createDeepAgent)({ skills: SKILLS })"),
            ("a non-null assertion on the callee", "await createDeepAgent!({ skills: SKILLS })"),
        ],
    )
    def test_a_wrapped_callee_is_still_the_call_it_names(
        self, name: str, call: str, path: str
    ) -> None:
        """``await createDeepAgent<State>({...})`` is the shape that was lost outright.

        With both an ``await`` and a type argument, the grammar makes the
        ``await_expression`` the call's *function* field rather than its parent,
        so reading that field literally found no call at all -- while the
        Analyzer still opened the file and still reported ``completed``, which
        is a miss no reader can tell from a clean Scan.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
const SKILLS = ["/skills/"];
export const agent = {call};
"""
        assert rule_ids(analyzer.node(make_state({path: source}))) == ["DA-SKILL-WRITABLE"], name

    @BOTH_GRAMMARS
    @pytest.mark.parametrize(
        ("name", "options"),
        [
            ("an as-cast", '{ skills: ["/skills/"] } as CreateDeepAgentOptions'),
            ("a satisfies check", '{ skills: ["/skills/"] } satisfies CreateDeepAgentOptions'),
            ("parentheses", '({ skills: ["/skills/"] })'),
            ("an as-const on the list", '{ skills: ["/skills/"] as const }'),
        ],
    )
    def test_a_transparent_wrapper_is_unwrapped_rather_than_refused(
        self, name: str, options: str, path: str
    ) -> None:
        """Each of these is erased by the compiler, so none may hide a literal.

        Stopping at one was the worst failure this module had: every setting was
        written at the call site, and the Scan reported no Finding, no boundary
        and a risk score of 0 -- the clean report the package docstring says it
        exists to prevent.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
export const agent = await createDeepAgent({options});
"""
        assert rule_ids(analyzer.node(make_state({path: source}))) == ["DA-SKILL-WRITABLE"], name

    def test_the_old_style_type_assertion_is_unwrapped_too(self) -> None:
        """``<T>value`` is the one wrapper written type-first, and it is TypeScript-only.

        It is unreachable under the TSX grammar by construction -- there the same
        characters open a JSX element -- so unlike its four siblings above this
        one is asserted on a ``.ts`` path alone.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent(<CreateDeepAgentOptions>{ skills: ["/skills/"] });
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"]

    @pytest.mark.parametrize(
        ("name", "extra"),
        [
            ("a method shorthand", "onStart() { return 1; }"),
            ("a getter", "get label() { return 'x'; }"),
            ("a computed key", "[optionName]: 1"),
        ],
    )
    def test_an_unreadable_property_drops_itself_and_not_the_object(
        self, name: str, extra: str
    ) -> None:
        """The spread's argument, applied to the shapes that are not spreads.

        One of these beside a literal ``skills`` silenced all four Rules. The
        tolerance is monotone -- a dropped property reads as absent, and the
        refusal it replaces made *every* property absent -- so this call site can
        only ever read more settings than before.
        """
        source = f"""import {{ createDeepAgent }} from "deepagents";
export const agent = await createDeepAgent({{
  skills: ["/skills/"],
  {extra},
}});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-SKILL-WRITABLE"], name

    def test_an_unreadable_property_is_still_refused_where_it_could_clear_a_finding(self) -> None:
        """The control for the tolerance above: only ``_options`` takes it.

        A permission rule carrying a getter is refused whole, which reaches the
        boundary rather than reading the rule as one that does not deny.
        """
        source = """import { createDeepAgent } from "deepagents";
export const agent = await createDeepAgent({
  skills: ["/skills/"],
  permissions: [{ operations: ["write"], paths: ["/skills/**"], get mode() { return "deny"; } }],
});
"""
        assert rule_ids(analyzer.node(make_state({"a.ts": source}))) == ["DA-UNRESOLVED"]


class TestTheCommittedFixtures:
    """The Rules, read out of real Scans of the committed fixture trees."""

    @staticmethod
    def scan(name: str) -> list[Any]:
        from tests.behavior.projection import FIXTURES_DIR, scan_state

        return list(scan_state(FIXTURES_DIR / name)["findings"])

    def test_the_layered_fixture_carries_one_of_each_of_three_rules(self) -> None:
        found = sorted(
            finding.rule_id
            for finding in self.scan("deepagents_js_layered_skills")
            if finding.rule_id.startswith("DA-")
        )
        assert found == ["DA-SHADOW", "DA-SKILL-WRITABLE", "DA-SUBAGENT-SKILLS"]

    def test_the_runtime_fixture_carries_only_the_boundary(self) -> None:
        found = [
            finding.rule_id
            for finding in self.scan("deepagents_js_runtime_skills")
            if finding.rule_id.startswith("DA-")
        ]
        assert found == ["DA-UNRESOLVED", "DA-UNRESOLVED"]

    def test_the_detection_fixture_carries_no_rule_at_all(self) -> None:
        """A bare signal is a Framework, not a Finding."""
        assert [
            finding.rule_id
            for finding in self.scan("deepagents_js_detection")
            if finding.rule_id.startswith("DA-")
        ] == []
