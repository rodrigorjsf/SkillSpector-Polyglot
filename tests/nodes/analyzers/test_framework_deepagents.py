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

"""Tests for the gated ``framework_deepagents`` Analyzer and its resolution boundary.

Every test enters through ``node(state)`` with a synthetic state.
:mod:`skillspector.deepagents.host_config` gets no test of its own on purpose:
a resolution decision that cannot be observed as a Finding is a decision that
should not exist, and a suite that asserted the resolver's return shapes would
go green on an Analyzer that never called it.

Many assertions read the ledger rows and status rather than the Finding list.
A green suite is not evidence the Analyzer ran: ``guard_analyzer_node`` turns any
exception into an empty Finding list plus a ``"failed"`` status, and an empty
Finding list is also the correct answer on a configuration that fully resolves --
so a test that only checked ``findings == []`` would pass on a completely broken
Analyzer. The rows are what separate the two.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from skillspector.framework import Framework
from skillspector.inspection_ledger import (
    LedgerOutcome,
    LedgerReason,
    finalize_ledger,
    inspection_work_id,
)
from skillspector.nodes.analyzers import framework_deepagents as analyzer

WRITABLE_SKILLS_PY = """from deepagents import create_deep_agent

agent = create_deep_agent(model="claude-sonnet-5", skills=["/skills/"])
"""

PYPROJECT = """[project]
name = "ops-agent"
version = "0.1.0"
dependencies = ["deepagents>=0.6.8"]
"""

SKILL_MD = """---
name: ops-runbook
description: Restart the ingest service.
---

# Ops runbook
"""

UNPARSEABLE_PY = """from deepagents import create_deep_agent

agent = create_deep_agent(model=, skills=[
"""

# The four boundary cases, one module each, each written the way upstream's own
# documentation writes it.

RUNTIME_SKILLS_PY = """from deepagents import create_deep_agent

SKILLS_BY_ROLE = {
    "engineering": ["/skills/code-review/"],
    "support": ["/skills/runbook/"],
}


def build(user_role: str):
    return create_deep_agent(
        model="claude-sonnet-5",
        skills=SKILLS_BY_ROLE.get(user_role, []),
    )
"""

HELPER_BACKEND_PY = """from deepagents import create_deep_agent

from .infra import backend_for_tenant

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=backend_for_tenant("acme"),
    skills=["/skills/"],
)
"""

HELPER_PERMISSIONS_PY = """from deepagents import create_deep_agent

from .policy import rules_for_tenant

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/"],
    permissions=rules_for_tenant("acme"),
)
"""

ROUTED_STORE_PY = """from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/"],
    backend=CompositeBackend(
        default=StateBackend(),
        routes={
            "/skills/": StoreBackend(
                namespace=lambda rt: (rt.server_info.assistant_id,),
            ),
        },
    ),
)
"""

# The controls. Each resolves through the boundary rather than falling on it.

MODULE_CONSTANT_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

SKILL_PATHS = ["/skills/shared/", "/skills/personal/"]
BACKEND = FilesystemBackend(root_dir="./app")

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=BACKEND,
    skills=SKILL_PATHS,
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/shared/**"], mode="deny"),
    ],
)
"""

NO_ARGUMENTS_PY = """from deepagents import create_deep_agent

agent = create_deep_agent(model="claude-sonnet-5")
"""

# The negative control of the whole Ticket: every Skill source the agent is
# given is denied write access, so a correctly configured application is silent
# and a future false positive on ordinary configuration is visible as noise
# rather than as one more Finding among several.
DENIED_PY = """from deepagents import FilesystemPermission, create_deep_agent

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/shared/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""


# The shadowing Rule's inputs. Every one of them denies write to both sources,
# so what a test reads is the shadowing verdict rather than the writability one
# arriving alongside it.

SHADOWED_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=FilesystemBackend(root_dir="./library"),
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

THREE_SOURCES_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=FilesystemBackend(root_dir="./library"),
    skills=["/skills/shared/", "/skills/team/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

# The default backend, written by omission. Its Skill files are not on disk, so
# no configured path maps -- and that is a configuration this Scan read rather
# than a place it stopped reading.
DEFAULT_BACKEND_PY = """from deepagents import FilesystemPermission, create_deep_agent

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

STORE_BACKEND_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends import StoreBackend

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=StoreBackend(),
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

# The one unmappable case that *is* a boundary: the root is written and this
# Scan cannot read it.
UNRESOLVED_ROOT_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from .infra import root_for_tenant

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=FilesystemBackend(root_dir=root_for_tenant("acme")),
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

# A filesystem backend that names no root at all. Upstream roots it at the
# process working directory, which is not a fact in any scanned file, so it is
# read as the Scan root -- the same limit a written relative root carries.
BARE_ROOT_PY = """from deepagents import FilesystemPermission, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

agent = create_deep_agent(
    model="claude-sonnet-5",
    backend=FilesystemBackend(),
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""


# The subagent Rule's inputs. Upstream states a custom subagent does not inherit
# the main agent's Skills, so the whole question is whether the definition
# carries a ``skills`` key of its own. Every one of these denies write to the
# main agent's own Skill source, so what a test reads is this verdict rather
# than ``DA-SKILL-WRITABLE`` arriving alongside it.

WITHOUT_OWN_SKILLS = """        {
            "name": "researcher",
            "description": "Gathers background on an incoming ticket.",
            "prompt": "Collect the account history the ticket refers to.",
        },"""

WITH_OWN_SKILLS = """        {
            "name": "researcher",
            "description": "Gathers background on an incoming ticket.",
            "prompt": "Collect the account history the ticket refers to.",
            "skills": ["/skills/research/"],
        },"""


def _with_subagents(definitions: str) -> str:
    """An agent whose own Skill source is denied, defining *definitions*."""
    return f"""from deepagents import FilesystemPermission, create_deep_agent

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/shared/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
    subagents=[
{definitions}
    ],
)
"""


# The subagent list assembled at runtime, and one definition this Scan cannot
# read. Neither names a Skill source, so neither carries a writability verdict
# that would have to be read around.
RUNTIME_SUBAGENTS_PY = """from deepagents import create_deep_agent

from .team import subagents_for_tenant

agent = create_deep_agent(
    model="claude-sonnet-5",
    subagents=subagents_for_tenant("acme"),
)
"""

OPAQUE_SUBAGENT_PY = """from deepagents import create_deep_agent

from .team import researcher

agent = create_deep_agent(
    model="claude-sonnet-5",
    subagents=[researcher],
)
"""


def _manifest(name: str) -> str:
    """An Agent Skills manifest declaring *name*."""
    return f"---\nname: {name}\ndescription: Route an incoming ticket.\n---\n\n# {name}\n"


# The two mapped source directories of ``SHADOWED_PY``, declaring one name.
COLLIDING_MANIFESTS: dict[str, str] = {
    "library/skills/shared/ticket-triage/SKILL.md": _manifest("ticket-triage"),
    "library/skills/personal/ticket-triage/SKILL.md": _manifest("ticket-triage"),
}

# The same two directories, each providing what the other does not.
LAYERED_MANIFESTS: dict[str, str] = {
    "library/skills/shared/ticket-triage/SKILL.md": _manifest("ticket-triage"),
    "library/skills/personal/meeting-notes/SKILL.md": _manifest("meeting-notes"),
}


def _messages(result: dict[str, Any]) -> list[str]:
    """The Finding messages a node call produced, in the order it produced them."""
    return [finding.message for finding in result["findings"]]


def _rule_ids(result: dict[str, Any]) -> list[str]:
    """The Rule each Finding belongs to, in the order the node produced them."""
    return [finding.rule_id for finding in result["findings"]]


def make_state(
    file_cache: dict[str, str],
    framework: Framework = Framework.DEEPAGENTS,
) -> dict[str, Any]:
    """Build the slice of Scan state the Analyzer reads."""
    return {
        "framework": framework,
        "file_cache": dict(file_cache),
        "components": sorted(file_cache),
    }


class TestTheFrameworkGate:
    """The gate is the first statement, and a declining Analyzer emits nothing."""

    @pytest.mark.parametrize(
        "framework", [member for member in Framework if member is not Framework.DEEPAGENTS]
    )
    def test_another_framework_produces_no_findings_and_no_ledger(
        self, framework: Framework
    ) -> None:
        """Every Framework but this one, so a Framework added later is covered too."""
        result = analyzer.node(
            make_state(
                {"agent.py": WRITABLE_SKILLS_PY, "pyproject.toml": PYPROJECT},
                framework=framework,
            )
        )

        assert result["findings"] == []
        assert result.get("inspection_ledger", []) == []
        assert result.get("analyzer_status_events", []) == []

    def test_a_missing_framework_key_declines(self) -> None:
        result = analyzer.node({"file_cache": {"agent.py": WRITABLE_SKILLS_PY}})

        assert result["findings"] == []
        assert result.get("inspection_ledger", []) == []
        assert result.get("analyzer_status_events", []) == []


class TestApplicability:
    """A matching Framework always reports exactly one Analyzer Status.

    Applicability is one predicate -- the Components this Analyzer opens -- and
    both the gate and the accounting derive from it, so a Component that is
    opened is always a Component that is reported.
    """

    def test_all_three_applicable_kinds_are_opened_and_reported(self) -> None:
        result = analyzer.node(
            make_state(
                {
                    "agent.py": WRITABLE_SKILLS_PY,
                    "pyproject.toml": PYPROJECT,
                    "requirements-dev.txt": "deepagents>=0.6.8\n",
                    "skills/ops/SKILL.md": SKILL_MD,
                    "README.md": "# Ops agent\n",
                    "Makefile": "test:\n\tpytest\n",
                }
            )
        )

        assert [event["path"] for event in result["inspection_ledger"]] == [
            "agent.py",
            "pyproject.toml",
            "requirements-dev.txt",
            "skills/ops/SKILL.md",
        ]
        assert all(
            event["outcome"] is LedgerOutcome.COMPLETED for event in result["inspection_ledger"]
        )
        statuses = result["analyzer_status_events"]
        assert len(statuses) == 1
        assert statuses[0]["status"] == "completed"

    def test_a_component_that_produced_nothing_still_gets_a_work_item(self) -> None:
        """The whole point of this slice: no Rules, and still a row per Component."""
        result = analyzer.node(make_state({"pyproject.toml": PYPROJECT}))

        assert result["findings"] == []
        status = result["analyzer_status_events"][0]
        assert status["status"] == "completed"
        assert [target["path"] for target in status["planned_work"]] == ["pyproject.toml"]

    def test_an_unrecognized_file_alone_reports_not_applicable(self) -> None:
        """Synthetic state only -- the real graph cannot produce this input.

        Every signal ``detect_framework`` reads Deep Agents from is a Python
        module or a Python requirement file, and both are applicable here, from
        the same ``file_cache``. So a Scan that detected Deep Agents always has
        something for this Analyzer to open. The branch is ADR 0006's required
        gate shape rather than an observed case, and issue #70's criterion
        asking for it to be driven through the real graph assumed otherwise.
        """
        result = analyzer.node(make_state({"README.md": "# Ops agent\n"}))

        assert result["findings"] == []
        assert result.get("inspection_ledger", []) == []
        statuses = result["analyzer_status_events"]
        assert len(statuses) == 1
        assert statuses[0]["status"] == "not_applicable"
        assert statuses[0]["reason_code"] is LedgerReason.NO_APPLICABLE_FILES
        assert statuses[0]["planned_work"] == []

    def test_a_not_applicable_status_does_not_make_a_scan_incomplete(self) -> None:
        """Asserted through the projection rather than assumed from the reason code."""
        components = ["README.md"]
        result = analyzer.node(make_state({components[0]: "# Ops agent\n"}))

        completeness, _effective = finalize_ledger(
            {
                "components": components,
                "findings": [],
                "effective_finding_ids": [],
                "inspection_ledger": [],
                "analyzer_status_events": result["analyzer_status_events"],
            }
        )

        assert completeness["limitations"] == []
        assert completeness["is_complete"] is True
        assert completeness["execution_successful"] is True


class TestTheResolutionBoundary:
    """``DA-UNRESOLVED``: the four things this Scan refuses to guess at."""

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            pytest.param(RUNTIME_SKILLS_PY, "Skill source list", id="skill-list"),
            pytest.param(HELPER_BACKEND_PY, "backend is built", id="backend"),
            pytest.param(HELPER_PERMISSIONS_PY, "permission rules", id="permissions"),
            pytest.param(ROUTED_STORE_PY, "/skills/", id="routed-store"),
            pytest.param(RUNTIME_SUBAGENTS_PY, "subagent", id="subagent-list"),
            pytest.param(OPAQUE_SUBAGENT_PY, "subagent", id="opaque-subagent"),
        ],
    )
    def test_each_case_raises_one_finding_that_names_what_was_unresolvable(
        self, source: str, expected: str
    ) -> None:
        result = analyzer.node(make_state({"agent.py": source}))

        assert [finding.rule_id for finding in result["findings"]] == ["DA-UNRESOLVED"]
        assert expected in result["findings"][0].message
        assert result["findings"][0].severity == "MEDIUM"
        assert result["findings"][0].file == "agent.py"

    def test_the_messages_of_these_cases_do_not_all_read_the_same(self) -> None:
        """The criterion the report is judged on: which surface went unexamined.

        Asserted across the set rather than per case, because the failure this
        guards against -- one message reused -- is invisible from inside any
        single one of them. The two subagent shapes are one message deliberately:
        a list assembled at runtime and a definition written as something this
        Scan cannot read leave the same thing unexamined, which subagents were
        defined without Skills of their own.
        """
        messages = {
            _messages(analyzer.node(make_state({"agent.py": source})))[0]
            for source in (
                RUNTIME_SKILLS_PY,
                HELPER_BACKEND_PY,
                HELPER_PERMISSIONS_PY,
                ROUTED_STORE_PY,
                RUNTIME_SUBAGENTS_PY,
                OPAQUE_SUBAGENT_PY,
            )
        }

        assert len(messages) == 5

    def test_the_finding_points_at_the_argument_rather_than_the_call(self) -> None:
        """A multi-line call is the ordinary shape, so the top of it is not enough."""
        result = analyzer.node(make_state({"agent.py": HELPER_PERMISSIONS_PY}))

        lines = HELPER_PERMISSIONS_PY.splitlines()
        assert "rules_for_tenant" in lines[result["findings"][0].start_line - 1]

    def test_the_pattern_catalog_supplies_the_reported_prose(self) -> None:
        """Read from ``pattern_defaults``, not restated in the node."""
        finding = analyzer.node(make_state({"agent.py": RUNTIME_SKILLS_PY}))["findings"][0]

        assert finding.category == "Deep Agents Framework"
        assert finding.pattern == "Unresolvable Host Configuration"
        assert finding.explanation
        assert finding.remediation


class TestWhatResolvesRaisesNothing:
    """The boundary is only worth anything if ordinary code lands on the other side.

    Asserted as the absence of ``DA-UNRESOLVED`` rather than of every Finding:
    a configuration that resolves is exactly the one the writability verdict
    then judges, and several of these are judged writable. Which is the
    partition the two Rules are built on -- what resolved is judged, what did
    not is reported as not having been.
    """

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param(WRITABLE_SKILLS_PY, id="literal-list"),
            pytest.param(MODULE_CONSTANT_PY, id="same-module-constants"),
            pytest.param(NO_ARGUMENTS_PY, id="no-arguments"),
            pytest.param(DENIED_PY, id="denied"),
        ],
    )
    def test_a_resolvable_configuration_raises_no_boundary(self, source: str) -> None:
        assert "DA-UNRESOLVED" not in _rule_ids(analyzer.node(make_state({"agent.py": source})))

    def test_an_absent_argument_is_a_configuration_rather_than_a_silence(self) -> None:
        """No Skills, no rules and the default backend are answers, not boundaries."""
        result = analyzer.node(make_state({"agent.py": NO_ARGUMENTS_PY}))

        assert result["findings"] == []
        assert result["analyzer_status_events"][0]["status"] == "completed"

    def test_a_name_assigned_twice_at_module_level_resolves_to_nothing(self) -> None:
        """Which assignment reaches the call is control flow, so it is a boundary.

        The control is ``MODULE_CONSTANT_PY`` above: the same shape assigned
        once is silent, so this Finding comes from the reassignment rather than
        from same-module constants being unsupported.
        """
        source = MODULE_CONSTANT_PY.replace(
            'BACKEND = FilesystemBackend(root_dir="./app")',
            'BACKEND = FilesystemBackend(root_dir="./app")\nBACKEND = FilesystemBackend(root_dir="./other")',
        )

        assert _messages(analyzer.node(make_state({"agent.py": source}))) == [
            _messages(analyzer.node(make_state({"agent.py": HELPER_BACKEND_PY})))[0]
        ]

    def test_a_route_that_covers_no_skill_source_path_raises_nothing(self) -> None:
        """A store routed somewhere the agent was never given Skills from."""
        source = ROUTED_STORE_PY.replace('skills=["/skills/"]', 'skills=["/vetted/"]')

        assert "DA-UNRESOLVED" not in _rule_ids(analyzer.node(make_state({"agent.py": source})))

    def test_an_unresolved_skill_list_is_not_also_reported_as_an_opaque_route(self) -> None:
        """One silence, described once, in the vocabulary that fits it."""
        source = ROUTED_STORE_PY.replace(
            'skills=["/skills/"]', "skills=SKILLS_BY_ROLE.get(user_role, [])"
        )

        assert _messages(analyzer.node(make_state({"agent.py": source}))) == [
            _messages(analyzer.node(make_state({"agent.py": RUNTIME_SKILLS_PY})))[0]
        ]

    def test_a_non_python_component_produces_no_finding(self) -> None:
        """A requirement file and a manifest are opened and listed, and nothing more."""
        result = analyzer.node(
            make_state({"pyproject.toml": PYPROJECT, "skills/ops/SKILL.md": SKILL_MD})
        )

        assert result["findings"] == []
        assert len(result["inspection_ledger"]) == 2


def _writable_paths(result: dict[str, Any]) -> list[str]:
    """Which Skill source path each ``DA-SKILL-WRITABLE`` Finding is about.

    Read out of the message rather than tracked separately, because "the Finding
    names the path it is about" is the property the Ticket asks for and a helper
    that read it from anywhere else would go green on a Finding whose prose said
    nothing.
    """
    named = [
        re.search(r"Skill source path (\S+) and nothing denies", finding.message)
        for finding in result["findings"]
        if finding.rule_id == "DA-SKILL-WRITABLE"
    ]
    assert all(match is not None for match in named), "a verdict named no path"
    return [match.group(1) for match in named if match is not None]


def _permissioned(paths: str, mode: str, skills: str = '["/skills/shared/"]') -> str:
    """One agent given *skills*, under a single write rule over *paths*."""
    return f"""from deepagents import FilesystemPermission, create_deep_agent

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills={skills},
    permissions=[
        FilesystemPermission(operations=["write"], paths={paths}, mode="{mode}"),
    ],
)
"""


class TestTheWritabilityVerdict:
    """``DA-SKILL-WRITABLE``: one composed verdict per resolved Skill source path."""

    def test_the_tutorial_default_is_reported_once_per_path(self) -> None:
        """No ``permissions`` and no ``backend`` -- the configuration upstream teaches.

        The single case the whole Deep Agents work exists to report, and the one
        a "not on disk, so not writable" reading of the backend would silence:
        state files are exactly what a self-modifying agent rewrites.
        """
        source = WRITABLE_SKILLS_PY.replace(
            'skills=["/skills/"]', 'skills=["/skills/shared/", "/skills/personal/"]'
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-SKILL-WRITABLE", "DA-SKILL-WRITABLE"]
        assert _writable_paths(result) == ["/skills/shared/", "/skills/personal/"]
        assert all(finding.severity == "MEDIUM" for finding in result["findings"])
        assert all(finding.confidence == 0.9 for finding in result["findings"])

    def test_a_denied_path_produces_nothing(self) -> None:
        result = analyzer.node(make_state({"agent.py": _permissioned('["/skills/**"]', "deny")}))

        assert result["findings"] == []

    def test_a_deny_that_does_not_cover_the_path_leaves_the_verdict_standing(self) -> None:
        """The control for the test above: the rule is what cleared it, not its presence."""
        result = analyzer.node(make_state({"agent.py": _permissioned('["/vetted/**"]', "deny")}))

        assert _writable_paths(result) == ["/skills/shared/"]

    def test_a_rule_governing_another_operation_does_not_end_the_walk(self) -> None:
        source = _permissioned('["/skills/**"]', "deny").replace(
            'operations=["write"]', 'operations=["read"]'
        )

        assert _writable_paths(analyzer.node(make_state({"agent.py": source}))) == [
            "/skills/shared/"
        ]

    def test_the_finding_carries_the_catalog_prose_rather_than_its_own(self) -> None:
        finding = analyzer.node(make_state({"agent.py": WRITABLE_SKILLS_PY}))["findings"][0]

        assert finding.rule_id == "DA-SKILL-WRITABLE"
        assert finding.category == "Deep Agents Framework"
        assert finding.pattern == "Writable Skill Source"
        assert finding.explanation
        assert finding.remediation


class TestRulePrecedence:
    """Rule order is semantics, so the verdict is a walk rather than a search."""

    _SPECIFIC_BEFORE_BROAD = """from deepagents import FilesystemPermission, create_deep_agent

agent = create_deep_agent(
    model="claude-sonnet-5",
    skills=["/skills/shared/", "/skills/personal/"],
    permissions=[
        FilesystemPermission(operations=["write"], paths=["/skills/personal/**"], mode="interrupt"),
        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),
    ],
)
"""

    def test_a_specific_rule_placed_first_decides_the_paths_it_covers(self) -> None:
        """Upstream's own advice, and what a "is there any deny" predicate would miss.

        The broad ``deny`` covers both paths. Only the shared library is denied,
        because the personal directory is decided by the more specific rule
        written above it.
        """
        result = analyzer.node(make_state({"agent.py": self._SPECIFIC_BEFORE_BROAD}))

        assert _writable_paths(result) == ["/skills/personal/"]

    def test_reordering_the_same_two_rules_reverses_the_verdict(self) -> None:
        """The mutation that separates an ordered walk from an unordered one.

        Same two rules, same two paths, broad ``deny`` first: nothing is
        writable. A predicate blind to order reports both files identically.
        """
        lines = self._SPECIFIC_BEFORE_BROAD.splitlines(keepends=True)
        specific, broad = lines[6], lines[7]
        reordered = "".join(lines[:6] + [broad, specific] + lines[8:])

        assert analyzer.node(make_state({"agent.py": reordered}))["findings"] == []
        assert analyzer.node(make_state({"agent.py": self._SPECIFIC_BEFORE_BROAD}))["findings"]


class TestTheInterruptMitigation:
    """A human in front of the write lowers the verdict; it never raises one."""

    def test_an_interrupt_rule_lowers_the_severity_rather_than_clearing_it(self) -> None:
        result = analyzer.node(
            make_state({"agent.py": _permissioned('["/skills/**"]', "interrupt")})
        )

        assert _rule_ids(result) == ["DA-SKILL-WRITABLE"]
        assert result["findings"][0].severity == "LOW"

    def test_the_unmitigated_control_is_the_same_configuration_at_medium(self) -> None:
        """So the LOW above comes from the mitigation rather than from the Rule."""
        result = analyzer.node(make_state({"agent.py": WRITABLE_SKILLS_PY}))

        assert result["findings"][0].severity == "MEDIUM"

    def test_an_interrupt_gate_over_both_write_tools_mitigates_every_path(self) -> None:
        """Wider than a rule's ``mode``, because upstream says it is."""
        source = WRITABLE_SKILLS_PY.replace(
            'skills=["/skills/"]',
            'skills=["/skills/shared/", "/skills/personal/"], '
            'interrupt_on={"write_file": True, "edit_file": True}',
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert [finding.severity for finding in result["findings"]] == ["LOW", "LOW"]

    @pytest.mark.parametrize(
        "gate",
        [
            pytest.param('{"write_file": True}', id="one-tool-only"),
            pytest.param('{"write_file": True, "edit_file": False}', id="turned-off"),
            pytest.param("gate_for_tenant()", id="unresolvable"),
        ],
    )
    def test_a_gate_that_is_not_over_both_write_tools_mitigates_nothing(self, gate: str) -> None:
        """Half a gate is an agent still editing a Skill file with nobody asked.

        The unresolvable case is deliberately the same answer rather than a
        fifth boundary: an unconfirmed mitigation left in place would lower a
        real Finding's severity on evidence nobody has.
        """
        source = WRITABLE_SKILLS_PY.replace(
            'skills=["/skills/"]', f'skills=["/skills/"], interrupt_on={gate}'
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-SKILL-WRITABLE"]
        assert result["findings"][0].severity == "MEDIUM"

    def test_a_gate_never_produces_a_finding_of_its_own(self) -> None:
        """On a fully denied application, adding a gate adds nothing."""
        source = _permissioned('["/skills/**"]', "deny").replace(
            'model="claude-sonnet-5",',
            'model="claude-sonnet-5",\n    interrupt_on={"write_file": True, "edit_file": True},',
        )

        assert analyzer.node(make_state({"agent.py": source}))["findings"] == []


class TestWhatTheVerdictRefusesToDecide:
    """Everything unresolvable reaches the boundary Rule instead of a verdict."""

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param(RUNTIME_SKILLS_PY, id="skill-list"),
            pytest.param(HELPER_BACKEND_PY, id="backend"),
            pytest.param(HELPER_PERMISSIONS_PY, id="permissions"),
            pytest.param(ROUTED_STORE_PY, id="routed-store"),
        ],
    )
    def test_a_boundary_case_produces_no_writability_verdict(self, source: str) -> None:
        assert _rule_ids(analyzer.node(make_state({"agent.py": source}))) == ["DA-UNRESOLVED"]

    def test_only_the_routed_path_loses_its_verdict(self) -> None:
        """The control for the routed-store case: the route is what cleared it.

        A second Skill source the route does not cover is still judged, so the
        silence above is the route rather than a call the verdict skipped whole.
        """
        source = ROUTED_STORE_PY.replace('skills=["/skills/"]', 'skills=["/skills/", "/personal/"]')
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-UNRESOLVED", "DA-SKILL-WRITABLE"]
        assert _writable_paths(result) == ["/personal/"]

    @pytest.mark.parametrize(
        "rule",
        [
            pytest.param(
                'FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="allow")',
                id="unknown-mode",
            ),
            pytest.param(
                'FilesystemPermission(operations=["write"], paths=["/skills/**"])',
                id="no-mode",
            ),
            pytest.param(
                'FilesystemPermission(operations="write", paths=["/skills/**"], mode="deny")',
                id="operations-not-a-list",
            ),
            pytest.param(
                'FilesystemPermission(operations=["write"], paths=42, mode="deny")',
                id="paths-not-a-list",
            ),
        ],
    )
    def test_a_rule_written_in_an_unreadable_shape_reaches_the_boundary(self, rule: str) -> None:
        """A rule this Scan cannot read leaves the ordered walk undecided.

        Undecided for **every** path, not only the ones the rule names: the part
        that could not be read may be the ``paths`` that would have decided them.
        """
        source = _permissioned('["/skills/**"]', "deny").replace(
            'FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny")', rule
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-UNRESOLVED"]
        assert "does not recognize" in result["findings"][0].message


class TestPathCoverage:
    """Glob matching, and the near-misses it deliberately does not forgive."""

    @pytest.mark.parametrize(
        ("pattern", "skill", "denied"),
        [
            pytest.param('["/skills/**"]', '["/skills/shared/"]', True, id="glob-covers-below"),
            pytest.param('["/skills/shared/"]', '["/skills/shared/"]', True, id="exact"),
            pytest.param('["/skills/**"]', '["/other/skills/x/"]', False, id="not-a-substring"),
            pytest.param('["/skills/shared"]', '["/skills/shared/"]', False, id="trailing-slash"),
            pytest.param('["/skills/**"]', '["skills/shared/"]', False, id="relative-path"),
            pytest.param('["/SKILLS/**"]', '["/skills/shared/"]', False, id="case-differs"),
            # A single `*` stops at a separator and `**` crosses one. This is the
            # distinction `fnmatch` cannot make -- its `*` crosses `/` -- and
            # reading a rule the wide way would clear a Finding on a path the
            # rule never named.
            pytest.param('["/skills/*"]', '["/skills/shared/"]', False, id="star-stops-at-slash"),
            pytest.param('["/skills/*/"]', '["/skills/shared/"]', True, id="star-within-a-segment"),
            pytest.param(
                '["/skills/*/"]', '["/skills/shared/team/"]', False, id="star-spans-one-segment"
            ),
            pytest.param(
                '["/skills/**"]', '["/skills/shared/team/"]', True, id="globstar-crosses-slashes"
            ),
            pytest.param('["/skills/?hared/"]', '["/skills/shared/"]', True, id="single-character"),
            pytest.param('["/skills/?/"]', '["/skills/shared/"]', False, id="single-is-one-only"),
        ],
    )
    def test_whether_a_deny_rule_covers_a_skill_source_path(
        self, pattern: str, skill: str, denied: bool
    ) -> None:
        result = analyzer.node(
            make_state({"agent.py": _permissioned(pattern, "deny", skills=skill)})
        )

        assert (result["findings"] == []) is denied


class TestAnUnparseablePythonFile:
    """A file that does not parse was not inspected, however clean the report looks."""

    def test_it_is_skipped_with_the_syntax_error_reason(self) -> None:
        result = analyzer.node(make_state({"agent.py": UNPARSEABLE_PY}))

        events = result["inspection_ledger"]
        assert [event["outcome"] for event in events] == [LedgerOutcome.SKIPPED]
        assert events[0]["reason_code"] is LedgerReason.SYNTAX_ERROR

    def test_the_status_is_derived_rather_than_written_here(self) -> None:
        """``degraded`` is reserved to the ledger's own cascade.

        The control for that is the sibling test above: the same Analyzer
        reports ``completed`` when nothing is skipped, so this status is coming
        from the events rather than being a constant.
        """
        result = analyzer.node(
            make_state({"agent.py": UNPARSEABLE_PY, "pyproject.toml": PYPROJECT})
        )

        assert result["analyzer_status_events"][0]["status"] == "degraded"

    def test_a_parseable_file_alongside_it_is_still_opened(self) -> None:
        result = analyzer.node(
            make_state({"agent.py": UNPARSEABLE_PY, "worker.py": WRITABLE_SKILLS_PY})
        )

        outcomes = {event["path"]: event["outcome"] for event in result["inspection_ledger"]}
        assert outcomes == {
            "agent.py": LedgerOutcome.SKIPPED,
            "worker.py": LedgerOutcome.COMPLETED,
        }


class TestTheLedgerContract:
    """Planned work and emitted rows are the same set, keyed the same way."""

    def test_planned_work_matches_the_emitted_rows(self) -> None:
        result = analyzer.node(
            make_state({"agent.py": WRITABLE_SKILLS_PY, "pyproject.toml": PYPROJECT})
        )

        status = result["analyzer_status_events"][0]
        assert [target["work_id"] for target in status["planned_work"]] == [
            event["work_id"] for event in result["inspection_ledger"]
        ]
        assert [target["work_id"] for target in status["planned_work"]] == [
            inspection_work_id(analyzer.ANALYZER_ID, path, None, None)
            for path in ("agent.py", "pyproject.toml")
        ]

    def test_a_correctly_permissioned_configuration_emits_no_finding_at_all(self) -> None:
        """It resolves, so no boundary; every path is denied, so no verdict."""
        result = analyzer.node(
            make_state(
                {
                    "agent.py": DENIED_PY,
                    "pyproject.toml": PYPROJECT,
                    "skills/ops/SKILL.md": SKILL_MD,
                }
            )
        )

        assert result["findings"] == []
        assert all(event["emitted_finding_ids"] == [] for event in result["inspection_ledger"])

    def test_a_finding_is_accounted_for_on_the_row_of_the_file_it_came_from(self) -> None:
        result = analyzer.node(
            make_state({"agent.py": RUNTIME_SKILLS_PY, "pyproject.toml": PYPROJECT})
        )

        emitted = {
            event["path"]: event["emitted_finding_ids"] for event in result["inspection_ledger"]
        }
        assert emitted["pyproject.toml"] == []
        assert emitted["agent.py"] == [finding.finding_id for finding in result["findings"]]
        assert len(emitted["agent.py"]) == 1


class TestTheShadowingVerdict:
    """``DA-SHADOW`` fires on a confirmed collision and on nothing weaker.

    Every input below carries a ``deny`` covering both sources, so what these
    tests read is this Rule rather than ``DA-SKILL-WRITABLE`` arriving with it.
    That the two are independent is asserted once, at the end, rather than being
    assumed by every case.
    """

    def test_one_name_in_two_mapped_sources_is_reported_once(self) -> None:
        result = analyzer.node(
            make_state({"agent.py": SHADOWED_PY, **COLLIDING_MANIFESTS}),
        )

        assert _rule_ids(result) == ["DA-SHADOW"]
        assert result["findings"][0].severity == "HIGH"

    def test_the_finding_names_both_sources_and_the_manifest_the_agent_loads(self) -> None:
        """A Finding that named one source would leave the reviewer to find the other."""
        message = _messages(
            analyzer.node(make_state({"agent.py": SHADOWED_PY, **COLLIDING_MANIFESTS}))
        )[0]

        assert "/skills/shared/" in message
        assert "/skills/personal/" in message
        assert "library/skills/personal/ticket-triage/SKILL.md" in message

    def test_two_sources_that_provide_different_skills_raise_nothing(self) -> None:
        """Layering is what upstream recommends; the Rule fires on the names, not the list."""
        result = analyzer.node(make_state({"agent.py": SHADOWED_PY, **LAYERED_MANIFESTS}))

        assert result["findings"] == []

    def test_the_last_source_wins_over_every_earlier_one(self) -> None:
        """Three sources, one name: two Findings, and both name the final source.

        One Finding per *shadowed* source rather than per name, so a reviewer can
        accept one substitution without also accepting the other -- the
        granularity ``DA-SKILL-WRITABLE`` chose for the same reason.
        """
        manifests = {
            "library/skills/shared/triage/SKILL.md": _manifest("ticket-triage"),
            "library/skills/team/triage/SKILL.md": _manifest("ticket-triage"),
            "library/skills/personal/triage/SKILL.md": _manifest("ticket-triage"),
        }
        messages = _messages(analyzer.node(make_state({"agent.py": THREE_SOURCES_PY, **manifests})))

        assert len(messages) == 2
        assert all("later source /skills/personal/" in message for message in messages)
        assert any("Skill source /skills/shared/" in message for message in messages)
        assert any("Skill source /skills/team/" in message for message in messages)

    def test_a_manifest_outside_every_mapped_source_is_not_compared(self) -> None:
        """The mapping is computed through the backend root, never assumed.

        These two manifests hold one name and would collide under any reading
        that matched on the Skill directories alone. Neither is under the root
        this call configures, so neither is read for this verdict -- and both are
        still opened and still reported.
        """
        outside = {
            "elsewhere/skills/shared/triage/SKILL.md": _manifest("ticket-triage"),
            "elsewhere/skills/personal/triage/SKILL.md": _manifest("ticket-triage"),
        }
        result = analyzer.node(make_state({"agent.py": SHADOWED_PY, **outside}))

        assert result["findings"] == []
        assert [event["path"] for event in result["inspection_ledger"]] == [
            "agent.py",
            *sorted(outside),
        ]


class TestWhatCannotBeMapped:
    """Only one of the Ticket's three unmappable cases is a boundary.

    ADR 0008 §3's amendment, asserted rather than only written down. A
    ``StoreBackend`` and the default ``StateBackend`` are configurations this
    Scan read successfully -- what it read is that the Skill files are not on
    disk -- so they raise nothing, and reporting them would put a Finding on the
    shape the upstream tutorial teaches. A ``root_dir`` the Scan cannot read is
    resolution stopping, which is §1's boundary exactly.
    """

    @pytest.mark.parametrize("source", [DEFAULT_BACKEND_PY, STORE_BACKEND_PY])
    def test_skill_files_that_are_not_on_disk_raise_nothing(self, source: str) -> None:
        result = analyzer.node(make_state({"agent.py": source, **COLLIDING_MANIFESTS}))

        assert result["findings"] == []

    @pytest.mark.parametrize("source", [DEFAULT_BACKEND_PY, STORE_BACKEND_PY])
    def test_every_manifest_is_still_opened_and_still_given_a_work_item(self, source: str) -> None:
        """ADR 0008 §3's stated price, and the thing that makes the silence readable.

        Without these rows, "no shadowing found" and "the names were never read"
        are the same report.
        """
        result = analyzer.node(
            make_state({"agent.py": source, "pyproject.toml": PYPROJECT, **COLLIDING_MANIFESTS})
        )

        status = result["analyzer_status_events"][0]
        assert status["status"] == "completed"
        assert [target["path"] for target in status["planned_work"]] == [
            "agent.py",
            *sorted(COLLIDING_MANIFESTS),
            "pyproject.toml",
        ]

    def test_a_backend_that_names_no_root_maps_from_the_scan_root(self) -> None:
        """An absent ``root_dir`` is a configuration, and it is read the same way a relative one is.

        Upstream roots it at the process working directory, which no scanned file
        states. Reading it as the Scan root is the limit
        ``host_config.FilesystemRoot`` states for a written relative root, applied
        to the same value written by omission -- so the two do not disagree. It is
        the one place in this Rule where the assumption can produce a Finding
        rather than withhold one, which is why it is pinned rather than left to
        the general case.
        """
        under_scan_root = {
            "skills/shared/triage/SKILL.md": _manifest("ticket-triage"),
            "skills/personal/triage/SKILL.md": _manifest("ticket-triage"),
        }
        result = analyzer.node(make_state({"agent.py": BARE_ROOT_PY, **under_scan_root}))

        assert _rule_ids(result) == ["DA-SHADOW"]

    def test_a_root_the_scan_cannot_read_reaches_the_boundary_rule(self) -> None:
        result = analyzer.node(make_state({"agent.py": UNRESOLVED_ROOT_PY, **COLLIDING_MANIFESTS}))

        assert _rule_ids(result) == ["DA-UNRESOLVED"]
        assert "root directory" in _messages(result)[0]

    def test_an_unreadable_root_does_not_silence_the_writability_verdict(self) -> None:
        """The root is a channel of its own, never a state of the backend's resolution.

        Folding the two together would make ``DA-SKILL-WRITABLE`` -- which asks
        only *which* backend this is -- go quiet on a configuration it can decide.
        """
        source = UNRESOLVED_ROOT_PY.replace(
            '        FilesystemPermission(operations=["write"], paths=["/skills/**"], mode="deny"),\n',
            "",
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert sorted(set(_rule_ids(result))) == ["DA-SKILL-WRITABLE", "DA-UNRESOLVED"]

    def test_an_unresolvable_skill_list_reports_one_silence_rather_than_two(self) -> None:
        """No path resolved, so there is nothing the root could have mapped."""
        source = UNRESOLVED_ROOT_PY.replace(
            'skills=["/skills/shared/", "/skills/personal/"]', "skills=skills_for_tenant()"
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-UNRESOLVED"]
        assert "Skill source list" in _messages(result)[0]


class TestTheSubagentVerdict:
    """``DA-SUBAGENT-SKILLS``: a custom subagent defined without Skills of its own.

    The one Rule of this Analyzer whose claim is correctness rather than
    security, and the only one that reads no path and opens no second file: a
    subagent definition decides the question inside the same call.
    """

    def test_a_custom_subagent_without_its_own_skills_is_reported(self) -> None:
        result = analyzer.node(make_state({"agent.py": _with_subagents(WITHOUT_OWN_SKILLS)}))

        assert _rule_ids(result) == ["DA-SUBAGENT-SKILLS"]
        assert result["findings"][0].severity == "LOW"
        assert result["findings"][0].file == "agent.py"

    def test_a_custom_subagent_that_declares_its_own_skills_produces_nothing(self) -> None:
        """The negative control: the same definition, one key longer."""
        result = analyzer.node(make_state({"agent.py": _with_subagents(WITH_OWN_SKILLS)}))

        assert result["findings"] == []
        assert result["analyzer_status_events"][0]["status"] == "completed"

    def test_the_finding_points_at_the_definition_rather_than_the_call(self) -> None:
        """Two subagents in one list are told apart by their line and nothing else.

        The message names no subagent, because the identifier a definition is
        named by is not a spelling the captured reference documents -- see the
        Analyzer's own record of it. So the line has to carry the whole of which
        one this is.
        """
        source = _with_subagents(f"{WITH_OWN_SKILLS}\n{WITHOUT_OWN_SKILLS}")
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-SUBAGENT-SKILLS"]
        lines = source.splitlines()
        reported = result["findings"][0].start_line
        assert lines[reported - 1].strip() == "{"
        # The second definition, so the one that declares its own Skills is the
        # one the Finding passed over rather than the one it landed on.
        assert reported > next(
            index for index, line in enumerate(lines, start=1) if '"/skills/research/"' in line
        )

    def test_each_subagent_defined_without_skills_is_reported_on_its_own(self) -> None:
        """One Finding per definition, so accepting one does not accept the other."""
        source = _with_subagents(f"{WITHOUT_OWN_SKILLS}\n{WITHOUT_OWN_SKILLS}")
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-SUBAGENT-SKILLS", "DA-SUBAGENT-SKILLS"]
        assert len({finding.start_line for finding in result["findings"]}) == 2

    def test_the_general_purpose_subagent_has_no_definition_and_so_no_finding(self) -> None:
        """Upstream's exclusion needs no code, and this is what says so.

        The general-purpose subagent is built in and inherits the main agent's
        Skills automatically; nothing in the source declares it. So an agent
        given Skills and no ``subagents`` at all -- which is exactly the
        application that has a general-purpose subagent and nothing else --
        raises nothing here, and no name is matched on to arrange that.
        """
        result = analyzer.node(make_state({"agent.py": DENIED_PY}))

        assert result["findings"] == []
        assert "subagents" not in DENIED_PY

    def test_an_absent_subagents_argument_is_a_configuration_rather_than_a_silence(self) -> None:
        """No ``subagents`` is no custom subagents, which is the invariant of every Rule here."""
        assert analyzer.node(make_state({"agent.py": NO_ARGUMENTS_PY}))["findings"] == []

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param(RUNTIME_SUBAGENTS_PY, id="list-built-elsewhere"),
            pytest.param(OPAQUE_SUBAGENT_PY, id="definition-built-elsewhere"),
        ],
    )
    def test_a_subagent_list_this_scan_cannot_read_reaches_the_boundary_rule(
        self, source: str
    ) -> None:
        """Criterion 4 of the Ticket: not a silent pass, and not a guessed verdict."""
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-UNRESOLVED"]
        assert result["findings"][0].severity == "MEDIUM"

    def test_a_definition_holding_a_spread_is_read_as_unresolvable(self) -> None:
        """What a ``**`` contributes is exactly what this Scan will not guess at.

        The control is the same definition without it: a dict whose keys are all
        written is read, and one key of it may well be the ``skills`` this Rule
        looks for.
        """
        source = _with_subagents(WITHOUT_OWN_SKILLS).replace(
            '            "name": "researcher",', "            **defaults(),"
        )
        result = analyzer.node(make_state({"agent.py": source}))

        assert _rule_ids(result) == ["DA-UNRESOLVED"]

    def test_a_subagent_key_that_does_not_resolve_does_not_hide_the_skills_key(self) -> None:
        """Only the keys are read, never the values.

        A definition binds a subagent's tools to objects no Scan can evaluate,
        so requiring the whole dict to resolve would send every realistic
        definition to the boundary and this Rule would never fire.
        """
        source = _with_subagents(
            WITH_OWN_SKILLS.replace(
                '            "skills": ["/skills/research/"],',
                '            "tools": [search_tickets],\n            "skills": ["/skills/research/"],',
            )
        )

        assert analyzer.node(make_state({"agent.py": source}))["findings"] == []

    def test_the_pattern_catalog_supplies_the_reported_prose(self) -> None:
        finding = analyzer.node(make_state({"agent.py": _with_subagents(WITHOUT_OWN_SKILLS)}))[
            "findings"
        ][0]

        assert finding.category == "Deep Agents Framework"
        assert finding.pattern == "Subagent Without Skills"
        assert finding.explanation
        assert finding.remediation


class TestTheDetectionFixtureThroughTheRealGraph:
    """The one committed Deep Agents input, driven end to end.

    Its Behavior Snapshot is the pre-Analyzer baseline this Ticket moves by
    exactly one status row. Reading the row out of a live Scan is what says the
    row is produced rather than merely committed.
    """

    @staticmethod
    def _scan() -> dict[str, Any]:
        from tests.behavior.projection import FIXTURES_DIR, scan_state

        return dict(scan_state(FIXTURES_DIR / "deepagents_detection"))

    def test_the_analyzer_reports_completed_over_the_requirement_file(self) -> None:
        statuses = self._scan()["analysis_completeness"]["analyzer_statuses"]
        mine = [status for status in statuses if status["analyzer_id"] == analyzer.ANALYZER_ID]

        assert len(mine) == 1
        assert mine[0]["status"] == "completed"
        assert mine[0]["planned_work"] == 1
        assert mine[0]["completed"] == 1
        assert mine[0]["skipped"] == 0
        assert mine[0]["failed"] == 0
        assert mine[0]["unaccounted"] == 0

    def test_the_writability_fixtures_are_the_verdict_and_its_negative_control(self) -> None:
        """The two committed applications of issue #72, driven end to end.

        Chosen from a throwaway prototype rather than authored: the scenario
        matrix was scanned through this same entry point first, and these two
        are what it returned. One Finding on the arrangement upstream
        recommends -- a shared source under a rule, a per-user source left open
        -- which is what a per-path verdict means; nothing at all on the
        application whose every source is covered.

        The silence is asserted here as well as pinned by the snapshot because
        this Rule fires on the configuration the tutorial teaches, so the way it
        fails is by firing on configuration that is already right.
        """
        from tests.behavior.projection import FIXTURES_DIR, scan_state

        writable = [
            finding
            for finding in scan_state(FIXTURES_DIR / "deepagents_personal_skills")["findings"]
            if finding.rule_id == analyzer._WRITABLE_RULE_ID
        ]
        assert [finding.severity for finding in writable] == ["MEDIUM"]
        assert "/skills/personal/" in writable[0].message
        assert "/skills/shared/" not in writable[0].message

        assert scan_state(FIXTURES_DIR / "deepagents_denied_skills")["findings"] == []

    def test_the_shadowing_fixtures_are_the_verdict_and_its_negative_control(self) -> None:
        """The two committed applications of issue #73, driven end to end.

        They differ in one thing only -- whether the two layered sources declare
        a Skill of one name -- so what separates them is the confirmation rather
        than the source list, which is what this Rule was scoped to require.

        The silence of the second is asserted here as well as pinned by its
        snapshot because layering is a pattern upstream recommends: the way this
        Rule fails is by firing on an application that took the advice.
        """
        from tests.behavior.projection import FIXTURES_DIR, scan_state

        shadowed = scan_state(FIXTURES_DIR / "deepagents_shadowed_skills")["findings"]
        assert [finding.rule_id for finding in shadowed] == [analyzer._SHADOW_RULE_ID]
        assert shadowed[0].severity == "HIGH"
        assert "ticket-triage" in shadowed[0].message
        assert "library/skills/personal/ticket-triage/SKILL.md" in shadowed[0].message

        assert scan_state(FIXTURES_DIR / "deepagents_layered_skills")["findings"] == []

    def test_it_contributes_no_limitation_and_moves_no_coverage(self) -> None:
        """The behavioral cost of this Ticket is one status row and nothing else."""
        completeness = self._scan()["analysis_completeness"]

        # The disabled semantic Analyzers used to be three limitations here, and
        # were why `is_complete` was False on this fixture. Upstream's `698e2bf`
        # stopped counting an Analyzer the run explicitly turned off as a
        # limitation, so a `--no-llm` scan of a complete fixture now reports no
        # limitation at all. What this test is about is unchanged: a Framework
        # Analyzer that reports `completed` adds nothing to the list, whatever
        # else is or is not on it.
        assert completeness["limitations"] == []
        assert analyzer.ANALYZER_ID not in " ".join(completeness["limitations"])
        assert completeness["is_complete"] is True
        assert completeness["execution_successful"] is True
        assert completeness["coverage_percent"] == 100.0
        assert completeness["fully_inspected_files"] == 1
        assert completeness["entirely_uninspected_files"] == 0
        assert completeness["ledger_exceptions"] == []
