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

"""Contract coverage for the scheduled upstream-drift measurement.

A ``schedule:`` trigger cannot be exercised from a test, so what is pinned here
is the workflow's *text contract* -- the same technique
``test_github_release_workflow.py`` already uses for the release workflow.

Two of these properties are the reason the file exists rather than a matter of
taste. The workflow **must never write to `NVIDIA/SkillSpector`**, which
``.claude/rules/license-compliance.md`` names under "What never happens" -- and
``gh`` on a fork resolves upstream by default, so every call has to be pointed
at the fork explicitly. And it **must never merge**, because issue ``#105``
approved a job that measures and reports; step 4 of
``.claude/skills/upstream-sync/SKILL.md`` exists to force a judgment a scheduled
job must not make.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "upstream-drift.yml"

FORK = "rodrigorjsf/SkillSpector-Polyglot"

# The one `gh` call that is deliberately *not* `--repo`-pinned: the guard step
# asserts what bare `gh` resolves to, so pinning it would assert nothing.
_DELIBERATELY_UNPINNED = "gh repo view --json nameWithOwner"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _command_lines() -> list[str]:
    """Return the workflow's lines with comments and blank lines dropped.

    Every property below is about what the job *runs*. A comment mentioning
    ``gh issue`` is prose, and asserting over it would let a real unpinned call
    hide behind a reassuring sentence -- or fail the suite for a sentence that
    changed nothing.
    """
    lines = []
    for raw in _workflow().splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


class TestItCannotWriteToUpstream:
    """Every write is aimed at the fork, and nothing can point `gh` elsewhere."""

    def test_every_gh_call_names_the_fork_explicitly(self) -> None:
        unpinned = [
            line
            for line in _command_lines()
            if re.search(r"\bgh (issue|api|pr) ", line)
            and '--repo "$TARGET_REPO"' not in line
            and "repos/$TARGET_REPO/" not in line
        ]
        assert unpinned == [], (
            "every `gh` write must name the fork explicitly, because `gh` on a fork "
            "resolves its base repository from git remotes and prefers one named "
            f"`upstream`. Unpinned: {unpinned}"
        )

    def test_the_only_unpinned_gh_call_is_the_guard_that_measures_resolution(self) -> None:
        bare = [
            line
            for line in _command_lines()
            if re.search(r"\bgh repo view\b", line) and '--repo "$TARGET_REPO"' not in line
        ]
        assert len(bare) == 1 and _DELIBERATELY_UNPINNED in bare[0], (
            "the guard step reads what *bare* `gh` resolves to; pinning it would make "
            f"it assert nothing. Found: {bare}"
        )

    def test_it_refuses_to_run_when_a_remote_points_at_upstream(self) -> None:
        workflow = _workflow()
        assert "refusing to continue: a git remote points at upstream" in workflow
        assert "refusing to continue: gh resolved" in workflow

    def test_it_never_adds_upstream_as_a_named_remote(self) -> None:
        assert "git remote add upstream" not in _workflow(), (
            "a remote named `upstream` is one `gh` prefers over GH_REPO; the "
            "measurement fetches by URL precisely so the remote stays absent"
        )

    def test_it_targets_the_fork_and_only_the_fork(self) -> None:
        workflow = _workflow()
        assert f"TARGET_REPO: {FORK}" in workflow
        assert f"GH_REPO: {FORK}" in workflow
        assert f"if: github.repository == '{FORK}'" in workflow


class TestItMeasuresAndNeverMerges:
    """Issue #105 approved a job that reports. The merge stays a human's."""

    def test_it_never_merges_pushes_or_opens_a_pull_request(self) -> None:
        forbidden = [
            line
            for line in _command_lines()
            # `git merge\s` and not `git merge-base`, which is the measurement.
            if re.search(r"\bgit merge\s", line)
            or re.search(r"\bgit (push|commit|cherry-pick|rebase)\b", line)
            or re.search(r"\bgh pr create\b", line)
        ]
        assert forbidden == [], (
            "this workflow measures and reports only -- the judgment in step 4 of "
            f"the sync skill is not a machine's to make. Found: {forbidden}"
        )

    def test_it_holds_no_permission_it_does_not_need(self) -> None:
        # Comment-stripped: the file explains in prose that it grants neither
        # `contents: write` nor `pull-requests: write`, and a raw-text check
        # would fail on the sentence that says so.
        granted = _command_lines()
        assert "contents: read" in granted
        assert "issues: write" in granted
        assert "contents: write" not in granted
        assert "pull-requests: write" not in granted

    def test_it_runs_the_measurement_the_skill_defines(self) -> None:
        """Step 1 of the skill is the authority; this reuses it rather than a second spelling."""
        workflow = _workflow()
        assert "git merge-base upstream/main origin/main" in workflow
        assert "rev-list --count" in workflow
        assert "comm -12" in workflow


class TestItEditsOnlyTheIssueItWrote:
    """A wholesale body replacement must not land on a human's issue."""

    def test_the_marker_is_defined_once_and_used_for_both_write_and_match(self) -> None:
        workflow = _workflow()
        assert 'ISSUE_MARKER: "<!-- upstream-drift-report -->"' in workflow
        assert '"$ISSUE_MARKER"' in workflow
        # Two literals could drift apart; one variable cannot.
        assert workflow.count("<!-- upstream-drift-report -->") == 1

    def test_it_selects_the_existing_issue_by_marker_not_by_title(self) -> None:
        workflow = _workflow()
        assert "--json number,body" in workflow
        assert 'select((.body // "") | startswith($marker))' in workflow
        assert "select(.title | startswith(" not in workflow, (
            "matching on a title prefix would let this job overwrite any issue a "
            "human filed under the same wording, every week"
        )

    def test_untrusted_text_never_reaches_a_shell_string_or_a_jq_program(self) -> None:
        """Upstream commit subjects and paths reach the body by redirection only."""
        workflow = _workflow()
        assert "git log --oneline" in workflow
        assert 'jq -r --arg marker "$ISSUE_MARKER"' in workflow
        interpolated = re.findall(r"\$\{\{\s*github\.event\.", workflow)
        assert interpolated == [], (
            f"`github.event.*` must not be interpolated into a run block: {interpolated}"
        )

    def test_it_converges_on_one_issue_rather_than_filing_weekly(self) -> None:
        workflow = _workflow()
        assert "sort_by(.number) | .[0].number // empty" in workflow
        assert "--state open" in workflow
        assert "--method PATCH" in workflow


class TestItSaysWhatOnlyAHumanCanDo:
    """The design depends on a human twice; both instructions must be reachable."""

    def test_the_issue_body_asks_the_reader_to_close_it(self) -> None:
        """The job never closes; a stale open issue asserts a drift already gone."""
        assert "Close this issue once the sync merges" in _workflow()

    def test_the_sync_skill_step_6_says_to_close_it(self) -> None:
        skill = (REPO_ROOT / ".claude" / "skills" / "upstream-sync" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        step_6 = skill.split("## 6. Close it out", 1)[-1].split("## 7.", 1)[0]
        assert "close the open" in step_6.lower(), (
            "step 6 is where the sync is finished, so it is where the human is told "
            "to close the drift issue -- the workflow only opens and edits"
        )
        assert "Upstream drift:" in step_6

    def test_the_body_directs_the_reader_to_the_user_invoked_skill(self) -> None:
        workflow = _workflow()
        assert "/upstream-sync" in workflow
        assert "Nothing has been merged" in workflow

    def test_a_manual_trigger_exists_because_the_schedule_can_be_disabled(self) -> None:
        """GitHub disables a public repo's schedule after 60 days of inactivity."""
        workflow = _workflow()
        assert "workflow_dispatch:" in workflow
        assert "60 days" in workflow, (
            "the auto-disable withdraws the cadence in exactly the circumstance "
            "#105 describes; the file must say so"
        )


def test_third_party_actions_are_pinned_by_sha() -> None:
    """Matches the discipline `.github/workflows/ci.yml` already applies."""
    unpinned = [
        line
        for line in _command_lines()
        if line.startswith("- uses:") and not re.search(r"@[0-9a-f]{40}\b", line)
    ]
    assert unpinned == [], f"third-party actions must be pinned by commit SHA: {unpinned}"
