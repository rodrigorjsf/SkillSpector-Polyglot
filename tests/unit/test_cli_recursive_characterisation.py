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

"""What ``--recursive`` does today, recorded so a change to it is visible.

Every other behavior in this project is fenced by the Behavior Snapshot gate.
This flag is not: ``tests/behavior/projection.py`` Scans by calling
``graph.invoke({"skill_path": ...})`` directly and never imports ``cli``, so every
committed snapshot stays green through any change to ``--recursive``, including
one that breaks it outright.

These tests are therefore not assertions that the recorded behavior is *right*.
Several of them record shapes that read as defects and are decisions -- the
two-Skill threshold, the root short-circuit, an ``--output`` that is not valid
SARIF. Issue #39 exists to decide what to do about them; the point of recording
them first is that any of its three paths then becomes reviewable as a diff of
observed behavior rather than an argument about what the flag used to do.

The unit-level companion is ``tests/test_multi_skill.py``, which tests
``detect_skills`` in isolation. What is here is the CLI, driven end to end over
a real directory tree, because the flag's behavior is the composition of
detection with what ``cli`` then chooses to do about it. Two contracts #39 names
are recorded in ``tests/unit/test_cli.py`` rather than here and are not repeated:
the ``--baseline`` rejection (``test_recursive_multi_skill_scan_rejects_shared_baseline``,
and the single-root-skill case that still accepts one) and the per-skill payload
inside the combined JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from skillspector.cli import app

runner = CliRunner()


def _write_skill(directory: Path, name: str) -> Path:
    """A minimal, clean Skill at *directory*. Deliberately raises no Finding."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A skill that does nothing of note.\n---\n\n"
        "Summarise the input.\n",
        encoding="utf-8",
    )
    return directory


def _unwrapped(output: str) -> str:
    """*output* with rich's line wrapping collapsed, so a phrase can be matched.

    The console wraps at its own width, and a fragment asserted here would
    otherwise fail the day a message grows by a word and wraps somewhere new.
    """
    return " ".join(output.split())


class TestWhenRecursiveEngagesAtAll:
    """The detection half, observed through the CLI rather than through the API."""

    def test_two_child_skills_are_scanned_separately(self, tmp_path: Path) -> None:
        """The baseline the other cases in this class are departures from."""
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        output = tmp_path / "combined.json"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(output)],
        )

        assert result.exit_code == 0, result.output
        combined = json.loads(output.read_text(encoding="utf-8"))
        assert [entry["name"] for entry in combined["skills"]] == ["alpha", "beta"]

    def test_one_child_skill_is_below_the_threshold(self, tmp_path: Path) -> None:
        """``detect_skills`` requires two, so a lone child Skill does not engage.

        It falls through to Scanning *the parent* as one anonymous Skill: the
        parent holds no ``SKILL.md``, so the Manifest is ``absent``, the name is
        ``unknown``, and the Risk Score is computed over the child's files as
        though they were the parent's own. Under ``--repo-scan`` the same tree
        reports the one Skill it holds. The fall-through itself is unchanged --
        the threshold is a decision, not a defect.

        What changed with #39 is that it is no longer *silent*. The advisory used
        to be guarded on ``len(detection.skills) == 0``, false here because one
        Skill was found and merely fell short of two, so the case the warning
        exists for was the one case it never covered.
        """
        _write_skill(tmp_path / "only", "only")
        output = tmp_path / "report.json"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(output)],
        )

        assert result.exit_code == 0, result.output
        # A lone child under no conventional root: --repo-scan finds nothing here
        # either, so the advice is to point the scan at the skill itself.
        assert "--recursive found 1 skill(s) immediately below" in _unwrapped(result.output)
        assert "--repo-scan finds none" in _unwrapped(result.output)
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["skill"]["name"] == "unknown"
        assert report["skill"]["manifest_status"] == "absent"

    def test_a_root_skill_short_circuits_every_nested_one(self, tmp_path: Path) -> None:
        """A ``SKILL.md`` at the root wins, and the nested Skills are not reported.

        ``detect_skills`` returns early on the root Skill without ever listing
        the children, so ``--recursive`` behaves as though the flag were absent.
        """
        _write_skill(tmp_path, "root")
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.output)
        assert "Multi-skill directory detected" not in unwrapped
        # The positive half: a negative match alone would pass on any output at
        # all, including an error. The root Skill is what was scanned.
        assert "root" in unwrapped

    def test_only_immediate_children_are_looked_at(self, tmp_path: Path) -> None:
        """Depth one. A monorepo layout finds nothing and Scans the tree as one Skill.

        This is the trap #39 names: ``skills/`` one level down is invisible to
        ``--recursive``, which is precisely the wrong-shaped Scan ``--repo-scan``
        was built to prevent. Discovery is unchanged; the advisory now runs
        ``discover_skills`` and reports what the other flag would have found,
        rather than offering both flags and leaving the choice to the reader.
        """
        _write_skill(tmp_path / "modules" / "billing" / "skills" / "invoice", "invoice")
        _write_skill(tmp_path / "modules" / "shipping" / "skills" / "label", "label")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 0, result.output
        assert "--repo-scan finds 2 skill(s) here" in _unwrapped(result.output)

    def test_a_jvm_build_directory_is_not_skipped(self, tmp_path: Path) -> None:
        """``target/`` holding a ``SKILL.md`` counts toward the threshold.

        ``JVM_BUILD_DIRECTORIES`` is a Repository Scan concept. ``detect_skills``
        walks ``iterdir()`` with no skip set at all, so a Skill copied into build
        output is reported as a Skill -- and, with one real sibling, is what
        pushes the directory over the two-Skill threshold in the first place.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "target", "alpha-copy")
        output = tmp_path / "combined.json"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(output)],
        )

        assert result.exit_code == 0, result.output
        combined = json.loads(output.read_text(encoding="utf-8"))
        assert [entry["path"] for entry in combined["skills"]] == ["alpha", "target"]


class TestTheAdvisoryOnAnOrdinaryScan:
    """``cli`` calls ``detect_skills`` on every directory Scan, only to advise."""

    def test_a_multi_skill_directory_is_pointed_at_recursive(self, tmp_path: Path) -> None:
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.output)
        assert "Found 2 skills" in unwrapped
        # Unchanged by #39: for two or more immediate children, `--recursive` is
        # the flag that fits, so this advisory was already determinate.
        assert "--recursive" in unwrapped

    def test_a_repository_root_is_now_warned_instead_of_scanned_silently(
        self, tmp_path: Path
    ) -> None:
        """The trap, sprung with no flag at all -- and previously not mentioned.

        Pointing an ordinary Scan at a repository root produced the wrong-shaped
        report #29 exists to prevent, and said nothing: ``detect_skills`` finds
        no immediate child Skill, ``is_multi_skill`` is false, and the advisory
        only fired when it was true. Added by #39.
        """
        _write_skill(tmp_path / "modules" / "billing" / "skills" / "invoice", "invoice")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.output)
        assert "--repo-scan finds 1 skill(s) here" in unwrapped
        # No `--recursive` threshold explained on a path where the flag was never
        # passed: the advice is about the layout, not about a flag's internals.
        assert "--recursive" not in unwrapped

    def test_a_tree_holding_no_skill_at_all_says_which_flags_found_nothing(
        self, tmp_path: Path
    ) -> None:
        """The third branch: neither discovery rule matches, so neither is offered.

        Recommending ``--repo-scan`` here would send the reader to a flag that
        reports nothing, which is the failure this advisory exists to prevent in
        the other direction.
        """
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.output)
        assert "No skill was found immediately below either" in unwrapped
        assert "--repo-scan-root" in unwrapped

    def test_a_directory_that_declares_a_skill_is_left_alone(self, tmp_path: Path) -> None:
        """The bound on the new advisory: it must not fire on an ordinary Scan.

        A Skill directory is the overwhelmingly common input. Warning there would
        make the message noise, and noise is how a real warning stops being read.
        """
        _write_skill(tmp_path, "solo")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm"])

        assert result.exit_code == 0, result.output
        assert "--repo-scan" not in _unwrapped(result.output)


class TestTheAdvisoryStaysOutOfTheReport:
    """Which stream the warning goes to, which is not a cosmetic question.

    Without ``--output``, a non-terminal ``--format`` writes the report to
    **stdout**, so ``skillspector scan . -f json | jq`` is a real pipeline and a
    CI step people run. An advisory printed to stdout lands ahead of the report
    and breaks it — and this advisory fires on any directory declaring no
    ``SKILL.md``, which is exactly the input such a pipeline points at.

    Every other assertion in this file reads ``result.output``, which cannot
    distinguish the streams. These read them apart.
    """

    def test_the_json_report_on_stdout_is_still_parseable(self, tmp_path: Path) -> None:
        _write_skill(tmp_path / "modules" / "billing" / "skills" / "invoice", "invoice")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "-f", "json"])

        assert result.exit_code == 0, result.output
        # The assertion that would have caught the regression: parse, don't grep.
        assert json.loads(result.stdout)["skill"]["name"] == "unknown"
        assert "Warning" not in result.stdout

    def test_the_advice_is_on_stderr_where_a_pipe_leaves_it(self, tmp_path: Path) -> None:
        """The other half: routing it away from stdout must not silence it."""
        _write_skill(tmp_path / "modules" / "billing" / "skills" / "invoice", "invoice")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "-f", "json"])

        assert "--repo-scan finds 1 skill(s) here" in _unwrapped(result.stderr)

    def test_the_older_multi_skill_warning_is_on_stderr_too(self, tmp_path: Path) -> None:
        """#99: the sibling advisory, which predates #39 and stayed on stdout.

        Two immediate child Skills and no ``--recursive``: the directory itself
        declares no ``SKILL.md``, so a report *is* written to stdout, and this
        warning used to land ahead of it. ``json.loads`` on ``result.stdout`` is
        the assertion the issue reproduces at the shell with ``| jq``; every
        pre-existing assertion in this file reads ``result.output``, which folds
        the two streams and passes either way.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "-f", "json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["skill"]["name"] == "unknown"
        assert "Warning" not in result.stdout
        # Moved, not silenced.
        assert "Found 2 skills in this directory" in _unwrapped(result.stderr)


class TestTheOutputContracts:
    """What the combined file holds. Two different shapes, chosen by ``--format``."""

    def test_combined_json_carries_the_documented_keys(self, tmp_path: Path) -> None:
        """The shape a CI consumer parses. Renaming any of these breaks them."""
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        output = tmp_path / "combined.json"

        runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(output)],
        )
        combined = json.loads(output.read_text(encoding="utf-8"))

        assert combined["multi_skill"] is True
        assert combined["skill_count"] == 2
        # Containment, not equality: a key added to the summary is not a break
        # for a consumer reading these five, and an exact set would fail on it.
        # Removing or renaming one is the break, and that this catches.
        assert {
            "multi_skill",
            "skill_count",
            "max_risk_score",
            "execution_successful",
            "skills",
        } <= set(combined)
        assert {"name", "path", "risk_score", "risk_severity", "finding_count"} <= set(
            combined["skills"][0]
        )

    def test_sarif_output_is_concatenated_documents_not_one_log(self, tmp_path: Path) -> None:
        """``--format sarif --output`` writes text separators between SARIF bodies.

        The file is therefore **not parseable as SARIF**, which the code says in
        as many words (``cli.py``: "not merged SARIF"). ``--repo-scan`` answers
        the same question with one valid log carrying one run per Skill. Anything
        that makes ``--recursive`` produce valid SARIF is an improvement *and* a
        behavior change for whoever splits this file on the separator today.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        output = tmp_path / "combined.sarif"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "sarif", "-o", str(output)],
        )

        assert result.exit_code == 0, result.output
        written = output.read_text(encoding="utf-8")
        assert written.startswith("--- alpha ---")
        assert "\n--- beta ---\n" in written
        try:
            json.loads(written)
        except json.JSONDecodeError:
            pass
        else:  # pragma: no cover - a pass here means the contract changed
            raise AssertionError("the concatenated output parsed as JSON; see issue #39")
