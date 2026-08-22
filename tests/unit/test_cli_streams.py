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

"""Which stream every line of ``cli`` goes to: the report on stdout, the rest on stderr.

``--format json`` and ``--format sarif`` write the report to stdout when no
``--output`` is given, so ``skillspector scan . -f json | jq`` is a real pipeline
that CI steps run. Anything else printed there lands *inside* the report and
makes it unparseable — the defect issue #99 records, and the reason #39 added the
stderr console this file exercises across the rest of ``cli``.

Every other CLI test in this directory asserts against ``result.output``, which
folds the two streams and therefore passes whichever stream a line went to. These
read ``result.stdout`` and ``result.stderr`` apart, which is the only way the
distinction is visible at all.

The Multi-Skill Summary table used to be the one line that was a judgement call
rather than a classification, because ``--recursive`` wrote its combined report
**only** to ``--output`` *once the flag engaged* — so with ``-f terminal`` and no
``--output`` the table was the whole of what the Scan produced and
``skillspector scan ./skills --recursive | less`` had it or had nothing. Issue
#114 gave that path the ``print`` fall-back every other one already had, and
``TestTheMultiSkillSummaryIsADigest`` below records what is left: the table is a
digest of a report on every format that has a shape for one, so it goes to stderr
unconditionally, exactly like ``--repo-scan``'s. ``-f sarif`` and ``-f markdown``
are the formats with no such shape — neither has a merged document to print — so
stdout stays empty there, and that half is pinned too. Below the two-skill
threshold the flag never engages: the Scan falls through to an ordinary one,
which prints a report to stdout in the requested format, and that counterexample
is pinned here as well.

Any assertion here that matches a *path* inside rich output needs ``_wide_console``
below, and the module-level fixture applies it to everything so that no future one
can be written without it.

Every site in ``cli`` that writes user-facing output is covered *individually and
in both directions* across ``tests/unit/``: moving any one of them to the other
stream — an ``advice`` site to ``console``, a ``console`` site to ``advice``, or
any of the bare ``print()`` calls that put a report on stdout (in
``_write_result``, in the ``--mcp-registry`` branch, at the end of
``_scan_repository``, and in ``_emit_multi_skill_body``) onto ``advice`` — fails
a test on its own, with no other site moving with it. Those are enumerated
deliberately: they are how the report reaches stdout at all, so a claim about
print sites that skipped them would omit the very thing the rule exists to
protect. That was all measured by flipping each site in turn, not assumed; all
but two of them fail a test *in this file*. The two exceptions are
``_advise_on_a_fallthrough``'s
``--repo-scan finds N skill(s) here`` branch — its other two branches *are* pinned
here — and the older ``Found N skills in this directory`` warning in ``scan``,
both pinned by ``TestTheAdvisoryStaysOutOfTheReport`` in
``test_cli_recursive_characterisation.py`` — where #39 put the first and #99 put
the second beside it, next to the ``--recursive`` behaviour they advise about.
Nothing here duplicates that class; a sweep touching either site has to read it.

Both halves of the direction matter. A mutation that reverted a whole function at
a time would prove far less, because one shared assertion would cover for every
site around it — which is why every one of the summary table's prints is asserted
separately rather than the banner standing in for them all. And a "not on stdout"
assertions is satisfied by an empty stdout, which is why
``TestTheReportIsWhatStdoutCarries`` pins what stdout is *for*.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from skillspector import __version__
from skillspector.cli import _combined_skill_entry, _multi_skill_public_record_count, app
from skillspector.models import Finding
from skillspector.nodes.report import reported_findings
from skillspector.sarif_models import validate_sarif_report
from skillspector.suppression import SuppressedFinding, effective_findings

runner = CliRunner()

_MCP_REGISTRY_CAPTURE = (
    Path(__file__).parents[1] / "fixtures" / "mcp_registry" / "mcp_registry.json"
)


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop rich folding a ``tmp_path`` in half, which no assertion here survives.

    A non-terminal rich ``Console`` defaults to 80 columns and folds *inside* an
    over-long unbreakable token, so a long enough temporary directory arrives
    with a newline in the middle of it and ``Report saved to: {path}`` never
    matches. Whether that happens is a property of the machine — a Windows
    ``%TEMP%`` under a long user name reaches it, a short ``/tmp`` does not — so
    without this the assertions below pass or fail by accident.

    ``Console`` reads ``COLUMNS`` from a live reference to ``os.environ``, so
    this reaches the module-level consoles ``cli`` built at import time. It is
    autouse rather than opt-in because the trap is invisible on the machine
    where such an assertion gets written.
    """
    monkeypatch.setenv("COLUMNS", "400")


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
    """*output* with rich's line wrapping collapsed, so a phrase can be matched."""
    return " ".join(output.split())


def _without_timestamps(document: object) -> object:
    """*document* with every ``scanned_at`` replaced, so two Scans can be compared.

    The only field that legitimately differs between two Scans of the same input.
    Dropping the key instead would let a report that stopped emitting one compare
    equal to a report that still does.
    """
    if isinstance(document, dict):
        return {
            key: "<scanned_at>" if key == "scanned_at" else _without_timestamps(value)
            for key, value in document.items()
        }
    if isinstance(document, list):
        return [_without_timestamps(item) for item in document]
    return document


def _explode(*_args: object, **_kwargs: object) -> dict[str, object]:
    """A Scan that raises past the ``FileNotFoundError``/``ValueError`` handlers."""
    raise RuntimeError("the graph came apart")


class TestTheReportIsWhatStdoutCarries:
    """The other half of the rule, which moving a line to stderr cannot violate.

    Every other class here proves a note is *not* on stdout. Those assertions are
    all satisfiable by an empty stdout, so on their own they would let a later
    sweep move the report itself to stderr and stay green. These two pin the
    positive: what stdout is *for*.
    """

    def test_a_terminal_report_with_no_output_file_is_printed_to_stdout(
        self, tmp_path: Path
    ) -> None:
        """The default invocation, and the single most important stdout claim.

        ``skillspector scan ./skill`` with no flags at all: there is no file, so
        the rendered report is the whole product and stdout is where it goes.
        """
        skill = _write_skill(tmp_path / "solo", "solo")

        result = runner.invoke(app, ["scan", str(skill), "--no-llm"])

        assert result.exit_code == 0, result.output
        assert "SkillSpector Security Report" in result.stdout

    def test_the_version_is_the_output_it_was_asked_for(self) -> None:
        """``--version`` prints no report, but what it prints *is* the artifact.

        The one line on ``console`` that is not a scan report, and a deliberate
        exception rather than an oversight: a caller running
        ``skillspector --version`` asked for exactly this string and pipes it.
        """
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0, result.output
        assert f"SkillSpector v{__version__}" in _unwrapped(result.stdout)


class TestAnOrdinaryScan:
    """The single-Skill path, where ``--output`` decides where the report goes."""

    def test_the_saved_to_note_does_not_join_the_report_on_stdout(self, tmp_path: Path) -> None:
        """``--output`` makes the file the report, so stdout carries nothing."""
        skill = _write_skill(tmp_path / "solo", "solo")
        report = tmp_path / "report.json"

        result = runner.invoke(
            app, ["scan", str(skill), "--no-llm", "-f", "json", "-o", str(report)]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Report saved to: {report}" in _unwrapped(result.stderr)

    def test_a_terminal_report_saved_to_a_file_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """The ``-f terminal`` half of the same note, which is a separate line of code.

        ``_write_result`` prints two different ``Report saved to:`` lines, one
        rich-markup and one plain, chosen by the format. The ``-f json`` case
        above reaches only the plain one, so without this the markup one could be
        reverted to stdout with the whole suite green.
        """
        skill = _write_skill(tmp_path / "solo", "solo")
        report = tmp_path / "report.txt"

        result = runner.invoke(app, ["scan", str(skill), "--no-llm", "-o", str(report)])

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Report saved to: {report}" in _unwrapped(result.stderr)
        assert "SkillSpector Security Report" in report.read_text(encoding="utf-8")

    def test_a_verbose_progress_line_stays_off_the_report(self, tmp_path: Path) -> None:
        """``--verbose`` is chrome in every format, including the piped ones."""
        skill = _write_skill(tmp_path / "solo", "solo")

        result = runner.invoke(app, ["scan", str(skill), "--no-llm", "-f", "json", "--verbose"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["skill"]["name"] == "solo"
        assert "Running scan..." in _unwrapped(result.stderr)

    def test_a_directory_declaring_no_skill_still_pipes_its_report(self, tmp_path: Path) -> None:
        """The fall-through advisory's third branch: nothing found by any rule.

        The Scan still runs and still writes its report to stdout, so the advice
        printed ahead of it is exactly the #99 shape — advice about a report that
        is on the stream it would otherwise corrupt.
        """
        (tmp_path / "src").mkdir()

        result = runner.invoke(app, ["scan", str(tmp_path), "--no-llm", "-f", "json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["skill"]["name"] == "unknown"
        assert "No skill was found immediately below either" in _unwrapped(result.stderr)


class TestARepositoryScan:
    """``--repo-scan``, which always prints a report and so never needs its table.

    That the report reaches stdout is the rule; that it is *parseable* is a
    separate property, and one this path has under ``-f sarif`` and — since
    [#116](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/116) —
    under ``-f json`` as well. ``-f markdown`` and ``-f terminal`` keep the
    ``--- path ---`` concatenation, and
    ``test_a_markdown_repository_report_is_still_concatenated`` pins that half so
    neither claim is read as the other.
    """

    def _repository(self, root: Path) -> Path:
        _write_skill(root / "skills" / "one", "one")
        _write_skill(root / "skills" / "two", "two")
        return root

    def test_the_merged_sarif_log_on_stdout_is_still_parseable(self, tmp_path: Path) -> None:
        """The strongest assertion available here: parse, don't grep.

        With no ``--output`` this path writes one merged SARIF log to stdout, one
        run per Skill. A progress line or a summary row printed there would make
        it unparseable exactly as issue #99's advisory did to the JSON report.
        """
        repository = self._repository(tmp_path)

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        assert result.exit_code == 0, result.output
        assert len(json.loads(result.stdout)["runs"]) == 2
        assert "Scanning" not in result.stdout

    def test_a_json_repository_report_is_one_merged_document(self, tmp_path: Path) -> None:
        """This pinned the concatenation until #116 merged it; it now pins the merged shape.

        The stream rule was never the defect — the body *is* the report, so
        stdout is where it belongs. What it was not was a single document: only
        ``-f sarif`` was merged and every other format fell through to the
        per-Skill bodies glued behind ``--- path ---`` separators, which no JSON
        reader accepts.
        [#116](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/116)
        gave this format the merge SARIF already had, and each Skill is
        identified in it by its repository-relative path.
        """
        repository = self._repository(tmp_path)

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        merged = json.loads(result.stdout)
        assert merged["skill_count"] == 2
        assert [entry["path"] for entry in merged["skills"]] == ["skills/one", "skills/two"]
        assert "--- skills/one ---" not in result.stdout

    def test_it_answers_in_the_same_vocabulary_as_the_other_discovery_mode(
        self, tmp_path: Path
    ) -> None:
        """The point of #116: one object shape, told apart by the flag that was run.

        Asserted as an equivalence between the two modes rather than against a
        literal key list copied into this file, so the shape cannot drift in one
        mode while a hand-written expectation keeps agreeing with the other. The
        *values* differ — the paths are relative to different roots and each mode
        reports its own ``scope`` — so it is the keys that are compared.
        """
        repository = self._repository(tmp_path)
        flat = tmp_path / "flat"
        _write_skill(flat / "one", "one")
        _write_skill(flat / "two", "two")
        combined = tmp_path / "recursive.json"

        repo_scan = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )
        recursive = runner.invoke(
            app,
            ["scan", str(flat), "--recursive", "--no-llm", "-f", "json", "-o", str(combined)],
        )

        assert repo_scan.exit_code == 0, repo_scan.output
        assert recursive.exit_code == 0, recursive.output
        merged = json.loads(repo_scan.stdout)
        reference = json.loads(combined.read_text(encoding="utf-8"))
        assert list(merged) == list(reference)
        assert list(merged["analysis_completeness"]) == list(reference["analysis_completeness"])
        assert [sorted(entry) for entry in merged["skills"]] == [
            sorted(entry) for entry in reference["skills"]
        ]

    def test_each_mode_names_its_own_discovery_in_the_scope_field(self, tmp_path: Path) -> None:
        """The one field that says which mode built the object, asserted per mode.

        The shared keys are compared as an equivalence above; ``scope`` is the
        deliberate difference and so cannot be asserted that way. It is also the
        only field that lets a reader tell a Repository Scan's zeroed
        ``public_finding_records`` and ``report_characters`` -- budgets that mode
        does not have -- from a recursive Scan that really consumed none of its
        own. And it is a vocabulary contract: ``CONTEXT.md`` lists "recursive
        scan" among the spellings a Repository Scan is never called, and a
        machine-readable field is prose too.
        """
        repository = self._repository(tmp_path)
        flat = tmp_path / "flat"
        _write_skill(flat / "one", "one")
        _write_skill(flat / "two", "two")

        repo_scan = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )
        recursive = runner.invoke(app, ["scan", str(flat), "--recursive", "--no-llm", "-f", "json"])

        assert repo_scan.exit_code == 0, repo_scan.output
        assert recursive.exit_code == 0, recursive.output
        assert json.loads(repo_scan.stdout)["analysis_completeness"]["scope"] == "repository_skills"
        assert json.loads(recursive.stdout)["analysis_completeness"]["scope"] == "recursive_skills"

    def test_a_raising_child_is_still_counted_as_scanned_in_both_modes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``skills_scanned + skills_omitted == skill_count``, whichever mode was run.

        The recursive mode counts every Skill it *attempted*, so a child whose
        graph invocation raised is scanned-and-failed rather than never reached,
        and its omitted count is the discovery total minus that -- the identity
        holds there by construction. A Repository Scan omits nothing, so counting
        only the children that came back answered ``0 + 0`` against a
        ``skill_count`` of two: the same key meaning two different things in the
        one object both modes are supposed to answer in.

        Asserted with one child raising rather than all of them, because the
        all-raising case makes the two counters disagree by the same amount and
        an equality between the modes would still hold if one of them were
        counting the wrong thing.
        """
        repository = self._repository(tmp_path)
        flat = tmp_path / "flat"
        _write_skill(flat / "one", "one")
        _write_skill(flat / "two", "two")
        calls = {"n": 0}

        def _explode_once(*args: object, **kwargs: object) -> dict[str, object]:
            calls["n"] += 1
            if calls["n"] % 2 == 1:
                raise RuntimeError("the graph came apart")
            return {
                "report_body": '{"skill": {"name": "two"}}',
                "risk_score": 0,
                "risk_severity": "LOW",
                "execution_successful": True,
            }

        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode_once))

        repo_scan = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )
        recursive = runner.invoke(app, ["scan", str(flat), "--recursive", "--no-llm", "-f", "json"])

        assert repo_scan.exit_code == 2
        assert recursive.exit_code == 2
        merged = json.loads(repo_scan.stdout)
        reference = json.loads(recursive.stdout)
        for body in (merged, reference):
            assert body["skills_scanned"] + body["skills_omitted"] == body["skill_count"]
        assert merged["skills_scanned"] == reference["skills_scanned"] == 2

    def test_a_child_that_failed_without_raising_is_still_a_failure_in_the_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The merged object's own claims have to agree with the exit code.

        A Skill can run to completion and report ``execution_successful`` false;
        that raises nothing, so it lands among the scanned results rather than
        among the failures. Reading the aggregate off the failures alone printed
        ``execution_successful: true`` and ``SAFE`` beside an exit code of ``2``
        — a contradiction the concatenated body could not have, because it never
        made an aggregate claim at all. Merging created the claim, so merging
        owes it.
        """
        repository = self._repository(tmp_path)
        failed = {
            "report_body": '{"skill": {"name": "one"}}',
            "risk_score": 0,
            "risk_severity": "LOW",
            "execution_successful": False,
        }
        monkeypatch.setattr(
            "skillspector.cli.graph", SimpleNamespace(invoke=lambda *a, **k: dict(failed))
        )

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 2
        merged = json.loads(result.stdout)
        assert merged["execution_successful"] is False
        assert merged["risk_recommendation"] == "DO_NOT_INSTALL"
        assert merged["analysis_completeness"]["execution_successful"] is False

    def test_a_partially_inspected_child_is_not_rounded_up_to_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A partial inspection must survive the merge, or the Ledger's point is lost.

        An Inspection Ledger is what makes an absence of Findings distinguishable
        from an absence of inspection. A child reporting an incomplete
        `analysis_completeness` raises nothing and exits `0`, so an aggregate that
        counted only exceptions called the repository fully inspected — and a
        reader would take "no findings" for "nothing found" rather than "not all
        of it was read".
        """
        repository = self._repository(tmp_path)
        partial = {
            "report_body": '{"skill": {"name": "one"}}',
            "risk_score": 0,
            "risk_severity": "LOW",
            "execution_successful": True,
            "analysis_completeness": {"is_complete": False, "status": "partial"},
        }
        monkeypatch.setattr(
            "skillspector.cli.graph", SimpleNamespace(invoke=lambda *a, **k: dict(partial))
        )

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        merged = json.loads(result.stdout)
        assert merged["analysis_completeness"]["is_complete"] is False
        assert merged["analysis_completeness"]["partially_inspected_files"] == 2
        assert merged["risk_recommendation"] == "CAUTION"

    def test_a_repository_whose_every_skill_raised_still_merges_to_no_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A discovery *hit* must not borrow the discovery *miss*'s report.

        The miss emits one run holding no result, which reads as "the tool ran
        and found nothing". Here it ran over two Skills and every one of them
        raised, so nothing was inspected at all — and because a Skill only joins
        the scanned results when the graph returns, that reaches the merge with
        an empty list too. A fall-back keyed on *that* emptiness rather than on
        discovery's would put ``executionSuccessful: true`` beside an exit code
        of ``2``, in the one field GitHub code scanning reads.

        The zero-run log this asserts is byte-for-byte what the mode emitted
        before #115 and #116, which is the other half of why it is asserted: a
        discovery hit changed in no format. That the log is *also* refused by
        ``validate_sarif_report`` is a separate, older defect —
        [#138](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/138) —
        whose answer is a run declaring ``executionSuccessful`` **false**, not
        this input dressed up as a success. Rewrite this test when #138 lands;
        do not work around it.
        """
        repository = self._repository(tmp_path)

        def _explode(*args: object, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("the graph came apart")

        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        assert result.exit_code == 2
        assert json.loads(result.stdout)["runs"] == []
        assert "executionSuccessful" not in result.stdout

    def test_a_child_that_failed_without_raising_merges_to_no_run_either(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The same claim on the variant that never raises, which takes another path.

        A Skill can run to completion, report ``execution_successful`` false and
        carry no ``sarif_report``; it lands *among* the scanned results, so the
        merge loop does run and skips it. The list of runs is empty for a
        different reason than above, and a guard on that emptiness would fire
        here too — so both variants are pinned, not one standing in for the
        other.
        """
        repository = self._repository(tmp_path)
        failed = {
            "report_body": '{"skill": {"name": "one"}}',
            "risk_score": 0,
            "risk_severity": "LOW",
            "execution_successful": False,
        }
        monkeypatch.setattr(
            "skillspector.cli.graph", SimpleNamespace(invoke=lambda *a, **k: dict(failed))
        )

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        assert result.exit_code == 2
        assert json.loads(result.stdout)["runs"] == []
        assert "executionSuccessful" not in result.stdout

    def test_a_markdown_repository_report_is_still_concatenated(self, tmp_path: Path) -> None:
        """The half #116 deliberately left alone, pinned so the README cannot rot.

        Merging Markdown is a separate question with no shape in this codebase to
        reuse, so ``-f markdown`` keeps the per-Skill bodies behind
        ``--- path ---`` separators. Without this assertion the claim that #116
        merged *json* would read as a claim that it merged everything.
        """
        repository = self._repository(tmp_path)

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "markdown"]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("--- skills/one ---")
        assert "--- skills/two ---" in result.stdout

    def test_the_merged_json_written_to_a_file_is_the_one_it_prints(self, tmp_path: Path) -> None:
        """``--output`` changed shape with stdout, rather than keeping the old one."""
        repository = self._repository(tmp_path)
        report = tmp_path / "merged.json"

        printed = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )
        saved = runner.invoke(
            app,
            ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json", "-o", str(report)],
        )

        assert saved.exit_code == 0, saved.output
        assert saved.stdout == ""
        on_disk = json.loads(report.read_text(encoding="utf-8"))
        assert list(on_disk) == list(json.loads(printed.stdout))
        assert on_disk["skill_count"] == 2

    def test_the_progress_and_the_digest_are_on_stderr(self, tmp_path: Path) -> None:
        """Moved, not silenced — an operator watching a long Scan still sees it."""
        repository = self._repository(tmp_path)

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        unwrapped = _unwrapped(result.stderr)
        assert "[1/2] Scanning one (skills/one/)" in unwrapped
        assert "one 0 LOW 0" in unwrapped

    def test_the_terminal_reports_are_what_stdout_carries(self, tmp_path: Path) -> None:
        """The measurement the judgement call rests on, pinned so it cannot rot.

        Issue #99 supposed this path's summary table to be the only output a
        ``-f terminal`` user gets, which would have made moving it to stderr a
        regression. It is not: the per-Skill reports are printed to stdout in
        full, so the table is a digest of something the reader already has.
        """
        repository = self._repository(tmp_path)

        result = runner.invoke(app, ["scan", str(repository), "--repo-scan", "--no-llm"])

        assert result.exit_code == 0, result.output
        assert "--- skills/one ---" in result.stdout
        assert "SkillSpector Security Report" in result.stdout

    def test_finding_no_skill_at_all_still_leaves_a_terminal_stdout_empty(
        self, tmp_path: Path
    ) -> None:
        """The one format
        [#115](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/115) left alone.

        This pinned an *empty stdout on every format* until #115 flipped it. A
        rendered report of no Skills is nothing, so ``-f terminal`` still writes
        nothing at all and the warning on stderr is the whole answer — which is
        what it always was for a human reader. Every machine-readable format now
        answers instead; the three tests below are the flipped half.
        """
        (tmp_path / "src").mkdir()

        result = runner.invoke(app, ["scan", str(tmp_path), "--repo-scan", "--no-llm"])

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert "no skill found under" in _unwrapped(result.stderr)

        # The warning is the whole of stderr, not merely present in it. Discovery
        # matching nothing skips the per-skill column heading, and a containment
        # check on the warning cannot see a bare heading printed beneath it.
        assert "Severity" not in _unwrapped(result.stderr)
        assert "Findings" not in _unwrapped(result.stderr)

    def test_finding_no_skill_at_all_still_answers_in_sarif(self, tmp_path: Path) -> None:
        """#115: a discovery miss is a report of no findings, not an absent report.

        The log carries **one** run holding no result rather than no run at all.
        The SARIF 2.1.0 schema allows ``runs`` to be empty, but GitHub code
        scanning documents "an array of one or more runs", so a zero-run log is
        not acceptable to both — and this project's own ``validate_sarif_report``
        refuses one too, which is what this asserts against rather than a
        hand-written key check.
        """
        (tmp_path / "src").mkdir()

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        assert result.exit_code == 0, result.output
        log = json.loads(result.stdout)
        validate_sarif_report(log)
        assert len(log["runs"]) == 1
        assert [finding for run in log["runs"] for finding in run["results"]] == []
        assert "no skill found under" in _unwrapped(result.stderr)
        assert "no skill found under" not in result.stdout

    def test_the_empty_sarif_log_declares_the_schema_a_discovery_hit_declares(
        self, tmp_path: Path
    ) -> None:
        """One scanner, one ``$schema`` — asserted as an equivalence, not a literal.

        ``_merge_repository_sarif`` copies the field off the children it merges,
        so a hit declares whatever ``sarif_models`` built. A miss has no child to
        copy from and used to fall back to an unrelated schemastore URL, which
        made the scanner describe itself two ways depending on whether discovery
        matched. ``validate_sarif_report`` does not read the field, so only this
        catches it — and comparing against the hit rather than against a constant
        keeps the two from drifting apart later.
        """
        empty = tmp_path / "empty"
        (empty / "src").mkdir(parents=True)
        repository = self._repository(tmp_path / "found")

        miss = runner.invoke(app, ["scan", str(empty), "--repo-scan", "--no-llm", "-f", "sarif"])
        hit = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif"]
        )

        assert miss.exit_code == 0, miss.output
        assert hit.exit_code == 0, hit.output
        assert json.loads(miss.stdout)["$schema"] == json.loads(hit.stdout)["$schema"]

    def test_finding_no_skill_at_all_still_answers_in_json(self, tmp_path: Path) -> None:
        """#115: the empty case of the very object a discovery hit emits.

        The shape is #116's merged object with the counts at zero, not a second
        vocabulary invented for the empty case — so a gate parses one shape
        whether or not discovery matched.
        """
        (tmp_path / "src").mkdir()

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        merged = json.loads(result.stdout)
        assert merged["skill_count"] == 0
        assert merged["skills"] == []
        assert merged["max_risk_score"] == 0
        assert merged["execution_successful"] is True
        assert "no skill found under" in _unwrapped(result.stderr)

    def test_the_empty_json_body_is_the_shape_a_discovery_hit_emits(self, tmp_path: Path) -> None:
        """Asserted as an equivalence, so the empty case cannot drift from the hit case."""
        empty = tmp_path / "empty"
        (empty / "src").mkdir(parents=True)
        repository = self._repository(tmp_path / "found")

        miss = runner.invoke(app, ["scan", str(empty), "--repo-scan", "--no-llm", "-f", "json"])
        hit = runner.invoke(app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"])

        assert miss.exit_code == 0, miss.output
        assert hit.exit_code == 0, hit.output
        assert list(json.loads(miss.stdout)) == list(json.loads(hit.stdout))

    def test_finding_no_skill_at_all_still_answers_in_markdown(self, tmp_path: Path) -> None:
        """#115: a report naming the miss, never an empty document.

        The concatenation Markdown emits is empty when there is nothing to
        concatenate, and an empty file cannot be told from a crashed run.
        """
        (tmp_path / "src").mkdir()

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "-f", "markdown"]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("# SkillSpector Repository Scan")
        assert "No skill was found under" in result.stdout
        assert "`--repo-scan-root`" in result.stdout

    def test_an_empty_repository_report_goes_to_the_output_file_instead(
        self, tmp_path: Path
    ) -> None:
        """``--output`` takes the same body, and stdout keeps none of it."""
        (tmp_path / "src").mkdir()
        report = tmp_path / "empty.sarif"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--repo-scan", "--no-llm", "-f", "sarif", "-o", str(report)],
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Report saved to: {report}" in _unwrapped(result.stderr)
        validate_sarif_report(json.loads(report.read_text(encoding="utf-8")))

    def test_a_terminal_discovery_miss_writes_no_output_file_either(self, tmp_path: Path) -> None:
        """The deliberate gap, pinned so a later reader does not "fix" it into an empty file.

        ``-f terminal`` has no report shape for zero Skills, so #115 left it
        writing nothing — with ``--output`` as without. An empty ``report.txt``
        would be indistinguishable from a run that crashed before writing, which
        is the confusion this whole issue exists to remove.
        """
        (tmp_path / "src").mkdir()
        report = tmp_path / "empty.txt"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "-o", str(report)]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert not report.exists()
        assert "Report saved to" not in _unwrapped(result.stderr)

    def test_its_own_saved_to_note_does_not_reach_stdout(self, tmp_path: Path) -> None:
        """``_scan_repository`` writes its own note, separate from ``_write_result``."""
        repository = self._repository(tmp_path)
        report = tmp_path / "merged.sarif"

        result = runner.invoke(
            app,
            ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "sarif", "-o", str(report)],
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Report saved to: {report}" in _unwrapped(result.stderr)
        assert len(json.loads(report.read_text(encoding="utf-8"))["runs"]) == 2


class TestTheMultiSkillSummaryIsADigest:
    """``--recursive``, whose table stopped having to be argued about at #114.

    It used to write its combined report **only** to ``--output``, so with
    ``-f terminal`` and nothing else the table *was* the whole product of the
    Scan and had to sit on stdout to keep ``| less`` worth running.
    [#114](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/114) gave
    the path the ``print`` fall-back every other one already had. A report is
    written on every format that has a shape for one, the table is a digest of it
    like ``--repo-scan``'s, and it goes to stderr with the rest of the notes —
    the conditional that used to pick between the two consoles is gone.
    """

    def test_without_an_output_file_the_table_is_now_a_digest_on_stderr(
        self, tmp_path: Path
    ) -> None:
        """This pinned the table on **stdout** until #114 put a report there instead.

        The table is built from five separate ``print`` calls — banner, column
        headings, rule, one row per Skill, trailing spacer — and each is its own
        site that a sweep could move on its own, so each is asserted separately;
        asserting only the banner and one row would leave three of them free to
        drift back. What changed is the stream, not the content: ``| less`` now
        shows the combined terminal report, of which this is the digest.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.stderr)
        assert "═══ Multi-Skill Summary ═══" in unwrapped
        assert "Skill Score Severity Findings Execution" in unwrapped
        assert "─" * 30 in unwrapped
        assert "alpha 0 LOW 0 successful" in unwrapped
        assert "beta 0 LOW 0 successful" in unwrapped
        assert "═══ Multi-Skill Summary ═══" not in result.stdout

    def test_without_an_output_file_stdout_carries_the_combined_terminal_report(
        self, tmp_path: Path
    ) -> None:
        """What the table gave way to: the report itself, on the stream it belongs to.

        Without this the change above would read as "the table was silenced",
        which would leave ``skillspector scan ./skills --recursive | less``
        showing nothing at all — the exact regression the old stdout placement
        existed to prevent.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("--- alpha ---")
        assert "--- beta ---" in result.stdout
        assert "SkillSpector Security Report" in result.stdout

    def test_the_progress_around_it_is_not(self, tmp_path: Path) -> None:
        """Chrome in every format, so it goes to stderr on every format."""
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert "Multi-skill directory detected" not in result.stdout
        assert "[1/2] Scanning" not in result.stdout
        unwrapped = _unwrapped(result.stderr)
        assert "Multi-skill directory detected: 2 skills found" in unwrapped
        assert "[1/2] Scanning alpha (alpha/)" in unwrapped
        assert "Score: 0/100 (LOW)" in unwrapped

    def test_json_alone_now_puts_the_combined_object_on_stdout(self, tmp_path: Path) -> None:
        """This pinned an **empty** stdout until #114; it now pins the report on it.

        ``-f json`` with no ``--output`` used to write the combined report
        nowhere: every Skill was scanned, the exit code was right, and the format
        flag was accepted and discarded. The table stayed on stderr then because
        a rich table in front of a caller's ``jq`` is #99's defect exactly — and
        it stays there now for the better reason that the object beside it is the
        report.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        combined = json.loads(result.stdout)
        assert combined["multi_skill"] is True
        assert combined["skill_count"] == 2
        assert [entry["name"] for entry in combined["skills"]] == ["alpha", "beta"]
        assert "═══ Multi-Skill Summary ═══" in _unwrapped(result.stderr)
        assert "═══ Multi-Skill Summary ═══" not in result.stdout
        assert "Scanning" not in result.stdout

    def test_the_printed_object_is_the_one_output_would_have_saved(self, tmp_path: Path) -> None:
        """#114 reused the existing combined body rather than defining a second shape.

        Compared as documents — only ``scanned_at`` may differ, since the two
        Scans ran at different moments — so a divergence anywhere else in the
        object fails here rather than being discovered by a consumer.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        combined = tmp_path / "combined.json"

        printed = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )
        saved = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(combined)],
        )

        assert printed.exit_code == 0, printed.output
        assert saved.exit_code == 0, saved.output
        assert _without_timestamps(json.loads(printed.stdout)) == _without_timestamps(
            json.loads(combined.read_text(encoding="utf-8"))
        )

    def test_sarif_and_markdown_alone_still_leave_stdout_empty(self, tmp_path: Path) -> None:
        """The half #114 deliberately did not deliver, pinned so the README cannot rot.

        Markdown has no merged document to print: its ``--output`` shape is the
        per-Skill bodies concatenated behind ``--- path ---`` separators, and
        printing that would put unparseable text on the very pipeline the
        fall-back exists to serve. SARIF is a different case — measured, its
        ``--output`` shape *is* one merged log, since upstream's recursive merge
        arrived with the 2.9.6 sync — so only #114's scope keeps it off stdout,
        not the concatenation the issue was written against, and #136 tracks
        printing it. Pinned so that doing so is a deliberate change to this test
        rather than a silent one.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        for machine_readable in ("sarif", "markdown"):
            result = runner.invoke(
                app,
                ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", machine_readable],
            )

            assert result.exit_code == 0, result.output
            assert result.stdout == "", machine_readable
            assert "═══ Multi-Skill Summary ═══" in _unwrapped(result.stderr)

    def test_with_an_output_file_the_file_is_the_report_and_stdout_is_empty(
        self, tmp_path: Path
    ) -> None:
        """``--output`` makes the table a digest, and a digest goes to stderr."""
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        combined = tmp_path / "combined.json"

        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json", "-o", str(combined)],
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        unwrapped = _unwrapped(result.stderr)
        assert "═══ Multi-Skill Summary ═══" in unwrapped
        assert f"Combined report saved to: {combined}" in unwrapped
        assert json.loads(combined.read_text(encoding="utf-8"))["skill_count"] == 2

    def test_a_concatenated_output_file_says_so_on_stderr_as_well(self, tmp_path: Path) -> None:
        """The non-JSON ``--output`` shape, which is a second line of code.

        ``-f json --output`` builds one merged object; every other format
        concatenates the per-Skill bodies behind ``--- path ---`` separators, and
        announces itself from its own ``print``. Without this the second one could
        be reverted to stdout with the whole suite green.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        combined = tmp_path / "combined.txt"

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-o", str(combined)]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Combined report saved to: {combined}" in _unwrapped(result.stderr)
        assert "--- alpha ---" in combined.read_text(encoding="utf-8")

    def test_a_failing_skill_reports_its_error_off_the_report_stream(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A per-Skill failure is a note about the Scan, not part of its report.

        ``--recursive`` keeps going when one Skill fails, so this line is printed
        in the middle of the run — and since #114 put the combined object back on
        stdout, printing it there would land it *inside* that object, which is
        #99 exactly. The report still reaches stdout, with the failure recorded
        as data rather than as a stray line.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 2
        combined = json.loads(result.stdout)
        assert [entry["error"] for entry in combined["skills"]] == [
            "the graph came apart",
            "the graph came apart",
        ]
        assert "Error: the graph came apart" in _unwrapped(result.stderr)
        assert "Error: the graph came apart" not in result.stdout

    def test_a_failing_skill_gets_its_row_in_the_digest_on_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``ERROR`` row, which is a separate ``print`` from the per-Skill error line.

        No other assertion reaches this site: the digest test above exercises the
        rows of Skills that *succeeded*. Before #114 this row was on stdout under
        ``-f terminal``, because the table was then the whole report and a Skill
        that failed had to appear in it or the report silently omitted a Skill the
        Scan was pointed at. The report is on stdout itself now, so the row went
        to stderr with the rest of the digest — and moving it back on its own
        fails here.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 2
        unwrapped = _unwrapped(result.stderr)
        assert "alpha ERROR" in unwrapped
        assert "beta ERROR" in unwrapped
        assert "ERROR" not in result.stdout
        assert "Error: the graph came apart" in unwrapped

    def test_below_the_threshold_the_flag_never_engages_and_stdout_carries_a_report(
        self, tmp_path: Path
    ) -> None:
        """The counterexample to everything above: one child Skill, so no multi-skill Scan.

        ``--recursive`` needs **two** immediate child Skills. With one it falls
        through to an ordinary Scan, which prints its report to stdout in the
        requested format like any other — so "``--recursive`` writes no report to
        stdout" is true of the engaged flag only, and the README says so in the
        same words its ``--baseline`` row already uses. The advisory naming the
        flag that *would* have found the Skill is printed here, ahead of that
        report, which is why the stream it goes to matters.
        """
        _write_skill(tmp_path / "alpha", "alpha")

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["skill"]["name"] == "unknown"
        assert "--recursive found 1 skill(s) immediately below" in _unwrapped(result.stderr)


class TestAnErrorNeverEntersTheReport:
    """A rejection is a note about the run, and a consumer parses stdout regardless."""

    def test_a_rejected_flag_combination_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """``--mcp-registry`` supports only ``-f json``, so it is a pipeline too."""
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--mcp-registry", "-f", "terminal", "--no-llm"]
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "--mcp-registry currently supports only --format json" in _unwrapped(result.stderr)

    def test_a_repo_scan_pointed_at_a_file_leaves_stdout_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "SKILL.md"
        target.write_text("---\nname: solo\n---\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(target), "--repo-scan", "--no-llm"])

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "--repo-scan needs a directory to search" in _unwrapped(result.stderr)

    def test_an_unreadable_baseline_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """The generic error handler, reached before the graph is ever invoked."""
        skill = _write_skill(tmp_path / "solo", "solo")

        result = runner.invoke(
            app,
            [
                "scan",
                str(skill),
                "--no-llm",
                "-f",
                "json",
                "--baseline",
                str(tmp_path / "absent.yaml"),
            ],
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Error:" in result.stderr

    def test_an_incompatible_mcp_registry_combination_leaves_stdout_empty(
        self, tmp_path: Path
    ) -> None:
        """The other ``--mcp-registry`` rejection, raised before the format check."""
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--mcp-registry", "--recursive", "-f", "json", "--no-llm"]
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "--mcp-registry cannot be combined with" in _unwrapped(result.stderr)

    def test_spec_checks_is_rejected_by_a_registry_scan_rather_than_ignored(
        self, tmp_path: Path
    ) -> None:
        """A Registry Scan runs no Analyzer, so the flag could only do nothing.

        Rejecting says so; accepting it would be the silent no-op issue #115
        records for ``--format`` on another path.
        """
        result = runner.invoke(
            app,
            [
                "scan",
                str(_MCP_REGISTRY_CAPTURE),
                "--mcp-registry",
                "-f",
                "json",
                "--spec-checks",
                "strict",
            ],
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "--spec-checks" in _unwrapped(result.stderr)

    def test_a_registry_scan_still_accepts_the_flags_default(self, tmp_path: Path) -> None:
        """The rejection is of the *mode*, not of a flag every invocation carries."""
        result = runner.invoke(
            app, ["scan", str(_MCP_REGISTRY_CAPTURE), "--mcp-registry", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["mcp_registry"] is True

    def test_refusing_a_shared_baseline_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """``--recursive`` rejects one baseline across Skills, and says so on stderr."""
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--recursive",
                "--no-llm",
                "-f",
                "json",
                "--baseline",
                str(tmp_path / "shared.yaml"),
            ],
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "--baseline is not supported for recursive" in _unwrapped(result.stderr)

    def test_a_malformed_registry_capture_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """``--mcp-registry``'s own handler, which no other rejection reaches.

        The two rejections above are raised before ``scan_registry`` runs, from a
        different ``print``. This one is raised by the source read itself, on the
        one command whose only supported format is the piped ``-f json``.
        """
        capture = tmp_path / "registry.json"
        capture.write_text("not json at all", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(capture), "--mcp-registry", "-f", "json"])

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "MCP Registry source failed" in _unwrapped(result.stderr)

    def test_an_unexpected_failure_without_verbose_leaves_stdout_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The one-line error ``--verbose`` replaces with a traceback — a separate ``print``.

        Both branches of the same handler are notes about the run, and neither is
        pinned by the other: the traceback test below exercises only the
        ``--verbose`` half.
        """
        skill = _write_skill(tmp_path / "solo", "solo")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(app, ["scan", str(skill), "--no-llm", "-f", "json"])

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Error: the graph came apart" in _unwrapped(result.stderr)

    def test_a_verbose_traceback_is_not_part_of_the_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``--verbose`` swaps the one-line error for a full traceback; both are notes.

        ``cli`` prints a traceback rather than a message at three sites, one per
        driver, and each needs reaching separately — the only route to any of
        them is a Scan raising something other than ``FileNotFoundError`` or
        ``ValueError``. This is the ordinary single-Skill one.
        """
        skill = _write_skill(tmp_path / "solo", "solo")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(app, ["scan", str(skill), "--no-llm", "-f", "json", "--verbose"])

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Traceback" in result.stderr
        assert "the graph came apart" in _unwrapped(result.stderr)

    def test_a_verbose_traceback_from_a_repository_scan_is_not_either(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second site. Here the Scan survives the failure and still prints a report.

        ``--repo-scan`` keeps going so one bad Skill does not lose the others, so
        stdout is not empty here — it carries the (empty) merged report. What it
        must not carry is the traceback.
        """
        _write_skill(tmp_path / "skills" / "one", "one")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "--verbose"])

        assert result.exit_code == 2
        assert "Traceback" not in result.stdout
        assert "the graph came apart" not in result.stdout
        assert "Traceback" in result.stderr


class TestTheSpecConformanceAdvisory:
    """``--spec-checks advisory`` prints one line about the report, beside it.

    The count of findings that were reported without being scored is a note
    *about* the scan — the report already carries every one of them — so it goes
    to stderr, where a `-f json` pipeline never sees it.
    """

    @staticmethod
    def _nonconforming(directory: Path) -> Path:
        """A Skill that violates one scored rule and one advisory-only rule.

        The directory name matches the declared one, so ``SPEC-4`` — the other
        scored rule — stays out of the way and the two under test stand alone.
        """
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text(
            "---\nname: weather--report\ndescription: Reports the weather when asked.\n---\n\n"
            "Read [the guide](references/GUIDE.md) first.\n",
            encoding="utf-8",
        )
        return directory

    def test_the_advisory_count_does_not_join_the_report_on_stdout(self, tmp_path: Path) -> None:
        skill = self._nonconforming(tmp_path / "weather--report")

        result = runner.invoke(
            app, ["scan", str(skill), "--no-llm", "-f", "json", "--spec-checks", "advisory"]
        )

        assert result.exit_code in (0, 1), result.output
        issues = json.loads(result.stdout)["issues"]
        assert {issue["id"] for issue in issues} == {"SPEC-6", "SPEC-15"}
        assert "advisory finding(s) reported without affecting" in _unwrapped(result.stderr)

    def test_strict_prints_no_such_note(self, tmp_path: Path) -> None:
        """In ``strict`` every finding is in the score, so there is nothing to say."""
        skill = self._nonconforming(tmp_path / "weather--report")

        result = runner.invoke(
            app, ["scan", str(skill), "--no-llm", "-f", "json", "--spec-checks", "strict"]
        )

        assert result.exit_code in (0, 1), result.output
        assert "advisory finding(s)" not in _unwrapped(result.stderr)

    def test_the_default_scan_says_nothing_about_conformance(self, tmp_path: Path) -> None:
        """With the flag absent the feature is not there at all, on either stream."""
        skill = self._nonconforming(tmp_path / "weather--report")

        result = runner.invoke(app, ["scan", str(skill), "--no-llm", "-f", "json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["issues"] == []
        assert "advisory finding(s)" not in _unwrapped(result.stderr)

    def test_a_baseline_that_accepts_every_conformance_finding_silences_the_note(
        self, tmp_path: Path
    ) -> None:
        """The count is what the report carries, not what the scan computed.

        A Baseline is applied inside ``report``, downstream of every findings key
        the CLI can read, so counting those keys announced on stderr findings
        that stdout did not contain -- and a Baseline that accepts everything is
        the steady state of a Baseline, not an edge case.
        """
        skill = self._nonconforming(tmp_path / "weather--report")
        baseline_file = tmp_path / "baseline.yaml"
        written = runner.invoke(
            app,
            [
                "baseline",
                str(skill),
                "-o",
                str(baseline_file),
                "--no-llm",
                "--spec-checks",
                "advisory",
            ],
        )
        assert written.exit_code == 0, written.output

        result = runner.invoke(
            app,
            [
                "scan",
                str(skill),
                "--no-llm",
                "-f",
                "json",
                "--spec-checks",
                "advisory",
                "--baseline",
                str(baseline_file),
            ],
        )

        assert result.exit_code in (0, 1), result.output
        assert json.loads(result.stdout)["issues"] == []
        assert "advisory finding(s)" not in _unwrapped(result.stderr)

    def test_a_baseline_that_accepts_only_the_scored_finding_leaves_the_note(
        self, tmp_path: Path
    ) -> None:
        """The other direction: a partial Baseline still leaves something to report.

        Without it, "no note" would pass for a count that had simply been turned
        off, rather than for one measured against what the report carries.
        """
        skill = self._nonconforming(tmp_path / "weather--report")
        baseline_file = tmp_path / "baseline.yaml"
        written = runner.invoke(
            app,
            [
                "baseline",
                str(skill),
                "-o",
                str(baseline_file),
                "--no-llm",
                "--spec-checks",
                "advisory",
            ],
        )
        assert written.exit_code == 0, written.output
        document = yaml.safe_load(baseline_file.read_text(encoding="utf-8"))
        document["fingerprints"] = [
            entry for entry in document["fingerprints"] if entry["rule_id"] != "SPEC-6"
        ]
        baseline_file.write_text(yaml.safe_dump(document), encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "scan",
                str(skill),
                "--no-llm",
                "-f",
                "json",
                "--spec-checks",
                "advisory",
                "--baseline",
                str(baseline_file),
            ],
        )

        assert result.exit_code in (0, 1), result.output
        assert {issue["id"] for issue in json.loads(result.stdout)["issues"]} == {"SPEC-6"}
        assert "1 advisory finding(s) reported without affecting" in _unwrapped(result.stderr)

    def test_a_repository_scan_reports_its_advisory_total(self, tmp_path: Path) -> None:
        """The invocation the README recommends, which used to print no sign of the mode.

        ``--repo-scan`` invokes the graph once per discovered Skill, so the note
        is a total over the run rather than one line per Skill -- and it is a
        note about the Scan, so it stays off the stdout this path always writes a
        report to.
        """
        self._nonconforming(tmp_path / "skills" / "weather--report")

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--repo-scan", "--no-llm", "--spec-checks", "advisory"]
        )

        assert result.exit_code in (0, 1), result.output
        assert "advisory finding(s) reported without affecting" in _unwrapped(result.stderr)
        assert "advisory finding(s)" not in _unwrapped(result.stdout)

    def test_a_recursive_scan_reports_its_advisory_total(self, tmp_path: Path) -> None:
        """``--recursive`` needs two Skills to engage, and the note is one total for both.

        ``advice`` on this path as on every other: since #114 the combined report
        reaches stdout here, so a note printed there would land inside it.
        """
        self._nonconforming(tmp_path / "weather--report")
        self._nonconforming(tmp_path / "tide--report").joinpath("SKILL.md").write_text(
            "---\nname: tide--report\ndescription: Reports the tide when asked.\n---\n\n"
            "Read [the guide](references/GUIDE.md) first.\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "--spec-checks", "advisory"]
        )

        assert result.exit_code in (0, 1), result.output
        assert "advisory finding(s) reported without affecting" in _unwrapped(result.stderr)
        assert "advisory finding(s)" not in _unwrapped(result.stdout)


class TestTheSpecChecksFlagAddsNoAdvice:
    """``--spec-checks`` needs no pairing advice, because it no longer degrades.

    It used to warn that ``--spec-checks`` without ``--no-llm`` reported almost
    nothing: every rule of the catalogue is MEDIUM or LOW, and
    ``LLMMetaAnalyzer.apply_filter`` kept a MEDIUM or LOW finding only when the
    model confirmed it -- which it was never asked to do for a SPEC id. That made
    a scoring feature work only in a mode that turns off the semantic analysis the
    rest of the tool exists for.

    ``meta_analyzer`` now exempts the catalogue from both of its filter paths, so
    the degradation is gone and so is the advice. The stream contract is what is
    asserted here; that the findings actually survive the filter is asserted at
    the filter, in ``tests/nodes/test_meta_analyzer.py``.
    """

    def test_the_llm_path_prints_no_pairing_advice(self, tmp_path: Path) -> None:
        """``--repo-scan`` on a file exits 2 at once, which keeps this off a provider."""
        target = tmp_path / "SKILL.md"
        target.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")

        result = runner.invoke(
            app, ["scan", str(target), "--repo-scan", "--spec-checks", "advisory"]
        )

        assert result.exit_code == 2, result.output
        assert "--spec-checks was asked for" not in _unwrapped(result.stderr)
        assert "--no-llm" not in _unwrapped(result.stderr)

    def test_strict_prints_no_pairing_advice_either(self, tmp_path: Path) -> None:
        target = tmp_path / "SKILL.md"
        target.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(target), "--repo-scan", "--spec-checks", "strict"])

        assert "--spec-checks was asked for" not in _unwrapped(result.stderr)

    def test_no_llm_is_quiet(self, tmp_path: Path) -> None:
        skill = TestTheSpecConformanceAdvisory._nonconforming(tmp_path / "weather--report")

        result = runner.invoke(
            app, ["scan", str(skill), "--no-llm", "-f", "json", "--spec-checks", "advisory"]
        )

        assert result.exit_code in (0, 1), result.output
        assert "--spec-checks was asked for" not in _unwrapped(result.stderr)

    def test_the_default_scan_is_quiet(self, tmp_path: Path) -> None:
        """The flag's absence adds nothing to either stream, LLM stage on or not."""
        target = tmp_path / "SKILL.md"
        target.write_text("---\nname: x\ndescription: y\n---\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(target), "--repo-scan"])

        assert result.exit_code == 2, result.output
        assert "--spec-checks was asked for" not in _unwrapped(result.stderr)

    def test_the_baseline_command_is_quiet_too(self, tmp_path: Path) -> None:
        """``baseline`` takes the same flag and writes a file a team commits.

        The graph is stubbed out, which is what keeps this off a provider.
        """
        skill = TestTheSpecConformanceAdvisory._nonconforming(tmp_path / "weather--report")
        import skillspector.cli as cli_module

        original = cli_module.graph
        cli_module.graph = SimpleNamespace(invoke=_explode)
        try:
            result = runner.invoke(
                app,
                [
                    "baseline",
                    str(skill),
                    "-o",
                    str(tmp_path / "b.yaml"),
                    "--spec-checks",
                    "advisory",
                ],
            )
        finally:
            cli_module.graph = original

        assert "--spec-checks was asked for" not in _unwrapped(result.stderr)
        assert "--spec-checks was asked for" not in _unwrapped(result.stdout)


class TestTheRegistryScan:
    """``--mcp-registry``, which supports only ``-f json`` and so is a pipeline by design."""

    def test_the_report_is_the_only_thing_on_stdout(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(_MCP_REGISTRY_CAPTURE), "--mcp-registry", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["mcp_registry"] is True

    def test_the_saved_to_note_does_not_take_its_place(self, tmp_path: Path) -> None:
        """This path writes its own note, not ``_write_result``'s."""
        report = tmp_path / "registry.json"

        result = runner.invoke(
            app,
            ["scan", str(_MCP_REGISTRY_CAPTURE), "--mcp-registry", "-f", "json", "-o", str(report)],
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert f"Report saved to: {report}" in _unwrapped(result.stderr)


class TestTheMcpServer:
    """``skillspector mcp``, where stdout is not a report but a protocol channel.

    The stdio transport speaks JSON-RPC on stdout, so a stray line there is worse
    than an unparseable report — it corrupts the session before it starts. The
    one line this command can print before handing stdout over is the missing-extra
    error, and it goes to stderr like every other note.
    """

    def test_the_missing_extra_error_never_touches_the_protocol_channel(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_import = builtins.__import__

        def _without_the_extra(name: str, *args: object, **kwargs: object) -> object:
            if name == "skillspector.mcp_server":
                raise ModuleNotFoundError("No module named 'mcp'")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", _without_the_extra)

        result = runner.invoke(app, ["mcp"])

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "No module named 'mcp'" in _unwrapped(result.stderr)


class TestTheBaselineCommand:
    """``baseline`` produces a *file*, never a report, so stdout is empty throughout.

    Nothing this command prints is ever the artifact — the artifact is the
    baseline file named by ``--output``. Every line therefore goes to stderr, and
    stdout stays clean for a caller that pipes the command inside a larger
    script.
    """

    def test_the_written_note_is_not_a_report_on_stdout(self, tmp_path: Path) -> None:
        skill = _write_skill(tmp_path / "solo", "solo")
        baseline_file = tmp_path / "baseline.yaml"

        result = runner.invoke(app, ["baseline", str(skill), "--no-llm", "-o", str(baseline_file)])

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert "Wrote baseline with" in _unwrapped(result.stderr)
        assert baseline_file.exists()

    def test_the_verbose_progress_line_is_a_note_too(self, tmp_path: Path) -> None:
        skill = _write_skill(tmp_path / "solo", "solo")
        baseline_file = tmp_path / "baseline.yaml"

        result = runner.invoke(
            app, ["baseline", str(skill), "--no-llm", "-o", str(baseline_file), "--verbose"]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert "Scanning to build baseline..." in _unwrapped(result.stderr)

    def test_a_failure_leaves_stdout_empty_as_well(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["baseline", str(tmp_path / "absent"), "--no-llm", "-o", str(tmp_path / "b.yaml")],
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Error:" in result.stderr

    def test_an_unexpected_failure_without_verbose_leaves_stdout_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """This command's own one-line error, the branch ``--verbose`` skips."""
        skill = _write_skill(tmp_path / "solo", "solo")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(
            app, ["baseline", str(skill), "--no-llm", "-o", str(tmp_path / "b.yaml")]
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Error: the graph came apart" in _unwrapped(result.stderr)

    def test_a_verbose_traceback_leaves_stdout_empty_as_well(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The third and last traceback site, reached only through this command."""
        skill = _write_skill(tmp_path / "solo", "solo")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(
            app,
            ["baseline", str(skill), "--no-llm", "-o", str(tmp_path / "b.yaml"), "--verbose"],
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Traceback" in result.stderr


class TestASummaryTableAgreesWithItsReport:
    """A "Findings" column that disagrees with the report beside it is a wrong number.

    Three tables count findings without rendering them -- the ``--repo-scan``
    table, the ``--recursive`` table, and the ``--recursive --output`` JSON
    payload -- and all three used to read a findings key straight out of graph
    state through an ``or`` chain, as did ``skillspector baseline`` and the MCP
    tool's verdict payload. Two things are wrong with that reading, and
    ``report.reported_findings`` -- one reader for all five, delegating since
    #130 to ``suppression.effective_findings`` -- is where both are answered:

    - **The suppressed partition is subtracted.** `report` wrote
      ``filtered_findings`` before partitioning it against the baseline until
      upstream ``73dd1f1`` narrowed the key to the kept side, so a baseline that
      accepted every finding still counted them: ``Findings 2`` beside a report
      holding none.
    - **An ``or`` chain treats an empty list as an absent key** and falls back to
      the pre-filter list, so a scan whose findings the meta filter all dropped
      counted the ones it dropped.
    """

    @staticmethod
    def _nonconforming(directory: Path, name: str) -> Path:
        """A Skill raising two conformance findings, one scored and one not."""
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Reports something when asked.\n---\n\n"
            "Read [the guide](references/GUIDE.md) first.\n",
            encoding="utf-8",
        )
        return directory

    def _baseline(self, skill: Path, baseline_file: Path) -> None:
        written = runner.invoke(
            app,
            [
                "baseline",
                str(skill),
                "-o",
                str(baseline_file),
                "--no-llm",
                "--spec-checks",
                "advisory",
            ],
        )
        assert written.exit_code == 0, written.output

    def test_a_repository_scan_counts_what_its_report_carries(self, tmp_path: Path) -> None:
        """The full shape: baseline accepts everything, so every count is zero."""
        skill = self._nonconforming(tmp_path / "skills" / "weather--report", "weather--report")
        baseline_file = tmp_path / "baseline.yaml"
        self._baseline(skill, baseline_file)

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--repo-scan",
                "--no-llm",
                "-f",
                "json",
                "--spec-checks",
                "advisory",
                "--baseline",
                str(baseline_file),
            ],
        )

        assert result.exit_code in (0, 1), result.output
        # `--repo-scan` writes one report per Skill under a `--- path ---`
        # header, so stdout is not one JSON document to parse.
        assert '"issues": []' in result.stdout
        table = _unwrapped(result.stderr)
        assert "weather--report 0 LOW 0" in table
        assert "advisory finding(s)" not in table

    def test_a_repository_scan_without_a_baseline_still_counts_its_findings(
        self, tmp_path: Path
    ) -> None:
        """The control. Without it, "zero" would pass for a count that never counts."""
        self._nonconforming(tmp_path / "skills" / "weather--report", "weather--report")

        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--repo-scan",
                "--no-llm",
                "-f",
                "json",
                "--spec-checks",
                "advisory",
            ],
        )

        assert result.exit_code in (0, 1), result.output
        assert '"id": "SPEC-6"' in result.stdout
        assert '"id": "SPEC-15"' in result.stdout
        assert "weather--report 10 LOW 2" in _unwrapped(result.stderr)

    def test_an_empty_filtered_list_is_honoured_rather_than_fallen_back_from(self) -> None:
        """The second defect, on the state shape that produces it.

        A scan whose findings the meta filter all dropped carries
        ``filtered_findings == []`` beside a non-empty ``findings``. `report`
        selects by presence and reports none of them; an ``or`` chain reads the
        empty list as falsy and counts the pre-filter ones instead. Exercised on
        the helper because arranging that state from a fixture would mean finding
        an analyzer whose finding this filter happens to drop, which pins the test
        to that analyzer rather than to the reading under test.
        """
        finding = Finding(
            rule_id="TM1", message="m", severity="LOW", confidence=0.2, file="tool.py"
        )

        assert reported_findings({"filtered_findings": [], "findings": [finding]}) == []

    def test_an_absent_filtered_key_still_falls_back(self) -> None:
        """Presence, not truth: a scan that never set the key reads the raw list.

        The direct-node compatibility path `report` documents, and the reason the
        reader is not simply ``result["filtered_findings"]``.
        """
        finding = Finding(
            rule_id="TM1", message="m", severity="LOW", confidence=0.2, file="tool.py"
        )

        assert reported_findings({"findings": [finding]}) == [finding]

    def test_a_suppressed_finding_is_subtracted(self) -> None:
        """The first defect, isolated: a state carrying both partitions is read
        as though the kept side were the whole of it."""
        kept = Finding(rule_id="TM1", message="m", severity="LOW", confidence=1.0, file="a.py")
        accepted = Finding(rule_id="TM2", message="m", severity="LOW", confidence=1.0, file="b.py")

        result = reported_findings(
            {
                "filtered_findings": [kept, accepted],
                "suppressed_findings": [SuppressedFinding(finding=accepted, reason="accepted")],
            }
        )

        assert [f.rule_id for f in result] == ["TM1"]


def _reader_finding(rule_id: str) -> Finding:
    """One Finding, distinguishable by its rule id alone."""
    return Finding(
        rule_id=rule_id, message="m", severity="LOW", confidence=1.0, file=f"{rule_id}.py"
    )


_KEPT = _reader_finding("TM1")
_ACCEPTED = _reader_finding("TM2")
_ACCEPTED_ENTRY = SuppressedFinding(finding=_ACCEPTED, reason="accepted")

# Every shape a `graph.invoke` result can hand a consumer, including the ones a
# real Scan cannot produce -- a hand-assembled result and a direct call of the
# report node both reach the last four.
_SELECTION_SHAPES: dict[str, dict[str, object]] = {
    "a partitioned report": {
        "findings": [_KEPT, _ACCEPTED],
        "filtered_findings": [_KEPT],
        "suppressed_findings": [_ACCEPTED_ENTRY],
    },
    "everything filtered away": {"findings": [_KEPT], "filtered_findings": []},
    "everything suppressed": {
        "filtered_findings": [_KEPT, _ACCEPTED],
        "suppressed_findings": [
            SuppressedFinding(finding=_KEPT, reason="accepted"),
            _ACCEPTED_ENTRY,
        ],
    },
    "no filtered key, nothing suppressed": {"findings": [_KEPT]},
    "no filtered key, a suppressed partition": {
        "findings": [_KEPT, _ACCEPTED],
        "suppressed_findings": [_ACCEPTED_ENTRY],
    },
    "a malformed filtered key": {
        "findings": [_KEPT, _ACCEPTED],
        "filtered_findings": "not a list",
        "suppressed_findings": [_ACCEPTED_ENTRY],
    },
    "a non-Finding member": {
        "filtered_findings": [_KEPT, object()],
        "suppressed_findings": [_ACCEPTED_ENTRY],
    },
    "nothing at all": {},
}


class TestOneRecursiveScanCountsItsFindingsOnce:
    """Two readers ran over one child result of one ``--recursive`` Scan.

    ``_combined_skill_entry``'s ``finding_count`` -- the number the combined JSON
    report publishes per Skill, and the one the Multi-Skill Summary table prints
    beside it -- counts through ``report.reported_findings``.
    ``_multi_skill_public_record_count``, the budget deciding whether that
    Skill's records fit in the recursive report at all, selects through
    ``suppression.effective_findings``. One intent, two functions, and issue #130
    measured them disagreeing on exactly one shape: ``filtered_findings`` absent
    while ``suppressed_findings`` is present, where the fork's reader subtracted
    a partition the raw ``findings`` list never came from. The fork's reader now
    delegates to upstream's, so the disagreement is unrepresentable rather than
    merely unreached.
    """

    @pytest.mark.parametrize("shape", list(_SELECTION_SHAPES), ids=list(_SELECTION_SHAPES))
    def test_the_two_named_readers_select_the_same_findings(self, shape: str) -> None:
        """Every shape either reader can be handed, not only the ones a Scan produces."""
        result = _SELECTION_SHAPES[shape]

        assert reported_findings(result) == effective_findings(result)

    def test_the_budget_and_the_summary_count_one_result_identically(self) -> None:
        """The two call sites, on the shape they disagreed about.

        The two numbers are not equal by construction: the budget counts
        occurrence records and adds the suppressed side to the active one, while
        the summary counts active findings. What has to agree is the *selection*
        -- subtract the one suppressed record and the budget is counting exactly
        what the summary counts. Reading the fork's function before it delegated
        left the budget one ahead.
        """
        result = _SELECTION_SHAPES["no filtered key, a suppressed partition"]
        suppressed = result.get("suppressed_findings")
        suppressed_records = len(suppressed) if isinstance(suppressed, list) else 0

        # Through the entry builder, not through a second call to the same reader.
        # Re-expressing the production selection here would make the assertion
        # true of itself, and a regression that inlined the selection at the call
        # site would leave this green.
        entry = _combined_skill_entry("one", "skills/one", result)

        assert (
            _multi_skill_public_record_count(result) - suppressed_records == entry["finding_count"]
        )


class TestAFreshBaselineHoldsWhatTheScanReports:
    """``skillspector baseline`` records the findings the scan reports, and only those.

    It loads no baseline of its own -- there is no ``--baseline`` option, and the
    ``baseline_path`` it sets is read only by
    ``build_context._selected_baseline_component``, which excludes the output file
    from the walk -- so nothing is ever suppressed on this path. The reading that
    mattered is the empty one: an ``or`` chain fell back to the raw pre-filter
    findings when the meta filter had dropped them all, writing entries for
    findings the scan does not report and whose fingerprints bind pre-filter
    evidence, so a later ``scan --baseline`` computes a different hash and they
    suppress nothing at all.
    """

    def test_a_scan_reporting_nothing_writes_an_empty_baseline(self, tmp_path: Path) -> None:
        skill = _write_skill(tmp_path / "solo", "solo")
        baseline_file = tmp_path / "baseline.yaml"

        result = runner.invoke(app, ["baseline", str(skill), "-o", str(baseline_file), "--no-llm"])

        assert result.exit_code == 0, result.output
        assert "Wrote baseline with 0 suppressed finding(s)" in _unwrapped(result.stderr)
        assert yaml.safe_load(baseline_file.read_text(encoding="utf-8"))["fingerprints"] == []

    def test_a_scan_reporting_findings_writes_exactly_them(self, tmp_path: Path) -> None:
        """The control, and the reason the fix is not "write nothing"."""
        skill = TestASummaryTableAgreesWithItsReport._nonconforming(
            tmp_path / "weather--report", "weather--report"
        )
        baseline_file = tmp_path / "baseline.yaml"

        result = runner.invoke(
            app,
            [
                "baseline",
                str(skill),
                "-o",
                str(baseline_file),
                "--no-llm",
                "--spec-checks",
                "advisory",
            ],
        )

        assert result.exit_code == 0, result.output
        document = yaml.safe_load(baseline_file.read_text(encoding="utf-8"))
        assert {entry["rule_id"] for entry in document["fingerprints"]} == {"SPEC-6", "SPEC-15"}
