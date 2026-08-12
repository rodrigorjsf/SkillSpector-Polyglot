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

The one line that is a judgement call rather than a classification is the
Multi-Skill Summary table, and ``TestTheMultiSkillSummaryIsTheReport`` below
records every half of it: measured, ``--recursive`` writes its combined report
**only** to ``--output`` *once the flag engages* (issue #114), so with
``-f terminal`` and no ``--output`` that table is the whole of what the Scan
produced and ``skillspector scan ./skills --recursive | less`` has it or has
nothing. Ask for ``-f json`` without an ``--output`` and there is no report
anywhere, so the table is not one either and stdout stays empty rather than
unparseable. Below the two-skill threshold the flag never engages: the Scan falls
through to an ordinary one, which does print a report to stdout in the requested
format, and that counterexample is pinned here too.
``--repo-scan``'s table is not the same case at all — that path always prints a
report, so its table only ever duplicates one, and it goes to stderr.

Any assertion here that matches a *path* inside rich output needs ``_wide_console``
below, and the module-level fixture applies it to everything so that no future one
can be written without it.

Every site in ``cli`` that writes user-facing output is covered *individually and
in both directions* across ``tests/unit/``: moving any one of them to the other
stream — an ``advice`` site to ``console``, a ``console``/``summary`` site to
``advice``, or any of the three bare ``print()`` calls that put a report on stdout
(in ``_write_result``, in the ``--mcp-registry`` branch, and at the end of
``_scan_repository``) onto ``advice`` — fails a test on its own, with no other
site moving with it. Those three are counted deliberately: they are how the report
reaches stdout at all, so a claim about print sites that skipped them would omit
the very thing the rule exists to protect. That was all measured by flipping each
site in turn, not assumed; all but two of them fail a test *in this
file*. The two exceptions are ``_advise_on_a_fallthrough``'s
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
from typer.testing import CliRunner

from skillspector import __version__
from skillspector.cli import app

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
    separate property this path only has under ``-f sarif``, and
    ``test_a_json_repository_report_is_concatenated_not_merged`` pins the
    difference so neither claim is read as the other.
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

    def test_a_json_repository_report_is_concatenated_not_merged(self, tmp_path: Path) -> None:
        """Characterisation: what stdout carries here is the report, and unparseable anyway.

        The stream rule holds — this concatenation *is* the report, so stdout is
        where it belongs, and no line was moved off it. What it is not is a
        single document: only ``-f sarif`` is merged, and every other format
        falls through to the per-Skill bodies glued behind ``--- path ---``
        separators. Pinned here so the README clause saying so cannot rot, and
        so that fixing it
        ([#116](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/116))
        is a visible, intended change to this test rather than a silent one.
        """
        repository = self._repository(tmp_path)

        result = runner.invoke(
            app, ["scan", str(repository), "--repo-scan", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("--- skills/one ---")
        assert "--- skills/two ---" in result.stdout
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.stdout)

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

    def test_finding_no_skill_at_all_leaves_stdout_empty(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()

        result = runner.invoke(app, ["scan", str(tmp_path), "--repo-scan", "--no-llm"])

        assert result.stdout == ""
        assert "no skill found under" in _unwrapped(result.stderr)

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


class TestTheMultiSkillSummaryIsTheReport:
    """``--recursive``, the one path whose table has to be argued about.

    It writes its combined report **only** to ``--output``; there is no
    fall-back that prints one. So the stream this table goes to is not a
    cosmetic question either way: on stderr with no ``--output``, stdout would
    be empty and ``| less`` would show nothing at all.
    """

    def test_without_an_output_file_the_table_is_on_stdout(self, tmp_path: Path) -> None:
        """The positive assertion that stops a later sweep from moving it.

        The table is built from five separate ``print`` calls — banner, column
        headings, rule, one row per Skill, trailing spacer — and each is its own
        site that a sweep could move on its own. Asserting only the banner and one
        row would leave three of them free to drift to stderr, which would leave
        ``| less`` showing a headerless fragment.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 0, result.output
        unwrapped = _unwrapped(result.stdout)
        assert "═══ Multi-Skill Summary ═══" in unwrapped
        assert "Skill Score Severity Findings Execution" in unwrapped
        assert "─" * 30 in unwrapped
        assert "alpha 0 LOW 0 successful" in unwrapped
        assert "beta 0 LOW 0 successful" in unwrapped
        # The trailing spacer, printed after the last row and the last thing this
        # path writes to stdout at all, so a blank line is what stdout ends with.
        assert result.stdout.endswith("\n\n")

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

    def test_a_machine_readable_format_alone_leaves_stdout_empty(self, tmp_path: Path) -> None:
        """The other half of the judgement call, and #99's failure mode exactly.

        ``-f json`` with no ``--output`` writes the combined report *nowhere*
        (issue #114), so there is nothing on stdout for the table to be. Printed
        there anyway it is a rich table in front of a caller's ``jq``, which is
        the defect this whole change exists to remove — so it goes to stderr
        with the rest of the notes and stdout stays empty and honest.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 0, result.output
        assert result.stdout == ""
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
        """A per-Skill failure is a note about the Scan, not a row of its report.

        ``--recursive`` keeps going when one Skill fails, so this line is printed
        in the middle of the run. It is the site that would reintroduce #99 the
        moment #114 puts a report back on stdout, and no other assertion reaches
        it: the summary table's ``ERROR`` row is a separate ``print``.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--recursive", "--no-llm", "-f", "json"]
        )

        assert result.exit_code == 2
        assert result.stdout == ""
        assert "Error: the graph came apart" in _unwrapped(result.stderr)

    def test_a_failing_skill_still_gets_its_row_in_the_table_that_is_the_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``ERROR`` row, which is a separate ``print`` from the per-Skill error line.

        The test above runs under ``-f json``, where the whole table is on stderr,
        so it never reaches this row on the stream that matters. Here — ``-f
        terminal``, no ``--output`` — the table *is* the report, and a Skill that
        failed has to appear in it or the report silently omits a Skill the Scan
        was pointed at. The per-Skill error line printed while the Scan is still
        going stays a note either way, which is the other half of the assertion.
        """
        _write_skill(tmp_path / "alpha", "alpha")
        _write_skill(tmp_path / "beta", "beta")
        monkeypatch.setattr("skillspector.cli.graph", SimpleNamespace(invoke=_explode))

        result = runner.invoke(app, ["scan", str(tmp_path), "--recursive", "--no-llm"])

        assert result.exit_code == 2
        unwrapped = _unwrapped(result.stdout)
        assert "alpha ERROR" in unwrapped
        assert "beta ERROR" in unwrapped
        assert "the graph came apart" not in unwrapped
        assert "Error: the graph came apart" in _unwrapped(result.stderr)

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
