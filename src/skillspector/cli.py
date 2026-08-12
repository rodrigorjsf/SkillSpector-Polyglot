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

"""CLI for Skillspector — thin wrapper over the LangGraph workflow.

Maps CLI args to initial state, invokes the graph, then maps result to output and exit code.
No business logic; workflow lives in the graph.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, cast

import typer
from langchain_core.runnables import RunnableConfig
from rich.console import Console

from skillspector import __version__
from skillspector.cleanup import cleanup_result
from skillspector.constants import RISK_THRESHOLD
from skillspector.graph import graph
from skillspector.logging_config import get_logger, set_level
from skillspector.mcp_registry import scan_registry
from skillspector.multi_skill import MultiSkillDetectionResult, detect_skills
from skillspector.repository_scan import DISCOVERY_ROOTS, DiscoveredSkill, discover_skills
from skillspector.suppression import build_baseline_dict, dump_baseline, load_baseline

logger = get_logger(__name__)


def _ensure_utf8_streams() -> None:
    """Reconfigure stdout/stderr to UTF-8 so Unicode report output does not crash.

    On Windows the default console encoding (e.g. cp1252) cannot encode the
    box-drawing characters and icons used in the terminal report, which raises
    UnicodeEncodeError. Reconfiguring with errors="replace" makes output robust
    across platforms without crashing.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                logger.debug("Could not reconfigure %s to UTF-8", stream)


_ensure_utf8_streams()

app = typer.Typer(
    name="skillspector",
    help="Security scanner for AI agent skills (LangGraph). Detect vulnerabilities before installation.",
    add_completion=False,
    no_args_is_help=True,
)

# One rule governs every line this module prints, and the two consoles below are
# how it is expressed: **the report goes to stdout, everything else to stderr**.
#
# `--format json` and `--format sarif` write the report to stdout when no
# `--output` is given, so `skillspector scan . -f json | jq` is a real pipeline.
# Anything printed alongside the report lands *inside* it and breaks it.
#
# `console` therefore carries the report and nothing else -- plus `--version`,
# which is itself the output that was asked for.
console = Console()

# `advice` carries everything that is a note *about* the scan rather than the
# scan's product: advisories, progress lines, "Report saved to", per-skill
# summaries that duplicate a report written elsewhere, errors and tracebacks. A
# pipe leaves stderr alone and a terminal still shows it, so nothing is lost.
#
# The one line that has to be argued rather than classified is the Multi-Skill
# Summary table; see `_scan_multi_skill`, which explains why that table *is* the
# report of a `-f terminal --recursive` scan that was given no `--output`, and
# only of that one.
advice = Console(stderr=True)

_FALLTHROUGH_PREFIX = (
    "[yellow]Warning:[/yellow] no SKILL.md here, so this scans the whole tree as one "
    "unnamed skill with an empty manifest. "
)


def _advise_on_a_fallthrough(directory: Path, children_with_a_skill: int) -> None:
    """Name the flag that would have found the skills, at the moment it is needed.

    Reached when *directory* declares no skill of its own, so the Scan about to
    run is the wrong-shaped one: an empty manifest, components spanning the whole
    tree, and a risk score computed over that mixture.

    Determinate rather than a menu. Discovery is actually run, so the advice names
    the flag that finds something *here* and says how much, instead of listing both
    flags and handing the choice back to a reader who does not know which of two
    discovery rules matches their layout. It costs one walk, on a path that is
    about to walk the whole tree anyway.
    """
    discovered = discover_skills(directory)
    if discovered:
        advice.print(
            f"{_FALLTHROUGH_PREFIX}--repo-scan finds {len(discovered)} skill(s) here and "
            "scans each on its own; use it instead."
        )
    elif children_with_a_skill:
        advice.print(
            f"{_FALLTHROUGH_PREFIX}--recursive found {children_with_a_skill} skill(s) "
            "immediately below and needs at least 2, and --repo-scan finds none under the "
            "conventional roots. Point the scan at the skill directory itself, or pass "
            "--repo-scan-root for a layout the roots do not cover."
        )
    else:
        advice.print(
            f"{_FALLTHROUGH_PREFIX}No skill was found immediately below either, nor by "
            "--repo-scan under the conventional roots. Point the scan at a skill directory, "
            "or pass --repo-scan --repo-scan-root for a layout the roots do not cover."
        )


class FormatChoice(StrEnum):
    """Output format choices for the CLI."""

    terminal = "terminal"
    json = "json"
    markdown = "markdown"
    sarif = "sarif"


class TransportChoice(StrEnum):
    """Transport choices for the MCP server."""

    stdio = "stdio"
    http = "http"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"SkillSpector v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """
    SkillSpector - Security scanner for AI agent skills (LangGraph).

    Analyze skill bundles to detect vulnerabilities and security risks.
    Supports: Git URL, file URL, .zip file, .md file, or directory.
    """
    pass


def _scan_state(
    input_path: str,
    format: FormatChoice,
    no_llm: bool,
    yara_rules_dir: str | None = None,
    baseline: Path | None = None,
    show_suppressed: bool = False,
) -> dict[str, object]:
    """Build initial graph state from scan CLI args."""
    state: dict[str, object] = {
        "input_path": input_path,
        "output_format": format.value,
        "use_llm": not no_llm,
    }
    if yara_rules_dir is not None:
        state["yara_rules_dir"] = yara_rules_dir
    if baseline is not None:
        # Loading may raise FileNotFoundError/ValueError, mapped to exit code 2 by scan().
        state["baseline"] = load_baseline(baseline)
        state["baseline_path"] = os.path.abspath(baseline.expanduser())
        state["show_suppressed"] = show_suppressed
    return state


def _result_body(result: dict) -> str:
    report_body = result.get("report_body") or ""
    if not report_body and result.get("sarif_report") is not None:
        report_body = json.dumps(result["sarif_report"], indent=2)
    return report_body


def _write_result(
    result: dict[str, object],
    output: Path | None,
    format: FormatChoice,
) -> None:
    """Write report_body to file or stdout. Uses sarif_report if report_body missing."""
    report_body = _result_body(result)
    if output:
        Path(output).write_text(report_body, encoding="utf-8")
        # The report is the file; this line is only a note that it exists.
        if format == FormatChoice.terminal:
            advice.print(f"\n[green]Report saved to:[/green] {output}")
        else:
            advice.print(f"Report saved to: {output}")
    else:
        if format == FormatChoice.terminal:
            console.print(report_body)
        else:
            print(report_body)


def _recursive_json_payload(result: dict[str, object]) -> dict[str, object] | None:
    """Return parsed report_body when it is valid JSON object text."""
    raw_report_body = result.get("report_body")
    if not isinstance(raw_report_body, str):
        return None

    try:
        parsed = json.loads(raw_report_body)
    except json.JSONDecodeError:
        return None

    return parsed if isinstance(parsed, dict) else None


@app.command()
def scan(
    input_path: Annotated[
        str,
        typer.Argument(
            help="Path or URL to scan. Supports: Git URL, file URL, zip file, .md file, or directory.",
        ),
    ],
    format: Annotated[
        FormatChoice,
        typer.Option(
            "--format",
            "-f",
            help="Output format.",
            case_sensitive=False,
        ),
    ] = FormatChoice.terminal,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path. If not specified, prints to stdout.",
        ),
    ] = None,
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Skip LLM analysis (faster, less accurate). Uses static analysis only.",
        ),
    ] = False,
    yara_rules_dir: Annotated[
        Path | None,
        typer.Option(
            "--yara-rules-dir",
            help="Directory containing additional YARA rule files (.yar/.yara) to load alongside built-in rules.",
        ),
    ] = None,
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive",
            "-r",
            help="Scan immediate subdirectories that each contain a SKILL.md as independent skills.",
        ),
    ] = False,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "-b",
            help="Baseline file (YAML/JSON) of suppressed findings. Matching findings "
            "are dropped before scoring. Generate one with 'skillspector baseline'.",
        ),
    ] = None,
    show_suppressed: Annotated[
        bool,
        typer.Option(
            "--show-suppressed",
            help="List findings suppressed by the baseline in the report (they still "
            "do not count toward the risk score).",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-V",
            help="Show detailed progress.",
        ),
    ] = False,
    mcp_registry: Annotated[
        bool,
        typer.Option(
            "--mcp-registry",
            help="Scan an MCP Registry payload or URL instead of a skill.",
        ),
    ] = False,
    repo_scan: Annotated[
        bool,
        typer.Option(
            "--repo-scan",
            help="Repository Scan: find every skill inside a repository and scan each "
            "separately, instead of treating the whole tree as one skill.",
        ),
    ] = False,
    repo_scan_root: Annotated[
        list[str] | None,
        typer.Option(
            "--repo-scan-root",
            help="Replace the conventional discovery roots of a Repository Scan. "
            "Repeatable. Each is matched as a path suffix at any depth.",
        ),
    ] = None,
) -> None:
    """
    Scan a skill for security vulnerabilities.

    Examples:

        skillspector scan ./my-skill/
        skillspector scan ./my-skill/ --format json --output report.json
        skillspector scan https://github.com/user/my-skill --no-llm
        skillspector scan ./skill-collection/ --recursive

    Environment variables:

        SKILLSPECTOR_PROVIDER  Active LLM provider: openai | anthropic |
                               anthropic_proxy | bedrock | nv_build |
                               nv_inference. Defaults to the NVIDIA path
                               (nv_inference, falling back to nv_build in
                               OSS builds).
        SKILLSPECTOR_MODEL     Override the active provider's default
                               model (applies to every analyzer slot).
        SKILLSPECTOR_LOG_LEVEL DEBUG | INFO | WARNING | ERROR (default WARNING).

    Provider credentials (one of):

        OPENAI_API_KEY [+ OPENAI_BASE_URL]   for SKILLSPECTOR_PROVIDER=openai
        ANTHROPIC_API_KEY                    for SKILLSPECTOR_PROVIDER=anthropic
        AWS_PROFILE (optional) + AWS_REGION  for SKILLSPECTOR_PROVIDER=bedrock
                                             (AWS_PROFILE: standard boto3 credential
                                             chain when unset; AWS_REGION default: us-west-2)
        NVIDIA_INFERENCE_KEY                 for the NVIDIA providers
    """
    if mcp_registry:
        if (
            recursive
            or repo_scan
            or baseline is not None
            or show_suppressed
            or yara_rules_dir is not None
        ):
            advice.print(
                "[red]Error:[/red] --mcp-registry cannot be combined with "
                "--recursive, --repo-scan, --baseline, --show-suppressed, or --yara-rules-dir"
            )
            raise typer.Exit(code=2)
        if format != FormatChoice.json:
            advice.print("[red]Error:[/red] --mcp-registry currently supports only --format json")
            raise typer.Exit(code=2)
        try:
            result = scan_registry(input_path)
            report = json.dumps(result, indent=2)
            if output:
                output.write_text(report, encoding="utf-8")
                advice.print(f"Report saved to: {output}")
            else:
                print(report)
            if result["risk_score"] > RISK_THRESHOLD:
                raise typer.Exit(code=1)
        except typer.Exit:
            raise
        except Exception as e:
            advice.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=2) from e
        return

    if verbose:
        set_level("DEBUG")

    resolved_path = Path(input_path).resolve()
    if repo_scan:
        if not resolved_path.is_dir():
            advice.print("[red]Error:[/red] --repo-scan needs a directory to search")
            raise typer.Exit(code=2)
        _scan_repository(
            resolved_path,
            tuple(repo_scan_root) if repo_scan_root else DISCOVERY_ROOTS,
            format,
            output,
            no_llm,
            yara_rules_dir,
            baseline,
            show_suppressed,
            verbose,
        )
        return

    if recursive and resolved_path.is_dir():
        detection = detect_skills(resolved_path)
        if detection.is_multi_skill:
            if baseline is not None:
                advice.print(
                    "[red]Error:[/red] --baseline is not supported for recursive "
                    "multi-skill scans; scan each sub-skill with its own baseline"
                )
                raise typer.Exit(code=2)
            _scan_multi_skill(detection, format, output, no_llm, yara_rules_dir, verbose)
            return
        if not detection.has_root_skill:
            # Guarded on the *outcome*, not on an empty list. The old guard was
            # `len(detection.skills) == 0`, which is false for a directory with
            # exactly one child Skill -- the case that most needs saying, since
            # --recursive needs two and silently scans the parent instead.
            _advise_on_a_fallthrough(resolved_path, len(detection.skills))
    elif resolved_path.is_dir():
        detection = detect_skills(resolved_path)
        if detection.is_multi_skill:
            # #99: this predates the fall-through advisory below and used to print
            # to stdout, landing ahead of a `-f json`/`-f sarif` report written
            # there and making it unparseable. It is advice about the shape of the
            # scan, not part of the report, so it belongs on the same stream as
            # its sibling.
            advice.print(
                f"[yellow]Warning:[/yellow] Found {len(detection.skills)} skills in "
                f"this directory. Use --recursive to scan each independently."
            )
        elif not detection.has_root_skill:
            # The trap #39 names, at the moment it is sprung: no Skill is
            # declared here and none was found one level down, so this Scan is
            # about to report the whole tree as one anonymous Skill.
            _advise_on_a_fallthrough(resolved_path, len(detection.skills))

    result = None
    try:
        yara_dir = str(yara_rules_dir.resolve()) if yara_rules_dir else None
        state = _scan_state(
            input_path,
            format,
            no_llm,
            yara_rules_dir=yara_dir,
            baseline=baseline,
            show_suppressed=show_suppressed,
        )
        if verbose:
            advice.print("[dim]Running scan...[/dim]")
        logger.debug(
            "Scan started: input_path=%s, format=%s, use_llm=%s",
            input_path,
            format,
            not no_llm,
        )
        trace_config = _build_trace_config(input_path, format, no_llm)
        result = graph.invoke(state, config=trace_config)

        _write_result(result, output, format)

        if result.get("execution_successful") is False:
            raise typer.Exit(code=2)
        if (result.get("risk_score") or 0) > RISK_THRESHOLD:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except (FileNotFoundError, ValueError) as e:
        advice.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2) from e
    except Exception as e:
        if verbose:
            advice.print_exception()
        else:
            advice.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2) from e
    finally:
        if result is not None:
            cleanup_result(result)


def _build_trace_config(input_path: str, format: FormatChoice, no_llm: bool) -> RunnableConfig:
    """Build LangSmith trace config for a scan invocation."""
    env = os.environ.get("ENV", "dev")
    tags = ["skillspector", f"environment:{env}"]
    extra_tags = os.environ.get("LANGCHAIN_TAGS_EXTRA", "")
    tags.extend(t.strip() for t in extra_tags.split(",") if t.strip())
    return {
        "run_name": "skillspector-scan",
        "tags": tags,
        "metadata": {
            "input_path": input_path,
            "use_llm": not no_llm,
            "output_format": format.value,
            "version": __version__,
        },
    }


def _scan_multi_skill(
    detection: MultiSkillDetectionResult,
    format: FormatChoice,
    output: Path | None,
    no_llm: bool,
    yara_rules_dir: Path | None,
    verbose: bool,
) -> None:
    """Scan each detected sub-skill independently and produce a combined report.

    Which stream each line goes to is decided by one question: *does stdout carry
    the report here?* Unlike every other Scan path, this one writes the combined
    report **only** to ``--output`` -- there is no ``print(body)`` fall-back, the
    limitation issue #114 records -- so with ``-f terminal`` and no ``--output``
    the Multi-Skill Summary table is not a digest of a report printed elsewhere.
    It is the whole of what the Scan produced, and ``skillspector scan ./skills
    --recursive | less`` has it or has nothing, so it goes to stdout.

    That is the *only* case in which it does. ``--output`` makes the file the
    report and demotes the table to a digest of it; and with ``-f json``,
    ``-f sarif`` or ``-f markdown`` and no ``--output`` there is no report
    anywhere -- printing a rich table to stdout would then leave a caller piping
    to ``jq`` with exactly the unparseable stream issue #99 was filed about, so
    stdout stays empty and the table goes to stderr with everything else. Fixing
    #114 makes the table a digest on every path and collapses ``summary`` to
    plain ``advice``.

    Everything around it -- the detection banner, the per-skill progress and
    score lines, a per-skill error, "Combined report saved to" -- is a note about
    the Scan on every path, and goes to stderr always.
    """
    skills = detection.skills
    advice.print(f"[bold]Multi-skill directory detected:[/bold] {len(skills)} skills found\n")

    results: list[dict[str, object]] = []
    max_score = 0
    execution_failed = False

    for i, skill in enumerate(skills, 1):
        advice.print(
            f"  [{i}/{len(skills)}] Scanning [bold]{skill.name}[/bold] ({skill.relative_path}/)"
        )
        yara_dir = str(yara_rules_dir.resolve()) if yara_rules_dir else None
        state = _scan_state(str(skill.path), format, no_llm, yara_rules_dir=yara_dir)
        trace_config = _build_trace_config(str(skill.path), format, no_llm)

        try:
            result = graph.invoke(state, config=trace_config)
            results.append(result)
            if result.get("execution_successful") is False:
                execution_failed = True
            score = result.get("risk_score") or 0
            if isinstance(score, int) and score > max_score:
                max_score = score
            severity = result.get("risk_severity") or "LOW"
            advice.print(f"         Score: {score}/100 ({severity})\n")
        except Exception as e:
            advice.print(f"         [red]Error:[/red] {e}\n")
            execution_failed = True
            results.append({"skill_name": skill.name, "error": str(e)})

    # The predicate is "does stdout carry the report here?", and it is true in
    # one case only: `-f terminal` with no `--output`, where this table is the
    # entire product of the Scan. See this function's docstring, and #114 for the
    # missing fall-back that makes the case exist at all.
    summary = console if (output is None and format == FormatChoice.terminal) else advice

    summary.print("\n[bold]═══ Multi-Skill Summary ═══[/bold]\n")
    summary.print(
        f"  {'Skill':<30} {'Score':<8} {'Severity':<12} {'Findings':<10} {'Execution':<10}"
    )
    summary.print(f"  {'─' * 30} {'─' * 8} {'─' * 12} {'─' * 10} {'─' * 10}")

    for skill, result in zip(skills, results, strict=True):
        if "error" in result:
            summary.print(f"  {skill.name:<30} {'ERROR':<8} {'—':<12} {'—':<10} {'error':<10}")
            continue
        score = result.get("risk_score", 0)
        severity = result.get("risk_severity", "LOW")
        filtered = result.get("filtered_findings") or result.get("findings")
        finding_count = len(filtered) if isinstance(filtered, list) else 0
        execution = "failed" if result.get("execution_successful") is False else "successful"
        summary.print(
            f"  {skill.name:<30} {score:<8} {severity:<12} {finding_count:<10} {execution:<10}"
        )

    summary.print("")

    if output and format == FormatChoice.json:
        combined: dict[str, object] = {
            "multi_skill": True,
            "skill_count": len(skills),
            "max_risk_score": max_score,
            "execution_successful": not execution_failed,
            "skills": [],
        }
        combined_skills = cast(list[dict[str, object]], combined["skills"])
        for skill, result in zip(skills, results, strict=True):
            if "error" in result:
                combined_skills.append({"name": skill.name, "error": result["error"]})
            else:
                payload = _recursive_json_payload(result) or {}
                selected_findings = result.get("filtered_findings") or result.get("findings") or []
                finding_count = len(selected_findings) if isinstance(selected_findings, list) else 0
                entry = {
                    "name": skill.name,
                    "path": skill.relative_path,
                    "risk_score": result.get("risk_score", 0),
                    "risk_severity": result.get("risk_severity", "LOW"),
                    "finding_count": finding_count,
                    "execution_successful": result.get("execution_successful", True),
                }
                entry.update(payload)
                entry["name"] = skill.name
                entry["path"] = skill.relative_path
                entry["risk_score"] = result.get("risk_score", 0)
                entry["risk_severity"] = result.get("risk_severity", "LOW")
                entry["finding_count"] = finding_count
                entry["execution_successful"] = result.get("execution_successful", True)
                combined_skills.append(entry)
        Path(output).write_text(json.dumps(combined, indent=2), encoding="utf-8")
        advice.print(f"[green]Combined report saved to:[/green] {output}")
    elif output:
        # concatenated non-JSON output: not merged SARIF
        sections = []
        for skill, result in zip(skills, results, strict=True):
            if "error" not in result:
                sections.append(f"--- {skill.relative_path} ---\n\n{_result_body(result)}")
        Path(output).write_text("\n\n".join(sections), encoding="utf-8")
        advice.print(f"[green]Combined report saved to:[/green] {output}")

    if execution_failed:
        raise typer.Exit(code=2)
    if max_score > RISK_THRESHOLD:
        raise typer.Exit(code=1)


def _relocate_sarif_run(run: dict, prefix: str) -> dict:
    """Copy one SARIF run with every artifact URI moved under *prefix*.

    Each Skill is Scanned in its own directory, so its SARIF locations are
    relative to that directory. A Repository Scan's output is read against the
    repository root -- by GitHub code scanning, among others -- so the URIs are
    rewritten to match, or every location would point at a path that does not
    exist there.
    """
    relocated = copy.deepcopy(run)
    for result in relocated.get("results", []):
        for location in result.get("locations", []):
            artifact = location.get("physicalLocation", {}).get("artifactLocation")
            if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
                artifact["uri"] = f"{prefix}/{artifact['uri']}"
    return relocated


def _merge_repository_sarif(scanned: list[tuple[DiscoveredSkill, dict]]) -> dict[str, object]:
    """One SARIF log for a whole Repository Scan, a run per Skill.

    SARIF carries several runs in one log, which is exactly the shape here: each
    Skill was a separate Scan and keeping them separate preserves which tool
    invocation produced what.
    """
    runs: list[dict] = []
    version = "2.1.0"
    schema = "https://json.schemastore.org/sarif-2.1.0.json"
    for skill, result in scanned:
        report = result.get("sarif_report")
        if not isinstance(report, dict):
            continue
        version = str(report.get("version", version))
        schema = str(report.get("$schema", schema))
        runs.extend(_relocate_sarif_run(run, skill.relative_path) for run in report.get("runs", []))
    return {"$schema": schema, "version": version, "runs": runs}


def _scan_repository(
    repository_root: Path,
    roots: tuple[str, ...],
    format: FormatChoice,
    output: Path | None,
    no_llm: bool,
    yara_rules_dir: Path | None,
    baseline: Path | None,
    show_suppressed: bool,
    verbose: bool,
) -> None:
    """Scan every Skill inside a repository, each as its own Skill.

    The alternative this replaces is not "no result" but a wrong one: a
    repository root declares no Skill, so an ordinary Scan reports the whole
    tree as one anonymous Skill with an empty Manifest and scores it as such.

    Everything printed here except ``body`` goes to stderr. Unlike
    ``_scan_multi_skill``, this path always writes the report -- to ``--output``
    or, failing that, to stdout -- so its per-Skill table never has to stand in
    for one: with ``-f sarif`` and no ``--output``, stdout carries a single
    merged SARIF log that a progress line or a table would make unparseable, and
    with ``-f terminal`` it carries every per-Skill report in full, of which the
    table is a digest.
    """
    discovered = discover_skills(repository_root, roots=roots)
    if not discovered:
        advice.print(
            f"[yellow]Warning:[/yellow] no skill found under {repository_root}. "
            f"Searched these directory patterns at any depth: {', '.join(roots)}. "
            "Use --repo-scan-root for a layout that does not follow them."
        )
        return

    yara_dir = str(yara_rules_dir.resolve()) if yara_rules_dir else None
    scanned: list[tuple[DiscoveredSkill, dict]] = []
    failures: list[tuple[DiscoveredSkill, str]] = []
    max_score = 0
    execution_failed = False

    for index, skill in enumerate(discovered, start=1):
        advice.print(f"[{index}/{len(discovered)}] Scanning {skill.name} ({skill.relative_path}/)")
        result = None
        try:
            state = _scan_state(
                str(skill.path),
                format,
                no_llm,
                yara_rules_dir=yara_dir,
                baseline=baseline,
                show_suppressed=show_suppressed,
            )
            result = graph.invoke(
                state, config=_build_trace_config(str(skill.path), format, no_llm)
            )
            max_score = max(max_score, int(result.get("risk_score") or 0))
            if result.get("execution_successful") is False:
                execution_failed = True
            scanned.append((skill, dict(result)))
        except Exception as exception:  # one bad Skill must not lose the other results
            if verbose:
                advice.print_exception()
            failures.append((skill, str(exception)))
            execution_failed = True
        finally:
            if result is not None:
                cleanup_result(result)

    advice.print(f"\n{'Skill':<28} {'Score':>6} {'Severity':>10} {'Findings':>9}")
    for skill, result in scanned:
        findings = result.get("filtered_findings") or result.get("findings") or []
        advice.print(
            f"{skill.name[:28]:<28} {int(result.get('risk_score') or 0):>6} "
            f"{str(result.get('risk_severity') or ''):>10} {len(findings):>9}"
        )
    for skill, message in failures:
        advice.print(f"{skill.name[:28]:<28} {'ERROR':>6} {message[:40]}")

    if format == FormatChoice.sarif:
        body = json.dumps(_merge_repository_sarif(scanned), indent=2)
    else:
        body = "\n\n".join(
            f"--- {skill.relative_path} ---\n{_result_body(result)}" for skill, result in scanned
        )
    if output:
        Path(output).write_text(body, encoding="utf-8")
        advice.print(f"Report saved to: {output}")
    else:
        print(body)

    if execution_failed:
        raise typer.Exit(code=2)
    if max_score > RISK_THRESHOLD:
        raise typer.Exit(code=1)


@app.command()
def mcp(
    transport: Annotated[
        TransportChoice,
        typer.Option(
            "--transport",
            "-t",
            help="Transport: FastMCP stdio for local CLI agents, http for remote/A2A callers.",
            case_sensitive=False,
        ),
    ] = TransportChoice.stdio,
    host: Annotated[
        str,
        typer.Option("--host", help="Host to bind (http transport only)."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Port to bind (http transport only)."),
    ] = 8000,
) -> None:
    """
    Run SkillSpector as an MCP server.

    Exposes a single tool, ``scan_skill``, so any MCP-capable agent (Claude Code,
    Codex CLI, Gemini CLI) or remote runtime can scan a skill and gate installs
    on the verdict.

    Requires the optional mcp extra. Reinstall the GitHub tool package with
    that extra enabled, as shown in the README Quick Start section.

    Examples:

        skillspector mcp                      # FastMCP stdio for local CLI agents
        skillspector mcp --transport http --port 8000
    """
    try:
        from skillspector.mcp_server import run as run_mcp

        run_mcp(transport=transport.value, host=host, port=port)
    except ModuleNotFoundError as e:
        # The stdio transport owns stdout as its protocol channel, so this is the
        # one command where a stray line on stdout is worse than unparseable.
        advice.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2) from e


@app.command()
def baseline(
    input_path: Annotated[
        str,
        typer.Argument(
            help="Path or URL to scan. Supports: Git URL, file URL, zip file, .md file, or directory.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Where to write the baseline file (YAML; .json extension writes JSON).",
        ),
    ] = Path(".skillspector-baseline.yaml"),
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Skip LLM analysis when generating the baseline (static analysis only).",
        ),
    ] = False,
    reason: Annotated[
        str,
        typer.Option(
            "--reason",
            help="Reason recorded for every suppressed finding in the baseline.",
        ),
    ] = "Accepted finding (auto-generated baseline)",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-V", help="Show detailed progress."),
    ] = False,
) -> None:
    """
    Generate a baseline file that suppresses every finding in the current scan.

    Run this once to accept all existing findings, then commit the file and pass
    it to future scans with --baseline so only NEW findings are reported.

    Examples:

        skillspector baseline ./my-skill/
        skillspector baseline ./my-skill/ -o team-baseline.yaml --no-llm
        skillspector scan ./my-skill/ --baseline .skillspector-baseline.yaml
    """
    result = None
    try:
        if verbose:
            set_level("DEBUG")
            advice.print("[dim]Scanning to build baseline...[/dim]")
        # output_format is irrelevant here; we consume findings, not report_body.
        state = _scan_state(input_path, FormatChoice.json, no_llm)
        state["baseline_path"] = os.path.abspath(output.expanduser())
        result = graph.invoke(state)
        findings = result.get("filtered_findings") or result.get("findings") or []
        data = build_baseline_dict(
            findings,
            reason=reason,
            file_cache=result.get("file_cache") or {},
            scanner_version=__version__,
        )
        dump_baseline(data, output)
        advice.print(
            f"[green]Wrote baseline with {len(findings)} suppressed finding(s) to:[/green] {output}"
        )
    except typer.Exit:
        raise
    except (FileNotFoundError, ValueError) as e:
        advice.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2) from e
    except Exception as e:
        if verbose:
            advice.print_exception()
        else:
            advice.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=2) from e
    finally:
        if result is not None:
            cleanup_result(result)


if __name__ == "__main__":
    app()
