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

"""The behavior gate: one Scan per fixture, projected, compared against a file.

Carries no pytest marker, and its path contains no ``integration`` segment, so
it runs under ``make test-unit``. Both matter -- see ``tests/behavior/__init__``.

A mismatch is a real behavior change. Snapshots are only ever rewritten by
``make update-snapshots``, in their own commit.

The module is partitioned deliberately. Tests that hold *behavior* still run
across the whole corpus; tests that assert something about a measured *shape*
-- a colliding sort key, a non-empty finding list, a first SARIF run -- stay
pinned to ``REFERENCE_FIXTURE``, because parametrizing them would turn them
vacuous on the fixtures that lack that shape. The out-of-process determinism
checks compare the whole corpus using three child interpreters in total, not
three per fixture.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from skillspector import framework
from tests.behavior import projection as proj

FIXTURE = proj.REFERENCE_FIXTURE
REPO_ROOT = Path(__file__).resolve().parents[2]

# Every corpus entry, as a parametrization. The id is the corpus name, so a
# failure names the fixture that changed behavior.
CORPUS_PARAMS = pytest.mark.parametrize("fixture", proj.CORPUS_NAMES, ids=proj.CORPUS_NAMES)


@pytest.fixture(scope="module")
def scan_once() -> Callable[[str], dict[str, Any]]:
    """Return a memoized "Scan this fixture once" callable.

    Scanning lazily, one fixture at a time, is what keeps a failure attributable:
    eagerly building every one would surface an error scanning the seventeenth
    fixture inside whichever parametrization happened to run first.
    """
    scanned: dict[str, dict[str, Any]] = {}

    def scan(name: str) -> dict[str, Any]:
        if name not in scanned:
            scanned[name] = proj.scan(proj.CORPUS[name])
        return scanned[name]

    return scan


# --------------------------------------------------------------------------- #
# The gate itself
# --------------------------------------------------------------------------- #


@CORPUS_PARAMS
def test_scan_matches_committed_snapshot(
    fixture: str, scan_once: Callable[[str], dict[str, Any]]
) -> None:
    """The Scan's projection equals the committed snapshot, for every fixture.

    Reads through ``load_snapshot``, which is what makes the deleted- and
    corrupt-snapshot tests below cover the gate rather than a helper beside it.
    """
    assert scan_once(fixture) == proj.load_snapshot(fixture)


@CORPUS_PARAMS
def test_committed_snapshot_is_canonically_serialized(fixture: str) -> None:
    """The file on disk is byte-for-byte what ``make update-snapshots`` writes.

    Without this, a hand-edit that reflowed a file would pass the gate above
    and then show up as churn in the next regeneration's diff.
    """
    committed = proj.snapshot_path(fixture).read_text(encoding="utf-8")
    assert proj.serialize(proj.load_snapshot(fixture)) == committed


def test_this_test_module_is_outside_the_auto_marked_path() -> None:
    """The gate must stay off any path that carries the ``integration`` marker.

    ``tests/integration/conftest.py`` applies that marker by path substring and
    ``addopts`` deselects it, so a move under that tree would silently retire
    the gate instead of failing.
    """
    assert "integration" not in str(Path(__file__).relative_to(REPO_ROOT))


def test_missing_snapshot_fails_rather_than_regenerating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deleted snapshot raises."""
    monkeypatch.setattr(proj, "SNAPSHOT_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        proj.load_snapshot(FIXTURE)


def test_corrupt_snapshot_fails_rather_than_regenerating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupt snapshot raises; the corruption is not silently overwritten."""
    monkeypatch.setattr(proj, "SNAPSHOT_DIR", tmp_path)
    corrupt = tmp_path / f"{FIXTURE}.json"
    corrupt.write_text('{"findings": [', encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        proj.load_snapshot(FIXTURE)
    assert corrupt.read_text(encoding="utf-8") == '{"findings": ['


# --------------------------------------------------------------------------- #
# The corpus: every leaf fixture in, every family parent out, nothing orphaned
# --------------------------------------------------------------------------- #


def _fixture_leaves() -> set[str]:
    """Discover the leaf scan targets on disk, independently of ``CORPUS``.

    A leaf is a fixture directory that is neither one of the family containers
    nor one of the non-target directories. It is found here by walking the tree
    rather than by reading ``CORPUS``, so a fixture added without a snapshot
    fails the gate instead of joining silently.
    """
    leaves: set[str] = set()
    for path in proj.FIXTURES_DIR.iterdir():
        if not path.is_dir() or path.name in proj.NON_TARGET_DIRS:
            continue
        if path.name in proj.FAMILY_PARENTS:
            leaves.update(f"{path.name}/{child.name}" for child in path.iterdir() if child.is_dir())
        else:
            leaves.add(path.name)
    return leaves


def test_the_corpus_is_exactly_the_leaf_fixture_directories() -> None:
    """Adding a fixture without a snapshot fails here rather than passing."""
    assert set(proj.CORPUS_NAMES) == _fixture_leaves()


def test_the_corpus_matches_the_measured_target_count() -> None:
    """The count is asserted so a silent shrink cannot masquerade as a pass.

    The literal lives here and nowhere else in the tests: growing the corpus
    means changing this one number, deliberately, alongside the new snapshot.
    """
    assert len(proj.CORPUS_NAMES) == 38
    assert len(set(proj.CORPUS_NAMES)) == 38


def test_every_family_parent_is_excluded_and_is_really_a_container() -> None:
    """The three parents stay out, and the reason they are out still holds.

    They are excluded for being fixture-layout containers rather than Skills, so
    the control is that none of them bears a ``SKILL.md`` of its own while each
    holds child directories that do.
    """
    for parent in proj.FAMILY_PARENTS:
        directory = proj.FIXTURES_DIR / parent
        assert directory.is_dir()
        assert not (directory / "SKILL.md").exists()
        assert any((child / "SKILL.md").exists() for child in directory.iterdir())
        assert parent not in proj.CORPUS_NAMES


def test_every_non_target_directory_is_excluded_and_is_really_not_a_target() -> None:
    """The non-target directories stay out, and the reason they are out still holds.

    They are excluded for holding sample inputs rather than anything scannable,
    so the control is what every corpus member has and these do not: a
    ``SKILL.md``, a Framework manifest, or child directories. A real fixture
    dropped into one of these fails here rather than being skipped.

    "Framework manifest" is asked of ``framework`` rather than restated as a
    list of file names. Restating it would leave this control passing while
    silently ceasing to discriminate the day a Framework gains a manifest kind,
    and it would miss ``build.gradle.kts``, which ``framework`` matches by prefix
    rather than by literal.
    """
    for name in proj.NON_TARGET_DIRS:
        directory = proj.FIXTURES_DIR / name
        assert directory.is_dir()
        assert not any(
            child.name == "SKILL.md"
            or framework._is_jvm_build_file(child.name)
            or framework._is_python_requirement_file(child.name)
            for child in directory.iterdir()
        ), (
            f"{name} now carries a manifest, so it may be a scan target -- "
            "drop it from NON_TARGET_DIRS and give it a snapshot."
        )
        assert not any(child.is_dir() for child in directory.iterdir()), (
            f"{name} now holds child directories, so it may be a family parent -- "
            "move it to FAMILY_PARENTS or give its children snapshots."
        )
        assert name not in proj.CORPUS_NAMES


@CORPUS_PARAMS
def test_every_corpus_entry_points_at_a_real_directory(fixture: str) -> None:
    assert proj.CORPUS[fixture].is_dir()


def test_no_snapshot_file_is_orphaned() -> None:
    """Every committed snapshot belongs to a corpus entry, and vice versa."""
    committed = {
        str(path.relative_to(proj.SNAPSHOT_DIR).with_suffix(""))
        for path in proj.SNAPSHOT_DIR.rglob("*.json")
    }
    assert committed == set(proj.CORPUS_NAMES)


def test_the_snapshot_layout_mirrors_the_fixture_layout() -> None:
    """A nested fixture's snapshot is nested the same way."""
    nested = [name for name in proj.CORPUS_NAMES if "/" in name]
    assert nested, "expected the family fixtures to nest"
    for name in nested:
        assert proj.snapshot_path(name).relative_to(proj.SNAPSHOT_DIR) == Path(f"{name}.json")


def test_mcp_registry_is_in_the_corpus_without_a_manifest() -> None:
    """The anonymous-Skill result now says why the Manifest is empty -- see #11.

    ``mcp_registry`` bears no ``SKILL.md``. Its Manifest stays empty, because the
    fix is additive; what changed is that the snapshot now records that the
    emptiness is an absent Skill rather than a Skill declaring nothing.
    """
    assert "mcp_registry" in proj.CORPUS_NAMES
    assert not (proj.CORPUS["mcp_registry"] / "SKILL.md").exists()
    snapshot = proj.load_snapshot("mcp_registry")
    assert snapshot["manifest"] == {}
    assert snapshot["manifest_status"] == "absent"


def test_langchain4j_detection_reports_its_analyzer_and_costs_only_that_row() -> None:
    """The one snapshot #52 changed, and the three figures it left alone.

    The Analyzer now opens the build file and says so, where the Scan used to
    carry nothing about it at all. That row is the entire cost: ``completed`` is
    non-limiting, so the fixture's completeness flag, execution flag and
    coverage figure read exactly as they did while the Analyzer was silent. The
    flag is ``False`` because three semantic Analyzers are disabled without
    credentials -- which is what ``limitations`` names, and it names nothing
    else.
    """
    completeness = proj.load_snapshot("langchain4j_detection")["analysis_completeness"]
    statuses = {status["analyzer_id"]: status for status in completeness["analyzer_statuses"]}

    assert statuses["framework_langchain4j"]["status"] == "completed"
    assert statuses["framework_langchain4j"]["planned_work"] == 1
    assert statuses["framework_langchain4j"]["completed"] == 1
    assert completeness["is_complete"] is False
    assert completeness["execution_successful"] is True
    assert completeness["coverage_percent"] == 100.0
    assert (
        completeness["limitations"] == ["Analyzer was disabled by the requested configuration."] * 3
    )


def test_langchain4j_tool_mode_proves_the_non_shell_rules() -> None:
    """The Rules that are not about shell mode fire without the shell module.

    Issue #53. Every Rule used to be demonstrated only inside
    ``langchain4j_shell_skill``, whose build file declares
    ``langchain4j-experimental-skills-shell``. So the ordinary, recommended way
    to use Skills -- Tool mode, reaching them through registered tools with
    content preloaded -- was analysed correctly and nothing proved it, and a
    change that coupled the Analyzer to the shell artifact would have passed the
    gate.

    Three Rules, not four. ``L4J-WORKDIR``'s receiver is
    ``RunShellCommandToolConfig``, the shell configuration type this fixture
    keeps out of its tree, so a Tool mode application cannot reach it. That is a
    property of the fixture rather than of the Rule: driven on its own, with
    ``ShellSkills`` referenced nowhere, ``L4J-WORKDIR`` fires by itself.
    """
    snapshot = proj.load_snapshot("langchain4j_tool_mode")
    fired = {finding["rule_id"] for finding in snapshot["findings"]}

    assert {"L4J-UNRESOLVED", "L4J-TOOL-DESC", "L4J-MCP-FILTER"} <= fired
    assert "L4J-SHELL" not in fired
    assert "L4J-WORKDIR" not in fired
    assert snapshot["framework"] == "langchain4j"


def test_langchain4j_tool_mode_pins_the_silence_of_its_benign_files() -> None:
    """A false positive on ordinary Tool mode code fails the gate.

    The fixture is a negative control as well as a positive one. Its wiring
    class, its repository class and its ``SKILL.md`` carry nothing to report, and
    naming them here means a future Rule that starts matching ordinary
    LangChain4j code turns this red rather than quietly widening the corpus's
    Findings.
    """
    snapshot = proj.load_snapshot("langchain4j_tool_mode")
    reported = {finding["file"] for finding in snapshot["findings"]}

    assert "src/main/java/com/example/SupportAgent.java" not in reported
    assert "src/main/java/com/example/OrderRepository.java" not in reported
    assert "src/main/resources/skills/order-triage/SKILL.md" not in reported
    assert "pom.xml" not in reported


def test_langchain4j_tool_mode_costs_only_the_rows_it_opens() -> None:
    """Its completeness flag, execution flag and coverage figure.

    ``planned_work`` is six rather than seven: the ``SKILL.md`` under the
    conventional classpath layout is a Component of the Scan but not an
    applicable file for this Analyzer, which opens Java compilation units and
    JVM build files.

    The flag is ``False`` because four Analyzers are disabled without
    credentials -- what ``limitations`` names, and all it names. Four rather than
    ``langchain4j_detection``'s three: this fixture produces Findings, so
    ``meta_analyzer`` has something to meta-analyze and reports ``disabled``
    where the Findings-free fixture reports ``not_applicable``, which is not a
    limitation. ``langchain4j_shell_skill`` names four for the same reason.
    """
    completeness = proj.load_snapshot("langchain4j_tool_mode")["analysis_completeness"]
    statuses = {status["analyzer_id"]: status for status in completeness["analyzer_statuses"]}

    assert statuses["framework_langchain4j"]["status"] == "completed"
    assert statuses["framework_langchain4j"]["planned_work"] == 6
    assert statuses["framework_langchain4j"]["completed"] == 6
    assert statuses["framework_langchain4j"]["unaccounted"] == 0
    assert completeness["is_complete"] is False
    assert completeness["execution_successful"] is True
    assert completeness["coverage_percent"] == 100.0
    assert (
        completeness["limitations"] == ["Analyzer was disabled by the requested configuration."] * 4
    )
    assert statuses["meta_analyzer"]["status"] == "disabled"


# --------------------------------------------------------------------------- #
# What the projection carries, and what it drops
# --------------------------------------------------------------------------- #


@CORPUS_PARAMS
def test_committed_snapshot_carries_the_projected_keys_only(fixture: str) -> None:
    """The ADR 0003 keys, less any conditionally carried one; none excluded."""
    snapshot = proj.load_snapshot(fixture)
    assert set(snapshot) <= set(proj.PROJECTED_STATE_KEYS)
    assert set(proj.PROJECTED_STATE_KEYS) - set(snapshot) <= set(proj.OMITTED_WHEN)
    assert not set(snapshot) & set(proj.EXCLUDED_STATE_KEYS)


def test_the_conditionally_carried_key_is_carried_by_some_fixture_and_not_others() -> None:
    """The omission rule is a real partition of the corpus, not a dead branch.

    Without both halves the rule would be vacuous: a key no snapshot carries
    proves nothing about a Scan whose Manifest is not ``present``, and a key
    every snapshot carries proves nothing about the omission.
    """
    for key, omitted_value in proj.OMITTED_WHEN.items():
        carried = {name for name in proj.CORPUS_NAMES if key in proj.load_snapshot(name)}
        assert carried, f"no snapshot carries {key}"
        assert carried != set(proj.CORPUS_NAMES), f"every snapshot carries {key}"
        for name in carried:
            assert proj.load_snapshot(name)[key] != omitted_value


@CORPUS_PARAMS
def test_committed_snapshot_carries_neither_stripped_field(fixture: str) -> None:
    """Neither ``finding_id`` nor the driver version survives into the file."""
    snapshot = proj.load_snapshot(fixture)
    assert all("finding_id" not in finding for finding in snapshot["findings"])
    for run in snapshot["sarif_report"]["runs"]:
        assert "version" not in run["tool"]["driver"]
        for result in run["results"]:
            assert "findingId" not in result["properties"]


def test_stripping_removes_fields_that_are_actually_there() -> None:
    """Guard against a vacuous strip: the raw Scan carries all three fields.

    Pinned to the reference fixture. On a fixture with no Finding every
    assertion below is vacuously true, which is exactly what this test exists
    to rule out.
    """
    state = proj.scan_state(proj.CORPUS[FIXTURE])
    assert state["findings"], "the control needs a fixture that produces Findings"
    assert all(finding.finding_id for finding in state["findings"])
    run = state["sarif_report"]["runs"][0]
    assert run["tool"]["driver"]["version"]
    assert all("findingId" in result["properties"] for result in run["results"])


def test_stripping_leaves_neighbouring_version_fields_alone() -> None:
    """Stripping is addressed by path, so SARIF's own version fields survive."""
    snapshot = proj.load_snapshot(FIXTURE)
    assert snapshot["sarif_report"]["version"]
    assert snapshot["sarif_report"]["runs"][0]["tool"]["driver"]["name"]


# --------------------------------------------------------------------------- #
# Sorting: named key plus canonical-serialization tie-breaker
# --------------------------------------------------------------------------- #


def _named_finding_keys(snapshot: Mapping[str, Any]) -> list[tuple[Any, ...]]:
    return [proj._finding_key(finding) for finding in snapshot["findings"]]


def test_named_finding_key_collides_so_the_tie_break_is_exercised() -> None:
    """``malicious_skill`` holds two Findings the named key cannot separate.

    This is why the key carries the canonical serialization as its final
    component. If the fixture ever stops colliding, the tie-break stops being
    covered -- so the collision is asserted rather than assumed.
    """
    keys = _named_finding_keys(proj.load_snapshot(FIXTURE))
    assert len(keys) - len(set(keys)) >= 1, "no colliding pair left to exercise"


@CORPUS_PARAMS
def test_every_list_is_ordered_by_named_key_then_serialization(fixture: str) -> None:
    """Sorting a committed snapshot again is a no-op, at every depth."""
    snapshot = proj.load_snapshot(fixture)
    assert proj._sort(snapshot, "$") == snapshot


def test_tied_elements_are_separated_by_their_serialization() -> None:
    """The colliding pair is ordered, and ordered by the full element."""
    snapshot = proj.load_snapshot(FIXTURE)
    findings = snapshot["findings"]
    keys = _named_finding_keys(snapshot)
    tied = [i for i in range(len(keys) - 1) if keys[i] == keys[i + 1]]
    assert tied, "expected an adjacent tied pair"
    for index in tied:
        left, right = findings[index], findings[index + 1]
        assert left != right, "a genuinely identical pair cannot produce a diff"
        assert proj._canonical(left) < proj._canonical(right)


def test_the_sort_orders_a_tied_pair_regardless_of_input_order() -> None:
    """The tie-break is total, not merely stable.

    Sorting is stable, so a named key that ties would leave the pair in whatever
    order the producer emitted -- exactly the nondeterminism the sort exists to
    remove. Feeding the real colliding pair in both orders is what distinguishes
    a total key from a stable one: without the serialization tie-breaker, this
    reverses with its input.
    """
    findings = proj.load_snapshot(FIXTURE)["findings"]
    keys = _named_finding_keys({"findings": findings})
    pair = next(
        [findings[i], findings[i + 1]] for i in range(len(keys) - 1) if keys[i] == keys[i + 1]
    )
    assert proj._sort(pair, "$.findings") == proj._sort(list(reversed(pair)), "$.findings")


def test_the_unexercised_sort_keys_are_still_unexercised() -> None:
    """``ledger_exceptions`` and ``scope_exclusions`` are empty in every fixture.

    Their named key has therefore still never ordered anything, which is a
    stated coverage limit rather than a defect. Asserted so that the day a
    fixture populates one, this fails and the limit is revisited instead of
    quietly becoming false.
    """
    for name in proj.CORPUS_NAMES:
        completeness = proj.load_snapshot(name)["analysis_completeness"]
        assert not completeness.get("ledger_exceptions")
        assert not completeness.get("scope_exclusions")


# --------------------------------------------------------------------------- #
# Determinism, across runs and across processes
# --------------------------------------------------------------------------- #


@CORPUS_PARAMS
def test_two_consecutive_scans_produce_identical_projections(
    fixture: str, scan_once: Callable[[str], dict[str, Any]]
) -> None:
    """Two Scans of one Skill in one process project byte-identically.

    The first Scan is the memoized one the gate already compared against the
    committed file; the second is fresh. Comparing the serializations rather
    than the dictionaries is deliberate -- byte-identity is the property the
    committed file depends on, and it is strictly stronger than equality.
    """
    first = proj.serialize(scan_once(fixture))
    second = proj.serialize(proj.scan(proj.CORPUS[fixture]))
    assert first == second


# The child environment is built from nothing, rather than copied and pruned:
# nothing carried over can hold a credential.
CREDENTIAL_FREE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.environ.get("HOME", "/tmp"),
}


def _run_out_of_process(*, hash_seed: str, provider: str) -> dict[str, Any]:
    """Project the whole corpus in a fresh interpreter under a controlled env.

    A separate process is required for two of these checks. ``PYTHONHASHSEED``
    is fixed before the interpreter starts, and the provider that decides
    ``model_config`` is resolved when ``skillspector.constants`` is imported --
    neither can be varied inside a running test.

    The environment is built from nothing but ``PATH`` and ``HOME``, so no API
    key of any kind is reachable: the Scan runs with no LLM credentials.

    ``--emit-all`` covers every fixture per spawn, so widening the corpus
    left the interpreter-spawn count at three for the module.
    """
    env = dict(CREDENTIAL_FREE_ENV)
    env["PYTHONHASHSEED"] = hash_seed
    env["SKILLSPECTOR_PROVIDER"] = provider
    # Guards this helper against a later edit widening the child environment.
    assert set(env) == {"PATH", "HOME", "PYTHONHASHSEED", "SKILLSPECTOR_PROVIDER"}

    completed = subprocess.run(
        [sys.executable, "-m", "tests.behavior.regenerate", "--emit-all"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.fixture(scope="module")
def reference_run() -> dict[str, Any]:
    return _run_out_of_process(hash_seed="0", provider="openai")


@pytest.fixture(scope="module")
def other_hash_seed_run() -> dict[str, Any]:
    return _run_out_of_process(hash_seed="1", provider="openai")


@pytest.fixture(scope="module")
def other_provider_run() -> dict[str, Any]:
    return _run_out_of_process(hash_seed="0", provider="anthropic")


def test_the_out_of_process_run_covers_the_whole_corpus(reference_run: dict[str, Any]) -> None:
    """The three determinism checks below are corpus-wide, not fixture-wide."""
    assert set(reference_run["projections"]) == set(proj.CORPUS_NAMES)


def test_scan_completes_without_llm_credentials(reference_run: dict[str, Any]) -> None:
    """The Scan runs to a projection in an environment holding no API key.

    Pinned to the reference fixture for the Findings assertion: a fixture that
    produces none would make it vacuous. Every other fixture is still shown to
    have completed by the corpus-coverage test above.
    """
    projection = reference_run["projections"][FIXTURE]
    assert projection["risk_score"] >= 0
    assert projection["findings"]


@CORPUS_PARAMS
def test_projection_matches_snapshot_out_of_process(
    fixture: str, reference_run: dict[str, Any]
) -> None:
    """A fresh interpreter reproduces every committed snapshot."""
    assert reference_run["projections"][fixture] == proj.load_snapshot(fixture)


@CORPUS_PARAMS
def test_a_different_hash_seed_produces_the_same_projection(
    fixture: str, reference_run: dict[str, Any], other_hash_seed_run: dict[str, Any]
) -> None:
    """No set-derived ordering leaks into any fixture's projection."""
    assert other_hash_seed_run["projections"][fixture] == reference_run["projections"][fixture]


@CORPUS_PARAMS
def test_two_providers_produce_the_same_projection(
    fixture: str, reference_run: dict[str, Any], other_provider_run: dict[str, Any]
) -> None:
    """``model_config`` is excluded, demonstrated against two live settings.

    The control comes first: the two runs must genuinely resolve different model
    configurations, or the equality below would prove nothing.
    """
    assert other_provider_run["model_config"] != reference_run["model_config"]
    assert other_provider_run["projections"][fixture] == reference_run["projections"][fixture]
