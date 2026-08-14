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

"""What ``structure_agent_skills_spec`` reports, and what it stays silent about.

Every Rule is asserted in both directions -- a conforming Manifest raises nothing
of it, a violating one raises exactly it -- because a Rule that never fires and a
Rule that always fires both pass a one-sided assertion.

Nothing here adds a fixture directory. Every input is written into ``tmp_path``
or handed to the node as state, which keeps the Behavior Snapshot corpus exactly
as it was: a new fixture would add a snapshot file, and the whole claim of this
Analyzer is that with the flag absent no snapshot moves at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from skillspector.agent_skills_spec import (
    RULES,
    SCORED_BY_DEFAULT,
    UNSCORED_NOTE,
    SpecChecks,
    in_bundled_directory,
)
from skillspector.cli import app
from skillspector.inspection_ledger import (
    AnalyzerStatus,
    LedgerOutcome,
    LedgerReason,
    LedgerRecordType,
    ledger_event,
)
from skillspector.models import Finding
from skillspector.nodes.analyzers.structure_agent_skills_spec import ANALYZER_ID, node
from skillspector.suppression import finding_fingerprint

CONFORMING = (
    "---\nname: weather-report\ndescription: Reports the weather. Use it when asked "
    "about weather.\n---\n\nSummarise the forecast.\n"
)


def _state(
    manifests: dict[str, str],
    *,
    spec_checks: str | None = SpecChecks.ADVISORY.value,
    skill_path: str = "/skills/weather-report",
    temp_dir: str | None = None,
    sizes: dict[str, int] | None = None,
    other_components: tuple[str, ...] = (),
    unreadable: tuple[str, ...] = (),
    excluded: tuple[tuple[str, LedgerReason], ...] = (),
) -> dict[str, object]:
    """Graph state for a Scan whose Manifests are *manifests*, path to content.

    *unreadable* names Manifests that are Components of the Scan but never
    reached ``file_cache`` -- the shape a read error leaves behind.

    *excluded* names paths the Scan recorded a scope boundary for, each with the
    reason ``build_context._walk_skill_files`` gives it. The spellings are that
    walk's own, measured from a real Scan: a hidden file bare, a pruned directory
    with a trailing slash.
    """
    sizes = sizes or {}
    file_cache = {path: content for path, content in manifests.items() if path not in unreadable}
    component_metadata = [
        {"path": path, "size_bytes": sizes.get(path, len(content.encode()))}
        for path, content in manifests.items()
    ]
    component_metadata.extend({"path": path, "size_bytes": 1} for path in other_components)
    state: dict[str, object] = {
        "skill_path": skill_path,
        "temp_dir_for_cleanup": temp_dir,
        "file_cache": file_cache,
        "component_metadata": component_metadata,
        "inspection_ledger": [
            ledger_event(
                outcome=LedgerOutcome.OUT_OF_SCOPE,
                record_type=LedgerRecordType.SCOPE_BOUNDARY,
                phase="discovery",
                path=path,
                reason=reason,
            )
            for path, reason in excluded
        ],
    }
    if spec_checks is not None:
        state["spec_checks"] = spec_checks
    return state


def _rule_ids(response: dict) -> list[str]:
    return [finding.rule_id for finding in response["findings"]]


def _one_manifest(content: str, **kwargs: object) -> dict:
    """The node's response for a single-Skill Scan whose Manifest is *content*."""
    return node(_state({"SKILL.md": content}, **kwargs))  # type: ignore[arg-type]


class TestTheGate:
    """``--spec-checks off`` is the flag's absence, and its absence is silence."""

    def test_off_returns_nothing_at_all(self) -> None:
        """No Finding, no Work Item, no Analyzer Status -- the ADR 0002 shape.

        This is the whole behavior-preservation argument. An Analyzer Status
        alone would reach ``analysis_completeness``, which the Behavior Snapshot
        projects, and would move every committed snapshot.
        """
        response = _one_manifest("not a manifest at all", spec_checks=SpecChecks.OFF.value)

        assert response == {"findings": []}

    def test_an_absent_key_is_off(self) -> None:
        """A Scan that predates the flag carries no key, and must behave as before."""
        assert _one_manifest("not a manifest at all", spec_checks=None) == {"findings": []}

    def test_an_unrecognized_mode_is_off(self) -> None:
        """Graph state is untyped, so an unknown spelling must fail closed."""
        assert _one_manifest("not a manifest at all", spec_checks="Advisory!") == {"findings": []}

    def test_advisory_reports_the_unscored_rules_at_their_honest_confidence(self) -> None:
        """Reported, deliberately not scored -- and the *run* says which, not the Finding.

        ``confidence`` answers "how certain is the Scanner that this is real", and
        that answer does not change with the mode that asked. The mode is carried
        in ``unscored_rule_ids`` beside the Findings.
        """
        response = _one_manifest("no declaration here")

        assert _rule_ids(response) == ["SPEC-1"]
        assert response["findings"][0].confidence == RULES["SPEC-1"].confidence > 0.0
        assert "SPEC-1" in response["unscored_rule_ids"]

    def test_strict_scores_the_same_rule(self) -> None:
        """The only difference between the two modes is which ids the run exempts."""
        response = _one_manifest("no declaration here", spec_checks=SpecChecks.STRICT.value)

        assert _rule_ids(response) == ["SPEC-1"]
        assert response["findings"][0].confidence == RULES["SPEC-1"].confidence > 0.0
        assert response["unscored_rule_ids"] == []

    def test_the_same_finding_is_identical_in_both_modes(self) -> None:
        """Byte-for-byte the same Finding, which is what the fingerprint binds to.

        The defect the ``confidence = 0.0`` mechanism caused, asserted at its
        source: two modes must not describe one defect two ways, because
        ``suppression.finding_fingerprint`` hashes every field below.
        """
        advisory = _one_manifest("no declaration here")["findings"][0].to_dict()
        strict = _one_manifest("no declaration here", spec_checks=SpecChecks.STRICT.value)[
            "findings"
        ][0].to_dict()
        # The only field a fresh `uuid4()` makes differ, and the one field
        # `finding_fingerprint` does not hash.
        advisory.pop("finding_id")
        strict.pop("finding_id")

        assert advisory == strict

    def test_the_note_naming_the_flag_travels_with_the_ids(self) -> None:
        """The remedy sentence is published here, because it names ``--spec-checks``.

        ``report`` renders it verbatim and receives the ids as an opaque set, so
        this Analyzer is the only place that may name its own flag. Asserted on
        both past-the-gate paths -- the one that found Manifests and the one that
        found none -- since either can reach the report.
        """
        assert _one_manifest("no declaration here")["unscored_rule_note"] == UNSCORED_NOTE
        assert "--spec-checks strict" in UNSCORED_NOTE

        no_manifest = node(_state({}, other_components=("README.md",)))  # type: ignore[arg-type]
        assert no_manifest["unscored_rule_note"] == UNSCORED_NOTE

    def test_the_unscored_ids_are_the_twelve_the_catalogue_names(self) -> None:
        """The key published to state is the catalogue's own split, not a re-derivation."""
        response = _one_manifest("no declaration here")

        assert set(response["unscored_rule_ids"]) == set(RULES) - SCORED_BY_DEFAULT

    def test_a_rule_scored_by_default_scores_in_advisory_too(self) -> None:
        """The five with a runtime consequence carry their confidence in both modes."""
        response = _one_manifest(CONFORMING, skill_path="/skills/elsewhere")

        assert _rule_ids(response) == ["SPEC-4"]
        assert response["findings"][0].confidence == RULES["SPEC-4"].confidence > 0.0


class TestApplicability:
    """What the Analyzer opens, and what it says when it opens nothing."""

    def test_a_scan_with_no_manifest_is_not_applicable(self) -> None:
        """A directory declaring no Skill: reported, never silent, past the gate."""
        response = node(_state({}, other_components=("README.md",)))  # type: ignore[arg-type]

        assert response["findings"] == []
        assert response["analyzer_status_events"][0]["status"] == AnalyzerStatus.NOT_APPLICABLE
        assert response["analyzer_status_events"][0]["reason_code"] == (
            LedgerReason.NO_APPLICABLE_FILES
        )
        assert "inspection_ledger" not in response

    def test_every_manifest_opened_gets_a_row(self) -> None:
        """An absence of Findings has to be distinguishable from an absence of inspection."""
        response = node(
            _state(
                {"SKILL.md": CONFORMING, "sub/SKILL.md": CONFORMING}, skill_path="/x/weather-report"
            )  # type: ignore[arg-type]
        )

        paths = [event["path"] for event in response["inspection_ledger"]]
        assert paths == ["SKILL.md", "sub/SKILL.md"]
        assert response["analyzer_status_events"][0]["status"] == AnalyzerStatus.COMPLETED

    def test_a_manifest_that_never_reached_the_cache_is_skipped_not_judged(self) -> None:
        """An unreadable Manifest is uninspected, and must not read as conforming."""
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING}, unreadable=("SKILL.md",), skill_path="/x/weather-report"
            )
        )

        assert response["findings"] == []
        assert response["inspection_ledger"][0]["outcome"] == LedgerOutcome.SKIPPED
        assert response["inspection_ledger"][0]["reason_code"] == LedgerReason.MISSING_FILE_CACHE
        assert response["analyzer_status_events"][0]["status"] == AnalyzerStatus.DEGRADED

    def test_every_finding_is_accounted_for_by_the_component_it_came_from(self) -> None:
        """The ledger's emitted ids must cover every Finding the Analyzer returned."""
        response = node(
            _state(  # type: ignore[arg-type]
                {"a/SKILL.md": CONFORMING, "b/SKILL.md": CONFORMING}, skill_path="/x/anon"
            )
        )

        emitted = {
            finding_id
            for event in response["inspection_ledger"]
            for finding_id in event["emitted_finding_ids"]
        }
        assert emitted == {finding.finding_id for finding in response["findings"]}
        assert response["findings"] != []

    def test_a_directory_shipping_both_manifest_spellings_is_one_skill(self) -> None:
        """``MANIFEST_FILENAMES`` is a precedence, not two Skills in one directory.

        ``build_context._parse_manifest`` reads ``SKILL.md`` then ``skill.md``
        and stops at the first, so the shadowed spelling is not the Manifest of
        anything. Read as two, every Rule reported twice and ``SPEC-17`` -- a
        scored Rule -- reported a collision between a directory and itself.
        """
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING, "skill.md": CONFORMING},
                skill_path="/skills/weather-report",
            )
        )

        assert _rule_ids(response) == []
        assert [event["path"] for event in response["inspection_ledger"]] == ["SKILL.md"]

    def test_the_shadowed_spelling_is_not_inspected_in_a_nested_directory_either(self) -> None:
        """The unit is the containing directory, at any depth of the Scan."""
        wrong_name = CONFORMING.replace("name: weather-report", "name: tide-report")
        response = node(
            _state(  # type: ignore[arg-type]
                {"sub/SKILL.md": wrong_name, "sub/skill.md": wrong_name},
                skill_path="/x/anon",
            )
        )

        assert _rule_ids(response) == ["SPEC-4"]
        assert [event["path"] for event in response["inspection_ledger"]] == ["sub/SKILL.md"]

    def test_a_lone_lowercase_manifest_is_still_the_manifest(self) -> None:
        """Precedence only decides a tie; with no ``SKILL.md`` there is none to decide."""
        response = node(
            _state(  # type: ignore[arg-type]
                {"skill.md": CONFORMING}, skill_path="/skills/weather-report"
            )
        )

        assert _rule_ids(response) == []
        assert [event["path"] for event in response["inspection_ledger"]] == ["skill.md"]

    @pytest.mark.parametrize("bundled", ["references", "scripts", "assets"])
    def test_a_manifest_a_skill_bundles_is_not_a_skill_directory(self, bundled: str) -> None:
        """The three directories the specification defines for what a Skill bundles.

        A Skill that ships a template Manifest under one of them used to earn
        twenty scored points from a Skill that conforms: ``SPEC-4`` against the
        directory name ``references``, and ``SPEC-17`` against the very Skill
        that ships it. Neither is inspected now, so the ledger has no row for it
        either -- applicability is decided once, not per Rule.
        """
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING, f"{bundled}/SKILL.md": CONFORMING},
                skill_path="/skills/weather-report",
            )
        )

        assert _rule_ids(response) == []
        assert [event["path"] for event in response["inspection_ledger"]] == ["SKILL.md"]

    def test_a_manifest_the_specification_does_not_place_is_still_a_skill_directory(self) -> None:
        """The residue this narrowing leaves, asserted rather than implied.

        Applicability is a filename plus a path segment, not a loader's notion of
        a skill directory, so a Manifest parked somewhere the specification names
        no convention for is still read as one. Issue #121 carries it; this test
        is what will fail when it is closed.
        """
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING, "docs/examples/SKILL.md": CONFORMING},
                skill_path="/skills/weather-report",
            )
        )

        assert _rule_ids(response) == ["SPEC-4", "SPEC-17"]

    def test_the_exclusion_reads_the_segments_above_the_manifest_and_not_the_path_itself(
        self,
    ) -> None:
        """ "Beneath a bundled directory" is not "is one", and the guard is the slice.

        Asked directly, because through the node the two readings agree: every
        path the node offers ends in a Manifest filename, so the last segment is
        never a bundled-directory name and dropping the slice changes no verdict. The
        contract the docstring states is nonetheless the narrower one, and a
        caller reaching for this helper with a directory path is what would find
        out.
        """
        assert in_bundled_directory("references/SKILL.md")
        assert in_bundled_directory("assets/templates/SKILL.md")
        assert not in_bundled_directory("references")
        assert not in_bundled_directory("SKILL.md")
        assert not in_bundled_directory("docs/examples/SKILL.md")

    def test_a_skill_scanned_at_a_bundled_directorys_own_name_is_unaffected(self) -> None:
        """A Scan rooted at ``references/`` reads its own Manifest, not an excluded one."""
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING.replace("name: weather-report", "name: references")},
                skill_path="/skills/references",
            )
        )

        assert _rule_ids(response) == []
        assert [event["path"] for event in response["inspection_ledger"]] == ["SKILL.md"]


class TestEachRule:
    """Both directions, one Rule at a time."""

    def test_a_conforming_manifest_raises_nothing(self) -> None:
        """The control every case below is measured against."""
        response = _one_manifest(CONFORMING)

        assert response["findings"] == []
        assert response["analyzer_status_events"][0]["status"] == AnalyzerStatus.COMPLETED

    def test_spec_1_no_declaration_block(self) -> None:
        assert _rule_ids(_one_manifest("# Just a heading\n")) == ["SPEC-1"]

    def test_spec_1_a_file_whose_first_line_is_not_the_opening_delimiter(self) -> None:
        """A body that happens to hold a horizontal rule is not a declaration block.

        Written to reach the opening-delimiter test on its own: everything after
        the rule *would* parse as a mapping, so an Analyzer that only looked for
        a closing delimiter would read this file's prose as a declaration and
        report two missing fields instead of the one missing block.
        """
        manifest = "Notes: this skill is experimental\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-1"]

    def test_spec_1_unterminated_declaration_block(self) -> None:
        assert _rule_ids(_one_manifest("---\nname: weather-report\n")) == ["SPEC-1"]

    def test_spec_1_yaml_that_does_not_parse(self) -> None:
        assert _rule_ids(_one_manifest("---\nname: [unclosed\n---\n\nbody\n")) == ["SPEC-1"]

    def test_spec_1_a_block_that_is_not_a_mapping(self) -> None:
        assert _rule_ids(_one_manifest("---\n- one\n- two\n---\n\nbody\n")) == ["SPEC-1"]

    def test_spec_1_silences_every_rule_that_reads_what_it_could_not_read(self) -> None:
        """One unreadable declaration is one defect, not eight missing fields.

        The body Rules go with them: a file whose declaration block never closed
        has no body this Analyzer can say it measured.
        """
        manifest = "---\nname: [unclosed\n---\n\n" + "line\n" * 600

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-1"]

    def test_spec_2_name_missing(self) -> None:
        manifest = "---\ndescription: Reports the weather when asked.\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-2"]

    def test_spec_3_description_missing(self) -> None:
        manifest = "---\nname: weather-report\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-3"]

    def test_spec_4_name_disagrees_with_its_directory(self) -> None:
        assert _rule_ids(_one_manifest(CONFORMING, skill_path="/skills/forecasts")) == ["SPEC-4"]

    def test_spec_4_reads_a_nested_manifests_own_directory(self) -> None:
        """A nested Manifest's directory is inside the tree, so it is always observable."""
        response = node(
            _state({"forecasts/SKILL.md": CONFORMING}, skill_path="/x/anon")  # type: ignore[arg-type]
        )

        assert _rule_ids(response) == ["SPEC-4"]

    def test_spec_4_stays_silent_where_the_directory_is_this_tools_own(self) -> None:
        """A cloned, downloaded or unzipped input sits in a directory nobody declared."""
        response = _one_manifest(
            CONFORMING, skill_path="/tmp/skillspector_ab12/repo", temp_dir="/tmp/skillspector_ab12"
        )

        assert _rule_ids(response) == []

    def test_spec_5_name_outside_the_allowed_charset(self) -> None:
        manifest = CONFORMING.replace("name: weather-report", "name: Weather_Report")

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/Weather_Report")) == ["SPEC-5"]

    @pytest.mark.parametrize("name", ["-weather", "weather-", "weather--report"])
    def test_spec_6_hyphenation(self, name: str) -> None:
        manifest = CONFORMING.replace("name: weather-report", f"name: {name}")

        assert _rule_ids(_one_manifest(manifest, skill_path=f"/s/{name}")) == ["SPEC-6"]

    def test_spec_7_name_over_sixty_four_characters(self) -> None:
        name = "w" * 65
        manifest = CONFORMING.replace("name: weather-report", f"name: {name}")

        assert _rule_ids(_one_manifest(manifest, skill_path=f"/s/{name}")) == ["SPEC-7"]

    def test_spec_7_accepts_exactly_sixty_four(self) -> None:
        name = "w" * 64
        manifest = CONFORMING.replace("name: weather-report", f"name: {name}")

        assert _rule_ids(_one_manifest(manifest, skill_path=f"/s/{name}")) == []

    def test_spec_2_name_declared_empty(self) -> None:
        """The specification's lower bound: "must be 1-64 characters".

        ``SPEC-7`` caps the other end and no charset Rule can speak about a name
        with no characters in it, so without ``SPEC-2`` the only Rule left with
        anything to say about ``name: ""`` is ``SPEC-4``. It is ``SPEC-2`` for
        the same reason ``SPEC-8`` rather than ``SPEC-9`` covers the empty
        ``description``: nothing declared is an absence, not a malformation.

        ``SPEC-4`` is reported *beside* it and not swallowed by it. It is the one
        scored Rule about ``name``, so ending the walk at ``SPEC-2`` made the
        emptiest declaration the cheapest one: ``name: ""`` in ``weather-report/``
        scored nothing while ``name: forecasts`` in the same directory scored.
        """
        manifest = '---\nname: ""\ndescription: Reports the weather when asked.\n---\n\nbody\n'

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/weather-report")) == [
            "SPEC-2",
            "SPEC-4",
        ]

    def test_spec_2_name_declared_as_whitespace(self) -> None:
        """A name of blanks declares no more identity than an empty one."""
        manifest = '---\nname: "   "\ndescription: Reports the weather when asked.\n---\n\nbody\n'

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/weather-report")) == [
            "SPEC-2",
            "SPEC-4",
        ]

    def test_spec_2_an_empty_name_still_scores_where_a_wrong_one_does(self) -> None:
        """The monotonicity the early return broke, asserted as a comparison.

        The emptier declaration must not be the cheaper one. Both are read at the
        confidence ``advisory`` gives them, so this compares what reaches the
        score rather than only which Rules fired.
        """
        empty = '---\nname: ""\ndescription: Reports the weather when asked.\n---\n\nbody\n'
        wrong = CONFORMING.replace("name: weather-report", "name: forecasts")

        def scored(manifest: str) -> float:
            response = _one_manifest(manifest, skill_path="/s/weather-report")
            return sum(finding.confidence for finding in response["findings"])

        assert scored(empty) >= scored(wrong) > 0

    def test_spec_2_a_name_that_is_not_text_stops_there(self) -> None:
        """The boundary the empty case does not move: ``SPEC-4`` compares strings.

        A bare YAML number is not a name a loader registers and not a string
        ``SPEC-4`` can compare against a directory name, so the walk ends at
        ``SPEC-2``. An empty string is a string, which is why it does not.
        """
        manifest = "---\nname: 42\ndescription: Reports the weather when asked.\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/weather-report")) == ["SPEC-2"]

    def test_spec_2_accepts_a_name_of_one_character(self) -> None:
        """The lower bound is one character, so one character conforms."""
        manifest = "---\nname: w\ndescription: Reports the weather when asked.\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/w")) == []

    def test_spec_5_reads_a_trailing_newline_in_the_name(self) -> None:
        """A YAML block scalar carries one, and ``$`` would have matched before it.

        The name is compared against its own directory as well, so the Scan is
        given a directory that cannot be observed and ``SPEC-4`` stays out of it.
        """
        manifest = (
            "---\nname: |\n  weather-report\ndescription: Reports the weather when asked.\n"
            "---\n\nbody\n"
        )

        response = _one_manifest(
            manifest, skill_path="/tmp/skillspector_ab12/repo", temp_dir="/tmp/skillspector_ab12"
        )

        assert _rule_ids(response) == ["SPEC-5"]

    def test_spec_8_description_declared_empty(self) -> None:
        manifest = "---\nname: weather-report\ndescription: '   '\n---\n\nbody\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-8"]

    def test_spec_9_description_over_the_cap(self) -> None:
        manifest = CONFORMING.replace(
            "description: Reports the weather. Use it when asked about weather.",
            f"description: {'d' * 1025}",
        )

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-9"]

    def test_spec_9_accepts_exactly_the_cap(self) -> None:
        manifest = CONFORMING.replace(
            "description: Reports the weather. Use it when asked about weather.",
            f"description: {'d' * 1024}",
        )

        assert _rule_ids(_one_manifest(manifest)) == []

    def test_spec_10_compatibility_over_the_cap(self) -> None:
        manifest = CONFORMING.replace("---\n\n", f"compatibility: {'c' * 501}\n---\n\n")

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-10"]

    def test_spec_10_accepts_a_compatibility_within_it(self) -> None:
        manifest = CONFORMING.replace("---\n\n", f"compatibility: {'c' * 500}\n---\n\n")

        assert _rule_ids(_one_manifest(manifest)) == []

    def test_spec_11_metadata_that_is_not_text_to_text(self) -> None:
        manifest = CONFORMING.replace("---\n\n", "metadata:\n  version: 1\n---\n\n")

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-11"]

    def test_spec_11_accepts_a_text_to_text_mapping(self) -> None:
        manifest = CONFORMING.replace("---\n\n", 'metadata:\n  version: "1"\n---\n\n')

        assert _rule_ids(_one_manifest(manifest)) == []

    def test_spec_12_body_over_five_hundred_lines(self) -> None:
        manifest = CONFORMING + "line\n" * 500

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-12"]

    def test_spec_13_body_over_the_token_budget(self) -> None:
        """Long lines, few of them: the token budget fires where the line budget does not."""
        manifest = CONFORMING + ("word " * 100 + "\n") * 45

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-13"]

    def test_spec_14_a_manifest_at_the_ten_megabyte_limit(self) -> None:
        """Measured from the size on disk, which is the only place a Scan carries it."""
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING},
                sizes={"SKILL.md": 10 * 1024 * 1024},
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == ["SPEC-14"]

    def test_spec_14_accepts_a_manifest_below_it(self) -> None:
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": CONFORMING},
                sizes={"SKILL.md": 10 * 1024 * 1024 - 1},
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_spec_15_a_reference_to_a_file_that_is_not_there(self) -> None:
        manifest = CONFORMING + "\nSee [the guide](references/GUIDE.md).\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-15"]

    def test_spec_15_accepts_a_reference_that_resolves(self) -> None:
        manifest = CONFORMING + "\nSee [the guide](references/GUIDE.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/GUIDE.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_spec_15_accepts_a_percent_encoded_reference_that_resolves(self) -> None:
        """``references/User%20Guide.md`` and ``references/User Guide.md`` are one path.

        ``SPEC-15`` is scored, so a spelling the Component answers to has to be
        read as the Component. Percent-encoding is how a Markdown target carrying
        a space is written when it is not written in angle brackets.
        """
        manifest = CONFORMING + "\nSee [the guide](references/User%20Guide.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/User Guide.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_spec_15_accepts_a_component_whose_name_really_holds_a_percent(self) -> None:
        """Decoding is tried *as well as* the raw spelling, never instead of it."""
        manifest = CONFORMING + "\nSee [the report](references/Q1%20report.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/Q1%20report.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_spec_15_still_reports_an_encoded_reference_that_resolves_to_nothing(self) -> None:
        """Decoding widens what resolves; it does not silence the Rule."""
        manifest = CONFORMING + "\nSee [the guide](references/User%20Guide.md).\n"

        assert _rule_ids(_one_manifest(manifest)) == ["SPEC-15"]

    def test_spec_16_does_not_read_an_encoded_slash_as_a_separator(self) -> None:
        """Depth is measured on the raw target, so ``%2F`` is a character, not a level."""
        manifest = CONFORMING + "\nSee [the guide](references/api%2FGUIDE.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/api/GUIDE.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_spec_15_ignores_a_url_and_an_anchor(self) -> None:
        manifest = CONFORMING + "\n[docs](https://example.com/x) and [top](#heading).\n"

        assert _rule_ids(_one_manifest(manifest)) == []

    def test_spec_15_ignores_a_reference_inside_a_fenced_block(self) -> None:
        """A fence is where an example lives, and an example is not a reference."""
        manifest = CONFORMING + "\n```markdown\n[the guide](references/GUIDE.md)\n```\n"

        assert _rule_ids(_one_manifest(manifest)) == []

    def test_spec_16_a_reference_more_than_one_level_deep(self) -> None:
        manifest = CONFORMING + "\nSee [the guide](references/api/GUIDE.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/api/GUIDE.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == ["SPEC-16"]

    def test_spec_16_accepts_one_level(self) -> None:
        manifest = CONFORMING + "\nSee [the guide](references/GUIDE.md).\n"
        response = node(
            _state(  # type: ignore[arg-type]
                {"SKILL.md": manifest},
                other_components=("references/GUIDE.md",),
                skill_path="/s/weather-report",
            )
        )

        assert _rule_ids(response) == []

    def test_neither_reference_rule_reads_a_target_that_climbs_out(self) -> None:
        """A ``..`` target leaves the tree this Scan walked, so neither Rule guesses.

        ``SPEC-15`` is scored and cannot answer "is it there" for a path outside
        the Scan; ``SPEC-16`` cannot answer "how deep is it" either, because the
        depth of ``../../shared/a/b.md`` is measured from a root the Scan never
        saw. The guard is asserted on a target that would otherwise raise both.
        """
        manifest = CONFORMING + "\nSee [the guide](../../shared/a/b.md).\n"

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/weather-report")) == []

    def test_spec_15_does_not_report_a_directory_target_that_holds_no_component(self) -> None:
        """A target written with a trailing slash names a directory, not a file.

        A Scan lists Components, never the directories between them, so a
        directory holding nothing the Scan kept is indistinguishable from one
        that is not there. ``SPEC-15`` is scored, so it declines rather than
        guessing -- the same target written as a file does report, which is what
        makes this a guard rather than a Rule that never fires.
        """
        manifest = CONFORMING + "\nSee [the archive](nowhere/).\n"
        as_a_file = CONFORMING + "\nSee [the archive](nowhere).\n"

        assert _rule_ids(_one_manifest(manifest, skill_path="/s/weather-report")) == []
        assert _rule_ids(_one_manifest(as_a_file, skill_path="/s/weather-report")) == ["SPEC-15"]

    def test_spec_17_two_directories_declaring_one_name(self) -> None:
        """The one Rule that reasons across skill directories rather than inside one."""
        response = node(
            _state(  # type: ignore[arg-type]
                {
                    "weather-report/SKILL.md": CONFORMING,
                    "zzz-weather-report/SKILL.md": CONFORMING,
                },
                skill_path="/x/anon",
            )
        )

        # The first directory agrees with the name it declares, the second does
        # not -- which is what makes the collision reachable in one Scan at all.
        assert _rule_ids(response) == ["SPEC-4", "SPEC-17"]
        duplicate = [f for f in response["findings"] if f.rule_id == "SPEC-17"][0]
        assert duplicate.file == "zzz-weather-report/SKILL.md"
        assert "weather-report/SKILL.md" in duplicate.message

    def test_spec_17_does_not_collide_two_manifests_that_declare_no_name(self) -> None:
        """One predicate for "declares a usable name", asked by ``SPEC-2`` and here.

        The two drifted apart: ``SPEC-2`` read a name of blanks as absent and
        ``SPEC-17`` read it as a name, so both directories were told at once that
        they declare no usable name and that they collide on it. A scored Rule
        reporting a collision on a non-name is the expensive half of that.
        """
        blank = '---\nname: "   "\ndescription: Reports the weather when asked.\n---\n\nbody\n'
        response = node(
            _state(  # type: ignore[arg-type]
                {"alpha/SKILL.md": blank, "beta/SKILL.md": blank},
                skill_path="/x/anon",
            )
        )

        assert _rule_ids(response) == ["SPEC-2", "SPEC-4", "SPEC-2", "SPEC-4"]

    def test_spec_17_reads_the_declared_spelling_rather_than_a_stripped_one(self) -> None:
        """Two spellings of one name are two names, because ``SPEC-17`` is scored.

        Folding ``weather-report `` together with ``weather-report`` would put a
        scored Finding on a normalisation no loader was observed to perform.
        ``SPEC-5`` already reports the blank the second spelling carries.
        """
        padded = CONFORMING.replace("name: weather-report", 'name: "weather-report "')
        response = node(
            _state(  # type: ignore[arg-type]
                {"weather-report/SKILL.md": CONFORMING, "zzz/SKILL.md": padded},
                skill_path="/x/anon",
            )
        )

        assert "SPEC-17" not in _rule_ids(response)

    def test_spec_17_accepts_two_directories_with_names_of_their_own(self) -> None:
        other = CONFORMING.replace("name: weather-report", "name: tide-report")
        response = node(
            _state(  # type: ignore[arg-type]
                {"weather-report/SKILL.md": CONFORMING, "tide-report/SKILL.md": other},
                skill_path="/x/anon",
            )
        )

        assert _rule_ids(response) == []


class TestTheFindingsItBuilds:
    """The shape a Finding carries into the report."""

    def test_a_finding_names_its_manifest_and_line(self) -> None:
        response = _one_manifest(CONFORMING, skill_path="/skills/forecasts")
        finding = response["findings"][0]

        assert finding.file == "SKILL.md"
        assert finding.start_line == 2
        assert finding.category == "Specification Conformance"
        assert finding.pattern == RULES["SPEC-4"].name
        assert finding.remediation == RULES["SPEC-4"].remediation

    def test_no_finding_claims_a_risk_taxonomy(self) -> None:
        """A conformance Rule belongs to no OWASP category, so it claims none."""
        assert _one_manifest(CONFORMING, skill_path="/skills/forecasts")["findings"][0].tags == []


class TestTheThreeModesEndToEnd:
    """The flag, through the real CLI, over one Skill that violates both kinds of Rule."""

    runner = CliRunner()

    @staticmethod
    def _skill(root: Path) -> Path:
        directory = root / "Weather_Report"
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text(
            "---\nname: weather--report\ndescription: ''\n---\n\n"
            "Read [the guide](references/deep/GUIDE.md) first.\n",
            encoding="utf-8",
        )
        return directory

    def _scan(self, skill: Path, mode: str | None) -> dict:
        argv = ["scan", str(skill), "--no-llm", "-f", "json"]
        if mode is not None:
            argv += ["--spec-checks", mode]
        result = self.runner.invoke(app, argv)
        assert result.exit_code in (0, 1), result.output
        return json.loads(result.stdout)

    def test_off_reports_nothing_and_scores_nothing(self, tmp_path: Path) -> None:
        report = self._scan(self._skill(tmp_path), "off")

        assert [issue["id"] for issue in report["issues"] if issue["id"] in RULES] == []
        assert report["risk_assessment"]["score"] == 0

    def test_the_default_is_off(self, tmp_path: Path) -> None:
        """The flag's absence and ``--spec-checks off`` are the same scan."""
        assert self._scan(self._skill(tmp_path), None)["issues"] == []

    def test_advisory_reports_every_rule_and_scores_only_some(self, tmp_path: Path) -> None:
        """Every Rule reported, at an honest confidence, and only some in the score.

        Which of them scored is no longer readable off ``confidence`` -- that is
        the point of the change -- so it is measured the only way that is still
        true: by running the same Skill in ``strict`` and comparing scores.
        """
        report = self._scan(self._skill(tmp_path), "advisory")

        assert {i["id"] for i in report["issues"]} == {
            "SPEC-4",
            "SPEC-6",
            "SPEC-8",
            "SPEC-15",
            "SPEC-16",
        }
        assert all(issue["confidence"] > 0 for issue in report["issues"])
        assert report["risk_assessment"]["score"] > 0

    def test_strict_scores_every_rule(self, tmp_path: Path) -> None:
        advisory = self._scan(self._skill(tmp_path / "a"), "advisory")
        strict = self._scan(self._skill(tmp_path / "b"), "strict")

        assert {i["id"] for i in strict["issues"]} == {i["id"] for i in advisory["issues"]}
        assert all(issue["confidence"] > 0 for issue in strict["issues"])
        assert strict["risk_assessment"]["score"] > advisory["risk_assessment"]["score"]

    def test_the_twelve_unscored_rules_contribute_nothing(self, tmp_path: Path) -> None:
        """The scoring half of the mode, isolated from the reporting half.

        ``SPEC-6``, ``SPEC-8`` and ``SPEC-16`` are reported in ``advisory`` at
        full confidence; the score is what ``SPEC-4`` and ``SPEC-15`` alone come
        to, and ``strict`` adds the other three on top.
        """
        advisory = self._scan(self._skill(tmp_path / "a"), "advisory")
        strict = self._scan(self._skill(tmp_path / "b"), "strict")
        # Every rule here is at confidence 1.0 and the manifest is not
        # executable, so the arithmetic is bare severity points: MEDIUM=10
        # (SPEC-4) + MEDIUM=10 (SPEC-15) in `advisory`, plus LOW=5 three times
        # (SPEC-6, SPEC-8, SPEC-16) in `strict`.
        assert advisory["risk_assessment"]["score"] == 20
        assert strict["risk_assessment"]["score"] == 35

    def test_a_conformance_finding_survives_the_no_llm_filter(self, tmp_path: Path) -> None:
        """The path every credential-free run and every CI job takes.

        ``_fallback_filtered`` drops a LOW or MEDIUM finding below confidence
        0.4. It once needed an exemption for this catalogue, because ``advisory``
        emitted at ``0.0``; it needs none now, and this is where "needs none" is
        held to the real CLI rather than to the filter in isolation.
        """
        report = self._scan(self._skill(tmp_path), "advisory")

        assert "SPEC-6" in {issue["id"] for issue in report["issues"]}

    def _baseline(self, skill: Path, baseline_file: Path, mode: str) -> None:
        written = self.runner.invoke(
            app,
            [
                "baseline",
                str(skill),
                "-o",
                str(baseline_file),
                "--no-llm",
                "--spec-checks",
                mode,
            ],
        )
        assert written.exit_code == 0, written.output

    def _scan_against_baseline(self, skill: Path, baseline_file: Path, mode: str) -> dict:
        result = self.runner.invoke(
            app,
            [
                "scan",
                str(skill),
                "--no-llm",
                "-f",
                "json",
                "--spec-checks",
                mode,
                "--baseline",
                str(baseline_file),
            ],
        )
        assert result.exit_code in (0, 1), result.output
        return json.loads(result.stdout)

    @pytest.mark.parametrize(
        ("taken_in", "scanned_in"),
        [("advisory", "strict"), ("strict", "advisory")],
    )
    def test_a_baseline_suppresses_across_the_modes(
        self, tmp_path: Path, taken_in: str, scanned_in: str
    ) -> None:
        """A Baseline binds to the *evidence*, and the mode is not evidence.

        This is the defect the ``confidence = 0.0`` mechanism caused, asserted in
        both directions. ``suppression.finding_fingerprint`` hashes ``confidence``,
        the mode was expressed in ``confidence`` and nowhere else, so one defect
        fingerprinted two ways: a Baseline taken in ``advisory`` suppressed
        nothing in ``strict``, and escalating the flag silently re-reported every
        conformance Finding a team had already accepted -- now with points
        attached. The mode is a property of the run and now lives in
        ``unscored_rule_ids``; ``README.md``, ``docs/SUPPRESSION.md`` and
        ``suppression.finding_fingerprint`` all state the invariant, and this is
        where it is held to the code.
        """
        skill = self._skill(tmp_path)
        baseline_file = tmp_path / "baseline.yaml"
        self._baseline(skill, baseline_file, taken_in)

        for mode in (taken_in, scanned_in):
            report = self._scan_against_baseline(skill, baseline_file, mode)
            assert [issue["id"] for issue in report["issues"] if issue["id"] in RULES] == [], mode

    def test_one_defect_fingerprints_the_same_in_both_modes(self, tmp_path: Path) -> None:
        """The bug itself, asserted directly on the fingerprint rather than through a scan."""
        skill = self._skill(tmp_path)
        manifest = (skill / "SKILL.md").read_text(encoding="utf-8")

        def fingerprints(mode: str) -> set[str]:
            response = node(
                {
                    "spec_checks": mode,
                    "skill_path": str(skill),
                    "component_metadata": [
                        {"path": "SKILL.md", "size_bytes": len(manifest.encode("utf-8"))}
                    ],
                    "file_cache": {"SKILL.md": manifest},
                }  # type: ignore[arg-type]
            )
            return {
                finding_fingerprint(finding, file_content=manifest, scanner_version="test-version")
                for finding in response["findings"]
            }

        assert fingerprints("advisory") == fingerprints("strict")
        assert fingerprints("advisory")

    def test_a_fully_suppressing_baseline_leaves_no_advisory_count(self, tmp_path: Path) -> None:
        """Nothing reported, nothing counted -- the stderr note and the report agree.

        The count is subtracted for suppression, so a Baseline that accepts every
        conformance Finding prints no note at all. Its sibling assertion --
        that the summary tables agree too -- lives in ``tests/unit/test_cli_streams.py``.
        """
        skill = self._skill(tmp_path)
        baseline_file = tmp_path / "baseline.yaml"
        self._baseline(skill, baseline_file, "advisory")
        result = self.runner.invoke(
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
        assert "Spec conformance:" not in result.stderr


_REFERENCING = (
    "---\nname: weather-report\ndescription: Reports the weather. Use when asked "
    "about weather.\n---\n\nSee [guide]({target}).\n"
)


class TestWhatTheScanDidNotWalk:
    """``SPEC-15`` reports a missing file, never a file the Scan declined to look for.

    It is scored, so each of these shapes cost real Risk Score points on a Skill
    that conforms. The Rule's question is "is this file there"; a Scan that never
    walked the directory the file is in cannot answer it, and answering anyway is
    what these pin shut.
    """

    def test_a_hidden_target_the_scan_recorded_skipping_is_not_reported(self) -> None:
        """``build_context`` drops a leading-dot file and says so in the ledger.

        Reporting it made one report say both that the path is out of scope and
        that the path was not found.
        """
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target=".env.example")},
                excluded=((".env.example", LedgerReason.HIDDEN_FILE),),
            )  # type: ignore[arg-type]
        )

        assert "SPEC-15" not in _rule_ids(response)

    def test_a_target_inside_a_pruned_directory_is_not_reported(self) -> None:
        """``_SKIP_DIRS`` prunes ``node_modules`` and records a boundary with a slash."""
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target="node_modules/tool.js")},
                excluded=(("node_modules/", LedgerReason.EXCLUDED_DIRECTORY),),
            )  # type: ignore[arg-type]
        )

        assert "SPEC-15" not in _rule_ids(response)

    def test_a_single_file_input_reports_no_reference_at_all(self) -> None:
        """A lone Manifest in a tool-made temporary directory carries no tree.

        Measured on the real CLI: a fully conforming ``pdf-processing`` scanned as
        ``SKILL.md`` earned three scored ``SPEC-15`` Findings and a Risk Score of
        10, every one of them naming a file that was on disk.
        """
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target="references/GUIDE.md")},
                temp_dir="/tmp/skillspector_abc123",
            )  # type: ignore[arg-type]
        )

        assert "SPEC-15" not in _rule_ids(response)

    def test_a_temporary_directory_that_kept_the_tree_still_reports(self) -> None:
        """The narrow half of the guard, and the reason it is a conjunction.

        A clone, a download and a Zip extraction all set ``temp_dir_for_cleanup``
        and all carry the Skill's whole tree. Suppressing on the temporary
        directory alone would blind ``SPEC-15`` on all three.
        """
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target="references/GUIDE.md")},
                temp_dir="/tmp/skillspector_abc123",
                other_components=("README.md",),
            )  # type: ignore[arg-type]
        )

        assert "SPEC-15" in _rule_ids(response)

    def test_a_directory_holding_only_the_manifest_still_reports(self) -> None:
        """The other narrow half: no temporary directory means the tree was real."""
        response = node(
            _state({"SKILL.md": _REFERENCING.format(target="references/GUIDE.md")})  # type: ignore[arg-type]
        )

        assert "SPEC-15" in _rule_ids(response)

    def test_an_unrelated_exclusion_does_not_silence_a_real_break(self) -> None:
        """A recorded boundary suppresses its own subtree and nothing else."""
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target="references/GUIDE.md")},
                excluded=(("node_modules/", LedgerReason.EXCLUDED_DIRECTORY),),
            )  # type: ignore[arg-type]
        )

        assert "SPEC-15" in _rule_ids(response)

    def test_depth_is_still_measured_on_a_tree_the_scan_did_not_walk(self) -> None:
        """``SPEC-16`` reads the target string, so it survives what silences ``SPEC-15``.

        Depth is a property of what the author wrote, not of what the Scan found,
        and the Rule is unscored besides -- so the suppression is deliberately
        scoped to the one Rule that asserts something about the disk.
        """
        response = node(
            _state(
                {"SKILL.md": _REFERENCING.format(target="a/b/c/deep.md")},
                temp_dir="/tmp/skillspector_abc123",
            )  # type: ignore[arg-type]
        )

        assert _rule_ids(response) == ["SPEC-16"]


class TestTheCatalogueItself:
    """Facts about the Rule set that its prose states."""

    def test_seventeen_rules(self) -> None:
        assert sorted(RULES) == sorted(f"SPEC-{index}" for index in range(1, 18))

    def test_five_are_scored_by_default(self) -> None:
        scored = {rule_id for rule_id, rule in RULES.items() if rule.scored_by_default}

        assert scored == {"SPEC-4", "SPEC-9", "SPEC-14", "SPEC-15", "SPEC-17"}

    def test_no_rule_reads_allowed_tools(self) -> None:
        """The recorded comma/space deviation must not be depended on or corrected."""
        source = (
            Path(__file__).parents[3] / "src" / "skillspector" / "agent_skills_spec.py"
        ).read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        body = code.split('"""', 2)[-1]

        assert "allowed-tools" not in body

    def test_every_rule_carries_its_own_report_text(self) -> None:
        for rule in RULES.values():
            assert rule.explanation and rule.remediation and rule.name
            assert rule.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert 0.0 < rule.confidence <= 1.0


def test_the_analyzer_id_is_the_registered_one() -> None:
    from skillspector.nodes.analyzers import ANALYZER_NODES

    assert ANALYZER_NODES[ANALYZER_ID] is node


def test_a_finding_is_what_the_scorer_skips() -> None:
    """The contract the advisory mechanism rests on, asserted where it is used."""
    from skillspector.nodes.report import _compute_risk_score

    advisory = Finding(rule_id="SPEC-6", message="m", severity="LOW", confidence=0.0)
    scored = Finding(rule_id="SPEC-6", message="m", severity="LOW", confidence=1.0)

    assert _compute_risk_score([advisory], False)[0] == 0
    assert _compute_risk_score([scored], False)[0] > 0
