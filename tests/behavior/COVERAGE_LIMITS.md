# What the behavior gate does not cover

The Behavior Snapshot is a committed, canonical projection of one Scan, compared by a blocking test
so that a change to existing behavior surfaces as a reviewable file diff. What it projects is
specified by [ADR 0003](../../docs/adr/0003-behavior-snapshot-projection.md) and measured in
[the #6 findings](../../docs/behavior-snapshot-projection-findings.md).

This file records the other side: what a green gate does **not** prove. Every limit below is
accepted deliberately. A limit that stops being acceptable is closed by widening the projection and
regenerating every snapshot — not by filtering something quietly.

## What a green gate does prove — the demonstrated red

A gate that has never failed is evidence of nothing, and a perturbation chosen for convenience proves
only that the test *can* fail. The demonstration therefore used a change class the gate exists for:
removing `".py"` from `_EXECUTABLE_EXTENSIONS` (`src/skillspector/nodes/build_context.py:68`), one of
the two changes §3.4 of the design document defers as behavior-affecting.

One edit moved three projected surfaces — `has_executable_scripts`, `component_metadata[].executable`
and the Risk Score multiplier that depends on the flag — and failed **exactly the 13 fixtures** where
`has_executable_scripts` is true, in both the in-process and the out-of-process gate (26 failures,
208 passed). The other 11 stayed green. `malicious_skill` went 93 → 77 with 6 → 5 Findings;
`mcp_overprivileged_skill` went 12 → 0 with 5 → 0. The change was then reverted and the working tree
confirmed clean. Full per-fixture numbers are in the #8 close-out comment.

## Corpus

- **Every leaf scan target**, one committed snapshot each, laid out to mirror `tests/fixtures/`
  (`snapshots/sdi/sdi1_mismatch.json`). Measured at 11 079 lines across the original 24, 323–859 per
  fixture. Most bear a `SKILL.md` **at their root**, which is the only place the Manifest parser
  looks; `mcp_registry` bears none and is in the corpus anyway,
  because it is a scan target in practice, the three `*_detection` fixtures bear none because
  they carry one Framework signal and nothing else, and the application trees —
  `langchain4j_shell_skill` (#28), `langchain4j_tool_mode` (#53),
  `langchain4j_gradle_skill` (#88),
  `deepagents_runtime_skills` (#71), `deepagents_personal_skills` (#72),
  `deepagents_denied_skills` (#72), `deepagents_shadowed_skills` (#73),
  `deepagents_layered_skills` (#73), `deepagents_subagent_skills` (#74),
  `deepagents_js_layered_skills` and `deepagents_js_runtime_skills` — bear none at their
  root because their Skills are nested
  under `src/main/resources/skills/`, `skills/` and `library/skills/` respectively. A count is
  deliberately not written here; `tests/behavior/test_behavior_snapshot.py` holds the one literal.
- **The three fixture family parents (`sdi/`, `sqp/`, `ssd/`) are out of the corpus** and will stay
  out: they are fixture-layout containers, not Skills. Scanned as targets they behave as anonymous
  Skills — `sdi` and `sqp` at Risk Score 48 with an empty Manifest (#11).
- The corpus is checked against the fixture tree on every run, so a fixture added without a snapshot
  fails rather than joining silently.
- **The gate proves preservation over this fixture corpus, not over arbitrary user input.** What the
  corpus does not contain, it cannot guard. It holds 23 markdown, 13 Python, 2 YAML and 2 JSON files
  and nothing else — notably **no JVM source file**, which means adding JVM extensions to the
  file-type map genuinely cannot change any existing fixture. §3.4 of the design document overstates
  the risk for those specific extensions.

## Change classes the corpus cannot see

- **Skip-directory changes are unguarded.** No fixture contains a skippable directory, so
  `analysis_completeness.scope_exclusions` is empty in every one and a change to the skip set cannot
  move any snapshot. A test asserts the emptiness, so the day a fixture populates it, this limit is
  revisited rather than quietly becoming false.
- **Suppression is unguarded.** `suppressed_findings` is empty in every fixture and
  `filtered_findings` is byte-identical to `findings` throughout, so no fixture exercises a Baseline.
- **The anonymous-Skill failure mode is reported, not resolved.** `mcp_registry`'s snapshot records a
  directory with no `SKILL.md` scanning as one Skill with an empty Manifest and a Risk Score of 0.
  #11 landed as a visible diff on exactly that snapshot: the Scan now also reports
  `manifest_status: absent`, so the report says *why* the Manifest is empty. The Scan still returns a
  scored verdict for a directory that is not a Skill — changing that was explicitly out of #11's
  scope, and no fixture guards it.
- **`manifest_status` is guarded in one direction only.** It is one of the two projected keys carried
  conditionally: dropped when it holds `present` (ADR 0003), so the snapshots whose root Manifest
  parses carry no
  `manifest_status` byte at all. A Skill whose Manifest regressed to any other status still fails the
  byte compare, because the key would appear. The reverse — `mcp_registry` reverting to `present` —
  is caught by its own snapshot, and by nothing else. A test holds the rule non-vacuous by requiring
  that some fixture carry the key and some fixture not.
- **`framework` is guarded the same way.** Detection (#21) is the second conditionally carried key,
  dropped when it holds `agent_skills`, which is what every input scanned before detection existed
  detects as. Eleven fixtures carry the key — the two `*_detection` ones, the three LangChain4j
  applications and the six Deep Agents applications — so the rule stays non-vacuous. What is guarded is that a pre-existing input must
  never start detecting as another Framework: the key would appear in its snapshot and the byte
  compare would fail.
- **A Framework Analyzer is now exercised, in both of its modes.** `langchain4j_shell_skill` (#28)
  carries the shell wiring and the shell artifact; `langchain4j_tool_mode` (#53) declares only
  `dev.langchain4j:langchain4j-skills` and proves the Rules that are not about shell mode fire
  without it. Between them, `L4J-SHELL` firing on Tool mode and a non-shell Rule that silently
  stopped matching are both behind the gate. `L4J-WORKDIR` is the exception: its receiver is the
  shell configuration type, which the Tool mode fixture keeps out of its tree by construction, so
  only `langchain4j_shell_skill` holds it. **Both build systems are now behind the gate too.**
  `langchain4j_gradle_skill` (#88) is built by Gradle rather than Maven, so detection, applicability,
  Finding construction and SARIF emission are pinned over a `build.gradle` as well as over a
  `pom.xml`. What its snapshot does *not* hold is a Gradle build file whose `exclude` refuses the
  shell module: that shape raises nothing since #68, and the ten spellings it can be written in live
  in the Analyzer's own suite. This fixture holds the discriminating shape instead — a real
  declaration that excludes something else — which is why its snapshot read the same before and
  after that fix.
- **The JavaScript fixtures are the first `package.json` in the corpus, and each carries one
  base-catalog Finding because of it.** All three declare `"deepagents": "^1.9.1"`, and `SC1`
  (Unpinned Dependencies, LOW) matches a caret range in a dependency file. That is correct — a caret
  range *is* unpinned — and it is deliberately left in rather than pinned away: a caret is what real
  npm manifests carry, and pinning it to keep the snapshots tidy would remove the corpus's only
  evidence that the base catalog reaches a `package.json` at all. The cost is that an edit to `SC1`'s
  catalogue prose moves these three snapshots along with every other fixture carrying the rule, which
  is the behavior gate working rather than failing.
- **The Deep Agents for JavaScript track is behind the gate in three fixtures, not six.** The Rules
  it carries are the Python track's own, so what its fixtures have to pin is that a second *parser*
  feeds the same verdicts — not the verdicts again. `deepagents_js_runtime_skills` pins
  `DA-UNRESOLVED` in two modes at once (an unresolvable Skill list **and** an unresolvable backend),
  and `deepagents_js_layered_skills` pins `DA-SKILL-WRITABLE`, `DA-SHADOW` and
  `DA-SUBAGENT-SKILLS` together with each one's **silence** in the same tree — a covered Skill
  source beside an open one, a Skill name in one source only beside one in both, and a subagent
  with its own Skills beside one without. What no JavaScript fixture holds is the mitigation ladder
  or the TSX grammar: `mode: "interrupt"`, `interruptOn`, and a `.tsx` Component whose call is
  enclosed by JSX all live in the Analyzer's own suite. A regression in any of those is caught
  there and not here.
- **The Deep Agents boundary is exercised in one mode only; the writability verdict in three.**
  `deepagents_runtime_skills` (#71) assembles its Skill list per request, so `DA-UNRESOLVED` is
  behind the gate for the Skill-list case and for that case alone. The other four boundary cases —
  an unresolvable backend, an unresolvable permission set, a resolved Skill path routed to a store
  computed per request, and a permission rule written in an unreadable shape — live only in the
  Analyzer's own suite. `DA-SKILL-WRITABLE` fares better: `deepagents_personal_skills` (#72) pins
  the per-path verdict and the `deny` that clears a sibling path, and `deepagents_denied_skills`
  (#72) is the negative control this file previously said was owed — a correctly permissioned
  application whose **silence** is pinned, so a false positive on ordinary configuration fails the
  gate as loudly as a lost Finding. What no fixture holds is the mitigation ladder: `mode="interrupt"`
  and `interrupt_on` lower a Finding to LOW in the Analyzer's suite only, so a regression that
  stopped recognizing either would move no snapshot.
- **`DA-SHADOW` is guarded in both directions, and its unmappable cases in neither.**
  `deepagents_shadowed_skills` (#73) pins the confirmed collision and `deepagents_layered_skills`
  (#73) pins the silence of the layering upstream recommends — the pair differs only in whether the
  two sources declare a Skill of one name, so a Rule that stopped confirming the names and a Rule
  that started firing on the source list would each move a snapshot. What no fixture holds is what
  happens when the mapping cannot be made: the default backend, a `StoreBackend`, an unreadable
  `root_dir`, and a mapping that lands on no manifest live in the Analyzer's own suite only. That
  matters more here than elsewhere, because three of those four are required to raise **nothing**,
  and a Rule that started reporting them would put a Finding on the configuration the upstream
  tutorial teaches without moving any snapshot in this corpus.
- **`DA-SUBAGENT-SKILLS` is guarded in both directions inside one fixture, and its boundary in
  neither.** `deepagents_subagent_skills` (#74) defines two custom subagents that differ only in
  whether one names Skill sources of its own, so a Rule that stopped firing and a Rule that started
  firing on a definition that *does* declare them would each move the snapshot — the pair is inside
  a single scan target rather than across two, because the verdict is decided inside one
  `create_deep_agent(...)` call. What no fixture holds is the boundary the Rule falls to: a subagent
  list assembled elsewhere, a definition that is not a mapping written in the file, and a `**` spread
  inside one live in the Analyzer's own suite only. Nor does any fixture pin the general-purpose
  exclusion, which is structural — no definition declares that subagent — so there is nothing a
  snapshot could hold.
- **SARIF is no longer a coverage limit.** It was previously listed here as unguarded on the grounds
  that it is derived and reintroduces the timestamp; the timestamp claim was measured false, and
  `sarif_report` is in the projection minus `tool.driver.version` (ADR 0003).

## State the projection excludes

Four state keys are outside the projection, each for a stated reason: `model_config` (environment
dependent), `report_body` (wall clock plus absolute path), `skill_path` and `temp_dir_for_cleanup`
(absolute paths). Their behavior is therefore unguarded here:

- **Report rendering is unguarded.** `report_body` is where the Markdown and JSON report text is
  produced. A change to phrasing, section order, or the JSON report shape does not move the snapshot.
  This limit became load-bearing with #11: the Manifest status reaches a reader only through
  `report_body` — `skill.manifest_status` in the JSON report and the `Manifest:` line in the terminal
  and Markdown ones — so none of that rendering is behind the gate. `tests/nodes/test_manifest_status`
  covers it instead.
- **Input resolution is unguarded.** `skill_path` and `temp_dir_for_cleanup` are what `resolve_input`
  produces for a git URL, a zip, or a single file. The gate only ever scans a local directory.
- **Model selection is unguarded**, by construction. That is the point of excluding it, and the test
  suite demonstrates the exclusion by projecting identically under two provider settings.

State keys outside the eleven-key allow-list are likewise unguarded, notably `inspection_ledger`,
`analyzer_status_events`, `effective_finding_ids`, `filtered_findings`, `file_cache`, and
`llm_call_log`. `analysis_completeness` is projected, so an Analyzer's *status* is guarded even
though the ledger row behind it is not — that is what gives
[ADR 0002](../../docs/adr/0002-gated-analyzers-decline-silently.md) its teeth.

`filtered_findings` was measured byte-identical to `findings` in every fixture, because no fixture
exercises suppression. Suppression and baselines are entirely outside the gate.

## Fields stripped from inside the projection

- **`findings[].finding_id`** — a `uuid4()`, dropped rather than normalized. Nothing that consumes
  the identifier is inside the projection, so identifier *linkage* between a Finding, the ledger and
  SARIF is unguarded.
- **`sarif_report..tool.driver.version`** — a release bump is not a behavior change. A regression that
  emitted the *wrong* version, or none, would not be caught here.

## The LLM path

The Scan is driven with `use_llm=False`, pinned in code rather than read from the environment. Every
LLM-backed Analyzer therefore declines, and **no semantic finding is covered by the gate at all**.
The snapshot records that decline — `analysis_completeness.limitations` carries the
"Analyzer was disabled by the requested configuration" entries — so a change to *how* an Analyzer
declines is caught, while a change to what it would have found is not.

## Shape choices worth knowing when reading a diff

- A Finding is projected via `dataclasses.asdict`, not `Finding.to_dict`. `asdict` carries the full
  dataclass — including `message`, which the §4 named sort key needs and `to_dict` does not emit.
  Line counts therefore do not match the `to_dict`-shaped tables in the #6 findings document.
- A projected key absent from the returned state is absent from the snapshot rather than recorded as
  `null`. A key that stops being emitted is a behavior change and shows as a diff either way.
- **Two registered sort keys are still unexercised.** `analysis_completeness.ledger_exceptions` and
  `scope_exclusions` are empty in **every** fixture, not just in `malicious_skill`, so their named
  key has still never ordered anything. Widening the corpus did not close this. Its shape was
  checked against `InspectionLedgerException` (`src/skillspector/inspection_ledger.py`) rather than
  against data — every field it reads is a `str` or an `int | None`.
- **The gate costs three interpreter spawns plus two in-process `graph.invoke` calls per fixture** —
  one for the gate itself and one for the consecutive-run check — plus one on `malicious_skill` for
  the pre-strip control, for a few seconds of `make test-unit`. Written as the rule rather than as a
  total: the total is the corpus count doubled, and a total is a corpus count that no `34` grep can
  find when the corpus grows. The out-of-process checks did **not**
  scale with the corpus: `regenerate.py --emit-all` projects the whole corpus per spawn, so three
  child interpreters cover every fixture against two hash seeds and two providers.
- **A fixture's line endings are part of the frozen behavior.** The projection carries each
  component's `size_bytes`, so a checkout that rewrites `\n` to `\r\n` inflates every recorded size
  by one byte per line. `tests/fixtures/.gitattributes` pins the corpus to LF for exactly this
  reason. Without it the gate passes on a CRLF development checkout and fails every fixture in
  continuous integration — the state #9 found on the first real workflow run. Any fixture added
  outside `tests/fixtures/` needs its own pin.
- Every list is sorted, including nested lists with no named key registered; those fall back to the
  canonical serialization alone, which is total. So **list order is never guarded** — a change that
  only reorders a list is invisible here. #6 measured order to be stable anyway; the sort exists so
  that an incidentally-stable order can never become a flaky suite.
