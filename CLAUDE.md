# SkillSpector-Polyglot

LangGraph pipeline that scans `SKILL.md` skill directories for vulnerabilities and emits SARIF plus a 0–100 risk score. This fork extends that to skills embedded in a programming-language framework's own source tree — LangChain4j, Deep Agents for Python and Deep Agents for JavaScript, all three shipped as gated Framework Analyzers. The two Deep Agents Analyzers carry the same four Rules — `DA-UNRESOLVED`, `DA-SKILL-WRITABLE`, `DA-SHADOW` and `DA-SUBAGENT-SKILLS` — because they ask one upstream framework's questions in two languages. Three upstream vocabularies carry a measured version range; `contrib/vocabulary_sweep` re-measures the Maven Central and PyPI ones, and the npm one is measured by hand — `docs/VOCABULARY_REMEASUREMENT.md` owns both procedures and says why.

The GitHub repository is `SkillSpector-Polyglot`; the distribution, the package under `src/skillspector/`, and the console script stay `skillspector`. Renaming them would break upstream merges and existing installs — never propose it as a cleanup.

## Tooling

- Every `make` target assumes a venv is already created **and activated** — `uv venv .venv && source .venv/bin/activate`, then `make install-dev`.
- Test: `make test-unit` · Lint: `make lint` and `make format-check`.
- `mypy` is configured in `pyproject.toml` but invoked by nothing — not `make lint`, not CI, not pre-commit. Ruff is the only enforced check.
- `pytest` `addopts` deselects the `integration` and `provider` markers, so a bare `pytest` silently skips them. Use `make test-integration` / `make test-provider [openai|anthropic|nv_build|gemini]`.
- The TypeScript extension tests run in neither pytest nor `make`: `node --test tests/opencode/skillspector_scan_lib.test.ts` and `node --test tests/unit/test_pi_extension.mjs`. They need Node 22.20, which CI pins.
- On fish, venv activation does not survive between non-interactive commands. Two autoloaded functions in `~/.config/fish/functions/` avoid it entirely — `sspy <args>` runs `.venv/bin/python`, and `sspytest [paths]` runs the unit selection (`pytest -m "not integration and not provider"`). Examples: `sspy -c 'import skillspector'`, `sspytest tests/unit -q`. They are user-local, not checked in; `sspy` exits 127 with the setup command if the venv is missing.

## Code search

This repo is indexed (`.codegraph/`). Ask the `codegraph_explore` MCP tool before grep for any *how does this work / where does this live / what calls this* question; grep is for literals and non-code text. `maxFiles` truncates by file without re-ranking, so narrow the query rather than the cap.

## Remote

This repo is a fork. **Every git and GitHub operation targets `rodrigorjsf/SkillSpector-Polyglot` — never the
upstream `NVIDIA/SkillSpector`.** Pushes, branches, pull requests, issues, issue comments, releases
and workflow runs all belong to the fork. Upstream is a read-only sync source: fetch from it, never
push to it and never open a pull request or issue against it. `gh` resolves the upstream remote by
default on a fork, so pass `--repo rodrigorjsf/SkillSpector-Polyglot` whenever the target is not
unambiguous.

## Licensing

This fork inherits NVIDIA's Apache-2.0 license and is a Derivative Work under it. **§4 binds every
commit, not just releases** — people install this fork, so the license has to be right from the
first change, never retrofitted. `.claude/rules/license-compliance.md` is mandatory reading before
creating a source file, modifying an inherited one, adding a dependency, or touching `LICENSE`,
`THIRD_PARTY_NOTICES.md` or any copyright header. When the license text and the repository disagree,
say so and ask — never guess.

## README is part of the change

`README.md` opens with this fork's own documentation — mission, framework support matrix, audience,
install, usage, configuration, transparency — and only then the inherited upstream README under the
`# Inherited documentation` marker. **The fork sections above that marker are not a snapshot; they
are a contract.** A pull request that adds or alters a rule, a framework, a CLI flag, an environment
variable, an exit code, an output format, or which stream a line is printed to updates them in the
*same* pull request — never a follow-up. The README's own "Contributing, and keeping these docs true" table maps each kind of
change to the section it must update; keep that table correct too.

Below the marker, keep the diff append-only and leave the `NVIDIA/skillspector` URLs alone — they
are upstream provenance, not stale links.

## Commits

- **Atomic** — one scope of change per commit. Never mix unrelated scopes; split instead.
- **Conventional Commits, strictly** — `type(scope): subject`, imperative mood, no trailing period. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`. Breaking changes use `!` after the scope and a `BREAKING CHANGE:` footer.
- Every commit needs a `Signed-off-by:` trailer — use `git commit -s`. CI's DCO job walks each commit in the PR range and fails without it.

## Pull requests

**Only call a PR ready — or recommend merging it — once everything that belongs in it is
finished.** Not started, not queued, not "running in the background": finished, with its output
read. Before saying it is ready, all of these must be true.

- **Validations green.** `make test-unit`, `make lint`, `make format-check`, and
  `make update-snapshots` leaving the tree clean.
- **Reviews closed out.** Every review or adversarial pass complete, with each finding either
  fixed on the branch or written into the PR body as a deliberate deferral.
- **Subagents finished.** A background subagent is unfinished work, not a parallel activity the
  merge can race. Wait for it and read its result — one has already caught a defect after the PR
  was green and the human had been told to merge.
- **Nothing left to add.** A `CLAUDE.md` edit, an Applied Learning bullet, or a documentation
  correction the work exposed rides **this** PR. Never a follow-up.
- **CI verified against the right commit.** `gh pr checks` must be green on a `headRefOid` equal
  to `git rev-parse HEAD`, with `state` still `OPEN`.

If anything is outstanding, say what it is instead of saying the PR is ready. A human merges on
that word, and a merged PR ignores later pushes — a commit that lands afterwards is lost from
`main` and costs a second PR to recover.

**Every merged PR leaves an orphan branch. Delete it, local and remote.**
`delete_branch_on_merge` is off on this repository, so nothing is cleaned up automatically and
merged branches accumulate. `gh pr merge --delete-branch` handles both sides when the agent does
the merge; when a human merges, delete it afterwards with `git branch -d` and
`git push origin --delete <branch>`. A merge is not closed out until its branch is gone.

## Critical Constraints

- New source files need the SPDX + Apache-2.0 header block. **Do not copy one from a neighbour** — the copyright line depends on who wrote the file, and a neighbour may be inherited, modified or fork-authored, each carrying a different line. See `.claude/rules/license-compliance.md`. Convention only; nothing enforces it.
- `skillspector.constants` resolves the active provider and validates the model config **at import time**; importing it raises when `SKILLSPECTOR_STRICT_MODEL_VALIDATION=true` and a model is unknown.
- This repo is a fork of NVIDIA/SkillSpector and still merges upstream. Prefer new files in new paths; where an existing file must change, keep the diff append-only.
- Active goal: extend scanning to skills embedded in a framework's source tree — LangChain4j, Deep Agents for Python and Deep Agents for JavaScript today, more later. **Existing behavior on existing inputs must not change** — new analyzers are gated, never unconditionally wired, and a new Framework's detection signals may not narrow an existing Framework's.

## Agent skills

- Issues are tracked in GitHub Issues — `docs/agents/issue-tracker.md`
- Triage labels pair one state role from the canonical five with one category — `docs/agents/triage-labels.md`
- Domain-doc and ADR conventions — `docs/agents/domain.md`
- Implementing a Spec: Umbrella Branch, one branch per Ticket through `/implement`, a human merges the Umbrella PR — `docs/agents/spec-workflow.md`. Outside a Spec, standalone work branches from `main` and opens its PR against `main`.

Two project skills live in `.claude/skills/`, both **user-invoked** — ask the user to run one rather
than reaching for it. `/upstream-sync` measures how far this fork has drifted from
`NVIDIA/SkillSpector` and merges upstream's new work in; it is the one operation where a moved
Behavior Snapshot is correct rather than a regression. `/license-audit` measures this fork against
Apache-2.0 §4 and fixes the drift, and it is the natural follow-up to a sync.

`.github/workflows/upstream-drift.yml` re-runs the sync's step-1 measurement weekly and opens — or
edits — one `Upstream drift:` issue while upstream is ahead. It never merges, pushes, opens a pull
request or closes that issue; `/upstream-sync` § 1 says what it needs from a human.

## References

- Domain glossary — use these terms, not their synonyms — `CONTEXT.md`
- Architecture, node and provider walkthroughs, env vars — `docs/DEVELOPMENT.md`
- Extending the scanner to LangChain4j and to Deep Agents in either language — `docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`
- Captured upstream framework docs — `docs/references/README.md`
- Pi and OpenCode agent extensions — `docs/PI_EXTENSION.md`, `docs/OPENCODE_EXTENSION.md`
- Re-measuring a Framework vocabulary's version range, and its trigger — `docs/VOCABULARY_REMEASUREMENT.md`
- Batch scanner, own runners, excluded from `make test` — `contrib/batch_scan/CLAUDE.md`
- Vocabulary sweep, own runner, excluded from `make test` — `contrib/vocabulary_sweep/CLAUDE.md`

## Applied Learning

When something fails repeatedly, when User has to re-explain, or when a workaround is found for a platform/tool limitation, add a one-line bullet here. Keep each bullet under 15 words. No explanations. Only add things that will save time in future sessions.

- A worktree needs its own venv; the main checkout's editable install imports its dirty `src/`.
- `gh issue view` needs `--json`; `gh pr edit` fails too — PATCH via `gh api --input <json>`, never `-f body=@-`.
- Code search `filename:build.gradle` already matches `build.gradle.kts`; one query.
- `gh api --jq .body_html` needs `Accept: application/vnd.github.html+json`, else empty.
- Ticket PRs run no CI and `Closes #N` no-ops there; empty `gh pr checks` is not a pass.
- `make` needs `export PATH="$PWD/.venv/bin:$PATH"`; sourcing `activate.fish` fails in Bash.
- `core.autocrlf`: `M` with an empty diff and commit-time CRLF warnings are noise, not changes.
- Fork Actions need the Actions-tab enable button clicked once; only a human can.
- Squash-merge Ticket PRs; DCO checks every merge commit inside the PR range.
- Never squash a sync PR; repair a lost parent with `git merge -s ours <the synced SHA>`.
- `CONTEXT.md` `_Avoid_` terms bind docstrings and test names, not just prose.
- `CONTEXT.md` entries define terms only; symbol names belong in `DEVELOPMENT.md`.
- Link sub-issues via `gh api -F sub_issue_id=<id>`; `-f` sends a string and 422s.
- After shipping, grep docs for text still claiming the feature is unbuilt.
- Truncated subagent result: resume it with `SendMessage`, never re-run it.
- `gh api search/code` matches terms, not phrases; use WebSearch for exact phrases.
- `agentskills.io/llms.txt` lists every spec page; grep all before claiming absence.
- Rule `paths`: `**/*.py` skips the base dir; pair it with `*.py`.
- Run the CLI as `.venv/bin/skillspector`; `python -m skillspector` has no `__main__`.
- JSON report nests findings under `issues`, keyed `id` — not `findings`/`rule_id`.
- Mutation test: mutate in a throwaway script; `git checkout --` would drop the file's other edits.
- Bare `python` is absent; run throwaway scripts with `.venv/bin/python`.
- `gh pr checks --json` is unsupported here; grep its text output instead.
- A trailing greedy `[^\n]*` never backtracks into a following optional group.
- A GitHub-population survey is refetchable: #88's comment carries the exact query and filter.
- `--repo-scan`/`--recursive` differences are a README table; update it, not just code.
- Copyright headers: classify by `git diff --diff-filter` against the merge-base, never by path.
- An upstream sync's test failures are the fork's own guards, not upstream's tests.
- A dist-info may ship no LICENSE; read the tagged repo LICENSE instead.
- `push --delete` saying "remote ref does not exist" means GitHub already deleted it.
- The venv's installed version can fall below `pyproject.toml`'s floor; check before reading a dist-info.
- `GH_REPO` steers `gh issue list` but not bare `gh repo view`; an `upstream` remote wins there.
- Findings in JSON report use key `finding`, not `message`; status uses `reason_code`.
- A module-wide revert proves non-vacuity, not per-site coverage; mutate one site.
- `--recursive` engages on one child skill since upstream `ed787e9`; only zero falls through.
- README's Contributing table, its own prose, and CLAUDE.md's list must enumerate one set.
- Mutate every print site, not the changed ones; a docstring's universal claim binds all.
- Any Analyzer Status moves every snapshot; `analysis_completeness` is a projected key.
- Regex `$` matches before a trailing newline; anchor with `\Z`.
- `MANIFEST_FILENAMES` is a precedence: one directory can ship both spellings.
- A confidence read from user YARA meta is data; `confidence=` literals miss it.
- Since upstream `73dd1f1` `report` writes only the kept side into `filtered_findings`.
- One reader selects a finished Scan's Findings: `effective_findings`; never re-express it.
- A `SKILL.md` under `references/`, `scripts/` or `assets/` is a template, not a Skill.
- An early `return` in a Rule walk can suppress a *scored* Rule further down.
- Dropping a Batch loses its Findings from the report; decline it via `should_submit`.
- Withholding a Finding from the prompt also means withholding it from the token budget.
- A state key without a reducer kills the scan on a second parallel writer.
- A declined Batch sits in `successful`; never read that as a model answer.
- Adding a runtime dependency needs `uv lock`; `uv sync --locked` in CI will not re-resolve.
- A conflict can align two functions' identical tails; diff each spliced function whole.
- Hardcoded line numbers into `THIRD_PARTY_NOTICES.md` break on any dependency change.
- `dict.update` keeps a key's position; re-assert identity keys to fix JSON key order.
- A discovery-miss report needs one SARIF run, not zero; GitHub documents "one or more".
- An issue's premise can predate a sync; measure the shape before repeating it in prose.
- README rule tables and the pattern counts sit below the Inherited-documentation marker.
- An empty-runs guard also fires on a hit whose Skills all failed; gate on discovery.
- Sweep stale prose by its claim; a backticked-identifier grep misses the same assertion.
- SARIF cannot show a discovery miss; gate on JSON `skill_count`, not result count.
- Thread a fork flag through `_run_graph_scan_for_source` with `partial`, as upstream does.
- Upstream consoles route by format; bind them to `advice` to keep the stream contract.
- Upstream adds dependencies without notices; `THIRD_PARTY_NOTICES.md` entries are the fork's to write.
- Sync conflict scripts must read universal newlines; the working tree is CRLF.
