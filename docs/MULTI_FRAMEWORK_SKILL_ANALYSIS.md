# Multi-framework skill analysis — design

**Status:** partly built. [§4](#4-the-unchanged-behavior-gate)'s unchanged-behavior gate is merged,
and phases 1–7 of [§5](#5-phasing) have shipped: `detect_framework` and the `framework` state
key (issue #21), then the LangChain4j-in-CI increment (issue #23) — the gated
`framework_langchain4j` Analyzer carrying all five L4J rules of
[§3.6](#36-java-parsing-and-definition-path-coverage), and the Repository Scan of
[§3.7](#37-repository-level-discovery-cicd) behind `--repo-scan`, and phase 2 — the gated
`framework_deepagents` Analyzer carrying all four of the Deep Agents rules of
[§2.3](#23-deep-agents-python-host) (issues #70–#74) and the vocabulary stability measurement
that closes it (#75), and phase 3 — `structure_agent_skills_spec`, the seventeen conformance
rules of [§3.5](#35-spec-conformance-rules-and-scoring) behind `--spec-checks`, off by default.
**Phase 8 alone remains design proposal** — the deferred behavior-affecting changes. One piece of
phase 3 is outstanding rather than shipped: §3.5's advisory *section heading*, which would group
unscored conformance findings apart from the security ones. The rest of the advisory rendering
shipped — a one-line stderr summary, and a per-finding "not scored" note beside an honest
confidence.
[§9](#9-recommended-next-step) carries the live status; each phase row in §5 names the Ticket that
landed it.
**Goal:** extend SkillSpector to evaluate skills hosted by **LangChain4j** (Java) and
**LangChain Deep Agents** (Python), covering both structural/best-practice conformance and
the security analysis SkillSpector already performs.
**Hard constraint:** current behavior on current inputs must not change. This document
treats that as a testable gate, not a promise — see [§4](#4-the-unchanged-behavior-gate).

Framework references live in [`docs/references/`](references/README.md).

---

## 1. The finding that shapes everything

**All three skill ecosystems share one on-disk format.** LangChain4j Skills and Deep Agents
both state upstream that they implement the
[Agent Skills specification](references/agent-skills-specification.md) — the same
`SKILL.md` + `scripts/` + `references/` + `assets/` layout SkillSpector already scans, with
the same frontmatter keys `_parse_manifest` already reads
(`src/skillspector/nodes/build_context.py:253`).

The practical consequence is large and worth stating plainly before any design follows:

> **SkillSpector already analyzes LangChain4j and Deep Agents skill payloads correctly
> today.** Point `skillspector scan` at a `skills/docx/` directory from either framework and
> all 14 `static_patterns_*` analyzers, `static_yara`, and the three `semantic_*` analyzers
> run exactly as they do on a Claude Code skill. For Deep Agents, `behavioral_ast` and
> `behavioral_taint_tracking` also cover `scripts/` unchanged, because the scripts are
> Python.

So this is not a port. The gap is narrower and sits in two places:

1. **Spec conformance is parsed but never validated.** SkillSpector extracts frontmatter
   and never checks it against the specification's constraints.
2. **Host code is invisible.** The code that *wires* skills into an application —
   `ShellSkills` in Java, `create_deep_agent(permissions=...)` in Python — carries the
   security-relevant configuration, and none of it lives in `SKILL.md`.

## 2. Gap analysis

### 2.1 Spec conformance (framework-independent)

The specification defines machine-checkable constraints for every field. None were enforced when
this document was written; every row but the last is now a rule of
[§3.5](#35-spec-conformance-rules-and-scoring), reached by `--spec-checks` and off by default.

| Constraint | When this was written | Now |
|------------|-----------------------|-----|
| `name` matches parent directory name | Not checked | SPEC-4, scored |
| `name` charset, 1–64 chars, no leading/trailing/consecutive hyphens | Not checked | SPEC-2 (lower bound), SPEC-5, SPEC-6, SPEC-7 |
| `description` present, ≤ 1024 chars | Not checked | SPEC-3, SPEC-8, SPEC-9 |
| `compatibility` ≤ 500 chars | Field not parsed at all | SPEC-10, from the conformance analyzer's own parse — `_parse_manifest` still drops the field |
| `SKILL.md` body ≤ 500 lines / ~5000 tokens | Not checked | SPEC-12, SPEC-13 |
| File references one level deep, targets exist | Not checked | SPEC-15, SPEC-16, over Markdown link targets only |
| `allowed-tools` is **space**-separated | **Parsed as comma-separated** | Unchanged, deliberately — no SPEC rule reads the field |

The last row is a live defect rather than a missing feature. `_parse_manifest`
(`build_context.py:297`) and `_normalize_allowed_tools`
(`src/skillspector/nodes/analyzers/mcp_least_privilege.py:143`) both split on `,`. A
spec-canonical value collapses to one token:

```
input:      "Bash(git:*) Bash(jq:*) Read"
parsed:     ['Bash(git:*) Bash(jq:*) Read']
categories: set()
```

`_map_allowed_tools_to_categories` (`mcp_least_privilege.py:190`) does an exact lowercase
lookup against `_TOOL_TO_CAPABILITY` (`mcp_least_privilege.py:172`), so the single token
matches nothing. `has_declaration` is `True` at `mcp_least_privilege.py:334` while the
derived capability set is empty — LP1/LP4 reason over a skill that appears to declare tools
while granting no capabilities. Scoped syntax (`Bash(git:*)`) also fails to match even after
correct whitespace splitting; the base tool name needs extracting first.

**Decision: current behavior is retained.** Fixing this changes findings on existing
inputs, which the non-negotiable constraint forbids. It is recorded as a known deviation
with an explicit trigger rather than scheduled as work — see
[§5, Known deviation](#known-deviation-allowed-tools-separator).

### 2.2 LangChain4j (Java host)

| Signal | Risk | Nearest existing analyzer |
|--------|------|---------------------------|
| `ShellSkills` / `langchain4j-experimental-skills-shell` present | Unsandboxed arbitrary command execution — upstream itself documents this as unsafe | `static_patterns_excessive_agency`, `static_patterns_privilege_escalation` |
| `RunShellCommandToolConfig.workingDirectory` unset | Commands default to the JVM's `user.dir` | `static_patterns_excessive_agency` |
| `@Tool("...")` description text | Instruction-carrying string the model reads — the tool-poisoning surface, in Java rather than an MCP manifest | `mcp_tool_poisoning` (TP1–TP4) |
| `McpToolProvider` without `.filter(...)` or `.filterToolNames(...)` | Every MCP tool exposed post-activation instead of a scoped subset | `mcp_least_privilege` (LP1–LP4) |
| Skill `content(...)` built by concatenation or fetched remotely | Instruction text that exists in no scanned file | `static_patterns_prompt_injection` |
| `pom.xml` / `build.gradle` dependencies | Maven ecosystem unsupported in `osv_client.py:56` (PyPI and npm only) | `static_patterns_supply_chain` (SC4) |

Two structural facts make Java harder than Python:

- **No `.java` file type.** `_FILE_TYPES` (`build_context.py:50`) has no `.java`, `.kt`,
  `.gradle`, or `.xml` entry, so `pom.xml` and every Java source file classify as `"other"`.
  `_EXECUTABLE_EXTENSIONS` (`build_context.py:68`) has no JVM entry, so
  `has_executable_scripts` stays `False` for a Java-only skill and the risk multiplier that
  depends on it never applies.
- **No Java parser in the dependency set.** `behavioral_ast` and `behavioral_taint_tracking`
  are built on Python's stdlib `ast`. Java needs one added — see
  [§3.6](#36-java-parsing-and-definition-path-coverage) for the choice and its cost.

`ClassPathSkillLoader` also allows skills under `src/main/resources/skills/` or bundled
inside a JAR. The path is trivially handled; the JAR is not — `InputHandler` keys archive
handling off the `.zip` suffix (`src/skillspector/input_handler.py:148`), so a `.jar` is
never opened.

### 2.3 Deep Agents (Python host)

| Signal | Risk | Nearest existing analyzer |
|--------|------|---------------------------|
| `create_deep_agent(skills=[...])` with no `permissions=[...]` | Agents can write to skill files by default when the backend permits — self-modifying skills | `mcp_rug_pull` (RP1–RP3), `static_patterns_memory_poisoning` |
| No `FilesystemPermission(..., mode="deny")` on a `/skills/**` path also passed in `skills` | Writable shared skill library | `mcp_least_privilege` |
| `interrupt_on` absent for `write_file` / `edit_file` | No human in the loop for skill mutation | `static_patterns_excessive_agency` |
| Duplicate skill `name` across sources | Silent last-one-wins override | New |
| Custom subagent without its own `skills` | Capability silently unavailable — a correctness bug upstream calls out | New |

The duplicate-name case is the most interesting new primitive. `skills=[shared, personal]`
means a user-writable `personal/` skill can shadow a curated `shared/` skill of the same
name. That is supply-chain substitution expressible purely in configuration and invisible to
any single-directory scan. Detecting it requires reasoning across the whole list of skill
sources — architecturally closer to `multi_skill.detect_skills`
(`src/skillspector/multi_skill.py:51`) than to any per-file analyzer.

Deep Agents is substantially cheaper to support than LangChain4j: its host language is the
one SkillSpector already parses, so host-code detection reuses the existing Python AST
infrastructure rather than requiring new machinery.

## 3. Architecture

### 3.1 Principle: detect, then gate

`graph.py:53` fans out **every** id in `ANALYZER_NODE_IDS` from `build_context`
unconditionally. Appending framework analyzers therefore executes them on every existing
scan. What makes gating viable is that an analyzer returning `{"findings": []}` is
**entirely invisible**: `guard_analyzer_node` (`src/skillspector/inspection_ledger.py:773`)
only synthesizes ledger and status events when the analyzer *raises*. A gated analyzer that
declines by returning no findings emits **nothing** — no ledger event, no analyzer status —
so nothing reaches `analysis_completeness` or the `ledger_exceptions` that
`finalize_inspection_ledger` surfaces in terminal and markdown output
(`grep -n 'render_rows("Ledger' src/skillspector/nodes/report.py` finds both writers).

That silence is deliberate, and it is recorded in
[ADR 0002](adr/0002-gated-analyzers-decline-silently.md) rather than left implicit — it reads
like a violation of the Inspection Ledger's purpose. The reconciliation is the definition of
Work Item as a *planned* unit of inspection: an analyzer whose framework gate does not open
plans none, so there is no unaccounted work. The gate is a convention with no enforcement;
the behavior snapshot in [§4](#4-the-unchanged-behavior-gate) is what catches an analyzer
that emits a status event by habit.

So the rule is **additive *and* gated**, never unconditionally wired:

```
build_context
  └─ detect_framework(components, file_cache, manifest) → framework: str
       "agent_skills" (default) | "langchain4j" | "deepagents"

framework_* analyzers
  └─ first statement: if state.get("framework") not in (...): return {"findings": []}
```

A new `framework` key on `SkillspectorState` is set by `build_context` and read by the new
analyzers. Existing analyzers never read it and are untouched.

### 3.2 Detection signals

Detection must be conservative: **when in doubt, return `"agent_skills"`** and behave
exactly as today.

| Framework | Positive signals |
|-----------|------------------|
| `langchain4j` | `pom.xml` / `build.gradle*` containing `dev.langchain4j`; any `.java`/`.kt` file importing `dev.langchain4j.*`; `src/main/resources/skills/` layout |
| `deepagents` | `pyproject.toml` / `requirements*.txt` naming `deepagents`; any `.py` importing `deepagents` or calling `create_deep_agent` |

Detection is a pure function over `components` and `file_cache`, both already built. It adds
no I/O and cannot fail a scan.

### 3.3 Proposed analyzer nodes

Four new nodes, appended to `ANALYZER_NODE_IDS` after `semantic_quality_policy` so existing
ordering is preserved.

Two of them now exist. `framework_langchain4j` ships all five of its Rules (#28, #30, #31).
`framework_deepagents` is wired and reports its status (#70) and carries all four of its Rules:
`DA-UNRESOLVED` (#71), the resolution boundary, which the row below does not propose at all,
`DA-SKILL-WRITABLE` (#72), the writability verdict, which is the row's first three collapsed into
one, `DA-SHADOW` (#73), the cross-source collision, and `DA-SUBAGENT-SKILLS` (#74), the subagent
defined without Skills of its own. The shape they take is
[ADR 0008](adr/0008-deepagents-analyzer-resolves-one-module-deep.md)'s rather than this row's — it
collapsed the first three into one composed verdict per Skill source path, and added the boundary
that #71 shipped. Read the row as the original proposal, not as what is running.

| Node id | Gate | Rules |
|---------|------|-------|
| `structure_agent_skills_spec` | `--spec-checks` (opt-in, default `off`) | Frontmatter conformance: name↔directory, charset, length, description bounds, body size, dangling file references. Rule catalogue and scoring split in [§3.5](#35-spec-conformance-rules-and-scoring) |
| `framework_langchain4j` | `framework == "langchain4j"` | `ShellSkills` usage, unset `workingDirectory`, `@Tool` description poisoning, unfiltered `McpToolProvider` |
| `framework_deepagents` | `framework == "deepagents"` | Missing `permissions` / `interrupt_on`, writable `/skills/**`, subagent skill inheritance, duplicate skill `name` across the `skills=[...]` list |

> **Note on `structure_agent_skills_spec`.** This one is framework-independent and would fire
> on existing inputs, which is exactly what the gate forbids. Hence the opt-in flag rather
> than a detection gate: it stays off until a major version, then flips to on-by-default with
> a changelog entry. This is the honest cost of the constraint — valuable checks that apply
> to today's inputs cannot be silently enabled.

> **Note on duplicate skill names.** There are two distinct cases and they live in different
> nodes. Shadowing across the Deep Agents `skills=[...]` list — where last-one-wins is
> documented upstream — belongs to `framework_deepagents`. Duplicate names across sibling
> skill *directories* have no override semantics of their own and are covered by SPEC-17 in
> [§3.5](#35-spec-conformance-rules-and-scoring).

`framework_langchain4j` parses Java with tree-sitter rather than matching patterns — see
[§3.6](#36-java-parsing-and-definition-path-coverage). Deep Agents detection reuses the
existing Python `ast` infrastructure to inspect `create_deep_agent` call keywords directly.

### 3.4 Supporting changes

| Change | File | Risk |
|--------|------|------|
| Add `.java`, `.kt`, `.gradle`, `.xml` to `_FILE_TYPES` | `build_context.py:50` | **Behavior-affecting** — flips `component_metadata[].type` from `"other"` for any current scan containing such a file |
| Add JVM extensions to `_EXECUTABLE_EXTENSIONS` | `build_context.py:68` | **Behavior-affecting** — flips `has_executable_scripts`, which feeds the risk multiplier |
| Maven ecosystem in OSV queries | `osv_client.py:56` | Additive — new ecosystem constant, new lockfile parser |
| `.jar` treated as an archive | `input_handler.py:148` | Additive — new input type, must inherit the existing zip-slip and size caps |

The first two rows are the ones to be careful with. Neither is required for the framework
analyzers to work — `framework_langchain4j` selects its inputs by path suffix and reads
`file_cache` directly, regardless of the inferred type — so **both should be deferred**
rather than bundled into the first phase.

### 3.5 Spec-conformance rules and scoring

#### The rule catalogue

**Shipped**, as `structure_agent_skills_spec` (`src/skillspector/nodes/analyzers/`), whose rule
catalogue and verdicts live in `src/skillspector/agent_skills_spec.py`.

Seventeen deterministic checks — string comparison and path existence, no LLM. None was covered
before; the nearest analyzer, `semantic_quality_policy` (SQP-1/2/3), judges trigger vagueness,
missing user warnings, and natural-language policy violations, all by LLM. It checks nothing
mechanical.

> **The counts in this section used to be wrong, and this note is the record of it.** The prose
> said "sixteen deterministic checks" and "the four above score normally" while the table below
> listed seventeen rules and named five scored by default. SPEC-17 was added later — see
> [§7](#7-decisions-taken), "Directory-level shadowing check? **Yes**, as SPEC-17" — and the two
> sentences were never re-counted. Seventeen minus five is twelve, which is the one number that
> was already right.

| Rule | Check | Spec | Scored by default |
|------|-------|------|-------------------|
| SPEC-1 | `SKILL.md` has no declaration block, or the YAML fails to parse | — | No |
| SPEC-2 | `name` missing, empty, or not text | required | No |
| SPEC-3 | `description` missing | required | No |
| SPEC-4 | `name` ≠ parent directory name | `name` | **Yes** |
| SPEC-5 | `name` contains characters outside `a-z0-9-` | `name` | No |
| SPEC-6 | `name` starts/ends with `-`, or contains `--` | `name` | No |
| SPEC-7 | `name` longer than 64 characters | `name` | No |
| SPEC-8 | `description` empty | `description` | No |
| SPEC-9 | `description` longer than 1024 characters | `description` | **Yes** |
| SPEC-10 | `compatibility` longer than 500 characters | `compatibility` | No |
| SPEC-11 | `metadata` is not a string→string mapping | `metadata` | No |
| SPEC-12 | `SKILL.md` body over 500 lines | progressive disclosure (SHOULD) | No |
| SPEC-13 | `SKILL.md` body over ~5000 tokens | progressive disclosure (SHOULD) | No |
| SPEC-14 | `SKILL.md` over 10 MB — Deep Agents skips the file silently | Deep Agents | **Yes** |
| SPEC-15 | `SKILL.md` references a relative path that does not exist | file references | **Yes** |
| SPEC-16 | File reference more than one level deep | file references (SHOULD) | No |
| SPEC-17 | Two skill directories in the same scan declare the same `name` | — (loader behavior) | **Yes** |

**Two of the seventeen are loader-behavior rules, not specification clauses**, and the `Spec`
column says so rather than inventing a section for them. SPEC-14 cites Deep Agents because that is
where the 10 MB skip is observed. SPEC-17 cites nothing: the captured specification has **no**
skill-name uniqueness clause — `grep -n unique docs/references/agent-skills-specification.md`
returns one line, inside `metadata` ("Key names should be reasonably unique"), which is about
metadata keys and not about skill names. The only `name`-scoped cross-directory constraint the page
states is "Must match the parent directory name", and SPEC-4 already covers it. SPEC-17 is
justified below on what a loader must do, which is a sound reason to score it and not a reason to
attribute it to a page that does not say it.

Five rules are scored by default because each has a runtime consequence, not merely a style
one:

- **SPEC-4** — Deep Agents resolves same-name overrides across the `skills=[...]` list by
  `name`, not by path. A `name` that disagrees with its directory is a shadowing primitive.
- **SPEC-9** — the description goes into the system prompt in both frameworks; content past
  the 1024-character cut is silently dropped.
- **SPEC-14** — the skill looks installed and never loads.
- **SPEC-15** — `SKILL.md` instructs the agent to run a script that is not there, so the
  agent improvises.
- **SPEC-17** — a duplicate `name` across sibling skill directories, reachable only where one
  `graph.invoke` sees several `SKILL.md` files: an ordinary scan of a directory that declares no
  skill of its own. `--recursive` and `--repo-scan` invoke the graph once per discovered skill
  *directory*, so a collision between two discovered skills is out of reach there, and one between
  a skill and a skill nested inside it is not. `multi_skill.detect_skills`
  has no override semantics of its own, so this is not a substitution primitive the way the
  Deep Agents `skills=[...]` list is. It is scored anyway because whichever loader consumes
  those directories will have to pick one, and the choice is not visible from the tree.

The remaining twelve are conformance and hygiene. They are reported, not scored.

**The specification's 1-character lower bound on `name` is SPEC-2's, not SPEC-5's.** No charset
rule can speak about a name that holds no characters, and the upper bound only caps the other end,
so without SPEC-2 the only rule with anything left to say about `name: ""` is SPEC-4. It is
reported as SPEC-2 for the same reason SPEC-8 rather than SPEC-9 covers an empty `description`: a
declaration that holds nothing is an absence, not a malformation. The charset pattern is anchored
with `\Z` rather than `$` for the neighbouring hole — `$` matches before a trailing newline, which
a YAML block scalar leaves on the value.

**SPEC-2 is reported beside SPEC-4, not instead of it, and that is a correction.** Ending the
walk at SPEC-2 suppressed the one *scored* rule about `name`, which made the emptiest declaration
the cheapest one: `name: ""` in `weather-report/` scored nothing while the milder
`name: forecasts` in the same directory scored 10. An empty name is not the name of its directory
either, which is exactly SPEC-4's condition, so it is reported — and the charset, hyphenation and
length rules are still skipped, because "holds a character the specification forbids" is the wrong
sentence about a name holding none. The boundary is the string: a `name:` that is not text at all
(a bare YAML number) still ends the walk at SPEC-2, because SPEC-4 compares two directory-name
*strings* and a number is not one.

**"Declares a usable name" is one predicate, asked in both places that need it.** SPEC-2 read a
name of blanks as absent while SPEC-17 read it as a name, so two directories declaring
`name: "   "` were told at once that they declare no usable name *and* that they collide on it —
the second being scored. `agent_skills_spec.usable_name` is now the single reader. It normalises
nothing beyond that test: SPEC-17 keys on the declared spelling, so `weather-report ` and
`weather-report` are two names, because folding them together would put a scored finding on a
normalisation no loader was observed to perform — and SPEC-5 already reports the blank.

**Two rules under-match on purpose, and one reads the component rather than its text.**

- **SPEC-15 and SPEC-16 read Markdown link targets only.** The specification shows a second
  reference shape — a bare `scripts/extract.py` on its own line — and telling that apart from
  prose that names a path is not a string comparison. SPEC-15 is scored, so a reference written
  that way is missed rather than guessed at. Link targets inside a fenced code block are skipped
  for the same reason: a fence is where an example of a bad reference lives.
- **SPEC-15 resolves a percent-encoded target as well as a raw one.** `references/User%20Guide.md`
  and `references/User Guide.md` are one path, and encoding is how a Markdown target carrying a
  space is written when it is not written in angle brackets. Both spellings are tried and either
  satisfies the rule — the decoded form *as well as* rather than *instead of* the raw one, so a
  component whose name genuinely holds a `%` still resolves. SPEC-16 keeps measuring depth on the
  raw target, so an encoded `%2F` stays a character of one path component rather than becoming a
  level; decoding it there would report a depth the author never wrote, which is the direction a
  scored rule must not take.
- **SPEC-14 is measured from `component_metadata[].size_bytes`**, not from the cached text.
  `build_context._read_file_cache` applies no size cap, so a 10 MB `SKILL.md` does reach
  `file_cache` — but it is decoded with `errors="replace"`, so the length of that string is not
  the length of the file. The size on disk is carried in `component_metadata` and nowhere else,
  which is also why the analyzer's applicability is built from that list rather than from the
  cache.
- **A directory shipping both manifest spellings is one skill, not two.** `MANIFEST_FILENAMES`
  holds `SKILL.md` and `skill.md` because `build_context._parse_manifest` reads both — but it
  reads them *in that order and stops at the first*, so the second is shadowed and is the manifest
  of nothing. The analyzer's applicability is therefore one manifest per containing directory, in
  the same precedence. Read as two, every rule reported twice and SPEC-17 — scored — reported a
  name collision between a directory and itself. The shadowed file is not inspected and plans no
  work item, so the ledger has nothing to account for.
- **A `SKILL.md` a skill *ships* is not a skill directory.** The specification defines exactly
  three directories for what a skill bundles — `scripts/`, `references/`, `assets/` — and a manifest
  under one of them is a template or an example, not a skill. Read as a skill directory it cost a
  conforming skill 20 scored points: SPEC-4 against the directory name `references`, plus SPEC-17
  against the very skill that ships it. The exclusion is in `_manifests`, the one place
  applicability is decided, rather than in the two rules — `.claude/rules/analyzers.md` names two
  expressions of "applicable" as the defect ADR 0006 records. **This narrows the gap without
  closing it:** applicability is still a filename plus a path segment, not a loader's notion of a
  skill directory, so a manifest parked somewhere the specification names no convention for —
  `docs/examples/SKILL.md` — is still read as one. Carried as
  [issue #121](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/121).
- **SPEC-4 stays silent where the directory name is this tool's own.** A git clone, a download, a
  zip extraction and a single-file input all leave the scanned root inside a temporary directory
  named by `input_handler` (`repo`, `extracted`, a `mkdtemp` suffix). `temp_dir_for_cleanup` is
  exactly the state key that says so, and without that guard a scored finding would land on every
  conforming skill scanned from a Git URL. A *nested* `SKILL.md` is always compared, because its
  directory is inside the tree that was walked.

#### The `--spec-checks` flag

One new CLI option, a `StrEnum` following the existing `FormatChoice` / `TransportChoice`
pattern (`src/skillspector/cli.py:140`, `:149` — the citations here read `:76` and `:85` until
this phase shipped, and had rotted by some sixty lines):

| Value | Behavior |
|-------|----------|
| `off` (default) | Analyzer returns `{"findings": []}`. Today's behavior exactly. |
| `advisory` | All 17 rules run and report at their own confidence. The five above score normally; the other twelve are published in `unscored_rule_ids` and contribute zero. |
| `strict` | All 17 rules run and **all** contribute to the risk score. |

The enum itself is `SpecChecks` in `src/skillspector/agent_skills_spec.py` rather than a third
enum in `cli.py`: unlike `FormatChoice` and `TransportChoice` it is also read back out of graph
state by the analyzer it gates, so a second spelling of the same three values would be a
vocabulary to keep aligned by hand. The flag is threaded through every `_scan_state` call site —
the ordinary scan, `--recursive`, `--repo-scan` and `skillspector baseline`, the last so that a
conformance finding can be accepted like any other.

**`off` is a silent decline, not a `disabled` status, and that is a deliberate second case
[ADR 0002](adr/0002-gated-analyzers-decline-silently.md) was amended to accept — a configuration
gate whose default is the absence of a request, beside the framework mismatch the record was
written for. `.claude/rules/analyzers.md` names both, and a third has to be argued in the ADR
rather than here.** The semantic analyzers answer `--no-llm` with an analyzer status of `disabled` and
`LedgerReason.DISABLED_BY_CONFIGURATION`. Copying that here fails arithmetically: an analyzer
status lands in `analysis_completeness.analyzer_statuses`, which the Behavior Snapshot projects,
and `disabled` is outside `NON_LIMITING_STATUSES` — so every scan that never asked for this
analyzer would gain a row *and* lose `is_complete`. It also fails on meaning: `--no-llm` is a
request a user made, while `--spec-checks off` is the absence of one, and reporting the default
of a flag as a limitation of a scan is not what the Inspection Ledger is for. Past the gate the
analyzer reports on every input, including `not_applicable` where the scan holds no `SKILL.md`
at all.

#### The mechanism — a run-scoped state key the scorer reads

**This subsection replaces an earlier one, and the earlier design is stated here rather than
deleted, because its argument was good and its conclusion was wrong.** It read
`_compute_risk_score`'s own docstring —

> Each finding's contribution is also scaled by its confidence value (clamped to [0, 1]).
> Findings with confidence <= 0 are skipped entirely — **they do not contribute to the score
> but remain in the reported findings list.**

— and concluded that emitting advisory findings at `confidence = 0.0` gave "reported but not
scored" for free, with **no change to `report.py` at all**. That is what this section specified and
what the analyzer was first written to; it was rejected before release, for a reason the docstring
cannot see. No commit of this repository ever carried it, so no installed SkillSpector produces a
mode-bound baseline and nothing has to be regenerated.

**`confidence` already means something, and the flag overloaded it.** It answers *how certain is
the scanner that this finding is real*. Every rule in this catalogue is a measurement — a string
comparison, a length, a path that is either there or not — so the honest answer is 1.0 (0.7 for
`SPEC-13`, the one token estimate). Writing 0.0 instead said *this run was configured not to score
it*, which is a property of the **invocation**, not of the finding. The overload leaked in three
directions:

- **`suppression.finding_fingerprint` hashes `confidence`.** One defect therefore fingerprinted
  two ways, and a baseline recorded under `advisory` suppressed nothing under `strict`. Since
  `skillspector baseline` takes `--spec-checks` too, a team could generate a baseline in one mode
  and scan in another and be told nothing.
- **The report rendered `Confidence: 0%`** — a claim about certainty the scanner never made
  ([issue #119](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/119)).
- **The `--no-llm` meta filter reads a low confidence as a reason to drop**
  ([issue #120](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/120)), which needed an
  exemption to work around.

**The invariant, now written into the code rather than only here:** *a baseline fingerprint depends
only on the evidence — what was found and where.* Its enforceable form is the one the code states:
**no analyzer may encode run configuration into a `Finding`.** It is written in
`suppression.finding_fingerprint`'s docstring, where the payload is built, and in **two** rule
files, because the rule binds two audiences that never open the same file. `.claude/rules/suppression.md`
is `paths`-scoped to `suppression.py`, so it reaches whoever changes the fingerprint — and *only*
them: the author of the next gated analyzer opens `nodes/analyzers/*.py` and would never have loaded
it. `.claude/rules/analyzers.md`, scoped to exactly that path, therefore carries the same rule in its
analyzer-facing form, which is where the violation would actually be written. One rule stated where
each half of its audience reads.

It binds the analyzers rather than the whole pipeline because the meta-analysis stage already
violates the wider reading and predates this work: it rewrites `confidence`, `message`,
`remediation`, `explanation` and `tags`, all five hashed, and which branch runs is decided by
`--no-llm`. So a baseline is bound to the side of *that* flag it was generated on
([issue #124](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/124)) — measured, filed,
and deliberately not repaired here, because excluding those fields from the payload would
re-fingerprint every committed v2 baseline. It is in fact worse than a two-sided binding, and
`docs/SUPPRESSION.md` now says so: on the LLM side four of those five fields are model output
written verbatim, with no temperature and no seed pinned and the model env-selectable, so that side
has no fingerprint stability even between two identical invocations. Stating the invariant in the absolute form would have
made three documents false on the day they were written; stating it as a rule on analyzers is what
would have caught `confidence = 0.0`, and is true.

**No field of the `Finding` could have carried the flag, and that is measured rather than
assumed.** The obvious repair — tag advisory findings — moves the collision instead of fixing it:
`finding_fingerprint` hashes `tags` as well as `confidence`. Grep the payload
(`grep -n '"tags"\|"confidence"' src/skillspector/suppression.py`) rather than trusting line
numbers, which have rotted in this document before. So the signal lives on the **run**:

1. `structure_agent_skills_spec` emits every finding at its rule's honest `confidence`, in every
   mode. The two modes now produce byte-identical findings for the same defect.
2. Past its gate it writes `unscored_rule_ids: list[str]` into graph state, computed by
   `agent_skills_spec.unscored_rule_ids(mode)` from the mode and the catalogue it already owns —
   the twelve unscored ids in `advisory`, `[]` in `strict`. With `--spec-checks off` the analyzer
   declines before this point, so the key is **absent**.
3. `_compute_risk_score` gains a fourth parameter, defaulting to `None`, and skips those ids **in
   addition to** its existing `confidence <= 0` skip, which is untouched for every other analyzer.
   The report node passes the state key through.

**`report.py` is modified, and the modification is bounded by what it is not allowed to know.**
It receives an *opaque* set of rule ids. It does not import `agent_skills_spec`, does not know what
a SPEC rule is, and never sees `spec_checks` — the catalogue knowledge stays in the analyzer that
owns it, which is what keeps this from becoming a second expression of the same predicate
(`.claude/rules/analyzers.md`, ADR 0006). Default behaviour is untouched: with the flag absent the
key is absent, `unscored` is the empty frozenset, and the loop runs exactly as before. Every
committed Behavior Snapshot is byte-identical.

**The sentence printed beside such a finding is published with the ids, not written in the report.**
The remedy a reader needs is *which flag would score this*, and that is catalogue knowledge in the
plainest form — a literal `--spec-checks strict` in `report.py` would have kept the ids opaque and
made the sentence beside them a hard-coded fact about one analyzer, so a second gated catalogue
publishing its own ids would inherit this one's flag and print a remedy that does nothing. The
analyzer therefore writes `unscored_rule_note: str` alongside the ids, from
`agent_skills_spec.UNSCORED_NOTE`, and both writers render it verbatim. `report.py` owns only the
generic half — `not scored in this run`, true whatever published the ids — as the fallback for a
publisher that names ids and no sentence.

**That layering is what makes a second gated catalogue *possible*; it does not make one work yet,
and the difference is a measurement.** Both keys are bare channels on `SkillspectorState` — no
`Annotated` reducer — while `graph.build_graph` fans every analyzer out from `build_context` in
parallel. Two analyzers writing `unscored_rule_ids` in the same superstep raise LangGraph's
`InvalidUpdateError` while the channel update is applied, which is outside any node and therefore
past where `guard_analyzer_node` could absorb it: the whole scan dies, not just that analyzer.
Adding a second publisher means choosing a reducer for **both** keys first, and the note is the
harder half — two remedies cannot concatenate into one sentence, so the honest shape is a mapping
from rule id to its note rather than `operator.add`.
`tests/unit/test_unscored_rule_ids_single_publisher.py` fails the moment a second module anywhere in
`src/skillspector` writes either key, so the choice is forced at test time rather than discovered in
a crash.

**One exemption was removed rather than left standing beside its replacement.**
`meta_analyzer._fallback_filtered` — the `--no-llm` path — drops a MEDIUM or LOW finding below
confidence 0.4. It needed a catalogue exemption only while advisory findings arrived at 0.0. The
lowest confidence in the catalogue is `SPEC-13`'s 0.7, the analyzer sets no `context` for the
code-example downweight to halve, and both facts are asserted rather than argued
(`tests/nodes/test_meta_analyzer_fallback.py::TestConformanceFindingsNeedNoExemption`). The
exemption is gone.

**The LLM stage never sees a SPEC id, and "never sees" had to be made literally true.** With the
LLM stage on, `apply_filter` keeps a MEDIUM or LOW finding only if the model *confirmed* it — every
rule of this catalogue is MEDIUM or LOW, so filtering on confirmation made `--spec-checks` report
almost nothing unless paired with `--no-llm`, the flag that turns off the semantic analysis the rest
of the tool exists for. The first repair skipped these ids in `apply_filter` alone, and the
surrounding prose then claimed the model was never asked about one. **It was asked.** `get_batches`
put every finding of a file into `batch.findings`, `build_prompt` formatted all of them into the
prompt, and only the answer was discarded — measurably: with three SPEC findings added to one file,
the prompt is not byte-identical and the per-file token overhead the content budget subtracts goes
from 23 to 95 tokens.

The predicate is therefore `meta_analyzer._model_visible`, read in three places at once — the
prompt, the token overhead charged against the content budget, and
`LLMAnalyzerBase.should_submit`, a hook that declines a batch whose every finding is withheld.
Three consequences, each of which the old shape got wrong:

- The model genuinely is never asked. The prompt of an `advisory` run is byte-identical to the
  prompt of the same scan under `off`.
- **The flag is inert to the LLM stage**, which is what makes the README's "a baseline is not bound
  to the mode it was taken in" true for *every* rule rather than only for the SPEC ones. Charging
  the withheld findings to the overhead estimate shrank the content budget, which moves chunk
  boundaries, which hands `apply_filter`'s enrichment branch — writer of `message`, `confidence`,
  `remediation` and `explanation`, all four hashed into the fingerprint — a different answer about
  an *unrelated* co-located finding. The submitted batch set is now identical under `off` and
  `advisory` for the same input.
- A manifest whose only findings are conformance findings costs no chat-model invocation, and the
  scan's `llm_call_log` stays empty rather than reporting a call that succeeded.

Declining is not the same as dropping, and the hook lives in the base class for that reason: a
declined batch still lands in `BatchExecutionResult.successful` as `(batch, [])`.
`_meta_ledger_response` derives the Inspection Ledger rows from that list, and
`effective_finding_ids` — which `report.report` selects the reported findings from — is derived from
those rows. A batch removed from the submitted list instead would take its findings out of the
report entirely, and `finalize_ledger` would refuse to let them be added back: it asserts that the
effective ids equal the ids emitted by the meta rows.

`apply_filter` still skips the catalogue, now as the second half of one decision rather than the
whole of it: a model that was never asked can still name a SPEC id in a response — stale, or
hallucinated — and the skip is what stops such an answer from reaching a finding. A SPEC finding
therefore passes through **unchanged**, and *unchanged* stays the load-bearing word. The enrichment
branch overwrites `confidence` with the model's own, and `confidence` is hashed into the
fingerprint, so a "confirmed" conformance finding would fingerprint differently from the identical
defect on a `--no-llm` run: a baseline taken on one path would suppress nothing on the other. That
is the same class of leak as the `confidence = 0.0` encoding, and the invariant above is what both
answer to.

The exemption is keyed on rule id rather than on confidence, which is what makes it additive: every
id in `agent_skills_spec.RULES` is unreachable unless `--spec-checks` asked for it. Exempting every
zero confidence would **not** have been inert — `static_yara._parse_meta` reads `confidence` from
user-supplied YARA rule metadata, so a rule declaring `confidence = "0"` at MEDIUM or LOW would have
started being reported, and no committed Behavior Snapshot runs with a custom rules directory to
catch it.

This is also still why the enum lives on the flag rather than in `models.py`: **do not add a `NOTE`
or `INFO` member to `Severity`.** `_SEVERITY_POINTS.get(sev, 5)` in `report.py` falls back to 5
points for any unrecognized severity, so a new member would silently score as `LOW` unless every
scoring table were updated in lockstep.

#### Visual treatment

The three changes this section originally specified, and where each stands:

- **A one-line summary when advisory findings exist.** **Shipped**, in `cli.py`:
  `skillspector scan --spec-checks advisory` prints the count of findings reported without
  affecting the risk score to **stderr**, under the stream rule that puts the report on stdout and
  every note about it beside. It is counted from `unscored_rule_ids` — the same key the scorer
  reads, so the note and the score cannot disagree — over the findings the report actually carries,
  so a finding a `--baseline` already accepted is not announced.
- **Replace the `0%` confidence line with an explicit "not scored" note.** **Shipped**, and the
  shape changed with the mechanism. There is no longer a `0%` to replace: the confidence rendered
  is the honest one, and the note is appended beside it —
  `Confidence: 100% (not scored — run with --spec-checks strict to include)`, in both the terminal
  and the Markdown writer. The branch is on membership in the opaque `unscored_rule_ids` set, not
  on the finding, because a finding this run does not score is a finding at full confidence and has
  nothing on it to branch on. That closes the defect
  [issue #119](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/119) names.
- **A separate `Spec conformance (advisory — not scored)` heading.** **Not shipped.** It is section
  layout in two writers rather than a false statement, and the issue itself ranks it second for that
  reason.

All three are reachable only when `--spec-checks` is not `off`, so the
[§4 gate](#4-the-unchanged-behavior-gate) still holds: with the flag absent, the behavior snapshot
is unchanged. `report_body` is excluded from the snapshot anyway (wall clock + absolute path), so
the rendering is asserted on the rendered text directly, in `tests/nodes/test_report.py`.

#### Baseline interaction — decided

Baseline suppression (`suppression.py`) fingerprints findings by rule and location. Conformance
findings enter the findings list, so they are baseline-eligible like any other, **by design**. A
baseline generated under one `--spec-checks` mode suppresses under the other.

**This paragraph has been wrong twice, in opposite directions, and the record of both is the point.**
It first claimed mode-independence as a fact. Measurement falsified that — the v2 fingerprint hashed
`confidence`, and the mode was expressed in `confidence` and nowhere else, so the two modes
fingerprinted one defect differently:

```
$ skillspector baseline ./weather--report -o b.yaml --no-llm --spec-checks advisory
Wrote baseline with 1 suppressed finding(s)
$ skillspector scan ./weather--report --no-llm --spec-checks advisory --baseline b.yaml -f json
issues [] suppressed 1 score 0
$ skillspector scan ./weather--report --no-llm --spec-checks strict   --baseline b.yaml -f json
issues ['SPEC-6'] suppressed 0 score 5
```

The paragraph was then rewritten to *keep* that behavior and call it correct: "for a conformance
finding the mode **is** part of that evidence". **That argument is now rejected.** The mode is not
evidence — it is configuration, and nothing about the defect on disk changed between the two
commands above. Binding a committed, shared artifact to a command-line flag means a team's accepted
findings silently return, with risk points attached, the day someone escalates the flag; the
regeneration that supposedly answers it is a regeneration nothing tells them to perform. The
fingerprint invariant in `finding_fingerprint` is the general form of the rejection, and
`test_a_baseline_suppresses_across_the_modes` holds it to the code in both directions.

**What this does to [issue #122](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/122).**
That issue asked for the baseline document to record its mode, so `scan --baseline` could warn at
the moment of a mismatch. There is no longer a mismatch to warn about — a baseline suppresses in
every mode — so the premise it was filed on is gone. It is left open rather than closed here,
because recording provenance in a baseline may still be wanted for reasons this change did not
touch; what is settled is that no *suppression* correctness argument depends on it.

### 3.6 Java parsing and definition-path coverage

The goal is production LangChain4j applications, so this section covers **every way
LangChain4j lets a skill be defined**, and says plainly where static analysis stops.

#### Parser choice: tree-sitter

| Candidate | Verdict |
|-----------|---------|
| `javalang` 0.13.0 | **Rejected.** Last released 2020-03-28, Java 8 era grammar — predates text blocks (Java 15). LangChain4j's own docs define skill content with `.content("""…""")`, so the single most important construct fails to parse. |
| `tree-sitter` 0.26.0 + `tree-sitter-java` 0.23.5 | **Chosen.** Current, `requires_python >=3.10` against this project's `>=3.12`, error-tolerant parsing (a partially-invalid file still yields a usable tree). |

This adds a runtime dependency to a deliberately tight dependency list, so it lands in its
own phase with its own decision — see [§5](#5-phasing). **Accepted** in
[ADR 0001](adr/0001-tree-sitter-for-java-parsing.md) and shipped with issue #23; both
distributions publish `cp39-abi3` wheels, so no C toolchain is needed on any supported
interpreter.

#### Definition-path coverage

| Definition path | Statically resolvable | Notes |
|-----------------|----------------------|-------|
| `FileSystemSkillLoader.loadSkills(Path.of("skills/"))` | Yes | Literal path argument |
| `FileSystemSkillLoader.loadSkill(Path.of("skills/docx"))` | Yes | Single-skill form |
| `ClassPathSkillLoader.loadSkills("skills")` | Yes | Resolves to `src/main/resources/skills/` |
| `Skill.builder().content("""…""")` | Yes | Text block or string literal |
| `Skill.builder().content(CONSTANT)` | Usually | Resolvable when the constant is a literal in the same compilation unit |
| `Skill.builder().content(someVar)` — DB, remote API, runtime-generated | **No** | See below |
| `SkillResource.builder().relativePath(…).content(…)` | Same rules as `Skill.builder()` | |
| `skill.toBuilder().tools(new OrderTools())` | Yes | The class is named, so its `@Tool` annotations are read wherever the file holding them is scanned — by `L4J-TOOL-DESC`, per file. Since issue #94 that rule's message also names the attachment site, joined across the scan's own `file_cache`: `new OrderTools()` names a *simple* name, so the join is declined outright unless the scan declares that name exactly once. Declared twice, in two packages, it would attribute the tool to a Skill it may never reach; declared nowhere, resolution has left the scan, and there is no annotation in view to have reported |
| `skill.toBuilder().tools(someVariable)` | **No** | The tool set is assembled out of view, so the Scan cannot say what capability the Skill was granted. Reported as `L4J-UNRESOLVED` (issue #57) |
| `skill.toBuilder().tools(new OrderTools(), runtimeTools)` | **No** | Per argument, not per call: one unreadable argument leaves the tool set unknown even though the other is named. Also `L4J-UNRESOLVED` |
| `.toolProviders(McpToolProvider.builder()…)` | Yes | Presence and the absence of both `.filter(…)` and `.filterToolNames(…)` are visible |
| `.tools(Map.of(spec, executor))` | Partially | The `ToolSpecification` literal is readable; the `ToolExecutor` lambda body is not analyzed. Since #57 this also raises `L4J-UNRESOLVED`, on the same test as the row above — the argument is a call rather than a `new X()`, so no tool class is named — which is the honest reading: what the map grants is decided by an executor nothing here reads |
| `Skills.from(…)` vs `ShellSkills.from(…)` | Yes | Mode selection is a type reference |

#### The coverage limit, stated as a finding

"State of the art" cannot mean resolving arbitrary Java dataflow. A skill whose `content(…)`
comes from a variable, a database, or a remote call has **instruction text that exists in no
scanned file** — invisible to every content analyzer SkillSpector has.

Silence there would be worse than a finding, because the report would read as "clean" when
the primary attack surface was never examined. So this emits its own rule:

> **L4J-UNRESOLVED** — *Skill content is not statically resolvable; the instruction surface
> was not scanned.* Severity `MEDIUM`, reported whenever a `Skill.builder()` chain reaches
> `.content(…)` with a non-literal argument. Names the file and line of the builder chain.

The same applies to `.name(…)` and `.description(…)` built dynamically, and to
`ClassPathSkillLoader.loadSkill(path, myClassLoader)` with a custom loader whose resolution
cannot be followed.

### 3.7 Repository-level discovery (CI/CD)

The stated target is running the CLI in the CI/CD pipeline of a Java or Python application —
i.e. against a **whole repository**, not a skill directory. Three verified facts block that
today:

| Fact | Evidence | Consequence |
|------|----------|-------------|
| `detect_skills` is not on the ordinary scan path, and sees immediate children only | `cli.py:327`, `:343` — reached only under `--recursive` or to print a warning; `multi_skill.py:71` (`iterdir()`) | An ordinary scan of a Java repo does **not** produce zero skills. `build_context` walks the whole tree unbounded (`build_context.py:96`) and parses the manifest only at the root (`:259`), so the repo scans as **one giant anonymous skill with an empty manifest** — every file in it treated as one skill's payload |
| `_SKIP_DIRS` has no JVM build directories | `build_context.py:46` — `{.git, __pycache__, node_modules, .venv, venv, .tox, .pytest_cache}` | A post-`mvn package` tree walks all of `target/`, including compiled classes and any fat JAR |
| A local directory input has no ingest cap | `input_handler.py:152` returns the path directly; only `MAX_FILE_CHARS = 1_000_000` per file applies (`static_runner.py:60`) | Repo size is unbounded at ingest; the per-file cap does not bound the walk |

The first row is worse than a missing feature and worse than the "zero skills" reading it
replaces. Zero skills would at least be a visibly empty result. What actually happens is a
report that looks complete: one anonymous skill whose manifest is empty, whose components are
the entire repository including `target/`, and whose risk score is computed over that mixture.
Every per-skill signal — name, description, `allowed-tools` — is absent not because the repo
lacks skills but because the root has no `SKILL.md`.

**Measured, not hypothesized — and the defect is wider than the no-file case.** Issue #11
reproduced the first row on four fixture directories in this repository, with `use_llm=False` and no
credentials. Two of them return a scored MEDIUM verdict while reporting an empty manifest:

| Target | `manifest` | components | findings | risk |
|---|---|---:|---:|---:|
| `tests/fixtures/mcp_registry` | `{}` | 2 | 0 | 0 (LOW) |
| `tests/fixtures/sdi` | `{}` | 10 | 8 | **48 (MEDIUM)** |
| `tests/fixtures/sqp` | `{}` | 10 | 3 | **48 (MEDIUM)** |
| `tests/fixtures/ssd` | `{}` | 5 | 0 | 0 (LOW) |

Triage then built five control directories differing only in their `SKILL.md` — absent, no fence,
`---\n---`, a declaration block parsing to a list rather than a mapping, and invalid YAML — and
**all five produced a
byte-identical signature**: `manifest == {}`, with `manifest_absent` as the Inspection Ledger reason
code. The empty manifest was an overloaded sentinel for those five causes plus a sixth the controls
could not produce portably — a file that exists but raises on read — and the absence of a Skill was
indistinguishable from a Skill whose declaration failed to parse.

**Fixed additively.** A Scan now carries `manifest_status` beside `manifest`
(`src/skillspector/manifest_status.py`), taking one of `present`, `empty`, `unparseable`,
`unreadable`, `absent`. Every return path of the manifest parser maps to exactly one of them, and the
report renders the status for every value but `present` — so a reader can tell from the output that
the scanned directory declared no Skill. `manifest` itself is unchanged in type and contents for
every input, which is why 23 of the 24 committed Behavior Snapshots stayed byte-identical and only
`mcp_registry` regenerated. This makes the absence *reportable*; it does not build discovery on top
of it, which remains phase 7 below.

Required work:

1. **Deep skill discovery** — find `SKILL.md` at any depth under conventional roots
   (`skills/`, `src/main/resources/skills/`, `.deepagents/skills/`, `.agents/skills/`),
   bounded by a maximum depth and by the skip list.
2. **JVM build-directory exclusion** — add `target`, `build`, `.gradle`, `.mvn`, `out` to the
   walk's skip set.

**Neither is free, and neither may be applied unconditionally.** Adding entries to
`_SKIP_DIRS` changes `components` and the ledger's `EXCLUDED_DIRECTORY` events for any
existing scan that contains a `build/` or `target/` directory — the same class of change as
the `_FILE_TYPES` edit already deferred in [§3.4](#34-supporting-changes). Deepening
discovery likewise changes what `detect_skills` returns for existing inputs.

Both therefore go behind the framework gate or an explicit `--repo-scan` flag. CI/CD is not
an exception to the [§4 gate](#4-the-unchanged-behavior-gate).

What already works for CI/CD and needs nothing: SARIF output (GitHub code scanning ingests
it directly), exit code 1 above the risk threshold and 2 on error, and `--baseline` for
accepting known findings.

## 4. The unchanged-behavior gate

"Current behavior must not change" becomes a command that either passes or fails.

The obvious mechanism — capture `skillspector scan --format json` output into `/tmp/ss-before`
before a change, re-capture into `/tmp/ss-after` after it, and require `diff -ru` to be empty
— **cannot pass**, and is recorded here as rejected so it is not reached for again.
`_format_json` injects `"source"` (the absolute resolved input path) and `"scanned_at"`
(`datetime.now(UTC).isoformat()`) into every report — `grep -n 'scanned_at' src/skillspector/nodes/report.py`
finds the injection, and `grep -n 'source = skill_path' …` the two other writers that render the
same resolved path. The diff is therefore non-empty on every
file on every run with zero code changed. It has two further defects: it is invisible to CI,
and it requires a human to capture "before" *before* editing, which a dirty working tree
already makes impossible.

The gate is instead a **committed Behavior Snapshot plus a test that regenerates and compares
it**. Git supplies the "before" for free, and the snapshot is reviewable in the diff of the
commit that changes it. It is specified in
[issue #4](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/4), was sliced into issues #5–#9,
and **is delivered**: the gate lives in [`tests/behavior/`](../tests/behavior/), runs in
`make test-unit` and in CI, and its stated blind spots are recorded in
[`tests/behavior/COVERAGE_LIMITS.md`](../tests/behavior/COVERAGE_LIMITS.md).

- **Seam: `graph.invoke`** — the highest existing seam below the CLI, with prior art at
  `tests/integration/test_graph.py:29`. The CLI is rejected as a seam precisely because
  `_format_json` reintroduces `source` and `scanned_at`; projecting from graph state drops
  them by construction, since the formatter is what injects them.
- **A projection of state, not raw state.** Nine keys are projected — `findings`,
  `risk_score`, `risk_severity`, `risk_recommendation`, `component_metadata`,
  `has_executable_scripts`, `manifest`, `analysis_completeness`, `sarif_report`. Four are
  excluded with a stated reason each: `model_config` (environment-dependent),
  `report_body` (wall clock + absolute path), `skill_path`, `temp_dir_for_cleanup`. Two fields
  are stripped from inside it: `findings[].finding_id`, a `uuid4()` that is the only measured
  source of nondeterminism in state, and `sarif_report..tool.driver.version`, because a release
  bump is not a behavior change. Every list is sorted by a named key plus the element's full
  canonical serialization as the tie-breaker. Decided and justified in
  [ADR 0003](adr/0003-behavior-snapshot-projection.md); measured in
  [`behavior-snapshot-projection-findings.md`](behavior-snapshot-projection-findings.md).
- **Breadth: maximal.** All three behavior-affecting changes [§3.4](#34-supporting-changes)
  fears — `component_metadata[].type`, `has_executable_scripts`, the ledger's
  `EXCLUDED_DIRECTORY` events — live *outside* findings and risk score. A snapshot narrowed to
  those two would catch none of them. Measurement confirmed the breadth is affordable: the
  specified projection is 323–859 lines per fixture and 11 079 across the original 24, well inside
  what a reviewer reads.
- **Corpus: 35 leaf directories.** Every fixture directory bearing a root `SKILL.md` (23), plus
  `tests/fixtures/mcp_registry`, which bears none and scans as an anonymous Skill, plus the two
  `*_detection` fixtures phase 1 added, which bear none either and carry one Framework signal each,
  plus the three LangChain4j applications the `framework_langchain4j` Analyzer reads —
  `langchain4j_shell_skill` in shell mode, `langchain4j_tool_mode`, which declares only
  `dev.langchain4j:langchain4j-skills` and proves the Rules that are not about shell mode fire
  without the shell artifact anywhere in its tree, and `langchain4j_gradle_skill`, the one built by
  Gradle rather than Maven — plus the six Deep Agents applications
  `framework_deepagents` reads: `deepagents_runtime_skills`, whose agent picks its Skill sources
  per request and therefore exercises the resolution boundary, `deepagents_personal_skills`, which
  leaves one of two Skill sources open and carries the per-path writability verdict,
  `deepagents_denied_skills`, the negative control whose silence is pinned, and the shadowing pair
  `deepagents_shadowed_skills` and `deepagents_layered_skills`, which layer a per-user Skill
  directory over a shared library under a resolvable filesystem backend root and differ only in
  whether the two sources declare a Skill of one name, and `deepagents_subagent_skills`, whose two
  custom subagent definitions differ only in whether one names Skill sources of its own. The three
  family parents — `sdi/`, `sqp/`, `ssd/` — are fixture-layout containers, not Skills, and are
  not scan targets.
- **Blocking, inside `make test-unit`**, with a `make update-snapshots` to regenerate. The
  friction is the feature: it forces a behavior change to be declared as a reviewable commit.
  The counter-example is already in this repo — `mypy` is configured and invoked by nothing.

`--no-llm` remains load-bearing: the semantic analyzers are non-deterministic, so a snapshot
that includes them proves nothing.

Acceptance for any phase claiming to be behavior-preserving:

1. The snapshot test is green **with no snapshot file modified** in the same change.
2. `make test-unit` green.
3. `make lint` and `make format-check` green.
4. `ruff` is the only linter CI runs — `mypy` is configured (`pyproject.toml:94`) but
   invoked nowhere, so type errors will not be caught for you.

Two traps worth stating explicitly:

- **`tests/nodes/analyzers/test_registry.py:24` hardcodes `EXPECTED_ANALYZER_NODE_IDS`** as
  an exact, order-sensitive list and asserts equality. Every new analyzer must be added
  there, in position, or the suite fails.
- **`guard_analyzer_node` swallows exceptions** (`inspection_ledger.py:773`). A new analyzer
  that throws on every file is converted to `{"findings": []}` plus a `"failed"` ledger
  status and will *not* fail the run. A green test suite is not evidence a new analyzer
  works — assert on its findings directly.

Fixtures for the new frameworks go in new directories (`tests/fixtures/langchain4j_skill/`,
`tests/fixtures/deepagents_skill/`) so the snapshot over the existing fixture corpus stays
meaningful — a new fixture adds a snapshot entry, it does not change an existing one.

## 5. Phasing

Ordered by value-to-risk. Each phase is independently shippable and independently revertible.

| Phase | Content | Behavior-preserving? |
|-------|---------|----------------------|
| **0** | This document + [`docs/references/`](references/README.md) | Yes — docs only |
| **1** | ~~`detect_framework` + `framework` state key~~ **Done** (#21) — no analyzer read it at the time; `framework_langchain4j` does now. Unit tests assert correct detection on new fixtures and `"agent_skills"` on every existing fixture | Yes |
| **2** | ~~`framework_deepagents` analyzer, gated~~ **Done** (#58): the analyzer is wired and reports its status (#70), `DA-UNRESOLVED` ships its resolution boundary (#71), `DA-SKILL-WRITABLE` the writability verdict (#72), `DA-SHADOW` the cross-source collision (#73) and `DA-SUBAGENT-SKILLS` the subagent defined without Skills of its own (#74); the vocabulary stability measurement (#75) closed the phase and brought LangChain4j's own measurement under the same procedure, [`docs/VOCABULARY_REMEASUREMENT.md`](VOCABULARY_REMEASUREMENT.md) | Yes, via gate |
| **3** | ~~`structure_agent_skills_spec` behind `--spec-checks`~~ **Done** — 17 rules, default `off`, every committed Behavior Snapshot byte-identical. The advisory rendering of [§3.5](#35-spec-conformance-rules-and-scoring) shipped as the stderr summary line plus the per-finding "not scored" note; only the separate section heading is outstanding | Yes, via opt-in |
| **4** | ~~**Dependency decision:** accept `tree-sitter` + `tree-sitter-java`~~ **Done** (#23) — accepted in [ADR 0001](adr/0001-tree-sitter-for-java-parsing.md), both ship `cp39-abi3` wheels | N/A |
| **5** | ~~LangChain4j fixture~~ **Done** (#28, extended by #30 and #31) — `tests/fixtures/langchain4j_shell_skill/` | Yes — test data only |
| **6** | ~~`framework_langchain4j` analyzer, gated~~ **Done** (#28, #30, #31) — all five L4J rules; every pre-existing Behavior Snapshot byte-identical | Yes, via gate |
| **7** | ~~Repository-level discovery for CI/CD~~ **Done** (#29) — `src/skillspector/repository_scan.py` behind `--repo-scan`, JVM build-dir exclusion on that path only | Yes, via flag — **not** if applied unconditionally |
| **8** | Maven/OSV, `.jar` ingest, `_FILE_TYPES` / `_EXECUTABLE_EXTENSIONS` additions | Mixed — the last two are behavior-affecting; ship separately |

Phases 1–3 deliver Deep Agents support and spec conformance without touching a single
existing code path. Phase 4 was a decision, not code: tree-sitter adds a runtime dependency to
a deliberately tight list, and phases 5–6 could not proceed to the standard §3.6 describes until
it was accepted. Phase 8's last two items are the only scheduled work that trades the
constraint for correctness.

**Phases 4–7 shipped together** as the LangChain4j-in-CI increment rather than one at a time —
[ADR 0004](adr/0004-langchain4j-before-deepagents.md) records why the Java track went first and why
the analyzer and the Repository Scan were paired. Phase 8 is the only one that remains.

### Known deviation: `allowed-tools` separator

SkillSpector splits the Agent Skills `allowed-tools` frontmatter field on commas; the
specification defines it as **space**-separated. Full analysis in [§2.1](#21-spec-conformance-framework-independent).

**Status: observed, deliberately unfixed.** Correcting the separator changes findings on
inputs that are scanned today, and preserving current behavior outranks spec fidelity here.
This is a recorded deviation, not a backlog item — no work is scheduled against it.

**Blast radius if it were changed** (both call sites lack direct test coverage):

| Site | Current |
|------|---------|
| `src/skillspector/nodes/build_context.py:297` | `allowed_tools.split(",")` → `manifest["allowed-tools"]` |
| `src/skillspector/nodes/analyzers/mcp_least_privilege.py:143` | `value.split(",")` in `_normalize_allowed_tools` |

Downstream: `_map_allowed_tools_to_categories` (`mcp_least_privilege.py:190`) and the
`has_declaration` branch (`mcp_least_privilege.py:334`), which drive LP1, LP3, and LP4.

**Reopen this decision when any of these is observed:**

1. A real scan of a skill whose `allowed-tools` uses the spec-canonical space separator
   produces a wrong LP1/LP3/LP4 verdict — most likely LP3 suppressed (a declaration is
   present, so `has_declaration` is `True`) while no capability category was actually
   derived, so declared-vs-detected reconciliation silently passes.
2. A user reports a false negative or false positive traceable to `allowed-tools` parsing.
3. Upstream NVIDIA/SkillSpector changes the separator — then take theirs and drop this note.
4. Scoped tool syntax (`Bash(git:*)`) needs to map to a capability. That requires extracting
   the base tool name before the `_TOOL_TO_CAPABILITY` lookup, and is a second, independent
   defect from the separator: it fails even with correct whitespace splitting.

**If reopened**, the change is not behavior-preserving. It needs a changelog entry, a minor
version bump, and — because `.skillspector-baseline.example.yaml` shows baselines are in
use — a note that existing baselines may need regenerating.

A regression test asserting the *current* comma behavior would lock in the deviation and make
a future fix look like a break. Prefer a test that documents the deviation explicitly (named
for it, with a comment pointing here) over one that silently ratifies it.

## 6. Fork considerations

This repository is a fork of [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector).
Assuming upstream merges continue:

- **New files in new paths.** `docs/references/`, `docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`,
  `src/skillspector/nodes/analyzers/framework_*.py`, `tests/fixtures/langchain4j_skill/`.
  These never conflict.
- **Where an existing file must change, keep the diff append-only.** Appending to
  `ANALYZER_NODE_IDS`, `ANALYZER_NODES`, `_FILE_TYPES`, and `EXPECTED_ANALYZER_NODE_IDS`
  produces conflicts that resolve by taking both sides. Reordering or reformatting those
  lists does not.
- **`test_registry.py` will conflict on every upstream analyzer addition.** Unavoidable —
  the list is order-sensitive by design. Keep fork-added ids strictly at the end.
- Upstream commit `e8e08c5` ("read exact versions from Python lockfiles for OSV") is the
  closest precedent for the phase-8 supply-chain work; follow its shape.

## 7. Decisions taken

Recorded so the reasoning is not relitigated. Each links to where it is implemented in the design.

| Question | Decision |
|----------|----------|
| Should an `advisory` run write spec findings into a baseline? | **Yes.** Advisory findings are baseline-eligible by design, and an `advisory` baseline suppresses a later `strict` run — a fingerprint binds to the evidence, and the mode is configuration rather than evidence ([§3.5](#baseline-interaction--decided)) |
| How far into Java? | **As far as static analysis allows.** Target is production LangChain4j applications, so tree-sitter replaces regex and every definition path is covered, with unresolvable content reported as `L4J-UNRESOLVED` rather than passed over ([§3.6](#36-java-parsing-and-definition-path-coverage)) |
| Directory-level shadowing check? | **Yes**, as SPEC-17, scored by default ([§3.5](#35-spec-conformance-rules-and-scoring)) |
| Where does the CLI run? | Primary usage is repository-level with codebase access; CI/CD of a Java or Python application is the production target ([§3.7](#37-repository-level-discovery-cicd)) |
| `allowed-tools` separator | **Keep current behavior.** Recorded as a known deviation with reopen triggers ([§5](#known-deviation-allowed-tools-separator)) |

## 8. Open questions

Both are now resolved by [ADR 0004](adr/0004-langchain4j-before-deepagents.md); kept here as the
record of what was open.

1. **`.jar` ingest scope.** A JAR is a zip, but usually holds compiled classes, not source.
   Reading `src/main/resources/skills/` out of one is useful; reading `.class` files is not.
   Worth confirming the deployment shape — is the CLI ever pointed at a built artifact rather
   than a source tree? — before building it (phase 8).
   **Resolved: source tree only.** In CI the target is the checked-out source, so `.jar` ingest
   stays deferred to phase 8.
2. **`--repo-scan` discovery roots.** [§3.7](#37-repository-level-discovery-cicd) proposes
   `skills/`, `src/main/resources/skills/`, `.deepagents/skills/`, `.agents/skills/`. A
   monorepo with several modules would need per-module roots. Whether to make the root list
   configurable or infer it from `pom.xml` / `pyproject.toml` locations is unresolved.
   **Resolved: fixed conventional patterns matched as a suffix at any depth** (so monorepo
   modules are found without configuration) **plus a `--repo-scan-root` override flag.** Inferring
   roots from build-file locations was rejected as machinery ahead of need.

## 9. Recommended next step

**Phases 2 and 3 are finished; phase 8 is what remains.**

Phase 3 shipped `structure_agent_skills_spec`, seventeen deterministic conformance rules behind
`--spec-checks`, whose catalogue and verdicts live in `src/skillspector/agent_skills_spec.py` and
whose default returns nothing at all. Three things about it were measured rather than assumed and
are worth carrying forward. **First**, the mode gate could *not* be expressed in `confidence`: the
first implementation emitted advisory findings at `0.0`, which `_compute_risk_score` already treats
as reported-but-unscored, and that overload leaked into the baseline fingerprint (which hashes
`confidence`), into the rendered report, and into the `--no-llm` filter. It is now a run-scoped
state key, `unscored_rule_ids`, that `_compute_risk_score` reads as an opaque set —
[§3.5](#the-mechanism--a-run-scoped-state-key-the-scorer-reads) carries the argument
and the invariant it produced. **Second**, the LLM stage had to be made blind to the catalogue
rather than merely made to ignore its answers: `meta_analyzer._model_visible` withholds every SPEC
id from the prompt, from the token overhead the content budget is charged, and from the decision to
call at all, and `apply_filter` skips them on top of that. Skipping alone left the ids in the
prompt, which made the claim "the model is never asked about a SPEC id" false and let the flag move
chunk boundaries for unrelated findings; the `--no-llm` filter needs no exemption at all, since the
catalogue's lowest confidence is 0.7 against a 0.4 threshold. **Third**, the
advisory rendering of §3.5 shipped as the stderr summary line plus a per-finding "not scored" note;
only the separate section heading is outstanding.

The Deep Agents analyzer is
wired and gated (#70) and carries all four of its Rules. `DA-UNRESOLVED` (#71) resolves a literal and a
same-module constant and reports every place a host configuration stopped resolving —
`src/skillspector/deepagents/host_config.py`, the boundary [ADR 0008 §1](adr/0008-deepagents-analyzer-resolves-one-module-deep.md)
copied from the Java track. `DA-SKILL-WRITABLE` (#72) is the verdict the work exists for — one
Finding per resolved Skill source path that no rule denies write to, computed in
`src/skillspector/deepagents/writability.py` by walking the permission rules **in the order they
were written**, because upstream's own advice to place specific rules before broad ones only means
something under first-match-wins. `DA-SHADOW` (#73) is the only Rule here that reasons across
Components: it maps each configured Skill source path onto the files of the Scan through the backend
root and confirms a duplicate Skill `name` across two of them, in
`src/skillspector/deepagents/skill_sources.py`. `DA-SUBAGENT-SKILLS` (#74) is the one whose claim is
correctness rather than security: upstream states that a custom subagent does not inherit the main
agent's Skills, so a definition inside `subagents=[...]` written without its own `skills` runs
without them and nothing at runtime says so. It reads a definition's keys and never its values, and
the general-purpose subagent is excluded structurally rather than by name — nothing declares it, so
there is nothing to exclude. The vocabulary stability measurement (#75) closed the phase: 78
published `deepagents` releases swept, nothing ever removed, recorded in `OBSERVED_VERSION_RANGE`,
with the re-measurement procedure and trigger of [`docs/VOCABULARY_REMEASUREMENT.md`](VOCABULARY_REMEASUREMENT.md)
covering both Frameworks — which closed #46 and found, on its first run, that `L4J-MCP-FILTER`
matched a method no published release declares, corrected in #82.

The boundary went first on purpose: the writability verdict of #72 needed somewhere to fall when it
cannot decide, and building that landing place afterwards would have meant building it twice. It
paid off in a case ADR 0008 did not anticipate: **the "read-only backend" #72 was written around
does not exist upstream.** The captured reference documents four backends and describes none of
them as read-only — the only read-only-ness on the page is a `deny` rule. So the backend axis
contributes unknowability rather than a negative verdict, and it reaches the boundary Rule instead
of clearing a path.

What it reports when it has nothing to do was already decided, in
[ADR 0006](adr/0006-langchain4j-applicability-is-what-it-opens.md): applicability is one predicate
over the Components the analyzer opens — for Deep Agents, Python sources, Python requirement files
and every `SKILL.md`, widened from this section's original two by
[ADR 0008 §3](adr/0008-deepagents-analyzer-resolves-one-module-deep.md) — with both the gate and the
planned work derived from that single result. A Framework mismatch is silent; a matching Framework
that opens nothing reports `not_applicable`; a matching Framework that opens something reports
`completed`, even with no Findings. That shape shipped in #70 rather than being re-decided, and the
vocabulary module of [ADR 0005](adr/0005-langchain4j-upstream-vocabulary.md) shipped alongside it as
`src/skillspector/deepagents/vocabulary.py`.

One thing #70 measured that this section did not anticipate: on a Deep Agents Scan the
`not_applicable` branch is **unreachable**. Every signal §3.2 detects Deep Agents by is a Python
module or a Python requirement file, and both are inside the applicability predicate, read from the
same `file_cache`. The branch is kept because ADR 0006 makes it the shape of an applicability gate,
and later Rules only widen the predicate — but it is exercised from synthetic state, not from a
tree.

The **LangChain4j-in-CI increment is done.** Issue #23, sliced into #28–#31, landed phases 4–7 as
one deliverable: `tree-sitter` accepted as a dependency, a LangChain4j application fixture, the
gated `framework_langchain4j` analyzer carrying all five L4J rules, and the Repository Scan behind
`--repo-scan`.

| Rule | Fires on | Severity |
|------|----------|----------|
| `L4J-SHELL` | `ShellSkills` wiring, or any declared `langchain4j-…shell…` dependency — `langchain4j-experimental-skills-shell` is the only one published, and [ADR 0007](adr/0007-l4j-shell-survives-the-graduation-rename.md) records why the match is wider than it | HIGH |
| `L4J-UNRESOLVED` | A Skill's content, name, description or loader path built at runtime | MEDIUM |
| `L4J-TOOL-DESC` | A `@Tool` description that instructs rather than describes | MEDIUM |
| `L4J-MCP-FILTER` | `McpToolProvider` built without `.filter(...)` or `.filterToolNames(...)` | MEDIUM |
| `L4J-WORKDIR` | `RunShellCommandToolConfig` built without `workingDirectory` | MEDIUM |

Resolvable Skill content — a text block, a literal, a same-unit constant — is handed to the
existing content analyzers and relocated onto the Java file and line it came from. What cannot be
resolved is reported rather than chased, which is the §3.6 boundary made visible.

One thing is worth carrying forward rather than leaving in the closed issues:

- **`--recursive` and `--repo-scan` now overlap.** They answer similar questions with different
  discovery depth, different `--baseline` support and different combined output.

  **Settled by issue #39, and not the way this paragraph originally assumed.** Consolidating the two
  discovery functions was recorded here as "worth doing"; measured, it is not. `repository_scan.py`
  already imports `_has_skill_md` and `_extract_skill_name` from `multi_skill.py`, so the leaf logic
  is shared and the two walks have **no lines in common** — `iterdir()` at depth one with no skip
  set and a `>= 2` threshold, against `os.walk` with `_SKIP_DIRS | JVM_BUILD_DIRECTORIES`,
  root-suffix matching, dot-directory exceptions and a depth bound. One function serving both needs
  parameters for depth, roots, skip-directories and dot-directory policy, each caller using a
  disjoint subset, plus caller-side threshold and short-circuit: more code than it removes, for no
  behavior change. The overlap is therefore **documented rather than removed** — the README carries a
  table of every difference and a rule for when each flag fits — and `cli`'s fall-through advisory
  now runs discovery and names the flag that would actually find something. Deprecating `--recursive`
  outright (#39's path B) remains available and would need its own release note and a deprecation
  window; nothing here forecloses it.

This increment **overrode §5's value-to-risk order**, which recommended phase 2 first as the
cheapest. [ADR 0004](adr/0004-langchain4j-before-deepagents.md) scheduled the Java track ahead of
Deep Agents on risk grounds: `ShellSkills` — unsandboxed arbitrary command execution — is the
highest-severity signal in the design, and covering the gravest risk first outranked minimising
effort-to-first-value. §5 stands unchanged as the value-to-risk analysis of record.

Phase 1 was the recommendation before that. **That is done.** Issue #21 landed
[`src/skillspector/framework.py`](../src/skillspector/framework.py) and the `framework` state key,
set by `build_context` and read by nothing, with detection asserted `agent_skills` on every input
scanned before it existed. The key is projected into the Behavior Snapshot and omitted at
`agent_skills`, so no pre-existing snapshot changed and a future change that flips one to another
Framework fails the gate on the key's appearance.

The recommendation before that was to make the behavior gate executable before any analyzer
work, because until it existed every phase in [§5](#5-phasing) carried an acceptance criterion
nobody could demonstrate. **That is done.** Issue #4, sliced into #5–#9, landed the committed
snapshot corpus in [`tests/behavior/`](../tests/behavior/): 35 fixtures, blocking in
`make test-unit`, verified in CI, demonstrated red on a real behavior change, with its blind
spots stated in [`COVERAGE_LIMITS.md`](../tests/behavior/COVERAGE_LIMITS.md). Every phase below
can now be claimed behavior-preserving against evidence rather than against a promise: the
snapshot test is green with no snapshot file modified in the same change.

Phase 5 was the previous recommendation here, on the grounds that a LangChain4j fixture would
make the [§3.7](#37-repository-level-discovery-cicd) claim falsifiable. **That purpose is
discharged.** The claim was settled by reading the source instead, and the real failure mode —
one giant anonymous skill, not zero skills — is recorded in §3.7. What remains of phase 5 is
test data for phase 6. With ADR 0004 scheduling the Java track first and ADR 0001 accepted, the
phase-4 gate that blocked it is closed: phase 5 is now the immediate prerequisite for the
LangChain4j-in-CI increment above.
