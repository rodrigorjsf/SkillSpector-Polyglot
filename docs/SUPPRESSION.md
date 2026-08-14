# Baseline / False-Positive Suppression

SkillSpector's analyzers — especially the LLM semantic ones — can produce
findings that are correct in general but not actionable for *your* skills
(framework/architectural patterns, first-party tooling conventions, accepted
lab practices). A **baseline** lets you suppress those known findings so that:

- the risk score reflects only **un-triaged** issues,
- re-scans surface only **new** findings (incremental CI/CD), and
- every suppression carries an auditable **reason**.

Suppressed findings never count toward the risk score or active finding count.
They remain in SARIF marked with an external suppression for auditability. They
are shown in the terminal/Markdown report only when you pass `--show-suppressed`,
and are always listed (machine-readable) in the JSON report under `suppressed` /
`suppressed_count`.

> Addresses [issue #88](https://github.com/NVIDIA/SkillSpector/issues/88).

## Quick start

```bash
# 1. Accept all current findings into a baseline (run once).
skillspector baseline ./my-skill/ -o .skillspector-baseline.yaml

# 2. Commit the baseline, then scan against it. Only NEW findings are reported.
skillspector scan ./my-skill/ --baseline .skillspector-baseline.yaml

# Review what was suppressed.
skillspector scan ./my-skill/ --baseline .skillspector-baseline.yaml --show-suppressed
```

## CLI

| Command / option | Description |
|------------------|-------------|
| `skillspector baseline <path> [-o FILE] [--no-llm] [--reason TEXT]` | Scan and write a baseline that fingerprint-suppresses every current finding. Default output: `.skillspector-baseline.yaml`. **A baseline that has to keep matching is a `--no-llm` baseline**: without the flag the LLM stage writes model text into four hashed fields, with no temperature or seed pinned, so the same defect can fingerprint two ways between identical runs — see [What a fingerprint binds to](#what-a-fingerprint-binds-to). |
| `skillspector scan <path> --baseline FILE` (`-b`) | Suppress findings matching the baseline before scoring/reporting. |
| `skillspector scan <path> --baseline FILE --show-suppressed` | Also list the suppressed findings (they still don't affect the score). |

A missing, malformed, or unsupported baseline file exits with code 2.
When a selected baseline or baseline output is stored inside the scan target,
SkillSpector treats that exact file as an explicit scope exclusion. This
prevents sensitive rule text from creating a finding against itself or entering
regenerated fingerprints. Other baseline files and sibling YAML/JSON files
remain in normal scan scope unless they are selected with `--baseline` or `-o`.

## Baseline file format

YAML or JSON (the `.json` extension selects JSON output when generating). Two
complementary mechanisms:

```yaml
version: 2
scanner_version: "X.Y.Z" # generated automatically; do not edit

rules:                       # human-authored, glob-based, drift-tolerant
  - id: "SQP-1"              # glob over the finding's rule id
    reason: "Trigger-phrase breadth is a description nit, not a vuln"
  - id: "SSD-2"
    path: "example-skill/SKILL.md"       # glob over the finding's file
    message: "*example false-positive phrase*"   # glob over its description or matched text
    reason: "False positive: benign trigger phrase, not an instruction"

fingerprints:                # machine-generated, exact
  - hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    rule_id: "SDI-2"         # informational (for humans reading the file)
    file: "example-skill/SKILL.md"
    reason: "Accepted — reads its own environment for context"
```

### `rules` — glob suppression

A finding is suppressed when **every** field a rule specifies matches it;
unspecified fields match anything. Use this for:

- **Global pattern suppression** — `id: "SQP-1"` (or `id: "SQP-*"`) drops a rule
  or rule family across all skills.
- **Skill/file-scoped suppression** — add `path:` (and optionally `message:`) to
  scope the suppression to a specific skill, file, or message.

Field reference:

| Field | Matches against | Notes |
|-------|-----------------|-------|
| `id` (or `rule_id`) | `Finding.rule_id` | glob |
| `path` (or `file`) | `Finding.file` | glob; `*` crosses `/`, `**` is an alias for `*` |
| `message` | `Finding.message`, plus the matched text shown as `finding` in reports | glob, case-insensitive; wrap a keyword in `*` for substring |
| `reason` | — | required; recorded in reports and audits |

Glob matching uses Python's [`fnmatch`](https://docs.python.org/3/library/fnmatch.html),
so `*` matches across path separators (`*SKILL.md` matches `a/b/SKILL.md`).
Rules are **drift-tolerant**: they keep working after line numbers shift or
content is reworded.

### `fingerprints` — exact suppression

Each entry is a full SHA-256 digest over canonical JSON that binds the finding
to the SkillSpector version, normalized component path, complete decoded text
presented to the scanner, and every risk/evidence field (including rule,
severity, confidence, location, matched text, context, intent, and tags).
Generated by `skillspector baseline`, it is intentionally exact:
editing the source or upgrading SkillSpector keeps the finding active until it
is reviewed and the baseline is regenerated.

Every v2 entry must be a mapping with a 64-hex-character `sha256:` hash and a
non-empty `reason`. `rule_id` and `file` are informational fields for reviewers.
If source content is unavailable or `scanner_version` does not match, exact
fingerprints fail closed and suppress nothing. Use `rules` only when you
intentionally want a reviewed suppression to survive source drift.

### What a fingerprint binds to

**A fingerprint binds to the evidence — what was found and where.** Every field it
hashes is something the scanner observed: the file's content, the rule, the
severity, the location, the emitted text. The rule that keeps it that way is that
**no analyzer may encode how the run was configured into a `Finding`** — a baseline
is committed and shared, so a fingerprint that moved with the command line would
suppress a finding under one invocation and not another, silently, and every field
of a `Finding` is hashed.

That rule is what makes an **Agent Skills conformance finding** (`SPEC-1` …
`SPEC-17`, see
[Specification conformance](../README.md#specification-conformance----spec-checks))
mode-independent, and `skillspector baseline --spec-checks` relies on it. A
baseline generated under `advisory` suppresses the same defect under `strict`, and
the other way round: escalating the mode changes what a finding *costs*, not
whether the baseline accepts it, so nothing a team already reviewed comes back
unannounced. The mode is carried in graph state rather than on the finding, and
the invariant is restated in `suppression.finding_fingerprint` so the next such
overload is caught at the source.

That holds for **every** finding in the scan, not only the conformance ones,
because `--spec-checks` is inert to the LLM stage: `meta_analyzer._model_visible`
keeps every `SPEC-*` id out of the meta-analysis prompt *and* out of the token
overhead the per-file content budget is charged, so enabling the flag cannot move
an unrelated finding into a different chunk and get a different answer about it
from the model.

**Two known exceptions, and neither is something the conformance rules
introduced.** Both are inherited behaviour and both predate them.

- **`--no-llm`.** The LLM stage rewrites `confidence`, `message`, `remediation`,
  `explanation` and `tags` — all five hashed — so the same defect fingerprints one
  way with the flag and another way without it. Tracked as
  [issue #124](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/124)
  with the measurement and the repair options.

  **Generating and consuming on the same side of the flag is necessary but not
  sufficient, so it is not the remedy.** With `--no-llm` those five fields are
  computed from the static finding and are stable run to run. Without it, four of
  them are *model output copied verbatim* — `message`, `confidence`, `remediation`
  and `explanation` — and the fifth (`tags`) turns on whether the model confirmed
  the finding. Nothing pins that text: no temperature and no seed are set on the
  chat model, and which model answers is itself run configuration
  (`SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL`, `SKILLSPECTOR_MODEL_<SLOT>`). So
  two consecutive identical invocations may fingerprint the same defect
  differently, and the non-suppression is silent — no warning, no exit-code
  change.

  **A baseline that has to keep matching is a `--no-llm` baseline.** An LLM-side
  baseline is best-effort: useful for a single review pass, not something to
  commit and rely on.
- **The scan root.** `component.path` is normalized relative to the root the scan
  was given, and it is hashed, so a fingerprint only matches a scan rooted the
  same way. This bites on `--repo-scan`, because `skillspector baseline` has no
  repo-scan mode: pointed at a repository root it scans the whole tree as one
  anonymous skill and records `skills/My_Skill/SKILL.md`, while `scan --repo-scan`
  invokes the scanner once per discovered skill directory and records `SKILL.md`.
  Those never match, so that baseline suppresses nothing. **Baseline each skill
  directory** (`skillspector baseline ./skills/My_Skill …`) — those entries do
  match under `--repo-scan`, measurably — and concatenate their `fingerprints`
  lists into the single document `--baseline` accepts. There is no supported
  command that emits that combined document today.

Read the paragraphs above as a rule binding the analyzers, not as a description of
the meta-analysis stage or of how the CLI chooses a scan root.

### Migrating version 1 baselines

Version 1 fingerprints omitted the matched evidence and source content, so a
benign and malicious finding could share a fingerprint when rule, file, line,
and generic message were unchanged. They cannot be upgraded safely without a
new scan and human review. SkillSpector rejects version 1 files that contain
fingerprints; rerun `skillspector baseline`, re-triage every generated entry,
and commit the v2 file. Legacy files containing only explicit rules remain
loadable with a warning so reviewed policy suppressions are preserved. Do not
copy old hashes into the new file.

Recursive multi-skill scans do not accept one shared baseline because exact
fingerprints are scoped to each independently scanned skill. Run each sub-skill
with its own baseline. A single-skill scan still supports `--recursive` together
with `--baseline`.

## How it fits the pipeline

Suppression is applied in the **report node** (`skillspector/nodes/report.py`),
the single place where findings are scored and formatted, so the CLI and any
future REST API behave identically. The CLI loads the baseline file into a
`skillspector.suppression.Baseline` and passes it via graph state
(`state["baseline"]`, `state["show_suppressed"]`); the report node partitions
findings into kept vs. suppressed via
`skillspector.suppression.partition_findings`.

## Recommended workflow

1. Triage the first scan and generate exact v2 fingerprints for individually
   accepted findings. Reserve drift-tolerant `rules` for deliberate,
   tightly-scoped policy suppressions: source changes do not invalidate them,
   so a broad rule can hide newly malicious content.
2. Commit the baseline file to the repo.
3. In CI, run `skillspector scan <path> --baseline <file>`; the build fails
   (exit 1) only when a **new** finding pushes the risk score above threshold.
4. Periodically review with `--show-suppressed` and prune stale entries.
