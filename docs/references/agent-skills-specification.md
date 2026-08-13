# Agent Skills specification

> **Source:** <https://agentskills.io/specification>
> **Captured:** 2026-08-01
>
> **Verified:** 2026-08-02 — re-fetched from `Source:`. Every heading on the upstream page
> is present here, so this capture is not partial, and `allowed-tools` is still specified
> as a space-separated string. Scope of that check: a heading-level comparison plus that
> one spot check, not a line-by-line re-audit of every normative claim.
>
> **Status:** normative. This is the shared format both LangChain4j Skills and
> LangChain Deep Agents defer to, and the format SkillSpector's `SKILL.md`
> manifest parser already targets.

---

## Directory structure

A skill is a directory containing, at minimum, a `SKILL.md` file:

```
skill-name/
├── SKILL.md          # Required: metadata + instructions
├── scripts/          # Optional: executable code
├── references/       # Optional: documentation
├── assets/           # Optional: templates, resources
└── ...               # Any additional files or directories
```

## `SKILL.md` format

The `SKILL.md` file must contain YAML frontmatter followed by Markdown content.

### Frontmatter fields

| Field | Required | Constraints |
|-------|----------|-------------|
| `name` | Yes | Max 64 characters. Lowercase letters, numbers, and hyphens only. Must not start or end with a hyphen. |
| `description` | Yes | Max 1024 characters. Non-empty. Describes what the skill does and when to use it. |
| `license` | No | License name or reference to a bundled license file. |
| `compatibility` | No | Max 500 characters. Indicates environment requirements (intended product, system packages, network access, etc.). |
| `metadata` | No | Arbitrary key-value mapping for additional metadata. |
| `allowed-tools` | No | **Space-separated string** of pre-approved tools the skill may use. (Experimental) |

Minimal example:

```markdown
---
name: skill-name
description: A description of what this skill does and when to use it.
---
```

Example with optional fields:

```markdown
---
name: pdf-processing
description: Extract PDF text, fill forms, merge files. Use when handling PDFs.
license: Apache-2.0
metadata:
  author: example-org
  version: "1.0"
---
```

### `name`

The required `name` field:

- Must be 1–64 characters
- May only contain unicode lowercase alphanumeric characters (`a-z`, `0-9`) and hyphens (`-`)
- Must not start or end with a hyphen (`-`)
- Must not contain consecutive hyphens (`--`)
- **Must match the parent directory name**

Valid: `pdf-processing`, `data-analysis`, `code-review`

Invalid:

```yaml
name: PDF-Processing  # uppercase not allowed
name: -pdf            # cannot start with hyphen
name: pdf--processing # consecutive hyphens not allowed
```

### `description`

The required `description` field:

- Must be 1–1024 characters
- Should describe both what the skill does and when to use it
- Should include specific keywords that help agents identify relevant tasks

Good:

```yaml
description: Extracts text and tables from PDF files, fills PDF forms, and merges multiple PDFs. Use when working with PDF documents or when the user mentions PDFs, forms, or document extraction.
```

Poor:

```yaml
description: Helps with PDFs.
```

### `license`

Optional. Specifies the license applied to the skill. Keep it short — either the name of
a license or the name of a bundled license file.

```yaml
license: Proprietary. LICENSE.txt has complete terms
```

### `compatibility`

Optional. Must be 1–500 characters if provided. Should only be included if the skill has
specific environment requirements: intended product, required system packages, network
access needs. Most skills do not need this field.

```yaml
compatibility: Designed for Claude Code (or similar products)
compatibility: Requires git, docker, jq, and access to the internet
compatibility: Requires Python 3.14+ and uv
```

### `metadata`

Optional. A map from string keys to string values. Clients can use this to store
additional properties not defined by the specification. Key names should be reasonably
unique to avoid accidental conflicts.

```yaml
metadata:
  author: example-org
  version: "1.0"
```

### `allowed-tools`

Optional, **experimental**. A space-separated string of tools that are pre-approved to
run. Support for this field may vary between agent implementations.

```yaml
allowed-tools: Bash(git:*) Bash(jq:*) Read
```

### Body content

The Markdown body after the frontmatter contains the skill instructions. There are no
format restrictions.

Recommended sections:

- Step-by-step instructions
- Examples of inputs and outputs
- Common edge cases

The agent loads this entire file once it has decided to activate a skill. Longer
`SKILL.md` content should be split into referenced files.

## Optional directories

### `scripts/`

Executable code that agents can run. Scripts should be self-contained or clearly document
their dependencies, include helpful error messages, and handle edge cases gracefully.
Supported languages depend on the agent implementation; common options are Python, Bash,
and JavaScript.

### `references/`

Additional documentation that agents read when needed — `REFERENCE.md` for detailed
technical reference, `FORMS.md` for form templates or structured data formats,
domain-specific files (`finance.md`, `legal.md`). Keep individual reference files
focused; agents load them on demand, so smaller files use less context.

### `assets/`

Static resources: document or configuration templates, images (diagrams, examples), data
files (lookup tables, schemas).

## Progressive disclosure

Agents load skills *progressively*, pulling in more detail only as a task calls for it:

| Level | What loads | Budget |
|-------|------------|--------|
| 1. Metadata | `name` and `description`, for every skill | ~100 tokens |
| 2. Instructions | Full `SKILL.md` body, when the skill is activated | < 5000 tokens recommended |
| 3. Resources | Files under `scripts/`, `references/`, `assets/` | Loaded only when required |

Keep the main `SKILL.md` under **500 lines**. Move detailed reference material into
separate files.

## File references

When referencing other files in a skill, use relative paths from the skill root:

```markdown
See [the reference guide](references/REFERENCE.md) for details.

Run the extraction script:
scripts/extract.py
```

Keep file references one level deep from `SKILL.md`. Avoid deeply nested reference chains.

## Validation

The upstream [`skills-ref`](https://github.com/agentskills/agentskills/tree/main/skills-ref)
reference library validates frontmatter and naming conventions:

```bash
skills-ref validate ./my-skill
```

---

## Relevance to SkillSpector

*This section is SkillSpector's analysis, not upstream content.*

The specification defines machine-checkable constraints that SkillSpector's manifest
parser reads but does **not** currently validate. `_parse_manifest`
(`src/skillspector/nodes/build_context.py:253`) extracts `name`, `description`,
`triggers`, `permissions`, `allowed-tools`, and `parameters`, then returns them
unvalidated.

Unenforced constraints, each a candidate rule — and each now a rule of
`structure_agent_skills_spec`, which reads its own copy of the declaration block (`_parse_manifest`
is unchanged) and runs only when `--spec-checks` asks it to:

| Constraint | Spec section | Handling |
|------------|--------------|----------|
| `name` matches parent directory name | [`name`](#name) | SPEC-4, scored |
| `name` charset / length / hyphen rules | [`name`](#name) | SPEC-5, SPEC-6, SPEC-7, and SPEC-2 for the 1-character lower bound |
| `description` present and ≤ 1024 chars | [`description`](#description) | SPEC-3, SPEC-8, SPEC-9 |
| `compatibility` ≤ 500 chars | [`compatibility`](#compatibility) | SPEC-10; still not parsed into graph state |
| `SKILL.md` body ≤ 500 lines / ~5000 tokens | [Progressive disclosure](#progressive-disclosure) | SPEC-12, SPEC-13 |
| File references one level deep | [File references](#file-references) | SPEC-15, SPEC-16, over Markdown link targets only |

### `allowed-tools` is space-separated, not comma-separated

The specification defines `allowed-tools` as a **space-separated string**. SkillSpector
splits it on commas in two places:

- `src/skillspector/nodes/build_context.py:297` — `allowed_tools.split(",")`
- `src/skillspector/nodes/analyzers/mcp_least_privilege.py:143` — `value.split(",")`

A spec-canonical value therefore collapses into one opaque token:

```
input:      "Bash(git:*) Bash(jq:*) Read"
parsed:     ['Bash(git:*) Bash(jq:*) Read']
categories: set()
```

`_map_allowed_tools_to_categories`
(`src/skillspector/nodes/analyzers/mcp_least_privilege.py:190`) does an exact
lowercase lookup, so the single token matches nothing. The declaration is non-empty —
`has_declaration` is `True` at `mcp_least_privilege.py:334` — while the derived
capability set is empty. LP1/LP4 then reason over a skill that appears to declare tools
while granting no capabilities.

Note that scoped tool syntax (`Bash(git:*)`) does not match `_TOOL_TO_CAPABILITY`
(`mcp_least_privilege.py:172`) even after correct whitespace splitting; the base tool
name must be extracted first.

**This deviation is known and deliberately retained.** Changing the parsing alters findings
on scans that run today, and preserving current behavior takes precedence over spec
fidelity. Do not "fix" it as a drive-by.

The conditions that would reopen the decision — and the blast radius if it is reopened —
are recorded in
[MULTI_FRAMEWORK_SKILL_ANALYSIS.md § Known deviation](../MULTI_FRAMEWORK_SKILL_ANALYSIS.md#known-deviation-allowed-tools-separator).
In short: a real scan producing a wrong LP1/LP3/LP4 verdict on a space-separated
`allowed-tools` value, a user-reported false negative or positive traced to this parsing, or
upstream changing it first.

### What this specification does not define

The specification defines how a Skill is laid out and declared — directory structure, the
Manifest fields, and authoring guidance. It says nothing about how a host agent wires
Skills in, and in particular it defines **no named integration approaches**. If you came
here looking for
"tool-based agents" or "filesystem-based agents" because
[langchain4j-skills.md](langchain4j-skills.md) cites the specification for them, the terms
are absent by fact, not by omission in this capture — that citation is upstream
LangChain4j's own framing, verified and documented in
[langchain4j-skills.md § The two "integration approaches" are not specification vocabulary](langchain4j-skills.md#the-two-integration-approaches-are-not-specification-vocabulary).

Host-side integration is covered by a separate, non-normative upstream guide,
`https://agentskills.io/client-implementation/adding-skills-support`. Do not cite this
specification for a claim that only that guide supports.
