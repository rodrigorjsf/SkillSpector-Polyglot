# SkillSpector-Polyglot

**Security scanner for AI agent skills, across frameworks.** Detect vulnerabilities, malicious
patterns, and security risks in the skills an agent loads — whether they ship as a standalone
`SKILL.md` bundle or live inside a programming-language framework's source tree.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Fork of NVIDIA/SkillSpector](https://img.shields.io/badge/fork%20of-NVIDIA%2FSkillSpector-76b900.svg)](https://github.com/NVIDIA/SkillSpector)

---

## Mission

Agent skills execute with implicit trust. Upstream [SkillSpector](https://github.com/NVIDIA/SkillSpector)
answers **"is this skill safe to install?"** for a skill you obtain as a bundle — a directory, a zip,
a Git repository — and answers it well.

That framing has a blind spot, and it is the one this fork exists to close. In an *agentic project*,
a skill is not something you download and inspect before installing. It is **source code you already
own**: a `SKILL.md` under `src/main/resources/skills/` loaded by LangChain4j's classpath loader, a
Java `@Tool` method whose description instructs the model, a shell tool wired without a working
directory. Nobody ever "installs" it, so nobody ever vets it — and the instruction surface reaching
the model is assembled at build time from files scattered across a multi-module repository.

**SkillSpector-Polyglot's objective:** make the skills embedded in a framework's own codebase a
first-class subject of security analysis, so a team can gate them in CI on every pull request, with
the same rule catalog, the same 0–100 risk score, and the same SARIF output already used for
standalone skills.

Two commitments follow from that, and they constrain every change made here:

- **Upstream behavior is never altered.** Every capability this fork adds is gated on framework
  detection or on an explicit flag. On an input upstream already scans, the output is byte-for-byte
  what upstream produces. This is enforced by a test gate, not by good intentions —
  see [the unchanged-behavior gate](docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md#4-the-unchanged-behavior-gate).
- **Nothing is claimed before it is built.** The support matrix below states what actually ships
  today, and names what is still a design proposal.

## Framework support

What SkillSpector-Polyglot does with a scanned tree depends on the framework it detects
(`src/skillspector/framework.py`). Detection is automatic — there is no flag to set.

| Framework | Language | Detection | Framework-specific rules | Status |
|---|---|---|---|---|
| **Agent Skills** (Claude Code, Codex CLI, Gemini CLI, …) | any | default | — (the full 77-pattern base catalog applies) | **Shipped** — upstream behavior, unchanged |
| **LangChain4j** | Java / Kotlin | `langchain4j` Maven coordinate, `dev.langchain4j` import, or `src/main/resources/skills/` layout | 5 rules — `L4J-SHELL`, `L4J-UNRESOLVED`, `L4J-TOOL-DESC`, `L4J-MCP-FILTER`, `L4J-WORKDIR` | **Shipped** |
| **Deep Agents** (Python) | Python | `deepagents` distribution, `import deepagents`, or `create_deep_agent(` | 4 rules — `DA-SKILL-WRITABLE`, `DA-SHADOW`, `DA-SUBAGENT-SKILLS`, `DA-UNRESOLVED` | **Shipped** — `framework_deepagents` reads the host-side `create_deep_agent(...)` configuration, says per skill source path whether the agent can rewrite it, reports a skill in a later source that silently replaces a same-named one in an earlier source, reports a custom subagent defined without skills of its own, and reports where resolution stopped ([design](docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md), [shape](docs/adr/0008-deepagents-analyzer-resolves-one-module-deep.md)) |
| **Deep Agents** (JavaScript) | TypeScript / JavaScript | `"deepagents"` in a `package.json` `dependencies`, `devDependencies`, `peerDependencies` or `optionalDependencies` block — read out of the parsed manifest, so a key of that name elsewhere in the file is not a signal — plus `import`/`require` of `deepagents`, or `createDeepAgent(` where a statement could start, so a help string, a `//` line or a JSDoc line quoting the SDK is not a signal, while a template literal quoting it still is, because its contents are whole lines ([#127](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/127)) — every signal gated on a `.ts`/`.tsx`/`.mts`/`.cts`/`.js`/`.mjs`/`.cjs` file or a `package.json`, because the npm and PyPI distribution names are identical | the **same 4 rules** — `DA-SKILL-WRITABLE`, `DA-SHADOW`, `DA-SUBAGENT-SKILLS`, `DA-UNRESOLVED` | **Shipped** — `framework_deepagents_js` asks the same four questions of the host-side `createDeepAgent({...})` options object, parsed with `tree-sitter-typescript`. The rule ids are reused rather than duplicated: it is the same upstream framework in a second language, so a glob suppression rule keyed on `rule_id` covers both tracks and the catalogue stays one entry per question. What differs is the shapes read — an options object rather than keyword arguments, a plain object literal rather than `FilesystemPermission(...)`, a positional route map rather than `routes=`, and `interruptOn` rather than `interrupt_on`. The four rules mean the same thing in both tracks and are asked over the same two write tools, so a configuration reported one way in Python is reported the same way in TypeScript ([design](docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md), [shape](docs/adr/0009-tree-sitter-for-typescript-parsing.md), [capture](docs/references/deepagents-js-skills.md)) |

The base catalog — prompt injection, data exfiltration, privilege escalation, supply chain, taint
tracking, YARA signatures, MCP least privilege, and the rest — applies to **every** framework. The
rows above add to it; they never replace it. Full rule tables are in
[Vulnerability Patterns](#vulnerability-patterns).

### Specification conformance — `--spec-checks`

One rule set belongs to no framework row, because all four frameworks implement the same
[Agent Skills specification](docs/references/agent-skills-specification.md): 17 deterministic
conformance rules, `SPEC-1` … `SPEC-17`, string comparisons and path lookups with no LLM
involved. Fifteen check a constraint the captured specification states; **two are loader
behavior** and are labelled as such rather than attributed to the page — `SPEC-14` (Deep Agents
skips a 10 MB manifest) and `SPEC-17` (the page states no skill-name uniqueness clause). They are
**off by default** and reached with `--spec-checks`:

| Value | What runs |
|---|---|
| `off` *(default)* | Nothing. The scan is byte-for-byte what it was before the flag existed |
| `advisory` | All 17 rules report; only the five with a runtime consequence — `SPEC-4`, `SPEC-9`, `SPEC-14`, `SPEC-15`, `SPEC-17` — affect the risk score. The other twelve are printed, marked `not scored` beside their confidence, and contribute zero |
| `strict` | All 17 rules report **and** affect the risk score |

```bash
# Report all 17; only the five with a runtime consequence reach the score
skillspector scan ./my-skill --no-llm --spec-checks advisory

# Gate on conformance too: all 17 reach the score
skillspector scan ./my-skill --no-llm --spec-checks strict
```

**Neither mode is inert, including `advisory`.** Its five scored rules raise the risk score like
any other finding, so a skill near the threshold can move from `SAFE` to `CAUTION` — or across it,
turning exit `0` into exit `1` and failing a build. Every conformance finding also enters the SARIF
output, so a code-scanning upload gains alerts for them. Turning the flag on is a change to what
your gate does; `off`, the default, is the only mode that changes nothing.

**The flag works the same with or without the LLM stage.** That stage filters MEDIUM and LOW
findings by asking the model to confirm them, and every conformance rule is MEDIUM or LOW — so
these findings used to be dropped almost entirely unless you passed `--no-llm`, which turns off the
semantic analysis the rest of the tool exists for. The conformance catalogue is now **exempt from
that filter**: a rule that is a string comparison has nothing for a security model to confirm or
deny, and a confirmed one would also have its confidence rewritten by the model. A conformance
finding is reported at its rule's own confidence on both paths, so `--spec-checks` needs no pairing
and the CLI prints no advice about one.

**In `advisory`, each unscored finding says so in the report, and one line on stderr counts them.**
The report prints the rule's real confidence and appends the reason it did not count —
`Confidence: 100% (not scored — run with --spec-checks strict to include)` — in both the terminal
and Markdown output, so a reviewer is never told the scanner is unsure about a string comparison.
Beside that, on stderr —
`Spec conformance: N advisory finding(s) reported without affecting the risk score.` The count is
what the report carries, so a finding a `--baseline` already accepted is not in it — the line is
absent entirely when the baseline accepts them all. It is a note about the scan rather than part of
it, so it never joins the report on stdout, and it is a total for the run: `--recursive` and `--repo-scan` invoke the scanner once per discovered skill and the
count covers all of them. `strict` prints no such line, because there everything is in the score.

**That note is prose only: the JSON and SARIF reports carry no per-finding signal that a
conformance finding was reported without being scored.** Both formats emit an advisory finding
exactly as they emit a scored one — same rule id, same severity, same confidence — so a machine
consumer of `--format json` or `--format sarif` can tell the two modes apart only by the risk
score. The stderr line above is the whole of the machine-visible signal, and it is a total for the
run rather than a mark on a finding
([issue #125](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/125)).

Two rules deliberately under-match rather than guess: `SPEC-15` and `SPEC-16` read Markdown link
targets only (a bare `scripts/extract.py` written in prose is not read as a reference, and a link
inside a fenced code block is treated as an example), and `SPEC-4` stays silent when the scanned
root is a temporary directory this tool created — a git clone, a download, a zip or a single
file — because the directory name there is not the author's. `SPEC-15` accepts a percent-encoded
link target — `references/User%20Guide.md` resolves against `references/User Guide.md` — and tries
the raw spelling too, so a file whose name really holds a `%` still resolves; `SPEC-16` measures
depth on the raw target, so an encoded `%2F` is a character rather than another level.

**`SPEC-15` reports a missing file, never a file the scan declined to look for.** It is scored, so
the difference costs real points. It stays silent for a target the scan was in no position to find:

- **A single-file input** (`skillspector scan ./my-skill/SKILL.md`), which copies the manifest alone
  into a temporary directory and so carries no tree at all. A clone, a download and a zip **do**
  carry the skill's tree, so `SPEC-15` keeps reporting on all three — the exclusion is the lone-file
  shape and nothing wider.
- **A hidden file** and **a pruned directory** (`node_modules/` and its neighbours), both of which
  the scan already records as out of scope in `analysis_completeness.scope_exclusions`. Reporting
  them made one report say both that a path is out of scope and that the path was not found.

One shape is **not** covered: a file under a **directory symlink**, which the walk does not descend
and records no exclusion for, so a conforming skill still earns a scored finding there
([issue #123](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/123)).

**A `SKILL.md` a skill *ships* is not a skill directory.** The specification defines three
directories for what a skill bundles — `scripts/`, `references/`, `assets/` — and a manifest under one
of them is a template or an example, so it is not inspected at all. Without that, a conforming skill
shipping `references/SKILL.md` earned 20 scored points: `SPEC-4` against the directory name
`references`, plus `SPEC-17` against the skill that ships it. **The exclusion is those three names
and nothing more**, so a manifest parked somewhere the specification names no convention for —
`docs/examples/SKILL.md` — is still read as a skill directory and can still collide with the skill
around it ([issue #121](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/121)).

**A baseline is not bound to the mode it was taken in.** A v2 fingerprint binds to the *evidence* a
finding carried — the file's content, the rule, the location, the emitted text — and which mode you
ran is not evidence. So a baseline generated under `--spec-checks advisory` also suppresses under
`strict`, and the other way round: escalating the mode changes what a conformance finding costs, not
whether the baseline accepts it, and nothing your team already reviewed comes back unannounced.
That covers every finding in the scan and not just the conformance ones, because the flag is inert
to the LLM stage: no `SPEC-*` id reaches the meta-analysis prompt or the token budget that decides
where a large file is split, so turning it on cannot change what the model is told about an
unrelated finding beside it. Regenerate the baseline when the scanner version or the file content
changes, as always — not when you change this flag.

Two things a baseline *is* bound to, both of which predate conformance checking and apply to every
rule. `--no-llm` moves five hashed fields, four of which are model output copied verbatim when the
flag is off — with no temperature or seed pinned and the model itself env-selectable — so the LLM
side offers no fingerprint stability at all, not even between two identical invocations. **A
baseline you commit and rely on is a `--no-llm` baseline**; an LLM-side one is best-effort
([issue #124](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/124)). And a fingerprint
binds to the path *relative to the scan root*, so a baseline taken with `skillspector baseline .`
suppresses nothing under `--repo-scan`, which scans each discovered skill as its own root — baseline
each skill directory instead. See [Baseline suppression](docs/SUPPRESSION.md) for the measurement
and for what a fingerprint hashes.

`SPEC-17` compares skill names *across* directories, so it is reachable only when one scan sees
several `SKILL.md` files — the usual shape being a directory that declares no skill of its own and
holds several that do. `--recursive` and `--repo-scan` scan each discovered skill directory
separately, so they reach it only for a skill that nests another skill inside its own tree. A single
directory shipping both accepted manifest spellings is **one** skill, not two: `SKILL.md` wins over
`skill.md`, which is the precedence the rest of the scanner already reads them in, so the shadowed
file raises no rule and `SPEC-17` never reports a directory against itself.

No rule reads `allowed-tools`, whose comma/space handling is a
[recorded deviation](docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md#known-deviation-allowed-tools-separator).

**Deep Agents, precisely:** a Deep Agents project is detected and reported as such, and its
`SKILL.md` files are scanned by the base catalog like any other skill. The `framework_deepagents`
analyzer (Python) or `framework_deepagents_js` analyzer (TypeScript/JavaScript) reads the host-side
configuration on top of that, and the scan report carries a row naming which components it opened,
so an absence of Deep Agents findings is distinguishable from an absence of inspection. **Exactly
one of the two ever runs**, and a repository that is genuinely both — a monorepo with a Python agent
beside a TypeScript one — detects as plain Agent Skills and runs neither, which is the conservative
answer detection has always given to an ambiguous tree.

What it says today is **whether the agent can rewrite its own instructions, whether a later skill
source silently replaces a skill in an earlier one, whether a custom subagent was defined without
skills of its own, and where it stopped looking**.
`DA-SKILL-WRITABLE` answers the first, once per resolved skill source path: upstream's
documented default is that an agent may write to skill files unless a permission rule blocks the
path, so an application that adds no denying rule gets one finding per path it passed in
`skills=[...]`. The permission rules are walked in the order they are written — a specific rule
placed before a broad `deny` decides the paths it covers, which is what upstream tells you to
write — and an approval gate, `mode="interrupt"` or `interrupt_on`, lowers the finding to LOW rather
than clearing it. `DA-SHADOW` answers the second, and it is the one finding no scan of a single
skill directory can reach: upstream's later sources override earlier ones for skills of the same
`name`, so a same-named skill in a writable per-user source replaces the vetted one in a shared
library and every later run reads the replacement. It fires only on a **confirmed** collision — the
names are read out of the manifests the configured paths map onto — because layering two sources is
itself a pattern upstream recommends. `DA-SUBAGENT-SKILLS` answers the third, and it is the one
rule here whose claim is correctness rather than security: upstream states that only the
general-purpose subagent inherits the main agent's skills and that every custom subagent needs its
own `skills` parameter, so a definition written without one runs without the capability the
application was built around and nothing at runtime says so. `DA-UNRESOLVED` answers the fourth: a
literal and a constant declared in the same module are read, nothing else is guessed at, and the
skill source list, the backend, the permission rules, the subagent definitions, the store a resolved
skill path is routed to, or a backend root the scan cannot read are each reported whenever they are
assembled at runtime.

What it does **not** say is which subagent a `DA-SUBAGENT-SKILLS` finding belongs to — the upstream
page documents `subagents` in prose and shows no example of a definition, so a finding names the
line the definition opens on rather than a name read out of it. Shadowing is confirmable only where
the skill files are on disk — under the default backend they live in agent state, so the manifests
are opened and reported and no shadowing verdict is reached.

## Who this is for

- **Teams building agentic applications in Java or Kotlin with LangChain4j** — the primary audience.
  You have skills in your own repository and no gate on them today.
- **Teams building agentic applications in Python with Deep Agents** — base-catalog coverage works
  now, the host-side configuration is judged for skill writability, cross-source shadowing and
  subagents defined without skills of their own, and the scan tells you where it stopped.
- **Platform and AppSec engineers** who need agent-skill findings in an existing security pipeline.
  SARIF output uploads to GitHub code scanning; the exit code gates a build.
- **Anyone vetting a third-party skill before installing it** — the original upstream use case,
  which works here exactly as it does upstream.

**This is not for you if** you only ever scan standalone skill bundles and want the canonical,
vendor-maintained tool. Use [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) directly —
this fork adds surface area you would not use.

## Install

The GitHub repository is named `SkillSpector-Polyglot`, but the Python distribution, the importable
package, and the command are all still **`skillspector`**. That is deliberate: renaming them would
break every existing install and every future merge from upstream, and buys nothing. Expect the
repository name and the command name to differ.

```bash
# CLI only
uv tool install git+https://github.com/rodrigorjsf/SkillSpector-Polyglot.git

# With the MCP server extra (needed for `skillspector mcp`)
uv tool install 'skillspector[mcp] @ git+https://github.com/rodrigorjsf/SkillSpector-Polyglot.git'

# From source
git clone https://github.com/rodrigorjsf/SkillSpector-Polyglot.git
cd SkillSpector-Polyglot
uv venv .venv && source .venv/bin/activate
make install          # or: make install-dev
```

The inherited documentation below installs from `github.com/NVIDIA/skillspector`. Those URLs are
left as-is on purpose — they point at upstream, which is where that documentation came from. Use the
fork URLs above to get this fork.

## Usage in an agentic project

The single most important flag for this fork's use case is `--repo-scan`. Pointing the scanner at a
repository root **without** it does not fail — it succeeds wrongly, scanning the whole tree as one
anonymous skill and computing a risk score over that mixture.

```bash
# Scan every skill in an agentic repository, static analysis only, SARIF for CI
skillspector scan . --repo-scan --no-llm --format sarif --output skillspector.sarif

# Re-scan against an accepted baseline: only NEW findings are reported and scored.
# Build the baseline from PER-SKILL runs — `skillspector baseline .` has no --repo-scan
# mode and records paths this scan never emits. See docs/SUPPRESSION.md
skillspector baseline ./skills/my-skill --no-llm -o skillspector-baseline.yaml
skillspector scan . --repo-scan --no-llm --baseline skillspector-baseline.yaml

# A layout the default discovery roots miss
skillspector scan . --repo-scan --repo-scan-root playbooks --repo-scan-root ops/skills
```

```bash
# Add Agent Skills specification conformance to the same run. Not inert: its five
# scored rules raise the risk score and can flip the exit code — see the section below
skillspector scan . --repo-scan --no-llm --spec-checks advisory
```

Discovery roots, the JVM build directories that are skipped, and a complete GitHub Actions job are
documented under [Scanning a Whole Repository](#scanning-a-whole-repository); `--spec-checks` under
[Specification conformance](#specification-conformance----spec-checks).

## Scanning the MCP Registry

`skillspector scan --mcp-registry` is a **Registry Scan** — a mode of its own, not a variation on a
skill scan. It reads records published to the
[MCP Registry](https://registry.modelcontextprotocol.io) and reports on what a server *owner
asserted* about their server. It never downloads or inspects the server itself, so it opens no
component, runs no analyzer, produces no SARIF and issues no `SAFE` / `CAUTION` /
`DO_NOT_INSTALL` recommendation. Only the 0–100 risk score and the exit-code contract are shared
with an ordinary scan.

Use it to vet an MCP server's publication hygiene *before* you install it; use `skillspector scan`
on the server's own repository to vet its code.

### The three input shapes

The positional argument accepts three different things, and which one you gave is decided in this
order:

```bash
# 1. A local JSON file holding a registry payload — an object with a "servers" list
skillspector scan ./registry-dump.json --mcp-registry --format json

# 2. The official registry URL, exactly. Every page is followed via metadata.nextCursor
skillspector scan https://registry.modelcontextprotocol.io/v0/servers --mcp-registry --format json

# 3. A bare server name. Fetches the whole official registry and keeps that server's latest record
skillspector scan ai.agenticshelf/graffeo --mcp-registry --format json
```

Shape 3 is the one the flag's `--help` text does not mention. Anything that is neither an existing
file nor an `http(s)` URL is treated as a server name; a name that matches no published record is an
error, not an empty result. Where a name matches several records — the registry keeps every
published version — the scan assesses the record flagged `isLatest`, falling back to all matches
when none is.

### The payload shape

A payload is an object with a `servers` list, and **each entry wraps its record under a `server`
key** — an entry that is a bare record raises rather than scanning. This matters when you hand-write
or trim a dump: the fields the scan actually reads are these, and nothing else is inspected.

```jsonc
{
  "servers": [
    {
      "server": {
        "name": "ai.example/thing",          // required; a nameless server is an error
        "title": "…", "description": "…", "version": "…", "websiteUrl": "…",
        "repository": { "url": "…", "source": "…", "id": "…", "subfolder": "…" },
        "packages": [
          {
            "registryType": "npm",
            "identifier": "…",
            "version": "1.2.3",
            "fileSha256": "…",
            "transport": { "type": "…", "url": "…" }
          }
        ],
        "remotes": [ { "type": "streamable-http", "url": "https://…" } ]
      },
      "_meta": {
        "io.modelcontextprotocol.registry/official": {
          "status": "active", "publishedAt": "…", "updatedAt": "…", "isLatest": true
        }
      }
    }
  ],
  "metadata": { "nextCursor": "…" }          // followed when fetching the live registry
}
```

Two claims this documentation deliberately does *not* make: that the scan validates a payload against
a published MCP Registry schema, and which revision of that schema it targets. Neither is in the
code. The endpoint it fetches is `/v0/servers`, and the list above is the whole of what it reads —
a hand-made dump that omits the `_meta` block is accepted, and every check that reads it reports
`unavailable`.

### The checks it applies

These are posture checks over a published record, not the Rules an Analyzer applies to a Skill —
nothing here opens a Component, and what it emits is not a Finding. Each is applied per server:

| Check | Fires when | Severity | Risk |
|---|---|---|---|
| `MCP-PACKAGE-VERSION` | A package version is a mutable tag (`latest`, `main`, …), a range (`^1.2`, `1.x`), or carries no digit at all (`snapshot`). For `registryType: npm` only, the bar is higher: anything that is not a full `MAJOR.MINOR.PATCH` fires, so `1.2` fires on npm but not on pypi | high | 30 |
| `MCP-PACKAGE-SHA256` | A declared `fileSha256` is not 64 **lowercase** hex characters — an uppercase digest fires | high | 25 |
| `MCP-PLAIN-HTTP` | A remote endpoint URL starts with `http://` | high | 25 |
| `MCP-OFFICIAL-STATUS` | The registry's official status is anything other than `active` (e.g. `deprecated`) | medium | 20 |
| `MCP-REPOSITORY` | The record carries no repository URL — always reported as `unavailable`, never as a verdict | info | 0 |

Where a field is absent, some — not all — of these report `unavailable`: an `info`, zero-risk entry
saying the check could not be made rather than passing silently. Which ones, exactly:

- `MCP-REPOSITORY` and `MCP-OFFICIAL-STATUS` are applied **once per server, always**, and report
  `unavailable` when the record carries no repository URL or no official status.
- `MCP-PACKAGE-VERSION` and `MCP-PACKAGE-SHA256` are applied **once per package object**, and report
  `unavailable` when that object omits `version` or `fileSha256`. A record whose `packages` list is
  empty or absent produces neither — an unpackaged server is not reported as unexamined.
- `MCP-PLAIN-HTTP` has no `unavailable` result at all: a record with no remotes produces nothing.

The risk score is the sum of the entries' scores across **every** server in the payload, capped at
100 — so scanning the whole registry says nothing useful about any single server. `max_risk_score`
carries the worst single entry. Scan one server at a time when you want a per-server verdict.

### Constraints, before you hit them

- **`--format json` is mandatory.** The default is `terminal`, so the bare
  `skillspector scan <target> --mcp-registry` exits `2` with
  `Error: --mcp-registry currently supports only --format json`. SARIF is unavailable in this mode
  today; the error says "currently" because the restriction is a limitation, not a design promise.
- **Six flags are rejected outright**, exit `2`: `--recursive`, `--repo-scan`, `--baseline`,
  `--show-suppressed`, `--yara-rules-dir`, `--spec-checks`. There is no way to accept a known
  posture check and stop scoring it — baselines apply to skill scans only. `--spec-checks` is
  rejected rather than ignored because a Registry Scan opens no component and runs no analyzer: it
  assesses what a server owner published, and there is no `SKILL.md` to hold to a specification.
- **Three flags are accepted and silently ignored**: `--no-llm`, `--verbose` / `-V` and
  `--repo-scan-root`. A Registry Scan never calls an LLM, with or without `--no-llm`.
- `--output` / `-o` works and writes the JSON report to the given path.
- Exit codes match a skill scan: `0` when the risk score is ≤ 50, `1` when it is > 50, `2` on any
  error — including a malformed payload, an unreachable registry, or an unknown server name.

### What leaves your machine

A Registry Scan does not go through the ordinary input handler, so the `ALLOWED_DOWNLOAD_HOSTS`
allowlist that governs `skillspector scan <url>` does not apply to it. It has a narrower rule
instead: the **only** URL it will fetch is the official registry endpoint,
`https://registry.modelcontextprotocol.io/v0/servers`. Any other `http(s)` argument is rejected
before a request is made. Requests carry a 30-second timeout and do not follow redirects. Nothing
else is contacted — no LLM provider, no package registry, no repository host.

### Output

```console
$ skillspector scan ./registry-dump.json --mcp-registry --format json
{
  "mcp_registry": true,
  "source": "./registry-dump.json",
  "server_count": 3,
  "risk_score": 45,
  "max_risk_score": 25,
  "findings": [
    {
      "id": "MCP-PLAIN-HTTP",
      "target": "http://example.invalid/mcp",
      "message": "Remote endpoint uses plain HTTP",
      "severity": "high",
      "evidence": "registry_assertion",
      "risk_score": 25
    }
  ],
  "snapshots": [ ... ],
  "servers": [ { "snapshot": { ... }, "findings": [ ... ] } ]
}
```

`findings` is flat across all servers; `servers` pairs each snapshot with its own findings; and
`snapshots` is the normalized record — including a `record_hash` over the published record and the
official metadata, which is stable under JSON key reordering and so is usable for detecting that an
owner changed a published record between two scans.

## Configuration

Everything is configured through environment variables and CLI flags — there is no config file.
Static analysis needs no credentials at all; only the optional LLM stage does.

| What you want | How |
|---|---|
| No credentials, no network egress to an LLM | `--no-llm` |
| Choose an LLM provider | `SKILLSPECTOR_PROVIDER` — `openai`, `anthropic`, `anthropic_proxy`, `bedrock`, `nv_build`, `claude_cli`, `codex_cli`, `gemini_cli` |
| Use a local agent CLI session instead of an API key | `SKILLSPECTOR_PROVIDER=claude_cli` (or `codex_cli`) |
| Override the model | `SKILLSPECTOR_MODEL` |
| Debug a scan | `SKILLSPECTOR_LOG_LEVEL=DEBUG`, or `-V` |
| Report Agent Skills specification conformance | `--spec-checks advisory` (reported, unscored) or `--spec-checks strict` (scored) |

The complete variable table is in [Environment Variables](#environment-variables), every flag in
[CLI Options](#cli-options), and what leaves your machine in
[Trust model and data egress](#trust-model-and-data-egress).

## Transparency

- **This is a community fork, not an NVIDIA product.** It is not endorsed by, supported by, or
  affiliated with NVIDIA. Upstream is [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector);
  this fork tracks it and merges from it. Issues with this fork belong
  [here](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues), not upstream.
- **License unchanged.** Apache-2.0, as upstream. See [LICENSE](LICENSE).
- **This fork has modified files it inherited from upstream, and added files of its own.** That
  sentence is the Apache-2.0 §4(b) notice for the distribution as a whole, and it covers the build
  and documentation files — `README.md`, `Makefile`, `pyproject.toml`, `THIRD_PARTY_NOTICES.md`,
  `docs/` — that have no comment syntax to carry one. Every *source* file says so for itself: a file
  this fork changed carries NVIDIA's copyright line with the fork's beneath it, and a file this fork
  wrote carries the fork's line only. Read the header to know who wrote a source file; run
  `git diff <merge-base> HEAD` against upstream to know exactly what changed. Dependencies this fork
  added are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) beside upstream's.
- **The detection rates quoted in the Overview are upstream's research**, reproduced as inherited
  documentation. This fork has not independently reproduced them.
- **Known limits are stated, not hidden.** Static analysis matches patterns and cannot prove intent;
  the LLM stage is probabilistic. See [Limitations](#limitations) — they apply to the
  framework-specific rules exactly as they apply to the base catalog.
- **Sending skill content to a third party is opt-out, not opt-in.** The LLM stage is on by default
  and transmits skill content to the configured provider. `--no-llm` keeps every scan local.
- **The framework rules match upstream spellings, and a rename breaks them silently.** When upstream
  renames an identifier, the rule that matched it stops producing findings and the report still reads
  as clean. Each framework's spellings therefore live in one inventory carrying a *measured* range of
  published releases, re-measured by reading those releases rather than the documentation:
  [`docs/VOCABULARY_REMEASUREMENT.md`](docs/VOCABULARY_REMEASUREMENT.md) is the procedure, its trigger,
  and what the last run found.

## Contributing, and keeping these docs true

Contributions are welcome — open an issue or a pull request on
[rodrigorjsf/SkillSpector-Polyglot](https://github.com/rodrigorjsf/SkillSpector-Polyglot).

**This documentation is part of the change, not a follow-up to it.** A pull request that adds or
alters a rule, a framework, a CLI flag, an environment variable, an exit code, an output format, or
which stream a line is printed to updates this README in the *same* pull request. Concretely:

| A change to… | …updates, in the same PR |
|---|---|
| Framework detection or a framework analyzer | the [Framework support](#framework-support) matrix — including its **Status** column. A framework whose analyzer reuses another framework's rule ids says so in its row, so the [Vulnerability Patterns](#vulnerability-patterns) count stays one entry per question rather than one per language |
| Any detection rule | the relevant [Vulnerability Patterns](#vulnerability-patterns) table and the pattern count in [Features](#features) — which is the number of rows those tables carry, so it is a claim a reader can check on the page. A conformance rule is counted in its own line there rather than among the 86, because it assesses conformance rather than risk |
| A CLI flag or subcommand | [CLI Options](#cli-options), and [Usage in an agentic project](#usage-in-an-agentic-project) if it changes the recommended invocation |
| `--mcp-registry` behavior: an input shape, a check, a rejected flag, or the network rule | [Scanning the MCP Registry](#scanning-the-mcp-registry) and the walkthrough in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) |
| A domain term, or the meaning of one | [`CONTEXT.md`](CONTEXT.md) — the glossary is the vocabulary the prose, the docstrings and the test names are held to |
| An environment variable | [Environment Variables](#environment-variables) and the [Configuration](#configuration) summary |
| An exit code, an output format, or which stream a line is printed to | [Integrating SkillSpector](#integrating-skillspector) — including [Which stream carries what](#which-stream-carries-what), the one rule every `console.print` in `cli.py` is held to — and the **Logging** bullet of [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md), which is where a contributor adding a print site reads which of the two consoles to use |
| Anything that ships a designed-but-unbuilt capability | the **Status** column above, and [`docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md`](docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md) |
| Any detection rule, again | [`docs/OWASP-AST10-COVERAGE.md`](docs/OWASP-AST10-COVERAGE.md) — the row the rule belongs to, or the gaps list where it belongs to none |
| A redistributed dependency in `pyproject.toml`, added **or removed** — a runtime one, or one in the `mcp` extra | **`uv.lock`**, re-locked with `uv lock` in the same PR — `.github/workflows/release.yml` runs `uv sync --locked`, which errors rather than re-resolving, so a stale lock fails the release rather than the tests; and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), in the section matching the declaration — `## Runtime Dependencies` or `## Optional Dependencies (mcp extra)`; license and copyright read from the installed `dist-info`, not recalled; `tests/unit/test_third_party_notices.py` fails, per section, on a missing entry and on one that outlived its dependency. The `dev` and `langgraph-dev` extras declare the project's own toolchain rather than capability a consumer installs, and stay out |
| A **new** optional-dependency extra in `pyproject.toml` | [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) — its own `## Optional Dependencies (<extra> extra)` section when the extra delivers capability to a consumer, which is what generates its comparisons in `tests/unit/test_third_party_notices.py`; when it declares tooling for working on this project, like `dev` and `langgraph-dev`, no section and a line in that test's `_NOT_REDISTRIBUTED_EXTRAS` instead — plus the row above; exactly one of the two, and the same test fails on any extra with neither *and* on any extra with both, as well as on a duplicated section heading. An extra that composes another by naming this distribution back — `skillspector[mcp]`, the idiom `dev` uses — owes no entry for that self-reference: the composed extra's own section discloses it |
| An upstream spelling a framework rule matches | the framework's `vocabulary.py` — never a literal elsewhere — and, if the spelling is new, a re-measured range per [`docs/VOCABULARY_REMEASUREMENT.md`](docs/VOCABULARY_REMEASUREMENT.md). Two frameworks that wrap the same upstream project in two languages keep **two** inventories and two guards: they ship on different release clocks, and one rename must not move both |
| A new captured upstream reference | [`docs/references/README.md`](docs/references/README.md) — its table row, and the "Why these …" section that states the admission rule |

A capability that ships without its row updated is a documentation bug — report it as one.

---

# Inherited documentation

Everything below this line is upstream SkillSpector's documentation, kept intact so its provenance
stays legible. It describes the scanner both projects share; where it says "SkillSpector", it means
the tool this fork is built on. Install URLs in this section point at upstream by design — see
[Install](#install) above for this fork.

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/NVIDIA/SkillSpector/badge)](https://scorecard.dev/viewer/?uri=github.com/NVIDIA/SkillSpector)

## Overview

AI agent skills (used by Claude Code, Codex CLI, Gemini CLI, etc.) execute with implicit trust and minimal vetting. Research shows that **26.1% of skills contain vulnerabilities** and **5.2% show likely malicious intent**.

SkillSpector helps you answer: **"Is this skill safe to install?"**

SkillSpector is part of the [NVIDIA Verified Skills pipeline](https://docs.nvidia.com/skills/), which scans, evaluates, and signs agent skills before publication. Skills that pass are published to the [NVIDIA skills catalog](https://github.com/NVIDIA/skills).

## Documentation

- **[Scan agent skills before installation](https://docs.nvidia.com/skills/scanning-agent-skills)** — Hosted guide: when to scan, how to read a report, and how to gate installs.
- **[Development guide](docs/DEVELOPMENT.md)** — Architecture, package layout, and how to extend the analyzer pipeline.
- **[Analysis resource bounds](docs/ANALYSIS_RESOURCE_BOUNDS.md)** — Fail-closed bundle, parser, nested-artifact, ledger, and finding ceilings.
- **[Pi extension](docs/PI_EXTENSION.md)** — Install SkillSpector as a Pi tool for scanning skills from inside agent sessions.

## Features

- **Multi-format input**: Scan Git repos, URLs, zip files, directories, or single files
- **86 vulnerability patterns** across 20 categories: prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system prompt leakage, memory poisoning, tool misuse, rogue agent, anti-refusal, trigger abuse, dangerous code (AST), taint tracking, insecure deserialization, YARA signatures, MCP least privilege, MCP tool poisoning, LangChain4j framework, and Deep Agents framework
- **17 Agent Skills conformance rules** — 15 from the specification, 2 from loader behavior (`SPEC-14`, `SPEC-17`) — counted apart from the patterns above because they assess conformance rather than risk, and off unless `--spec-checks` asks for them ([Specification conformance](#specification-conformance----spec-checks))
- **Two-stage analysis**: Fast static analysis + optional LLM semantic evaluation
- **Live vulnerability lookups**: SC4 queries [OSV.dev](https://osv.dev) for real-time CVE data with automatic offline fallback
- **Multiple output formats**: Terminal, JSON, Markdown, and SARIF reports
- **Risk scoring**: 0-100 score with severity labels and clear recommendations
- **Baseline / false-positive suppression**: Accept known findings via a glob-rule or fingerprint baseline so re-scans surface only *new* issues ([docs](docs/SUPPRESSION.md))

## Quick Start

### Installation

> **Open-source software notice:** This project will download and install additional third-party open source software projects. Review the license terms of these open source projects before use.

Create and activate a virtual environment first (all `make` targets assume the venv is active). Use **uv** or **pip**; the Makefile uses `uv` if available, otherwise `pip`.

**Quick install with uv (CLI-only):**

```bash
uv tool install git+https://github.com/NVIDIA/skillspector.git
# Update later: uv tool update skillspector
```

If you plan to run `skillspector mcp`, install the MCP extra at install time:

```bash
uv tool install 'skillspector[mcp] @ git+https://github.com/NVIDIA/skillspector.git'
```

**From source:**

```bash
# Clone the repository
git clone https://github.com/NVIDIA/skillspector.git
cd skillspector

# Create and activate virtual environment
uv venv .venv && source .venv/bin/activate
# or: python3 -m venv .venv && source .venv/bin/activate

# Install for production use
make install

# Or install with development dependencies
make install-dev
```

### Docker (no Python required)

Run SkillSpector without installing Python by building it locally from the included [Dockerfile](Dockerfile). The image is based on the Docker Official Python `3.12-slim-bookworm` image.

**Build the image:**

```bash
make docker-build
# or: docker build -t skillspector .
```

**Scan a local directory** by mounting your current directory into `/scan`, the container's working directory:

```bash
docker run --rm -v "$PWD:/scan" skillspector scan ./my-skill/ --no-llm
```

**Scan with LLM analysis** by passing credentials with a local `.env` file:

```bash
cat > .env <<'EOF'
SKILLSPECTOR_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
EOF
```

```bash
docker run --rm \
  -v "$PWD:/scan" \
  --env-file .env \
  skillspector scan ./my-skill/
```

Or pass credentials directly from your shell environment:

```bash
docker run --rm \
  -v "$PWD:/scan" \
  -e SKILLSPECTOR_PROVIDER=anthropic \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  skillspector scan ./my-skill/
```

**Write a report to the host filesystem** by writing to the mounted directory:

```bash
docker run --rm \
  -v "$PWD:/scan" \
  skillspector scan ./my-skill/ --no-llm --format json --output report.json
```

**Optional alias** for repeated static scans:

```bash
alias skillspector-docker='docker run --rm -v "$PWD:/scan" skillspector'
skillspector-docker scan ./my-skill/ --no-llm
```

### Basic Usage

```bash
# Scan a local skill directory
skillspector scan ./my-skill/

# Scan a single SKILL.md file
skillspector scan ./SKILL.md

# Scan a Git repository
skillspector scan https://github.com/user/my-skill

# Scan a zip file
skillspector scan ./my-skill.zip
```

#### Size limits

SkillSpector enforces two independent caps on remote and archive inputs to bound the impact of oversized downloads and zip bombs:

- **Per-ingest cap**: `INGEST_MAX_BYTES` (100 MiB) — applied to streamed URL downloads, total uncompressed size of zip archives, and post-clone disk usage of Git repos.
- **Zip member cap**: `INGEST_MAX_ZIP_MEMBERS` (10,000) — caps the number of entries in a single zip.

A third cap applies further downstream, and it is denominated differently:

- **Per-file analysis cap**: `MAX_FILE_CHARS` (1,000,000 **characters**) — bounds what individual analyzers will read out of an already-ingested directory.

The two ingest caps count bytes on disk; the analysis cap counts characters of decoded text. They are not interchangeable — a UTF-8 file of 1,000,000 CJK characters occupies roughly 3 MB on disk and is still under the analysis cap. A breach of either ingest cap fails closed with an `IngestLimitExceededError`. A file over the analysis cap is not a failure: it is skipped, and the skip is reported with a `size_limit` reason, so an absence of findings for that file is distinguishable from a clean one.

### Output Formats

```bash
# Terminal output (default) - pretty formatted
skillspector scan ./my-skill/

# JSON output - machine readable
skillspector scan ./my-skill/ --format json --output report.json

# Markdown output - for documentation
skillspector scan ./my-skill/ --format markdown --output report.md

# SARIF output - for CI/CD integration and IDE tooling
skillspector scan ./my-skill/ --format sarif --output report.sarif
```

### Batch Scanning

Scan entire directories of skills in parallel from `contrib/batch_scan/`:

```bash
python -m contrib.batch_scan.batch_scan ./my-skills/ --no-llm
python -m contrib.batch_scan.batch_scan ./my-skills/ --workers 20 -f json -o report.json
python -m contrib.batch_scan.batch_scan ./tests/fixtures/ -f terminal --workers 20
```

Supports multilingual detection (zh/ja/ko) and terminal/JSON/Markdown output.

For LLM scans with higher concurrency, configure multiple API keys following
[`.env.example`](contrib/batch_scan/.env.example) — the pool improves throughput
and resilience, provided the keys don't share an account-level rate limit.

See the [contrib guide](contrib/batch_scan/docs/) for details.

> **Note on LLM support:** The default configuration targets DeepSeek as the
> cheapest public option. DeepSeek-Chat is
> [expected to sunset](https://api-docs.deepseek.com/), and the contributor
> does not have hardware to test against local models. The batch scanner was
> originally tested with OpenAI-compatible endpoints — DeepSeek's lack of
> structured-output support required manual JSON-parsing patches. If you can
> contribute a more universal backend (Ollama, vLLM, or a different provider),
> PRs are very welcome.

### Scanning a Whole Repository

Pointing SkillSpector at a repository root without `--repo-scan` does not fail — it
succeeds wrongly. A repository root holds no `SKILL.md`, so the entire tree is scanned as **one
anonymous skill with an empty manifest**: its components span everything, including `target/`, and
the risk score is computed over that mixture. The report looks complete and is not. The scan now
prints a warning naming the flag that would have found the skills, but the warning is advice — the
wrong-shaped report is still what gets written.

`--repo-scan` finds every skill inside the repository and scans each on its own:

```bash
skillspector scan . --repo-scan --no-llm --format sarif --output skillspector.sarif
```

Skills are found under these directory patterns, each matched as a **path suffix at any depth** — so
a multi-module repository declaring the same layout twice yields both, with no configuration:

| Pattern | Typical layout |
|---|---|
| `skills/` | Agent Skills convention |
| `src/main/resources/skills/` | Maven / Gradle resources, used by LangChain4j's classpath loader |
| `.deepagents/skills/` | Deep Agents |
| `.agents/skills/` | Agent Skills, hidden-directory form |

JVM build directories — `target`, `build`, `.gradle`, `.mvn`, `out` — are skipped, so a scan after
`mvn package` does not read compiled output. This applies **only** with `--repo-scan`; an ordinary
scan is byte-for-byte unchanged. For a layout the patterns miss, replace them:

```bash
skillspector scan . --repo-scan --repo-scan-root playbooks --repo-scan-root ops/skills
```

The SARIF output and the exit code work as they do for a single skill. SARIF locations are rewritten
to be relative to the repository root, so GitHub code scanning resolves them against the checked-out
tree.

**`--baseline` works here, but `skillspector baseline .` cannot produce the file it needs.** The
flag is threaded through to every discovered skill, and each skill is scanned as its own root, so a
fingerprint records `SKILL.md` rather than `skills/my-skill/SKILL.md`. `skillspector baseline` has
no `--repo-scan` mode: pointed at the repository root it scans the whole tree as one anonymous skill
and writes the repo-root-relative form. `component.path` is hashed, so those entries match nothing
and suppress nothing. Baseline each skill directory instead — those entries *do* match — and
concatenate their `fingerprints` lists into the one document `--baseline` accepts.
[Baseline suppression](docs/SUPPRESSION.md) carries the measurement.

#### `--repo-scan` or `--recursive`?

Two flags mean "there is more than one skill under this path". **`--repo-scan` is the one to reach
for.** `--recursive` predates it and is narrower everywhere that matters, and is kept because
changing it would change results for anyone depending on them. It is *wider* in exactly one place,
and not helpfully so: it walks build output that `--repo-scan` skips.

| | `--repo-scan` | `--recursive` |
|---|---|---|
| Looks | at any depth, under the patterns above | at the immediate children only |
| Minimum to engage | one skill | **two** — one child skill is not enough |
| A `SKILL.md` at the path itself | irrelevant | short-circuits: the tree is scanned as that one skill |
| `target/`, `build/`, `.gradle/` | skipped | walked, and a skill inside one counts |
| `--baseline` | threaded through every skill, and it suppresses — but only for a baseline taken *per skill directory*: `skillspector baseline .` has no repo-scan mode and writes repo-root-relative paths this scan never emits | rejected, exit `2` — but **only** once the flag engages. Below the two-skill threshold it falls through to an ordinary scan and the baseline applies |
| `--format sarif --output` | one valid SARIF log, one run per skill | one valid SARIF log, one run per skill — upstream's own recursive SARIF merge arrived with the 2.9.6 sync and replaced the `--- path ---` concatenation this row used to describe, so anything splitting the file on that separator has to stop |
| `--format json --output` | per-skill bodies concatenated | one object: `multi_skill`, `skill_count`, `max_risk_score`, `execution_successful`, `skills` |
| **No** `--output` | the report is written to stdout, in every format — but only `sarif` is one merged document; `json` and `markdown` are the same `--- path ---` concatenation as the row above ([#116](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/116)) | no report at all — the combined body is only ever written to a file ([#114](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/114)). With `--format terminal` stdout carries the summary table and nothing else; with `json`, `sarif` or `markdown` stdout is **empty** and the format flag is silently ignored. As with `--baseline`, **only** once the flag engages: below the two-skill threshold it falls through to an ordinary scan, which does write a report to stdout in the requested format |
| Discovery roots | `--repo-scan-root`, repeatable | not configurable |

Use `--recursive` only for the shape it was built for: a flat directory whose immediate children are
two or more skills, consumed through its combined-JSON contract. Anything else — a repository, a
monorepo, one skill under `skills/`, a build tree, a shared baseline, SARIF for code scanning — is
`--repo-scan`.

When the path declares no skill of its own, the scan now says so instead of reporting the
anonymous-skill result silently — and it runs discovery before advising, so the warning states how
many skills `--repo-scan` would actually find here rather than listing both flags and leaving the
choice open. Where neither flag would find anything, it says that too.

#### Example CI configuration

```yaml
name: Skill security scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required to upload the SARIF

jobs:
  skillspector:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install git+https://github.com/NVIDIA/skillspector.git

      # Exit code 1 above the risk threshold, 2 on a scan error.
      # `continue-on-error` lets the SARIF upload run even on a failing scan.
      - name: Scan every skill in the repository
        id: scan
        continue-on-error: true
        run: skillspector scan . --repo-scan --no-llm --format sarif --output skillspector.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillspector.sarif

      - name: Fail the build on a risky skill
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

Add `--baseline skillspector-baseline.yaml` once known findings are accepted, so re-scans surface
only new ones — but build that file from **per-skill** `skillspector baseline` runs, not from
`skillspector baseline .`, which records paths this scan never emits. See the `--baseline` note
above.

### Suppressing False Positives (baseline)

Suppress known/accepted findings so the risk score reflects only un-triaged
issues and re-scans surface only *new* findings. See the
[suppression guide](docs/SUPPRESSION.md) for the full reference.

```bash
# Accept all current findings into a baseline (run once), then commit it.
skillspector baseline ./my-skill/ -o .skillspector-baseline.yaml

# Scan against the baseline — only NEW findings are reported and scored.
skillspector scan ./my-skill/ --baseline .skillspector-baseline.yaml

# Review what was suppressed (still excluded from the score).
skillspector scan ./my-skill/ --baseline .skillspector-baseline.yaml --show-suppressed
```

A baseline can also use drift-tolerant glob rules (by rule id, file path, or
message) — see [`.skillspector-baseline.example.yaml`](.skillspector-baseline.example.yaml).
Exact fingerprint baselines are evidence-bound: changing the scanned source or
SkillSpector version keeps the finding active until it is reviewed again.
When a selected baseline or baseline output is stored inside the skill
directory, SkillSpector excludes that exact file from content analysis so its
suppression text cannot create findings or enter regenerated fingerprints;
sibling files remain in normal scan scope.

### LLM Analysis

For the best results, configure an OpenAI-compatible LLM endpoint for
semantic analysis. Pick a provider with `SKILLSPECTOR_PROVIDER`; hosted providers ship bundled default models, while CLI providers fall back to the local runtime's default model unless `SKILLSPECTOR_MODEL` is set. SkillSpector also works against
local OpenAI-compatible servers (Ollama, vLLM, llama.cpp) and managed
inference gateways.

| Provider (`SKILLSPECTOR_PROVIDER`) | Credential env var | Endpoint | Default model |
| ---------- | ---- | ---- | ---- |
| `openai` | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`) | api.openai.com (or any OpenAI-compatible URL) | `gpt-5.4` |
| `anthropic` | `ANTHROPIC_API_KEY` | api.anthropic.com | `claude-opus-4-6` |
| `anthropic_proxy` | `ANTHROPIC_PROXY_API_KEY` + `ANTHROPIC_PROXY_ENDPOINT_URL` | Any Vertex-style raw-predict proxy | `claude-sonnet-4-6` |
| `bedrock` | `AWS_PROFILE` (optional) + `AWS_REGION` — SigV4 via boto3 | AWS Bedrock Runtime | `us.anthropic.claude-sonnet-4-6-20250915-v1:0` |
| `nv_build` | `NVIDIA_INFERENCE_KEY` | build.nvidia.com | `deepseek-ai/deepseek-v4-flash` |
| `claude_cli` | _(none — uses local CLI auth)_ | local `claude` binary | local Claude runtime fallback, or `SKILLSPECTOR_MODEL` |
| `codex_cli` | _(none — uses local CLI auth)_ | local `codex` binary | local Codex runtime fallback, or `SKILLSPECTOR_MODEL` |

```bash
# Stock OpenAI
export SKILLSPECTOR_PROVIDER=openai
export OPENAI_API_KEY=sk-...
skillspector scan ./my-skill/

# Anthropic
export SKILLSPECTOR_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
skillspector scan ./my-skill/

# Anthropic via Vertex-style proxy (corporate gateways, GCP Vertex AI)
export SKILLSPECTOR_PROVIDER=anthropic_proxy
export ANTHROPIC_PROXY_ENDPOINT_URL=https://my-gateway.example.com/models/claude-sonnet-4-6:streamRawPredict
export ANTHROPIC_PROXY_API_KEY=your-bearer-token
export SKILLSPECTOR_MODEL=claude-sonnet-4-6
skillspector scan ./my-skill/

# AWS Bedrock (Claude via SigV4)
export SKILLSPECTOR_PROVIDER=bedrock
# Optional: select an AWS named profile. When unset, the standard
# boto3 credential chain (env vars, instance metadata, SSO, etc.) resolves.
# export AWS_PROFILE=my-profile
export AWS_REGION=us-west-2  # default if unset
# Default model: us.anthropic.claude-sonnet-4-6-20250915-v1:0
# Override with any Bedrock model ID, cross-region inference-profile
# ID, or your own application-inference-profile ARN:
# export SKILLSPECTOR_MODEL=us.anthropic.claude-opus-4-6-20250915-v1:0
skillspector scan ./my-skill/

# NVIDIA build.nvidia.com
export SKILLSPECTOR_PROVIDER=nv_build
export NVIDIA_INFERENCE_KEY=nvapi-...
skillspector scan ./my-skill/

# Local Claude CLI — no API key; uses your existing `claude auth login` session
# Requires: claude CLI installed and authenticated (claude auth login)
export SKILLSPECTOR_PROVIDER=claude_cli
# Uses the local Claude CLI runtime fallback unless SKILLSPECTOR_MODEL is set.
# export SKILLSPECTOR_MODEL=claude-sonnet-4-6
skillspector scan ./my-skill/

# Local Codex CLI — no API key; uses your existing `codex login` session
# Requires: codex CLI installed and authenticated
export SKILLSPECTOR_PROVIDER=codex_cli
skillspector scan ./my-skill/

# Local Ollama or any OpenAI-compatible endpoint
export SKILLSPECTOR_PROVIDER=openai
export OPENAI_API_KEY=ollama
export OPENAI_BASE_URL=http://localhost:11434/v1
export SKILLSPECTOR_MODEL=llama3.1:8b
skillspector scan ./my-skill/

# Override the provider's default model
export SKILLSPECTOR_MODEL=gpt-5.2
skillspector scan ./my-skill/

# Skip LLM analysis (faster, static analysis only)
skillspector scan ./my-skill/ --no-llm
```

### MCP Server

Run SkillSpector as a [Model Context Protocol](https://modelcontextprotocol.io)
server so any MCP-capable agent (Claude Code, Codex CLI, Gemini CLI) or remote
runtime can call scanning as a tool and **gate skill/MCP installs on the
result** — turning SkillSpector into a runtime guardrail instead of an
out-of-band audit step.

`skillspector mcp` requires `skillspector[mcp]`.

```bash
# Install, or reinstall if you already used the CLI-only path
uv tool install --force 'skillspector[mcp] @ git+https://github.com/NVIDIA/skillspector.git'

# FastMCP stdio transport for local CLI agents
skillspector mcp

# streamable HTTP/SSE transport for remote / A2A callers
skillspector mcp --transport http --host 127.0.0.1 --port 8000
```

The stdio transport is the current FastMCP path for local CLI agents, and the
initialize hang reported in issue #199 still applies there.

The server exposes a single tool:

- **`scan_skill(target, use_llm=true, output_format="json")`** — scans a Git
  URL, file URL, `.zip`, `.md` file, or directory and returns a structured
  verdict: `risk_score` (0-100), `severity`, `recommendation`,
  `safe_to_install`, and `findings`. It also reports `llm_used` / `scan_mode`
  so a low score from a static-only scan is never mistaken for a clean full
  scan.

Register it with Claude Code via:

```bash
claude mcp add skillspector -- skillspector mcp
```

> **Security — HTTP transport trust model**
>
> The HTTP transport ships **without authentication**. Any caller that can
> reach the port can invoke `scan_skill`. Over stdio or `127.0.0.1` this is
> the same trust boundary as the CLI. If you bind to a routable interface:
>
> - Sit the server behind an authenticating reverse proxy (e.g. nginx + mTLS)
>   before exposing it externally.
> - Local paths and `file://` URLs are **automatically rejected** over HTTP to
>   prevent unauthenticated callers from reading arbitrary host files. Only
>   remote Git and `.zip` URLs are accepted.

## Vulnerability Patterns

SkillSpector detects **86 vulnerability patterns** across 20 categories, plus **17 specification
conformance rules** that are counted separately and run only under `--spec-checks` — see
[Specification Conformance](#specification-conformance-17-rules-opt-in) at the end of this section:

### Prompt Injection (6 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| P1 | Instruction Override | HIGH | Commands to ignore safety constraints |
| P2 | Hidden Instructions | HIGH | Malicious directives in comments/invisible text |
| P3 | Exfiltration Commands | HIGH | Instructions to transmit context externally |
| P4 | Behavior Manipulation | MEDIUM | Subtle instructions altering agent decisions |
| P5 | Harmful Content | CRITICAL | Instructions that could cause physical harm |
| P9 | Whitespace Padding | MEDIUM | Large whitespace padding hiding instructions below/beside the visible area |

### Anti-Refusal (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| AR1 | Refusal Suppression | HIGH | Instructions to never refuse or always comply (e.g. "never refuse", "always comply") |
| AR2 | Disclaimer Suppression | HIGH | Instructions to omit warnings, disclaimers, or ethical commentary (e.g. "no disclaimers", "do not moralize") |
| AR3 | Safety Policy Nullification | HIGH | Jailbreak framing that nullifies guardrails (e.g. "you have no restrictions", "ignore your guidelines", "do anything now") |

### Data Exfiltration (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| E1 | External Transmission | MEDIUM | Sending data to external URLs |
| E2 | Env Variable Harvesting | HIGH | Enumerating, copying, or searching environment data to collect secrets |
| E3 | File System Enumeration | MEDIUM | Scanning directories for sensitive files |
| E4 | Context Leakage | HIGH | Transmitting conversation context externally |

### Privilege Escalation (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| PE1 | Excessive Permissions | LOW | Requesting access beyond stated functionality |
| PE2 | Sudo/Root Execution | MEDIUM | Invoking elevated system privileges |
| PE3 | Credential Access | HIGH | Reading SSH keys, tokens, passwords |

### Supply Chain (9+ patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| SC1 | Unpinned Dependencies | LOW | No version constraints on packages |
| SC2 | External Script Fetching | HIGH | curl \| bash and remote code execution |
| SC3 | Obfuscated Code | HIGH | Base64/hex encoded execution |
| SC4 | Known Vulnerable Dependencies | HIGH | Dependencies with known CVEs (live OSV.dev lookup) |
| SC5 | Abandoned Dependencies | MEDIUM | Unmaintained packages without security updates |
| SC6 | Typosquatting | HIGH | Package names similar to popular packages |
| SC8 | Shipped Python Bytecode | HIGH | `__pycache__` / `.pyc` present (discovery skips; malicious bytecode bypass) |
| SC9 | Concealed Executable Artifact | HIGH | Executable nested in a document container or hidden/disguised artifact |

### Excessive Agency (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| EA1 | Unrestricted Tool Access | HIGH | Unfettered tool access without constraints |
| EA2 | Autonomous Decision Making | HIGH | High-impact decisions without human-in-the-loop |
| EA3 | Scope Creep | MEDIUM | Capabilities extending beyond stated purpose |
| EA4 | Unbounded Resource Access | MEDIUM | No rate limits or quotas on resource consumption |

### Output Handling (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| OH1 | Unvalidated Output Injection | HIGH | Model output used without sanitization |
| OH2 | Cross-Context Output | MEDIUM | Output flows across trust boundaries without validation |
| OH3 | Unbounded Output | MEDIUM | No limits on output size or generation rate |

### System Prompt Leakage (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| P6 | Direct Leakage | HIGH | Instructions that expose system prompts or internal rules |
| P7 | Indirect Extraction | MEDIUM | Extraction via rephrasing, translation, or side-channels |
| P8 | Tool-Based Exfiltration | HIGH | System prompts exfiltrated via file writes or network requests |

### Memory Poisoning (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| MP1 | Persistent Context Injection | HIGH | Content designed to persist across interactions |
| MP2 | Context Window Stuffing | MEDIUM | Filler content displacing safety constraints |
| MP3 | Memory Manipulation | HIGH | Tampering with agent memory or stored state |

### Tool Misuse (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TM1 | Tool Parameter Abuse | HIGH | Crafted parameters for unintended behavior (shell=True, --force) |
| TM2 | Chaining Abuse | HIGH | Tool chains that bypass individual safety checks |
| TM3 | Unsafe Defaults | MEDIUM | Overly permissive defaults (disabled TLS, no auth) |

### Rogue Agent (2 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| RA1 | Self-Modification | CRITICAL | Modifying own code or configuration at runtime |
| RA2 | Session Persistence | HIGH | Unauthorized persistence via cron jobs or startup scripts |

### Trigger Abuse (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TR1 | Overly Broad Trigger | MEDIUM | Trigger patterns matching common words |
| TR2 | Shadow Command Trigger | HIGH | Triggers that shadow built-in commands or other skills |
| TR3 | Keyword Baiting Trigger | MEDIUM | Generic triggers designed to maximize activation |

### Behavioral AST (10 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| AST1 | exec() Call | CRITICAL | Direct exec() enabling arbitrary code execution |
| AST2 | eval() Call | HIGH | Direct eval() evaluating arbitrary expressions |
| AST3 | Dynamic Import | HIGH | \_\_import\_\_() loading arbitrary modules at runtime |
| AST4 | subprocess Call | HIGH | External command execution via subprocess |
| AST5 | os.system / exec-family | HIGH | Shell commands via os module |
| AST6 | compile() Call | MEDIUM | Code object creation from strings |
| AST7 | Dynamic getattr() | MEDIUM | Arbitrary attribute access with non-literal names |
| AST8 | Dangerous Execution Chain | CRITICAL | exec/eval combined with dynamic source (network, encoded data) |
| AST9 | Reflective getattr() Sink | HIGH | Reflective exec via `getattr(os,'system')` / `getattr(builtins,'exec')` that evades AST1/AST5 |
| AST10 | Insecure Deserialization | MEDIUM | `pickle.loads`, `yaml.load`, `torch.load`, `numpy.load` and friends reconstructing objects from untrusted bytes |

### Taint Tracking (6 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TT1 | Direct Taint Flow | HIGH | Data flows directly from a source to a sink without sanitization |
| TT2 | Variable-Mediated Taint Flow | MEDIUM | Data flows from source to sink through intermediate variables |
| TT3 | Credential Exfiltration Chain | CRITICAL | Credentials (env vars, secrets) flow to network output sinks |
| TT4 | File Read to Network Exfiltration | HIGH | File contents flow to network output sinks |
| TT5 | External Input to Code Execution | CRITICAL | Network or user input flows to exec/eval/subprocess sinks |
| TT6 | Untrusted Data to Deserializer Flow | HIGH | Network, file or user input flows into a deserializer that reconstructs arbitrary objects |

### Insecure Deserialization (4 patterns)

Language-specific deserialization sinks outside Python, which `AST10` covers. Each is a static
pattern rather than an AST walk, because the scanner parses no PHP, Ruby or JavaScript.

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| DS1 | PHP Object Injection | HIGH | `unserialize()` on untrusted input instantiates arbitrary classes and triggers magic methods |
| DS2 | Ruby Marshal Deserialization | HIGH | `Marshal.load` / `Marshal.restore` reconstructs arbitrary objects from a binary blob |
| DS3 | Unsafe Ruby YAML Deserialization | MEDIUM | `YAML.load` / `Psych.load` / `Oj.load` in object mode instantiates arbitrary Ruby objects |
| DS4 | Unsafe JavaScript Deserialization | HIGH | `node-serialize` / `funcster` / `serialize-to-js` evaluate embedded functions on unserialize |

### YARA Signatures (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| YR1 | Malware Match | CRITICAL | YARA rule match for known malware signatures |
| YR2 | Webshell Match | CRITICAL | YARA rule match for webshell patterns |
| YR3 | Cryptominer Match | HIGH | YARA rule match for crypto mining indicators |
| YR4 | Hack Tool / Exploit Match | HIGH | YARA rule match for hack tools or exploit code |

### MCP Least Privilege (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| LP1 | Underdeclared Capability | HIGH | Code uses capabilities not listed in declared permissions |
| LP2 | Wildcard Permission | MEDIUM | Permission list contains wildcards (\*, all, full, any) |
| LP3 | Missing Permission Declaration | MEDIUM | No permissions field but code has detectable capabilities |
| LP4 | Overdeclared Permission | LOW | Permission declared but no corresponding code capability found |

### MCP Tool Poisoning (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TP1 | Hidden Instructions | HIGH | Hidden directives in metadata (HTML comments, zero-width chars, base64, data URIs) |
| TP2 | Unicode Deception | HIGH | Homoglyphs, RTL overrides, mixed-script identifiers in tool metadata |
| TP3 | Parameter Description Injection | MEDIUM | Injection patterns in parameter definitions (overrides, system tokens, malicious defaults) |
| TP4 | Description-Behavior Mismatch | MEDIUM | Declared tool description does not match actual code behavior (LLM-powered) |

### LangChain4j Framework (5 patterns)

Applies only to a scan whose tree is detected as a LangChain4j project. On every other input
these rules are inert and the scan is unchanged.

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| L4J-SHELL | Unsandboxed Shell Mode | HIGH | `ShellSkills` wiring, or any `langchain4j-…shell…` dependency (`langchain4j-experimental-skills-shell` today), gives the agent arbitrary command execution with no sandbox. A build file that names the artifact only to *refuse* it is not declaring it and raises nothing — in a comment, in a dependency's `<exclusions>`, in Enforcer's `<bannedDependencies>`, or in a Gradle `exclude` call in any of its spellings. A real declaration that excludes something *else* is still reported, at the declaring line |
| L4J-UNRESOLVED | Unresolvable Skill Content | MEDIUM | A Java-defined Skill's content, name, description, or loader path is built at runtime, so the instruction surface was never scanned. A `.tools(...)` call says the same about capability whenever *any* argument is not a plain `new X()` — a variable, a `Map.of(...)`, a call — because the tool set is then assembled out of view. Naming every class, `.tools(new A(), new B())`, resolves and raises nothing, and so does attaching none |
| L4J-TOOL-DESC | Instruction-Carrying Tool Description | MEDIUM | A `@Tool` description instructs the model instead of describing the tool — tool poisoning written in Java rather than in an MCP manifest. Reported at the annotation, and the message also names the Skill that was granted the class — the `.tools(new X())` call's file and line, plus the Skill's name where the same chain set one. Only when the join is unambiguous: `new X()` names a simple name, so if the scan declares that name in more than one file, or in none, the finding says nothing about attachment rather than naming a Skill the tool may never reach. Several attachment sites for one unambiguous class are all named |
| L4J-MCP-FILTER | Unfiltered MCP Tool Provider | MEDIUM | `McpToolProvider` built without `.filter(...)` or `.filterToolNames(...)`, so every tool the server exposes reaches the agent. Either setter scopes the set and satisfies the Rule; `.alwaysVisibleToolNames(...)` does not, since it exempts tools from a filter rather than narrowing what is exposed |
| L4J-WORKDIR | Unset Shell Working Directory | MEDIUM | `RunShellCommandToolConfig` built without `workingDirectory`, so commands run wherever the JVM started |

### Deep Agents Framework (4 patterns)

Applies only to a scan whose tree is detected as a Deep Agents project. On every other input these
rules are inert and the scan is unchanged.

**Four patterns, two analyzers.** Deep Agents ships as a Python distribution and a JavaScript one,
and SkillSpector reads both — `framework_deepagents` and `framework_deepagents_js`. They are the
same four questions about the same upstream framework, so they are the same four rule ids. What that
reuse buys is a suppression **rule** — a glob rule keyed on `rule_id` keeps matching across both
tracks — and one catalogue, OWASP and coverage entry per question rather than one per language. It
does **not** carry an exact baseline across a port: a v2 fingerprint binds to the evidence, and the
component path, the file bytes, the line and the message all change when an application is rewritten
in another language. Everything below is written
with the Python spellings, because that is the distribution the rules were first read from; the
JavaScript equivalents (`createDeepAgent`, an options object, a plain permission object, `rootDir`,
`interruptOn`) are in [the JavaScript capture](docs/references/deepagents-js-skills.md) and
[ADR 0009](docs/adr/0009-tree-sitter-for-typescript-parsing.md).

Two of the four partition every `create_deep_agent(...)` call between them: what resolved is judged,
and what did not is reported as not having been. Resolution stops at the module boundary — a literal
and a constant declared in the same module are read, and nothing else is guessed at. That is the same
boundary the Java track draws, and `DA-UNRESOLVED` is what makes it visible instead of silent.

The other two ask different questions. `DA-SHADOW` asks not what the call permits but what its
skill sources *contain*; it reasons across sources, which is why the analyzer opens every `SKILL.md`
in the scan. `DA-SUBAGENT-SKILLS` asks what the call's subagent definitions were given, and it is
the one rule here whose claim is correctness rather than security — upstream frames a custom
subagent without its own skills as a bug its documentation calls out, not as a risk.

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| DA-SHADOW | Shadowed Skill Source | HIGH | Two skill sources passed in one `skills=[...]` both declare a skill of the same `name`, so the later source overrides the earlier one and the skill that runs is not the one a reviewer vetted. It fires on a **confirmed** collision only — the `name` is read out of each mapped source's `SKILL.md` frontmatter — never on the mere presence of more than one source, because layering is a pattern upstream recommends. Confirming it needs the configured paths mapped onto scanned files through a `FilesystemBackend` whose `root_dir` resolves, read as relative to the scan root; where the files are not on disk at all (a `StoreBackend`, or the default `StateBackend`) nothing is raised, and where the `root_dir` itself cannot be read the call reaches `DA-UNRESOLVED`. One finding per shadowed source, so three sources holding one name produce two |
| DA-SKILL-WRITABLE | Writable Skill Source | MEDIUM (LOW where a human approves the write) | A skill source path passed in `skills=[...]` that no `FilesystemPermission` denies write access to, so the agent can rewrite the instructions it runs on. One finding per path, so a deliberately writable personal directory can be baselined without also suppressing a shared library. The rules are walked in the order they are written and the first one governing write over the path decides it; `mode="interrupt"` on that rule, or `interrupt_on` over both write tools, lowers the severity to LOW instead of clearing the finding. Path patterns are matched with `**` crossing a `/` and a single `*` stopping at one, so a rule written `paths=["/skills/*"]` does not clear a nested source it never named. A path whose backend routes it somewhere computed per request reaches `DA-UNRESOLVED` instead, and so does a permission rule written in a shape the scan cannot read. No backend upstream documents is read-only, so no backend clears a path on its own |
| DA-SUBAGENT-SKILLS | Subagent Without Skills | LOW | A custom subagent is defined in `subagents=[...]` without a `skills` key of its own. Upstream states that only the general-purpose subagent inherits the main agent's skills and that each custom subagent definition needs its own `skills` parameter, so the subagent runs without the capability the application was built around and nothing at runtime reports it. The general-purpose subagent is excluded structurally rather than by name: it is built in, so no definition declares it. Only a definition's keys are read, never its values — a real definition binds tools to objects no scan evaluates — so a finding names the line the definition opens on rather than the subagent, and a definition written as anything other than a mapping in this file, or holding a `**` spread, reaches `DA-UNRESOLVED` |
| DA-UNRESOLVED | Unresolvable Host Configuration | MEDIUM | A `create_deep_agent(...)` argument is assembled at runtime, so the configuration deciding what the agent may do to its skills was never read. Seven cases, each named in its own message: the skill source list, the backend, the `FilesystemPermission` rules, the subagent definitions, a resolved skill path routed to a store whose contents are computed per request, a permission rule whose `operations`, `paths` or `mode` is not one this scan recognises, and a `FilesystemBackend` whose `root_dir` cannot be read, so no configured skill path maps onto a file. An argument that is simply absent is a configuration, not a boundary, and raises nothing |

### Specification Conformance (17 rules, opt-in)

Counted apart from the 77 patterns above, because a conformance rule states that a declaration
disagrees with the [Agent Skills specification](docs/references/agent-skills-specification.md), not
that a risk category applies — which is also why these findings carry no OWASP tag. They run only
under `--spec-checks`; see
[Specification conformance](#specification-conformance----spec-checks) for the three modes and the
limits worth knowing before turning it on.

| ID | Rule | Severity | Scored by default | Description |
|----|------|----------|-------------------|-------------|
| SPEC-1 | Missing Or Unparseable Declaration | MEDIUM | No | `SKILL.md` opens with no `---` YAML block, or with one that does not close or does not parse as a mapping. The remaining field rules stay silent on such a file: one unreadable declaration is one defect, not eight missing fields |
| SPEC-2 | Missing Name | MEDIUM | No | No `name` is declared, or it holds nothing but blanks, or it is not text. The empty case is the specification's 1-character lower bound, which no charset or length rule can speak to. It is reported *beside* SPEC-4 rather than instead of it — an empty name is not the name of its directory either, and swallowing that made the emptiest declaration the cheapest one. A `name` that is not text at all stops here, because SPEC-4 compares two directory-name strings |
| SPEC-3 | Missing Description | MEDIUM | No | No `description` is declared |
| SPEC-4 | Name Does Not Match Directory | MEDIUM | **Yes** | The declared `name` is not the name of its own directory. Loaders that resolve same-name overrides by `name` rather than by path then load this skill as the one it declares, not the one it sits in. Silent when the scanned root is a temporary directory this tool created (git, URL, zip or single-file input), because that directory name is not the author's |
| SPEC-5 | Name Charset | LOW | No | `name` holds characters outside `a-z`, `0-9` and `-` |
| SPEC-6 | Name Hyphenation | LOW | No | `name` opens or closes with `-`, or holds `--` |
| SPEC-7 | Name Length | LOW | No | `name` is over 64 characters |
| SPEC-8 | Empty Description | LOW | No | `description` is declared and holds nothing |
| SPEC-9 | Description Length | MEDIUM | **Yes** | `description` is over 1024 characters. It goes into the system prompt, so everything past the cut is dropped before the agent reads it |
| SPEC-10 | Compatibility Length | LOW | No | `compatibility` is over 500 characters |
| SPEC-11 | Metadata Shape | LOW | No | `metadata` is not a mapping from text keys to text values |
| SPEC-12 | Body Line Budget | LOW | No | The body after the declaration block is over 500 lines; all of it loads at once when the skill activates |
| SPEC-13 | Body Token Budget | LOW | No | The body is over roughly 5000 tokens. The only estimate in the catalog — counted from character length, not with a tokenizer — and it carries a lower confidence for that reason |
| SPEC-14 | Manifest Size Limit | MEDIUM | **Yes** | `SKILL.md` is 10 MB or larger. Deep Agents skips such a file while loading, so the skill looks installed and never loads. Measured from the file's size on disk, not from its decoded text |
| SPEC-15 | Missing File Reference | MEDIUM | **Yes** | A Markdown link in the body names a relative path the scan did not find, so the instructions point the agent at something that is not there. Bare paths written in prose are not read as references, and a link inside a fenced code block is treated as an example. It reports a **missing** file, never one the scan declined to look for: a single-file input carries no tree, and a hidden file or a pruned directory is already recorded as out of scope. A file under a directory symlink is the one uncovered shape ([issue #123](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/123)) |
| SPEC-16 | Deep File Reference | LOW | No | A Markdown link target is more than one level deep |
| SPEC-17 | Duplicate Skill Name | MEDIUM | **Yes** | Two skill directories in the same scan declare one `name`, so whichever loader consumes them picks between them invisibly. **Loader behavior, not a specification clause** — the captured page states no skill-name uniqueness constraint; this is scored on the consequence, not on a citation. Reported once, on the later directory in path order. A manifest declaring no usable name is not a side of a collision — the same test SPEC-2 asks. Which invocations reach it is described under [Specification conformance](#specification-conformance----spec-checks) |

All detected patterns are listed in the tables above.

## Risk Scoring

### Score Calculation

- **CRITICAL issues**: +50 points
- **HIGH issues**: +25 points
- **MEDIUM issues**: +10 points
- **LOW issues**: +5 points
- **Executable scripts**: 1.3x multiplier

### Severity Levels

| Score | Severity | Recommendation |
|-------|----------|----------------|
| 0-20 | LOW | SAFE |
| 21-50 | MEDIUM | CAUTION |
| 51-80 | HIGH | DO NOT INSTALL |
| 81-100 | CRITICAL | DO NOT INSTALL |

## Example Output

### Terminal Output

```
 SkillSpector Security Report  v2.0.0

Skill: suspicious-skill
Source: ./suspicious-skill/
Scanned: 2026-01-29 10:30:00 UTC

        Risk Assessment
 Metric          Value
 Score           78/100
 Severity        HIGH
 Recommendation  DO NOT INSTALL

        Components (3)
 File              Type      Lines  Executable
 SKILL.md          markdown    142  No
 scripts/sync.py   python       87  Yes
 requirements.txt  text          3  No

Issues (2)

  HIGH: Env Variable Harvesting (E2)
    Location: scripts/sync.py:23
    Finding: for key, val in os.environ.items():...
    Confidence: 94%
    Explanation: This code collects environment variables containing
    API keys and secrets, then sends them to an external server.

  HIGH: External Transmission (E1)
    Location: scripts/sync.py:45
    Finding: requests.post("https://api.skill.io/env"...
    Confidence: 89%
    Explanation: Data is being sent to an external server. Combined
    with env harvesting above, this indicates credential exfiltration.
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SKILLSPECTOR_PROVIDER` | Active LLM provider: `openai`, `anthropic`, `anthropic_proxy`, `bedrock`, `nv_build`, `ollama`, `azure_openai`, `openai_compatible`, `claude_cli`, `codex_cli`, or `gemini_cli`. Hosted providers use bundled `model_registry.yaml` defaults; `claude_cli` and `codex_cli` fall back to the local CLI runtime's default model unless `SKILLSPECTOR_MODEL` is set. Defaults to `nv_build`. | Optional |
| `NVIDIA_INFERENCE_KEY` | Credential for the `nv_build` provider (build.nvidia.com). | Required for LLM analysis when `SKILLSPECTOR_PROVIDER=nv_build` |
| `OPENAI_API_KEY` | Credential for the OpenAI provider (`SKILLSPECTOR_PROVIDER=openai`). Also serves as the tier-2 fallback in the credential waterfall when the active provider returns no credentials. | Required for LLM analysis when `SKILLSPECTOR_PROVIDER=openai` |
| `OPENAI_BASE_URL` | Override the OpenAI endpoint (e.g. point at Ollama). | Optional |
| `SKILLSPECTOR_REASONING_EFFORT` | Optional provider- and model-dependent reasoning-effort setting. Non-empty values are trimmed and passed through unchanged; unset or blank preserves provider-default behavior. | Optional |
| `ANTHROPIC_API_KEY` | Credential for the Anthropic provider (`SKILLSPECTOR_PROVIDER=anthropic`). | Required for LLM analysis when `SKILLSPECTOR_PROVIDER=anthropic` |
| `ANTHROPIC_BASE_URL` | Override the native Anthropic endpoint (default: `https://api.anthropic.com`). | Optional |
| `ANTHROPIC_PROXY_ENDPOINT_URL` | Full endpoint URL for the Anthropic proxy provider (Vertex-style raw-predict). | Required when `SKILLSPECTOR_PROVIDER=anthropic_proxy` |
| `ANTHROPIC_PROXY_API_KEY` | Bearer token for the Anthropic proxy provider. | Required when `SKILLSPECTOR_PROVIDER=anthropic_proxy` |
| `ANTHROPIC_PROXY_API_VERSION` | `anthropic_version` value sent in the request body (default: `vertex-2023-10-16`). | Optional |
| `AWS_PROFILE` | Named AWS profile for the Bedrock provider — authenticates via SigV4 through boto3. When unset, the standard boto3 credential chain (env vars, instance metadata, SSO, etc.) resolves. | Optional (used when `SKILLSPECTOR_PROVIDER=bedrock`) |
| `AWS_REGION` | AWS region for the Bedrock Runtime endpoint. Defaults to `us-west-2`. | Optional (used when `SKILLSPECTOR_PROVIDER=bedrock`) |
| `OLLAMA_BASE_URL` | Endpoint for the `ollama` provider (default: `http://localhost:11434`). No credential is involved — the server is local. | Optional (used when `SKILLSPECTOR_PROVIDER=ollama`) |
| `AZURE_OPENAI_ENDPOINT` | Resource endpoint for the `azure_openai` provider. | Required when `SKILLSPECTOR_PROVIDER=azure_openai` |
| `AZURE_OPENAI_API_KEY` | Credential for the `azure_openai` provider. | Required when `SKILLSPECTOR_PROVIDER=azure_openai` |
| `AZURE_OPENAI_DEPLOYMENT` | Deployment name to call on that resource. | Required when `SKILLSPECTOR_PROVIDER=azure_openai` |
| `AZURE_OPENAI_API_VERSION` | API version sent with the request. | Optional (used when `SKILLSPECTOR_PROVIDER=azure_openai`) |
| `SKILLSPECTOR_COMPAT_BASE_URL` | Endpoint for the `openai_compatible` provider — any server speaking the OpenAI chat-completions API. | Required when `SKILLSPECTOR_PROVIDER=openai_compatible` |
| `SKILLSPECTOR_COMPAT_API_KEY` | Credential for that endpoint. | Optional (used when `SKILLSPECTOR_PROVIDER=openai_compatible`) |
| `SKILLSPECTOR_MODEL` | Override the active provider model. For hosted providers, this replaces the bundled default from the LLM Analysis table. For `claude_cli` and `codex_cli`, this is forwarded as `--model` instead of using the local CLI runtime fallback. | Optional |
| `SKILLSPECTOR_MODEL_REGISTRY` | Override the bundled per-provider YAML registry (`src/skillspector/providers/<provider>/model_registry.yaml`) with a custom path. | Optional |
| `SKILLSPECTOR_LOG_LEVEL` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `WARNING`). | Optional |

> **CLI providers** (`claude_cli`, `codex_cli`): No API key is needed. Authentication is managed entirely by the agent CLI's own login session (`claude auth login` / `codex login`). SkillSpector never reads or forwards API keys when these providers are active. The subprocess is run in a hardened sandbox: tools disabled, no MCP, read-only sandbox mode (codex), and untrusted skill content is delivered only via stdin.

### CLI Options

```bash
skillspector scan --help

Options:
  -f, --format [terminal|json|markdown|sarif]  Output format [default: terminal]
  -o, --output PATH                            Output file path
  --no-llm                                     Skip LLM analysis (static only)
  --yara-rules-dir PATH                        Extra YARA rules directory
  -r, --recursive                              Scan each immediate subdirectory holding a
                                               SKILL.md as its own skill
  -b, --baseline PATH                          Suppress findings listed in a baseline
  --show-suppressed                            List baseline-suppressed findings
  --use-shipped-baseline                       Apply a baseline the scanned skill ships
                                               (.skillspector-baseline.yaml). Off by
                                               default: a skill author's baseline can
                                               suppress findings in your scan, so a
                                               discovered one is only reported until you
                                               opt in. Ignored with --baseline
  --transitive                                 Follow transitive external references
                                               after the initial scan
  --transitive-depth INTEGER                   Maximum transitive depth [default: 1]
  --transitive-allow-prefix TEXT               Only follow targets matching a canonical
                                               prefix (repeatable)
  --transitive-deny-prefix TEXT                Skip targets matching a canonical prefix
                                               (repeatable)
  --fail-on-incomplete                         Exit 1 when the analysis is partial
  --repo-scan                                  Find every skill in a repository, scan each
  --repo-scan-root TEXT                        Replace the discovery roots (repeatable)
  --spec-checks [off|advisory|strict]          Agent Skills specification conformance
                                               [default: off] (see Specification
                                               conformance)
  --mcp-registry                               Registry Scan: assess MCP Registry records
                                               instead of a skill (see Scanning the MCP
                                               Registry; requires --format json)
  -V, --verbose                                Show detailed progress
  --help                                       Show this message and exit

# Generate a baseline of all current findings (see docs/SUPPRESSION.md)
skillspector baseline <path> [-o FILE] [--no-llm] [--reason TEXT] [--spec-checks MODE]
```

## Integrating SkillSpector

SkillSpector is built to be driven by other tools (CI pipelines, install gates, editor integrations). Its exit code and JSON output are a stable contract.

### Exit codes

`skillspector scan` exits with:

| Code | Meaning |
|------|---------|
| `0` | Scan completed, `risk_score` ≤ 50 (recommendation `SAFE` or `CAUTION`) |
| `1` | Scan completed, `risk_score` > 50 (recommendation `DO_NOT_INSTALL`) |
| `2` | Error (bad input, unreadable source, internal failure) |

> The exit code collapses `SAFE` and `CAUTION` into `0`. To act differently on them (e.g. *warn* on `CAUTION` but *block* on `DO_NOT_INSTALL`), read the `recommendation` field from the JSON output rather than relying on the exit code.

### Machine-readable output

`--format json` produces a JSON report; with no `--output`/`-o` it is written to stdout:

```bash
skillspector scan ./my-skill/ --format json
```

The top-level shape is (this example shows a full LLM-backed scan; with `--no-llm`, `metadata.llm_requested` is `false`):

```json
{
  "skill": { "name": "...", "source": "...", "scanned_at": "<ISO 8601>" },
  "risk_assessment": { "score": 0, "severity": "LOW", "recommendation": "SAFE", "max_issue_severity": "LOW" },
  "components": [ { "path": "...", "type": "...", "lines": 0, "executable": false, "size_bytes": 0 } ],
  "issues": [ { "id": "...", "category": "...", "severity": "...", "confidence": 0.0, "location": { "file": "...", "start_line": 0 } } ],
  "metadata": {
    "has_executable_scripts": false,
    "skillspector_version": "...",
    "llm_requested": true,
    "llm_available": true,
    "inference_usage": [
      {
        "node": "semantic_security_discovery",
        "request_kind": "structured_output",
        "provider": "nv_inference",
        "model": "azure/anthropic/claude-opus-4-6",
        "model_source": "provider_response",
        "usage_source": "provider_response",
        "prompt_tokens": 1000,
        "completion_tokens": 100,
        "cached_tokens": 400,
        "cache_write_tokens": 50,
        "total_tokens": 1100
      }
    ]
  }
}
```

- `risk_assessment.severity` ∈ `LOW | MEDIUM | HIGH | CRITICAL`.
- `risk_assessment.recommendation` ∈ `SAFE | CAUTION | DO_NOT_INSTALL`, mapped from severity: `LOW → SAFE`, `MEDIUM → CAUTION`, `HIGH`/`CRITICAL → DO_NOT_INSTALL`.
- `risk_assessment.max_issue_severity` is the highest severity among the findings the
  report carries, and is `null` when it carries none. It is there because `score` is
  normalized: a single HIGH finding in a large skill can land under the threshold and
  read as `SAFE`. A gate that must not miss one reads this field rather than the score.
- `metadata.llm_error` appears only when LLM analysis was requested but unavailable.
- `metadata.inference_usage` contains one sanitized record per LLM response when the
  provider exposes token counters. It is an empty list when usage is unavailable;
  SkillSpector never estimates missing tokens. Prompt totals are inclusive of cache
  reads and writes so downstream pricing can separate those partitions safely.
  `model_source` distinguishes an independently identified provider model from
  the exact requested model used when response identity is absent or ambiguous.
  SkillSpector does not currently send Anthropic prompt-cache controls, so its
  scan requests cannot select the separate 5-minute or 1-hour cache-write tiers;
  TTL-specific response fields are normalized defensively into the aggregate
  cache-write counter.
- See [Inference usage telemetry](docs/INFERENCE_USAGE.md) for the complete
  provenance, cache-accounting, privacy, fail-closed ingestion, and downstream
  pricing contract.
- The full per-issue shape is defined by `Finding.to_dict()` in [models.py](src/skillspector/models.py); rely on the fields above and treat any additional fields as best-effort.

For CI/IDE tooling, `--format sarif` emits SARIF 2.1.0.

### Which stream carries what

One rule covers every line the CLI prints: **the report goes to stdout, everything else goes to
stderr** — advisories, progress lines, `Report saved to:`, per-skill summary tables (with one
argued exception, below), the `--spec-checks` advisory-count note described under
[Specification conformance](#specification-conformance----spec-checks), errors and tracebacks. So both of
these are pipelines you can rely on, with nothing to redirect away:

```bash
skillspector scan ./my-skill/ --format json | jq .
skillspector scan . --repo-scan --format sarif | jq '.runs | length'
```

Redirect stderr (`2>/dev/null`) only when you want the notes gone as well; the exit code is
unaffected either way. Both pipelines above assume the scan found a skill to report on — see
[What moved, and what that costs](#what-moved-and-what-that-costs) for the discovery cases where
stdout is legitimately empty.

The rule says which *stream* the report goes to, not that every format is one parseable document.
With `--repo-scan` only `--format sarif` is merged — one SARIF log, one run per skill, which is why
the example above uses it. `--format json` and `--format markdown` put the per-skill bodies on
stdout concatenated behind `--- <path> ---` separators, exactly the shape the `--format json
--output` row of the `--repo-scan` vs `--recursive` table in
[Scanning a Whole Repository](#scanning-a-whole-repository) describes, and no JSON or Markdown
consumer reads that as a single document. Merging them is
[#116](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/116); until then, use `sarif` for
a `--repo-scan` pipeline, or scan each skill separately.

`--recursive` is the one path where the distinction has to be argued rather than applied, because
once it engages it writes its combined report **only** to `--output` — there is no report on stdout
for the summary table to sit beside
([#114](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/114)). With `--format terminal`
and no `--output`, that `═══ Multi-Skill Summary ═══` table is the whole of what the scan produced,
so it *is* the report and stays on stdout, keeping
`skillspector scan ./skills --recursive | less` worth running.

That is the only case. Pass `--output` and the file becomes the report, the table drops to a digest
of it, and it moves to stderr with everything else. Ask for `--format json`, `sarif` or `markdown`
without an `--output` and there is no report anywhere, so stdout stays **empty** rather than
carrying a table that `jq` cannot read — the rule above holds, and `#114` is what would put a report
back on that stream.

All of that describes `--recursive` **once it engages**, exactly as the comparison table's
`--baseline` row does. The flag needs two or more immediate child skills; below that threshold it
never engages at all, and the scan that runs instead is an ordinary one that prints its report to
stdout in whatever format was asked for. So `skillspector scan ./skills --recursive -f json | jq` is
safe on one child skill and silent on two — the difference is the threshold, not the flag.

#### What moved, and what that costs

This is a change in where output appears, not in what is produced. Previously **stdout** carried:

- the multi-skill advisory, `Warning: Found N skills in this directory…`;
- `--recursive`'s own `Multi-skill directory detected: N skills found`, its `[i/N] Scanning <name>`
  progress lines and its per-skill `Score: X/100 (SEV)` lines;
- `--repo-scan`'s `[i/N] Scanning …` progress lines, its summary table, and its
  `Warning: no skill found under …` when discovery matched nothing;
- `--verbose`'s `Running scan…` and the `baseline` command's `Scanning to build baseline…`;
- every `Report saved to:` / `Combined report saved to:` note;
- every `Error:` line and traceback, and the `baseline` command's
  `Wrote baseline with N suppressed finding(s)`.

All of them are on **stderr** now. One further line moved *conditionally*: `--recursive`'s
`═══ Multi-Skill Summary ═══` table was always on stdout and is now on stdout in the single case
argued above — `--format terminal` with no `--output`, where it is the report — and on stderr in
every other.

So a piped `--format json` or `--format sarif` report is parseable without redirecting anything.
Nothing was removed and no exit code changed, and a script reading a combined stream (`2>&1`) still
gets every line — though a *piped* combined stream may interleave the two differently, because a
piped stdout is block-buffered while stderr is not. Order within either stream on its own is
unchanged.

For a script that reads **stdout alone**, this is strictly less noise on every path that puts a
report there. Three cases are worth naming, because in them the noise that went away was carrying
something:

- **`--repo-scan` finding no skill at all** now exits `0` with completely empty stdout, where it
  previously put an unparseable `Warning: no skill found under …` there. A gate that piped stdout
  into `jq` used to fail loudly on a discovery miss; it now passes vacuously. Gate on the *content*
  — `jq -e '.runs | length > 0'` — or watch stderr. Making that a designed signal rather than an
  accident is [#115](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/115).
- **`--recursive` with `--format json`, `sarif` or `markdown` and no `--output`** is the same hazard
  on a more common input, and it is the one shape closest to the pipeline this change exists to fix.
  It never wrote a report to stdout ([#114](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/114));
  what it wrote there was the detection banner, the progress lines and the summary table, so
  in `skillspector scan ./skills --recursive -f json | jq .` it was `jq` that failed, with a parse
  error and its own exit `5` — the scanner exited `0` throughout. That stdout is now empty, so `jq`
  succeeds on nothing and the pipeline exits `0` silently. The mitigation is the same:
  pass `--output` and read the file, or gate on content with `jq -e`. #114 is what puts a report
  back on that stream and removes the case.
- **`skillspector scan ./skills --recursive | less`** now shows the `═══ Multi-Skill Summary ═══`
  table alone, where it used to show the detection banner and the per-skill progress and score lines
  above it. Every per-skill score is still there, in the table's own rows.

### Recommended gate mapping

When using SkillSpector as an install gate, map the recommendation to an action:

| `recommendation` | Suggested action |
|------------------|------------------|
| `SAFE` | allow |
| `CAUTION` | prompt / warn the user |
| `DO_NOT_INSTALL` | block |

SkillSpector computes the score band and recommendation; how strict the gate is (e.g. whether `CAUTION` blocks in CI) is a policy decision for the integrating tool.

## Development

### Setup

All `make` targets assume a virtual environment is already created and activated. The Makefile uses **uv** if available, else **pip**.

```bash
# Clone, create venv, activate, install dev dependencies
git clone https://github.com/NVIDIA/skillspector.git
cd skillspector
uv venv .venv && source .venv/bin/activate
# or: python3 -m venv .venv && source .venv/bin/activate
make install-dev

# Run tests
make test

# Run tests with coverage
make test-cov

# Run linting
make lint

# Format code
make format
```

## How It Works

SkillSpector uses a two-stage detection pipeline:

### Stage 1: Static Analysis
- Fast regex-based pattern matching across 11 static analyzers
- AST-based behavioral analysis detecting dangerous calls (exec, eval, subprocess, etc.)
- Live vulnerability lookups via OSV.dev for known CVEs in dependencies
- Scans all analyzer-eligible files in the skill
- High recall (catches most issues)
- Moderate precision (some false positives)

A valid, root-level OpenSSF Model Signing signature (`skill.oms.sig`) is retained in the
component inventory as type `oms_signature`, but excluded from static and LLM content analysis.
OMS bundles necessarily contain long base64-encoded payload, signature, and certificate fields;
generic obfuscated-code checks can otherwise misclassify those fields as hidden executable content.
The recognizer checks the minimal OMS DSSE/in-toto structure; it does not verify the signature,
certificate chain, transparency-log entry, or signer identity. Invalid or unrecognized signature
files are scanned normally.

### Stage 2: LLM Semantic Analysis (Optional)
- Evaluates context and intent
- Filters false positives
- Provides human-readable explanations
- Improves precision to ~87%

The LLM prompt includes anti-jailbreak protections to prevent malicious skills from manipulating the analysis.

## Live Vulnerability Lookups (SC4)

SC4 uses the [OSV.dev](https://osv.dev) API to check dependencies against the full Open Source Vulnerabilities database — covering tens of thousands of advisories across PyPI and npm.

- **No API key required** — OSV.dev is free and unauthenticated.
- **Batch queries** — all dependencies are checked in a single HTTP call.
- **Automatic fallback** — if OSV.dev is unreachable (air-gapped/offline), a small built-in fallback list is used.
- **Caching** — results are cached in-memory for 1 hour to avoid redundant API calls during a session.

The tool requires outbound HTTPS access to `api.osv.dev` for live vulnerability data. When that is not available, findings are limited to the static fallback list.

## Trust model and data egress

SkillSpector is defense-in-depth, not a sandbox. Know what it does and does not do before relying on it:

- **It never executes the scanned skill.** All analysis is static (regex, Python AST, YARA) plus optional LLM evaluation of file *contents* — the skill's code is never run.
- **LLM analysis sends analyzer-eligible file contents to the configured provider.** When LLM analysis is enabled (the default), file contents are sent to the active `SKILLSPECTOR_PROVIDER` endpoint. Recognized OMS signature files are excluded. Use `--no-llm` to keep contents local (static analysis only).
- **SC4 sends dependency names to OSV.dev.** The supply-chain check queries [OSV.dev](https://osv.dev) with the package names and versions the skill declares, to look up known CVEs. This is fundamental to the check and runs even with `--no-llm`. It sends dependency coordinates (not file contents), requires no API key, and falls back to a bundled list when OSV.dev is unreachable.
- **It does not sandbox the host.** SkillSpector flags risky patterns *before* you install a skill; it does not contain or isolate a skill you choose to install anyway.

## Limitations

- **Non-English content**: May miss patterns in other languages
- **Image-based attacks**: Cannot analyze text in images
- **Encrypted/binary code**: Cannot analyze compiled or encrypted content
- **Runtime behavior**: Static analysis only, no dynamic execution
- **Offline SC4**: Without network access to `api.osv.dev`, SC4 uses a small static fallback list

## Research Background

Based on research from "Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale" (Liu et al., 2026):

- **Dataset**: 42,447 skills from major marketplaces
- **Vulnerable**: 26.1% contain at least one vulnerability
- **High-severity**: 5.2% show likely malicious intent
- **Key finding**: Skills with executable scripts are 2.12x more likely to be vulnerable

## Python API Integration

```python
from skillspector import graph

# Invoke the LangGraph workflow
result = graph.invoke({
    "input_path": "/path/to/skill",
    "output_format": "json",   # terminal, json, markdown, or sarif
    "use_llm": True,           # False for static-only analysis
})

# Access results
print(f"Risk Score: {result['risk_score']}/100")
print(f"Severity: {result['risk_severity']}")
print(f"Recommendation: {result['risk_recommendation']}")

for finding in result["filtered_findings"]:
    print(f"[{finding['severity']}] {finding['rule_id']}: {finding['message']}")
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Support

- **Issues**: [GitHub Issues](https://github.com/NVIDIA/skillspector/issues)
