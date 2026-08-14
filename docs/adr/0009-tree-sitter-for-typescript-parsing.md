# Parse TypeScript with tree-sitter, and port the Deep Agents Rules rather than share them

Status: accepted

Supporting Deep Agents for JavaScript means reading TypeScript and JavaScript to resolve which Skill
sources an agent is given and what it may do to them. We chose `tree-sitter-typescript`, accepting a
third runtime dependency on a deliberately tight list, and we chose to **port**
`skillspector.deepagents` into a parallel package rather than share one implementation between the
two languages.

[ADR 0001](0001-tree-sitter-for-java-parsing.md) is the precedent for the first decision and
[ADR 0005](0005-langchain4j-upstream-vocabulary.md) for the second. Both are applied here rather than
re-argued; what follows is only what is new.

## The dependency

`tree-sitter-typescript` **0.23.2**, MIT, `Copyright (c) 2017 Max Brunsfeld` — read from the
installed `dist-info`'s `LICENSE`, not recalled, per `.claude/rules/license-compliance.md`. The
copyright line differs from both of its neighbours in `THIRD_PARTY_NOTICES.md`
(`tree-sitter` is *"2019 Max Brunsfeld, GitHub"*, `tree-sitter-java` is *"2017 Ayman Nadeem"*), so it
is recorded verbatim rather than normalised to look like them.

ADR 0001's acceptance criterion was prebuilt `cp39-abi3` wheels, so no C toolchain is needed on any
supported interpreter. That holds: the wheel tags are `cp39-abi3-manylinux*`. 0.23.2 is also the
**latest** release, so the `>=0.23.2` floor in `pyproject.toml` currently pins the only version there
is.

**One measured caveat.** The distribution declares `tree-sitter~=0.23` — but only under its `core`
extra, which nothing here installs, and this project declares `tree-sitter>=0.26.0`. The two were
verified compatible empirically rather than by reading the specifier: both grammars build and parse
under the installed `tree-sitter` 0.26.0. `tree-sitter-java` 0.23.5 already sits in the same position
and has since ADR 0001.

## Two grammars, not one

`tree-sitter-typescript` ships `language_typescript()` **and** `language_tsx()`, and they are not
interchangeable — JSX fails under the TypeScript grammar, which reads `<Panel>` as a type parameter
list. Measured: a module whose `createDeepAgent` call is *enclosed* by JSX yields **zero**
configurations under the TypeScript grammar and one under TSX.

So `.tsx` goes to the TSX grammar, everything else goes to TypeScript, and a non-`.tsx` file that
fails is **retried** under TSX and kept only if the retry parses cleanly. The retry exists because the
suffix cannot distinguish JSX-in-`.js` from ordinary JavaScript; keeping it only on a clean retry is
what stops a file using real TypeScript generics from being re-read as JSX.

## A parse error is tolerated, not refused

The grammar's last release predates roughly two years of TypeScript syntax, so `has_error` is as
likely to mean "newer than the grammar" as "broken". tree-sitter is error tolerant, and the option
keys every Rule reads are ordinary object properties that survive an error elsewhere in the file.

This is where the JavaScript track **diverges from the Python one**. `framework_deepagents` skips a
module whose `ast.parse` raised, with `LedgerOutcome.SKIPPED` and `LedgerReason.SYNTAX_ERROR`,
because a Python file either parses or it does not. There is no such boundary here: tree-sitter
always returns a tree. Every applicable Component is therefore reported `completed`, and the cost is
stated rather than discovered — a genuinely malformed module is reported as completed, having
contributed whatever partial tree it had.

## The Rules are reused; the implementation is not

`DA-UNRESOLVED`, `DA-SKILL-WRITABLE`, `DA-SHADOW` and `DA-SUBAGENT-SKILLS` keep their ids, severities
and confidences. They judge the same upstream framework, so a team that has decided "this agent may
rewrite its Skills is acceptable here" states that decision once: a glob `SuppressionRule` keyed on
`rule_id` matches on both tracks. Minting `DAJS-*` would also double the catalogue in
`pattern_defaults` and split the AST10 crosswalk for no new question.

**What reuse does not buy is baseline continuity across a port.** An exact baseline is a v2
fingerprint over the evidence — `suppression.finding_fingerprint` hashes the component path, the
file's sha256, the start line and the message — and every one of those changes when the same
application is rewritten in another language. The rule id surviving is what makes a *rule* portable,
not a fingerprint.

**And the rule id is the only thing shared.** The catalogue entry behind it is written in Python's
syntax, so `framework_deepagents_js` overrides the explanation and remediation strings that name
`FilesystemPermission` — a class the JavaScript distribution does not export — or spell a key
`interrupt_on`, `skills=[...]`, `mode="deny"`. Emitting those verbatim would present the Python
distribution's API as the JavaScript one's inside a Finding, which
`.claude/rules/license-compliance.md` names as a §4 attribution failure rather than a cosmetic one.
`tests/unit/test_deepagents_js_vocabulary.py` guards it over every field a reader sees.

**The code behind them is duplicated on purpose.** `skillspector.deepagents_js` is a port of
`skillspector.deepagents`, not a caller of it. The reason is ADR 0005's: the PyPI distribution and the
npm distribution ship on different clocks, and a shared module would make one upstream rename move
both Frameworks' Rules at once — the silent-failure mode the vocabulary discipline exists to prevent.
Each package therefore has its **own** inventory, and each vocabulary guard excludes the other's home
while sweeping every other module in the tree.

## Where the port is not a copy

Each of these was read out of a **code block** in `docs/references/deepagents-js-skills.md`, never out
of its prose, which leaks Python spellings throughout (the capture annotates them).

| | Python | JavaScript |
|---|---|---|
| Settings | keyword arguments | one options object, first positional argument |
| A permission rule | `FilesystemPermission(...)` | a plain object literal |
| `CompositeBackend` routes | the `routes=` keyword | the second positional argument |
| The interrupt gate | `interrupt_on` over two write tools | `interruptOn` over the same two |
| The backend root | `root_dir` | `rootDir` |

The first inverts a limit the Python resolver states. There, "only keyword arguments are read" and a
positionally-passed configuration is not seen at all. Here every setting is positional by
construction, so the resolver reads the first argument **if it is an object literal** and refuses
everything else — an options object built by a helper carries no setting attributable to any name, so
it is a silence rather than a boundary. `DA-UNRESOLVED` names a setting, and there no setting was
named.

`edit_file` **is** inventoried, on the same footing as `write_file`, and this paragraph records a
correction rather than a decision. A first revision of this ADR left it out on the ground that the
JavaScript page publishes it only in prose, and called the omission a conservative narrowing. It is
the opposite. The mitigation check asks whether the configuration gates **every** inventoried write
tool, so a *smaller* inventory is *easier* to satisfy: with `write_file` alone, the `interruptOn`
block on upstream's own JavaScript page read as a mitigation on this side and as none on the Python
side — `DA-SKILL-WRITABLE` at LOW with "a human is asked" against MEDIUM with "no human is asked",
for the identical configuration. One rule id must not carry two risk statements because the
application was written in a second language, which is the whole premise of reusing the ids.

The code-over-prose rule was also misapplied. It settles a **disagreement**, and there is none: the
page's one `interruptOn` example gates `read_file`, `write_file` and `delete_file`, which is an
example of a gate rather than an enumeration of what may be gated. `edit_file` is snake_case in both
distributions, so it is not a Python spelling leak like `interrupt_on` or `create_deep_agent` — it is
a JavaScript tool name written in JavaScript prose — and the npm sweep finds it in all 32 releases of
the measured range. The consequence now is that an application gating only one of the two write tools
is reported unmitigated, in both tracks alike: under-reporting the mitigation, which leaves the
Finding at full severity, which is the direction a reviewer can correct.

## Detection generalises rather than adding a branch

`framework.py` resolved pairwise. A third Framework breaks that shape, and the semantics-preserving
generalisation is **exactly one signal fires → that Framework; zero or two-or-more → `AGENT_SKILLS`**.
With two signals that is identical to the code it replaces, so no pre-existing input can detect as
something new — asserted against every pre-existing fixture rather than argued.

**Every JavaScript signal is extension-gated, and it has to be.** `"deepagents"` is byte-identical as
a PyPI name and an npm name. What separates them is the file: a Python requirement file or a `.py`
module on one side, a `package.json` or a `.ts/.tsx/.mts/.cts/.js/.mjs/.cjs` module on the other.
Neither set overlaps, so the two Analyzers cannot fire on each other's files.

**The gate is necessary and was not sufficient**, which is the correction this section carries. A
first revision of the JavaScript import pattern let its lead cross a newline, so that a `.ts` file
mentioning the package in a comment matched from an `export` on the line above. The gate held — the
match was inside a `.ts` file, as designed — but a *Python* Deep Agents repository shipping one such
file then fired two signals, resolved to `AGENT_SKILLS` by the rule above, and lost all four `DA-*`
rules with no ledger row to say so. So a signal being confined to the right files does not make it a
signal about the right thing; the lead is line-bounded now, with a braced-binding alternative for the
multi-line import form, and both the wrong shape and its control are pinned in `SIGNALS`. The
JavaScript dependency signal is read out of the parsed `package.json`'s declaration blocks for the
same reason: a textual `"deepagents":` also fired on an `overrides` entry and on any config object
using the word as a key.

**A cost this ADR raises rather than discovers.** A monorepo shipping a Python agent beside a
TypeScript one is the *ordinary* shape of that project, not an exotic polyglot repository — and it now
fires two signals, detects `AGENT_SKILLS`, and loses the same four Rules twice. That makes "return a
set of Frameworks" no longer speculative generality; `framework.py`'s docstring records the reopened
question honestly rather than deleting the old premise. It is not done here because it reaches every
gate and every Behavior Snapshot that projects the key.

## Where the catalogue prose is overridden, and why not deferred

The Python spellings in `pattern_defaults` were first recorded here as a limitation to file rather
than fix, on the belief that changing them meant editing the catalogue and moving every committed
snapshot carrying the rule. **That belief was wrong.** `framework_deepagents_js` builds each Finding
itself and passes `remediation=` and `explanation=` per Finding, so overriding the two strings it
needs touches no `pattern_defaults` entry and moves no snapshot the Python track owns. The
override is therefore taken here, in the change that introduced the defect, and
[issue #126](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/126) keeps only whatever
genuinely shared prose survives it.

## Consequences

TypeScript configuration that is not statically resolvable — an options object built by a helper, a
Skill list assembled per tenant, a `rootDir` from `process.cwd()` — stays unresolvable. tree-sitter
does not move that boundary; it only makes the resolvable cases correct. Upstream's own headline
example falls on the far side of it, which is the honest answer rather than a gap.

Full analysis: `docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md` §3.6.
