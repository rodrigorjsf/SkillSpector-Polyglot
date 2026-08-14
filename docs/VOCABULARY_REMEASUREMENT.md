# Re-measuring a Framework vocabulary

Every Framework inventory carries a claim: *these spellings were observed across this range of
published releases, and none was ever removed*. This document is how that claim is re-measured, and
what obliges someone to re-measure it.

Three inventories carry it today, and the tooling reaches **two** of them:

| Inventory | Index | Re-measured by |
|---|---|---|
| `src/skillspector/langchain4j/vocabulary.py` | Maven Central | `contrib.vocabulary_sweep` |
| `src/skillspector/deepagents/vocabulary.py` | PyPI | `contrib.vocabulary_sweep` |
| `src/skillspector/deepagents_js/vocabulary.py` | npm | **by hand** — see below |

**The npm gap is stated rather than hidden.** `contrib/vocabulary_sweep` reads PyPI and Maven
Central; it has no npm reader, so the JavaScript inventory's range was measured by hand: every final
release of the npm distribution `deepagents` at or above the Skills floor upstream documents
(`1.7.0`) was downloaded from the registry and its packed `.js`, `.cjs`, `.mjs`, `.ts` and `.json`
files searched for each spelling as a whole word — 32 releases, `1.7.0` through `1.12.3`, on
2026-08-13. The result is recorded in that module's `OBSERVED_VERSION_RANGE` comment, including which
release each of the two late-arriving spellings first appears in.

Everything below applies to all three inventories; only the *command* differs, and teaching
`contrib/vocabulary_sweep` to read npm is the obvious way to close the difference. Until it does, a
re-measurement of the JavaScript inventory has to repeat the manual sweep and say in the commit body
that it did.

## The failure it guards against

A Rule matches an upstream spelling. Upstream renames it. The Rule stops producing Findings — and
nothing says so. The Scan still succeeds, the Analyzer still reports `completed`, every file it
opened still gets an Inspection Ledger row, and the report reads as clean. **An absence of Findings
caused by a stale spelling is indistinguishable from a genuinely clean Scan.**

No guard test catches this. `tests/unit/test_langchain4j_vocabulary.py`,
`tests/unit/test_deepagents_vocabulary.py` and `tests/unit/test_deepagents_js_vocabulary.py` fail the
build when a spelling is written *outside* its inventory; they cannot fail when the inventory itself
has gone stale, because a stale spelling is still perfectly consistent with the code that reads it.
Only reading published releases can tell.

This procedure closes the gap [ADR 0005](adr/0005-langchain4j-upstream-vocabulary.md) named and
[issue #46](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/46) recorded: the original
measurement had *"no procedure and no trigger"*.

## What to run

```bash
python -m contrib.vocabulary_sweep deepagents
python -m contrib.vocabulary_sweep langchain4j
```

Standard library only, so no install step beyond the project's own. Each command reads a public
package index over the network — PyPI for Deep Agents, Maven Central for LangChain4j — and nothing
else. Nothing is executed from a downloaded release: Python sources are parsed with `ast`, Java
class files are parsed as class files.

**Exit code 1 is a blocking result**, not a warning to skim past. See *Reading the output*.

## What it reads

For each inventoried constant the sweep holds a **role** — the shape upstream writes the spelling
in — and counts a release as carrying the spelling only when it occurs in that role.

| Role | Python | Java |
|---|---|---|
| Defined name | a `class`, a `def`, a module-level binding, a re-export | a class file the artifact ships |
| Bound name | a parameter, a keyword argument, an annotated field | a method some class *declares* |
| Literal value | a string constant | — |
| Distribution name | the index entry serving the wheel | the coordinates serving the jar |
| Not measured | a documented convention, a pattern, the range itself | same |

Roles are keyed by the inventory's *constant names*, never by their values, so the sweep holds no
second copy of a spelling for the guard tests to miss. A constant with no role — or a role for a
constant that no longer exists — stops the sweep rather than being skipped silently.

**Role matters more than it sounds.** Four Deep Agents spellings are ordinary English words, and
`name`, `content`, `tools` and `mode` are among the commonest identifiers in any Java library. A
sweep that asked "does this release contain the text `skills`" would answer yes for every release
ever published, including the ones predating the feature, and the stability claim would be exactly
the unmeasured assertion this procedure exists to replace.

### What is in scope

| | Releases swept |
|---|---|
| Deep Agents | every **final** release of the distribution — a version of three dotted integers and nothing appended. PyPI also serves `0.7.0b1` and `0.0.11rc1`; a spelling that appeared in a pre-release and was gone by the final release was never published as upstream's API. |
| LangChain4j | every version each artifact's own `maven-metadata.xml` lists. Nothing is filtered as a pre-release here: `-betaNN` is not a pre-release marker but part of how every release of the Skills artifacts is named. |

LangChain4j spans **four artifacts on three version lines** — `langchain4j-skills`,
`langchain4j-experimental-skills-shell`, `langchain4j-mcp` and `langchain4j-core`, the last released
without a `-betaNN` suffix. Each is swept over its own published history and reported under its own
heading, so a range is never read across artifacts that do not share one. Two of them predate Skills
by years, so their swept range is much longer and says nothing about the Skills API: **the range
recorded as `OBSERVED_VERSION_RANGE` is the Skills artifacts' range**, not the widest one printed.

## Reading the output

Each spelling comes back as one of four verdicts.

- **observed across the whole range** — the claim holds for it.
- **added at `<version>`** — annotate the constant with that release. Expected in a `0.x`
  distribution; not expected in a stable one.
- **REMOVED at `<version>`** — *blocking*. This is the event ADR 0005 named as reopening its rejected
  per-version API profiles. Do not record a range without settling that question.
- **never observed** — *blocking*. The inventory and the published releases disagree: either the
  spelling is stale or the role assigned to it is wrong. Settle which before recording anything.

The two blocking verdicts exit non-zero, so a trigger can be automated later without re-deciding
what counts as a failure.

**One step the tool cannot do for you.** A *literal value* is a bare string, and a sweep for one
cannot tell the spelling's real use from any other use of the same word. Before recording the first
release of a literal-value spelling, read the release it claims — `deepagents` 0.5.0 writes
`multitask_strategy="interrupt"` in an unrelated middleware, two releases before the `mode` value of
the same name exists. The recorded annotation is the corrected one, with the reason beside it.

## Recording the new claim

The sweep's output is not the claim; the inventory is. What lands:

1. `OBSERVED_VERSION_RANGE` in the vocabulary module, as the oldest and newest release swept.
2. Every spelling that was added mid-range, annotated with its first release — beside the constant,
   or as a table above the range when most of an inventory is annotated.
3. The date of the sweep, in the module docstring, so a reader can tell how stale the claim is.
4. The same range wherever it is restated in prose — the captured reference's front-matter, the ADRs
   that reason about it, and any fixture comment quoting it. Grep both endpoint strings before
   editing; the LangChain4j range is prose in four places besides the constant.

**A sweep that finds a stale spelling does not fix the Rule in the same change.** Recording a
measurement changes no Scan behavior, and mixing a Rule correction into it destroys the property
that makes the measurement checkable — that every snapshot stayed byte-identical. File the Rule
change as its own issue and leave the inventory alone, with the result written beside the constant
so the next reader meets it there.

## The trigger

Re-measure when **any** of these happens. The first two are events; the third is the backstop for
the risk the first two miss, which is precisely the release SkillSpector has not adopted.

1. **Before adding or changing a Rule that matches a new spelling.** The inventory the new Rule joins
   is the one whose claim is about to be extended.
2. **When a scanned corpus, an issue, or an upstream release note names a Framework version outside
   the recorded range.** The range is a staleness marker a maintainer reads; a version beyond it is
   the moment to read it.
3. **Every six months otherwise.** Every upstream here publishes fast — Deep Agents shipped 78 final
   releases in roughly a year on PyPI, and 32 on npm between its Skills floor and today — and each is
   pre-1.0, beta or freshly past 1.0 by upstream's own description.
   LangChain4j says so on the page this project captured: *"The Skills API is experimental. APIs and
   behavior may still change in future releases."*

Recording a sweep's date in the module docstring is what makes the third trigger checkable without
a calendar somewhere else.

## Worked example: the 2026-08-03 re-measurement

Run once against both Frameworks, under issue #75. It is the reason the procedure is worth having
rather than an illustration of it.

**Deep Agents — first measurement.** 78 final releases, `0.0.1` through `0.7.3`. No spelling was
ever removed. Nineteen of the twenty-two were added during that history, which is what a `0.x`
distribution looks like; the permission vocabulary arrives together at `0.5.2`, which is the
practical floor for everything the Rules read. The `deepagents>=0.6.8` floor quoted in the captured
reference is a floor for a different question and sits above it.

**LangChain4j — re-measurement.** The range was confirmed unchanged: still 17 releases,
`1.12.1-beta21` through `1.18.1-beta28`, with no new release since the original measurement. The
shell artifact is still published under its `experimental` name, so the graduation rename ADR 0007
watches for has not happened. Two corrections came out of it.

- **`tools` was also added at `1.13.0-beta23`.** The original record said `ClassPathSkillLoader` was
  the *only* change across the history. It compared class listings, and a builder argument added to
  a class that already exists changes no listing. Reading each release's own method tables shows
  `tools` appearing on `AbstractSkill$BaseBuilder` in the same release. The claim was not wrong about
  what it measured; it was measuring something narrower than it said.
- **`toolFilter` has never been published.** `McpToolProvider.Builder` declares `filter` and
  `filterToolNames`, at `1.12.1-beta21` as at `1.18.1-beta28`. The spelling entered this project from
  upstream's Skills tutorial, whose MCP example writes `.toolFilter(...)` — contradicted by
  upstream's own MCP tutorial and by every jar it publishes. `L4J-MCP-FILTER` therefore reported a
  builder chain as unfiltered whatever it did, since no chain compiled against a published release
  could call the setter it looked for. Filed as issue #82 and left unchanged here, because a
  measurement must not move behavior; #82 has since replaced the spelling with `filter` and
  `filterToolNames` and regenerated the two Behavior Snapshots that carried it.

The second finding is the one to remember when deciding whether this procedure earns its cost. A
capability the project reasoned about, documented, fixtured and shipped rested on a method name that
no published release has ever had — and reading the published artifacts is what said so.
