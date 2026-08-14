# Vendored framework references

Captured upstream documentation for the agent frameworks SkillSpector analyzes.
These files are **reference material, not SkillSpector documentation**: they exist so
analyzer authors can cite a normative rule when writing a detection, without
re-fetching a live site during development or review.

| File | Upstream source | Captured |
|------|-----------------|----------|
| [agent-skills-specification.md](agent-skills-specification.md) | <https://agentskills.io/specification> | 2026-08-01 |
| [langchain4j-skills.md](langchain4j-skills.md) | <https://docs.langchain4j.dev/tutorials/skills/> | 2026-08-01 |
| [langchain-deepagents-skills.md](langchain-deepagents-skills.md) | <https://docs.langchain.com/oss/python/deepagents/skills> | 2026-08-01 |
| [deepagents-js-skills.md](deepagents-js-skills.md) | <https://docs.langchain.com/oss/javascript/deepagents/skills> | 2026-08-13 |

## Why these four

The Agent Skills specification is the **shared normative anchor**. LangChain4j Skills and
both LangChain Deep Agents distributions state explicitly that their skills follow it, and
all three consume the same `SKILL.md` layout SkillSpector already scans. The
framework-specific files cover only what the specification does not: the host-side wiring
(Java classes, Python `create_deep_agent` arguments, JavaScript `createDeepAgent` options)
where the security-relevant configuration lives.

**Two of the four capture the same framework in two languages, and that is deliberate.** The
PyPI distribution `deepagents` and the npm distribution `deepagents` are published from
different repositories on different release clocks, and their host APIs differ in shape even
where they agree in meaning. One merged capture would have to pick a spelling for every
difference, and every pick would be wrong on one side. So each language gets its own capture,
its own measured version range and its own inventory module — and where a page's *prose*
borrows the other language's spellings, the annotation rule below applies.

**A framework earns a capture here by publishing host-side skill-loading documentation that
names the Agent Skills specification and consumes the same `SKILL.md` layout.** That is the
admission rule; a framework that merely has "skills" in some other sense does not qualify.

## Conventions

- Each file records its source URL and capture date in a front-matter block.
- Content is a faithful capture of the upstream normative material, reorganized for
  reference use. Code samples are reproduced as published.
- A **"Relevance to SkillSpector"** section at the end of each file maps upstream rules
  to concrete detection opportunities. That section is SkillSpector's own analysis, not
  upstream content.
- An optional **`Verified:`** line in the front-matter block records a date on which the
  capture was re-checked against upstream and found still accurate. It is deliberately
  distinct from `Captured:`, which changes only on an actual re-capture — a `Verified:`
  date means the content was confirmed unchanged, not refreshed. Bumping `Captured:`
  without re-capturing would misreport when this text was taken.
- **A `Verified:` line must state what was checked.** Re-verification is nearly always
  partial — a heading comparison, one field, a single disputed sentence — and a bare
  "verified" reads as a full re-audit nobody performed. Name the scope and the limit, so a
  later reader can tell what still rests on the original capture. These files are cited as
  primary sources when analyzers are written; an overstated line here is exactly the drift
  this directory exists to prevent.

## Upstream cross-citations are claims, not facts

These files quote Frameworks that cite *each other* — most often the Agent Skills
specification, which both LangChain4j and Deep Agents name as the convention they follow.
Such a citation is upstream's assertion and can be wrong. Before relying on one, check it
against the cited capture. When it does not hold, annotate the citing file rather than
silently rewriting upstream's words, so the capture stays faithful and the correction stays
visible.

One such citation has been checked and does not hold; the finding is recorded once, in
[langchain4j-skills.md § The two "integration approaches" are not specification vocabulary](langchain4j-skills.md#the-two-integration-approaches-are-not-specification-vocabulary).

**The same treatment applies to a page that disagrees with *itself*.**
[deepagents-js-skills.md](deepagents-js-skills.md) is a JavaScript page whose prose repeatedly
uses the Python distribution's spellings — `create_deep_agent`, `interrupt_on`, `root_dir`, a
Python dict with a capital `True`, a `list[str]` type annotation — while its code blocks are
correct JavaScript throughout. The capture reproduces both and annotates the conflict in a
section of its own; **the code blocks are the ones SkillSpector's spellings were read from.**
Correcting the prose in place would have hidden that upstream ships it that way, which is
exactly what a later reader needs to know.

**The rule settles a disagreement; it is not a licence to read a code block as an
enumeration.** That capture's annotation once filed `edit_file` as a prose-only spelling and
left it out of the JavaScript inventory on this rule. Both halves were wrong. The page's one
`interruptOn` example gates three tools, which is *an* example of a gate rather than a list of
what may be gated, so nothing disagreed with anything; and `edit_file` is snake_case in both
distributions, so it is a JavaScript tool name in JavaScript prose rather than a Python
spelling leak like `interrupt_on`. Sweeping the published npm tarballs — which is what settles
a spelling here, not a page — found it in every release of the measured range. Before deciding
a spelling is absent, check that the code block really *contradicts* the prose, and check the
artifacts.

## Refreshing

Upstream docs move. Re-capture with:

```bash
# Mintlify-backed sites (agentskills.io, docs.langchain.com) serve raw markdown
curl -sSL https://agentskills.io/specification.md
curl -sSL https://docs.langchain.com/oss/python/deepagents/skills.md
curl -sSL https://docs.langchain.com/oss/javascript/deepagents/skills.md

# Docusaurus (docs.langchain4j.dev) serves HTML only
curl -sSL https://docs.langchain4j.dev/tutorials/skills/ | lynx -dump -nolist -stdin
```

Update the capture date in the file's front-matter block and in the table above. Drop any
stale `Verified:` line at the same time — it describes the text being replaced.
LangChain4j's Skills API is marked experimental upstream — expect it to drift.

**A re-capture overwrites annotations. Re-apply them.** These commands emit upstream
content only, so they discard the "Relevance to SkillSpector" section and every editorial
marker attached to the body — today that means the `[^approach]` footnote markers in
`langchain4j-skills.md` and their definition. Diff the fresh capture against the committed
file rather than replacing it wholesale, and carry the annotations across. An annotation
silently lost in a refresh restores the very citation it was written to correct.
