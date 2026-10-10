---
paths:
  - "src/skillspector/deepagents/**"
  - "src/skillspector/deepagents_js/**"
  - "src/skillspector/langchain4j/**"
  - "src/skillspector/framework.py"
  - "src/skillspector/nodes/analyzers/framework_*.py"
  - "tests/unit/test_*vocabulary*.py"
---

# Framework Analyzers: vocabulary guards, parsers, detection

Traps met while building the three Framework Analyzers. Re-measuring a vocabulary's version range: `docs/VOCABULARY_REMEASUREMENT.md`.

- Guarding literals: match spellings exactly — containment hits Finding-message prose.
- Vocabulary guard: exempt a homonym spelling by call site, never globally.
- A new `deepagents/` module must join the vocabulary guard's explicit module list.
- A new vocabulary spelling also needs its guard test's `_EXPECTED_SPELLINGS` set.
- A non-spelling vocabulary constant needs the guard's `_NOT_A_SPELLING` set.
- A new framework package must be excluded from every *other* vocabulary guard's sweep.
- Renaming a vocabulary constant: fix both `contrib/vocabulary_sweep/roles.py` maps. `contrib/vocabulary_sweep/tests/test_readers.py` covers them, but `make test` never runs it.
- Upstream can turn an inventoried spelling into a homonym; extend both guards' `_HOMONYMS`.
- Analyzer modules importing a parser must import it lazily; a guard checks `sys.modules`.
- `sole_argument` returns `None` for zero *and* multi-argument calls alike.
- `tree-sitter-typescript` ships two grammars; `.tsx` needs `language_tsx()`.
- tree-sitter reports `comment` as a named child; skip it before indexing children.
- A tree-sitter `export const` hides in `export_statement`; unwrap its `declaration` field.
- tree-sitter puts `await` inside a generic call's `function` field, not outside it.
- Unwrap `as`/`satisfies`/parens/`!`, or a literal reads as unresolved.
- JavaScript has no statement terminator; a regex lead must exclude `\n`, not just `;`.
- Read a `package.json` dependency with `json.loads`; a regex also matches `overrides`.
- Anchor every JS/TS detection signal to line start; strings and comments are scanned too.
- A line-start anchor still fires inside a template literal; its contents are whole lines.
- A `SIGNALS` row is a detection contract; a new framework needs positives and negatives both.
- A superset-satisfied gate: dropping a required tool widens it, never narrows it.
- Reusing a rule id reuses `pattern_defaults` prose; override it per analyzer, not the catalogue.
- A rule id shared across languages does not carry an exact Baseline; the fingerprint is evidence-bound.
- Upstream JS docs leak Python spellings in prose; cite code blocks only.
- Upstream docs can name a method no release ships; sweep the artifacts, not the pages.
- Code-over-prose settles a disagreement; an example is not an enumeration.
