---
paths:
  - "src/skillspector/*.py"
  - "src/skillspector/**/*.py"
---

# Analyzer Status

Not every module that emits an Analyzer Status — through `analyzer_status_event` or through
`analyzer_status_for_events`, which wraps it — is an Analyzer node: the ledger itself,
`llm_analyzer_base.py`, `nodes/analyzers/static_runner.py` and `nodes/meta_analyzer.py` emit
statuses too. This rule is scoped to the whole source tree for that reason, matching the scope its
guard test already chose. (Count them with
`grep -rl 'analyzer_status_event\|analyzer_status_for_events' src/skillspector/` rather than reading
a number here — a number in this sentence rotted twice before it was removed.)

- Statuses come from `AnalyzerStatus` in `inspection_ledger.py`, never from a bare string. Import the
  member: `analyzer_status_event` raises on an undeclared spelling, and
  `tests/unit/test_analyzer_status.py` fails a status written inline.
- That guard reads three usage shapes — the `status=` argument, an assignment to a name called
  `status`, and a dict entry keyed `"status"`. Its docstring states what it therefore misses: a
  *valid* spelling reaching the ledger through a differently named variable is a style leak nothing
  catches. Import the member there too.
- An Analyzer that summarizes a list of terminal ledger events does **not** write the cascade
  itself — it calls `analyzer_status_for_events(ANALYZER_ID, events)`, which owns the derivation
  (empty means `not_applicable`, otherwise `failed` beats `degraded` beats `completed`) and builds
  `planned_work` from the same events. `tests/unit/test_analyzer_status_derivation.py` fails a copy,
  by reading `AnalyzerStatus.DEGRADED` outside `inspection_ledger.py` — the one term only this
  derivation names. The other five statuses are unaffected — a gate or an `unavailable` result still
  writes one directly. `degraded` is the exception: it is now reserved to the ledger, so a module
  that wants to report one widens `analyzer_status_for_events` rather than writing it inline.
- `LedgerOutcome` shares the spellings `completed` and `failed`, and `inspection_ledger.py` writes
  the outcome vocabulary as bare strings on purpose. Those are correct code — do not "fix" them to
  enum members.
