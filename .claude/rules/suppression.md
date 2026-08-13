---
paths:
  - "src/skillspector/suppression.py"
---

# Baseline suppression

Suppressed findings are dropped from the risk score **and** from the SARIF results
(`partition_findings`). A matching bug here silently hides real vulnerabilities — treat every change
as security-relevant, not as reporting cosmetics.

- **A v2 fingerprint depends only on the evidence — what was found and where.** The enforceable
  form of that: **no analyzer may encode run configuration into a `Finding`.** A baseline is
  committed and shared, so a fingerprint that moved with the invocation would suppress a finding
  under one command line and not another, silently — and every field of a `Finding` is in the
  payload. `confidence` **and** `tags` are both hashed, so relocating such a signal onto another
  `Finding` field moves the collision instead of fixing it — carry it in graph state, the way
  `unscored_rule_ids` carries `--spec-checks`. This rule exists because `--spec-checks advisory`
  was designed to encode itself as `confidence = 0.0`, which would have made an `advisory` baseline
  suppress nothing in `strict`; that design was rejected before release.
- **Two open violations are known, and neither is an analyzer's. Do not write "the only one".**
  Both are inherited, both predate the rule above, and the count is a measurement — say "one known
  violation" only after re-measuring.
  - **`--no-llm`**, which is `meta_analyzer`'s. The meta stage rewrites `confidence`, `message`,
    `remediation`, `explanation` and `tags` — every one hashed — so a baseline binds to the side of
    the flag it was generated on. Tracked as `#124`. Do not "fix" it by dropping those fields from
    the payload: that re-fingerprints every committed v2 baseline. `_SPEC_RULE_IDS` in
    `meta_analyzer.py` is why the conformance catalogue does not acquire it.
    **Same side is necessary, not sufficient — never write it as the remedy.** On the LLM side four
    of those five are model output written verbatim and the fifth turns on whether the model
    confirmed the finding; `llm_utils.get_chat_model` pins no temperature and no seed, and which
    model answers is itself run configuration (`SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL`,
    `SKILLSPECTOR_MODEL_<SLOT>`). Two identical invocations may fingerprint one defect two ways.
    A baseline that has to keep matching is a `--no-llm` baseline; an LLM-side one is best-effort.
  - **The scan root**, which moves the hashed `component.path`. `skillspector baseline` has no
    repo-scan mode, so it scans a repository root as one skill and writes `skills/My_Skill/SKILL.md`,
    while `scan --repo-scan` invokes the graph once per discovered skill directory and writes
    `SKILL.md`. Measured: `baseline . --no-llm` suppresses **nothing** under
    `scan . --repo-scan --no-llm --baseline`; the same findings baselined per-skill suppress all
    three, and two per-skill documents concatenated suppress both skills. So `--repo-scan --baseline`
    works — what is missing is a command that emits the combined document.
- `_match_glob` is `fnmatch`, not substring. `message: "hardcoded"` does **not** match
  `"found hardcoded secret"` — a rule needs `*hardcoded*`. Matching is case-insensitive, and `**` is
  rewritten to `*`, so there is no recursive-glob semantics despite the syntax suggesting it.
- A `message` rule is tested against three fields — `finding.message`, `finding.finding`,
  `finding.matched_text`. Matching any one of them suppresses.
- `SuppressionRule.matches` returns False when `rule_id`, `path` and `message` are all unset. That
  guard is what stops an empty rule from suppressing everything; `baseline_from_dict` rejects the
  same shape at load time. Keep both.
- v1 fingerprints are rejected outright — they did not bind to finding evidence. Only a v1
  *rule-only* baseline still loads, with a warning.
- v2 fingerprints suppress only when `baseline.scanner_version` equals the running
  `scanner_version`. A mismatch logs a warning and skips them — it is **not** an error. Bumping the
  scanner version therefore disables every fingerprint suppression silently.
- `_match_glob` has no direct test coverage. `tests/unit/test_suppression.py` exercises the layers
  above it, so a change to its semantics can pass the suite — add a direct test when you touch it.
- Prose reference for baseline authors: `docs/SUPPRESSION.md`.
