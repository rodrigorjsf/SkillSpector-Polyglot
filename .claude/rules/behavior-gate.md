---
paths:
  - "tests/behavior/**"
  - "tests/fixtures/**"
  - "src/skillspector/nodes/analyzers/pattern_defaults.py"
---

# Behavior Snapshot gate and its fixtures

A fixture under `tests/fixtures/` is scanner input, not test code, and every leaf fixture has a committed snapshot. What a green gate does not prove: `tests/behavior/COVERAGE_LIMITS.md`. Snapshots change only through `make update-snapshots`.

- Prove a snapshot change additive with `git status` after `make update-snapshots`.
- New fixtures also need a `DETECTION_FIXTURES` row in `test_framework_detection.py`.
- Fixture comments are scanned; never name the capability a fixture lacks.
- Editing `pattern_defaults` prose rewrites every snapshot carrying that rule.
- Editing a behavior fixture's comments moves its snapshot's `size_bytes`.
- Upstream can add a fixture directory that is not a Skill; `NON_TARGET_DIRS` excludes it.
- A corpus count hides in prose and in arithmetic (`2N+1`) across the docs; write "every committed snapshot", never a number, and grep the phrasing when one changes.
