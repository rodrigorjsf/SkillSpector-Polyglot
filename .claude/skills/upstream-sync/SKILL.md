---
name: upstream-sync
description: "Measure how far this fork has drifted from NVIDIA/SkillSpector, and merge upstream's new work in."
disable-model-invocation: true
---

# Syncing this fork with NVIDIA/SkillSpector

This fork carries **inherited** code — everything it did not write — and that inheritance goes stale.
Upstream ships fixes to the very analyzers this fork extends. **Drift** is the gap; this skill closes
it.

One fact governs every step. Everywhere else in this repository, a Behavior Snapshot that moves means
you broke something. **An upstream merge is the one case where a snapshot delta is correct** — upstream
changed what a Rule finds, and the fork inherits that change. So the gate stops being a pass/fail and
becomes a ledger: every delta must be **attributable** to a named upstream commit. A delta you cannot
name is the merge going wrong, and it is the only signal that will tell you.

## 1. Measure the drift

```bash
git fetch upstream && git fetch origin
MB=$(git merge-base upstream/main origin/main)
git log --oneline $MB..upstream/main          # what upstream did
git rev-list --count $MB..origin/main         # how far the fork has gone
git diff --name-only $MB upstream/main | sort > /tmp/up.txt
git diff --name-only $MB origin/main | sort > /tmp/fk.txt
comm -12 /tmp/up.txt /tmp/fk.txt              # the conflict surface
```

The **conflict surface** is the third command's output: files both sides changed. It is the whole of
the work — everything else merges itself.

**Done when** you can name every upstream commit and every file on the conflict surface. If
`$MB..upstream/main` is empty, the fork is current: say so and stop.

`.github/workflows/upstream-drift.yml` re-runs this measurement weekly and opens — or edits — one
`Upstream drift:` issue while `$MB..upstream/main` is non-empty, so the sync is triggered by the
backlog rather than by someone noticing. **This section is the authority**: the workflow is a second
spelling of these commands, and if the two ever disagree, the workflow is the bug. It stops here —
steps 2 through 6 are the judgment it exists to hand to a human, not work to automate later.

## 2. Read the commits, not the diff

An upstream commit that changes a Rule's behavior is the reason snapshots will move in step 5, and its
message is the only place that reason is written. Read each one, and note which touch
`nodes/analyzers/`, `build_context.py`, `state.py` or `report.py` — those reach the fork's gate.

**Done when** every upstream commit is labelled either *behavior-affecting* or *not*, with the
behavior-affecting ones matched to the fixtures you expect to move.

## 3. Merge onto a branch of its own

Branch from an up-to-date `main`, named for the sync rather than for a feature, and
`git merge upstream/main`. Let it conflict — resolving is step 4, and a merge you reshaped before
reading the conflicts hides which side changed what.

## 4. Resolve, keeping both intents

Each conflict is upstream's change meeting the fork's. The fork's rules decide the resolution:

- **`README.md`** — above the `# Inherited documentation` marker is the fork's own contract; upstream
  never touches it. Below the marker, take upstream's text and keep the diff **append-only**. The
  `NVIDIA/skillspector` URLs there are provenance, so they survive the merge unchanged.
- **`pyproject.toml`** — take upstream's `version`. The fork does not fork the version number; a fork
  version *below* upstream's is drift, not a decision. Keep the fork's added dependencies.
- **Inherited docs the fork edited** — `docs/DEVELOPMENT.md`. These describe upstream's own behavior,
  so upstream's text wins wherever the two describe the same thing, and the fork's additions sit
  beside it. A coverage claim upstream revised is a fact about the scanner, not an opinion the fork
  gets to keep.
- **Analyzer modules the fork extended** — upstream's fix and the fork's extension are usually
  disjoint hunks. Where they are not, upstream's logic wins and the fork's extension is re-applied on
  top, because the fork's promise is to extend upstream rather than to replace it.
- **`CLAUDE.md`, `docs/adr/`, `.claude/rules/`, `src/skillspector/langchain4j/`,
  `src/skillspector/deepagents/`** — fork-owned. Upstream has no opinion; keep the fork's.
- **A doc upstream withdrew is not the fork's to hold.** Upstream owns the truth about the core;
  this fork adapts its *rules* so they run against the frameworks it implements. Those are different
  things, and a document describing upstream's own scanner is the first kind. When upstream deletes
  such a page, the fork follows rather than adopting it — `docs/OWASP-AST10-COVERAGE.md` was kept
  through the 2.5.3 and 2.9.6 syncs on the reasoning that the fork's crosswalk of its own Rules lived
  in it, and retired in `#111` once that reasoning was put to the maintainer. Holding it made the
  fork the maintainer of upstream text upstream had withdrawn, and made every later sync re-litigate
  a page neither side owned.

  So if upstream republishes the page, it arrives as an ordinary **inherited doc**: take upstream's
  text, and add the fork's `L4J-*`, `DA-*` and `MCP-*` rows on top *at that point*, as the fork's
  clearly-marked adaptation. Do not resurrect the retired file to merge against — recover its
  content from history if it is wanted (`git show <commit>:docs/OWASP-AST10-COVERAGE.md`), never by
  reverting the retirement.

Where upstream deleted something the fork built on, that is a real design question, not a merge
decision — stop and put it to the user with the upstream commit that did it.

**Done when** `git diff --check` is clean, no conflict marker survives anywhere, and you can say for
each resolved file which side's intent you kept and why.

## 5. Turn the gate into a ledger

```bash
make update-snapshots && git status --short
```

Now account for the output. **Every** modified snapshot is matched to the upstream commit that
explains it — a Rule upstream tightened, a pattern it added. Read the actual diff of the snapshot, not
just its filename.

A snapshot that moved with no upstream commit behind it is the merge having gone wrong. So is an
*unchanged* snapshot for a fixture a behavior-affecting upstream commit should have moved — that means
the fix did not survive the resolution.

**Done when** every modified snapshot has a named upstream commit beside it, and every
behavior-affecting commit from step 2 has produced the delta you predicted. Write that mapping down;
it is the PR body.

## 6. Close it out

`make test-unit`, `make lint`, `make format-check`. Upstream ships its own tests — a failure among
them is a resolution defect, not a flaky test.

Then hand off to **`/license-audit`** — it is user-invoked, so ask the user to run it against this
branch before the PR is called ready, and say why. A merge is exactly when license drift enters:
upstream files arrive, files the fork had modified gain upstream hunks, and `pyproject.toml` may gain
a dependency `THIRD_PARTY_NOTICES.md` does not know about.

Open the PR against `main` with the step-5 mapping as its body, and say plainly that snapshots moved
and why — a reviewer who sees a snapshot diff in this repository assumes a regression until told
otherwise. **A human merges it.**

Once it lands, **close the open `Upstream drift:` issue** if `.github/workflows/upstream-drift.yml`
opened one. That workflow only ever opens and edits; it never closes. After the merge the
measurement is zero, so its write step is skipped and the stale issue is never corrected — it would
sit there asserting a drift that this sync just removed. Closing it is also what makes the next
non-zero measurement open a fresh one rather than edit a resolved report.

## 7. The merge must keep the second parent

**Say this in the PR body, because the default button is wrong here.** Everywhere else in this
repository a squash merge is right — Ticket PRs are squashed on purpose, and `CLAUDE.md`'s Applied
Learning says so. A sync PR is the one exception, and squashing it silently undoes the sync.

A squash rewrites the branch as one commit with a single parent, so git keeps the merged *tree* and
loses the record that `upstream/main` was ever merged. The merge-base does not advance, and step 1
then measures the same drift it measured before:

```bash
git log -1 --format='%p' origin/main                     # one SHA = squashed
git rev-list --count $(git merge-base upstream/main origin/main)..upstream/main
```

A non-zero count on a tree that already contains those commits is the signature. The next sync would
re-merge them into a tree that already has them — conflicts on identical content, and a step-5 ledger
with no attributable delta left in it.

**If it has already been squashed**, the repair does not touch a single file:

```bash
git merge -s ours upstream/main          # records the parent, keeps main's tree
```

Verify before pushing: the tree must be byte-identical to the squash commit's
(`git rev-parse <squash>^{tree}` equals `HEAD^{tree}`), the commit must have two parents, and the
count above must be `0`. Landed once already, in `208cfee`, after `#104` was squashed.

File whatever the sync surfaced and could not close as its own issue, per `CLAUDE.md`.
