---
name: license-audit
description: "Audit this fork against NVIDIA's Apache-2.0 §4 obligations, and fix the drift it finds."
disable-model-invocation: true
---

# Auditing the inherited Apache-2.0 obligations

This fork is a Derivative Work of NVIDIA/SkillSpector. §4 of Apache-2.0 asks four things of it, and
three of them turn on one question: **who wrote this file?** Get the **attribution** right and §4(b)
and §4(c) follow; get it wrong and the distribution credits upstream for work upstream did not do and
leaves the real authors unnamed.

`.claude/rules/license-compliance.md` states the target. This skill measures the distance to it.

Everything here is measured against `upstream/main`, never assumed. Run `git fetch upstream` first.

## 1. Classify every file

Three buckets, and every source file is in exactly one:

```bash
MB=$(git merge-base upstream/main HEAD)
SCOPE="src tests contrib scripts .github"
git diff --name-only --diff-filter=A $MB HEAD -- $SCOPE | xargs -r grep -l SPDX-FileCopyrightText
git diff --name-only --diff-filter=M $MB HEAD -- $SCOPE | xargs -r grep -l SPDX-FileCopyrightText
```

Anything with a header that appears in neither list is inherited and untouched.

`scripts/` and `.github/` belong in the scope — `scripts/release/` and both workflows under
`.github/workflows/` carry a header, and an audit scoped to `src tests contrib` alone would miss
them. Widen `$SCOPE` rather than dropping it: an unscoped `grep` matches the documentation *about*
headers, `.claude/rules/license-compliance.md` and this file included, and counts prose as source.

The three counts only add up if `$SCOPE` reaches every header in the tree, so prove that before
trusting them:

```bash
comm -23 <(git ls-files | xargs -r grep -l SPDX-FileCopyrightText | sort) \
         <(git ls-files $SCOPE | xargs -r grep -l SPDX-FileCopyrightText | sort)
```

Every line is either a header `$SCOPE` misses — widen it — or prose about headers, which is the only
acceptable residue.

Pin `$MB` explicitly. A file upstream added *after* the merge-base and edited here classifies
differently depending on the ref you diff against, and getting that backwards inverts the fix.

**Done when** every file carrying an `SPDX-FileCopyrightText` line sits in exactly one bucket, and the
three counts add up to `grep -rl SPDX-FileCopyrightText $SCOPE | wc -l`.

## 2. Audit the headers against the buckets

| Bucket | Correct header |
|---|---|
| Inherited, untouched | NVIDIA's line, unchanged |
| Inherited, modified here | NVIDIA's line **and** the fork's, upstream first — §4(c) retains, §4(b) notices |
| Fork-authored | the fork's line **only** |

Check the table by set membership, not by eye. Counts cannot see a misattribution — a file can sit in
the right bucket with the wrong line in it:

```bash
xargs -r grep -l 'SkillSpector-Polyglot contributors' < all.txt | sort > fork.txt
xargs -r grep -l 'NVIDIA CORPORATION'                 < all.txt | sort > nv.txt
comm -12 fork.txt inherited.txt                    # false fork attribution on an untouched file
comm -23 <(cat added.txt mod.txt | sort) fork.txt  # fork-touched file with no §4(b) notice
comm -23 mod.txt nv.txt                            # §4(c) violation: inherited line deleted
comm -12 added.txt nv.txt                          # NVIDIA's line on a "fork-authored" file
```

All four must be empty, and `wc -l fork.txt` must equal `added + modified` while `wc -l nv.txt`
equals `inherited + modified`.

The last row is the one to resolve by hand, because a moved merge-base produces it two ways that want
opposite fixes. After a sync, `$MB` is upstream's tip, so a file **upstream deleted and this fork
kept** shows up as added — it is inherited, NVIDIA's line stays, and stripping it would be the §4(c)
violation the rule forbids. A genuinely fork-authored file with a stale pre-sweep header wants the
opposite. Settle which with `git log upstream/main --diff-filter=D -- <path>` before editing a header.

A modified file with **no comment syntax** — `Makefile`, `pyproject.toml`, `README.md`, anything under
`docs/` — cannot carry a per-file notice at all. §4(b) for those is the Transparency bullet in
`README.md` stating that this fork modifies inherited files. Check that the bullet is still there;
do not invent a per-file mechanism for a file that has nowhere to put one.

Every file keeps `SPDX-License-Identifier: Apache-2.0` and the Apache boilerplate regardless: §4 offers
no option to relicense inherited portions, and the fork is Apache-2.0 too.

A file under `tests/fixtures/` carrying no header is **correct**, not a gap. Fixtures are analyzer
input; a header there is content the Scan reads, and adding one moves that fixture's Behavior
Snapshot. Audit files that carry a header, and leave the ones that deliberately do not.

**Done when** you have a count of files in each bucket whose header is wrong, and the list of them.

## 3. Audit the third-party notices

`THIRD_PARTY_NOTICES.md` is upstream's record of what the distribution pulls in.

**Presence is already enforced, once per section** — `tests/unit/test_third_party_notices.py` fails
when a declaration and its section of the notices disagree in either direction: `project.dependencies`
against `## Runtime Dependencies`, and each redistributed extra of `project.optional-dependencies`
against its `## Optional Dependencies (<extra> extra)` section (`#109`). It reads the redistributed
set out of the notices' headings rather than listing it, so writing a section is what generates its
comparisons. A further test fails when `pyproject.toml` declares an extra that has neither a section
nor a recorded not-redistributed status, when one has *both* — a section contradicts the very record
that says it has none — or when it drops one that has either, so a new extra cannot slip in
undisclosed and a renamed one cannot leave a comparison silently pointed at nothing. A third fails on
a duplicated section heading, which would otherwise hide every entry beneath the second copy from
both directions at once. The `dev` extra is deliberately absent from the notices — it declares
tooling for working on this project rather than capability a consumer installs to use the
distribution — and that decision is recorded in the test's `_NOT_REDISTRIBUTED_EXTRAS` rather than
re-decided per audit. So `make test-unit` answers "is anything missing" and this step does not
re-derive it. Two things it does **not** cover, and this step does:

- **License compatibility.** The test proves that an entry exists, never what it says. For each
  dependency the fork added since the merge-base:

  ```bash
  git diff $MB HEAD -- pyproject.toml | grep '^+' | grep -v '^+++'
  ```

  confirm its stated license is compatible with Apache-2.0 redistribution, reading the license and
  copyright line from the installed `dist-info` rather than recalling either.

- **That the `dist-info` you read is one the distribution permits.** The test compares names, never
  versions. Check the installed `METADATA`'s `Version:` against the specifier `pyproject.toml`
  declares before treating its license file as the source of a §4 fact — see the read-never-recalled
  paragraph of `.claude/rules/license-compliance.md`, and `#113` for enforcing it.

**Done when** the test passes and every fork-added redistributed dependency's license — runtime or
`mcp` extra — is confirmed compatible with Apache-2.0 redistribution, from a `dist-info` whose
version satisfies the declared bound.

## 4. Audit the license itself

- `LICENSE` is byte-identical to upstream's: `git diff $MB HEAD -- LICENSE` is empty.
- **§4(d):** check whether upstream ships a `NOTICE` file —
  `git ls-tree --name-only upstream/main | grep -i notice`. If it does, this fork must carry it. If it
  does not, §4(d) has nothing to propagate; record that you checked rather than that you assumed.

**Done when** both are verified against upstream, not against memory.

## 5. Report, then fix what you may

Report every finding with its measured count and the command that produced it. Then fix — with one
exception.

**The fork's copyright line is the user's decision, and it blocks the header sweep.**
`Copyright (c) 2026 SkillSpector-Polyglot contributors`, a personal name, a legal entity: all are
valid, and an agent picking one puts a name on a legal notice. Ask, and hold the header fix until the
answer comes. Notices and dependency entries do not depend on it and proceed.

When you do sweep headers, sweep by classification rather than by path. A blanket rewrite over `src/`
reaches `tests/fixtures/`, whose files are analyzer *input* — editing a fixture moves its Behavior
Snapshot's `size_bytes` and rewrites snapshots for reasons that have nothing to do with licensing.
Prove the sweep additive the way this repository proves everything else: `make update-snapshots`, then
`git status` showing no snapshot modified. Include `contrib/`, which `make test` never runs.

**Done when** every finding is either fixed on the branch or written down as blocked on a named
decision — and neither state is left implicit.
