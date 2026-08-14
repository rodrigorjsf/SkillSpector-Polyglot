# OWASP Agentic Skills Top 10 (AST10) coverage matrix

Mapped against: OWASP Agentic Skills Top 10, version 1.0-2026, public review v1, [repo commit `0e5a4c0601e41f1f6eda14da1017034c0bd9cbfb`](https://github.com/OWASP/www-project-agentic-skills-top-10/tree/0e5a4c0601e41f1f6eda14da1017034c0bd9cbfb)
Retrieved: 2026-07-19
Status: Informational, documentation only

> Addresses https://github.com/NVIDIA/SkillSpector/issues/221.

## Provenance of this page, and what the fork holds

**Upstream withdrew this page; this fork holds it.** `NVIDIA/SkillSpector` deleted
`docs/OWASP-AST10-COVERAGE.md` in its entirety on 2026-08-03 (`c54967a`, a pure revert of
`5b07626`), and said on both `NVIDIA/SkillSpector#288` and `#338` that it would
"bring updated wording next week with product team approval". So every line below that is not
marked as this fork's is upstream text **withdrawn pending a reword that has not landed yet**.
It is kept because this fork's own crosswalk lives here and nowhere else, and because
[README § Contributing](../README.md#contributing-and-keeping-these-docs-true) names this page as
where every detection rule is recorded.

Measured against `5b07626` — the last revision upstream published — this fork's additions are the
two places listed below, and nothing else. Re-measure rather than trust this list:
`git diff 5b07626 HEAD -- docs/OWASP-AST10-COVERAGE.md`.

- **Five matrix rows extended in place**, each keeping upstream's original rule list and rationale
  and appending to it: `AST02` (`DA-SHADOW`), `AST03` (`L4J-MCP-FILTER`, `DA-SKILL-WRITABLE`),
  `AST04` (`L4J-TOOL-DESC`), `AST06` (`L4J-SHELL`, `L4J-WORKDIR`), `AST08` (`L4J-UNRESOLVED`,
  `DA-UNRESOLVED`). Rows `AST01`, `AST05`, `AST07`, `AST09` and `AST10` are untouched upstream text.
- **Two bullets under "Coverage gaps and unknowns"** — the `DA-SUBAGENT-SKILLS` bullet and the
  five-`MCP-*`-checks bullet.

Those two bullets are **absence records**: each states that a rule maps to *no* row in the matrix,
and why. That is a claim about upstream's row set, not just about the fork's rules. When upstream
republishes, the five row extensions can be re-applied mechanically, but the two absence records
must be **re-validated against the new row set** before being re-applied — a reworded matrix may
give one of them a row, which would make the bullet wrong rather than merely stale.

Also fork-authored: this section. Whoever runs the next `/upstream-sync` should not have to read
`c54967a` to know any of the above.

Whether the fork's rows are then merged onto upstream's republished text or moved to a fork-owned
page of their own is a decision deliberately left open until that text exists and its row set is
known. It is tracked as
[issue #111](https://github.com/rodrigorjsf/SkillSpector-Polyglot/issues/111).

## Scope

This page is a revision-pinned crosswalk between SkillSpector's current rule catalog and one concrete OWASP AST10 revision. It helps readers reason about where current SkillSpector rules align with AST10 categories, where the alignment is partial, and where the repo has a documented gap.

It is an informational crosswalk, not an assurance claim, regulatory attestation, or exhaustive assessment. AST10 is still evolving, and SkillSpector's own rule set will continue to change.

## Terminology note

OWASP uses `AST10` to name the Agentic Skills Top 10 project. SkillSpector also uses `AST1` through `AST9` as internal rule ids for the Behavioral AST analyzer family. Those names are unrelated. In this page, `AST01` through `AST10` refer to OWASP risk categories, while `AST1` through `AST9` refer to SkillSpector rule ids.

## Method

This matrix is anchored to:

- OWASP AST10 source pages at the pinned commit linked above
- SkillSpector's current rule catalog in [README.md](https://github.com/NVIDIA/SkillSpector/blob/8f534e2951e0b7d0b8fb8e84832cd3605f95c032/README.md#vulnerability-patterns)

Each row asks a narrow question: which current SkillSpector rules are directly relevant to this AST10 risk, and what remains outside the tool's current surface.

Coverage labels are intentionally conservative:

- `Related rules present` means the current rule catalog has direct signals for the risk.
- `Partially addressed` means the current rule catalog exposes some symptoms or related mechanisms, but not the whole risk surface.
- `Not currently addressed` means the current rule catalog does not directly model the category.

## Matrix

| Category | Related SkillSpector rules | Coverage level | Rationale |
|---|---|---|---|
| AST01 Malicious Skills | `P1`-`P5`, `AR1`-`AR3`, `E1`-`E4`, `PE3`, `SC2`, `SC3`, `MP1`-`MP3`, `RA1`, `RA2`, `AST1`-`AST9`, `TT3`-`TT5`, `YR1`-`YR4`, `TP1`-`TP3` | Related rules present | Current rules detect malicious instructions, secret theft, persistence, dangerous execution chains, known malware signatures, and poisoned metadata commonly used by malicious skills. |
| AST02 Supply Chain Compromise | `SC1`-`SC6`, `DA-SHADOW` | Related rules present | The supply-chain family covers unpinned dependencies, remote script fetching, obfuscated execution, known vulnerable packages, abandoned packages, and typosquatting. `DA-SHADOW` covers the substitution that needs no package at all: a Deep Agents application layering skill sources loads the last source's skill wherever two declare the same name, so a skill in a per-user directory replaces the vetted one in the shared library and the skill a reviewer approved never runs. It is expressed entirely in host configuration, and no scan of either skill directory on its own can see it. |
| AST03 Over-Privileged Skills | `PE1`-`PE3`, `EA1`-`EA4`, `LP1`-`LP4`, `L4J-MCP-FILTER`, `DA-SKILL-WRITABLE` | Related rules present | Current rules flag excessive permissions, unrestricted tool or resource access, scope creep, and mismatches between declared and observed MCP capabilities. `L4J-MCP-FILTER` covers the case where the over-privilege is delegated: an unfiltered MCP tool provider grants whatever the server offers, which can widen without any change to the scanned application. A provider is unfiltered when it called neither of the setters that narrow the exposed set, `filter` and `filterToolNames`; issue #82 corrected the rule, which until then looked for a setter no release has ever published. `DA-SKILL-WRITABLE` covers the case where it is the framework's own default: a Deep Agents application may write to its skill files unless a permission rule denies the path, so the privilege is granted by the absence of a decision rather than by one — in the Python distribution and, since the JavaScript analyzer shipped, in that one too, under the same rule id because it is the same default. |
| AST04 Insecure Metadata | `P2`, `LP1`-`LP4`, `TP1`-`TP4`, `TR1`-`TR3`, `L4J-TOOL-DESC` | Related rules present | Current rules detect hidden instructions, poisoned MCP metadata, trigger abuse, and permission declaration mismatches that make skill metadata deceptive or unsafe. `L4J-TOOL-DESC` extends that reading to Java annotations, where tool metadata is code and is rarely reviewed as prose. |
| AST05 Untrusted External Instructions | `P1`-`P4`, `SC2`, `TP1`-`TP3`, `TT5` | Partially addressed | Current rules can detect dangerous instructions and remote execution patterns once the content is present in the scan input, but SkillSpector does not inventory or pin every mutable external instruction source by itself. |
| AST06 Weak Isolation | `PE2`, `EA1`, `EA4`, `TM3`, `AST1`, `AST4`, `AST5`, `TT5`, `L4J-SHELL`, `L4J-WORKDIR` | Partially addressed | Current rules highlight behaviors that become more dangerous when a skill runs with weak process, filesystem, shell, or network isolation, but they do not prove the deployed sandbox or runtime boundary. `L4J-SHELL` and `L4J-WORKDIR` are the rules that read a deployment's own isolation choice rather than inferring it: LangChain4j shell mode is documented by upstream as running with no sandboxing, containerization, or privilege restriction, and an unset working directory puts those commands in the application root. The absence of a boundary is stated in the host code rather than assumed. |
| AST07 Update Drift | `SC1`, `SC4`, `SC5` | Partially addressed | Dependency pinning, live vulnerability checks, and abandoned-package detection expose some update-drift risk, but the tool does not track installed package state, rollout history, or patch lag in a live environment. |
| AST08 Poor Scanning | Static patterns, Behavioral AST, taint tracking, YARA, MCP least privilege, MCP tool poisoning, optional LLM semantic pass, `L4J-UNRESOLVED`, `DA-UNRESOLVED` | Partially addressed | SkillSpector exists to improve scanning of agentic-skill specific risks, but it does not execute skills at runtime, fetch every external surface automatically, or settle every evasion path on its own. `L4J-UNRESOLVED` and `DA-UNRESOLVED` are the two rules that report the scanner's own blind spot rather than a property of the skill: when a Java-defined skill's instruction text is assembled at runtime, or a Deep Agents application decides its skill sources, backend or filesystem permissions per request, they say so instead of letting the absence read as a clean result. `DA-UNRESOLVED` is also where the writability verdict lands when it cannot decide, so a path whose backend the scan cannot see into is reported as unexamined rather than as safe. |
| AST09 No Governance | none directly | Not currently addressed | Reports, baselines, and SARIF output can feed governance workflows, but the current rule catalog does not directly model approval workflows, ownership, audit policy, or revocation state. |
| AST10 Cross-Platform Reuse | `LP1`-`LP4`, `TP1`-`TP4`, `TR1`-`TR3`, `PE1`, `EA3` | Partially addressed | Current rules can expose permission drift, metadata deception, trigger mismatch, and scope creep after a cross-platform port, but they do not compare source and target manifests for semantic equivalence. |

## Coverage gaps and unknowns

- AST05 remains partial because SkillSpector scans what it is given; it does not recursively fetch, pin, or monitor every external instruction document that a skill may reference.
- AST06 remains partial because local code and metadata inspection are not the same thing as proving container, sandbox, namespace, localhost-auth, or egress policy enforcement.
- AST07 remains partial because current rules reason about dependency hygiene and known package risk, not the live patch level or update history of an installed deployment.
- AST08 remains partial because the scanner itself has bounded visibility. It does not provide runtime execution tracing, binary unpacking for every format, or exhaustive coverage of every attacker-controlled external surface.
- AST09 is not currently addressed as a direct rule surface. Governance needs inventories, approval controls, action logging, and revocation workflows that sit outside the current scanner.
- `DA-SUBAGENT-SKILLS` maps to no category above, and that is a decision rather than an omission. It
  is the one rule in the catalog whose claim is correctness rather than security: a Deep Agents
  custom subagent defined without its own `skills` runs without the capability its author believes it
  has, which upstream documents as a bug and not as a risk. This matrix maps rules onto risk
  categories, so a rule whose claim is correctness earns no row; recording the absence here is what
  keeps it visible. Its findings do still carry the `ASI02` tag, because that tag is set once for
  every rule the Deep Agents analyzer emits and is not derived from this matrix; the two are
  independent taxonomies and this page maps only its own.
- The seventeen `SPEC-*` rules of `structure_agent_skills_spec`, reached only through
  `skillspector scan --spec-checks`, map to no category above, and that is a scope decision rather
  than an omission. This matrix crosswalks rules onto *risk* categories; a conformance rule states
  that a declaration disagrees with the Agent Skills specification, which is a different claim.
  Several of them have obvious security-adjacent readings — `SPEC-4` and `SPEC-17` are name
  collisions a substitution attack would exploit, `SPEC-15` sends an agent looking for a file that
  is not there — and mapping them on that basis would overstate what a length or a spelling proves.
  They are documented in
  [README § Specification Conformance](../README.md#specification-conformance-17-rules-opt-in);
  recording the absence here is what keeps the boundary visible. Their findings carry no tag at all,
  for the same reason.
- The five `MCP-*` posture checks of a Registry Scan — `MCP-PACKAGE-VERSION`, `MCP-PACKAGE-SHA256`,
  `MCP-PLAIN-HTTP`, `MCP-OFFICIAL-STATUS` and `MCP-REPOSITORY`, reached only through
  `skillspector scan --mcp-registry` — map to no category above, and that is a scope decision rather
  than an omission. This matrix crosswalks the rule catalog that assesses a **Skill**; those checks
  assess a record an MCP server owner published to the MCP Registry, and never read a skill, a
  component or a line of the server's code. Several of them would look at home under AST02 or AST07
  on subject matter alone, and claiming them there would overstate what the tool proves about any
  scanned skill. They are documented in
  [README § Scanning the MCP Registry](../README.md#scanning-the-mcp-registry);
  recording the absence here is what keeps the boundary visible.
- AST10 remains partial because cross-platform translation can drop or reinterpret security metadata in ways that require source-to-target manifest comparison, not only single-manifest analysis.

## What stays out of scope here

- No rule metadata fields are added.
- No SARIF or JSON taxonomy fields are added.
- No current rule ids or analyzer behaviors change.

Those follow-ups can be revisited after the AST10 taxonomy settles further.

## SkillSpector-specific limits that matter here

This mapping should be read alongside the repo's documented limits:

- SkillSpector is a static and optional LLM-assisted scanner, not a runtime sandbox.
- Coverage depends on the content being present in the scan input.
- The repo's own [trust model and data egress](https://github.com/NVIDIA/SkillSpector/blob/8f534e2951e0b7d0b8fb8e84832cd3605f95c032/README.md#trust-model-and-data-egress) and [limitations](https://github.com/NVIDIA/SkillSpector/blob/8f534e2951e0b7d0b8fb8e84832cd3605f95c032/README.md#limitations) sections still define what the tool can and cannot prove.

## Updating this page

When the OWASP AST10 project publishes a new revision, update this page by:

1. pinning the new revision explicitly
2. rechecking the exact AST01-AST10 names
3. rerunning the mapping against the current SkillSpector rule catalog
4. rewriting any rows whose rationale changed

## References

- OWASP AST10 home page: `index.md` at the pinned commit
- OWASP AST10 visual overview: `top10.md` at the pinned commit
- OWASP AST10 category pages: `ast01.md` through `ast10.md` at the pinned commit
- SkillSpector rule catalog: https://github.com/NVIDIA/SkillSpector/blob/8f534e2951e0b7d0b8fb8e84832cd3605f95c032/README.md#vulnerability-patterns
- Maintainer scope for issue #221: https://github.com/NVIDIA/SkillSpector/issues/221#issuecomment-5008664101
- OWASP project license: https://creativecommons.org/licenses/by-sa/4.0/
