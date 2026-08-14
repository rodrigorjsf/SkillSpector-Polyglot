# LangChain Deep Agents (JavaScript) — Skills

> **Source:** <https://docs.langchain.com/oss/javascript/deepagents/skills>
> **Captured:** 2026-08-13
>
> **Upstream releases swept:** 2026-08-13 — the spellings this capture documents were read out of
> every published npm `deepagents` tarball at or above the Skills floor upstream states below,
> `1.7.0` through `1.12.3`, 32 final releases. Two arrive inside that window rather than at its
> start — `permissions` at `1.8.0` and `deny` at `1.9.1` — so the practical floor for the whole
> inventory is `1.9.1`, above the `deepagents>=1.7.0` this page quotes. Releases below `1.7.0` were
> deliberately not swept: upstream says Skills do not exist there, so an absence would measure the
> feature rather than a rename. The range is recorded as `OBSERVED_VERSION_RANGE` in
> [`vocabulary.py`](../../src/skillspector/deepagents_js/vocabulary.py); re-measuring it is
> [`docs/VOCABULARY_REMEASUREMENT.md`](../VOCABULARY_REMEASUREMENT.md).
>
> **Scope note:** this is the **JavaScript/TypeScript** Deep Agents distribution, published to npm
> from [`langchain-ai/deepagentsjs`](https://github.com/langchain-ai/deepagentsjs). It is a
> different distribution from the PyPI package of the same name, captured separately in
> [langchain-deepagents-skills.md](langchain-deepagents-skills.md). The two share a name, a concept
> and most of a vocabulary; they do not share a release clock, and this capture exists so the
> JavaScript spellings are read from JavaScript sources.

Skills package domain expertise — workflows, best practices, scripts, reference docs, and
templates — into reusable directories. The agent gets a summary of the contents on startup and
discovers and reads the contained files only when relevant.

> Skills require `deepagents>=1.7.0`.

> Deep agent skills follow the
> [Agent Skills specification](agent-skills-specification.md).

---

## ⚠️ Annotation: this page's prose leaks Python spellings

*This section is SkillSpector's analysis, not upstream content.*

`docs/references/README.md` requires that a capture be faithful and that a defect in it be
**annotated rather than silently corrected**. This page has one, and it is systematic: several
passages of **prose** on the JavaScript page are written with the **Python** distribution's
spellings, while every **code block** on the same page is correct JavaScript. Where the two
disagree, **the code blocks are the source of truth**, and every spelling SkillSpector matches on
was taken from one.

| Written in this page's prose | What its code blocks actually publish |
|---|---|
| `create_deep_agent` (§ *Skills for subagents*) | `createDeepAgent` |
| `interrupt_on` (§ *Skill permissions*, § *Require approval for skill writes*) | `interruptOn` |
| `root_dir` (§ *skills* param, § *Backends*) | `rootDir` |
| `interrupt_on={"write_file": True, "edit_file": True}` — a Python dict, with a capital `True` | `interruptOn: { read_file: true, write_file: true, delete_file: true }` |
| `<ParamField body="skills" type="list[str]">` — a Python type annotation | an array of strings |
| `mode="interrupt"` — Python keyword-argument syntax | `mode: "interrupt"` — an object property |

Three consequences follow, and each is recorded where the code depends on it:

1. **`FilesystemPermission` does not appear on this page at all.** A permission rule in JavaScript
   is a plain object literal, not a class construction. SkillSpector's JavaScript inventory
   therefore has no such spelling, and its resolver reads the object shape.
2. **`routes` is not an option key.** `CompositeBackend` takes its default backend and its route map
   as two positional arguments.
3. **`edit_file` is *not* one of these leaks**, and it is recorded here because an earlier revision
   of SkillSpector filed it as one. Every leak in the table above is a **syntax** leak — camelCase
   written as snake_case, a Python dict, a Python type annotation, keyword-argument syntax.
   `edit_file` is snake_case in *both* distributions, so the sentence *"Both pause before
   `write_file` or `edit_file` runs"* is a statement about JavaScript behaviour in JavaScript tool
   vocabulary, with nothing Python about it. Nor does it contradict a code block: the page's one
   `interruptOn` example gates `read_file`, `write_file` and `delete_file`, which is *an* example of
   a gate, not an enumeration of the tools that may be gated, so the code-over-prose rule has no
   disagreement to settle. The sweep confirms it directly — `edit_file` is present in all 32 npm
   releases of the range recorded above, including the tool factory that creates it. SkillSpector
   therefore inventories both write tools, exactly as the Python track does.

   Deferring to the code block would not have been the cautious reading either. The mitigation check
   asks whether the configuration gates **every** inventoried write tool, so a *smaller* inventory is
   *easier* to satisfy: with `write_file` alone, the block published on this very page read as a
   mitigation in JavaScript and as none in Python — one rule id, two risk statements, which is the
   thing "Relevance to SkillSpector" below says the shared rule ids exist to prevent.

---

## Usage

1. **Create a top-level skills directory**, such as `skills/` under the backend root.

2. **Create a subdirectory per skill.** Each skill is a directory containing a `SKILL.md` file:
   markdown with YAML frontmatter (`name` and `description`) followed by instructions. It may also
   include `scripts/`, `references/` and `assets/`.

   ```
   skills/
   └── langgraph-docs/
       ├── SKILL.md
       ├── scripts/fetch_docs.py
       ├── references/api-patterns.md
       └── assets/report-template.md
   ```

3. **Pass the skill source paths to the agent.**

   ```ts
   import { createDeepAgent, FilesystemBackend } from "deepagents";

   const backend = new FilesystemBackend({ rootDir: process.cwd() });

   const agent = await createDeepAgent({
     model: "google-genai:gemini-3.1-pro-preview",
     backend,
     skills: ["/skills/"],
   });
   ```

### The `skills` option

> List of skill source paths.
>
> Paths must be specified using forward slashes and are relative to the backend's root.
>
> * If omitted, no skills are loaded.
> * When using `StateBackend` (default), provide skill files with `invoke(files={...})`.
> * With `FilesystemBackend`, skills are loaded from disk relative to the backend's `root_dir`.
>
> **Later sources override earlier ones for skills with the same name (last one wins).**
>
> When multiple skill sources contain a skill with the same name, the skill from the source listed
> later in the `skills` array takes precedence (last one wins). This lets you layer skills from
> different origins, such as base skills overridden by project-specific versions.

*(The `root_dir` in the third bullet is one of the prose leaks annotated above; the code blocks on
this page write `rootDir`.)*

---

## Backends and remote skill loading

Deep Agents supports different backends depending on how you want to store and manage skill files:

* `StateBackend`: Stores files in LangGraph agent state for the current thread.
* `StoreBackend`: Stores files in a LangGraph store for durable, cross-thread storage.
* `FilesystemBackend`: Reads and writes skill files from disk under a configurable `root_dir`.
* `CompositeBackend`: Routes path prefixes to other backends.

```ts
import { createDeepAgent, FilesystemBackend } from "deepagents";
import { MemorySaver } from "@langchain/langgraph";

const checkpointer = new MemorySaver();
const backend = new FilesystemBackend({ rootDir: process.cwd() });

const agent = await createDeepAgent({
  model: "google-genai:gemini-3.1-pro-preview",
  backend,
  skills: ["./examples/skills/"],
  interruptOn: {
    read_file: true,
    write_file: true,
    delete_file: true,
  },
  checkpointer, // Required!
});
```

### Namespaced skills

> Route `/skills/` to a `StoreBackend` with a namespace factory. Populate each namespace with only
> the skills that user should have access to, and the middleware resolves to the correct set at
> runtime.

```ts
import {
  createDeepAgent,
  CompositeBackend,
  StateBackend,
  StoreBackend,
} from "deepagents";

const agent = await createDeepAgent({
  model: "anthropic:claude-sonnet-4-6",
  skills: ["/skills/"],
  backend: new CompositeBackend(new StateBackend(), {
    "/skills/": new StoreBackend({
      namespace: (ctx) => [
        ctx.assistantId ?? "default",
        ctx.config?.configurable?.user_id ?? "anonymous",
      ],
    }),
  }),
});
```

**Note the shape**: `CompositeBackend` takes the default backend and the route map as two
**positional** arguments. There is no `routes` option key on this page.

---

## Skills for subagents

> * **General-purpose subagent**: Automatically inherits skills from the main agent when you pass
>   `skills` to `create_deep_agent`. No additional configuration is needed.
> * **Custom subagents**: Do not inherit the main agent's skills. Add a `skills` parameter to each
>   subagent definition with that subagent's skill source paths.
>
> Skill state is fully isolated: the main agent's skills are not visible to subagents, and subagent
> skills are not visible to the main agent.

*(`create_deep_agent` in the first bullet is a prose leak; the code block below writes
`createDeepAgent`.)*

```ts
import { createDeepAgent } from "deepagents";

const researchSubagent = {
  name: "researcher",
  description: "Research assistant with specialized skills",
  systemPrompt: "You are a researcher.",
  tools: [webSearch],
  skills: ["/skills/research/", "/skills/web-search/"], // Subagent-specific skills
};

const agent = await createDeepAgent({
  model: "google_genai:gemini-3.6-flash",
  skills: ["/skills/main/"], // Main agent and GP subagent get these
  subagents: [researchSubagent], // Researcher gets only its own skills
});
```

**Unlike the Python capture, this page does publish a subagent definition's shape** — `name`,
`description`, `systemPrompt`, `tools`, `skills`.

---

## Skill permissions

> Production deployments usually need to control three things: which skills each user can see,
> whether the agent can modify skill files, and whether writes require human approval. You control
> visibility with the `skills` argument and backend routing, access with filesystem permissions, and
> approval with `interrupt_on` or permission rules with `mode="interrupt"`.

*(Both `interrupt_on` and `mode="interrupt"` here are prose leaks; the code blocks write
`interruptOn` and `mode: "interrupt"`.)*

### Enforce read-only skills

> To share skills without letting agents modify them, route `/skills/` to a shared store and deny
> write operations under `/skills/**` with filesystem permissions. The agent can discover and read
> skills; only your application code or an admin workflow updates the store.

```ts
import { InMemoryStore } from "@langchain/langgraph";
import {
  createDeepAgent,
  CompositeBackend,
  StateBackend,
  StoreBackend,
} from "deepagents";

const store = new InMemoryStore();

const agent = createDeepAgent({
  model: "google-genai:gemini-3.6-flash",
  backend: new CompositeBackend(new StateBackend(), {
    "/skills/": new StoreBackend({
      namespace: (rt) => ["curated-skills", rt.context.orgId],
    }),
  }),
  skills: ["/skills/"],
  permissions: [
    {
      operations: ["write"],
      paths: ["/skills/**"],
      mode: "deny",
    },
  ],
  store,
});
```

**Note the shape**: a permission rule is a plain object literal. `FilesystemPermission` does not
appear anywhere on this page.

### Require approval for skill writes

> If agents may write to skill files but you want a human in the loop first, use either
> `interrupt_on` or a permission rule with `mode="interrupt"`. Both pause before `write_file` or
> `edit_file` runs and use the same resume flow.

```ts
import { MemorySaver } from "@langchain/langgraph";
import { createDeepAgent } from "deepagents";

const agent = await createDeepAgent({
  model: "anthropic:claude-sonnet-4-6",
  skills: ["/skills/personal/"],
  permissions: [
    {
      operations: ["write"],
      paths: ["/skills/**"],
      mode: "interrupt",
    },
  ],
  checkpointer: new MemorySaver(), // Required to pause and resume
});
```

> Alternatively, configure `interrupt_on={"write_file": True, "edit_file": True}` to require
> approval for all filesystem writes, not only skills paths.

*(That sentence is the most concentrated prose leak on the page: a Python dict literal, Python
`True`, and the Python spelling of the option, on a JavaScript page. The corresponding code block
above writes `interruptOn: { read_file: true, write_file: true, delete_file: true }`.)*

### Allow agents to edit personal skills

> **By default, agents can write to skill files if the backend permits it and no permission rule
> blocks the path.** To let agents create or refine skills without touching shared libraries:
>
> 1. Route a writable path such as `/skills/personal/` to a user-scoped `StoreBackend`.
> 2. Pass that path (along with any shared paths) in `skills`.
> 3. Do not add a `deny` rule for the writable path. **Place more specific rules before broader deny
>    rules** if you mix shared and personal paths.

---

## Relevance to SkillSpector

*This section is SkillSpector's analysis, not upstream content.*

### What already works unchanged

A Deep Agents for JavaScript skill directory is an Agent Skills directory, byte for byte the same
layout the Python distribution uses. `build_context` already walks it, `_parse_manifest` already
reads the frontmatter, and the base catalog already scans every `SKILL.md`, `scripts/` payload and
reference file inside it. Nothing about the Skill *directory* is new here.

### What is new, and what is not

**The rules are not new. The parser is.** The four questions the Python Deep Agents Analyzer asks —
can the agent rewrite its own Skills, does a later source shadow an earlier one, does a custom
subagent get Skills of its own, and where did resolution stop — are the same questions on this page,
about the same framework, with the same answers. SkillSpector therefore reuses `DA-SKILL-WRITABLE`,
`DA-SHADOW`, `DA-SUBAGENT-SKILLS` and `DA-UNRESOLVED` rather than minting a parallel set: a reviewer
who has accepted "this agent may rewrite its Skills" should not have to accept it twice because the
application is written in TypeScript.

What *is* new is that the configuration lives in TypeScript rather than Python, which needs a
grammar SkillSpector did not carry
([ADR 0009](../adr/0009-tree-sitter-for-typescript-parsing.md)), and four shapes that differ from
the Python API:

| Shape | Python distribution | This distribution |
|---|---|---|
| How settings are passed | keyword arguments | one options object, first positional argument |
| A permission rule | `FilesystemPermission(...)` | a plain object literal |
| A `CompositeBackend` route map | the `routes=` keyword | the second positional argument |
| The tool-level approval gate | `interrupt_on` | `interruptOn` — the same two write tools, so the check is identical |

### Where a scan still stops

`process.cwd()` is not a fact in any scanned file, so upstream's own headline example —
`new FilesystemBackend({ rootDir: process.cwd() })` — reaches the resolution boundary and is
reported as `DA-UNRESOLVED` rather than silently mapped. That is the intended answer: the directory
a process starts in is chosen at deployment, not in the repository.

See [MULTI_FRAMEWORK_SKILL_ANALYSIS.md](../MULTI_FRAMEWORK_SKILL_ANALYSIS.md) for how this is wired
without altering existing scan behavior.
