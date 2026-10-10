---
paths:
  - "src/skillspector/nodes/build_context.py"
  - "src/skillspector/nodes/analyzers/mcp_least_privilege.py"
---

# `allowed-tools` scoped syntax — known defect, do not fix in passing

- Scoped tool syntax (`Bash(git:*)`) does not map to a capability: `_map_allowed_tools_to_categories` looks the whole token up in `_TOOL_TO_CAPABILITY`, so it matches nothing. A skill declaring only scoped tools has a declaration and an empty capability set, which drives LP1, LP3 and LP4.
- **Do not change it as part of unrelated work.** Extracting the base tool name changes findings on inputs scanned today, which violates the repo's behavior-preservation constraint. It needs its own decision and changelog entry.
- The separator is no longer a deviation. Both parsers split on whitespace, or on commas when the value contains one, since upstream `1b87593`. Do not "restore" comma-only splitting.
- Background: `docs/MULTI_FRAMEWORK_SKILL_ANALYSIS.md` § Closed deviation.
