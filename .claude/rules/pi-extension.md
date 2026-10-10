---
paths:
  - "extensions/*.ts"
  - ".opencode/tools/*.ts"
---

# Pi and OpenCode extensions

Two extensions, one security contract. The helper names below are Pi's; the OpenCode tool under `.opencode/tools/` keeps the same contract under its own names: `redact()` on both streams, `SKILLSPECTOR_BIN` first in binary resolution, `noLlm` defaulting to true.

- Subprocess calls go through `pi.exec(bin, argsArray, {...})` with an argument **array**. Never build a shell string — there is no shell in this path and adding one reintroduces injection.
- Both `stdout` and `stderr` must pass through `redactSecrets()` before being returned to the caller.
- Path-like parameters go through `resolveMaybePath()` (which bypasses on `isLikelyUrl()`), not raw string concatenation.
- `noLlm` defaults to `true`. Keep it that way — flipping the default sends scanned content to a provider without the user asking.
- Binary resolution order is `SKILLSPECTOR_BIN` env → `.venv/bin/skillspector` relative to the package root → bare `skillspector` on `PATH`.
- The `provider` `StringEnum` in `scanSchema` mirrors `SKILLSPECTOR_PROVIDER` values from `src/skillspector/providers/__init__.py` and is **already stale** — it lists `nv_inference` and omits `bedrock`, `claude_cli`, `codex_cli`, `gemini_cli`, `antigravity_cli`. Verify against that file rather than trusting the enum.
