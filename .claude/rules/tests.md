---
paths:
  - "tests/**/*.py"
---

# Test markers

- `pyproject.toml` sets `addopts = "-m 'not integration and not provider'"`, so anything carrying those markers is deselected by default. Run them with `make test-integration` / `make test-provider [openai|anthropic|nv_build|gemini]`.
- `tests/integration/conftest.py` auto-applies `pytest.mark.integration` to every test under that path, which cuts both ways. **Never put a unit test there** — it is marked by location and silently deselected from the default run. **Anywhere else, mark explicitly** — a live-LLM or live-provider test written under `tests/unit/` or `tests/nodes/` runs unmarked in default CI and will call a real provider.
- Use the module-level form for explicit marking: `pytestmark = [pytest.mark.provider]` (see `tests/provider/test_provider_endpoint.py`). Existing examples outside the marker directories: `tests/nodes/analyzers/test_semantic_developer_intent.py`, `tests/test_mcp_tool_poisoning.py`.
- `asyncio_mode = "auto"` — `async def test_*` needs no `@pytest.mark.asyncio`.
- `testpaths = ["tests"]`, so nothing under `contrib/` runs in the default suite.
