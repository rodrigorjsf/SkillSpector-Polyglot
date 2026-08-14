# SPDX-FileCopyrightText: Copyright (c) 2026 SkillSpector-Polyglot contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Which Framework a scanned tree is written against.

Issue #21, phase 1. Detection is a pure function over ``components`` and
``file_cache``, so the whole signal matrix is driven in memory -- no directory,
no graph. Only the two seam tests at the bottom touch the disk: they prove
``build_context`` sets the key to what the pure function returned.

Every existing fixture is asserted to detect ``agent_skills``, which is the
evidence behind the phase's behavior-preservation claim. The fixtures listed in
``DETECTION_FIXTURES`` are the deliberate exception.
"""

from __future__ import annotations

import pytest

from skillspector.framework import Framework, detect_framework
from skillspector.nodes.build_context import build_context
from skillspector.state import SkillspectorState
from tests.behavior import projection as proj

# The behavior corpus is the declared list of leaf scan targets, and
# ``test_the_corpus_is_exactly_the_leaf_fixture_directories`` already holds it
# equal to what is on disk. Deriving from it rather than re-walking the tree
# keeps one leaf rule in the suite: a second one could drift silently, dropping
# a fixture from the assertion below without turning anything red.
FIXTURES_DIR = proj.FIXTURES_DIR

# Every fixture whose Framework is not the default, and what it must detect as.
# Three carry a bare detection signal and nothing else; the rest are application
# trees a Framework Analyzer reads -- three LangChain4j, six Deep Agents for
# Python and two Deep Agents for JavaScript. Every fixture outside this mapping
# predates Framework detection and must keep detecting ``agent_skills`` -- a
# fixture arriving here by accident rather than by this edit is the drift the
# assertion below exists to catch.
#
# ``langchain4j_tool_mode`` is the one that proves detection does not rest on the
# shell artifact: its build file declares only ``dev.langchain4j:langchain4j-skills``.
# ``langchain4j_gradle_skill`` is the one that proves detection does not rest on
# Maven: its build file is a ``build.gradle`` and there is no ``pom.xml`` in the
# tree at all.
DETECTION_FIXTURES: dict[str, Framework] = {
    "langchain4j_detection": Framework.LANGCHAIN4J,
    "deepagents_detection": Framework.DEEPAGENTS,
    "deepagents_denied_skills": Framework.DEEPAGENTS,
    "deepagents_layered_skills": Framework.DEEPAGENTS,
    "deepagents_personal_skills": Framework.DEEPAGENTS,
    "deepagents_shadowed_skills": Framework.DEEPAGENTS,
    "deepagents_subagent_skills": Framework.DEEPAGENTS,
    "deepagents_runtime_skills": Framework.DEEPAGENTS,
    "deepagents_js_detection": Framework.DEEPAGENTS_JS,
    "deepagents_js_layered_skills": Framework.DEEPAGENTS_JS,
    "deepagents_js_runtime_skills": Framework.DEEPAGENTS_JS,
    "langchain4j_gradle_skill": Framework.LANGCHAIN4J,
    "langchain4j_shell_skill": Framework.LANGCHAIN4J,
    "langchain4j_tool_mode": Framework.LANGCHAIN4J,
}

# One row per signal, positive and negative: the in-memory ``file_cache`` and
# the Framework a Scan of it must detect. ``components`` is the cache's keys,
# which is what ``build_context`` produces for every readable file.
SIGNALS: tuple[tuple[str, dict[str, str], Framework], ...] = (
    # -- LangChain4j, positive --------------------------------------------- #
    (
        "pom_names_the_coordinate",
        {"pom.xml": "<dependency><groupId>dev.langchain4j</groupId></dependency>"},
        Framework.LANGCHAIN4J,
    ),
    (
        "nested_module_pom",
        {"agent/pom.xml": "<groupId>dev.langchain4j</groupId>"},
        Framework.LANGCHAIN4J,
    ),
    (
        "gradle_groovy_names_the_coordinate",
        {"build.gradle": "implementation 'dev.langchain4j:langchain4j:0.36.0'"},
        Framework.LANGCHAIN4J,
    ),
    (
        "gradle_kotlin_names_the_coordinate",
        {"build.gradle.kts": 'implementation("dev.langchain4j:langchain4j:0.36.0")'},
        Framework.LANGCHAIN4J,
    ),
    (
        "java_imports_the_package",
        {"Agent.java": "package a;\n\nimport dev.langchain4j.service.AiServices;\n"},
        Framework.LANGCHAIN4J,
    ),
    (
        "java_static_import",
        {"Agent.java": "import static dev.langchain4j.internal.Utils.randomUUID;\n"},
        Framework.LANGCHAIN4J,
    ),
    (
        "kotlin_imports_the_package",
        {"Agent.kt": "import dev.langchain4j.service.AiServices\n"},
        Framework.LANGCHAIN4J,
    ),
    (
        "maven_skill_resource_layout",
        {"src/main/resources/skills/review/SKILL.md": "# review\n"},
        Framework.LANGCHAIN4J,
    ),
    # -- LangChain4j, negative --------------------------------------------- #
    (
        "pom_without_the_coordinate",
        {"pom.xml": "<dependency><groupId>org.junit</groupId></dependency>"},
        Framework.AGENT_SKILLS,
    ),
    (
        "gradle_without_the_coordinate",
        {"build.gradle.kts": 'implementation("org.junit.jupiter:junit-jupiter:5.10.0")'},
        Framework.AGENT_SKILLS,
    ),
    (
        "java_without_the_import",
        {"Agent.java": "package a;\n\nimport java.util.List;\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "kotlin_without_the_import",
        {"Agent.kt": "import kotlin.collections.List\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "coordinate_only_in_prose",
        {"README.md": "This Skill is meant for dev.langchain4j users.\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "java_names_the_package_mid_line",
        {"Agent.java": "int n = 1; // see import dev.langchain4j.service.AiServices\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "coordinate_in_an_xml_that_is_not_a_build_file",
        {"logback.xml": "<logger name='dev.langchain4j' level='DEBUG'/>"},
        Framework.AGENT_SKILLS,
    ),
    (
        "skills_directory_outside_the_maven_layout",
        {"skills/review/SKILL.md": "# review\n"},
        Framework.AGENT_SKILLS,
    ),
    # -- Deep Agents, positive --------------------------------------------- #
    (
        "pyproject_names_the_distribution",
        {"pyproject.toml": 'dependencies = ["deepagents>=0.1"]\n'},
        Framework.DEEPAGENTS,
    ),
    (
        "requirements_names_the_distribution",
        {"requirements.txt": "deepagents==0.1.0\n"},
        Framework.DEEPAGENTS,
    ),
    (
        "requirements_variant_names_the_distribution",
        {"requirements-dev.txt": "deepagents\n"},
        Framework.DEEPAGENTS,
    ),
    (
        "python_imports_the_package",
        {"agent.py": "import deepagents\n"},
        Framework.DEEPAGENTS,
    ),
    (
        "python_imports_from_the_package",
        {"agent.py": "from deepagents import create_deep_agent\n"},
        Framework.DEEPAGENTS,
    ),
    (
        "python_calls_the_constructor",
        {"agent.py": "agent = create_deep_agent(tools=[], instructions='')\n"},
        Framework.DEEPAGENTS,
    ),
    # -- Deep Agents, negative --------------------------------------------- #
    (
        "pyproject_without_the_distribution",
        {"pyproject.toml": 'dependencies = ["pydantic"]\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "python_without_the_import",
        {"agent.py": "import os\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "distribution_only_in_prose",
        {"README.md": "Works well with deepagents and create_deep_agent().\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "substring_of_a_longer_distribution",
        {"requirements.txt": "deepagents-contrib==2.0\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "package_named_inside_a_dotted_path",
        {"agent.py": "import vendor.deepagents\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "distribution_in_a_txt_that_is_not_a_requirement_file",
        {"notes.txt": "deepagents\n"},
        Framework.AGENT_SKILLS,
    ),
    # -- Deep Agents for JavaScript, positive ------------------------------- #
    #
    # Every row here is also a gate row. The npm distribution and the PyPI one
    # are spelled ``deepagents`` byte for byte, so what separates these signals
    # from the Python block above is only the file each is written in -- which
    # makes the negatives naming a ``.py``, a ``.md`` and a plain ``.json``
    # below the assertions that the gate exists at all.
    (
        "package_json_names_the_dependency",
        {"package.json": '{"dependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "nested_package_json_names_the_dependency",
        {"apps/agent/package.json": '{"dependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.DEEPAGENTS_JS,
    ),
    # The other three declaration blocks. The signal reads the manifest by name
    # rather than by text, so each block it accepts is pinned rather than
    # assumed -- and the negatives further down pin the keys it does not accept.
    (
        "package_json_names_the_dependency_for_development",
        {"package.json": '{"devDependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "package_json_names_the_dependency_as_a_peer",
        {"package.json": '{"peerDependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "package_json_names_the_dependency_as_optional",
        {"package.json": '{"optionalDependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "typescript_imports_the_package",
        {"src/agent.ts": 'import { createDeepAgent } from "deepagents";\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        # The form the captured reference publishes, and the one a line-bounded
        # pattern misses.
        "typescript_imports_the_package_across_lines",
        {
            "src/agent.ts": 'import {\n  createDeepAgent,\n  FilesystemBackend,\n} from "deepagents";\n'
        },
        Framework.DEEPAGENTS_JS,
    ),
    (
        "typescript_re_exports_the_package",
        {"src/agent.mts": 'export { createDeepAgent } from "deepagents";\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "javascript_requires_the_package",
        {"agent.cjs": 'const { createDeepAgent } = require("deepagents");\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "javascript_requires_the_package_across_lines",
        {"agent.cjs": 'const {\n  createDeepAgent,\n} = require("deepagents");\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "javascript_imports_the_package_dynamically",
        {"agent.mjs": 'const da = await import("deepagents");\n'},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "typescript_calls_the_constructor",
        {"src/agent.ts": "const agent = await createDeepAgent({});\n"},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "tsx_calls_the_constructor",
        {"src/App.tsx": "const agent = await createDeepAgent({});\n"},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "cts_calls_the_constructor",
        {"src/agent.cts": "const agent = await createDeepAgent({});\n"},
        Framework.DEEPAGENTS_JS,
    ),
    (
        "javascript_calls_the_constructor",
        {"agent.js": "const agent = await createDeepAgent({});\n"},
        Framework.DEEPAGENTS_JS,
    ),
    (
        # The form the layered fixture publishes: the declarator carries an
        # ``export``, and the call is what the module's binding is bound to.
        "typescript_exports_the_constructed_agent",
        {"src/agent.ts": "export const agent = await createDeepAgent({\n  skills: [],\n});\n"},
        Framework.DEEPAGENTS_JS,
    ),
    (
        # The form the runtime fixture publishes: the call is the return
        # expression of a factory, indented and preceded by no declarator.
        "typescript_returns_the_constructor",
        {"src/agent.ts": "export function make() {\n  return createDeepAgent({});\n}\n"},
        Framework.DEEPAGENTS_JS,
    ),
    # -- Deep Agents for JavaScript, negative -------------------------------- #
    (
        "package_json_without_the_dependency",
        {"package.json": '{"dependencies": {"zod": "^3.0.0"}}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "package_json_only_describes_the_word",
        {"package.json": '{"description": "an agent built on deepagents"}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "substring_of_a_longer_npm_distribution",
        {"package.json": '{"dependencies": {"deepagents-cli": "^1.0.0"}}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "dependency_in_a_json_that_is_not_a_node_manifest",
        {"tsconfig.json": '{"dependencies": {"deepagents": "^1.7.0"}}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # The gate, from the JavaScript side: the constructor is spelled in a
        # Python file, where no JavaScript signal may read it.
        "javascript_constructor_in_a_python_file",
        {"agent.py": "agent = createDeepAgent({})\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "javascript_constructor_only_in_prose",
        {"README.md": 'Call createDeepAgent({}) after importing from "deepagents".\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "typescript_without_the_import",
        {"src/agent.ts": 'import { z } from "zod";\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "package_named_inside_a_typescript_string",
        {"src/agent.ts": 'const pkg = "deepagents";\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "import_in_a_typescript_comment_tail",
        {"src/agent.ts": '// import { createDeepAgent } from "deepagents";\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # The braced alternative reaches its specifier across a newline, so a
        # block comment that spans the break must still not be a signal.
        "import_spanning_a_block_comment",
        {"src/agent.ts": '/* import { createDeepAgent }\n   from "deepagents" */\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # The lead is line-bounded, and this is the row that pins it. An earlier
        # revision let the lead cross a newline: this `export` then matched
        # forward into the comment on the next line, because a brace-delimited
        # body carries no `;` and automatic semicolon insertion means most
        # JavaScript statements carry none either.
        "comment_after_an_export_line",
        {"web/app.ts": 'export function f() {\n  // ported from "deepagents"\n}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # The same hole reached from a commented-out import rather than a
        # comment tail. The `import_in_a_typescript_comment_tail` row above
        # passed under the old regex only because nothing preceded it.
        "commented_import_preceded_by_an_export",
        {"src/agent.ts": 'export const A = 1\n// import { createDeepAgent } from "deepagents";\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # The same hole reached through the constructor rather than the import.
        # An unanchored call pattern read the name out of this help string, so a
        # Python Deep Agents repository shipping one such file fired two signals
        # and lost every ``DA-*`` Rule. The declarator lead excludes quotes and
        # stops at the newline, so neither line reaches the name.
        "constructor_inside_a_typescript_string",
        {
            "web/help.ts": (
                "export const HELP_TEXT =\n"
                '  "The server builds the agent; the JS SDK equivalent is '
                'createDeepAgent({ ... }).";\n'
            )
        },
        Framework.AGENT_SKILLS,
    ),
    (
        # A JSDoc line opens with ``*``, which starts no statement.
        "constructor_in_a_doc_comment",
        {"src/agent.ts": "/**\n * see createDeepAgent(...)\n */\nexport const X = 1;\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        "constructor_in_a_comment_tail",
        {"src/agent.ts": "// createDeepAgent({}) is the JS entry point\nexport const X = 1;\n"},
        Framework.AGENT_SKILLS,
    ),
    (
        # `"deepagents"` under a key that is not a dependency block. An
        # `overrides` entry pins a version for something else's dependency; it
        # is not this project declaring one, and README's and §3.2's wording is
        # what the signal now implements.
        "package_json_names_the_word_outside_a_dependency_block",
        {"package.json": '{"name": "x", "overrides": {"deepagents": "1.9.1"}}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        "package_json_names_the_word_in_an_arbitrary_object",
        {"package.json": '{"name": "x", "notes": {"deepagents": "we do not use it"}}\n'},
        Framework.AGENT_SKILLS,
    ),
    (
        # A manifest that does not parse states nothing, the same answer a
        # signal file that cannot be read at all gets.
        "package_json_that_does_not_parse",
        {"package.json": '{"dependencies": {"deepagents"\n'},
        Framework.AGENT_SKILLS,
    ),
    # -- Neither ------------------------------------------------------------ #
    ("nothing_at_all", {}, Framework.AGENT_SKILLS),
    (
        "an_ordinary_agent_skill",
        {"SKILL.md": "---\nname: review\ndescription: d\n---\n"},
        Framework.AGENT_SKILLS,
    ),
)

EVERY_SIGNAL = pytest.mark.parametrize(
    ("file_cache", "expected"),
    [(cache, expected) for _name, cache, expected in SIGNALS],
    ids=[name for name, _cache, _expected in SIGNALS],
)


@EVERY_SIGNAL
def test_every_signal_detects_its_framework(
    file_cache: dict[str, str], expected: Framework
) -> None:
    """One row per signal: each positive fires, each negative does not."""
    assert detect_framework(sorted(file_cache), file_cache) == expected


def test_both_frameworks_signalled_is_doubt_and_resolves_to_agent_skills() -> None:
    """A polyglot tree detects neither Framework -- §3.2's conservative rule.

    The consequence is stated in ``skillspector.framework``: such a tree loses
    Framework analysis, and loses it silently. Nothing reads the key yet.
    """
    file_cache = {
        "pom.xml": "<groupId>dev.langchain4j</groupId>",
        "pyproject.toml": 'dependencies = ["deepagents"]\n',
    }

    assert detect_framework(sorted(file_cache), file_cache) == Framework.AGENT_SKILLS


def test_the_ambiguous_case_is_not_vacuous() -> None:
    """Each half of the ambiguous tree detects its own Framework alone.

    Without this control the test above would pass on a pure function that
    simply never fires.
    """
    pom = {"pom.xml": "<groupId>dev.langchain4j</groupId>"}
    pyproject = {"pyproject.toml": 'dependencies = ["deepagents"]\n'}
    agent_ts = {"src/agent.ts": "const agent = await createDeepAgent({});\n"}

    assert detect_framework(sorted(pom), pom) == Framework.LANGCHAIN4J
    assert detect_framework(sorted(pyproject), pyproject) == Framework.DEEPAGENTS
    assert detect_framework(sorted(agent_ts), agent_ts) == Framework.DEEPAGENTS_JS


def test_both_deep_agents_distributions_resolve_to_agent_skills() -> None:
    """A Python agent beside a TypeScript one detects neither Deep Agents Framework.

    This is the ambiguity the JavaScript track made *ordinary* rather than
    exotic: the two distributions are both spelled ``deepagents``, so a monorepo
    shipping one agent in each language is the plain shape of that project
    rather than a polyglot curiosity. The extension gate keeps the two signals
    off each other's files, but it cannot stop a repository from genuinely
    containing both -- and two signals is doubt, which §3.2 resolves to
    ``AGENT_SKILLS``.

    ``skillspector.framework`` states the cost this pins: such a tree loses the
    same four Rules twice over, and loses them in silence, because ADR 0002 has
    the gate decline without a ledger event. The test exists so a later
    precedence rule cannot change that answer without saying so -- it is the one
    regression that leaves no trace in a report.
    """
    file_cache = {
        "pyproject.toml": 'dependencies = ["deepagents"]\n',
        "src/agent.ts": "const agent = await createDeepAgent({});\n",
    }

    assert detect_framework(sorted(file_cache), file_cache) == Framework.AGENT_SKILLS


def test_a_python_deepagents_tree_with_an_unrelated_ts_file_still_detects_deepagents() -> None:
    """A stray TypeScript file that only *mentions* the package must not flip the answer.

    This is the ambiguity above's near neighbour, and the two must not be
    confused: the tree really is a Python Deep Agents repository, and the ``.ts``
    file carries no JavaScript signal at all -- it names the package in a
    comment. An earlier revision of the JavaScript import pattern let its lead
    cross a newline, so the ``export`` opening the function matched forward into
    that comment, the tree fired two signals, and all four ``DA-*`` Rules were
    lost without a ledger row to say so.

    The control is the same tree without the ``.ts`` file, which proves the
    assertion is about the comment rather than about the Python side.
    """
    python_only = {"agent.py": "from deepagents import create_deep_agent\n"}
    with_stray_typescript = python_only | {
        "web/app.ts": 'export function makeAgent() {\n  // ported from "deepagents"\n}\n'
    }

    assert detect_framework(sorted(python_only), python_only) == Framework.DEEPAGENTS
    assert (
        detect_framework(sorted(with_stray_typescript), with_stray_typescript)
        == Framework.DEEPAGENTS
    )


def test_a_python_deepagents_tree_with_a_ts_file_quoting_the_constructor_still_detects() -> None:
    """The same damage through the constructor door, which was left open longer.

    The import lead was bounded to its line, but the constructor was matched
    wherever the name appeared -- so a help string quoting the JavaScript SDK,
    inside a repository that is entirely Python, fired the JavaScript signal.
    Two signals is doubt, the tree detected ``AGENT_SKILLS``, and all four
    ``DA-*`` Rules went silent with no ledger row to say so.

    Three shapes of prose are pinned rather than one, because they fail the
    pattern for three different reasons: a string continuation line opens with a
    quote, a JSDoc line opens with ``*``, and a comment tail opens with ``//``.
    The control is the same tree with a genuine call in the same file, which
    proves the constructor is still a signal rather than quietly deleted.
    """
    python_only = {"agent.py": "from deepagents import create_deep_agent\n"}
    prose = {
        "a_string": (
            'export const HELP_TEXT =\n  "the JS SDK equivalent is createDeepAgent({ ... }).";\n'
        ),
        "a_doc_comment": "/**\n * see createDeepAgent(...)\n */\nexport const X = 1;\n",
        "a_comment_tail": "// createDeepAgent({}) is the JS entry point\nexport const X = 1;\n",
    }

    assert detect_framework(sorted(python_only), python_only) == Framework.DEEPAGENTS
    for shape, source in prose.items():
        tree = python_only | {"web/help.ts": source}
        assert detect_framework(sorted(tree), tree) == Framework.DEEPAGENTS, shape

    genuine = python_only | {"web/help.ts": "const agent = await createDeepAgent({});\n"}
    assert detect_framework(sorted(genuine), genuine) == Framework.AGENT_SKILLS


def test_a_template_literal_quoting_the_constructor_still_fires_the_signal() -> None:
    """The prose shape the anchor does *not* exclude, pinned as the cost it is.

    The three shapes above fail the pattern because each opens its line with
    something no statement opens -- a quote, a ``*``, a ``//``. A backtick string
    opens no line at all: it carries whole lines, so an SDK example embedded in a
    prompt has a line that *is* a line of code and fires the signal. The
    consequence is the one the shapes above were anchored to prevent, arriving
    through the door an anchor cannot close: this Python tree fires two signals
    and detects ``AGENT_SKILLS``.

    This asserts what the code does, not what it should do. Telling a template
    literal from code needs backtick state across the file, which a regular
    expression does not have, and a stray backtick in a comment flipping that
    parity would silence a genuine JavaScript repository instead --
    ``src/skillspector/framework.py`` and §3.2 of the design document both record
    the trade, and issue #127 carries the ways out. The test exists so the cost
    stays measured: a later revision that closes the shape turns this red and has
    to say so deliberately.
    """
    python_only = {"agent.py": "from deepagents import create_deep_agent\n"}
    embedded_example = (
        "const SYSTEM_PROMPT = `\n"
        "You build agents. Example:\n"
        'const agent = await createDeepAgent({ skills: ["/skills/"] });\n'
        "`;\n"
    )

    assert detect_framework(sorted(python_only), python_only) == Framework.DEEPAGENTS
    tree = python_only | {"web/prompt.ts": embedded_example}
    assert detect_framework(sorted(tree), tree) == Framework.AGENT_SKILLS


def test_a_component_missing_from_the_cache_carries_no_signal() -> None:
    """An unreadable signal file cannot detect: there is no content to read.

    ``build_context`` lists a file in ``components`` and omits it from
    ``file_cache`` when the read failed, so the two are not interchangeable.
    """
    assert detect_framework(["pom.xml", "pyproject.toml"], {}) == Framework.AGENT_SKILLS


def test_the_enum_serializes_to_the_specified_wire_values() -> None:
    """§3.1's values are the contract; the enum is only how they are spelled."""
    assert Framework.AGENT_SKILLS == "agent_skills"
    assert Framework.LANGCHAIN4J == "langchain4j"
    assert Framework.DEEPAGENTS == "deepagents"
    assert Framework.DEEPAGENTS_JS == "deepagents_js"
    # Naming three of four members passed while the fourth was unpinned, which is
    # the vacuous shape this repository has been caught by before. The set is
    # asserted whole so a fifth Framework cannot arrive unnamed either.
    assert set(Framework) == {
        Framework.AGENT_SKILLS,
        Framework.LANGCHAIN4J,
        Framework.DEEPAGENTS,
        Framework.DEEPAGENTS_JS,
    }


# --------------------------------------------------------------------------- #
# The seam: build_context sets what the pure function returned
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [name for name in proj.CORPUS_NAMES if name not in DETECTION_FIXTURES],
    ids=lambda name: name,
)
def test_every_pre_existing_fixture_detects_agent_skills(name: str) -> None:
    """The evidence behind the phase's behavior-preservation claim.

    Detection returns the default on every input scanned today, so ``framework``
    is omitted from every pre-existing snapshot and none of them changes.
    """
    state: SkillspectorState = {"skill_path": str(FIXTURES_DIR / name)}

    assert build_context(state)["framework"] == Framework.AGENT_SKILLS


@pytest.mark.parametrize(("name", "expected"), sorted(DETECTION_FIXTURES.items()))
def test_the_detection_fixtures_detect_through_build_context(
    name: str, expected: Framework
) -> None:
    """The node sets the key, and it sets it to what the pure function says."""
    state: SkillspectorState = {"skill_path": str(FIXTURES_DIR / name)}

    result = build_context(state)

    assert result["framework"] == expected
    assert result["framework"] == detect_framework(
        result["components"],  # type: ignore[arg-type]
        result["file_cache"],  # type: ignore[arg-type]
    )
