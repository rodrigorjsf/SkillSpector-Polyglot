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

"""Reading the host code of a Deep Agents for JavaScript application.

The security-relevant configuration of a Deep Agents Skill lives in the
``createDeepAgent({...})`` call rather than in the Skill directory: which sources
the agent was given, whether it may write to them, whether a human is asked first.
This package is what makes that TypeScript and JavaScript readable to the
``framework_deepagents_js`` Analyzer.

``docs/adr/0009-tree-sitter-for-typescript-parsing.md`` decided the package exists
at all, and why it is a **port rather than a reuse** of
:mod:`skillspector.deepagents`: the two distributions ship on different clocks, so
one upstream rename must not move both Frameworks' Rules at once. The four Rules
themselves are unchanged -- ``DA-UNRESOLVED``, ``DA-SKILL-WRITABLE``,
``DA-SHADOW`` and ``DA-SUBAGENT-SKILLS`` mean here exactly what they mean on the
Python track.

Seven modules, and the resolver is deliberately alone on its side of the line: the
three judging modules read what it produced and it decides nothing about what a
refusal means.

* :mod:`skillspector.deepagents_js.vocabulary` is every upstream spelling this
  package matches on, and nothing else. Parser-free.
* :mod:`skillspector.deepagents_js.parser` is the single place tree-sitter enters.
  It owns the two grammars ``tree-sitter-typescript`` ships and the rule for
  choosing between them.
* :mod:`skillspector.deepagents_js.signals` answers which Components of a Scan the
  Analyzer opens. It is the one Applicability predicate ADR 0006 requires.
  Parser-free.
* :mod:`skillspector.deepagents_js.host_config` reads ``createDeepAgent({...})``
  and resolves a literal and a same-module constant, and says so rather than
  guessing when it cannot.
* :mod:`skillspector.deepagents_js.writability` decides, per resolved Skill source
  path, whether anything denies the agent write access to it -- walking the
  permission rules in the order they were written, because that order is semantics
  upstream.
* :mod:`skillspector.deepagents_js.skill_sources` maps each configured Skill
  source path onto the Components of this Scan -- through the backend root -- and
  confirms a name collision across two of them.
* :mod:`skillspector.deepagents_js.subagents` says which of a call's custom
  subagents were defined without Skills of their own.

**Import ordering matters here, and it does not on the Python track.** The Deep
Agents Python package reaches for ``ast`` from the standard library, so nothing it
imports can be missing from an installation. This one reaches for
``tree-sitter-typescript``, exactly as :mod:`skillspector.langchain4j` reaches for
``tree-sitter-java`` -- so :mod:`skillspector.deepagents_js.parser` is the only
module that imports it, and the Analyzer stays parser-free until its gate opens.
"""
