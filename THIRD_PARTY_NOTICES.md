# Third-Party Software Notices

SkillSpector includes or depends on the following third-party open-source
software. Each component is listed with its license type, copyright notice,
and project URL.

## Runtime Dependencies

### typer

- **License:** MIT
- **Copyright:** Copyright (c) 2019 Sebastian Ramirez
- **URL:** https://github.com/fastapi/typer

### rich

- **License:** MIT
- **Copyright:** Copyright (c) 2020 Will McGugan
- **URL:** https://github.com/Textualize/rich

### httpx

- **License:** BSD-3-Clause
- **Copyright:** Copyright (c) 2019 Encode OSS Ltd
- **URL:** https://github.com/encode/httpx

### packaging

- **License:** Apache-2.0 OR BSD-2-Clause — offered under either, and taken here
  under Apache-2.0, whose text is already reproduced below
- **Copyright:** Copyright (c) Donald Stufft and individual contributors
- **URL:** https://github.com/pypa/packaging

### PyYAML

- **License:** MIT
- **Copyright:** Copyright (c) 2017-2021 Ingy dot Net; Copyright (c) 2006-2016 Kirill Simonov
- **URL:** https://github.com/yaml/pyyaml

### pydantic

- **License:** MIT
- **Copyright:** Copyright (c) 2017 to present Pydantic Services Inc. and individual contributors
- **URL:** https://github.com/pydantic/pydantic

### openai

- **License:** Apache-2.0
- **Copyright:** Copyright (c) OpenAI
- **URL:** https://github.com/openai/openai-python

### langgraph

- **License:** MIT
- **Copyright:** Copyright (c) 2024 LangChain, Inc.
- **URL:** https://github.com/langchain-ai/langgraph

### langchain-anthropic

- **License:** MIT
- **Copyright:** Copyright (c) 2023 LangChain, Inc.
- **URL:** https://github.com/langchain-ai/langchain

### langchain-aws

- **License:** MIT
- **Copyright:** Copyright (c) 2024 LangChain, Inc.
- **URL:** https://github.com/langchain-ai/langchain-aws

### langchain-core

- **License:** MIT
- **Copyright:** Copyright (c) LangChain, Inc.
- **URL:** https://github.com/langchain-ai/langchain

### langchain-openai

- **License:** MIT
- **Copyright:** Copyright (c) LangChain, Inc.
- **URL:** https://github.com/langchain-ai/langchain

### boto3

- **License:** Apache-2.0
- **Copyright:** Copyright 2013-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **URL:** https://github.com/boto/boto3

### langsmith

- **License:** MIT
- **Copyright:** Copyright (c) 2023 LangChain
- **URL:** https://github.com/langchain-ai/langsmith-sdk

### tree-sitter

- **License:** MIT
- **Copyright:** Copyright (c) 2019 Max Brunsfeld, GitHub
- **URL:** https://github.com/tree-sitter/py-tree-sitter

### tree-sitter-java

- **License:** MIT
- **Copyright:** Copyright (c) 2017 Ayman Nadeem
- **URL:** https://github.com/tree-sitter/tree-sitter-java

### tree-sitter-typescript

- **License:** MIT
- **Copyright:** Copyright (c) 2017 Max Brunsfeld
- **URL:** https://github.com/tree-sitter/tree-sitter-typescript

### yara-python

- **License:** Apache-2.0
- **Copyright:** Copyright (c) 2007-2022 The YARA Authors
- **URL:** https://github.com/VirusTotal/yara-python

### google-auth

- **License:** Apache-2.0
- **Copyright:** Copyright 2014 Google Inc.
- **URL:** https://github.com/googleapis/google-auth-library-python

### pywhatwgurl

- **License:** MIT
- **Copyright:** Copyright (c) 2026 pywhatwgurl contributors
- **URL:** https://github.com/pywhatwgurl/pywhatwgurl

### regex

- **License:** Apache-2.0 AND CNRI-Python — the Apache-2.0 text is reproduced
  below. The distribution's `LICENSE.txt` names "CNRI's Python 1.6 license" for
  the portion derived from the `re` module of CPython 2.6 and 3.1 without
  reproducing its text, so it is reproduced below from SPDX
- **Copyright:** copyright (c) 1998-2001 by Secret Labs AB — the only copyright
  line `LICENSE.txt` carries; it licenses "all additions and alterations" under
  Apache-2.0 without naming a holder for them
- **URL:** https://github.com/mrabarnett/mrab-regex

## Optional Dependencies (mcp extra)

Installed when a consumer asks for the `mcp` extra — `pip install
skillspector[mcp]`, and the `dev` extra pulls it in as well — and redistributed
on the same footing as the runtime dependencies above once they do. The `dev`
and `langgraph-dev` extras are deliberately absent from these notices: they
declare tooling for working *on* this project rather than capability a consumer
installs to *use* the distribution, so listing them would overstate what the
distribution contains. `langgraph-dev` supplies `langgraph-cli[inmem]`, the
LangGraph dev server behind `make langgraph-dev`; nothing under `src/` imports
it, and the Makefile that invokes it is not part of the distribution. It was a
runtime dependency, and disclosed here as one, until upstream's `550b9f0` made
it optional precisely so an ordinary install stops carrying it.

Like the section above, this lists the **directly declared** dependencies only —
the names this distribution itself declares. What each of them in turn pulls in
is chosen by the installer, varies with resolver, lockfile and platform, and is
disclosed by that dependency's own notices rather than restated here. Where an
extra composes another by naming this distribution back — `skillspector[mcp]`,
which is how `dev` obtains it — that self-reference is not a third party and is
listed nowhere: the extra it names is disclosed by its own section above.

### mcp

- **License:** MIT
- **Copyright:** Copyright (c) 2024 Anthropic, PBC
- **URL:** https://github.com/modelcontextprotocol/python-sdk

---

## License Texts

### MIT License

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### BSD 3-Clause License

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Apache License 2.0

The full Apache License 2.0 text is distributed in the [LICENSE](LICENSE) file
at the root of this repository.

### CNRI Python License

SPDX identifier `CNRI-Python`. Reproduced for `regex`, whose `LICENSE.txt` names this license for
the portion derived from CPython's `re` module without carrying its text. The text is SPDX's,
unwrapped as published.

```
CNRI OPEN SOURCE LICENSE AGREEMENT

IMPORTANT: PLEASE READ THE FOLLOWING AGREEMENT CAREFULLY.

BY CLICKING ON "ACCEPT" WHERE INDICATED BELOW, OR BY COPYING, INSTALLING OR OTHERWISE USING PYTHON 1.6, beta 1 SOFTWARE, YOU ARE DEEMED TO HAVE AGREED TO THE TERMS AND CONDITIONS OF THIS LICENSE AGREEMENT.

1. This LICENSE AGREEMENT is between the Corporation for National Research Initiatives, having an office at 1895 Preston White Drive, Reston, VA 20191 ("CNRI"), and the Individual or Organization ("Licensee") accessing and otherwise using Python 1.6, beta 1 software in source or binary form and its associated documentation, as released at the www.python.org Internet site on August 4, 2000 ("Python 1.6b1").

2. Subject to the terms and conditions of this License Agreement, CNRI hereby grants Licensee a non-exclusive, royalty-free, world-wide license to reproduce, analyze, test, perform and/or display publicly, prepare derivative works, distribute, and otherwise use Python 1.6b1 alone or in any derivative version, provided, however, that CNRIs License Agreement is retained in Python 1.6b1, alone or in any derivative version prepared by Licensee.

Alternately, in lieu of CNRIs License Agreement, Licensee may substitute the following text (omitting the quotes): "Python 1.6, beta 1, is made available subject to the terms and conditions in CNRIs License Agreement. This Agreement may be located on the Internet using the following unique, persistent identifier (known as a handle): 1895.22/1011. This Agreement may also be obtained from a proxy server on the Internet using the URL:http://hdl.handle.net/1895.22/1011".

3. In the event Licensee prepares a derivative work that is based on or incorporates Python 1.6b1 or any part thereof, and wants to make the derivative work available to the public as provided herein, then Licensee hereby agrees to indicate in any such work the nature of the modifications made to Python 1.6b1.

4. CNRI is making Python 1.6b1 available to Licensee on an "AS IS" basis. CNRI MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED. BY WAY OF EXAMPLE, BUT NOT LIMITATION, CNRI MAKES NO AND DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON 1.6b1 WILL NOT INFRINGE ANY THIRD PARTY RIGHTS.

5. CNRI SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF THE SOFTWARE FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS A RESULT OF USING, MODIFYING OR DISTRIBUTING PYTHON 1.6b1, OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.

6. This License Agreement will automatically terminate upon a material breach of its terms and conditions.

7. This License Agreement shall be governed by and interpreted in all respects by the law of the State of Virginia, excluding conflict of law provisions. Nothing in this License Agreement shall be deemed to create any relationship of agency, partnership, or joint venture between CNRI and Licensee. This License Agreement does not grant permission to use CNRI trademarks or trade name in a trademark sense to endorse or promote products or services of Licensee, or any third party.

8. By clicking on the "ACCEPT" button where indicated, or by copying, installing or otherwise using Python 1.6b1, Licensee agrees to be bound by the terms and conditions of this License Agreement.

ACCEPT
```
