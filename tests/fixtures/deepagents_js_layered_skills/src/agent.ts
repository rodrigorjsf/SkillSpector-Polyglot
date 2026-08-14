/**
 * Builds the support agent from a shared library and a per-user directory.
 *
 * Both sources sit under the backend root, so both map onto directories in this
 * tree, and the list order settles which one the agent reads for a Skill that
 * appears in each. The rule below names the shared library.
 */

import { createDeepAgent, FilesystemBackend } from "deepagents";

const MODEL = "anthropic:claude-sonnet-4-6";

export const backend = new FilesystemBackend({ rootDir: "./library" });

export const SKILL_SOURCES = ["/skills/shared/", "/skills/personal/"];

const reviewer = {
  name: "reviewer",
  description: "Checks a drafted reply against the shared library.",
  systemPrompt: "You review drafted replies.",
  skills: ["/skills/shared/"],
};

const summarizer = {
  name: "summarizer",
  description: "Condenses a ticket thread into a short summary.",
  systemPrompt: "You summarize ticket threads.",
};

export const agent = await createDeepAgent({
  model: MODEL,
  backend,
  // Source paths are virtual POSIX paths relative to the backend root.
  skills: SKILL_SOURCES,
  permissions: [
    {
      operations: ["write"],
      paths: ["/skills/shared/**"],
      mode: "deny",
    },
  ],
  subagents: [reviewer, summarizer],
});
