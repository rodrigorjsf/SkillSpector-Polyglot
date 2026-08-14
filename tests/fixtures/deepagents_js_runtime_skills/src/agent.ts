/**
 * Builds one agent per tenant.
 *
 * Both the Skill source list and the backend come from the tenant record, which
 * is read at request time, so the values a run uses are chosen by the two helpers
 * below rather than written here.
 */

import { createDeepAgent } from "deepagents";
import { backendForTenant, skillSourcesForTenant } from "./tenants.js";

const MODEL = "anthropic:claude-sonnet-4-6";

export async function buildAgent(tenantId: string) {
  return createDeepAgent({
    model: MODEL,
    skills: skillSourcesForTenant(tenantId),
    backend: backendForTenant(tenantId),
  });
}
