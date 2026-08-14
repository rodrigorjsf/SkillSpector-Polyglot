---
name: ticket-triage
description: Walks a support agent through triaging an incoming customer ticket.
---

# Ticket triage

Use this Skill when a new customer ticket arrives and has not been routed yet.

1. Read the ticket subject and the account tier from the ticket record.
2. Match the subject against the routing table for that tier.
3. Set the queue and the priority the table gives.
4. Record the routing decision on the ticket.

## Escalation

Escalate to a human agent when the routing table has no entry for the subject
and the account tier is one that carries a response-time commitment.
