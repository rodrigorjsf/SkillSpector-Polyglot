# Spec execution workflow

Applies whenever a Spec — a parent issue plus its child Tickets, as published by `/to-spec` — is
being implemented. Every Ticket is implemented through the `/implement` skill, never ad hoc.

1. **Cut the Umbrella Branch first.** Before the first Ticket, `git fetch origin` and branch the
   whole Spec off an up-to-date `main` (this repo's default branch — there is no `master`). Name it
   for the feature, not for a Ticket.
2. **One branch per Ticket, cut from the Umbrella Branch** — never from `main`. It implements that
   Ticket completely.
3. **Close out each Ticket on merge.** Open a PR from the Ticket branch **into the Umbrella Branch**,
   merge it, and delete the branch local and remote — `delete_branch_on_merge` is off on this repo,
   so nothing is cleaned up for you. Then edit the Ticket issue: tick its acceptance-criteria
   checkboxes, and comment whatever the Ticket did not anticipate — a rejected approach, a discovered
   constraint, a deferred follow-up.
4. **Close out the Spec.** When every Ticket is merged into the Umbrella Branch, audit the parent's
   stories for gaps no Ticket owned, comment that audit on the parent issue, then open a PR from the
   Umbrella Branch into `main`. **A human merges that PR — an agent never does.**
5. **Close the parent after the merge.** A Spec parent does not close itself: merging the Umbrella
   PR leaves it open. Once `main` carries the work, verify it there, delete the Umbrella Branch local
   and remote, file whatever the audit surfaced as its own issue, and close the parent referencing
   the merge commit. A Spec is not done while its parent is open.

Within a Spec, the Umbrella Branch is the only branch that targets `main` — a Ticket branch never
does. **Outside a Spec** this workflow does not apply: standalone work such as a documentation
correction or a one-off fix branches from `main`, opens a PR against `main`, and is merged by
whoever the user says. Do not manufacture an Umbrella Branch for a single PR.
