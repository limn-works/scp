---
name: decision-blockedby-cannot-start-not-cannot-finish
description: PRD blockedBy models "cannot START without" — express "cannot FINISH without" via description + a downstream story's blockedBy, never by inverting an edge (that makes a cycle)
metadata:
  type: project
---

In `.docs/prds/*.json`, `blockedBy` means **"cannot start without"** (`.docs/standards/prd.md`
§Dependencies + the orchestrator rule "a story is assignable when all `blockedBy` stories are
`done`"). A story can also have a "cannot *finish* without" relation to a story that depends on
it — those two are different edges and inverting one to express the other creates a cycle.

**Why:** SCP-RELAYRES-004 (relay WRITE path) shipped a `RepublishManager` whose relay arm could
never activate, and its description claimed "this is the story that makes DID records reach
relays at all." The missing piece — a relay-client connection to bind onto the publisher — became
SCP-RELAYRES-006. 006 cannot START without 004's publisher type; 004's *claimed outcome* cannot
FINISH without 006's binding. Modelling the second as `004 blockedBy 006` would have produced a
literal cycle.

**How to apply:** when a story's promised outcome needs a later story:
1. `blockedBy` keeps the forward "cannot start" edge only (`006 blockedBy 004`).
2. Narrow the earlier story's `description` to its true deliverable and name the later story
   explicitly ("this story does NOT deliver X; SCP-NNN does").
3. Move the outcome acceptance criterion to the story that can actually satisfy it, and say so in
   the earlier story's AC ("end-to-end reachability is asserted by SCP-NNN; this story
   structurally cannot satisfy it").
4. Point the downstream integration story at the later story so scheduling is still correct
   (`005 blockedBy [003, 008]`, not `[003, 004]`).

Related: [[finding-phantom-provenance-issue-number-is-the-prd]].
