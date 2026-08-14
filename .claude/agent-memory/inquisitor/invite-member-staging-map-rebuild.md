---
name: invite-member-staging-map-rebuild
description: Interrogation of the invite_member structural rebuild (route through actor governance gate + staged_key_packages provider side-map). Premise-1 holds; staging-map is a partial fix mislabeled root; voting path is a DOA dead-end.
metadata:
  type: project
---

# invite_member structural rebuild — staged_key_packages interrogation

Branch `feat/adr049-2j-ffi-slice`, commit `648d4d2fa` (single commit over `1bc5d3aa3..HEAD`).
Coder routed `invite_member` through `propose_governance_action(AddMember)` (in-actor,
authorized, broadcasts the epoch Commit) and threaded the invitee KeyPackage via a
provider-side `DashMap<(context_id,did),Vec<u8>>` (`staged_key_packages`): stage before
propose, consume in `add_member(None)`, unstage on every non-executing early return.

## Verdicts
- **Premise 1 (add_member(None) errored in production; governance member-add never did a
  real MLS add in prod): HOLDS.** The production-error branch dates to #1570 (three-crate
  extract). `execute_add_member` (governance_helpers.rs:1149) is the SOLE caller of the
  governance `add_member`, and always passed `None`. No other production caller ever
  supplied a KP on the governance route. Confirmed genuinely non-functional in prod.
- **Premise 2 (staging map is the right structure): UNSOUND — it is a partial fix wearing
  root-fix clothing.** `stage_key_package` has exactly ONE non-test caller: `invite_member`.
  Every OTHER route into `execute_add_member` still hits `add_member(None)` UNSTAGED and
  still errors in production: (a) the FFI-exposed `propose_governance_action_checked(AddMember)`
  (context.rs:3669) — a real SDK op; (b) `execute_reset_member` re-add (governance_helpers.rs:2353);
  (c) the voting-approval execution path. Provider comment even calls the map "the local
  stand-in for a published-KeyPackage directory / DHT fetch" = a placeholder for unbuilt
  infra (violates no-stubs/no-placeholder). Structural answer: the KeyPackage should travel
  WITH the actor command (execute_add_member takes `Option<&[u8]>` KP sourced from the
  command envelope), not via provider mutable side-state — removes the DashMap, the
  stage/consume/unstage 3-call lifecycle, and the unstage-on-every-early-return rot surface.
- **Premise 3 (voting returns RequiresGovernanceApproval{proposal_id}): UNSOUND — a DOA
  dead-end.** The KP is unstaged when invite_member returns the proposal_id. When the vote
  is later approved, execution runs dispatch_governance_action → execute_add_member →
  add_member(None) with NOTHING staged → errors in prod; and the approval-execution path
  seals/delivers NO bundle to the invitee anyway. So the proposal structurally can never add
  the member. Returning a proposal_id reads as "pending approval" but cannot complete —
  violates No-DOA + "structurally prevents issues." Honest options: reject voting-context
  invites with a clear error, OR build the real deferred-invite (persist the invitee KP WITH
  the pending proposal; consume at execution — synchronous SingleAdmin AND deferred quorum).
  That persist-KP-with-proposal design is the true root fix that dissolves both P2 and P3.

## Coherence note
`add_member(None)` is a systemic wrong-shape, not an invite_member-local issue. reset_member
re-add is itself broken in prod at the add step — ironic given the change's "parity with
remove/reset" framing. The root is: the group's adder never has the invitee's KeyPackage
unless it is carried to the point of add. Fix the carriage, not one caller.
