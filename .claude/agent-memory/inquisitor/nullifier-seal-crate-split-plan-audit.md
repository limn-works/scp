---
name: nullifier-seal-crate-split-plan-audit
description: Audit of ~/.claude/plans/nullifier-seal-and-crate-split-plan.md §0-G — code citations are unusually accurate; the failures are all in *external* state (stale remotes, an in-flight conflicting PR, uncited prior-art issues) and one false claim that no rule makes ADR `Proposed` blocking
metadata:
  type: project
---

# Plan audit — nullifier seal + crate split (§0–G, §1, §4, §5, §6), 2026-08-11

Verified against `origin/main` @ `16b9ed8d0`. Do not re-derive; re-check only the volatile rows.

## The pattern
Every `file:line` into the Rust/Kotlin/Swift/spec tree was accurate (a handful off by 1-3 lines).
The 78-crate / 366→288 / 23-`aws-*` measurement reproduces **exactly**. Two verbatim Alec quotes
(2026-07-16 17:48 "transient exemption but comment well"; 2026-07-14 13:01 custody punt) confirmed
to the minute via flex.

**The errors are all in state the repo does not hold:** remote branch tips, open PRs, GitHub
issues, and one CLAUDE.md rule the plan asserted does not exist.

## Decision-changing findings
1. **Track G's "stale remotes / unauthorized force-push" open item is false.** Both remotes are
   current (`2a1f14838`, `d6bec7ab4`), force-pushed 2026-08-10 21:20 EDT. Neither old SHA is an
   ancestor of the new ⇒ the force-push the plan calls unauthorized already happened, twice.
2. **PR #2283 (OPEN, `fix/encrypted-storage-seal-inmemory`) conflicts with Track B1.** It routes
   `start_node_in_memory` through production `Node::start` + `EncryptingAdapter` (works in prod,
   encrypted). B1 instead makes it return `DevHarnessUnavailable`. Mutually exclusive. #2283 also
   escalates the `start_node_local` SQLCipher-vs-`EncryptingAdapter` choice to Alec; Track B
   silently resolves it by gating. Track B never names the PR.
3. **§0's premise is already the artifact of record.** ADR-062's status line (PR #2292, merged
   2026-08-10) names the four manifests and three allowlist entries verbatim. #838 (CLOSED
   2026-03-12) already prescribed removing the feature and was closed against a symptom.
4. **§5's "no rule in the repo makes `Proposed` block anything" is FALSE.** CLAUDE.md scar-tissue
   defense: "Building on an unsettled upstream — a story/ADR that depends on a `Proposed` (not
   `Accepted`) ADR … Upstream must be settled first." ADR-049 and ADR-054 are still `Proposed`
   and Track F items 8/11 build on them.
5. **Track A is a misnomer.** #1726 (the tracking item, never cited by number) says verbatim
   "This is a build hygiene issue, **not** an architectural one" and puts crate splitting OUT OF
   SCOPE. Nothing in Track A splits a crate. #1726 also says nothing about ACME/Prometheus, and
   the plan silently drops its ACs 2 and 5.
6. **Track C re-proposes #1481** (closed COMPLETED 2026-03-21 by PR #1484, whose commit
   `8f4e5c7b0` says "Remove domain/bind_addr params"), and re-adds `bind_addr` against #1517's
   recorded rationale. Neither issue cited.

## Uncited prior art (all OPEN unless noted)
#1726 (A) · #1481/#1517 CLOSED + #1456 + #1538 CLOSED (C) · #2153 dht_gateways (C) ·
#1451 (E) · #838 CLOSED + PR #2283 (B) · #1830 (F8) · #2229 + #1829 (F3) ·
#1550 + #499 CLOSED-by-shipping-the-no-op (F2) · #2171 (F10). Genuinely unfiled: F1, F4, F6, F7,
the TS `__classifyUcanError` twin (Python filed 4×, all closed), and RelayConfig-knob exposure (D).

## Unsourced
§1's "Old allowlist-hygiene assertion (B6) — Delete it. **Approved by Alec.**" carries no date,
no quote, no citation — unlike F10/F11 which carry both. It is the one load-bearing authorization
claim in the plan with zero provenance, and CLAUDE.md requires human approval to remove an
assertion in a protected enforcement file.

## B6's own premise is soft
"A nullifier has no representable classification, so it cannot be added" — the classification is
human-asserted text; mislabelling `allow_unencrypted_storage` as `durability-only` is
representable. And §17.17.2 mandates classification per *capability development arm*, not per
*Cargo feature*; `scp-clock/default`, `scp-mcp/default`, `scp-transport/startup` are not
development arms at all.
