---
name: adr058-invariants-over-runtime-defense
description: Interrogation of ADR-058 / defensive-code.md / arch invariant #9 — the "invalid states unrepresentable, review-enforced not gate-enforced" harness-loop guard. Verdict SOUND.
metadata:
  type: project
---

ADR-058 + `.docs/standards/defensive-code.md` + architecture §2.5.4 invariant #9 +
lesson `loop-scar-tissue-defensive-accretion.md` + 6 charter edits (simplifier/bug-catcher/
inquisitor attack side; white-hat/security-reviewer/cryptographer counterbalance side) +
CLAUDE.md change-protocol additions. Reviewed on branch worktree-harness-loop-guards 2026-07-03.

**Verdict: SOUND (clean bill), one watch-item.** All premises HOLD.

**Why:** Encodes "make bad states unrepresentable; validate once at trust boundary; no
defensive fallback on internal invariants" as an architecture invariant, enforced by the
type system (sound) + review roster, deliberately NO denylist gate.

Load-bearing facts I verified against current code (all TRUE):
- root Cargo.toml DOES deny unwrap_used/expect_used/panic/todo/unimplemented, does NOT deny
  unwrap_or_default/.ok() — so the "residual caught by review" framing is factually exact.
- Both cited carve-out sites are real and match the carve-out text: `validate_entries()` at
  lifecycle_helpers.rs:1807 & 2452 (in-memory import bypasses the serde try_from parse — the
  code comment ALREADY reasons in the standard's terms); `MAX_RECEIPT_BATCH` enforced at
  supervisor.rs:3123 AND all three FFI bridges (uniffi/napi/pyo3) — genuine DoS defense-in-depth.
- ADR-058 is the next free number (057 highest prior). No collision.
- "ambient unwrap_or_default/.ok() in runtime" same-class evidence is honest (35 + 9 in
  scp-runtime/src) — arguably understated, not overstated.

Sharpest tension (probed, resolved SOUND): "Enforce mechanically" builder tenet vs. the
deliberate no-gate decision. Reconciled correctly — the type system IS the mechanical
enforcement; a denylist gate re-checking it in weaker text form would VIOLATE the
pre-existing over-engineering/non-convergent-enforcement guardrail (CLAUDE.md). ADR Rejected
Alt 1 names this as the load-bearing rejection. Self-consistent: countering guard-accretion
with a new gate would be accretion one level up.

Counterbalance to the new failure mode (agent deleting a legit fail-closed control citing
#9) is present and strong: symmetric "Defensive removals" PR line + all 3 security reviewers
charged to BLOCK undeclared removal + simplifier self-check ("over-firing here is a finding
against you").

Watch-item (QUESTION, not defect — honestly disclosed in the ADR): the "distinct entry path
is its own trust boundary" line has a fuzzy edge and WILL be litigated per-PR. Bounded by an
objective test (did the value cross the enforcing parse?) and the guard's own intent comment.
