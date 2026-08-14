---
name: adr049-2j-ffi-slice
description: ADR-049 Phase 2J FFI joiner slice (reserve_key_package + context_join_from_welcome) — matrix fully wired; one ADR divergence (shipped work still marked deferred)
metadata:
  type: project
---

Reviewed branch `feat/adr049-2j-ffi-slice` (HEAD 92bcff46c). The slice makes
`Supervisor::reserve_key_package` + `spawn_actor_from_welcome` (both genuinely
`pub`, bare `DID`) reachable through PyO3/NAPI/UniFFI + Python/TS/Swift/Kotlin.

**Fully wired, verified cell-by-cell:** both ops present at Rust seam → 3 bridges
→ 4 SDK wrappers (all call through with real returns; pseudonym DERIVED via
`derive_member_pseudonym*`, `Some(..)` never `None`) → tests at every layer
(incl. NAPI bridge #[tokio::test] rejects) → capability-matrix true×4 no
exemption (check-sdk-coverage PASS) → bridge-aliases ×3 (check-bridge-symmetry
PASS) → 4 new pipeline_wiring assertions (52 floor) matching real literal
strings. KnownContext discovery 3×3 (create/join/join_from_welcome × 3 bridges)
all filled; reserve correctly excluded (stands up no context).

**The one finding — artifact divergence (why the verdict was INCOMPLETE):**
ADR-049 line ~418 "Deferred to the FFI follow-on slice" bullet still lists "the
PyO3/NAPI/UniFFI bridge exports + SDK wrappers" as what the follow-on slice WILL
add — but THIS branch ships + enforces exactly that (matrix flipped, pipeline
asserts, in the same commit range). The slice edited that bullet only to fix the
axis framing (bare-DID vs OwnedIdentityDid) and left the landed/deferred status
stale. Fix per one-way flow: move exports+wrappers+matrix+pipeline into a
"Landed" note; keep only legacy-provider deletion + tripwire flip as deferred
(genuinely gated on the not-yet-existing creator-side add-member→welcome_bytes
production op).

**Pattern lesson (reusable):** on phased FFI slices, when a slice lands part of
what an ADR deferred-work bullet describes, verify the bullet's landed/deferred
STATUS was updated, not just its prose framing. A branch that flips the matrix
to `true` while the ADR still says "the follow-on slice adds these exports" is a
self-contradiction inside one branch.

Cosmetic (not a gap): check-sdk-coverage.py join_from_welcome comment claims
auto-candidate `context_context_join_from_welcome`; real `domain_snake` is
`context_join_from_welcome` (single prefix) which already matches the Python
symbol, so that python alias is redundant + the comment misdescribes the resolver.
