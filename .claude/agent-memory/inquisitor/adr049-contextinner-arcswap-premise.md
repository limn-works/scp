---
name: adr049-contextinner-arcswap-premise
description: ADR-049 Decision-12 ContextHandle RwLock<ContextInner>->ArcSwap<ContextState> premise interrogation — false "single writer/no CAS" comment; RESOLVED @427b01e1f via CAS retry loop (structural fix, root not symptom)
metadata:
  type: project
---

**RESOLVED @427b01e1f (round-2 re-review).** Fix commits 4de63ce09..427b01e1f:
82673db6d (CAS + delete try_read_state + §13 stress test), 57dc18f03 (template .await),
427b01e1f (ADR §10 + agent-md docs). Verdict now SOUND — premise is TRUE-BY-CONSTRUCTION,
not patched: `transition_to` is a `compare_and_swap` retry loop (mod.rs ~182-207) validating
against the LIVE loaded state, ABA-safe (load-guard pins the old Arc allocation so no address
reuse). Correctness no longer depends on any writer-count invariant. All 3 doc sites (module
:27, struct field :108, method) rewritten to the honest multi-writer truth; zero residual
"single writer / no CAS / exclusive" language anywhere in mod.rs or the ADR (grep-clean).
`transition_to` is the SOLE mutator (no raw `.inner.store/swap/rcu` bypass) so 2F's off-path
joiner->Active composes safely — it goes through the same CAS. Order-dependence between two
concurrent legit transitions is intrinsic to any serialization and handled fail-closed (loser
either advances legitimately or gets clean Err(InvalidTransition), never an invalid store);
FSM is terminal-converging so no surprising divergence. §13 gate is a real std::thread stress
test asserting exactly-one-winner / no-invalid-edge / rejected-is-noop (verified FAIL vs
blind-store, PASS with CAS). ADR §10 accurately names ArcSwap+CAS; artifact-flow respected
(doc follows the committed Decision-12). No residual fragility. This is my recommended option
(a) rcu-class atomic fix, delivered.

---

Branch chore/adr049-contextinner-arcswap @4de63ce09 vs main 2e8a08459.
Change: `ContextHandle.inner: Arc<RwLock<ContextInner>>` -> `Arc<ArcSwap<ContextState>>`;
`state()`/`transition_to()` become SYNC; `transition_to` is a plain non-atomic
load-validate-store (NO compare-and-swap).

**Load-bearing FALSE premise (the finding):** the new comment claims "State writes are
performed exclusively by the owning per-context actor's single-threaded command loop
(ADR-049 §10), so no compare-and-swap retry loop is required." This is FALSE.
- `create_context` (lifecycle_helpers.rs:1483) stores `handle: handle.clone()` into
  `PerContextState`, and RETURNS the same handle to napi (stored as `NapiContextHandle.core_handle`).
  `ContextHandle::clone` clones the `Arc<ArcSwap>` -> actor's `cell.handle` and napi's
  `core_handle` are the SAME cell. (Comment on the `inner` field even says so.)
- napi `context_finalize_close_on` (scp-ffi/napi/src/context.rs:4242) writes
  `core_handle.transition_to(&Closing)` on the FFI thread, OUTSIDE the actor loop, BEFORE
  dispatching FinalizeClose. => genuine 2nd concurrent cross-thread writer on the shared cell.
- pyo3 `temp_handle` (scp-ffi/src/context.rs:2506/3099/3350) and ALL uniffi sites use FRESH
  `ContextHandle::new` throwaway handles -> NOT shared, no race. napi is the ONLY shared-cell
  FFI writer, and it only ever writes Closing.

**Why not merely cosmetic:** the shared cell is authorization-critical, not just display.
`require_active(&cell.handle)` (state.rs:2122) and `require_migrating_out` read
`try_read_state()` on this cell as the GATE for send/broadcast/governance. So §12a's
"best-effort cached getter may be stale" blessing does NOT cover this cell — it feeds gates.
(NOTE: §12a's cache is a DIFFERENT thing — the per-FFI-handle `std::sync::Mutex<ContextState>`
still on NapiContextHandle. Two state caches per context coexist; pre-existing smell.)

**Severity downgrade (why it's currently safe by accident):** transition table
(state_machine.rs) forbids self-transitions and only allows napi's Closing-write FROM Active
(MigratingOut->Closing is INVALID). The actor's Active-writes to cell.handle come from
MigratingOut (migration cancel, governance_helpers:3235/3303). So napi(Closing-from-Active)
and actor(Active-from-MigratingOut) can never both load the same source -> a stale-Active
FAIL-OPEN is NOT constructible today. Every lost-update biases FAIL-CLOSED (cell ends more
restrictive; worst case a legit CancelMigration/op wrongly rejected until the authoritative
actor mailbox reconciles; authoritative truth lives in PerContextState.migration_state + the
serial mailbox, not this cosmetic FSM cell). RwLock previously made the pre-existing 2nd
writer safe by serializing load-validate-store; ArcSwap-without-CAS removed that.

**Verdict INTERROGATE-FURTHER (decision sound, justification false+fragile):** ArcSwap IS the
Decision-12-prescribed primitive (clippy.toml/ADR line 254 lists it) — NOT cargo-culted; sync
getters correct. But the "single writer / no CAS" comment is a false invariant (phantom
provenance in a comment) that misleads a future maintainer: the moment any FFI path writes
Active to a cell-sharing handle (e.g. a future napi reactivate/join-that-shares-cell like
create does), the fail-open becomes reachable. No-DOA fix: use `ArcSwap::rcu` in
`transition_to` (one closure, still lock-free, Decision-12-clean) -> atomic under ANY writer
count, deletes the fragility for free; OR route napi's finalize pre-write through the actor
mailbox so exclusivity becomes actually true; OR at minimum replace the comment with the real
(table-dependent, fail-closed-bias) safety argument. Plain load+store justified by a false
exclusivity claim is a latent DOA.

Premise #3 (7 fns kept async-without-await, `#[allow(clippy::unused_async)]` citing Decision-7):
SOUND forward-design. Decision-7 (async-provider-trait, Phase 3, closes #1940) is a committed
ADR-049 decision, not phantom; these fns call crypto/persistence providers that Decision-7
makes async -> they regain awaits. Flipping to sync now then back = the DOA churn No-DOA
forbids. (create_session/session.rs:211 uses a DIFFERENT rationale — API-contract uniformity
with invoke_session — also legit.)

Premise #4 (coherence w/ in-flight 2F-residual joiner->Active transition_to in supervisor.rs):
merge conflict is MECHANICAL (drop `.await` once this makes transition_to sync) and already
called out in the finish plan. 2F's joiner->Active is another actor-thread write to the shared
cell — consistent with the pattern, doesn't change the fail-closed-bias analysis. No latent
design incoherence beyond the known resolution.
