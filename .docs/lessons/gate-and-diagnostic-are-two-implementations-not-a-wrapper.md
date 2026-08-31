# An enforcement gate never routes through its read-only diagnostic

**Source:** ADR-059 Decision 2, structured capability and trust validation across the
FFI (`.docs/adrs/phase-2.md`); PRD story SCP-304, the Layer-3 attestation summaries
story (`.docs/prds/main.json`); `crates/scp-protocol/src/trust/aggregate.rs`.

## The rule

When a subsystem exposes both an **enforcement gate** (fail-closed, returns a verdict,
may write) and a **read-only diagnostic** (returns a per-stage breakdown, writes
nothing), the two stay two implementations over one set of shared stage functions.
Neither one calls the other, and neither one is reconstructable from the other's
output. ADR-059 Decision 2 states this for `ucan_validate` (the gate) and
`ucan_evaluate` (the diagnostic); it binds every gate-plus-diagnostic pair, and
`AttestationCache::get_verified_attestations` (the Layer-3 filter) and
`AttestationCache::attestation_outcomes` (the Layer-3 diagnostic) are the second pair.

Sharing the stage functions is the point. Sharing the *composition* is the defect.

## What routing the gate through the diagnostic costs

An acceptance criterion in SCP-304 originally read "`get_verified_attestations` is
rewritten to call `attestation_outcomes` and keep the entries whose `signature_valid`
is true", and the same criterion required `attestation_outcomes` to run all four stages
per candidate *and* to call the composite gate `verify_attestation_with_revocation`.
Three consequences followed, and the criterion named none of them:

1. **Each candidate paid two Ed25519 verifications per call** — one from the stage
   function, one from the composite gate that re-ran the same stage.
2. **The gate's cache lost its purpose.** `get_verified_attestations` returns a
   within-TTL entry today after a revocation-map lookup and an `expires_at`
   comparison, verifying no signature, because `verified_at` is a stamp that only
   `verify_and_cache_with_revocation` writes and only after a successful check. The
   diagnostic reports the verdict as of `clock.now_secs()`, so it must re-run the
   signature stage on every candidate. Routing the gate through it moved the read cost
   of an evaluation from zero verifications on a warm cache to one per stored
   attestation per call, against a per-subject store that has no cap and no eviction
   (`crates/scp-runtime/src/store/trust.rs`).
3. **An existing test went red with no criterion authorizing its edit.**
   `cache_returns_fresh_attestations_without_reverification`
   (`crates/scp-protocol/src/trust/aggregate.rs`) hands a key-less resolver to a
   cache-fresh entry and asserts the entry comes back. Under the rewrite the signature
   stage runs, finds no key, and the filter drops the entry. An implementer facing that
   failure either deletes a test that pins a reviewed read-path behavior, or keeps the
   fast path and contradicts the criterion.

## Where the two answers legitimately differ, and how to write that down

The gate and the diagnostic answer two different questions, so they disagree on one
input class: a cache-fresh candidate whose issuer key stops resolving inside the cache
TTL stays in the gate's output, which stands on the trusted stamp, and drops out of the
diagnostic's, which checks the signature now. The diagnostic is the more conservative
answer, and the divergence closes when that cache entry expires.

Write that window into the story. A criterion that asserts the two outputs are equal,
over a fixture whose entries all sit outside the window, states an equality that does
not hold in general, and a reader takes it for an invariant.

## The test shape that catches a later collapse

Assert both outputs against **literal** expectations, never one against a projection of
the other. A criterion of the form "the id list of `get_verified_attestations` equals
the id list of the summaries the filter keeps" cannot fail once the gate is implemented
as that filter: it compares one vector against itself.

Then count the work. A resolver that records each `resolve_public_key` call turns the
cost property into an assertion: the gate resolves once per TTL-expired candidate and
never for a cache-fresh one; the diagnostic resolves once per candidate that survives
the revocation exclusion. A gate re-routed through the diagnostic raises the first
count; a diagnostic that also calls the composite gate doubles the second.

## Related

- `.docs/lessons/sdk-consume-structured-ffi-results-not-error-prose.md` — the same
  ADR-059 pair, seen from the SDK side.
- ADR-017 acceptance criterion 8, the four-layer trust engine (`.docs/adrs/phase-4.md`)
  — why a past-renewal attestation stays usable, so neither the gate nor a summary
  consumer excludes on the renewal stage.
