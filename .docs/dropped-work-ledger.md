# Dropped-Work Ledger

**Created:** 2026-08-09 · **Last verified against `origin/main`:** 2026-08-09 (`d1ebc5ab9`)

## Why this file exists

A four-part sweep of a single long session's transcript (2026-07-03 → 2026-08-09, five
compaction windows) established that a large body of **verified** findings existed only in
chat scrollback. Chat gets compacted; the findings evaporate; they get rediscovered from
scratch weeks later. The largest security finding recorded below had already been flagged
twice in July and dropped both times.

This file is the durable record of **verified-but-unrouted work** — findings that survived
verification but that no issue, story, ADR, or spec owns.

**These entries are NOT a substitute for issues or stories.** Every entry here is a defect
in the tracking system, not a feature of it. Each one should graduate to a GitHub issue or
a `.docs/prds/` story — or, preferably, just be fixed. **Delete an entry the moment its
work lands.** A ledger that only grows has failed at its job.

## How this list is meant to be used

1. **Verify before acting.** Several items originate from subagent reports whose *sibling*
   claims failed verification outright. Every claim below was re-checked against
   `origin/main` on the date in its row, and the verdict is recorded — but code moves.
   Re-verify with `git show origin/main:<path>` / `git grep <sym> origin/main -- 'crates/**'`
   before you act. (zsh does not word-split unquoted variables — never
   `git grep … -- $PATHS`, or you get a silent false "no hits".)
2. **Prefer fixing to filing.** Per the builder tenets, filing an issue instead of doing the
   work is the failure mode this project keeps hitting. A tracked gap is not a closed gap.
3. **Delete on landing.** When the work lands, remove the entry in the same commit. Do not
   mark it "done" and leave it.
4. **Respect the artifact flow.** Several items are spec defects. Those get fixed
   spec-first (`specs → ADRs → stories → code`), never by patching the code to match.

**Verdict key** — `CONFIRMED` (re-verified true on `origin/main`), `CORRECTED` (real issue,
but the originally-reported detail was wrong; the corrected form is what is written here),
`PARTLY RESOLVED` (part landed, the recorded residue has not), `UNVERIFIED` (could not be
mechanically checked; treat as a lead, not a fact).

---

## SEVERITY 1 — Security / fail-open

### S1-1 · `allow_unencrypted_storage` is enabled on the shipped FFI dependency edge

**Verdict:** CONFIRMED · **Owner:** **UNOWNED** (#695 and #838 both CLOSED)

`crates/scp-ffi/common/Cargo.toml:67` enables the feature in `[dependencies]` — not
`[dev-dependencies]`:

```toml
scp-node = { path = "../../scp-node", features = ["allow_unencrypted_storage"], optional = true }
```

`crates/scp-node/Cargo.toml:105` documents the feature as gating `Node::start_for_testing`
(which "accepts any `Storage` backend without the `EncryptedStorage` bound"). Three shipped
call sites remain in `crates/scp-ffi/common/src/server.rs` — `:343` (`start_node_in_memory`,
`Some(identity)` arm), `:459` and `:512` (both arms of `start_node_local`, the **persistent**
filesystem path). None is behind a `testing` cfg.

Spec `.docs/specs/17-persistence-and-storage.md` §17.5 says verbatim: *"Production code…
must NOT enable this feature."*

**First flagged:** 2026-03-11 (#695), re-flagged 2026-03-12 (#838). **#838 was closed the
same day it was opened, against a symptom — its own suggested fix (remove the feature) was
never done.** #695 closed 2026-03-11. Re-flagged in the 2026-07 mobile-artifact sweep
(see S1-10) and again 2026-08-09.

**Partial fix in flight:** `origin/fix/encrypted-storage-seal-inmemory` (`432fd408d`, pushed
2026-08-09) seals the in-memory site. **No PR was ever opened for it** — see S4-4. The
`start_node_local` persistent path is untouched by that branch.

### S1-2 · G1's "ZERO nullifier exceptions" allowlist carries three nullifier entries, and its self-test cannot detect them

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`scripts/check-shipped-feature-graph.sh:51-52` declares the allowlist carries
"ZERO nullifier features, no exceptions (ADR-062 §Decision 6; PR #2132)". The allowlist
then contains, at `:62`, `:77`, `:89`:

```
scp-core/allow_unencrypted_storage
scp-node/allow_unencrypted_storage
scp-runtime/allow_unencrypted_storage
```

The self-test that is supposed to enforce the invariant — `assert_allowlist_has_no_nullifier`
at `:219` — iterates `NULLIFIER_CONTROL_FEATURES` (`:112`), a hardcoded list of eleven
features every one of which is literally named `testing` (or is `scp-testing`). It therefore
cannot detect a nullifier that is not spelled `testing`.

**This is a design defect, not a missing fixture.** Feature-*name* analysis is not a sound
basis for a nullifier gate. Adding `allow_unencrypted_storage` to the control list would
make the gate pass a different denylist while leaving the same class of hole open — the
non-convergent-enforcement failure mode CLAUDE.md warns about. **Record: a reframe is
needed** (classify by what the feature *relaxes*, closed by construction), not another
fixture. Note `scripts/check-shipped-feature-graph.sh` is an enforcement file — the fix
requires human approval, per CLAUDE.md.

**First flagged:** 2026-08-09.

### S1-3 · `DispatchDidResolver` silently falls back to a resolver with no BEP44 verification

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`crates/scp-ffi/common/src/resolvers.rs:649-668`:

```rust
pub const fn new(production: Option<&IdentityBackedDidResolver>) -> DispatchDidResolver<'_> {
    match production {
        Some(resolver) => DispatchDidResolver::Identity(resolver),
        None => DispatchDidResolver::Bridge(BridgeDidResolver),
    }
}
```

`BridgeDidResolver` (`:43`) is string-only — no BEP44 signature check, no self-certification,
no sequence tracking — so **a revoked key still validates** when the global resolver is
uninitialized. The fallback is silent: no error, no log, no typed absence. This violates the
fail-closed tenet directly.

Reached from all three bridges: `crates/scp-ffi/src/ucan.rs:315,450`,
`crates/scp-ffi/src/outlets.rs:355`, `crates/scp-ffi/src/mcp.rs:744`,
`crates/scp-ffi/napi/src/ucan.rs:302,412`, `crates/scp-ffi/napi/src/outlets.rs:46`,
`crates/scp-ffi/uniffi/src/bridge.rs:4391,4991,15468,15631`.

`crates/scp-ffi/CLAUDE.md:125` documents the fallback as intended behaviour — that
documentation is itself part of the finding.

**First flagged:** 2026-08-09.

### S1-4 · Outlet registration signatures are never verified in production; all three bridges fabricate the operator DID

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`verify_outlet_registration_signature` is defined at
`crates/scp-protocol/src/context/outlets/registry.rs:564` and has **zero production
callers**. Every reference is a test:
`crates/scp-testing/src/conformance/outlet_registration.rs:70,656` and
`crates/scp-testing/tests/integration/conformance.rs:1981,2038`.

Meanwhile `crates/scp-ffi/common/src/context_params.rs:334` fabricates the operator identity
for all three bridges:

```rust
operator_did: scp_did::DID("did:key:placeholder".to_owned()),
```

with an empty signature. A hardcoded placeholder on a shipped production path is exactly the
"false guarantee" the no-dev-stand-ins tenet forbids.

**First flagged:** 2026-08-09.

### S1-5 · Streaming `End` chunks carry fabricated provenance — and the fabrication is signed

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`crates/scp-runtime/src/context/outlets/invoke.rs:3394` defines
`placeholder_data_provenance(context_id)`, consumed at `:4294` as the `provenance` field of
the terminal `ChunkPayload::End`. The function's own doc comment concedes the reason:
*"The free function `invoke_outlet` does not have access to the hosting context's full
provenance metadata."*

The chunk is then signed (S1-6, same file), so the fabricated provenance is **cryptographically
attested**. "Provenance everywhere" plus "the absence of provenance is itself a signal"
(protocol tenets) means a *fabricated* provenance record is strictly worse than an absent
one: absence is detectable, this is not.

**First flagged:** 2026-08-09.

### S1-6 · Chunk signing returns an all-zero signature when the signer fails

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`InnerPumpSigningContext::sign_inner_chunk`, `crates/scp-runtime/src/context/outlets/invoke.rs`,
returns `[0u8; 64]` on **three** distinct failure paths — `:3481` (signer is `None`), `:3501`
(preimage computation failed), `:3515` (**the signer itself returned an error**) — each after
a `tracing::error!`, then continues emitting the stream.

An all-zero signature is not an honest absent state; it is a well-formed 64-byte field that a
verifier must special-case to reject. `crates/scp-runtime/src/context/outlets/dispatch.rs:491`
and `:2628` show the *sibling* code path deliberately refuses to do this — "emitting an
unsigned `[0u8; 64]` placeholder would…" / "we never construct an unsigned…". The two paths
disagree; `invoke.rs` is the wrong one.

**First flagged:** 2026-08-09.

### S1-7 · NAPI unary + saga entry points gate on a stale cached context state while the streaming twin reads live state

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`crates/scp-ffi/napi/src/outlet_stream.rs:1155-1161` states the invariant explicitly:

> Read the AUTHORITATIVE lifecycle state from the per-context supervisor actor
> (`read_context_state`) — NOT the bridge-cached `NapiContextHandle::state()`, which LAGS:
> on close the core handle flips to Closed **only after** the actor tears down…

and does so at `:1179` / `:1190`.

`crates/scp-ffi/napi/src/outlets.rs` does the opposite at **eleven** sites: `:258`, `:364`,
`:536`, `:611`, `:622` (cross-context invoke — the escrow/spend gate), `:975`, `:985`
(cross-context **saga** start), `:1128`, `:1195`, `:1363`, `:1428`. On the cross-context
paths the stale read gates an escrow debit.

**First flagged:** 2026-08-09.

### S1-8 · `BridgeRevocationDistributor` distributes nothing and returns `Ok(())`

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`crates/scp-ffi/common/src/resolvers.rs:806-822` — the entire implementation is an `info!`
log followed by `Ok(())`. Its doc comment calls distribution "deferred to the transport layer
(when connected)"; no such deferral mechanism is wired.

It is the **only non-test `RevocationDistributor` impl**, and it is wired into `ucan_revoke`
on all three bridges: `crates/scp-ffi/src/ucan.rs:750`,
`crates/scp-ffi/napi/src/ucan.rs:696,1100,1170`,
`crates/scp-ffi/uniffi/src/bridge.rs:15750`. A caller who revokes a capability gets a success
return and no revocation propagates.

**First flagged:** 2026-08-09.

### S1-9 · `NoOpRevocationChecker` is re-exported ungated from the `scp-core` facade

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

Defined at `crates/scp-protocol/src/trust/attestation.rs:722` with no cfg gate
(`check_revocation` always returns `None` = never revoked). Re-exported to every consumer of
the facade at `crates/scp-core/src/lib.rs:172`.

A security nullifier nameable from the public production facade is one import away from a
shipped fail-open. Contrast the sibling nullifiers, which ADR-062 §Decision 6 correctly
re-gated to `feature = "testing"`.

**First flagged:** 2026-08-09.

### S1-10 · Mobile artifacts (`default = ["server"]`) compile the in-memory dev-node API

**Verdict:** CORRECTED (narrower than first reported) · **Owner:** **UNOWNED**

`crates/scp-ffi/uniffi/Cargo.toml:19` sets `default = ["server"]`, so every Swift/Kotlin build
compiles `node_start_in_memory_on` (`crates/scp-ffi/uniffi/src/server.rs:733`) → 
`server::start_node_in_memory` (`:743`), which builds an `InMemoryStorage`-backed node through
`Node::start_for_testing` — i.e. via the `allow_unencrypted_storage` edge of S1-1.

**Correction to the original report:** the "constructing plaintext key custody" half is now
**false**. The auto-generate arm fails closed on a shipped build
(`crates/scp-ffi/common/src/server.rs:335-341`, `ServerError::AutoGenerateUnavailable`), and
identity portability fails closed at `crates/scp-ffi/uniffi/src/server.rs:718-726`. The
`Some(identity)` arm annotates `FileKeyCustody`, not an in-memory custody. The residue is
**unencrypted in-memory storage on a shipped mobile artifact** — a strict subset of S1-1, and
it should be fixed together with S1-1.

**First flagged:** 2026-07 (never answered, never filed). Re-verified and narrowed 2026-08-09.

### S1-11 · Healing publisher's relay arm publishes bare document bytes with no signature

**Verdict:** CONFIRMED · **Owner:** partially — #482 (OPEN, created 2026-03-10) covers the
adjacent republish-loop instance; **this resolver instance is UNOWNED**

`crates/scp-identity/src/resolver.rs`, `heal()`: the DHT arm at `:350` publishes
`(public_key, signature, document_bytes, seq)`; the relay arm at `:361` publishes only
`(routing_id, ttl, document_bytes)` — the signature, sequence, and public key are dropped, so
a relay consumer has nothing to verify against.

`.docs/adrs/ADR-062-…md:180` records the same defect in the sibling republish loop
(`scp-identity/src/republish.rs:703` — "drops signature/sequence, publishes bare
`document_bytes` not the DID-record frame — #482 fix, out of ADR-062 scope"). The
`resolver.rs` healing instance is not covered by that note.

Fixed only on the **unmerged** `origin/feat/adr062-slice11-relay-querier` (see S4-2).

**First flagged:** 2026-08-09.

---

## SEVERITY 2 — Spec / provenance defects (fix spec-first)

### S2-1 · Provenance never reaches an HTTP consumer: §18.11 projection drops the signature *and* never verifies it

**Verdict:** CONFIRMED (with the premise corrected) · **Owner:** **UNOWNED** — lives only in
GitHub **Discussion** #2139

**Premise correction:** `.docs/specs/05-contexts.md` §5.14.5 does *not* model broadcast as
encryption-only. `BroadcastEnvelope` (`:1966-1976`) carries both `provenance:
Option<DataProvenance>` and `signature: Ed25519Signature`, and the native receive path
(`:2010`) verifies the signature pre-decryption.

**The drop is entirely in §18.11.** `.docs/specs/18-addressability-and-deployment.md`:

- §18.11.3 feed response (`:725-737`) and §18.11.4 per-message response (`:759-765`) each
  carry exactly five fields — `id`, `author_did`, `key_epoch`, `published_at`,
  `content` (base64 plaintext). **No `signature`, no `provenance`.**
- §18.11.5 "Decryption Architecture" (`:786-792`) is a five-step algorithm with **no
  signature-verification step at all** — so the node neither checks the signature nor
  forwards it.
- §18.11.9 `BroadcastContent` (`:861-876`) likewise carries no author signature.

Net: `author_did` reaches the HTTP consumer as an **unauthenticated assertion by the
projecting node** — a direct contradiction of "provenance everywhere" and
"relays are untrusted dumb pipes". Fix is spec-first: §18.11 must forward (and verify) what
§5.14.5 already carries.

**First flagged:** 2026-08-02 (Discussion #2139). Re-verified 2026-08-09.

### S2-2 · The "guarantee it" instruction is in no artifact

**Verdict:** CONFIRMED (absence verified) · **Owner:** **UNOWNED** — lives only in
Discussion #2139

The instruction that **access guarantees the option of pulling content as provenance-bearing
data** appears in no spec, no ADR, no story, and no issue. Verified absent:
`git grep -rniE "provenance-bearing|pull.{0,30}provenance|provenance.{0,25}(http|consumer|projection)" -- .docs/specs .docs/adrs .docs/prds`
returns zero hits; no open issue matches.

This is a human-issued protocol requirement sitting in a Discussion. Per the artifact-flow
invariant it must land in a spec before any of S2-1's downstream work can be scoped.

**First flagged:** 2026-08-02 (Discussion #2139).

### S2-3 · §18.6.4 contradicts §10.17 on whether a node is a protocol participant

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`.docs/specs/18-addressability-and-deployment.md:473` (§18.6.4 Properties and Invariants):

> The node's identity is a full SCP identity. It can create contexts, join contexts, send
> messages — **it is a protocol participant, not just infrastructure.**

`.docs/specs/10-infrastructure-and-self-hosting.md:1057` (§10.17 Node vs. Participant):

> A `scp-node` is **pure infrastructure**… A node **never participates in a context as
> itself.** … it does not join contexts, create MLS groups, or sign protocol messages in its
> own right.

§10.17 is the settled side — backed by **ADR-053 (Status: Decided)**, `.docs/adrs/phase-2.md:1906`.
§18.6.4:473 is stale text that must be corrected to match.

Related: §18.8 "Agent Deployment Flow" (`:498-536`) presents `.generate_identity()` (`:507`,
"Generates a new DID identity" `:512`) as the *only* deployment example, so generate-your-own
reads as the norm by omission rather than by any normative statement. Worth correcting in the
same pass.

**First flagged:** 2026-08-09.

### S2-4 · Spec §9.7.4.1 item 5 — a hard MUST for a plural-option custody ceremony — has no story, gate, or issue

**Verdict:** CONFIRMED · **Owner:** **UNOWNED** — realization lives only in RFC #2130 and
ADR-054 (**Status: Proposed**)

`.docs/specs/09-security-model.md:762-768`:

> 5. **SDK presentation.** At identity creation, the SDK MUST:
>    a. Generate the pre-rotation keypair.
>    b. **Present the user with custody options** (ordered by security as above).
>    c. Guide the user through the selected custody method.
>    d. Verify the backup…
>    e. Publish the `PreRotationCommitment` … only after backup verification succeeds.
>    f. Destroy the pre-rotation private key from the creating device's memory…

Item 6 (`:770`) repeats it post-rotation. `:742` states items 4 and 5 "remain canonical".

Coverage: nothing. `9.7.4.1` appears in `.docs/prds/` exactly once
(`adr062-capability-injection.json:3`) and only to cite **item 3a** while declaring
pre-rotation custody out of scope. No `scripts/` gate covers item 5. The obligation is
acknowledged in code prose only — `crates/scp-platform/src/traits.rs:703-728` enumerates
§5(b)/(c)/(d) as "the SDK's job" with nothing behind it.

`.docs/adrs/ADR-054-…md:3` is **Proposed**, and itself defers the §5 ceremony to RFC #2130.
Related open issue #1729 (production `PreRotationCustody` backends) covers **item 4**
backends, not the item-5 ceremony.

**First flagged:** 2026-08-09.

### S2-5 · PSK purpose `"device-enroll"` is normative but only `psk-rotate` is implemented

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`.docs/specs/03-identity.md:687` defines `"device-enroll"` as the purpose for "initial PSK
distribution when a device is enrolled … and during trusted-device / social recovery
(recovery IS enrollment, §3.3)", and `:690` makes the domain separation load-bearing: *"a
`device-enroll` wrap cannot be opened in a `psk-rotate` context."*
`.docs/specs/09-security-model.md:1821` lists `purpose ∈ {"device-enroll", "psk-rotate"}`.

Code has only the rotate half: `crates/scp-runtime/src/identity/recovery.rs:762`
`const PSK_PURPOSE_ROTATE: &[u8] = b"psk-rotate";`.
`git grep -n "device-enroll\|device_enroll\|DEVICE_ENROLL" -- crates` returns **zero hits**.
The enrollment flow the spec makes normative — including the recovery path — has no
implementation.

**First flagged:** 2026-08-09.

---

## SEVERITY 3 — False status / phantom provenance

### S3-1 · `reachability.json` — 16 of 16 stories `done`; 12 have unmet ACs

**Verdict:** CONFIRMED · **Owner:** #2278 (OPEN, created 2026-08-08) owns the **code** gap;
the **PRD correction is UNOWNED**

All 16 stories in `.docs/prds/reachability.json` carry `status: "done"`. #2278 —
*"Reachability subsystem: 12 stories marked done with unmet ACs — STUN service unwired, NAT
keepalive dead, bridge never enabled, Tier-1 self-test unsatisfiable"* — is open.

The status correction sits on `origin/fix/reachability-prd-false-done` (`79faacda1`, pushed
2026-08-08). **No PR was opened for it** (see S4-4). **Zero code has been fixed** — the branch
only corrects statuses.

Also: `SCP-236` (`done`) lists `crates/scp-transport/src/relay/operations.rs`, which does not
exist.

**First flagged:** 2026-08-08.

### S3-2 · `outlet.json` — two `done` stories whose named symbols exist nowhere; nineteen with stale file provenance

**Verdict:** CORRECTED (narrower and more precise than first reported) · **Owner:** **UNOWNED**

Verified phantom ACs — the symbol appears nowhere in `crates/` or `bindings/`:

- **SCP-OUT-022** (`done`) — AC reads *"Function `evaluate_all_layers(ctx, caveats, outlet,
  input)` returns `Ok(())` iff every layer admits"*. `git grep -rn "evaluate_all_layers"`
  matches **only `.docs/prds/outlet.json:1412,1423`** — the story is the sole occurrence in
  the repository.
- **SCP-OUT-005** (`done`, "Rename tool → outlet across all four FFI bridges") — names
  `outlet_update`, `outlet_deregister`, `outlet_get`; none exists under any spelling. NAPI
  exports exactly `outlet_register / invoke / verify / invoke_cross_context /
  invoke_cross_context_saga / session_{create,invoke,close} / interface_{expose,accept,revoke}`
  (`crates/scp-ffi/napi/src/outlets.rs:250-1478`).

**Correction:** the original "~9 stories whose code is absent" is **not** supported. What is
supported is the above two, plus **19 `done` stories whose `files` provenance no longer
resolves** — SCP-OUT-002/003/004/005/006/008/012/013/014/016/017/020/021/022/027/029/033/034/039.
Most of those paths are casualties of real refactors (`context/manager/*` dissolved by
ADR-049, `context/tools/*` renamed to `outlets/`, `scp-ffi/wasm/*` removed by ADR-055) — that
is provenance rot, not missing code, and it should be repaired by repointing, not by
reopening the stories.

**First flagged:** 2026-08-09.

### S3-3 · `adr062-capability-injection.json` — stories still `pending` whose work merged

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

All six stories in `.docs/prds/adr062-capability-injection.json` are `pending`. At least
three have landed:

| Story | Evidence it landed |
|---|---|
| `SCP-CAPINJECT-010` | PR **#2176 MERGED** — "ADR-062 Slice 10, SCP-CAPINJECT-010" |
| `SCP-CAPINJECT-011` | PR **#2272 MERGED** — "closes ADR-062 E4"; on `origin/main` at `51b59d426` |
| `SCP-CAPINJECT-006` | `crates/scp-node/Cargo.toml:31-37` — "`testing` is NO LONGER enabled here… it now FAILS CLOSED with a typed `IdentityError` (SCP-IDENT-1059)" |

**Status drift runs in both directions** — S3-1/S3-2 are `done`-but-not-built; this is
built-but-not-`done`. Any audit that only looks for over-claiming will miss half the drift.

**First flagged:** 2026-08-09.

### S3-4 · ~355 `done` stories across the remaining PRDs have never been audited

**Verdict:** CONFIRMED (counts re-derived 2026-08-09) · **Owner:** **UNOWNED**

| PRD | total | done | pending | in-progress |
|---|---:|---:|---:|---:|
| `main.json` | 185 | **175** | 7 | 3 |
| `outlet.json` | 55 | 43 | 10 | 2 |
| `persistence.json` | 35 | **35** | 0 | 0 |
| `transport-expansion.json` | 32 | 22 | 10 | 0 |
| `agent-binding.json` | 22 | 21 | 0 | 1 |
| `http-features.json` | 19 | 13 | 6 | 0 |
| `reachability.json` | 16 | 16 | 0 | 0 |
| `bridge-cooperative.json` | 13 | 13 | 0 | 0 |
| `content-access.json` | 10 | 10 | 0 | 0 |
| others (8 files) | 43 | 34 | 9 | 0 |

**Highest yield first:** `persistence.json` — 35/35 `done` **while its entire E2E suite is
compiled out** (see S3-5). Then `main.json` — 175 `done`, only a small minority ever
independently verified.

**First flagged:** 2026-08-09.

### S3-5 · 3,370 lines of integration tests are compiled out but still registered as `[[test]]` targets — CI reports green with zero tests run

**Verdict:** CORRECTED (line count exact; test count was overstated) · **Owner:** **UNOWNED**

| File | lines | `#[tokio::test]` | fn defs |
|---|---:|---:|---:|
| `crates/scp-testing/tests/integration/network_simulation.rs` | 1,649 | 2 | 35 |
| `crates/scp-testing/tests/integration/persistence.rs` | 1,088 | 14 (+ `persistence_tests!` macro at `:61`) | 45 |
| `crates/scp-testing/tests/integration/outlet_economy_wiring.rs` | 636 | 2 | 32 |
| **total** | **3,373** | **18** | **112** |

**Correction:** the originally-reported "130 test functions" is **wrong** — there are 18
`#[tokio::test]` attributes (plus macro-expanded cross-adapter parity cases) across 112
function definitions.

Each file opens with `#![cfg(any())]` (persistence.rs:4, and equivalently in the other two),
and each remains a registered target — `crates/scp-testing/Cargo.toml:232-233` and `:264-265`.
So `cargo test --test network_simulation` **passes with 0 tests executed**. A green
`[[test]]` target that runs nothing is worse than a deleted one: it reads as coverage.

**The cited blocker no longer blocks.** All three headers say they await backend injection on
`NodeMlsFactory::with_backends`. That seam **exists and is in use**:
`crates/scp-runtime/src/crypto/mls/provider.rs:481,520`, called at
`crates/scp-runtime/src/context/builder.rs:1209` and
`crates/scp-runtime/src/context/ttl.rs:1824`.

**First flagged:** 2026-08-09.

### S3-6 · ADR-052 claims a reachability proof; the test asserts a supertrait

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`.docs/adrs/phase-2.md:1895` (ADR-052, **Status: Decided**, `:1838`), AC 9:

> the `EncryptedStorage` structural test **proves the unencrypted-storage path is unreachable
> from the production identity-persisting constructors (`Node::start` and `Identity::create`)**

Repeated at `:1883` as a rejected-alternative justification.

The actual test, `crates/scp-node/tests/encrypted_storage_seal.rs` (59 lines total), contains
exactly two assertions: `:36-39` a never-called
`_assert_encrypted_storage_extends_storage<S: EncryptedStorage>()` — which proves only that
`EncryptedStorage` has `Storage` as a supertrait — and `:52-59` `size_of::<Node>() == 0`.
Neither mentions `Node::start`; `Identity::create` does not appear in the file at all.

A genuine reachability test was written on `origin/fix/encrypted-storage-seal-inmemory`
(`432fd408d`) — **unmerged, no PR** (S4-4).

**First flagged:** 2026-08-09.

### S3-7 · #2202 depends on an SCPR wire format that exists on no merged branch

**Verdict:** CONFIRMED (dependency verified absent; the "discarded at the Model-B pivot"
rationale is UNVERIFIED) · **Owner:** #2202 is OPEN but unactionable as written

#2202 — *"Migrate relay-published MLS KeyPackages to SCPR kind-2 (off
`OuterEnvelope.encrypted_blob`)"*, created 2026-08-02, OPEN.

`git grep -rn "scpr" -- crates/scp-protocol crates/scp-transport/src` returns **zero hits** on
`origin/main`. The only SCPR framing in the repository is
`crates/scp-protocol/src/envelope/scpr.rs` (445 lines) on the **unmerged**
`origin/feat/adr062-slice11-relay-querier` (S4-2). The issue therefore cannot be executed
against `main` as written.

**Not verified:** whether SCPR was formally "discarded at the Model-B pivot" (that claim comes
from transcript only). Either way #2202 needs a decision — resurrect SCPR via S4-2, or rewrite
#2202 against whatever framing replaces it.

**First flagged:** 2026-08-09.

### S3-8 · One stale doc comment names `InMemoryPreRotationCustody` the shipped production backend

**Verdict:** CORRECTED (there is **one**, not two) · **Owner:** **UNOWNED**

`crates/scp-platform/src/traits.rs:730-733`:

> **Today's shipped backend** ([`InMemoryPreRotationCustody`](super::testing::InMemoryPreRotationCustody))
> is process-memory only…

Stale since ADR-062 §Decision 6 / SCP-CAPINJECT-006: the type is now
`#[cfg(feature = "testing")]`-only and the shipped path fails closed. The intra-doc link also
points into `super::testing`, a module gated off on shipped builds.

**Correction:** the originally-reported second instance does not exist. Every *other* doc site
is correct and explicitly contradicts "shipped default" —
`crates/scp-identity/src/lib.rs:164-178`, `crates/scp-identity/src/config.rs:322-350` and
`:485-500`, `crates/scp-platform/src/testing/pre_rotation_custody.rs:1-11`,
`crates/scp-platform/src/lib.rs:61-68`. The one that is wrong lives on the
`PreRotationCustody` trait itself — the most-read doc surface for that capability.

Fix drafted on local branch `fix/stale-prerotation-nullifier-docs` (`2026-08-09`, **never
pushed** — see S4-4).

**First flagged:** 2026-08-09.

---

## SEVERITY 4 — Unsettled upstream, and finished work that never landed

### S4-1 · Three ADRs are `Proposed` while merged code depends on them; the status vocabulary is undefined

**Verdict:** CONFIRMED (counts exact) · **Owner:** **UNOWNED**

`**Status:** Proposed` — exactly three, all standalone files:

- `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md:3` — depended on
  by **six merged PRs** and the public FFI surface
- `.docs/adrs/ADR-049-actor-per-context.md:3` — the entire actor-per-context migration is
  merged
- `.docs/adrs/ADR-054-pre-rotation-custody-substrate-isolation.md:3`

Per CLAUDE.md's scar-tissue rule, *"a story/ADR that depends on a `Proposed` (not `Accepted`)
ADR"* is a blocker. These three are load-bearing and settled in practice; either they are
promoted or the rule is being violated wholesale.

**No document defines the status vocabulary.** Counts across `.docs/adrs/`:

- `**Status:** Decided` — **47** (phase-1: 8, phase-2: 13, phase-3: 5, phase-4: 8, phase-5: 4,
  phase-6: 9; zero in standalone `ADR-0NN-*.md`)
- `**Status:** Accepted` — **12** (ADR-046/047/048/050/051/056/057/058/060: 1 each, ADR-061: 2,
  phase-2.md: 1)
- `**Status:** Proposed` — **3**

`.docs/standards/` contains no ADR standard or template, and no file in `.docs/` defines the
set. **CLAUDE.md's scar-tissue rule uses the vocabulary normatively ("Proposed" vs "Accepted")
while 47 of 62 ADRs say "Decided"** — a word the rule never mentions. The rule is literally
unsatisfiable-by-reading for the majority of ADRs.

**First flagged:** 2026-08-09.

### S4-2 · `origin/feat/adr062-slice11-relay-querier` — 2,199 insertions, no PR ever opened

**Verdict:** PARTLY RESOLVED (the querier landed separately; the transport half did not) ·
**Owner:** **UNOWNED**

`origin/feat/adr062-slice11-relay-querier` @ `04c666220` — 26 files, **+2,199 / −599**,
3 commits, last pushed 2026-08-02. Two consecutive review rounds recorded. **No PR was ever
opened.** (The similarly-named `feat/adr062-slice11a-real-multi-relay-querier` shipped as
PR #2226, MERGED — do not confuse them.)

**Already landed via #2226:** `RealMultiRelayQuerier` is on `main`
(`crates/scp-identity/src/relay_querier.rs:128`, exported at
`crates/scp-identity/src/lib.rs:51`).

**Still only on the branch — port, do not rewrite:**

| Artifact | size | status on `main` |
|---|---:|---|
| `crates/scp-transport/tests/did_relay_round_trip.rs` | 401 lines, **6 `#[tokio::test]`** | absent — **`main` has no relay-only E2E test at all** (`crates/scp-transport/tests/` holds only combined/local-cache/nostr/quic/redb/sqlite/webrtc suites) |
| `crates/scp-protocol/src/envelope/scpr.rs` | 445 lines | absent (blocks #2202 — S3-7) |
| `crates/scp-transport/src/did_relay.rs` | 282 lines | absent |
| FFI wiring of the real querier | across all 3 bridges | **not wired** — every bridge still constructs `NoOpRelayQuerier`: `crates/scp-ffi/src/identity.rs:142`, `crates/scp-ffi/napi/src/identity.rs:196`, and `crates/scp-ffi/uniffi` via the shared path |

This is ≈ most of SCP-RELAYRES-006 plus ≈ all of SCP-RELAYRES-005
(`.docs/prds/relay-did-resolution.json`, 5 stories, all `pending`).

**First flagged:** 2026-08-02.

### S4-3 · `fix/1341-f4-mcp-subscribe-honest` — 5 commits, never pushed

**Verdict:** CONFIRMED · **Owner:** #1341 (OPEN, created 2026-03-17)

Local-only branch, tip 2026-08-08, absent from `git ls-remote --heads origin`. Five commits:

```
de074a26e test(mcp): fix the two UniFFI provider tests the resource gate invalidated
aa73ab84d fix(mcp): make every advertised MCP capability one the server can deliver (#1341)
99534ba8f refactor(runtime): name the context-event envelope instead of a bare tuple
0ae8889c9 test(mcp): pipeline assertion that subscribe is backed, not advertised (#1341)
dc64f3432 feat(mcp): back resources/subscribe with a real event source (#1341)
```

#1341 — *"MCP resource subscriptions are no-ops across all bridges"* — remains OPEN. **A
local-only branch is one `rm -rf` from gone.** Push it.

**First flagged:** 2026-08-08.

### S4-4 · Four more branches with finished work and no PR

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

| Branch | tip | pushed? | PR? | carries |
|---|---|---|---|---|
| `fix/encrypted-storage-seal-inmemory` | `432fd408d` (2026-08-09) | yes | **none** | in-memory seal for S1-1 + the real reachability test S3-6 claims |
| `fix/reachability-prd-false-done` | `79faacda1` (2026-08-08) | yes | **none** | the S3-1 status correction |
| `fix/ceiling-modify-reconcile` | `a503c860e` (2026-08-02) | yes | **none** | 6 commits: `ModifyCeiling` role/member reconciliation (§5.3.2), `add_signer` ceiling gate (a **local privilege-escalation close**), atomic member-removal teardown (#2216) |
| `fix/stale-prerotation-nullifier-docs` | (2026-08-09) | **no** | none | the S3-8 fix |

`fix/ceiling-modify-reconcile` is 6 ahead / 186 behind `origin/main`. Its `add_signer`
ceiling gate closes a governance escalation and has been sitting unmerged since 2026-08-02.

Per the Change protocol, *"Always open a PR when the work is complete and double-zero
reviewed — do NOT wait to be asked."* Four branches say otherwise.

**First flagged:** 2026-08-09.

### S4-5 · PR #2155 — DIRTY since the day it was opened

**Verdict:** CONFIRMED · **Owner:** #2155 (OPEN)

`chore(build): dev/test profile emits line-tables-only debug info`, head
`chore/dev-profile-line-tables`. Created **2026-07-16T04:28Z**, `updatedAt` identical,
`mergeable = CONFLICTING`, `mergeStateStatus = DIRTY`. Untouched for three weeks.

This is the fix for the disk-bloat question that opened the originating session — the very
first thing asked, still unlanded.

**First flagged:** 2026-07-16.

### S4-6 · PR #1792 — DIRTY since 2026-06-12; a large ancestor stack hangs off it

**Verdict:** CONFIRMED (state); ancestor-stack count UNVERIFIED · **Owner:** #1792 (OPEN)

`feat(outlets): outlet redesign — tool→outlet rename, Query/Action kinds, scoped UCAN
caveats, structured errors, streaming-native invocation`, head `feat/outlet-redesign`.
Created **2026-06-12T04:51Z**, `updatedAt` identical, `mergeable = CONFLICTING`,
`mergeStateStatus = DIRTY`.

The transcript claim that **47 of ~196 unmerged branches are its ancestor stack** was not
re-derived. The repository currently has **225 remote branches / 947 local branches**, so the
magnitude is plausible; the exact figure needs a fresh `git branch --contains` sweep before
anyone plans around it. This PR is the likely root of much of S3-2's outlet-story drift.

**First flagged:** 2026-06-12.

### S4-7 · `scp-node` feature-gating — the original session scope, explicitly asked for, and dropped

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

`crates/scp-node/Cargo.toml` compiles every optional backend unconditionally:

- `:24-30` — `scp-transport` with `sqlite-blob`, `redb-blob`, **`postgres-blob`**, **`s3-blob`**,
  `startup`, all in `[dependencies]` with no gate
- `:43` — `instant-acme = "0.8"`, unconditional — **even though `host_site` hard-rejects
  ACME**: `crates/scp-node/src/self_host.rs:1123` *"TlsMode::Acme is not valid for
  host_site"*
- `:82` — `metrics-exporter-prometheus`, unconditional
- `[features]` (`:100-118`) offers only `allow_unencrypted_storage`, `testing`, `quic`,
  `http3`, `udp`, `coap`, `upnp` — **no `blob-*`, no `acme`, no `dht-production`, no
  `metrics-export`**

Every consumer therefore compiles `aws_sdk_s3` (~126 MB debug rlib), `sqlx_postgres`, `redb`,
and `instant-acme`. Intended shape: `blob-sqlite` default; `blob-s3` / `blob-postgres` /
`blob-redb` / `acme` / `dht-production` / `metrics-export` opt-in.

**Alec explicitly said not to drop this. It was dropped anyway** — the session that opened on
this question ended without it.

**First flagged:** 2026-07-03 (session opening scope).

---

## SEVERITY 5 — Process and tracking traps

### S5-1 · #2130 and #2139 are GitHub **Discussions**, not issues — invisible to every burndown

**Verdict:** CONFIRMED · **Owner:** n/a (that is the problem)

- Discussion **#2130** — *"RFC: Pre-rotation recovery custody — realization design (PROPOSED,
  validate at execution)"*, open. Holds the entire ADR-054 realization (S2-4).
- Discussion **#2139** — *"scp-node identity & self-hosted-site provenance — open design
  questions"*, open. Holds S2-1 and S2-2, including a human-issued protocol requirement.

`gh issue list` never returns them; `gh api repos/…/issues/2130` does not resolve them. Any
"burn down the backlog" pass silently skips both. Their contents must graduate to specs/ADRs
or to real issues.

**First flagged:** 2026-08-09.

### S5-2 · #1733 closed by ADR fiat with no AC-by-AC map; #627 never reopened as promised

**Verdict:** CONFIRMED · **Owner:** **UNOWNED**

- **#1733** — *"Eliminate `scp_platform::testing` imports from production paths + add CI
  enforcement"* — created 2026-05-04, **CLOSED 2026-07-17**. ADR-062 declares it subsumed
  (`.docs/adrs/ADR-062-…md:180`: "#1733 (folded for custody/attestation/DHT/storage)"). **No
  AC-by-AC map was ever posted** showing each of its acceptance criteria is met by the folding
  ADR. S1-9 (`NoOpRevocationChecker` ungated on the `scp-core` facade) is precisely the class
  #1733 covered and is still open in the code.
- **#627** — *"production-dht feature not enabled for any FFI crate — all SDKs use
  InMemoryDhtClient"* — created 2026-03-10, **CLOSED 2026-03-11** (next day). A reopen was
  promised and never happened.

"An ADR says it's covered" is not verification. Closing on that basis is how S1-1 became a
five-month-old live defect.

**First flagged:** 2026-08-09.

### S5-3 · The primary checkout is a detached-HEAD trap for any non-isolated agent

**Verdict:** CONFIRMED · **Owner:** **UNOWNED** (operational)

`/Users/alec/Developer/limn/scp/.git/HEAD` → `1620de983a7fafabf4227a9edebb2e425c7db165`
— **detached**, on the `fix/ceiling-modify-reconcile` line (S4-4), **186 commits behind
`origin/main` with 3 commits ahead**.

Any agent that does not use worktree isolation will build, test, and reason against a
five-week-old tree containing unmerged local work. Compounding hazard: `~/.cargo/config.toml`
redirects `target-dir` to a **shared** `~/.cargo/shared-target`, so this stale checkout can
poison a *correct* worktree's clippy run with stale artifacts. Use an isolated
`CARGO_TARGET_DIR` per worktree.

**First flagged:** 2026-08-09.

### S5-4 · Backlog triage is half-finished

**Verdict:** PARTLY VERIFIED · **Owner:** **UNOWNED**

Live count on 2026-08-09: `gh issue list --author @me --state open` → **232 open**
(down from a 286 snapshot on 2026-08-02, so ~54 closed since).

Triage split recorded in the transcript, **not independently re-derived**: 60 obsolete +
3 duplicate + 39 noise = 102 closeable, of which 63 closed and 39 held; **44 trivial + 150
real remain untouched.**

Re-derive before planning against these numbers. The standing correction applies: the backlog
grew because work was *filed* instead of *done*. Burn it down; do not add to it — including
by graduating entries from this ledger into issues rather than fixing them.

### S5-5 · Nine agent memories flagged NOW-FALSE remain uncorrected

**Verdict:** UNVERIFIED · **Owner:** **UNOWNED**

The transcript records eleven agent memories under `.claude/agent-memory/` identified as
now-false, of which two were corrected — leaving nine. **The specific nine were not
enumerated in a durable artifact and could not be recovered mechanically**, so this entry is a
lead, not a fact.

Actionable form: sweep `.claude/agent-memory/*/MEMORY.md` and their topic files against
current `origin/main`, applying the standing rule — a memory naming a file, symbol, or flag is
a claim about *when it was written*; verify before recommending, and correct or delete on
divergence. Several entries in this ledger (S3-2, S3-5, S3-8, S4-2) are corrections of exactly
this kind of stale claim.

---

## Cross-references

- Builder tenets, artifact-flow invariant, scar-tissue defense, Change protocol — `CLAUDE.md`
- Nullifier / durability classification — `.docs/specs/17-persistence-and-storage.md` §17.17,
  `.docs/standards/sdk-common.md` §Stub and Placeholder Policy
- Capability injection and prove-absence —
  `.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md` (**Proposed**)
- Node-is-infrastructure — ADR-053 (`.docs/adrs/phase-2.md:1906`),
  `.docs/specs/10-infrastructure-and-self-hosting.md` §10.17
- Unified construction — ADR-052 (`.docs/adrs/phase-2.md:1834`),
  `.docs/standards/construction.md`
- Pre-rotation custody — ADR-054 (**Proposed**), `.docs/specs/09-security-model.md` §9.7.4.1,
  RFC Discussion #2130
