# SDK Common Standards

Cross-language coding standards for all SCP SDK implementations. Every language-specific standards file references this document. For project structure, FFI strategy, naming conventions, versioning, and conformance testing, see `.docs/scaffold/shared.md`.

## Error Hierarchy

All SDKs implement the same error hierarchy. Language-specific idioms (exceptions, Result types, error interfaces) differ, but the categories are identical.

```
ScpError (root)
├── IdentityError        — DID creation, resolution, key rotation failures
├── ContextError         — Context lifecycle (create, join, leave, close) failures
├── UcanPermissionError  — UCAN capability validation failures (avoids shadowing `builtins.PermissionError` in Python and the global `PermissionError` in TypeScript)
├── CryptoError          — Encryption, decryption, signature failures
├── TransportError       — Network, relay, connection failures
├── OutletError          — Outlet registration, invocation, verification failures
├── ValidationError      — Input validation, schema, parameter failures
├── StorageError         — Persistent-storage operation failures (SCP-STORAGE range)
├── AttestationError     — Device and identity attestation failures (SCP-ATTEST range)
├── McpError             — MCP protocol and tool-invocation failures (SCP-MCP range)
├── GovernanceError      — Context governance proposal and voting failures (SCP-GOV range)
└── EconomyError         — Payment, budget, and economic-policy failures (SCP-ECON range)
```

### Error requirements

- Every error includes a human-readable message and a machine-readable error code
- Error codes are stable across SDK versions (for programmatic handling)
- Errors propagate context: what failed, why, and what to do about it
- Crypto errors never leak key material or internal crypto state in messages

### Error code format

`SCP-{CATEGORY}-{NUMBER}` where category matches the hierarchy above:

| Category prefix | Range |
|-----------------|-------|
| `SCP-IDENT-` | 1000-1999 |
| `SCP-CTX-` | 2000-2999 |
| `SCP-PERM-` | 3000-3999 |
| `SCP-CRYPTO-` | 4000-4999 |
| `SCP-TRANS-` | 5000-5999 |
| `SCP-OUTLET-` | 6000-6999 |
| `SCP-VALID-` | 7000-7999 |
| `SCP-STORAGE-` | 8000-8999 |
| `SCP-ATTEST-` | 9000-9999 |
| `SCP-MCP-` | 10000-10999 |
| `SCP-GOV-` | 11000-11999 |
| `SCP-ECON-` | 12000-12999 |
| `SCP-SAGA-` | 13000-13999 |

### Registered SCP-SAGA- codes (cross-context tool-invocation saga, §6.2.4)

The `SCP-SAGA-` band (`13000-13999`, ADR-049 §3a) is partitioned into
sub-blocks by *which layer* raises the error, so a code is unique to one
distinct condition and `grep`-disambiguates a log line to a single call site.
`check-error-codes.sh` only range-checks the band; uniqueness within the band
is maintained by keeping each distinct error's number disjoint from every other
distinct error's number. When adding a new error, take the next free number
**inside the owning sub-block** — never reuse a number assigned to a different
condition, even across files.

| Sub-block | Owner | Purpose |
|-----------|-------|---------|
| `13000-13009` | `scp-protocol` `cross_context_saga.rs` | Saga-type signing / verification (pure, sync) |
| `13010-13099` | `scp-runtime` saga handler + supervisor FSM | Prepare / Commit / Abort phase coordination |
| `13100-13999` | *(reserved)* | Future cross-context saga families |

Within `13010-13099`, the handler (`actor/handlers/saga.rs`, the per-context
authorization + freshness + Commit-B execute/settle path) holds `13010-13049`,
and the supervisor (`supervisor/supervisor.rs`, the cross-actor FSM driver)
holds `13050-13099`, so the two layers never contend for the same number.

| Code | Layer | Condition |
|------|-------|-----------|
| `SCP-SAGA-13000` | protocol | Canonical preimage construction exceeded the length-prefix ceiling |
| `SCP-SAGA-13001` | protocol | Ed25519 saga signature failed verification |
| `SCP-SAGA-13002` | protocol | Malformed Ed25519 verifying key |
| `SCP-SAGA-13010` | handler | Caller lacks `outlet:interface` capability (outbound) |
| `SCP-SAGA-13011` | handler | Caller not in outbound `allowed_callers` |
| `SCP-SAGA-13012` | handler | `ucan_proof_id` not resolvable in target proof store |
| `SCP-SAGA-13013` | handler | UCAN re-validation failed (confused-deputy re-bind) |
| `SCP-SAGA-13014` | handler | `target_context_id` mismatch |
| `SCP-SAGA-13015` | handler | Inbound policy requires a spending UCAN but none was presented |
| `SCP-SAGA-13016` | handler | Tool not found in target registry |
| `SCP-SAGA-13017` | handler | Input schema specificity floor not met |
| `SCP-SAGA-13018` | handler | Invocation timestamp outside §9.14 skew tolerance |
| `SCP-SAGA-13019` | handler | Invocation nonce already seen in target dedup cache (replay) |
| `SCP-SAGA-13020` | handler | Re-derived chain depth exceeds `max_chain_depth` |
| `SCP-SAGA-13021` | handler | Input does not conform to registered schema |
| `SCP-SAGA-13023` | handler | Per-interface §6.2.0.2 rate limit exceeded |
| `SCP-SAGA-13024` | handler | Per-caller §6.2.0.2 rate limit exceeded |
| `SCP-SAGA-13025` | handler | Caller role not in inbound `allowed_source_roles` |
| `SCP-SAGA-13026` | handler | Per-interface §6.2.0.2 INBOUND rate limit exceeded at Prepare-B |
| `SCP-SAGA-13027` | handler | Configured inbound rate exceeds the cache-eviction-safe ceiling (§6.2.4 sizing-vs-ceiling) |
| `SCP-SAGA-13030` | handler | Commit-B reserve found no staged cross-context invocation |
| `SCP-SAGA-13031` | handler | Commit-B settle found no staged cross-context invocation |
| `SCP-SAGA-13032` | handler | Commit-B tool output is not valid JSON |
| `SCP-SAGA-13033` | handler | Commit-B receipt output JCS canonicalization failed |
| `SCP-SAGA-13034` | handler | Commit-B receipt signing failed |
| `SCP-SAGA-13035` | handler | Commit-B receipt serialization failed |
| `SCP-SAGA-13036` | handler | Divergence-marker signing failed |
| `SCP-SAGA-13037` | handler | Divergence-marker serialization failed |
| `SCP-SAGA-13038` | handler | Saga phase reached the wrong dispatch helper |
| `SCP-SAGA-13050` | supervisor | Initiator is not a member of the named caller context (caller-axis authorize-before-reserve) |
| `SCP-SAGA-13051` | supervisor | Prepare — `CrossContextOutletInvocation` reached `start_saga` without an executor context |
| `SCP-SAGA-13052` | supervisor | Prepare-A — caller context is not a co-resident actor |
| `SCP-SAGA-13053` | supervisor | Prepare-B — target context is not a co-resident actor |
| `SCP-SAGA-13054` | supervisor | Commit — `CrossContextOutletInvocation` reached `start_saga` without an executor context |
| `SCP-SAGA-13055` | supervisor | Commit-B — target context is not a co-resident actor |
| `SCP-SAGA-13056` | supervisor | Commit-B — executor already consumed but no output stashed (coordinator bug) |
| `SCP-SAGA-13057` | supervisor | Commit-B — cross-context tool executor failed |
| `SCP-SAGA-13058` | supervisor | Commit-B — tool output is not serializable |
| `SCP-SAGA-13059` | supervisor | Commit-A — no held reservation and witness absent (Commit-A did not durably land) |
| `SCP-SAGA-13060` | supervisor | Commit-B settle — target context is not a co-resident actor |
| `SCP-SAGA-13061` | supervisor | Commit-A — caller context is not a co-resident actor |
| `SCP-SAGA-13062` | supervisor | No established interface for the (caller, target, tool) triple (target-axis authorize-before-reserve) |
| `SCP-SAGA-13063` | supervisor | Commit — target receipt missing for saga |
| `SCP-SAGA-13064` | supervisor | Commit — target receipt signature invalid |
| `SCP-SAGA-13065` | supervisor | `NeedsRepair` terminal — Commit-retry exhausted; saga diverged and requires operator repair (carries `saga_id`) |
| `SCP-SAGA-13066` | supervisor | `Busy` terminal — participant context set overlaps an in-flight saga (per-participant-context-set gating, §5.15.4) |
| `SCP-SAGA-13067` | supervisor | Generic saga terminal abort with no specific sub-code (e.g. Prepare-phase 30s timeout, journal I/O failure) — the message string carries the specific cause |
| `SCP-SAGA-13068` | supervisor | `ParticipantUnavailable` — Prepare-phase abort: participant actor unavailable to complete the Prepare exchange — inbox closed/terminated (transient, retryable) |

### Registered SCP-OUTLET- codes: the 6100-6199 sub-block (outlet error taxonomy, §5.4.4)

Within the `SCP-OUTLET-` band (`6000-6999`) the **`6100-6199` sub-block** is the
compact outlet-error taxonomy defined by spec §5.4.4. Unlike the free-form
remainder of the band, this sub-block is a **registry**: the single source of
truth is `crates/scp-protocol/src/context/outlets/error_codes.rs`, where every
allocated code is a `pub const CODE_* = "SCP-OUTLET-61NN"` constant (collected in
the `ALL_CODES` array). The taxonomy is deliberately *compact* — roughly one to
two codes per class — because fine-grained distinctions are carried by a
dot-separated **slug**, not by minting new codes. New failure conditions become
new slugs under an existing code; a new *code* is minted only when a condition
needs a distinct machine-actionable number.

Every `OutletError` carries exactly one of **eight** root classes
(`OutletErrorClass`, defined in `outlets/errors.rs`). Each class owns a
contiguous decimal sub-range inside `6100-6199`:

| Class | Code sub-range | Meaning |
|-------|----------------|---------|
| `Protocol` | `6100-6109` | Registration, validation, classification, session-lifecycle violations |
| `Authorization` | `6110-6119` | UCAN / caveat / capability / attenuation / amplification denials |
| `Input` | `6120-6129` | Input schema, size, type, range violations |
| `Execution` | `6130-6139` | Handler panic, timeout, non-determinism, credit / stream exhaustion, cancel-ack timeout |
| `Output` | `6140-6149` | Output schema, size, serialization violations |
| `Economic` | `6150-6159` | Budget, insufficient funds, adapter failure, pricing, escrow overflow |
| `Transport` | `6160-6169` | Relay unavailable, cross-context bridge failure, rate limiting, concurrency caps |
| `Governance` | `6170-6179` | Deregistration, suspension, ceiling exceeded, active consequence |

The reserved tail `6180-6199` and every intra-class gap (`6111`, `6134`, …) are
**unallocated**: `error_code_to_class`, `error_code_to_default_slug`, and
`error_code_to_retry_policy` all return "none" for them. Reserving the gaps lets
a future condition that genuinely needs its own code take a stable number
without renumbering. The one cross-class slug is `protocol.interface-spam-cost`,
which carries a `protocol.` prefix but maps to the **`Economic`** class (code
`SCP-OUTLET-6150`) — the fee-insufficient rejection is economic, but the rule
lives at the protocol layer (§6.2.0.1). See spec §5.4.4 for the authoritative
per-code default-slug and retry-policy table.

**Rust code MUST reference the `CODE_*` constants — never a raw
`"SCP-OUTLET-61NN"` string literal.** The registry file is the single place a
raw sub-block literal may appear (it defines the consts, and its `#[cfg(test)]`
module exercises reserved ranges). Everywhere else in Rust — production or test
— the code is named via its `CODE_*` constant. This gives one source of truth
and makes the gate sound-by-construction without any source lexing.

`scripts/check-error-codes.sh` **Phase 4** (SCP-OUT-030) enforces the sub-block.
It is deliberately split by language so each half is sound and trivial:

- **(0) Allocated set.** Extract the allocated `6100-6199` codes from the
  registry's `CODE_*` const definitions (a positive, closed-by-construction
  whitelist).
- **(1a) Rust — no raw literals outside the registry.** Any raw double-quoted
  `"SCP-OUTLET-61NN"` literal in *any* `.rs` file except the registry — test or
  not — is a violation. Because no raw literal exists elsewhere, the check needs
  **no** `#[cfg(test)]`/comment discrimination (no brace-counting, no lexer): it
  is a plain grep. A rare legitimate exception (a code named in a block/doc
  comment, or a fixture that genuinely needs a reserved literal) opts out with
  an `SCP-CODE-OK:` marker on the line.
- **(1b) SDK bindings — allocated-set membership.** The language SDKs
  (Kotlin/Swift/Python/TypeScript) legitimately *restate* the codes as string
  literals and cannot reference the Rust consts, so every restated literal must
  be in the allocated set. This is a genuine cross-language drift check that
  `cargo test` cannot provide. SDK **test** files are excluded by path glob
  (never by comment/brace parsing).
- **(3) Class list.** The 8 `OutletErrorClass` variants are printed on every run
  for operator legibility. This is a printout only.

The "every allocated code maps to a class" invariant is **not** re-checked in
shell (parsing a compile-time `match` with awk would be redundant and could only
rot). It is enforced soundly in Rust, in `error_codes.rs`: the exhaustive
`error_code_to_class` match, plus two unit tests —
`all_codes_lists_exactly_the_defined_code_constants` (every defined `CODE_*` is
in `ALL_CODES`) and `every_allocated_code_resolves_class_default_slug_retry_policy`
(every `ALL_CODES` entry resolves to a class/slug/retry) — together pin it at
compile/test time.

Adding a code is therefore a single edit: add its `pub const CODE_*` to the
registry (which, by construction, expands the allowed set) and wire it into
`error_code_to_class`. No gate edit is required.

### Registered SCP-CTX- / SCP-CRYPTO- / SCP-TRANS- / SCP-VALID- codes (native registry vs. browser participant)

The native FFI-common registry (`crates/scp-ffi/common/src/error_codes.rs`) is
the Rust materialization of the per-number meanings for the **native** bridges
(`PyO3`, napi-rs, `UniFFI`). The browser participant surface
(`crates/scp-client-wasm/src/error.rs`, plus the `@limn-works/scp-ts-wasm` SDK
wrapper) **cannot** import that registry — the ADR-057 wasm/tokio fence keeps
`scp-client-wasm` off `scp_ffi_common` — so it hand-writes its
`[SCP-{CATEGORY}-{NUMBER}]` literals, which MUST agree with this ledger.

**Scope of the guarantee (be precise — #2144).** Error codes are emitted from
FIVE surfaces: the native registry, the Swift SDK (`bindings/swift/**`), the
Kotlin SDK (`bindings/kotlin/**`), the ts-native SDK (`bindings/typescript/src/**`),
and this ts-wasm surface. `scripts/check-error-codes.sh` machine-checks band
ranges and native-registry uniqueness, but its Phase-2 cross-surface collision
detector has a documented KNOWN LIMITATION: it does **not** inspect the
SDK-wrapper literals (Swift/Kotlin/TS/Python), which "must be reviewed manually
against error_codes.rs to prevent collisions." A **full cross-surface
`SCP-<band>-<n>` union** was computed by hand across all five surfaces, and every
**browser-owned** code registered below was assigned a number **absent from that
union** — i.e. cross-surface-unique as of this change. The ONE deliberate
exception is `SCP-CTX-2095`, whose meaning (pseudonym-registry-empty) is
identical on native + Swift + Kotlin + ts-native + this surface.

This is NOT a claim that *every* SCP code has one meaning across all surfaces:
pre-existing cross-language overlaps predate and are out of scope for #2144 (e.g.
`SCP-VALID-7010`/`7011`/`7012` mean UCAN-validation in the native registry but
are reused by the Swift/ts-native SDKs for their own validation conditions, and
`SCP-CTX-2003` is overloaded — see below). #2144 fixes only the browser
participant's own allocations so they stop colliding; the broader cross-language
reconciliation — auditing the full cross-surface namespace and strengthening the
compliance mechanism (`check-error-codes.sh` Phase-2 does not machine-check
SDK-wrapper or match-arm literals; see its documented KNOWN LIMITATION) — is
tracked in discussion #2208, not addressed here.

This table documents the allocation; it is not a new enforcement mechanism. The
scp-client-wasm mapping is additionally guarded by an exhaustive positive
allowlist test in `crates/scp-client-wasm/src/error.rs` (which also pins the
`lib.rs` direct-emitter literals via the shared `WASM_INPUT_VALIDATION_CODE`
constant).

| Code | Owner | Condition |
|------|-------|-----------|
| `SCP-CTX-2001` | native FFI-common registry (also Swift/Kotlin/ts-native SDKs) | Context operation failed (generic) — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CTX-2002` | native FFI-common registry | Context not found — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CTX-2003` | native FFI-common registry — **cross-surface OVERLOADED (pre-existing, out of #2144 scope)** | native = "Context already exists"; Swift = "message stream already active"; Kotlin = "not a member". NOT reused by `scp-client-wasm` precisely because of this overload |
| `SCP-CTX-2004` | native FFI-common registry | Context creation failed — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CTX-2005` | native FFI-common registry | Context join failed — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CTX-2040` | native FFI-common registry | Context operation error (native `CTX_2040`) — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CTX-2082` | `scp-client-wasm` (browser participant) | Unknown / not-held context (`ClientError::UnknownContext`) |
| `SCP-CTX-2083` | `scp-client-wasm` (browser participant) | Context already exists in this client (`ClientError::ContextAlreadyExists`) — browser-owned; does NOT reuse the overloaded native `2003` |
| `SCP-CTX-2084` | `scp-client-wasm` (browser participant) | Unsupported membership change — a received Commit removes a member (out of ADR-057 Slice 2 convergent scope) (`ClientError::UnsupportedMembershipChange`) |
| `SCP-CTX-2085` | `scp-client-wasm` (browser participant) | Driver invariant violation / malformed driver argument (`ClientError::Driver`) |
| `SCP-CTX-2086` | `scp-client-wasm` (browser participant) | No retained pending join material — join must reconstruct from the durable snapshot (`ClientError::NoPendingJoinMaterial`). (Sits at 2086 because 2080/2081 are taken by the Kotlin SDK.) |
| `SCP-CTX-2095` | native FFI-common registry + Swift + Kotlin + ts-native + `scp-client-wasm` (**shared meaning, all surfaces**) | Pseudonym registry empty — peers have not announced routing IDs (§9.10.4); native `ContextError::PseudonymRegistryEmpty`, browser `ClientError::PseudonymRegistryEmpty` |
| `SCP-CRYPTO-4010` | native FFI-common registry (also Kotlin SDK) | MLS group create error — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-CRYPTO-4020` | `scp-client-wasm` (browser participant) | Sender-key (§9.16) layer failure (`ClientError::SenderKey`) |
| `SCP-CRYPTO-4030` | `scp-client-wasm` (browser participant) | Event-log append / proof failure (`ClientError::EventLog`) |
| `SCP-CRYPTO-4040` | `scp-client-wasm` (browser participant) | Convergent committer-timestamp AAD failure — missing or malformed (ADR-057) (`ClientError::Mls(ConvergentTimestampMissing \| ConvergentTimestampMalformed)`) |
| `SCP-CRYPTO-4041` | `scp-client-wasm` (browser participant) | Generic MLS group operation failure — create/add/join/encrypt/decrypt/commit catch-all (`ClientError::Mls(_)`) |
| `SCP-TRANS-5005` | `scp-client-wasm` (browser participant) | Injected outbound `Socket`/`RelaySink` failed to enqueue a relay frame — WebSocket closed / JS exception (`ClientError::Transport`) |
| `SCP-TRANS-5010` | native FFI-common registry (also Kotlin SDK) | Transport subscription error — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-VALID-7010` | native FFI-common registry (**pre-existing cross-language overlap**: reused by Swift/Kotlin/ts-native SDKs for their own validation conditions) | UCAN token validation error — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-VALID-7011` | native FFI-common registry (**pre-existing cross-language overlap** with Swift/Kotlin/ts-native) | UCAN mint validation error — native meaning; NOT emitted by `scp-client-wasm` |
| `SCP-VALID-7028` | `scp-client-wasm` (browser participant) | Browser participant wire/input (de)serialization or byte-shape validation failure — `ClientError::Codec` (MLS wire codec) plus the wasm free-function input validators (`requestId`/`operatorPk`/`caveatsBinding` length, `OutletStreamChunk` decode, event-log & wrapping-key MessagePack serde). Emitted via the shared `WASM_INPUT_VALIDATION_CODE` constant |
| `SCP-VALID-7029` | `scp-client-wasm` (browser participant) | Frame content type did not match its relay channel — §9.10.4 mis-routed frame, defense-in-depth (`ClientError::ChannelContentMismatch`) |
| `SCP-VALID-7025` | `@limn-works/scp-ts-wasm` (browser SDK wrapper) | wasm module not initialized — `initScp()` (or `ScpBrowserClient.connect`) must be awaited before constructing/using a client |
| `SCP-VALID-7026` | `@limn-works/scp-ts-wasm` (browser SDK wrapper) | `WebSocketRelaySocket` (the managed transport) passed to `create()` instead of `ScpBrowserClient.connect()` — it would be left unattached |

The browser participant reuses **only** `SCP-CTX-2095` from the shared band —
its condition is semantically identical on all five surfaces. Every other
browser condition took a distinct browser-owned number (`2082-2086`,
`4020/4030/4040/4041`, `5005`, `7028/7029`, and the SDK-wrapper `7025/7026`),
each verified absent from the native/Swift/Kotlin/ts-native union so no
browser-owned code string collides with any other surface as of this change.
Notably `SCP-CTX-2083` (already-exists) does **not** reuse native `2003`, because
`2003` is already overloaded across native/Swift/Kotlin.

### Registered SCP-STORAGE- codes

The `SCP-STORAGE-` band (`8000-8999`) is shared across the storage-selection
layer and several platform/adapter storage backends, so a code is unique to one
distinct condition. `8000` is the storage-selection error (§17.6 "Storage
Selection Is Mandatory"). The remaining numbers are allocated per-owner below;
when adding a new storage code, take the next free number **inside the owning
sub-block** — never reuse a number assigned to a different backend, even across
languages. (This table is documentation of the existing allocation, not a new
enforcement mechanism.)

| Code | Owner | Condition |
|------|-------|-----------|
| `SCP-STORAGE-8000` | selection layer (all bridges) | No storage backend selected (mandatory selection missing) |
| `SCP-STORAGE-8001` | `scp-kt-android` `AndroidStorage` | Storage key not found |
| `SCP-STORAGE-8002` | `scp-kt-android` `AndroidStorage` | Storage operation failed |
| `SCP-STORAGE-8003` | `scp-kt-android` `AndroidStorage` | Key derivation failed |
| `SCP-STORAGE-8010` | `scp-client-wasm` (browser participant) | Injected `Storage` backend I/O fault (`get`/`put`/`delete`/`list_keys`) |
| `SCP-STORAGE-8011` | `scp-client-wasm` (browser participant) | Corrupt snapshot — bad decode / unknown version / context-id-vs-key mismatch / §9.9.3 checkpoint mismatch |
| `SCP-STORAGE-8012` | `scp-client-wasm` (browser participant) | Snapshot / pending-join blob belongs to a different identity (owner-DID mismatch) |
| `SCP-STORAGE-8013` | `scp-client-wasm` (browser participant) | Context poisoned — a persist failed after the in-memory ratchet advanced; reconstruct from the last durable snapshot |

The browser participant codes (`8010-8013`) start at `8010` specifically to avoid
colliding with the Android backend's `8001-8003`, which were allocated first.

### Registered SCP-ATTEST- codes

| Code | Description |
|------|-------------|
| `SCP-ATTEST-9001` | Device attestation provider call failed (Play Integrity API error) |
| `SCP-ATTEST-9006` | Attestation verification requires raw JSON, which is absent |
| `SCP-ATTEST-9010` | Identity link attestation create bridge function not yet exported |
| `SCP-ATTEST-9011` | Identity link attestation list bridge function not yet exported |
| `SCP-ATTEST-9012` | Identity link attestation remove bridge function not yet exported |
| `SCP-ATTEST-9013` | Identity link attestation renew bridge function not yet exported |
| `SCP-ATTEST-9014` | Identity link attestation verify bridge function not yet exported |
| `SCP-ATTEST-9015` | Attestation JSON bytes are not valid UTF-8 |
| `SCP-ATTEST-9016` | Attestation list JSON bytes are not valid UTF-8 |
| `SCP-ATTEST-9017` | Failed to re-serialize attestation to UTF-8 JSON |
| `SCP-ATTEST-9018` | Cryptographic-class verification method not verifiable via browser fetch |

### SCP-IDENT-1017 and its cross-bridge contract

This section documents `SCP-IDENT-1017` (missing signing custody) and the
per-bridge contract for how that one condition surfaces across the bridges. It
is **not** the full registry of `SCP-IDENT-` codes — other `SCP-IDENT-` codes
exist (for example, the pseudonym-derivation family `SCP-IDENT-1054`..`1057`)
and are documented with their own features.

| Code | Description |
|------|-------------|
| `SCP-IDENT-1017` | Operation requires retained signing custody (identity loaded externally with no retained custody, or handle is sign-only). Surfaced by handle-borne bridges for UCAN **mint** (NAPI + UniFFI), event-log **checkpoint** (NAPI + UniFFI), and **broadcast publish** (NAPI + UniFFI). UCAN **delegate** surfaces `SCP-IDENT-1001`, not `SCP-IDENT-1017`, on every bridge: PyO3, NAPI, and UniFFI each read a delegator's key from their identity registry, because a delegation signs with a delegator's own key and never with a context creator's key, so a missing delegator is a registry miss. |

**Cross-bridge note.** PyO3 surfaces the analogous failure as `SCP-IDENT-1001` (registry-based key resolution per ADR-048 §7 — a registered identity always retains custody, so the "registered-but-no-custody" condition cannot arise); NAPI's and UniFFI's UCAN **delegate** paths are registry-based for that same structural reason and surface `SCP-IDENT-1001` as well (see that table above). On all three bridges (PyO3, NAPI, and UniFFI → Swift / Kotlin / TS-via-NAPI), consumers that catch the `IdentityError` category are safe for the missing-custody condition; only code that switches on the exact code string must account for the per-bridge code splits described above.

### Custody strings and their cross-bridge contract

`identity_create` takes a custody string naming the backend that holds the new
identity's private keys. §3.2.2 of the identity spec, the custody vocabulary, decides
which values that string carries, and this section restates nothing that section
decides.

| Value | Backend it selects |
|---|---|
| `encrypted_file` | The on-disk key store SCP implements, which derives an AES-256 key from a passphrase with Argon2id and encrypts each key entry under AES-256-GCM |
| `os_keystore` | The operating system's own key store, which SCP reaches through the platform key-custody callback an SDK consumer supplies |

The vocabulary holds no third value. §3.2.2 of the identity spec states that a shipped
build answers every other string with a typed error. A build compiled with a bridge's
`testing` cargo feature additionally accepts the raw string `in_memory`, which reaches a
test-only in-memory key store; §3.2.2 of the identity spec states that a shipped build
rejects that string with the typed code `SCP-IDENT-1008`, and that no SDK custody type
spells it.

**The words `platform`, `software`, `file`, and `hardware` name no custody value.** An
SCP build from before this vocabulary landed accepted `file` for the encrypted key file
and carried `platform` and `software` in its SDK custody types. A caller who passes any
of those four strings to a current build reads a typed error instead of reaching a key
store. §3.2.2 of the identity spec states why the first two cannot name a backend: two
published specifications give `platform` two different meanings in key handling, and
`software` states a property a backend lacks rather than naming a store.

**`os_keystore` states which store holds the key, and states nothing about hardware
isolation.** On Apple platforms the operating system's key store holds SCP's keys in
software. `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:217`–`:221` states
the reason: "Apple's Secure Enclave only supports P-256 (NIST P-256 / secp256r1) key
operations. SCP uses Ed25519 for signing and X25519 for key agreement; neither is
supported by the Secure Enclave. All SCP identity keys on Apple platforms are therefore
software-backed via Keychain."

**A bridge that cannot reach a real platform key store fails closed.** When a caller
names `os_keystore` and the bridge holds no platform key-custody callback, the bridge
returns a typed error. It does not fall back to `encrypted_file`, and it does not fall
back to an in-memory store. §3.2.2 of the identity spec states that rule.

**Custody is a required argument on every SDK, and no SDK carries a default.** Key
custody is a security-relevant choice, and the agent-first API design tenet of
`CLAUDE.md` forbids an SDK making it for a caller. The Swift and Kotlin entry points
take a custody type rather than a bare string, so a caller cannot pass a value the type
already rejects.

**The substrate report is a separate vocabulary, and no caller passes one of its
values.** `scp_platform::CustodyType` (`crates/scp-platform/src/traits.rs:223`–`:232`)
names where a key already sits — `InMemory`, `Hardware`, and `Software` — and
`KeyCustody::custody_type` returns one of those three. A caller selects a backend with
the two values in the table above, never with these three, and §3.2.2 of the identity
spec governs neither this report nor the values a DID document publishes.

**Reading a custody type back.** `Identity::custody_type()` hands back the label the
identity was created under, and hands back `"callback"` for an identity created through
`identity_create_with_custody`. `"callback"` names the injection rather than the key
store, because the bridge cannot observe which substrate the injected provider uses, and
no SDK custody type spells it.

**One further gap, independent of custody.** Every create path on every bridge returns
`SCP-IDENT-1059` in a shipped build, because no production `PreRotationCustody` backend
is wired (ADR-062, capability injection and prove-absent dev backends). Closing the
custody gap does not close that one, and closing that one does not close the custody
gap.

## Stub and Placeholder Policy

Code that does not fully implement its documented contract (acceptance criterion, ADR spec, or trait method) is a **stub**. Stubs are tolerated during phased implementation but must be traceable to the planning system.

### Requirements

1. **Every stub must reference a PRD story ID** in its doc comment or inline comment. The story must have acceptance criteria that, when met, will remove the stub. Example: `// Stub — see SCP-217 for storage wiring`.
2. **No silent stubs.** A function that returns a placeholder value (e.g., hardcoded default, empty result, reconstructed-from-args) without documenting the gap is a bug, not a stub.
3. **Stories marked "done" must have zero stubs** against their acceptance criteria. If a criterion is unmet, the story status must be `in_progress` or `pending` with a `blockedBy` reference.

### Enforcement

| Language | Mechanism |
|----------|-----------|
| Rust | `clippy::todo = "deny"`, `clippy::unimplemented = "deny"` (compile-time). Inline `// Stub —` comments reference story IDs (review-time). |
| Kotlin | detekt `ForbiddenComment` rule with `TODO`, `FIXME`, `HACK` values (CI). |
| Python | ruff `FIX` rules (`FIX001` through `FIX004`) for `TODO`, `FIXME`, `HACK`, `XXX` (CI). |
| Swift | SwiftLint `todo` rule (CI). |
| TypeScript | ESLint `no-warning-comments` rule (CI). |

All languages: PR review must verify that any function described as a stub in code comments has a corresponding PRD story with `status != "done"`.

### No dev/test-only stand-in may mask a missing production implementation

A stub is honest about its gap on its own path. It is a **separate, forbidden failure** for a stub — or any production code path — to reach for a **dev/test-only construct** to *appear* functional in production. Prohibited on every shipped path:

- A **security nullifier** — in-memory/plaintext key custody, an always-succeeds attestation or certificate verifier, a non-resolving or in-memory DID/DHT resolver, an in-memory pre-rotation recovery custody — used because the real backend isn't built yet.
- A **`#[cfg(test)]`- or `testing`-feature-gated type**, an in-memory/no-op adapter, or a `*::testing::*` construct constructed on a production create/run path.
- A **placeholder value** — hardcoded default, empty result, `None`/`null`/`""`, or a value reconstructed from arguments — standing in for data that a real implementation would produce.

**The rule:** if the real implementation is not ready, the capability **fails closed** — return a typed error, or produce the honest protocol-supported absent state (e.g., an identity created with *no* recovery commitment rather than one backed by an in-memory nullifier). It does **not** silently fall back to the dev stand-in. A dev stand-in that ships in production emits a *false guarantee* — callers believe a security property holds when it does not — which is strictly worse than the capability being honestly absent, because absence is detectable and a nullifier lies.

**Deferral boundary:** deferring the *real backend* to a tracked workstream (issue/RFC) is legitimate. Shipping a dev stand-in *for it* in the interim is not. The two are independent: sever the nullifier now (make it test-harness-only, fail closed in prod); build the real backend on its own schedule.

**Mechanical enforcement:** the shipped-feature-graph prove-absence gate (per ADR-062 / spec §17.17) asserts `resolved-feature-set(artifact) ⊆ an allowlist of durability-only + real-backend features` and admits **zero nullifier features — no exceptions**. There is no "documented," "tracked," or "legible" allowlisted nullifier edge; a tracked deferral of the real backend does not earn one. Durability-only in-memory arms (state-loss only, no nullified security property — e.g. in-memory storage/push) remain legitimate *explicitly-selected* runtime options and are the only in-memory constructs the allowlist admits. See spec §17.17 for the durability-only-vs-nullifier classification.

## Async Patterns

All SCP SDK operations involving I/O (network, storage, crypto operations) are async. Each language uses its native async mechanism.

| Language | Async mechanism | Runtime | Sync wrapper pattern |
|----------|-----------------|---------|----------------------|
| Rust | `async fn` → `Future` | tokio | `tokio::runtime::Runtime::block_on()` |
| Python | `async def` → coroutine | asyncio | Background thread via `run_coroutine_threadsafe()` (see `python.md`) |
| TypeScript | `async function` → `Promise` | Event loop (browser/Bun/Node) | N/A (always async) |
| Swift | `async` → structured concurrency | Swift concurrency | `Task { await ... }.value` (rare) |
| Kotlin | `suspend fun` → coroutine | kotlinx.coroutines | `runBlocking { }` |
| Go | Synchronous with channels | goroutines | N/A (synchronous API, channels for streaming) |
| C# | `async Task<T>` | .NET task scheduler | `.GetAwaiter().GetResult()` (rare) |
| Java | `CompletableFuture<T>` | ForkJoinPool / virtual threads | `.get()` / `.join()` |

### Streaming return types

`Context.receive()` (and equivalents) returns a language-appropriate async stream. See `.docs/scaffold/shared.md` §Streaming Types for the full mapping. Summary:

| Language | `receive()` return type |
|----------|------------------------|
| Rust | `Pin<Box<dyn Stream<Item = Message> + Send>>` |
| Python | `AsyncIterator[Message]` |
| TypeScript | `AsyncIterable<Message>` |
| Swift | `AsyncSequence` |
| Kotlin | `Flow<Message>` |
| Go | `<-chan Message` |
| C# | `IAsyncEnumerable<Message>` |
| Java | `Flow.Publisher<Message>` (Reactive Streams) |

## Resource Lifecycle

SCP objects hold crypto state (MLS groups, key material, WebSocket connections) that must be properly released. Each language uses its idiomatic resource management pattern.

| Language | Pattern | Applied to |
|----------|---------|------------|
| Rust | `Drop` trait | `ContextHandle`, `Identity`, `TransportManager` |
| Python | `async with` (context manager) | `Context`, `Identity`, transport connections |
| TypeScript | `using` / `Symbol.dispose` (Explicit Resource Management) | `Context`, `Identity` |
| Swift | `deinit` + explicit `close()` | `Context`, `Identity` |
| Kotlin | `use { }` / `Closeable` | `Context`, `Identity` |
| Go | `defer ctx.Close()` / `io.Closer` | `Context`, `Identity` |
| C# | `await using` / `IAsyncDisposable` | `Context`, `Identity` |
| Java | `try-with-resources` / `AutoCloseable` | `Context`, `Identity` |

### Lifecycle invariant

When a resource goes out of scope or is disposed:
1. Leave any active contexts (sends `MemberLeft` event)
2. Destroy local key material (sender keys, MLS state)
3. Close transport connections
4. Flush pending events to the event log

Destruction of key material is immediate and irreversible. This is by design — SCP's security model depends on timely key destruction.

### Cleanup error handling

If any cleanup step fails (e.g., network unreachable when leaving a context), the resource MUST still complete local cleanup (key destruction, handle release). Errors during cleanup are logged but never propagated as exceptions — callers must not be penalized for disposing resources. The invariant: after dispose returns, all local state is released regardless of remote operation outcomes.

## Concurrency Model

All public handle types (`Identity`, `ContextHandle`/`Context`, `TransportManager`) are safe to share across threads and tasks. Individual operations are serialized internally — concurrent sends on the same context are safe and deliver in call order.

| Language | Guarantee | Mechanism |
|----------|-----------|-----------|
| Rust | `Send + Sync` | Interior `Arc<Mutex<_>>` or `Arc<RwLock<_>>` on mutable state |
| Python | Safe across `asyncio` tasks on the same event loop | GIL + interior locking in Rust core via PyO3 |
| TypeScript | Single-threaded event loop; safe across concurrent promises | N/A (no true concurrency) |
| Swift | `Sendable` | Actor isolation or `@unchecked Sendable` with interior locking |
| Kotlin | Safe across coroutines | Interior `Mutex` in Rust core via UniFFI |
| Go | Safe for concurrent use from multiple goroutines | Interior locking in Rust core via cgo |
| C# | Thread-safe | Interior locking in Rust core via P/Invoke |
| Java | Thread-safe | Interior locking in Rust core via JNA |

**Invariant:** No SDK user should ever need an external lock to use SCP types safely. If a data race is possible without user-side synchronization, the SDK has a bug.

## Context Creation

Context creation has two paths: template-based (primary) and explicit params (advanced). Both produce identical `ContextHandle` objects. See spec §5.12 for protocol-level template definitions.

Construction follows the unified config-object pattern (`.docs/standards/construction.md`, ADR-052): all five SDKs — Rust included — pass a single `ContextConfig` whose `creation: ContextCreation` field makes the template-vs-explicit choice a required enum (`Template { template, peer }` | `Explicit { ceiling, roles, governance, memory_scope }`). The previous Rust fluent `create_context().template().build()` builder is replaced so that every language uses the same options-object shape.

### Template-based creation (primary path)

All SDKs expose template-based context creation as the default. The template handles parameter selection; the caller provides only what varies (peer, TTL, tools for templates that allow them).

> **Bilateral `peer` and the invitation step.** Supplying `peer` names the counterparty to invite. The invitation/Welcome-delivery that actually adds the peer is delivered by a higher SDK layer; the core creation entry builds only the creator's local context. Until invitation delivery is wired, a `peer`-bearing config is **rejected loud** at the core entry (a typed `BilateralPeerNotSupported` error) rather than silently accepted-and-ignored — a supplied field is never dropped. The example below shows the target invitation surface; create with `peer` omitted to obtain the creator-local context today.

```
// Rust
let ctx = sdk.create_context(ContextConfig {
    ttl: Some(Duration::from_secs(300)),
    ..ContextConfig::defaults(ContextCreation::Template {
        template: Template::BilateralEphemeral,
        peer: Some(bob_did.clone()),
    })
}).await?;

// Python
ctx = await sdk.create_context(
    template="bilateral-ephemeral",
    peer=bob_did,
    ttl=timedelta(minutes=5),
)

// TypeScript
const ctx = await sdk.createContext({
    template: "bilateral-ephemeral",
    peer: bobDid,
    ttl: { minutes: 5 },
});

// Swift
let ctx = try await sdk.createContext(
    template: .bilateralEphemeral,
    peer: bobDID,
    ttl: .minutes(5)
)
```

### Explicit params (advanced path)

For contexts that don't fit a well-known template. The caller specifies all parameters. No template ID is attached to the context metadata.

```
// Rust
let ctx = sdk.create_context(ContextConfig {
    ttl: Some(Duration::from_secs(3600)),
    tools: vec![recipe_search, nutrition_lookup],
    ..ContextConfig::defaults(ContextCreation::Explicit {
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite, Capability::OutletQueryAll, Capability::OutletCallAll],
        roles: vec![admin_role, member_role, observer_role],
        governance: Governance::SingleAdmin,
        memory_scope: MemoryScope::Summary,
    })
}).await?;
```

### Bilateral shorthand

For bilateral templates (`bilateral-ephemeral`, `bilateral-persistent`, `coordination`), the SDK accepts a peer DID and handles the invitation internally:

1. Creates the context (MLS group, sender key, event log)
2. Bundles context metadata + MLS Welcome message into a single transport delivery
3. Sends to the peer
4. Returns the `ContextHandle` immediately (context is `Active` from the creator's perspective)

The peer receives everything needed to evaluate and join in one message. If the peer has an auto-accept policy that matches, the join is automatic. If not, the peer's agent is prompted.

### Auto-accept policies

SDKs implement local auto-accept policy evaluation for incoming context invitations. Policies are configured per-identity and stored locally (never transmitted).

```
// Rust
sdk.set_auto_accept_policy(AutoAcceptPolicy {
    template: Template::BilateralEphemeral,
    from: TrustRequirement::KnownDid(vec![alice_did]), // explicit allowlist — the only trigger
    max_ttl: Some(Duration::from_secs(600)), // ≤10 minutes
    rate_limit: Some(Rate::per_hour(5)),     // Max 5 auto-accepts/hour
});

// Python
sdk.set_auto_accept_policy(
    template="bilateral-ephemeral",
    trust=TrustRequirement.known_did([alice_did]),  # explicit allowlist — the only trigger
    max_ttl=timedelta(minutes=10),
    rate_limit=Rate.per_hour(5),
)
```

**No default:** absent an explicit, human-configured policy, every invitation prompts the agent/human (default-deny). `known_did` is the only auto-accept trigger; co-membership and discoverability are not trust signals.

**Hard constraint (all SDKs, non-overridable):** Auto-accept policies NEVER apply to contexts whose ceiling includes any outlet-related capability (`OutletQueryAll`, `OutletQuery(_)`, `OutletCallAll`, `OutletCall(_)`, `OutletRegister`). Outlet-bearing contexts always require explicit confirmation. This is enforced in the SDK and cannot be disabled by configuration.

### Auto-accept persistence

Auto-accept policies are persisted via the SDK's `Storage` trait (same backend as protocol state). Key convention: `policy/{identity_did}/auto_accept`. Policies are device-local — cross-device sync is not supported (each device configures independently). Policies are never transmitted over the network. On SDK initialization, policies are loaded from storage and applied to the invitation evaluation pipeline.

### Invitation evaluation

When the SDK receives a context invitation, it evaluates in this order:

1. **Template check.** If the invitation includes a template ID, validate that the context params match the template exactly. Reject if params don't match (prevents template spoofing — claiming `bilateral-ephemeral` but including tool capabilities).
2. **Auto-accept check.** If a matching policy exists, evaluate trust requirement, TTL cap, and rate limit. If all pass, join automatically.
3. **Agent prompt.** If no auto-accept policy matches, surface the invitation to the agent/human for decision. The invitation includes full context metadata (§5.7) plus the template ID if present.

### Standing contexts (contact graph)

Standing bilateral contexts serve as the real-time communication primitive (spec §5.12.4). The SDK manages them as persistent infrastructure — the agent's contact list.

```
// Rust — get or create a standing context with a peer
let channel = sdk.standing_context(&bob_did).await?;
// Returns existing bilateral-persistent context if one exists,
// creates one if not. Idempotent.

// NOTE: this caller is the INITIATOR, so this send succeeds. It is the
// *peer's* send that fails-closed: a side that obtained its replica via
// Welcome-join (the common non-initiating peer, or a collision-losing
// did_hi) cannot send until the Phase-2E spawn-from-Welcome entrypoint
// lands (spec §5.15.8). The initiator side here is unaffected.
channel.send("Are you available for the 3pm sync?").await?;

// Python
channel = await sdk.standing_context(bob_did)
# initiator-side send (succeeds); the *peer's* Welcome-joined send
# fails-closed until Phase-2E (spec §5.15.8)
await channel.send("Are you available for the 3pm sync?")

// Swift
let channel = try await sdk.standingContext(with: bobDID)
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
try await channel.send("Are you available for the 3pm sync?")

// TypeScript — NOTE: the return shape MUST NOT add a `created: bool` /
// `peer_joined` discriminant; it is identical to every other binding.
const channel = await sdk.standingContext(bobDid);
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
await channel.send("Are you available for the 3pm sync?");

// Kotlin
val channel = sdk.standingContext(bobDid)
// initiator-side send (succeeds); the *peer's* Welcome-joined send
// fails-closed until Phase-2E (spec §5.15.8)
channel.send("Are you available for the 3pm sync?")
```

**Semantics of `standing_context`** (see spec §5.15.8 for the normative contract):

1. Check local state for an existing `bilateral-persistent` context with this peer DID.
2. If found and `Active`, return it. Zero network cost — instant.
3. If not found, create one (`bilateral-persistent` template), dispatch the Welcome, return the handle. First message queues until the peer joins.
4. If a prior handle was reaped or never joined, it is transparently **auto-revived** under the deterministic `derived_context_id` (spec §5.15.8, ADR-049 §10) — *not* a fresh create. A dangling/reaped handle never surfaces an error.

**`Ok` does not mean "peer joined."** A successful `standing_context` return means the **initiator's replica is created and the Welcome dispatched** — it does *not* block on the peer joining and does *not* confirm a bidirectional channel. An offline, slow, blocking, or consent-declining peer **all yield the identical `Ok`** (no synchronous join confirmation; the peer's join is observed only out-of-band). This uniformity is intentional: it is what forecloses a synchronous block/pair-existence oracle.

**Welcome-joiner caveat (decrypt-but-not-send until Phase 2E).** A caller whose replica was obtained via **Welcome-join** — the common non-initiating peer, and a collision-losing `did_hi` — can join and **decrypt** but **cannot send** in the standing context until the Phase-2E spawn-from-Welcome entrypoint lands (ADR-049 §Follow-ups #1, spec §5.15.8). Do **not** assume `standing_context(peer)` immediately yields a send-capable channel on the joiner side; the initiator side is unaffected.

**No create-vs-found discriminant (MUST).** FFI/SDK bindings **MUST NOT** enrich the `standing_context` return with a create-vs-found or `peer_joined` discriminant (e.g. a `created: bool`) — such a field re-opens the existence oracle the uniform `Ok` forecloses. The return shape MUST be identical across all bindings (every SDK language).

**Startup reconnection.** On SDK initialization, reconnect transport for all standing contexts. This is background work — the SDK reconnects to relays for all active persistent contexts and begins receiving queued messages. Standing contexts are available immediately after `sdk.init()` returns.

## CI Matrix

SDK CI follows the same three-tier structure as the Rust core. See `specs/16-test-infrastructure.md` §16.15 for the full tier definitions. Each language-specific standards file inherits these tiers and may add language-specific jobs.

### Tier 1 — PR Checks

Every push to a PR branch. Target: < 3 minutes. Must pass before review.

| Check | All SDKs |
|-------|----------|
| Lint | Language-specific linter (see per-language standards) |
| Format | Language-specific formatter (see per-language standards) |
| Type check | Static type analysis where available |
| Unit tests | Language test framework |
| Security scan | Dependency audit and vulnerability scanning (cargo-deny, pip-audit, npm audit, etc.) |
| Build | Release build for all target platforms |
| Docs | Documentation generation (verify no broken links) |

### Tier 2 — Merge Gate

Merge queue entry or push to `main`. Target: < 10 minutes. Required to merge.

| Check | All SDKs |
|-------|----------|
| All Tier 1 checks | (same as above) |
| Conformance tests | Cross-language JSON fixtures (wrapping key lifecycle, reorder buffer, error hierarchy, etc.) |
| Binding integration tests | End-to-end through FFI bridge: identity creation → context join → message roundtrip |

Conformance tests exercise cross-language fixtures that validate protocol behavior across SDK boundaries. They are more thorough than unit tests and require the Rust core to be built, so they run at the merge gate rather than on every push.

### Tier 3 — Nightly / Pre-Release

Scheduled (nightly) or manual trigger. Uncapped duration. Failures create issues but do not block merges.

| Check | All SDKs |
|-------|----------|
| All Tier 2 checks | (same as above) |
| Extended conformance | Full fixture suite with edge cases and adversarial inputs |
| Multi-platform matrix | All target platforms × all supported language versions |

No SDK release without 100% conformance pass (see `.docs/scaffold/shared.md`).

## Conformance Test Descriptions

The CI matrix above references cross-language JSON fixtures. See `.docs/scaffold/shared.md` for the full conformance test category table and fixture format. The subsections below describe specific test suites that require detailed behavioral verification beyond what the category table captures.

### Wrapping key lifecycle tests

Wrapping keys enable offline sender key distribution. Each member maintains a stable HPKE keypair per context, published as a LeafNode extension, used by other members to encrypt sender key material for offline recipients.

| Test ID | Verifies |
|---------|----------|
| `sender-keys-wrapping-stable-001` | Each member maintains a stable wrapping keypair per context, published as the `scp_wrapping_key` LeafNode extension |
| `sender-keys-wrapping-no-epoch-rotate-002` | Wrapping key does NOT rotate on MLS epoch advances — only on explicit identity key rotation |
| `sender-keys-wrapping-hpke-distribute-003` | Sender key distributions are HPKE-encrypted to each recipient's wrapping key |
| `sender-keys-wrapping-offline-unwrap-004` | Offline or late-joining members can unwrap sender key distributions using their wrapping key after reconnecting |

### Reorder buffer tests

The reorder buffer ensures reliable delivery without rejecting out-of-order messages. All authenticated messages are accepted; the buffer reorders before surfacing to the application, with bounded resource usage and gap alerting.

| Test ID | Verifies |
|---------|----------|
| `messaging-reorder-accept-all-001` | All authenticated messages are accepted regardless of sequence order |
| `messaging-reorder-before-delivery-002` | Reorder-before-delivery semantics: messages are held and reordered before surfacing to the application |
| `messaging-reorder-gap-timeout-003` | 30-second gap timeout with suppression alert — missing messages are marked as gaps and buffered messages are delivered |
| `messaging-reorder-buffer-bound-004` | 100-message buffer bound — when exceeded, buffer flushes in order with gap markers for missing sequence numbers |
| `messaging-reorder-gap-alert-005` | Gap detection triggers an alert to the application, not message rejection |

### Receive stream buffer tests

The receive stream buffers events for the application layer. When the consumer falls behind, the buffer drops the oldest events and emits a warning rather than blocking the transport layer.

| Test ID | Verifies |
|---------|----------|
| `receive-buffer-capacity-001` | Receive stream buffers up to 1,000 events (default) before dropping |
| `receive-buffer-overflow-drop-002` | When buffer is full, oldest unconsumed event is dropped (not newest) |
| `receive-buffer-overflow-warning-003` | `BufferOverflow` warning event is emitted when events are dropped, including dropped count |
| `receive-buffer-configurable-004` | Buffer size is configurable within bounds (min 100, max 10,000) |

## FFI Async Bridging Risks

Cross-language async bridging introduces subtle failure modes. All SDK binding implementations must account for these risks.

### 1. Tokio runtime must never block on Python GIL acquisition

PyO3 bridge functions use `py.allow_threads(|| rt.block_on(...))` which releases the GIL before entering the tokio runtime. If a tokio task attempts to acquire the Python GIL (e.g., via `Python::with_gil()`) while another thread holds the GIL and is blocked waiting for a tokio future, deadlock occurs. **Rule:** Rust-side tokio tasks must never call into Python synchronously. `Python::with_gil()` is only safe from non-async contexts where no GIL contention exists.

### 2. UniFFI callbacks execute on Rust threads

UniFFI-generated callback interfaces invoke the foreign callback on whatever Rust thread is running. Swift and Kotlin code must not assume callbacks arrive on the main thread or any specific dispatcher. **Rule:** UniFFI callbacks that touch UI or main-thread-only APIs must dispatch to the appropriate context (Swift: `MainActor.run {}`, Kotlin: `Dispatchers.Main`).

### 3. cbindgen runtime initialization is not reentrant

The shared tokio `Runtime` created at FFI initialization (`scp_init()`) must be called exactly once. A second call from Go/C#/Java will panic or return an error. **Rule:** Guard initialization with a `Once` / `OnceCell`. Document in all cbindgen-based SDK READMEs that `init()` is not reentrant.

### 4. Shutdown ordering: language cleanup before Rust runtime drop

If the Rust tokio runtime is dropped while language-side objects still hold FFI handles, those objects will attempt to call into a dead runtime. **Rule:** SDKs must ensure all SCP objects are disposed/closed before the FFI runtime is shut down. Implement a shutdown hook or reference counter that blocks runtime drop until all outstanding handles are released (with a configurable timeout, default 5 seconds).
