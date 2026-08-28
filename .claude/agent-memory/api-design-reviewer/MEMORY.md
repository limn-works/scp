# API Design Reviewer Memory

- [Event-Log Substrate Phase-2 Final Review](eventlog_substrate_phase2_final.md) — APPROVED; provider trait typed EventType+timestamp_secs, anchored fields cross-binding consistent, PaymentReceived mirrors sibling, WASM shares taxonomy/merge by construction
- [Cross-SDK shape parity](cross-sdk-shape-parity.md) — SCP agent-first tenet: identical API shape across all 4 bindings; recurring parity defects (return-type/param/signature/name-collision) to flag
- [TS↔Python trust parity](ts-python-trust-parity.md) — four-layer trust + bridge-trust-tier + identity-lifecycle parity conventions; intentional divergences vs parity smells
- [SDK coverage fail-closed + parity review](sdk_coverage_failclosed_parity_review.md) — fix/sdk-coverage-fail-closed-and-parity: identity-lifecycle+economyVerifyPaymentReceipts clean; MED discover_contexts TS/py signature split (singleton vs SCP-instance)
- [SDK coverage fail-closed @57840faab](sdk_coverage_failclosed_parity_57840faab.md) — APPROVED; BridgeTrustLevel int Literal + discovery kind/layer Literals matched to Rust enums; PERM-3030 re-raise correct; ADR-051 provider agent-first; Python discover_contexts lacks TS variant validation
- [RelayPublisher &DidRecordV1 contract](relaypublisher_didrecordv1_contract.md) — SCP-RELAYRES-004: bare-bytes footgun killed by private-field type; residual routing_id-param lets frame/routing mismatch (derive from record.public_key())
- [SDK coverage fail-closed @341df72cc](sdk_coverage_failclosed_parity_341df72cc.md) — APPROVED; discovery TypedDicts now public + field-parity w/ TS; non-blocking nit total=False vs TS-required (DiscoveryResult/ResolutionPathDict should be total=True); PERM-3030 re-raise + BridgeTrustLevel verified; provider.rs comment-only; "ADR-053 PreRotationCustodyProvider" not in diff (renumber only)

## SCP SDK Standards Review (2026-02-22)
- Reviewed all 10 files in `.docs/standards/` (sdk-common.md + 8 language files + conventions.md)
- Key blocking issues found:
  - Untyped `ceiling` and `custody` params (string instead of enum) across all SDKs
  - Swift code example contains force unwraps despite the file's own safety rules forbidding them
  - Contract says `identity` is a param on context_send/leave/close, but all 6+ language implementations omit it
  - Kotlin `Context.close()` uses `runBlocking` which deadlocks from coroutine contexts
  - Python `PermissionError` shadows `builtins.PermissionError`
- Cross-language naming table in sdk-common.md only covers 6 of 18 operations; needs `receive` row and others
- Java `Flow.Publisher` for streaming is too complex for the SDK's target audience
- Context state tracked as a string, not an enum, in Python examples

## SCP FFI Layer Review (PR #86, 2026-02-26)
- Reviewed WASM, NAPI, UniFFI bridges + Swift SDK bindings + sketch alignment
- 18 findings total, 3 critical, 5 major, 5 moderate, 5 minor
- Critical: WASM tool/UCAN ops use bare context_id (no state check), error code prefixes inconsistent across bridges, WASM identity_create always errors as exported public API
- Major: context state/custody remain stringly-typed in WASM/NAPI (UniFFI has enums), NAPI context_create accepts raw strings not typed structs, WASM payload as base64 instead of Uint8Array, WASM DIDDocument uses JSON strings where Vec<String> works
- Pattern: UniFFI bridge is the most type-safe; WASM is the least. NAPI is in between but could match UniFFI since it has full runtime access.
- Error code ranges: standard says TRANS=5000, TOOL=6000. NAPI swapped them. WASM uses SCP-IDENT- prefix, NAPI uses SCP-IDN- prefix. Must unify.

## PR #127 Full-Stack API Review (2026-03-12)
- Reviewed Rust core + all 4 FFI bridges + 4 SDK layers (181 files, 26K+ lines)
- 12 changes, 10 observations. Verdict: NEEDS REVISION (3 blocking)
- Blocking: (1) context_close capability check only in PyO3, missing from NAPI/WASM/UniFFI (security gap), (2) BroadcastContext.get_author_mut exposes mutable internals bypassing protocol invariants, (3) WASM uses single error code SCP-CTX-2000 for all context errors + base64 payload encoding diverges from other bridges
- Recurring issues from PR #86 still open: PyO3 context state is still String not enum, WASM payload still base64 not Uint8Array
- New pattern: UniFFI ContextHandle.state() and Identity.custody_type() return String despite having proper enums defined in same file -- loses type safety at the accessor level
- Good patterns: InnerEnvelopeParams eliminates u64 transposition risk, BroadcastKey uses Zeroize/ZeroizeOnDrop, StoredValue version envelope for migration, Kotlin two-tier streaming (cold/hot), trust renewal re-verifies before updating timestamp
- ProtocolRepository takes raw &[u8] for context state/params -- should accept typed domain objects
- AddressResolver.cache is needlessly public
- Cross-SDK creation params diverge: PyO3 dict, NAPI JSON string, UniFFI typed record, WASM DID string + JSON

## Persistence Layer Review (feat/persistence-layer, 2026-03-03)
- 61 files, 18k+ lines. 9 changes, 10 observations. Verdict: NEEDS REVISION
- High: (1) Two incompatible `ClockFn` type aliases in same crate (Arc vs Box, infallible vs Result), (2) ProtocolRepository domain methods still accept raw &[u8] (recurring from PR #127)
- Medium: BlobStorage::store has 3 positional [u8;32] params (transposition risk), StoredValue fields are pub (bypass version management), constructor naming inconsistent (new vs open for I/O operations), ContextPersistence sync-trait has undocumented runtime panic condition
- Good: Storage trait is minimal (6 methods), conformance macros excellent DX, sanitize_key_component applied consistently, Migratable trait + StoredValue envelope is sound migration design, zeroize-on-write for key material, TypeScript StorageInterface 1:1 match with Rust
- Pattern: thin trait (Storage 6 methods) + thick coordinator (ProtocolRepository 50+ methods) is the right layering. Conformance macros (storage_conformance!, blob_store_conformance!) validate adapter implementations with one-liner invocation
- Convention established: `store_X/load_X/delete_X/list_X` naming across all 8 ProtocolRepository domain modules
- [Custody selection surface (SCP-294)](custody_selection_surface_scp294.md) — per-bridge custody-string matrix, IDENT-1003/1008 doc drift, Swift/Kotlin no-shipped-provider dead end
