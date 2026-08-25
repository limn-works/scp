# Changelog

All notable changes to SCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-08-16

### Six fail-open fixes, and what they change for a caller

Each item below removes a path where a capability reported success without
delivering what that success claims. Five of them change a caller-visible
contract, so each names what a caller does differently.

**Custody selection is required, with no in-memory default.** TypeScript
`SCP.identityCreate` and `SCP.identityCreateWithAgentKey`, and Kotlin's
`IdentityAdvanced.createWithAgentKey(custody: String)` overload, defaulted
`custody` to `"in_memory"`; Python's `SCP.identity_create` and
`SCP.identity_create_with_agent_key` defaulted it to `CustodyType.FILE`.
Persistence spec §17.8 classifies `InMemoryKeyCustody` as a security
nullifier, and `SCP-CAPSEL-8000` (§17.17.1) forbids a form that selects a
backend for a caller, whichever backend it picks. **A caller now names a
custody backend on every call.** TypeScript also rejects a missing selection at
runtime with `SCP-IDENT-1060`, which a JavaScript caller reaches without a type
check.

**An unknown governance outcome fails closed.** Python's
`GovernanceActionResult.from_bridge` returned `EXECUTED` for a string it did not
recognize, and Swift's `executeGovernanceAction` returned `.executed` in that
same way. **Both now raise `SCP-GOV-11040`**, and Python's
`UnknownGovernanceOutcomeError` carries `raw_outcome`. Python's
`SCP.governance_execute` and TypeScript's
`SCP.contextExecuteGovernanceAction` now return that typed outcome rather than
a bare string. Python, Swift, and TypeScript each gained three outcomes
their enums lacked — `MigrationProposed`, `MigrationCancelled`,
`ContextTombstoned` — and all three bridges name an outcome through one shared
mapping, which replaces a napi-rs `format!("{result:?}")` whose
payload-carrying variants rendered as a Rust debug dump.

**`FileKeyCustody` rejects a wrong passphrase at construction.**
`FileKeyCustody::new` used to return custody built from any passphrase, and
every later `sign` failed. Key-file format version `0x02` adds a passphrase
commitment and an HMAC-SHA-256 over every other byte in a file, so construction
reports a wrong passphrase and a modified file as two conditions
(`SCP-CAPSEL-8001`, persistence spec §17.8). **A `0x01` file is rejected
by version**: it carries neither value, so neither its passphrase nor its
integrity is checkable. Creation now uses an exclusive create, so two processes
racing on one path no longer overwrite each other's keys.

Two further defects in that same key file are closed. Every bridge opens one
`$HOME/.scp/keys.bin` and constructs a fresh `FileKeyCustody` for each identity
creation, so the writers that contend for that file are two custody objects
rather than two tasks inside one. `append_entry` and `destroy_key` now hold an
exclusive advisory lock across their whole read-modify-write, which excludes a
second process and a second object in this process alike; the per-object mutex
they held before excluded neither, so two concurrent creations each appended at
one index and the later write replaced the earlier — **one generated private key
never reached disk while both callers read success, and both handles then named
the surviving entry**. Each entry now carries a 16-byte `entry_id` that custody
draws once and no later write changes; a handle records that identifier, every
read finds its entry by comparing identifiers, and each entry's ciphertext binds
`key_type | entry_id` as AES-256-GCM associated data. Every read path also
compares an entry's stored `key_type` byte against the type its handle names
before decrypting, which turns a changed type byte into an error naming both
types rather than an opaque decryption failure.

A handle that recorded a position instead read whichever key a later write moved
into that position. `destroy_key` moves every entry after the removed one down
one position, so a handle another custody object minted before that call named
an entry that had left. Where both entries held one key type — two Ed25519 keys
of one identity, which is what `#0`, `#active`, and `#agent` are — the stored
type byte matched, and re-encrypting a moved entry under its new position made
the associated data match too, so AES-256-GCM accepted a key its caller never
designated and `sign` returned a signature under it. `destroy_key` reached the
same key by position and destroyed it. **A handle whose entry left the file now
reports an error on `sign`, on `public_key`, on `dh_agree`, and on
`destroy_key`, and every other handle keeps reading its own key.**
`destroy_key` copies each entry it moves byte for byte, because no entry's
ciphertext commits to a position.

**A relay names its blob storage backend.**
`scp_transport::startup::storage_from_env` substituted `sqlite` when
`SCP_RELAY_STORAGE_BACKEND` was unset and called `std::process::exit(1)` on
every failure. It now returns `Result<BlobStorageBackend, StorageError>`, and
`start_relay_from_env` returns `Result<_, StartupError>`; each binary turns
those errors into exit code 1 at its own boundary. **An operator sets
`SCP_RELAY_STORAGE_BACKEND` on every `scp-relay` run and on every persistent
`scp-node` run** — `docker-compose.yml`, this repository's README, and
`docs/guides/relay-operations.md` name `sqlite` in every example. `--ephemeral`
still selects an in-memory blob backend and reads no env var. `health_check`
returns a verdict instead of exiting, and `shutdown_signal` waits on ctrl_c
alone when a kernel refuses a SIGTERM handler.

**`identityCreateWithAgentKey("file")` creates an identity on Node.** The
napi-rs bridge admits `"file"` at its validation boundary and serves it on
`identity_create`, and `identity_create_with_agent_key` carried no `"file"`
arm, so that call fell to a catch-all that returned `SCP-IDENT-1005` with text
telling the caller they had found a bug in the bridge layer. **That method now
opens the same encrypted key file `identityCreate("file")` opens**, which is
what the `PyO3` bridge already did by routing both creators through one
`parse_custody`.

**Three in-memory or always-succeeds implementations left public API.**
`InMemoryFfiTrustStore`, `InMemoryViolationStore`, and `NoOpRevocationChecker`
were `pub` and ungated while nothing outside a test constructed any of them.
All three now carry `#[cfg(any(test, feature = "testing"))]`, and
`InMemoryFfiTrustStore` lost an `impl Default` that read as a default selection.

## [Unreleased] - 2026-05-10

### Enforcement infra hardening — PR-E (PR #1735)

Five enforcement-infra improvements that close gaps surfaced in the #1543
review series, plus the §1 cleanup the new gate identified. No protocol
behaviour change; all changes are mechanical hardening of the bridge
surface tests and refactoring of pure helpers per ADR-048 §1.

**Internal changes only — no external SDK behaviour change** other than
the SDK class methods listed below routing to module-level FFI exports
internally (the SDK class shape is unchanged for TypeScript / Swift /
Kotlin; Python continues to expose module-level functions per
`scp_sdk.{auth,identity,provenance}` per ADR-048 §7).

- **Phantom-alias scanner hardening (#26).** Bridge-symmetry alias
  resolution now requires the candidate fn to be exported through the
  bridge binding tooling, not merely defined in source. Both
  `scripts/check-bridge-symmetry.sh` and the syn-based
  `every_alias_resolves_to_a_real_fn_or_exemption` test in
  `crates/scp-testing/tests/integration/ffi_conformance.rs` were
  tightened. New fixture `bad-alias-undecorated-fn/`.
- **Empty arrays for exempt bridges (#27).** 24 placeholder cells in
  `scripts/bridge-aliases.json` (all wasm) replaced with `[]`. New invariant
  `every_bridge_alias_array_is_non_empty_or_exempt`. (A 25th placeholder, the
  napi `identity_migrate` cell, was instead wired to its real export — see the
  exemption durable-provenance bullet below.)
- **ADR-048 §1 pure-helpers mechanization (#28).** New syn-based gate
  `pure_helpers_stay_free_fns_at_ffi_layer` flags methods with a `self`
  receiver that never use it inside FFI-decorated impl blocks. Macro
  bodies are walked via `proc-macro2` so `format!("{}", self.field)` is
  correctly recognized as bound. 19 pre-existing violations cleaned up:
  - 1 NAPI: `NapiScp::check_scoped_capability` → module-level free fn.
  - 8 PyO3: `scpid_challenge`, `identity_verify_device_attestation`,
    `verify_identity_link_attestation`, and 5 provenance helpers moved
    from `#[pymethods] impl PyScp { ... }` to `#[pyfunction]` free fns
    registered in the appropriate `register_*` hook.
  - 10 UniFFI: `bridge_evaluate_trust`, `identity_resolve`,
    `identity_verify_{device_attestation,link_attestation}`,
    `sync_classify_offline{,_custom}`, `sync_get_policy`,
    `trust_query_score`, `trust_verify_attestation`,
    `verify_participation_requirements` moved from
    `#[uniffi::export] impl Scp { ... }` to free fns.
- **ADR-048 §7b cross-bridge semantic divergence registry (#29).**
  Documents canonical operations where bridge implementations diverged in
  semantics despite sharing the same name, and the evidence required to retire
  an entry. Both current entries are RESOLVED (retained one release cycle to
  flag the behavioral shift to consumers): `identity_create_link_attestation`
  (WASM aligned to `#active` signing per spec §3.5.2) and `identity_rotate_key`
  (WASM aligned to native active-key rotation by a later upstream change;
  DID-migration semantics now live in WASM's separate `identity_migrate`
  export). A single inline `// SEMANTIC DIVERGENCE` comment remains at the WASM
  attestation call site for its retention window.
- **Exemption durable-provenance gate.** New invariant
  `every_exemption_reason_cites_durable_provenance` requires every
  per-bridge exemption in `scripts/bridge-aliases.json` to justify itself
  with an ADR (`ADR-NNN`), spec section (`§N…`), or PRD story (`SCP-NNN`).
  Cited ADRs and SCP stories are existence-verified against `.docs/adrs/`
  and `.docs/prds/` (a fabricated `ADR-999`/`SCP-9999` is rejected, not just
  hand-waves); `§` sections remain shape-only. Issue/PR numbers are rejected
  (ephemeral; policy forbids issue refs in tracked data). The gate
  immediately caught a factually wrong exemption: `identity_migrate` was
  marked "not yet exported (known gap)" in NAPI, but it IS exported as the
  `Identity#migrate` instance method — the alias was simply never recorded.
  Wired the real `migrate` alias and removed the false exemption.

**Side fix:** `scripts/hooks/pretooluse-enforcement-files.sh` switched
from suffix to exact-canonical-path matching anchored at the worktree
root, and the enforcement-file guard was extended to `Bash` tool calls:
best-effort detection of write verbs (`tee`/`mv`/`cp`/`sed` in-place in all
GNU/BSD flag orderings/`python -c`) and stdout redirections (including `>|`
force-clobber) targeting a protected basename. Reads
(`cat`/`grep`/`jq`/`sed -n`/`node x.js file`/`python validate.py file`) are
still allowed; CI remains the canonical gate. `check-pure-helpers.sh`,
`pure-helpers-allowlist.txt`, and the hook script itself were registered in
both the CLAUDE.md enforcement list and the hook's protected-paths set.
Fixture copies of `bridge-aliases.json` no longer trigger false-positive
blocks; symlink-bypass protection preserved. A regression matrix at
`scripts/tests/enforcement-files-hook/run-tests.sh` locks the block/allow
behavior and runs in CI.

## [Unreleased] - 2026-04-25

### Actor-per-context refactor (ADR-049)

Internal concurrency redesign of `crates/scp-runtime`. The
previously-existing `ContextManager` is gone; `Supervisor` is the new
authoritative state owner (see
`.docs/adrs/ADR-049-actor-per-context.md`). FFI bridges and SDK
wrappers are unchanged at the surface level; the rewrite is internal
to `scp-runtime`.

**Caller-visible behavioral changes:**

- **50ms coalesce-rollback semantics for non-authorization-downward
  state.** Per ADR-049 §9 and spec §17.15.1, persistence outside the
  authorization-downward set (any operation that transitions a
  member's authorization downward — UCAN issuance/attenuation/
  revocation, role assignment/demotion/blocklist updates, MLS epoch
  advance, sender-key rotation, event log append, KeyPackage
  consumption, saga phase transitions) is coalesced on a 50ms write
  window per actor. On actor crash, the in-flight coalesce window may
  roll back up to 50ms of non-critical state (participation counters,
  velocity trackers, receive buffer position, etc.).
  Authorization-downward operations remain sync-persisted with no
  rollback risk — see ADR-049 §9 for the full authorization-state
  persistence rule.
- **`Supervisor::shutdown_all_contexts` is now async.** The blocking
  `try_lock` cleanup pattern was replaced with awaited `lock().await`
  acquisitions so cleanup does not silently skip on contention. Sync
  callers (destructor / atexit hooks) use the new
  `Supervisor::shutdown_all_contexts_sync` wrapper.

References: ADR-049 §9 (coalesced persistence rule),
`.docs/specs/17-persistence-and-storage.md` §17.15.

## [Unreleased] - 2026-04-18

### `DidDht::migrate_identity` partial-publish recovery handle

- **New `IdentityError::MigrationPublishFailed { phase, partial, source }` variant.** When either of `migrate_identity`'s two DHT publishes (step 7 publish-new, step 8 republish-old-with-`alsoKnownAs`) fails AFTER the irreversible cold-custody mutation at step 5 (`destroy_after_migration`), the function now returns this typed error instead of a generic `DhtPublishFailed`. The carried `Box<MigrationPartialState>` holds the byte-identical artifacts (new identity, new document, rotation event with the step-2 migration proof and pre-rotation proof, new pre-rotation handle, old identity, old document) needed to finish the migration. `MigrationPartialState` derives `Serialize`/`Deserialize` so callers can persist the recovery handle across process restarts; its fields are `pub(crate)` with read-only accessors (`phase()`, `new_did()`, `old_did()`, `rotation_event()`, `new_pre_rotation_handle()`) so the byte-parity invariant cannot be broken by field swaps.
- **New `MigrationResumePhase` enum** (`PublishNew` | `RepublishOldAlsoKnownAs`) — identifies which publish step failed and which steps a resume call must re-run. Co-located with `MigrationPartialState` in `crate::dht`; re-exported from the crate root.
- **New `MigrationOutcome` struct.** Replaces the prior 4-tuple return of `migrate_identity` / `resume_migration_publish` with a named struct (`new_identity`, `new_document`, `rotation_event`, `new_pre_rotation_handle`) — self-documenting at the call site, and forward-compatible: future additions (audit-log digest, attestation token) extend the struct without breaking destructuring callers.
- **New `IdentityError::as_migration_partial(&self) -> Option<&MigrationPartialState>` and `into_migration_partial(self) -> Result<MigrationPartialState, Self>`.** Idiomatic borrowing and owning extractors on the error type itself (replaces the prior `MigrationPartialState::from_error(&IdentityError)` helper, which could only borrow). `into_migration_partial` consumes the error and returns the original error in the `Err` arm for any other variant — exactly the shape `resume_migration_publish` (which takes the partial state by value) needs.
- **New `DidDht::resume_migration_publish(state, key_custody)` method.** Picks up exactly where `migrate_identity` left off: for `PublishNew`, re-runs step 7 + step 7b + step 8; for `RepublishOldAlsoKnownAs`, re-runs only step 8. Idempotent under BEP44 sequence monotonicity. Performs a custody-substrate pre-flight check (`public_key(&old_#0)` + `public_key(&new_#0)`) before any DHT publish so a mismatched substrate fails fast with a clean `IdentityError::Platform(KeyNotFound)` rather than a buried "publish failed at signing step." Returns a [`MigrationOutcome`] byte-identical to what a successful first-pass would have returned (spec §9.7.4.1 byte parity invariant).
- **Bridge surface (phase 1).** Each FFI bridge (PyO3, NAPI, UniFFI) maps `MigrationPublishFailed` to the new error code `SCP-IDENT-1053` with the error message body. Structured partial-state plumbing per language idiom lands in subsequent PRs (ADR-048 §7). WASM's registry-only `identity_migrate` has no two-stage DHT publish, so the partial-publish recovery flow does not apply.
- **Scope caveat — recovery covers DHT publish failures only.** The recovery handle is surfaced for failures at steps 7 (`publish_document(new)`) and 8 (`publish_document(old + alsoKnownAs)`). A failure between step 5's `destroy_after_migration` and the immediately-following `import_ed25519_signing_key` (e.g., a transient operational-custody fault that the step-0 probe missed) still propagates as a bare `IdentityError::Platform` with no partial state. The step-0 CSPRNG probe narrows the surface but does not eliminate it. A future `MigrationResumePhase::ImportNewIdentityKey` variant will close the window; tracked as follow-up work outside this release.
- **Specs / ADR.** `.docs/specs/09-security-model.md` §9.7.4.1 gains a "Partial-publish recovery" paragraph (with explicit dual-reference between the spec's item-6 numbering and the code's step-5 sequence). `.docs/adrs/phase-1.md` §4b gains a forward-reference bullet. New evergreen lesson at `.docs/lessons/migration-publish-recovery-handle.md` covers the general principle ("multi-step operations that consume irreversible state mid-pipeline MUST surface a typed recovery handle"). The resume byte-parity invariant lives in spec §9.7.4.1; ADR-046 governs the sibling *cross-bridge* byte parity (seed-window order, ephemeral RNG).

### Per-instance MCP stdio allowlist (PR #1725)

**Security fix.** Closes a realm-local RCE-pivot vulnerability: previously, calling
`mcp_disable_stdio_allowlist()` on any `SCP` instance unrestricted subprocess
spawning across every other instance in the same process. The allowlist is now
owned per-`BridgeInstance` (`CoreFields::mcp_allowlist`), so policy decisions on
one tenant cannot leak into another. See
`.docs/lessons/process-global-policy-state-is-realm-local-rce.md`.

**Breaking changes — external SDK consumers:**

- **Python:** the four module-level helpers in `scp_sdk.mcp` are deleted —
  `configure_stdio_allowlist()`, `disable_stdio_allowlist()`,
  `reset_stdio_allowlist()`, `get_stdio_allowlist()`. Use the per-instance
  methods on `SCP` instead:
  - `scp.mcp_configure_stdio_allowlist([...])`
  - `scp.mcp_disable_stdio_allowlist(i_trust_all_commands=True)`
  - `scp.mcp_reset_stdio_allowlist()`
  - `scp.mcp_get_stdio_allowlist()` → `McpAllowlistState` (TypedDict)
- **PyO3 extension (`_scp_core`):** the four `py_mcp_*_stdio_allowlist`
  `#[pyfunction]`s are deleted and replaced by `#[pymethods]` on `PyScp`.
  Callers reaching into `_scp_core` directly will see `AttributeError`.
- **TypeScript:** `SCP.mcpDisableStdioAllowlist` now requires
  `{ iTrustAllCommands: true }`; the snapshot returned by
  `SCP.mcpGetStdioAllowlist` is a named `McpAllowlistState` interface
  (was inline anonymous shape).
- **Swift:** `SCP.mcpDisableStdioAllowlist(iTrustAllCommands: true)` is the
  required call shape; throws `ScpError.Validation { code: "SCP-MCP-10010" }`
  when the flag is omitted or false.
- **Kotlin:** `SCP.mcpDisableStdioAllowlist(iTrustAllCommands = true)` —
  throws `IllegalArgumentException` when the flag is omitted or false.
- **UniFFI:** the four top-level `#[uniffi::export] pub fn mcp_*_stdio_allowlist`
  free functions are deleted; only the per-instance methods on `Scp` remain.
- **Rust core:** `scp_mcp::allowlist::StdioAllowlist` is now an owned `pub
  struct` with method-form API (`new_with_defaults`, `validate_command`,
  `configure`, `disable_enforcement(instance_id)`, `reset`, `snapshot`).
  The process-global `OnceLock<Mutex<StdioAllowlist>>` and the
  `AllowlistError::LockPoisoned` variant are deleted (`#[non_exhaustive]`
  preserved).
- **`scp-ffi-common`:** `CoreFields::mcp_allowlist`,
  `CoreFields::with_mcp_allowlist(|a| ...)` helper, and
  `AllowlistGuardError::Poisoned` typed error are public.

Closes #1543 (PR-D in master plan). See ADR-048 §1 (multi-instance neutrality),
the new lesson at `.docs/lessons/process-global-policy-state-is-realm-local-rce.md`,
and the `BridgeInstanceCore` enumeration in `.docs/adrs/ADR-048-scp-multi-instance.md` §2.

### Pre-rotation custody isolation + DID migration wiring

- **New `PreRotationCustody` trait in `scp_platform`.** Pre-rotation private-key material now lives behind a separate trait (distinct from `KeyCustody`) and a distinct `PreRotationKeyHandle` type — `From`/`Into` between `PreRotationKeyHandle` and operational `KeyHandle` are NOT provided, so the type system rejects accidental cross-substrate handoff. Spec §9.7.4.1 §3 storage isolation is enforced at compile time. `InMemoryPreRotationCustody` is the shipped default backend; substrate isolation (FIDO2 / paper / cold callback) is a separate workstream and continues to land via `PreRotationCustody` impls without protocol churn.
- **`DidDht::create_identity` return type changed** to `(Identity, DidDocument, PreRotationKeyHandle)`. Callers persist all three; the handle is the only reference to the pre-rotation private bytes (which never enter `ScpIdentity` itself — only the 32-byte SHA-256 commitment does), and the document is the published state callers republish to the DHT.
- **`DidDht::migrate_identity` signature changed** to `(identity, old_document, pre_rotation_handle, pre_rotation_custody, key_custody, rotated_at) -> (Identity, DidDocument, DidRotationEvent, PreRotationKeyHandle)`. Migration consumes the OLD pre-rotation handle (returning its private bytes, which become the new `#0`) and mints a fresh pre-rotation key+commitment for the new identity.
- **`verify_migration` signature widened** to `(old_did, old_document, new_did, migration_proof, pre_rotation_proof, rotated_at, now) -> Result<bool, IdentityError>` (was 4 args returning `bool`). Always-checked invariants (1-7, MODERATE assurance): (1) `old_document`'s `#0` verification method self-certifies to `old_did` (Step 0 precondition — rejects mismatched documents before any downstream invariant consults `old_document.pre_rotation_service()`; callers MUST supply `old_document` from a verified resolution path, see `verify_migration` rustdoc `# Caller contract`), (2) Ed25519 strict signature on the migration digest, (3) `old_public_key` self-certifies to `old_did`, (4) saturating future-skew bound (5 min) on `rotated_at`, (5) saturating past-window bound (5 years) on `rotated_at`, (6) hard epoch floor (`MIGRATION_EPOCH_FLOOR_UNIX_SECS = 1_700_000_000`, 2023-11-14 UTC) rejects pre-protocol timestamps even on a faulty verifier clock, (7) `pre_rotation_proof` MUST be `Some(_)` whenever the OLD DID document publishes a `PreRotationCommitment` service entry — STRONG assurance committed to at creation cannot be silently downgraded. Conditional invariants — applied only when `pre_rotation_proof` is `Some(_)` (STRONG assurance, 8-10): (8) `SHA-256(revealed_key) == commitment`, (9) `commitment` matches the OLD document's `PreRotationCommitment` service entry, (10) `revealed_key` self-certifies to `new_did`. See ADR-003 §4c.
- **`MigrationProof` and `PreRotationProof` JSON wire format moved to lowercase hex** (via `serde_hex_array::array64` / `serde_hex_array::array32`). Was `serde_bytes` previously, which produced JSON-array-of-numbers output. The change aligns with the project-wide convention for cryptographic byte material and matches the WASM bridge's emitted shape.
- **New SDK accessor: rotation event JSON** for distributing `DidRotationEvent` to active contexts after migration. Surfaced as `Identity.rotation_event_json` (Python), `BridgeIdentityHandle.rotationEventJson` (TypeScript), `Identity.rotationEventJson()` (Swift), and `Identity.rotationEventJson()` (Kotlin, surfaced through the `IdentityMigrateResult` returned by `IdentityAdvancedBridge.migrateWithRotationEvent`). The Kotlin `IdentityAdvancedBridge.migrate(handle)` overload is now `@Deprecated` because it silently drops the rotation event required by spec §3.2.1 step 4b; callers MUST switch to `migrateWithRotationEvent` and distribute the JSON to every active context (pre-context callers may discard explicitly).
- **WASM `WasmIdentity::from_did` now enforces** zbase32 canonicality (rejects non-canonical padding), Ed25519 curve-point validity (rejects 32-byte payloads that decode to invalid public keys), and the WASM-local identity registry capacity guard (returns `[SCP-VALID-7400]` at the 10,000-DID cap rather than evicting silently).
- **Kotlin** `IdentityAttestation.fromJsonObject` now fails closed on unrecognized `revocation_status` JSON shapes (throws `IllegalArgumentException` instead of silently defaulting to `Active`). A future Rust enum variant addition surfaces as a parse error rather than silent mis-categorization.

### Phase 4 PR 3 — Persistence + async resume + real UniFFI crypto

**Breaking changes — external SDK consumers migrating from PR 1 behavior:**

- **`SCP.resume()` is now async.** `BridgeInstanceCore::resume` became `async fn` (#1678) so per-bridge overrides can chain relay reconnect and persisted-context restoration on top of the suspended-flag flip. Callers must await / suspend:
  - Python: `await scp.resume()` (was synchronous)
  - TypeScript: `await scp.resume()` (returns `Promise<void>`)
  - Swift: `try await scp.resume()` (was synchronous `throws`)
  - Kotlin: `scp.resume()` inside a coroutine / suspend function (was blocking `ffiCall`)
  - Reconnect failures surface as `LifecycleError.ReconnectFailed { url, reason }` (new variant).
- **`StorageConfig` extended with SQLite (#1491, #1260).** New variant `Sqlite { path, key }` across PyO3, NAPI, UniFFI. WASM remains InMemory-only.
  - Python: `SCP(storage={"type": "sqlite", "path": str, "key": bytes})` — 32-byte key as Python `bytes`.
  - TypeScript: `SCP.withStorage({ type: "sqlite", path, key })` — `key` is hex `string` or `Uint8Array`.
  - Swift: `SCP.withStorage(sqliteDir: URL, key: Data)` convenience; also `StorageConfig.sqlite(path:key:)` directly.
  - Kotlin: `SCP.withSqlite(dir: File, key: ByteArray)` companion; also `StorageConfig.Sqlite(path, key)` directly.
- **UniFFI `ContextManager` requires a local DID before context ops (#1342).** `FfiBridgeCrypto` is deleted; UniFFI now constructs `MlsCryptoProvider::new(did)` exactly as PyO3 and NAPI do. Swift and Kotlin callers must invoke `scp.registerLocalDid(...)` before `context_create` / `context_join` / `context_import`. Calling a context operation before registration returns `ScpError.Context { code: "CTX_2000", msg: "bridge not ready: no local DID registered" }`.
- **Multi-relay reconnect via `HashSet` (#1678).** `CoreFields::relay_url: Mutex<Option<String>>` became `relay_urls: Mutex<HashSet<String>>`. Accessors replaced: `add_relay_url` / `remove_relay_url` / `pending_relay_urls` (was `set_relay_url` / `clear_relay_url` / `pending_relay_url`).

Closes #1342, #1260, #1491, #1678. See `.docs/adrs/ADR-048-scp-multi-instance.md` § "PR 3 actualized" for the full design commentary.

### Phase 4 PR 4 — Test codemod + enforcement + docs

- **Migration guide published** at `.docs/migration/phase-4.md`. Covers every breaking change landed in PR 1 → PR 3, the per-test `SCP` fixture recipe for Python / TypeScript / Swift / Kotlin, the `SCP-DEFAULT-INSTANCE-OK` opt-in tag, and the CI gate reference table.
- **New CI gate — `scripts/check-no-default-in-tests.sh`.** Fails the build if a test file calls a free-function façade (`scp_sdk.context_create(...)`, `.contextCreate(...)`, etc.) without an explicit `SCP-DEFAULT-INSTANCE-OK: <reason>` tag on the offending line or within 2 lines above. Guards the per-test-fixture invariant from ADR-048 §Decision 3. Exempts deprecation-verifying tests by filename.
- **New CI gate — `scripts/check-no-fallback-registry.sh`.** Greps for the `EMPTY_IDENTITY_REGISTRY` / `EMPTY_UCAN_REGISTRY` identifiers deleted in PR 2. Accepts occurrences inside comments (they remain as historical context); fails on any non-comment use. Regression guard for the silent "bridge not initialized" data-loss pattern described in ADR-048 §Context.
- **CI wiring.** `check-no-bridge-globals.sh`, `check-no-fallback-registry.sh`, and `check-handle-affinity.sh` are now required status checks alongside the existing `cross-layer`, `protocol-sync`, and `sdk-coverage` gates. `check-no-default-in-tests.sh` is staged in-tree but NOT yet wired to CI — it fires on ~500 pre-existing call sites that the per-test SCP fixture codemod (next PR) migrates to the new fixture pattern. The gate lights up in the codemod PR once those call sites move or carry the `SCP-DEFAULT-INSTANCE-OK` opt-in tag.
- **SDK capability matrix.** Added explicit rows for `scp_new`, `scp_default` (deprecated), `scp_with_storage_in_memory`, `scp_instance_id`, `shutdown_timeout`. The pre-existing `suspend` / `resume` / `with_storage_sqlite` / `add_relay_url` rows already documented the async / multi-relay surface.
- **CLAUDE.md enforcement file list updated.** The four gate scripts, `ratchet/once-lock-count.json`, and `sdk-capability-matrix.json` are all flagged as "modify only to expand coverage" so future agents can't silently weaken them.

No runtime or semantic changes. Closes #1549.

## [Unreleased] - 2026-03-16

### Security

- PCS break fixed (#1250) — `recovery_advance_epoch` now performs real MLS epoch advance
- Relay swap attack fixed (#1222) — leaf hash verification in `RelayBlobColdProvider`
- Kotlin JSON injection fixed (#1203) — `buildJsonObject` replaces string concatenation
- PSK nonce hardened (#1246) — random nonce replaces deterministic SHA-256
- Checkpoint signature verification (#623) — Ed25519 verification before comparison
- JCS compliance (#1252) — RFC 8785 canonical JSON for all hashing paths
- UCAN capability URI format (#1293) — fixed resource/action split mismatch across all 5 bridges
- MLS crypto snapshot Debug redaction (#706) — prevent key material exposure in logs
- Mutex poison partial state prevention (#712) — MLS `restore_crypto_state` atomicity
- Webhook replay protection and error code collision fixes (#1237)
- Decryption failures return 404 to prevent oracle (#1291)
- X-Forwarded-For trusted-proxy SHOULD upgraded to MUST (#1292)

### Added

- **WASM MLS encryption** (#602) — browser clients can now participate in encrypted contexts
- **Provenance event log recording** (#586) — `ProvenanceAttached`/`ProvenanceReceived` events across all 4 FFI bridges
- **Broadcast content delivery** — `BroadcastContent`, `ContentMetadata`, `ContentPath`, `MimeType` types (SCP-287)
- **Path-indexed projection endpoint** with atomic deploys (SCP-288, SCP-289)
- **Trust aggregation** exposed across all 4 bridges and SDKs (#596)
- **Economic governance** exposed across all 4 bridges (#613)
- **Media subsystem** exposed through FFI bridges (#597)
- **Bidirectional consent protocol** across all 4 bridges and SDKs (#579)
- **Invitation evaluation pipeline** with WASM security checks (#614)
- **Provenance privacy functions** across all 4 bridges (#585)
- **Bridge subsystem operations** through PyO3 bridge (#616)
- **MCP operations** exposed through UniFFI bridge for Swift/Kotlin (#591)
- **Tool session and cross-context invocation** wrappers for TypeScript and Kotlin (#526)
- **SCPID auth wrappers** for all 4 SDKs (#1058, #1059)
- **Identity advanced operation** test coverage across all SDKs (#428)
- **Governance pipeline and context lifecycle** methods exposed through FFI (#559)
- **MetadataRecord and ContextTemplate inspection** exposed through FFI (#615)
- **DegradedMode** with graceful degradation behavior (#606)
- **Participation types** added to TypeScript SDK with WASM bridge (#426)
- **Broadcast unblock** implemented across all layers (#617)
- **Min protocol version** added to `ContextParams` per spec section 13 (#607)
- **MLS group state and sender key persistence** across restarts (#645)
- **Encryption at rest** via sealed `EncryptedStorage` trait (#695)
- **Economic policy** set/get exposed across all FFI bridges and SDKs (#713)
- `cargo deny` configuration for dependency auditing

### Fixed

- **NAPI backend**: 82 tests passing (from 33), identity registry fallback, `MemberRole` case, DID resolver seeding (#1144, #1236)
- **Python SDK**: all 4 examples updated to match post-refactor API (#1297)
- **UCAN spec documentation**: two-tier validation design clarified (#1281)
- UCAN revocation pipeline wired with authorization and event logging (#499)
- `ToolCost` aligned with spec section 5.4.1 — renamed fields, added currency (#934)
- Error code harmonization across PyO3/UniFFI/NAPI/WASM bridges (#537)
- WASM sequence field harmonized to f64 matching NAPI (#1022)
- Swift `Context.lastError` stored instead of discarded (#541)
- Swift concrete `ContextHandle` in bridge function typealiases (#1018)
- Kotlin `toolVerifyResult` changed from Boolean to String (#1010)
- Kotlin `identityHandle` added to `ScpContextHolder` and `rememberScpContext` (#1009)
- TypeScript broadcast state preserved in mock `contextImport` (#1007)
- TypeScript `ucanToken` made required in `Context.invokeTool` (#745)
- TypeScript JSON.parse calls wrapped with safe error handling (#681)
- NAPI `PascalCase` `ParsedAddress` variant tags per spec (#737)
- WASM `DID` validation added to `context_leave` (#740)
- WASM `ucan_token` passed through `tool_invoke` bridge (#554)
- Governance timeout task with deadlock detection (#581)
- Sync TOCTOU race eliminated in reset request nonce tracking (#572)
- Sync mutual removal check in governance conflict resolution (#576)
- Context version check moved before crypto ops in `join_context` (#715)
- Context TTL expiry errors propagated with retry and observability (#612)
- Event log accepts pruned logs on restore (#705)
- Forward-compatible deserialization and FFI timestamp guards (#593, #538)
- Outbound queue ordering and bound enforcement (#709)
- Provenance rejects empty context IDs in discovery method parsing (#741)
- `SnapshotCodecFailed` renamed, `reconcile_epoch` returns Failed for unknown epoch (#1179, #1180)
- `Retry-After` field added to `InterfaceRateLimited` error (#1110)
- Typed `Capability` enum in `check_media_capability` replaces string comparison (#1042)
- Persistent `SenderKeyStore` in `bridge_create_shadow` (#539)
- NAPI `HANDLE_COUNT` underflow prevention (#1263)
- Envelope `deny_unknown_fields` removed from wire types per spec (#723)
- Event log per-entry keys for O(1) append persistence (#710)
- `ContextSnapshot` clone eliminated in persist (#711)

### SDK Validation

- **Kotlin**: 227 tests pass, detekt clean
- **Swift**: 437 tests pass, SwiftLint/SwiftFormat clean
- **Python**: 488 tests pass, ruff clean
- **TypeScript**: NAPI backend 82 tests pass, type checks clean

## [0.1.0] - 2026-03-11

Initial release of the Shared Context Protocol SDK.

### Added

- **Identity**: DID-based cryptographic identity with `did:dht` and `did:web` methods
- **Contexts**: Bounded, encrypted interaction spaces with MLS group encryption
- **Governance**: 4-engine governance system with 28 action types
- **Trust**: Behavioral fact statements, contextual trust scoring, content access control
- **UCAN**: Capability-based authorization with delegation chains
- **Transport**: Native relay protocol with 17 adapter targets across 3 tiers
- **Provenance**: Merkle event log with cryptographic audit trail
- **Discovery**: Context discovery, search, and federation
- **Media**: Media key derivation and signaling
- **MCP Bridge**: Model Context Protocol integration for AI agent connectivity

### SDK Packages

- **Rust**: `scp-core`, `scp-transport`, `scp-platform`, `scp-mcp` on crates.io
- **Python**: `scp-python` on PyPI
- **TypeScript**: `@limn-works/scp-ts` on npm (WASM + native NAPI addon)
- **Kotlin**: `works.limn:scp-kt` and `works.limn:scp-kt-android` on Maven Central
- **Swift**: `SCP` via SwiftPM (GitHub Releases)
