# Bug Catcher Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## SCP Project Knowledge

### Key Files
- `/Users/alec/Developer/limn/scp/.docs/specs/` — Full protocol specs.
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — Build document (~1024 lines).
- `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces (~1477 lines).
- `/Users/alec/Developer/limn/scp/.docs/specs/00-open-questions.md` — Open and resolved design decisions.
- `/Users/alec/Developer/limn/scp/.docs/adrs/phase-2.md` — Phase 2 ADRs (context, roles, tools, events, transport).

### Known Bug Patterns (Feb 2026 Review)
- Stale cross-references from A2A removal (provenance discoveryMethod, resolved decisions)
- HPKE key lifecycle issue in sender-side key layer (MLS LeafNode keys rotate)
- Strict sequence gap rejection vs multi-relay and offline delivery
- Discovery context MLS scaling (MLS does not scale to open-join 10K+ contexts)
- Cover traffic fingerprinting when disabled

### Known Bug Patterns (Feb 2026 Review — PR #4, commit b66c457)
- **Governance symmetry gaps:** Self-approval check in approve_registration not carried to reject_registration or revoke_bridge. Pattern: auth guards added to one path but not parallel paths.
- **Dead ownership checks:** HashMap keyed by DID makes ownership check (entry.did != requester_did) tautological when requester_did is used as lookup key. Pattern: using same value for both lookup and authorization.
- **Misleading event fields:** BridgeRegistrationEvent.governance_did forced to operator DID for Requested events (no governance actor exists). Pattern: non-optional fields that don't apply to all enum variants.
- **Disjoint set invariant not enforced:** Writers/readers Vecs in DiscoveryContext can overlap — no cross-list dedup. Pattern: parallel collections that should be mutually exclusive but aren't validated.
- **Test masking wrong error path:** agent_update_rejects_ownership_mismatch test passes with NotRegistered instead of OwnershipMismatch. Pattern: test asserts on a supertype error that masks the real code path.

### Known Bug Patterns (Feb 2026 Review — PR #4, commit 51a52f4)
- **Semantic split across data sources:** ContactCache uses ANY-match for capability_filter while DiscoveryContext::agent_search uses ALL-match. Pattern: trait without documented filter-semantics contract, relaxed in one impl.
- **Sequential "parallel" async:** query_contexts_parallel is a sequential for-loop due to AFIT lacking Send bounds. Pattern: async fn in trait prevents tokio::spawn/FuturesUnordered.
- **Dead timestamp fields:** ReliabilityScore.last_updated never written by update_score. Pattern: struct field initialized to 0, no code path writes it.
- **Hardcoded zero measurements:** send_to_context records latency_ms: 0 for all successes. Pattern: scoring field exists but measurement not wired.
- **Global tracker for per-context data:** Single SuppressionTracker for all contexts, but check_suppressions takes a single total_relays param applied to all blobs. Pattern: shared state that should be partitioned by context.
- **Silent filter drop:** DiscoveryQuery.min_history silently dropped because AgentSearchParams lacks the field. Pattern: type conversion that loses fields without warning.

### Known Bug Patterns (Feb 2026 Review — PR #76, initial)
- **Empty-set attenuation bypass:** validate_spending_attenuation allows empty child.allowed_adapters to pass when parent restricts adapters. Pattern: for-loop over empty collection silently passes subset checks.
- **Non-deterministic content_hash:** HashSet serialization order varies between runs, breaking ParentGovernanceConfig tamper detection. Pattern: HashSet + serde_json::to_string for "deterministic" hashing.
- **TOCTOU in standing_channel:** Lock dropped before async create, re-acquired to insert — concurrent callers race. Pattern: check-then-act across async boundaries.
- **Comment-code mismatch in ID generation:** generate_standing_channel_id comment says "timestamp makes re-creation unique" but no timestamp in hash. Pattern: Loom agents writing comments that describe intent, not implementation.
- **FFI rotate_key returns wrong identity:** py_identity_rotate_key creates a new identity instead of rotating the passed-in one, discards original DID. Pattern: placeholder implementations shipped as functional API.
- **Iterator termination on empty channel:** PyMessageReceiver.__anext__ returns Ok(None) for TryRecvError::Empty, ending Python async iteration prematurely. Pattern: collapsing distinct error states into single return value.
- **UCAN delegate uses token_id as context:** Python delegate() passes parent_token.token_id instead of context_id to mint(). Pattern: semantic type confusion when both are strings.
- **Unconditional sleep in shutdown:** shutdown_runtime sleeps for full SHUTDOWN_TIMEOUT instead of draining tasks. Pattern: using sleep for synchronization.

### Known Bug Patterns (Feb 2026 Review — PR #76, review fixes)
- **FIXED:** Non-deterministic content_hash (HashSet -> BTreeSet, content_hash returns Result).
- **FIXED:** TOCTOU in standing_channel (tokio::Mutex held across get-or-create, no deadlock risk).
- **FIXED:** RFC 6962 domain separation applied consistently in tree.rs, proof.rs, and all tests.
- **FIXED:** Governance duplicate proposal check added.
- **FIXED:** Unconditional sleep in shutdown reduced to 100ms (still uses sleep, but cosmetic).
- **STILL PRESENT:** Empty-set attenuation bypass in validate_spending_attenuation (spending.rs:460-469). The check_and_record runtime check was added but the attenuation validation function still allows empty child to bypass parent restriction.
- **STILL PRESENT:** Python delegate() still passes token_id as context (ucan.py:242). UcanToken has no context field; hasattr always False. The "fix" added hasattr guard but the field doesn't exist on the dataclass.
- **Pattern:** "Fix" that adds a hasattr/getattr guard for a field that doesn't exist on the type — the guard always takes the fallback path. Must verify the type actually has the field being checked.

### Known Bug Patterns (Feb 2026 — UniFFI bridge SCP-078 review)
- **Key material discarded on identity_create:** InMemoryKeyCustody + ScpIdentity created then dropped; FFI Identity only keeps DID string. Pattern: extracting an identifier from a resource then discarding the resource.
- **UcanToken Drop decrements without matching increment:** UcanToken has Drop impl calling decrement_handle_count() but no constructor calls increment_handle_count(). Currently unreachable (ucan_mint returns Err), but will underflow HANDLE_COUNT when wired. Pattern: Drop impl added symmetrically to all types but increment only added to types with live constructors.
- **scp_shutdown does not actually shut down the runtime:** It waits for handles to drain but RUNTIME is a static dropped only at process exit. No mechanism to prevent new handle creation after scp_shutdown returns.

### Known Bug Patterns (Feb 2026 — claiming.rs/shadow.rs/http.rs review)
- **Divergent canonical attestation formats:** bridge/claiming.rs compute_attestation_canonical_hash uses SHA-256 + to_be_bytes, while trust/attestation.rs canonical_attestation_bytes uses raw concat + to_le_bytes. Pattern: independent re-implementations of canonical serialization that drift.
- **Missing field separators in canonical hash:** compute_claim_canonical_hash and compute_attestation_canonical_hash concatenate fields without length prefixes or delimiters. Pattern: field boundary ambiguity in hash preimages.
- **serve() double-bind (pre-existing):** ApplicationNode::serve() binds to relay.bound_addr which is already occupied by the relay server. Pattern: single address field used for two listeners.

### Known Bug Patterns (Feb 2026 — SCP-154 economy/policy.rs review)
- **Auto-accept bypass via formula-only pricing:** policy_requires_payment only checks CostSchedule fields, ignoring PricingFormula. A policy with empty schedule but base_cost > 0 in PricingFormula evades auto-accept guard. Pattern: partial check of a composite cost model.
- **Overflow silently zeroes cost in verify_cost_sufficiency:** evaluate_cost returns None on arithmetic overflow, unwrap_or(Amount(0)) makes the action free. Pattern: using unwrap_or(zero) for an error condition where zero is the worst-case value.

### Known Bug Patterns (Feb 2026 — Swift bindings PR #86 review)
- **Sync/async mismatch with UniFFI callback interfaces:** Rust `KeyCustodyProvider`, `StorageProvider`, `PushProvider` traits are all synchronous (`fn`). Swift implementations are `async` or actor-isolated. UniFFI-generated protocol will be sync; Swift types cannot conform. Pattern: implementing async methods that need to conform to sync callback interfaces.
- **@unchecked Sendable standards violation:** `AppleDeviceAttestation` uses `@unchecked Sendable` which is explicitly banned in `.docs/standards/swift.md`. Class has no mutable instance state (storedKeyId comment is stale), so `@unchecked` is unnecessary. Pattern: stale justification comments describing removed state.
- **TOCTOU in resolveKeyId:** `loadKeyId()` check then `generateAndStoreKey()` with async gap. Two concurrent `attest()` calls can both see nil and generate two different keys. Pattern: check-then-act across async suspension points.
- **derivePseudonym leaks Keychain items:** Each call creates a new UUID handle and Keychain item, even for identical (keyHandle, contextId) inputs. Documented as "deterministic" but creates orphaned keys. Pattern: deterministic derivation stored under non-deterministic handles.
- **content-available validation accepts JSON true as 1:** NSNumber bridge conflates boolean true with integer 1. Pattern: NSNumber type erasure in JSONSerialization.

### Known Bug Patterns (Feb 2026 — SCP-130 multisig governance review)
- **Late votes accepted after deadline:** approve()/reject() don't check voting_deadline before accepting votes. try_resolve_after_vote checks threshold before expiry, so a post-deadline vote that completes threshold wins. Pattern: enforcement of time boundaries only in the resolution check, not at the entry point.
- **resolve() returns no events:** resolve() transitions proposals to Expired/Rejected but returns only ProposalStatus, not Vec<GovernanceEvent>. Timeout-triggered expiry cannot be recorded in Merkle log. Pattern: method signature designed for status inquiry repurposed for state transition without matching the event contract.
- **Trait missing spec methods:** GovernanceEngine trait omits withdraw_vote() and resolve() that ADR-031 specifies. These are inherent methods on ThresholdEngine only, making them inaccessible via Box<dyn GovernanceEngine>. Pattern: trait surface reduced from spec during implementation, breaking pluggable dispatch.
- **compute_proposal_id field separator gap (pre-existing):** Same concatenation-without-length-prefix pattern found in claiming.rs and attestation.rs. Now also in governance proposal IDs.

### Known Bug Patterns (Feb 2026 — SCP-115 Kotlin coroutine bridge review)
- **Silent message drop in callbackFlow:** trySend() result discarded in onMessage callback. Under back-pressure (buffer full), messages silently lost. Pattern: ignoring ChannelResult from trySend in callbackFlow when lossless delivery is required.
- **Dead catch clause in blocking-to-coroutine bridge:** ffiCallWithCancellation catches CancellationException from a blocking JNA call, but blocking calls cannot throw CancellationException. Only finally{!isActive} fires. Pattern: try/catch for cooperative exceptions around non-cooperative blocking code.
- **Empty awaitClose with captured handle:** subscriptionHandle captured but awaitClose body is empty. No unsubscribe call means Rust continues invoking callback after Flow cancellation. Pattern: placeholder cleanup that will leak when wired to real FFI.
- **Double-buffering in callbackFlow + .buffer():** callbackFlow already has Channel.BUFFERED internal capacity; .buffer(Channel.BUFFERED) adds another 64-item layer. Total buffer is ~128, not the documented 64. Pattern: redundant buffer operator on callbackFlow.
