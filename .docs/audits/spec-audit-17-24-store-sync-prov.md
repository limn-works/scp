---

# SCP Specification Audit: Unspecified Details in Sections 17, 18, 19, 22, 23, 24

## Executive Summary

This is an exhaustive audit of six SCP specification files for underspecification, ambiguity, missing constants, undefined failure behavior, and security-relevant omissions. The audit identified **73 findings** across the six spec sections. The bulk of the findings concentrate in sections 19 (Economic Governance) and 23 (Sync and Offline Strategy), where the spec transitions from describing architecture to prescribing protocol behavior -- the zone where vagueness becomes exploitable.

The strongest sections are 17 (Persistence and Storage), which is unusually precise for a protocol spec, and 23 (Sync), which has a well-defined constants table. The weakest is 19 (Economic Governance), which describes a payment adapter trait and integration flow but leaves critical operational details to "implementers" -- including relay-level payment interleaving, authorization hold lifetimes, and dispute resolution.

The findings are organized per-file, then by severity.

---

## Section 17: Persistence and Storage

### [17.2] Storage Trait Atomicity Claim Without Enforcement Mechanism
- **Category**: Ambiguous state transitions
- **Location**: Section 17.2, line 62
- **What's missing**: The `delete_prefix` doc comment says "Atomic: either all matching keys are deleted or none are (on error)." This atomicity guarantee is stated but there is no mechanism specified for how non-transactional backends (e.g., `FilesystemStorage`, `InMemoryStorage` with `RwLock`) achieve this. The `FilesystemStorage` description in 17.6 mentions atomic single-file writes (rename) but says nothing about multi-file prefix deletion atomicity. There is no conformance test for atomicity of `delete_prefix` under failure (e.g., crash during partial deletion).
- **Why it matters**: If `delete_prefix("context/{id}/")` crashes mid-way on `FilesystemStorage`, context state is partially deleted -- orphaned membership records with missing context state, or orphaned events with missing membership. Subsequent `restore_all_contexts` would encounter inconsistent state.
- **Severity**: MEDIUM

### [17.2] Missing Maximum Key Length
- **Category**: Missing constants/defaults
- **Location**: Section 17.2-17.3
- **What's missing**: Keys are "UTF-8 strings" with no maximum length specified. The key convention in 17.3 uses DIDs (variable length), context IDs (hex-encoded, variable length), and zero-padded sequence numbers. No maximum key length is specified. SQLite has a default max key of ~1 billion bytes; other backends may not.
- **Why it matters**: An adapter implementing `Storage` for a backend with a shorter key limit (e.g., redb's 4 KiB key limit) would silently truncate or fail. Without a specified max, conformance testing cannot validate key length handling.
- **Severity**: LOW

### [17.3] Missing Maximum Value Size
- **Category**: Missing constants/defaults
- **Location**: Section 17.3-17.4
- **What's missing**: No maximum value size is specified for `store()`. The `ProtocolStore` methods accept `&[u8]` values with no documented upper bound. Context state, MLS group state, and tool registrations could theoretically be arbitrarily large.
- **Why it matters**: Without a value size limit, a malicious or buggy protocol layer could cause OOM in storage backends that buffer the full value in memory. The streaming API exists for `BlobStorage` but not for `Storage`.
- **Severity**: MEDIUM

### [17.3] DID Cache TTL Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 17.4, lines 183-185
- **What's missing**: `cache_did_document` accepts an `expires_at: u64` parameter, but no default or recommended TTL is specified anywhere in the spec. How long should a cached DID document be considered valid? The spec for DID resolution (section 3) and the BEP44 sequence number monotonicity rule (section 18.2.1) are relevant but don't specify a cache duration.
- **Why it matters**: Too short a TTL causes excessive DHT queries (bandwidth, latency). Too long a TTL means stale DID documents (missed key rotations, relay URL changes). An implementor must guess.
- **Severity**: MEDIUM

### [17.3] TOFU Record Format Undefined
- **Category**: Missing wire format details
- **Location**: Section 17.4, lines 188-189
- **What's missing**: `store_tofu_record` and `load_tofu_record` accept and return `&[u8]` / `Option<Vec<u8>>`. The actual format of a TOFU record is not defined in this section and no cross-reference is provided to where it IS defined.
- **Why it matters**: An implementor cannot tell what fields a TOFU record contains or how to serialize it.
- **Severity**: LOW

### [17.5] StoredValue Version 0 Semantics Undefined
- **Category**: Missing edge cases
- **Location**: Section 17.5, lines 266-276
- **What's missing**: The `StoredValue` envelope uses `version: u16`. What is the initial version number? Is it 0 or 1? The `Migratable` trait says `CURRENT_VERSION` but doesn't specify the starting version or whether version 0 is reserved for "pre-versioning" data written before the envelope was introduced.
- **Why it matters**: During initial deployment, if data is written with version 0 and later the spec wants to use version 0 to mean "legacy unversioned data," there's an ambiguity.
- **Severity**: LOW

### [17.5] No MessagePack Field Ordering Guarantee
- **Category**: Missing wire format details
- **Location**: Section 17.5
- **What's missing**: The spec says "MessagePack (rmp-serde)" but does not specify whether serialization uses positional (array) or named (map) encoding. This is a known issue (referenced by issue #348). Positional encoding breaks if fields are reordered; named encoding is more robust but larger.
- **Why it matters**: Cross-version compatibility and migration correctness depend on knowing whether field position or field name is the serialization key.
- **Severity**: MEDIUM (already tracked as #348)

### [17.6] SQLCipher Key Derivation Source Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 17.6, lines 311-322
- **What's missing**: The SQLCipher PRAGMA shows `PRAGMA key = '<derived_key>'` but the derivation process is described only as "Encryption key derived from identity key material stored in platform key custody (Keychain/Keystore)." The specific derivation function (HKDF? PBKDF2? Direct use?) and domain separation label are not specified.
- **Why it matters**: Without a specified derivation, two implementations might derive different keys from the same identity material, making databases non-portable. More critically, if the derivation reuses a key used elsewhere (e.g., signing key used directly as encryption key), it creates a cryptographic cross-protocol attack surface.
- **Severity**: HIGH

### [17.6] WASM Value-Level Encryption Key Derivation Unspecified
- **Category**: Security-relevant omissions
- **Location**: Section 17.6, line 283
- **What's missing**: "Each value is encrypted with a key derived from the identity's WebCrypto key before writing to wa-sqlite." No encryption algorithm, key derivation function, IV/nonce management, or authentication tag handling is specified. Is this AES-GCM? AES-CBC? What's the nonce strategy? Are nonces stored alongside the ciphertext? Is there an authentication tag?
- **Why it matters**: This is a complete encryption scheme left to implementor discretion. A naive implementation could use ECB mode, reuse nonces, or omit authentication -- all of which have been demonstrated in real-world attacks against encrypted databases.
- **Severity**: HIGH

### [17.7] ReDB TTL Enforcement Interval Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 17.7, line 403
- **What's missing**: "TTL enforcement via periodic scan of the blobs table" -- what period? Every minute? Every hour? On every query? The SQLite and S3 backends have natural mechanisms (index on `expires_at`, prefix listing on `expiry/`), but redb requires a scan with no specified interval.
- **Why it matters**: Too frequent = performance impact. Too infrequent = expired blobs served to clients. The conformance test for "purge removes only expired blobs" tests correctness but not timeliness.
- **Severity**: LOW

### [17.9] MLS Storage Bridge Key Sanitization Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 17.9, line 476
- **What's missing**: The bridge "validates context IDs via `sanitize_key_component`" but this sanitization function is not defined in this section. What characters are allowed/rejected? What happens with path traversal characters (`../`) in context IDs?
- **Why it matters**: If `sanitize_key_component` is insufficient, a malicious context ID could escape the `mls/{context_id}/` namespace and overwrite keys in other namespaces (e.g., `identity/` or `tls/`). This is a classic path traversal.
- **Severity**: MEDIUM

### [17.10] Migration Chain Ordering Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 17.10, lines 496-500
- **What's missing**: The `Migratable` trait has `migrate(old_version: u16, data: &[u8]) -> Option<Self>` which "returns None if migration from this version is not supported." But the spec says "each migration step transforms bytes from version N to version N+1. The chain is applied iteratively." If the trait method signature takes raw bytes, how does the chain work? Does each step produce bytes that the next step consumes? Or does each step produce `Self`? The signature returns `Option<Self>`, not `Option<Vec<u8>>`, so intermediate steps would need to serialize back to bytes.
- **Why it matters**: Implementors need to know whether migration functions are `(u16, &[u8]) -> Option<Self>` (single-step) or `(u16, &[u8]) -> Option<Vec<u8>>` (chainable). The current signature implies single-step only, contradicting the "iterative chain" description.
- **Severity**: MEDIUM

### [17.10] Key-Space Migration Schema Version Not Initialized
- **Category**: Missing edge cases
- **Location**: Section 17.10, lines 501-503
- **What's missing**: "On startup, `ProtocolStore` checks a `_meta/schema_version` key." What happens when this key does not exist (first run, or migration from before this mechanism was introduced)? Is the absence of the key treated as version 0? Version 1? Error?
- **Why it matters**: The bootstrapping case is undefined. Every storage backend will encounter this on first initialization.
- **Severity**: LOW

---

## Section 18: Addressability and Deployment

### [18.2.1] SCPRelay URL Path Validation Not Specified
- **Category**: Missing conformance criteria
- **Location**: Section 18.2.1, line 37
- **What's missing**: The canonical path is `/scp/v1` but there is no specified behavior for non-canonical paths (e.g., `wss://relay.example.com/scp/v2`, `wss://relay.example.com/custom/path`). Must clients reject non-`/scp/v1` paths? Or is the path just convention?
- **Why it matters**: If the path is informational, version negotiation is impossible. If it's mandatory, future protocol versions need a transition plan.
- **Severity**: LOW

### [18.2.3] Relay Preference Ordering Semantics Undefined
- **Category**: Vague requirements
- **Location**: Section 18.2.3, line 73
- **What's missing**: "Relay entries are ordered by preference (first entry = preferred relay). Clients SHOULD respect ordering when selecting a subset." But no criteria for when to use a subset vs. all relays is specified. How many relays should a client use simultaneously? What if the preferred relay is unreachable -- does the client fall back to the second, or try all in parallel?
- **Why it matters**: Different implementations could use 1 relay (poor suppression resistance) or all relays (wasteful bandwidth). The spec says "3+ relays" for publishing (ADR-012) but doesn't specify subscriber-side behavior.
- **Severity**: LOW

### [18.3.1] .well-known/scp Maximum Document Size Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 18.3.1
- **What's missing**: No maximum size for the `.well-known/scp` JSON document. The `contexts` array is unbounded. The `handles` map (section 22.6.1) is unbounded. A domain with 100,000 broadcast contexts would generate an enormous document.
- **Why it matters**: Clients fetching `.well-known/scp` need to know when to stop reading. Without a limit, a malicious domain could serve a multi-gigabyte document to exhaust client memory.
- **Severity**: MEDIUM

### [18.3.1] .well-known/scp HTTP Caching Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 18.3.1
- **What's missing**: No `Cache-Control` or caching guidance for the `.well-known/scp` endpoint itself. The broadcast projection endpoints have explicit caching headers (section 18.11.3-4), but `.well-known/scp` does not.
- **Why it matters**: Without caching guidance, implementations may serve stale relay URLs (missing rotations) or force every client to re-fetch (DDoS risk).
- **Severity**: LOW

### [18.3.2] Verification Chain Timeout Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 18.3.2, lines 128-133
- **What's missing**: The verification chain (fetch `.well-known/scp`, resolve DID via DHT, compare) involves two network operations. No timeout is specified for either step or for the overall verification. No behavior is specified if DHT resolution fails (is `.well-known/scp` data usable without verification?).
- **Why it matters**: In practice, DHT resolution can take seconds to minutes depending on network conditions. Without a timeout, clients may hang. Without fallback behavior, clients with no DHT access (e.g., behind restrictive firewalls) cannot use `.well-known/scp` at all.
- **Severity**: MEDIUM

### [18.4.1] Context ID Hex Length Not Specified
- **Category**: Missing wire format details
- **Location**: Section 18.4.1, line 203
- **What's missing**: "Context ID MUST be valid hexadecimal" but the length is not specified. Is it always 64 hex characters (32 bytes, SHA-256)? Or variable length? Parsers need to know whether to validate length.
- **Why it matters**: Without a fixed expected length, parsers cannot distinguish between a truncated context ID and a valid short one.
- **Severity**: LOW

### [18.5.1] Fallback Relay List Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 18.5.1, lines 250-251
- **What's missing**: "A hardcoded list of well-known community relays shipped with the SDK" -- but no actual relay URLs are specified, nor a mechanism for updating the list without an SDK release. The spec says "MUST include at least one free relay" but doesn't specify one.
- **Why it matters**: At launch, there are no well-known community relays. The SDK ships with an empty or operator-provided list. The invariant "free relays MUST always exist in bootstrap list" is unenforceable if there are no free relays to list.
- **Severity**: MEDIUM

### [18.6.2] ApplicationNodeBuilder Type-State Generics Incomplete
- **Category**: Missing wire format details
- **Location**: Section 18.6.2, lines 342-365
- **What's missing**: The builder uses type-state pattern with generics `<K, D, S, Dom, Id>` but the concrete marker types (`HasDomain`, `HasNoDomain`, `HasIdentity`, `NoDomain`, `NoIdentity`) are not defined. The `impl` blocks use `...` for type parameters. The relationship between `generate_identity` and `explicit_identity` and their error conditions are not specified.
- **Why it matters**: This is API documentation, not a wire format, so the impact is on implementors rather than interoperability. But the incomplete type signatures make it unclear what the valid state transitions are.
- **Severity**: LOW

### [18.6.3] ACME Failure Behavior Not Specified
- **Category**: Undefined error/failure behavior
- **Location**: Section 18.6.3, lines 370-377
- **What's missing**: What happens when ACME certificate provisioning fails? The spec mentions DNS-01 as an alternative to HTTP-01 but doesn't specify: (a) How the node selects between challenge types. (b) What happens if both fail -- does the node fall back to `ws://`? Fail to start? Retry? (c) What happens if auto-renewal fails 30 days before expiry -- does the node continue with the expiring cert? Alert the operator? Shut down?
- **Why it matters**: ACME failures are common in production (port 80 blocked, DNS propagation delay, rate limits). The failure mode determines whether the node is available during certificate issues.
- **Severity**: MEDIUM

### [18.6.4] DID Re-Publication Trigger Not Fully Specified
- **Category**: Missing edge cases
- **Location**: Section 18.6.4, line 383
- **What's missing**: "DID publication happens once on `.build()` and on relay URL changes." But relay URL changes are never specified as a runtime operation on `ApplicationNode`. There's no `update_relay_url()` method. And the BEP44 republication interval for liveness (keeping the DHT entry alive) is not specified in this section, though section 3 mentions "every 6 days."
- **Why it matters**: BEP44 entries have a TTL. Without periodic republication, the identity becomes unresolvable after the DHT entry expires. The 6-day interval is mentioned in section 3 but not cross-referenced here, and `ApplicationNode` doesn't appear to have a background republication task.
- **Severity**: MEDIUM

### [18.10.2] Dev API Token Entropy Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 18.10.2, lines 487-488
- **What's missing**: "Token format: `scp_local_token_<32 random hex characters>`" -- 32 hex characters = 128 bits of entropy. This is specified but the randomness source is not. Must it be CSPRNG? And the token is "logged at INFO level on startup" -- this means it appears in log files. No guidance on log file permissions or rotation.
- **Why it matters**: If an attacker can read log files (common on shared hosting), they get the dev API token. Logging secrets at INFO is an anti-pattern.
- **Severity**: MEDIUM

### [18.10.3] Dev API Response Body Formats Not Specified
- **Category**: Missing wire format details
- **Location**: Section 18.10.3, lines 496-504
- **What's missing**: The endpoint table lists 7 endpoints but only the error response format is specified. The success response bodies for `GET /health`, `GET /identity`, `GET /relay/status`, `GET /contexts`, etc. are not defined with field names and types.
- **Why it matters**: Without response schemas, the dev API is not interoperable across implementations.
- **Severity**: LOW

### [18.11.3] Feed Endpoint Missing Error Responses
- **Category**: Undefined error/failure behavior
- **Location**: Section 18.11.3
- **What's missing**: The feed endpoint specifies the success response and the `since` cursor behavior, but does not specify: (a) What HTTP status code for an unknown `routing_id` -- 404? (b) What for an invalid `limit` value (negative, zero, >100)? (c) What for a malformed `since` blob ID? The `since` cross-context check returns 400, but other error cases are unspecified.
- **Why it matters**: Inconsistent error handling across implementations makes client integration fragile.
- **Severity**: LOW

### [18.11.5] Key Epoch Retention Duration Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 18.11.5, lines 652-653
- **What's missing**: "Keys are retained per epoch for the blob TTL window." But what is the blob TTL window for broadcast contexts? The relay's `max_blob_ttl` (from `relay_config`) is a relay-level setting, not a context-level one. If a context's blobs have different TTLs on different relays, which TTL governs key retention?
- **Why it matters**: Keys retained too long leak forward secrecy. Keys deleted too early make valid blobs undecryptable.
- **Severity**: MEDIUM

### [18.11.6] Projection Rate Limit X-Forwarded-For Trust Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 18.11.6, line 661
- **What's missing**: "Configure `X-Forwarded-For` / `X-Real-IP` extraction with a trusted-proxy allowlist" -- but no mechanism is specified for configuring this allowlist. Is it a builder method? An environment variable? A config file?
- **Why it matters**: Without proper `X-Forwarded-For` trust configuration, an attacker can spoof the header to bypass rate limiting. This is a well-known attack vector against rate-limited endpoints behind reverse proxies.
- **Severity**: MEDIUM

---

## Section 19: Economic Governance

### [19.1.1] CurrencyCode Validation Not Specified
- **Category**: Missing conformance criteria
- **Location**: Section 19.1.1, lines 46-47
- **What's missing**: `CurrencyCode(pub [u8; 4])` is "3-4 character code, null-padded." But: (a) Is validation required against ISO 4217? Or can arbitrary strings be used? (b) What null-padding direction (trailing)? (c) Are protocol-defined codes (BTC, SAT, SOL, USDC) a closed set or extensible? (d) What happens when a client encounters an unknown currency code?
- **Why it matters**: Without validation rules, a malicious payee could use a custom currency code to confuse payer UIs into displaying wrong amounts.
- **Severity**: MEDIUM

### [19.2.1] PaymentAuthorization Hold Duration Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 19.2.1, lines 158-159
- **What's missing**: `PaymentAuthorization` has `created_at` and `expires_at` fields but no default or maximum hold duration is specified. How long can an authorization be held before it must be captured or voided?
- **Why it matters**: Long authorization holds tie up payer funds indefinitely. Different payment rails have different hold limits (Stripe: 7 days, credit cards: 30 days). Without a protocol-level maximum, a malicious payee could hold authorizations open indefinitely.
- **Severity**: HIGH

### [19.2.1] PaymentAuthorization adapter_state Size Limit Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 19.2.1, line 159
- **What's missing**: `adapter_state: Vec<u8>` is "adapter-specific opaque state" with no size limit. Since `PaymentAuthorization` is persisted in `ProtocolStore` and potentially serialized in envelopes, unbounded opaque state is a DoS vector.
- **Why it matters**: A malicious adapter could return a multi-megabyte `adapter_state`, causing storage bloat and serialization overhead.
- **Severity**: MEDIUM

### [19.2.2] Relay-Level Payment Interleaving Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 19.2.2 and 19.8
- **What's missing**: The action-payment integration sequence (section 19.2.2) describes context-level payments where the authorization is "attached to action envelope (inside encrypted payload)." But for relay-level payments (`per_publish`, `per_byte_stored`), the relay is outside the encrypted envelope. How does a client pay a relay? Is it: (a) An HTTP header on the WebSocket upgrade? (b) A separate payment message before each PUBLISH? (c) A pre-paid balance system? (d) An x402/L402-style challenge-response on the WebSocket? The spec says "Agent evaluates relay config (visible before connecting) -> selects compatible adapter -> authorizes per-action -> relay verifies + captures" but provides no wire format for relay payment messages.
- **Why it matters**: This is a **complete protocol gap**. Relay-level payments are advertised as a feature (section 18.3.3, section 19.8) but the actual wire protocol between client and relay for payment is entirely unspecified. An implementor cannot build a paid relay.
- **Severity**: CRITICAL

### [19.2.3] "No Handshake" Negotiation vs Relay Payment Contradiction
- **Category**: Cross-reference inconsistencies
- **Location**: Section 19.2.3
- **What's missing**: "Stateless. No handshake." But relay-level payments require the relay to reject operations and the client to respond with payment -- that IS a handshake. The x402 and L402 patterns listed in 19.2.7 are explicitly challenge-response protocols (HTTP 402 -> payment -> retry). The "no handshake" claim applies to context-level payments (where the payee evaluates after delivery) but not to relay-level payments (where the relay must verify before accepting a PUBLISH).
- **Why it matters**: The spec's own description contradicts itself between "no handshake" and the relay payment patterns that require one.
- **Severity**: MEDIUM

### [19.3] Economic Policy Change Notification Period Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 19.3, line 291
- **What's missing**: "Changes go through governance, are logged in the event log, visible to all members, take effect after a notification period." What notification period? An hour? A day? A week? No default is specified, and the governed change mechanism (section 19.4, "grace period before effect") also has no specified duration.
- **Why it matters**: Without a minimum notification period, a context operator could change pricing from $0 to $1000/message with zero notice, trapping agents with queued messages.
- **Severity**: HIGH

### [19.3] EconomicPolicy payee DID Verification Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 19.3, line 302
- **What's missing**: `payee: DID` -- who verifies that the payee DID is legitimate? Can any context admin set any DID as the payee? Is there a requirement that the payee DID be a member of the context? Or the context creator?
- **Why it matters**: A compromised admin could change the payee DID to their own, redirecting all payments. Without verification requirements, this is an expected attack vector.
- **Severity**: MEDIUM

### [19.3] Tool-Level Cost Payee and Currency Independence
- **Category**: Missing edge cases
- **Location**: Section 19.3, line 314
- **What's missing**: "Tool costs carry their own payee DID (may differ from context payee)." But what if the tool's currency differs from the context's currency? Must the payer hold adapter credentials for both? What if the payer has a spending UCAN for USD but the tool costs BTC?
- **Why it matters**: Multi-currency contexts create combinatorial adapter requirements that the spec doesn't address.
- **Severity**: LOW

### [19.4] PricingMetric Measurement Windows Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 19.4, lines 349-354
- **What's missing**: `ContextMessageRate` is "messages/min" but over what window? Last 1 minute? Last 5 minutes? Exponential moving average? `SenderVelocity` is "sender's messages in sliding window" but what sliding window duration? `StorageUsage` is "context storage in bytes" but measured where -- client side? Relay side? Including expired blobs?
- **Why it matters**: If payer measures `ContextMessageRate` over 1 minute and receiver measures over 5 minutes, they will compute different costs from the same formula. The spec says "both sides evaluate the same formula against observable metrics" but the metrics themselves are not deterministically defined.
- **Severity**: HIGH

### [19.4] PricingFormula Evaluation Order Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 19.4, lines 331-345
- **What's missing**: When a formula has multiple variables, what is the evaluation order? Is the result `base_cost + sum(all variables)` and then cap/floor applied? Or are cap/floor applied per-variable? What about negative coefficients -- can a variable reduce cost below the base_cost?
- **Why it matters**: The spec uses integer arithmetic to avoid float nondeterminism, but evaluation order ambiguity reintroduces it. `cap(base + var1 + var2)` vs `cap(base + cap(var1) + cap(var2))` vs `cap(base + var1) + var2` produce different results.
- **Severity**: MEDIUM

### [19.4] Step Function Threshold Interpolation Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 19.4, lines 343-344
- **What's missing**: `Step { metric, thresholds: Vec<(u64, Amount)> }` -- are thresholds cumulative or independent? If thresholds are `[(10, +$0.001), (50, +$0.01)]` and the metric is 60, is the cost `+$0.001 + $0.01 = $0.011` (cumulative) or `+$0.01` (highest matching)? The anti-spam example in 19.7 appears to show cumulative (the "extreme" tier lists `$0.112/msg` which is `$0.001 + $0.001 + $0.01 + $0.10`), but this is not explicitly stated.
- **Why it matters**: Cumulative vs. highest-matching produces dramatically different costs at high metric values.
- **Severity**: MEDIUM

### [19.4] CostInsufficient Retry Loop Not Bounded
- **Category**: Missing edge cases
- **Location**: Section 19.4, lines 357-368
- **What's missing**: "Payer can retry with updated amount." But what prevents an infinite retry loop where: (a) Payer authorizes based on current metrics. (b) By the time authorization reaches receiver, metrics have changed. (c) Receiver rejects. (d) Payer retries. (e) Repeat. No maximum retry count or backoff is specified.
- **Why it matters**: Under high message rate conditions, the `ContextMessageRate` metric changes continuously, making it difficult for payer and receiver to agree on cost. Without bounded retries, the payer could loop indefinitely.
- **Severity**: MEDIUM

### [19.5] SpendingCapability time_window Semantics Unclear
- **Category**: Ambiguous state transitions
- **Location**: Section 19.5, lines 386-391
- **What's missing**: `time_window: Duration` is a "rolling window for max_total." But: (a) Rolling from when? First spend? UCAN issuance time? (b) How is the running total tracked? By the payer SDK? By each payee independently? (c) If the payer interacts with multiple payees, do all spends count against the same total?
- **Why it matters**: Without clear tracking semantics, the `max_total` constraint is unenforceable in a decentralized setting. Each payee sees only its own payments, not the payer's total across all payees.
- **Severity**: HIGH

### [19.5] SpendingCapability Enforcement Location Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 19.5
- **What's missing**: Where is `max_total` enforced? The payer SDK tracks its own spending? The payee verifies? A trusted third party? In a decentralized protocol with no trusted server, who maintains the authoritative spending counter?
- **Why it matters**: The payer SDK can trivially lie about its running total. The payee has no way to know what the payer has spent elsewhere. The `max_total` constraint is only as trustworthy as the payer's honesty -- which defeats the purpose of a spending limit.
- **Severity**: HIGH

### [19.6] PaymentReceipt receipt_id Derivation Not Specified
- **Category**: Missing wire format details
- **Location**: Section 19.6, line 410
- **What's missing**: `receipt_id: [u8; 32]` -- how is this computed? Is it a hash of the receipt fields? A random value? An adapter-provided value? The storage API uses it as a key (`store_payment_receipt(context_id, receipt_id, receipt)`), so uniqueness matters.
- **Why it matters**: Without a specified derivation, two implementations could generate different receipt IDs for the same payment, making receipt verification fail across implementations.
- **Severity**: MEDIUM

### [19.6] PaymentReceipt signature Scope Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 19.6, line 423
- **What's missing**: `signature: Vec<u8>` is "Ed25519 signature by payer." But what is signed? The entire receipt? A canonical serialization of specific fields? If the signature covers `adapter_proof` (which varies by adapter), the verification must know the canonical form. Also, which key signs -- the payer's `#active` key? `#agent` key? Either?
- **Why it matters**: Without specifying the signed payload, receipt signature verification is non-interoperable. Different implementations would compute different signatures for the same receipt.
- **Severity**: HIGH

### [19.6.1] EconomicPolicyChanged Event Missing New Policy Diff
- **Category**: Missing wire format details
- **Location**: Section 19.6.1
- **What's missing**: The `EconomicPolicyChanged` event contains "Old policy hash, new `EconomicPolicy`, governance justification" but the field names and serialization format are not specified. What hash algorithm for the old policy hash? SHA-256?
- **Why it matters**: Without field names, the event cannot be deserialized interoperably.
- **Severity**: LOW

### [19.7] Anti-Spam Cost Escalation vs Free Contexts
- **Category**: Missing edge cases
- **Location**: Section 19.7
- **What's missing**: The anti-spam section describes cost escalation as a spam deterrent. But the spec also says "Free operation is the default" and "no economic policy = free." For free contexts (the majority), there is no cost-based anti-spam. The section doesn't acknowledge this gap or cross-reference the non-economic rate limiting in section 9.2.1.
- **Why it matters**: An implementor reading section 19.7 in isolation might think cost escalation is the only spam prevention mechanism.
- **Severity**: LOW

### [19.8] Relay per_byte_stored Billing Period Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 19.8, line 486
- **What's missing**: `per_byte_stored: 1` (1 cent per byte in the example). But per what time period? Per second? Per hour? Until blob expires? Is it a one-time storage fee or recurring? The spec says "Amount in smallest currency unit" but doesn't specify the billing model.
- **Why it matters**: 1 cent per byte as a one-time fee for a 256KB blob = $2,621. As a per-second fee, it's astronomical. The billing semantics are critical for relay operators to set rational prices.
- **Severity**: HIGH

### [19.12] Dispute Resolution Not Specified
- **Category**: Missing edge cases
- **Location**: Section 19.12
- **What's missing**: What happens when: (a) Adapter captures payment but action fails? The spec says "On failure at step 5-7: adapter.void(auth)" but void might not be possible after capture. (b) Adapter authorizes but the adapter itself goes down before capture? (c) Payer disputes a captured payment? There is no dispute resolution mechanism, no partial refund flow, no timeout for uncaptured authorizations.
- **Why it matters**: In real payment systems, disputes are the primary source of operational complexity. The spec has `refund()` in the trait but no protocol for when/how/why it's invoked.
- **Severity**: MEDIUM

### [19.14] Free Relay Invariant Enforcement Mechanism Missing
- **Category**: Missing conformance criteria
- **Location**: Section 19.14, invariant 8
- **What's missing**: "Free relays MUST always exist in bootstrap list" is stated as a protocol invariant. But how is this enforced? If Limn's relay charges and no community relays exist at launch, the invariant is violated. There is no mechanism for verifying that the bootstrap list contains a free relay at SDK build time or runtime.
- **Why it matters**: A protocol invariant without an enforcement mechanism is a suggestion, not an invariant.
- **Severity**: MEDIUM

---

## Section 22: Human-Readable Addressing

### [22.2] Address Format Collision with Email
- **Category**: Missing edge cases
- **Location**: Section 22.2, lines 23-30
- **What's missing**: The `<local-part>@<scope>` format is identical to email addresses. The spec does not address how clients distinguish between an SCP address and an email address when presented in free text. When a user types `alice@example.com`, is it an email or an SCP address? Context is required but not specified.
- **Why it matters**: In UIs that handle both email and SCP, auto-detection will produce false positives. The spec needs to either prefix SCP addresses (e.g., `scp:alice@example.com`) or specify that SCP addresses are only valid in SCP-specific input fields.
- **Severity**: LOW

### [22.2] Scope Disambiguation for Single-Label Domains
- **Category**: Missing edge cases
- **Location**: Section 22.2, lines 33-38
- **What's missing**: Scope disambiguation relies on the presence of a `.` to distinguish domain handles from discovery context handles. But single-label domains exist (e.g., `localhost`, `.internal` TLDs, some ccTLDs like `.ai`). `alice@ai` -- is this a discovery context named "ai" or the domain `ai`?
- **Why it matters**: The disambiguation rule is fragile. In practice, new TLDs and single-label domains mean the "contains a dot" heuristic has edge cases.
- **Severity**: LOW

### [22.3.1] Handle Tool DID-Signature Verification Scheme Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 22.3.1, line 148
- **What's missing**: "All handle tool requests MUST carry a DID signature over the request payload." But: (a) What is "the request payload" -- the JSON body? A canonical serialization? (b) What signature scheme -- Ed25519 over the raw bytes? JWS? (c) Where is the signature carried -- an HTTP header? A field in the request body? A UCAN?
- **Why it matters**: Without specifying the signature format, implementations cannot verify each other's registrations. Cross-implementation discovery context participation would fail.
- **Severity**: HIGH

### [22.3.2] Discovery Context Naming Normalization Not Deterministic
- **Category**: Underspecified algorithms
- **Location**: Section 22.3.2, lines 154-155
- **What's missing**: "Normalized: lowercased, spaces replaced with hyphens, non-alphanumeric characters (except hyphens) removed." But: (a) What about underscores? The `local-part` allows underscores but the scope normalization removes "non-alphanumeric except hyphens." (b) What about consecutive hyphens after normalization (e.g., "My -- Context" -> "my---context" or "my-context")? (c) What about leading/trailing hyphens after normalization?
- **Why it matters**: Non-deterministic normalization means two implementations could derive different canonical scope names from the same metadata name.
- **Severity**: MEDIUM

### [22.3.2] Scope Name Collision Resolution Not Deterministic
- **Category**: Ambiguous state transitions
- **Location**: Section 22.3.2, line 160
- **What's missing**: "If multiple contexts share a name, the SDK uses the most recently used or user-preferred context." This is implementation guidance, not a protocol rule. No default is specified. "Most recently used" requires tracking usage history. "User-preferred" requires explicit configuration. Neither is mandatory.
- **Why it matters**: Two SDKs resolving the same address could resolve to different discovery contexts, breaking resolution consistency.
- **Severity**: MEDIUM

### [22.4] Petname Maximum Length Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 22.4
- **What's missing**: Petnames are "any string the user chooses" with no maximum length. Since they are stored in identity private state and synced across devices, unbounded petnames could bloat private state.
- **Why it matters**: Minor storage concern, but completeness.
- **Severity**: LOW

### [22.5.1] Attestation Lookup Pagination Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 22.5.1, lines 263-279
- **What's missing**: The `attestation_lookup` tool returns `results: [{...}]` with no pagination mechanism. If a popular handle has hundreds of claiming DIDs, the response could be very large.
- **Why it matters**: Unbounded response size in a discovery context tool call.
- **Severity**: LOW

### [22.5.2] Auto-Registration Failure Behavior Not Specified
- **Category**: Undefined error/failure behavior
- **Location**: Section 22.5.2, lines 286-293
- **What's missing**: "SDK SHOULD register the mapping in known discovery contexts." But what happens when registration fails (discovery context unreachable, registration rejected by governance, network error)? Is the attestation still created? Is the user notified? Is registration retried?
- **Why it matters**: Silent registration failure means the attestation exists but is not discoverable via reverse-lookup, which the user might not realize.
- **Severity**: LOW

### [22.6.1] Handles Map Maximum Entry Count Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 22.6.1
- **What's missing**: The `handles` map in `.well-known/scp` has no specified maximum entry count. Combined with the broadcast context limit in the `contexts` array, a large domain could serve thousands of handles.
- **Why it matters**: Same concern as the overall `.well-known/scp` document size issue (18.3.1).
- **Severity**: LOW

### [22.7] TrustLevel Ordering Not Total
- **Category**: Ambiguous state transitions
- **Location**: Section 22.7, line 411
- **What's missing**: "Trust levels are not strictly ordered -- their relative strength is context-dependent." This means `TrustLevel` cannot be used for mechanical comparison (e.g., "require at least DomainVerified"). Without ordering, an agent cannot write `if trust_level >= minimum_trust` style logic.
- **Why it matters**: The lack of ordering makes policy-based trust decisions impossible without additional agent-specific configuration.
- **Severity**: MEDIUM

### [22.8.2] Unscoped Resolution Timeout Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 22.8.2, lines 443-461
- **What's missing**: Unscoped resolution queries "in parallel: domain handles, discovery contexts, attestation indexes." No timeout is specified for the parallel resolution phase. If one discovery context is slow, does the resolver wait indefinitely? Return partial results after a timeout?
- **Why it matters**: In practice, resolution latency determines UX quality. Without a timeout, a single slow discovery context blocks the entire resolution.
- **Severity**: MEDIUM

### [22.8.4] Resolution Cache Invalidation Not Specified
- **Category**: Missing edge cases
- **Location**: Section 22.8.4, line 479
- **What's missing**: Cache entries have per-layer TTLs but no invalidation mechanism beyond TTL expiry. If a handle is deregistered from a discovery context, the cache could serve stale results for up to 15 minutes (the discovery context TTL). No push-based invalidation or event-based cache clearing is specified.
- **Why it matters**: 15 minutes of stale handle resolution could lead a user to contact the wrong DID.
- **Severity**: LOW

---

## Section 23: Sync and Offline Strategy

### [23.2] Outbound Queue Storage Key Not in Key Convention
- **Category**: Cross-reference inconsistencies
- **Location**: Section 23.2, line 37
- **What's missing**: "Messages are serialized... and stored in `ProtocolStore` under `queue/{context_id}/{seq:020d}`." But the key convention in section 17.3 does not list `queue/` as a namespace. The `ProtocolStore` API in section 17.4 has no `store_queued_message` or `load_queue` methods.
- **Why it matters**: The queue keys are specified in section 23 but not reflected in the storage key convention (section 17.3) or the `ProtocolStore` API (section 17.4). An implementor following section 17 alone would not know about queue storage.
- **Severity**: MEDIUM

### [23.2] Queue Overflow Eviction Policy Not Deterministic
- **Category**: Underspecified algorithms
- **Location**: Section 23.2, line 38
- **What's missing**: "When full, the oldest messages are dropped." Oldest by what criterion? `queued_at` timestamp? Sequence number within the queue? Oldest across all contexts or oldest within the context that's being added to? If the per-context limit (1,000) is reached for context A but the total (10,000) is not, does the queue drop from context A or refuse the new message?
- **Why it matters**: The eviction policy determines which messages survive offline periods. Different interpretations lead to different message loss patterns.
- **Severity**: LOW

### [23.3] Reconnection Phase Ordering Dependencies Not Explicit
- **Category**: Ambiguous state transitions
- **Location**: Section 23.3, lines 46-60
- **What's missing**: The six phases are "ordered" but the dependencies between them are implicit. Phase 4 (sender key re-acquisition) depends on Phase 1 (relay catch-up) providing `SenderKeyEpochAdvance` events. Phase 6 (queue drain) depends on Phase 2 (epoch reconciliation). But can Phase 3 (event log sync) run concurrently with Phase 4? The spec says "each context is synced concurrently" but within a context, are phases sequential?
- **Why it matters**: Incorrect ordering could cause Phase 6 to drain a queue before Phase 2 has reconciled the epoch, resulting in messages encrypted with the wrong epoch.
- **Severity**: MEDIUM

### [23.3] 120-Second Overall Timeout Behavior Not Specified
- **Category**: Undefined error/failure behavior
- **Location**: Section 23.3, line 60
- **What's missing**: "Each context is synced concurrently, with a 120-second overall timeout. Contexts that timeout are marked as Failed." But: (a) Is the 120-second timeout per-context or for the entire reconnection process? The wording "overall timeout" suggests the latter. (b) If one context takes 119 seconds and another takes 2 seconds, does the slow context block the fast one's queue drain? (c) What happens to partially-synced state when the timeout fires -- is partial progress preserved or rolled back?
- **Why it matters**: If the 120-second timeout is global and one context's epoch catch-up is slow, all other contexts are delayed.
- **Severity**: MEDIUM

### [23.4.1] CommitRangeRequest Wire Format Not in Spec
- **Category**: Missing wire format details
- **Location**: Section 23.4.1, line 72
- **What's missing**: `CommitRangeRequest` is referenced but its wire format is not defined in this section. The ADR (phase-6.md) defines it with fields `{context_id, from_epoch, to_epoch}`, but the spec section does not. Similarly, the response format (`CommitRangeResponse`) is only in the ADR.
- **Why it matters**: Wire format definitions in ADRs but not in the spec create a dual-source-of-truth problem. Implementors reading only the spec cannot implement peer-to-peer commit recovery.
- **Severity**: MEDIUM

### [23.4.1] CommitRangeRequest Sent at Stale Epoch Security Concern
- **Category**: Security-relevant omissions
- **Location**: Section 23.4.1, line 72
- **What's missing**: "The reconnecting member broadcasts a `CommitRangeRequest` as an MLS application message (using their current epoch keys -- they can still encrypt at their stale epoch)." But MLS application messages at a stale epoch are only decryptable by members who still have the old epoch's keys. If the sender key grace window (30 seconds, per ADR-007) has expired, no current member has the old epoch keys. The request would be undecryptable.
- **Why it matters**: For Tier 2 offline durations (4 hours to 7 days), the stale epoch keys are almost certainly destroyed. The `CommitRangeRequest` mechanism only works for very short offline periods -- essentially Tier 1 only. The spec doesn't acknowledge this limitation.
- **Severity**: HIGH

### [23.4.1] Welcome-Based Fast-Forward Authorization Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 23.4.1, lines 73-74
- **What's missing**: "An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage." But: (a) How does the admin know the reconnecting member wants a fast-forward? The reconnecting member's `CommitRangeRequest` may be undecryptable (see previous finding). (b) How is the admin notified? (c) What prevents a non-member from triggering a Welcome-based fast-forward by claiming to be a returning member?
- **Why it matters**: The fast-forward mechanism requires admin action but the triggering mechanism is underspecified. In practice, the admin may never know a fast-forward is needed.
- **Severity**: HIGH

### [23.5.2] ResetRequest Wire Format Not in Spec
- **Category**: Missing wire format details
- **Location**: Section 23.5.2, line 107
- **What's missing**: `ResetRequest` is described with field names ("Includes context_id, member_did, last_known_epoch, reset reason, and signature") but no formal wire format. The ADR defines `pub struct ResetRequest { context_id, member_did, last_known_epoch, reason: ResetReason, signature }` but the spec section does not.
- **Why it matters**: Same dual-source-of-truth issue as `CommitRangeRequest`.
- **Severity**: MEDIUM

### [23.5.2] ResetRequest Replay Protection Not Specified
- **Category**: Security-relevant omissions
- **Location**: Section 23.5.2, line 107
- **What's missing**: `ResetRequest` is "not MLS-encrypted" and "signed by the member's Active Signing Key." But there is no replay protection. An attacker who captures a `ResetRequest` from the relay could replay it later to force a member reset. The request has no timestamp, no nonce, no sequence number.
- **Why it matters**: A relay (which is untrusted) can trivially replay `ResetRequest` messages. Since the relay stores all blobs including `ResetRequest`, and `ResetRequest` is not encrypted, the relay can replay it at any time to force member re-joins. This disrupts the member's participation and forces unnecessary key rotation.
- **Severity**: HIGH

### [23.5.2] Role Re-Assignment During Reset Not Guaranteed
- **Category**: Missing edge cases
- **Location**: Section 23.5.2, step 2
- **What's missing**: "The admin re-assigns the same role during re-add." But MLS `add_member()` does not carry role information -- that's an SCP-layer concern. The spec doesn't specify: (a) How the admin knows what role to re-assign. (b) Whether role re-assignment is atomic with the MLS re-add. (c) What happens if the admin doesn't have `RoleAssign` capability.
- **Why it matters**: If role re-assignment is a separate step after MLS add, there is a window where the member is in the group without their previous role. During this window, their capabilities are wrong.
- **Severity**: MEDIUM

### [23.5.3] Pending Governance Proposals Loss Not Recoverable
- **Category**: Missing edge cases
- **Location**: Section 23.5.3, line 119
- **What's missing**: "Any pending governance proposals they initiated while offline (proposals reference specific epochs)" are lost. But there's no mechanism for the resetting member to learn which proposals were lost, or to re-submit them. The member just silently loses their proposals.
- **Why it matters**: For threshold governance, a lost vote could change the outcome of a pending decision. The member should be notified of what proposals they had pending.
- **Severity**: LOW

### [23.5.4] Bilateral Context Reset Admin Determination
- **Category**: Missing edge cases
- **Location**: Section 23.5.4, lines 130-131
- **What's missing**: "In a two-person context where one member has been offline for weeks, the other member is always the admin." But bilateral contexts might have specific governance models. If both members have equal roles, who is "the admin"? If the bilateral context uses `Unanimity` governance, can a single member process a reset?
- **Why it matters**: The spec assumes a clear admin in bilateral contexts, which may not match the governance model.
- **Severity**: LOW

### [23.6.1] GovernanceFreeze Resolution Protocol Not Specified
- **Category**: Undefined error/failure behavior
- **Location**: Section 23.6.1, line 146
- **What's missing**: "The context enters a `GovernanceFreeze` state. No new governance actions are accepted until an admin explicitly resolves the conflict." But: (a) How does the admin resolve? Is there a `ResolveConflict` governance action? (b) Does `GovernanceFreeze` affect non-governance operations (messages, tool calls)? (c) What if the admin is one of the conflicting parties?
- **Why it matters**: `GovernanceFreeze` is a DoS vector. Two colluding members can freeze a context's governance by submitting simultaneous proposals. Without a resolution mechanism, the freeze could be permanent.
- **Severity**: HIGH

### [23.6.1] Deadlock Detection Mechanism Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 23.6.1, line 148
- **What's missing**: "Detected when the governance model requires votes from permanently unavailable DIDs." But: (a) When is a DID "permanently unavailable"? After what duration? (b) How is this distinguished from "temporarily unavailable" (just a long offline period)? (c) What mechanism detects this -- periodic polling? Admin manual action?
- **Why it matters**: Without a detection threshold, governance models that require specific members' votes can be permanently stuck if a member loses their keys.
- **Severity**: MEDIUM

### [23.7] Event Log Reconciliation Event Request Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 23.7, step 3
- **What's missing**: "The member requests the missing events via event range requests." What is an "event range request"? Is it the same as `CommitRangeRequest`? A different message type? What are its fields?
- **Why it matters**: A fundamental reconciliation mechanism lacks a wire format definition.
- **Severity**: MEDIUM

### [23.8] Multi-Device Queue Deduplication Hash Not Specified
- **Category**: Missing wire format details
- **Location**: Section 23.8, line 174
- **What's missing**: "Each queued message includes a content-addressable hash." Hash of what? The inner envelope? The plaintext content? The signed content? What hash algorithm -- SHA-256?
- **Why it matters**: Two devices computing different hashes for the "same message" would fail to deduplicate.
- **Severity**: LOW

### [23.9] Reorder Buffer Gap Semantics Unclear
- **Category**: Ambiguous state transitions
- **Location**: Section 23.9, lines 178-182
- **What's missing**: "If a gap in the message sequence is not filled within this duration, the buffer delivers what it has and marks the gap." (a) What sequence -- MLS generation? Sender generation number? Inner envelope sequence number? (b) How is the gap "marked" -- an event to the application layer? A placeholder in the delivered stream? (c) If the missing message arrives after the gap timeout, is it delivered late or discarded?
- **Why it matters**: The gap handling behavior determines whether late messages are eventually delivered or permanently lost.
- **Severity**: MEDIUM

### [23.10] KeyPackage Pre-Publication Count Not Specified
- **Category**: Missing constants/defaults
- **Location**: Section 23.10, lines 185-186
- **What's missing**: "The SDK pre-publishes `KeyPackage`s to relays" but no count is specified. How many KeyPackages should be pre-published? One per relay? Ten per relay? And what is the replenishment strategy -- publish more when the count drops below a threshold?
- **Why it matters**: Too few KeyPackages means offline member addition fails (the KeyPackage is consumed by the Welcome). Too many wastes relay storage and creates a larger key management surface.
- **Severity**: MEDIUM

### [23.11] Missing Constants for Queue Limits and Reconnection Timeout
- **Category**: Missing constants/defaults
- **Location**: Section 23.11
- **What's missing**: The constants table in 23.11 lists 8 constants but omits: (a) `MAX_QUEUE_PER_CONTEXT` (1,000 -- specified in prose but not in the constants table). (b) `MAX_QUEUE_TOTAL` (10,000 -- same). (c) `RECONNECTION_OVERALL_TIMEOUT` (120 seconds -- same). (d) `RELAY_CATCHUP_OVERLAP` (5 seconds -- specified in Phase 1 prose).
- **Why it matters**: The constants table should be the definitive reference. Omissions force implementors to search the prose.
- **Severity**: LOW

---

## Section 24: Provenance System

### [24.2.1] DataProvenance Wire Format Not Specified
- **Category**: Missing wire format details
- **Location**: Section 24.2.1
- **What's missing**: `DataProvenance` is defined with field names and types in pseudocode but no MessagePack field ordering, no serialization format, and no version envelope. Is it serialized as a named map or positional array? Is it wrapped in `StoredValue`?
- **Why it matters**: Provenance records cross context boundaries. If the serialization is ambiguous, provenance attached in one context cannot be deserialized in another (cross-implementation scenario).
- **Severity**: MEDIUM

### [24.2.1] chain_path Unbounded
- **Category**: Missing constants/defaults
- **Location**: Section 24.2.1, line 33
- **What's missing**: `chain_path: [ContextId]?` grows with each hop. The chain depth maximum is 3, so `chain_path` is at most 3 entries. But `chain_depth` saturates at `u8::MAX` (255) -- if the max is raised per-context, `chain_path` could grow to 255 entries. No explicit bound on `chain_path` length is specified.
- **Why it matters**: The chain depth default max is 3, but it's "configurable per context" (section 24.4). A context with `max_chain_depth = 200` would allow a 200-entry `chain_path`. This is mostly a storage size concern.
- **Severity**: LOW

### [24.2.3] DiscoveryMethod::OutOfBand Semantics Overlap with NoProvenance
- **Category**: Ambiguous state transitions
- **Location**: Section 24.2.3 and 24.2.4
- **What's missing**: `DiscoveryMethod::OutOfBand` (formerly `::None`, renamed in #772) means "no protocol-level discovery path" -- data was introduced outside SCP discovery. But `NoProvenance` in the quality evaluation also covers "Data introduced without protocol-level origin tracking." If data has `discovery_method: OutOfBand` but has a valid `source_context`, `counterparties`, etc., what quality tier does it get? The evaluation table (24.5.1) does not consider `discovery_method` as an input.
- **Why it matters**: `DiscoveryMethod` is recorded but never used in quality evaluation, making its purpose unclear.
- **Severity**: LOW

### [24.3.1] "Current Membership Roster" Privacy Concern
- **Category**: Security-relevant omissions
- **Location**: Section 24.3.1, line 87
- **What's missing**: `counterparties` is "the source context's current membership roster DIDs at the time of data flow." This means crossing a context boundary leaks the entire membership roster of the source context to the target context. For encrypted contexts, membership is supposed to be private (visible only to members, section 9.10).
- **Why it matters**: Provenance attachment creates a side-channel for membership enumeration. An adversary could create a context, invite a target, and trigger cross-context data flow to learn who else is in the target's other contexts.
- **Severity**: HIGH

### [24.3.2] First Crossing chain_depth = 0 vs chain_depth = 1 Discrepancy
- **Category**: Cross-reference inconsistencies
- **Location**: Section 24.3.2, lines 95-99
- **What's missing**: "When data crosses its first context boundary, `chain_depth` is 0." But section 24.4 says "At the maximum depth, data cannot trigger further cross-context tool calls" with default maximum 3. If the first crossing is depth 0, then 4 crossings are possible (0, 1, 2, 3) before hitting the max of 3. Section 9.2.1 says "maximum chain depth (suggested default: 3 hops)" -- does "3 hops" mean 3 crossings (depth 0-2) or depth value 3 (4 crossings)?
- **Why it matters**: Off-by-one in chain depth enforcement means either one too many or one too few cross-context hops are allowed.
- **Severity**: MEDIUM

### [24.3.3] Dual Recording in Ephemeral Contexts
- **Category**: Missing edge cases
- **Location**: Section 24.3.3
- **What's missing**: "Provenance is recorded in both the source and target contexts' event logs." But if the source context is ephemeral (`memory_scope: Ephemeral`), its event log will be destroyed when the context closes. The dual recording claim is only true while both contexts are alive.
- **Why it matters**: The audit trail guarantee is weaker than stated for ephemeral source contexts.
- **Severity**: LOW

### [24.4] chain_depth Check Timing Not Specified
- **Category**: Missing edge cases
- **Location**: Section 24.4
- **What's missing**: "Called before any cross-context tool invocation to enforce the bound." But is the check against the incoming data's current depth (before increment) or the would-be depth (after increment)? If max is 3 and incoming data has depth 2, can it cross one more boundary (becoming 3) or is it rejected because 2+1 > 2 (the last allowed hop)?
- **Why it matters**: Determines the actual maximum number of hops. Combined with the depth-0-first-crossing question above, this compounds the ambiguity.
- **Severity**: MEDIUM

### [24.5.2] Source Type Update Trigger Not Specified
- **Category**: Underspecified algorithms
- **Location**: Section 24.5.2, lines 146-155
- **What's missing**: "When a source context's state changes... the `update_source_type` operation updates the provenance record's source type." But: (a) Who triggers this update? The source context? The target context? (b) How does the target context learn that the source context closed? It has no subscription to the source context's lifecycle. (c) Is this a pull-based check (target checks source status on access) or push-based (source notifies all targets on close)?
- **Why it matters**: Without a trigger mechanism, provenance quality evaluation returns stale `PersistentVerifiable` for contexts that have already closed. The "quality can degrade over time" claim is aspirational without a mechanism.
- **Severity**: HIGH

### [24.5.2] "Active" Context State Not Defined
- **Category**: Missing wire format details
- **Location**: Section 24.5.2, lines 149-154
- **What's missing**: The source type update table uses "Active" as a context state, but the context lifecycle in section 5 uses states like `open`, `suspended`, `closed`. What maps to "Active"? Is `suspended` still "Active" for provenance purposes?
- **Why it matters**: The provenance system uses its own state terminology without mapping to the context lifecycle states defined elsewhere.
- **Severity**: LOW

---

## Cross-Cutting Findings

### [17/23] Queue Storage Not Reflected in ProtocolStore
- **Category**: Cross-reference inconsistencies
- **Location**: Sections 17.3-17.4 and 23.2
- **What's missing**: Section 23.2 specifies that queued messages are stored under `queue/{context_id}/{seq:020d}` but this key prefix does not appear in the key convention (section 17.3) and no queue-related methods appear in `ProtocolStore` (section 17.4). The queue is a protocol-level concern that should be in `ProtocolStore`, not raw `Storage` access.
- **Why it matters**: Breaks the architectural invariant that "all structured protocol operations are mapped to flat KV operations by `ProtocolStore`."
- **Severity**: MEDIUM

### [17/19] Economic Storage Methods Accept Opaque Bytes
- **Category**: Missing wire format details
- **Location**: Sections 17.4 and 19.3
- **What's missing**: `store_economic_policy`, `store_payment_receipt`, `store_spending_ucan` all accept `&[u8]`. But the types in section 19 (`EconomicPolicy`, `PaymentReceipt`, `SpendingCapability`) are Rust structs. The serialization (MessagePack via `StoredValue`?) is assumed but not stated for economic types.
- **Why it matters**: Consistency with the `StoredValue` envelope pattern is unstated for economic types.
- **Severity**: LOW

### [18/19] Relay Economic Config in .well-known/scp vs Runtime Discovery
- **Category**: Missing edge cases
- **Location**: Sections 18.3.3 and 19.8
- **What's missing**: Relay economic config is available in `.well-known/scp` (HTTP-accessible before WebSocket connection). But `.well-known/scp` is optional and SHOULD-level. For relays without a domain (`.no_domain()` mode), there is no HTTP endpoint. How does a client discover a no-domain relay's economic policy? Over the WebSocket connection? Via the DID document?
- **Why it matters**: No-domain relays that charge for transport have no discovery mechanism for their economic policy.
- **Severity**: MEDIUM

### [23/24] Provenance During Offline Data Flow
- **Category**: Missing edge cases
- **Location**: Sections 23 and 24
- **What's missing**: When a member is offline and queues a message that references cross-context data, provenance attachment happens at queue time (when the source context state is known) or at drain time (when the source context may have changed)? The provenance `age` field ("how long ago the source interaction occurred") would differ significantly.
- **Why it matters**: Provenance accuracy degrades for offline-queued cross-context data.
- **Severity**: LOW

---

## Summary Statistics

| Section | CRITICAL | HIGH | MEDIUM | LOW | Total |
|---------|----------|------|--------|-----|-------|
| 17 - Persistence | 0 | 2 | 5 | 5 | 12 |
| 18 - Addressability | 0 | 0 | 7 | 5 | 12 |
| 19 - Economic | 1 | 5 | 6 | 2 | 14 |
| 22 - Addressing | 0 | 1 | 4 | 6 | 11 |
| 23 - Sync | 0 | 4 | 6 | 4 | 14 |
| 24 - Provenance | 0 | 2 | 3 | 5 | 10 |
| **Total** | **1** | **14** | **31** | **27** | **73** |

The single CRITICAL finding (relay payment wire protocol entirely missing in section 19) blocks implementation of paid relays. The HIGH findings concentrate in three areas: economic governance (payment semantics), sync (security of reconnection primitives), and provenance (membership leakage via counterparties).
