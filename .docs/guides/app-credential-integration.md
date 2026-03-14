# Credential Integration Guide: SCP Apps with External Services

**Audience:** Agent building an SCP-native app that connects to non-SCP services (Linear, GitHub, etc.)
**Status:** Guidance based on protocol spec + implementation audit (2026-03-13)

---

## Architecture Overview

Your app has three credential domains. Keep them strictly separated.

```
┌─────────────────────────────────────────────────────────┐
│  1. SCP Identity (DID)                                  │
│     Keys: #0 (offline), #active (biometric), #agent     │
│     Storage: Platform custody (Keychain/Keystore)       │
│     Purpose: SCP protocol operations, user auth to app  │
│     YOU DON'T MANAGE THESE — the SDK does               │
├─────────────────────────────────────────────────────────┤
│  2. App Session                                         │
│     Auth: DID-signed challenge-response                 │
│     No passwords, no session tokens stored at rest      │
│     The MLS context membership IS the session           │
├─────────────────────────────────────────────────────────┤
│  3. Connected Service Credentials (Linear, GitHub)      │
│     Tokens: OAuth access + refresh tokens, API keys     │
│     Storage: Encrypted, per-connection, isolated        │
│     Keys: Standalone per-connection secrets (NOT from   │
│           identity material)                            │
│     THIS IS WHAT YOU BUILD                              │
└─────────────────────────────────────────────────────────┘
```

**Cardinal rule:** Domain 3 credentials are NEVER derived from, stored alongside, or coupled to Domain 1 keys. A compromise of service credentials must not compromise the user's SCP identity. A compromise of the SCP identity must not expose service credentials.

---

## Part 1: User Authentication to Your App

Users don't "sign in" to your app — they join a context. Your app IS a context (spec §8.1).

For any HTTP API endpoints your app serves (REST, webhooks, callbacks), authenticate requests using DID-signed challenges:

### Pattern (from §22.3 / §6.2.2B discovery context readers)

```
1. Client requests a nonce from your server
   GET /auth/challenge → { nonce: "<32 random bytes, hex>", expires: <unix_ts> }

2. Client signs the challenge with #active or #agent
   signed_content = SHA-256("SCP-DID-AUTH-V1:" || nonce || your_app_audience_uri || timestamp)
   signature = Ed25519.sign(signing_key, signed_content)

3. Client sends back:
   POST /auth/verify → {
     did: "did:dht:...",
     key_id: "#active",  // or "#agent"
     signature: "<hex>",
     timestamp: <unix_ts>
   }

4. Server verifies:
   a. Resolve DID document via DHT
   b. Extract public key for key_id
   c. Confirm key_id is in the "authentication" relationship
   d. Verify Ed25519 signature over reconstructed signed_content
   e. Check nonce freshness + audience match
```

### Implementation note

This pattern is NOT yet a formalized SDK function. The primitives exist:
- DID resolution: `scp-identity` crate, exposed through all SDKs
- Ed25519 signing: via `KeyCustody` trait, exposed through all SDKs
- Signature verification: `scp-identity` crate

The full protocol is specified in §3.11 (DID Authentication for External Services). SDK functions `scpid_sign()` and `scpid_verify()` are defined in §3.11.8.

---

## Part 2: Connecting to Linear and GitHub

Both are OAuth 2.0 services. The spec fully covers this in §12.11 (bridge credential lifecycle) and §12.11.3 (OAuth 2.0 reference binding).

### What exists in Rust core (NOT yet in SDKs)

The following are **fully implemented and tested** in `crates/scp-core/src/bridge/`:

| Component | File | Status |
|-----------|------|--------|
| `BridgeCredential` struct | `credentials.rs` | Complete (encrypted storage, scoped per bridge) |
| `BridgeCredentialStore` trait | `credentials.rs` | Complete (provision, retrieve, rotate, revoke, list) |
| `InMemoryCredentialStore` | `credentials.rs` | Complete (test impl with suspension handling) |
| HKDF key derivation | `credentials.rs` | Complete (`derive_credential_key()`) |
| `OAuthCredentialManager` | `oauth.rs` | Complete (PKCE, refresh, revocation, backoff) |
| `OAuthHttpClient` trait | `oauth.rs` | Complete (abstract HTTP, no hard dependency) |
| `PkceChallenge` generation | `oauth.rs` | Complete (S256, 32-byte verifier) |

**These are NOT exposed through any FFI bridge or language SDK.** The Python, TypeScript, Swift, and Kotlin SDKs only expose `bridge_register()`, `bridge_evaluate_trust()`, and `bridge_create_shadow()`.

**Tracking:** [#616](https://github.com/limn-works/scp/issues/616) — "Bridge subsystem (shadow claiming, OAuth, envelope sealing, registration) largely not exposed through FFI" (P1/P2, open). Related: [#492](https://github.com/limn-works/scp/issues/492) (`BridgeLookup` trait no production impl), [#537](https://github.com/limn-works/scp/issues/537) (bridge error code inconsistency across bridges). When #616 ships, the app-layer implementations below can be swapped for SDK calls — follow the same HKDF parameters and storage key patterns to make migration a backend swap, not a redesign.

### What you need to build at the app layer

Since the Rust credential APIs aren't available through SDK bindings yet, implement the credential lifecycle in your app's language using the spec as your guide:

#### 2a. Credential Storage

```
Storage layout (per connection):
  connections/{connection_id}/credential/oauth_access_token
  connections/{connection_id}/credential/oauth_refresh_token

Encryption:
  - Generate a random 32-byte connection_credential_key per connection
  - Store the connection_credential_key in platform keychain
    (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly on iOS,
     or equivalent — no biometric gate, available to background processes)
  - Derive per-credential encryption keys via HKDF-SHA256:
      salt = SHA-256("SCP-BRIDGE-CREDENTIAL-V1")
      info = "scp-bridge-credential:" || connection_id
      key  = HKDF-Expand(HKDF-Extract(salt, connection_credential_key), info, 32)
  - Encrypt tokens with AES-256-GCM
  - Store as: nonce (12 bytes) || ciphertext || tag (16 bytes)
```

**Do NOT:**
- Derive encryption keys from the user's SCP identity keys (`#0`, `#active`, `#agent`)
- Share credential keys across connections (even for the same service)
- Store tokens in plaintext, in attestations, in UCANs, or in the DID document

#### 2b. OAuth 2.0 Flow (Linear + GitHub)

Both Linear and GitHub support Authorization Code + PKCE.

```
1. Generate PKCE challenge:
   verifier  = base64url(random(32 bytes))
   challenge = base64url(SHA-256(verifier))

2. Redirect to authorization endpoint:
   Linear:  https://linear.app/oauth/authorize
   GitHub:  https://github.com/login/oauth/authorize
   Params:  response_type=code, client_id, redirect_uri,
            scope=<minimal>, code_challenge, code_challenge_method=S256

3. Exchange code for tokens:
   POST to token endpoint with code + code_verifier
   Linear:  https://api.linear.app/oauth/token
   GitHub:  https://github.com/login/oauth/access_token

4. Encrypt and store both access_token and refresh_token (§2a above)
```

**Scope minimization (§12.11.3):**
- Linear: request only the scopes your bridge mode needs (read-only if you're just pulling issues)
- GitHub: same — `repo:read` if you're just reading, not `repo` (full access)

#### 2c. Token Refresh

```
- Refresh at 80% of token lifetime (e.g., if token expires in 1 hour, refresh at 48 min)
- On failure: exponential backoff (1s initial, 60s max, 5 retries)
- On permanent failure (refresh token revoked by platform):
    Mark connection as degraded, notify user
    Do NOT silently fail or retry forever
```

#### 2d. Revocation

```
When user disconnects a service:
  1. Call the platform's token revocation endpoint (if available):
     Linear:  POST https://api.linear.app/oauth/revoke
     GitHub:  DELETE https://api.github.com/applications/{client_id}/token
  2. Overwrite local token material with zeros
  3. Delete the credential record
  4. Overwrite and delete the connection_credential_key from keychain
```

---

## Part 3: Agent / Background Access

An autonomous agent running on behalf of the user needs access to connected service credentials without biometric re-prompting.

**This is supported by the access pattern:**

1. The `connection_credential_key` is stored in platform keychain with `AfterFirstUnlockThisDeviceOnly` access class — same as the `#agent` signing key (ADR-025). Available to background processes after first device unlock.

2. At session dispatch (foreground, user present), the agent reads and decrypts the needed credentials. Holding decrypted tokens in memory for the duration of the agent run is fine.

3. The agent uses the tokens to call Linear/GitHub APIs directly. No SCP protocol involvement — these are standard HTTP API calls.

**If the agent run outlives the token lifetime:**
- The agent must handle token refresh autonomously (using the stored refresh token)
- This is a normal OAuth flow, no biometric needed
- The refresh token itself is encrypted with the `connection_credential_key` which is accessible without biometrics

---

## Part 4: What NOT to Do

| Anti-pattern | Why it's wrong | What to do instead |
|---|---|---|
| Store API keys in identity attestations (§3.5) | Attestations are public/verifiable claims. API keys are secrets. Publishing a secret in a verifiable claim defeats its purpose. | Use encrypted credential storage (§2a) |
| Encode service tokens in UCANs (§7.2) | UCANs are SCP-context-scoped capability tokens. They don't model external service access. | Use encrypted credential storage (§2a) |
| Derive credential encryption keys from `#active` or `#0` | Couples credential lifecycle to key rotation. If `#active` rotates, all credentials need re-encryption. Also violates key isolation (§12.11.2). | Use standalone random keys per connection |
| Share credentials across connections | A GitHub token for Project A must not be accessible to the Linear connection for Project B, even under the same user. Per §12.11.2: cross-bridge credential sharing is prohibited. | Scope all storage by connection_id |
| Store tokens in the SCP context (as messages or metadata) | Context data is visible to all context members via MLS. Service credentials are user-private. | Store in local encrypted credential store, never in context |
| Use `ProtocolRepository` for credential storage | `ProtocolRepository` is context-scoped protocol state. Service credentials are operator-scoped private state. Different trust domain. | Use a separate credential store (the Rust core does this — `BridgeCredentialStore` is a separate trait) |

---

## Part 5: Future SDK Support

When FFI bindings for `BridgeCredentialStore` and `OAuthCredentialManager` ship, migrating from your app-layer implementation to the SDK will be straightforward:

1. Your encrypted credential format should match the spec (AES-256-GCM, HKDF-SHA256, same salt/info strings)
2. Your storage layout should use the `bridge/{id}/credential/{type}` key pattern
3. Your OAuth flow should use PKCE with S256

If you follow the spec now, the SDK migration is a swap of the storage backend, not a redesign.

---

## Reference

| Topic | Spec Section | Code (Rust core) |
|-------|-------------|------------------|
| Apps as contexts | §8.1–8.4 | — |
| Bridge credential lifecycle | §12.11 | `crates/scp-core/src/bridge/credentials.rs` |
| OAuth 2.0 reference binding | §12.11.3 | `crates/scp-core/src/bridge/oauth.rs` |
| Credential key derivation | §12.11.1 Phase 2 | `derive_credential_key()` in `credentials.rs` |
| Self-hosted credential isolation | §12.11.4 | — |
| SCPID (DID auth for external services) | §3.11 | `scpid_sign()`, `scpid_verify()` (§3.11.8) |
| DID-signed request auth (internal) | §22.3, §6.2.2B | `crates/scp-core/src/discovery/context.rs` (caller responsibility) |
| Agent key access pattern | ADR-025, ADR-039 | `crates/scp-platform/src/traits.rs` |
| Capability declarations | §8.4.1–8.4.2 | `crates/scp-core/src/app/` |
| Identity attestations (don't use for credentials) | §3.5 | `crates/scp-core/src/identity/attestation.rs` |
