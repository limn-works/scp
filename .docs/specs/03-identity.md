# 3. Identity

## 3.1 Root of Identity

Every identity is rooted in a cryptographic keypair. This is the canonical identifier at the protocol level — not a username, not an email, not an account on someone's server.

Build on **DID (Decentralized Identifiers, W3C standard)**. DIDs provide the right abstraction: a cryptographic root that's method-agnostic, meaning the underlying key custody can vary without changing the identity itself.

## 3.2 Key Custody

Users never see or manage keys directly. Custody is delegated to whatever the user already trusts:

- Device secure enclave (iOS Secure Enclave, Android Keystore)
- Platform accounts (Apple, Google) via passkey infrastructure
- Hardware security keys
- Self-managed keys (power users who want direct control)

The identity layer abstracts custody. The user authenticates however they choose; under the hood it resolves to a protocol-level DID. Migration between custody methods is possible without changing identity, using the key custody migration protocol (§3.2.1).

### 3.2.1 Key Custody Migration Protocol

Custody migration moves the operational signing capability from one custody provider to another (e.g., Secure Enclave to hardware security key, or passkey to self-managed key) without changing the identifier. The root set is unchanged by an operational-key custody migration; case 2 below is the one case in which the root itself changes.

**Two cases:**

1. **Active Signing Key migration (common).** The Active Signing Key (`#active`) is rotatable by design. Migration generates a new `#active` key in the target custody provider, and the standing root signs a `KeyState` event (`09-security-model.md` §9.7.4.2 R3) that lists the new key `current` and the old one `Superseded` (`09-security-model.md` §9.7.1). The identifier does not change because it derives from the inception event (`09-security-model.md` §9.7.4.2 R2), not from any key. This is the standard rotation applied to a custody change rather than a compromise; a compromise lists the replaced key `Compromised{from: N}` instead (§9.12). A peer observes this event and sets no standing against the identifier: §9.11 makes a routine operational rotation transparent to peers and reserves `PendingReverify` for an adopted `RootRecovery` and a `Contested` verdict.

2. **Root key change (rare).** If the root must change, the root changes by a `RootRecovery` event (`09-security-model.md` §9.7.4.2 R3): a threshold-satisficing subset of the next set authorizes the event, a fresh root set generated under the recovery's device boundary is installed, and the identifier does not change — no new DID, no `alsoKnownAs` forwarding record, and no `DidRotationEvent`. Relying parties re-verify key continuity (§9.11) on the recovery event. A planned root move with no compromise — a custody substrate being decommissioned with its key unexportable — is the same event: a `RootRecovery{CoSigns}` whose snapshot lists every key either `current` or retired with no compromise position (`09-security-model.md` §9.7.4.2 R8 for the snapshot's content; R10 for the choice of event).

**Migration protocol (case 1 — Active Signing Key):**

```
1. INITIATE on target device:
   a. Generate new Ed25519 keypair in target custody provider.
   b. Create CustodyMigrationRequest:
      - new_active_pubkey: [u8; 32]
      - custody_type: the custody-type enumeration of
        `09-security-model.md` §9.7.4.2 definitions, which fixes the values
        and states which of them a root member may carry
      - requested_at: u64 (Unix timestamp)

2. AUTHORIZE on a device holding a threshold of the standing root set:
   a. Verify the migration request was initiated by the identity owner
      (device-local authentication — biometric, PIN, or platform credential).
   b. Compose a KeyState event (`09-security-model.md` §9.7.4.2 R3) carrying
      the complete key state (R8):
      - new_active_pubkey listed #active and `current`, with its custody type.
      - The replaced #active listed `Superseded`.
      - Every other key the chain installed re-listed with its condition.
      - The standing root set, the witness set, and the service-key
        designation unchanged; the key state carries no relay list
        (`09-security-model.md` §9.7.4.2 definitions).
   c. Sign the KeyState with a root signature by the standing root set —
      one indexed signature per named index, at least t of them (R3).

3. PUBLISH:
   a. Publish the extended key-event log to the identity's own relays and
      to the fallback set (§3.10.5).
   a-bis. Re-sign the identity's service record under the new #active — the
      rotation reset every reader's service-record high-water mark for this
      identity, which is why the record must be republished (§3.10.13) — and
      publish it to the same relays (§3.10.13). The designation resolves to
      #active, so every copy signed by the replaced key stops verifying the
      moment a reader adopts the KeyState of step 2, and a reader that can
      verify no copy reports the identity as unroutable. This step runs
      before step 5 destroys the old key, and it is the same obligation
      `09-security-model.md` §9.12 places on the Active-Signing-Key
      compromise path.
   b. Issue MLS Update proposals in all active contexts with credentials
      referencing the new #active key (§9.7.3).
   c. Revoke all UCAN tokens signed by the old #active key.
      Reissue under the new #active key.

4. TRANSFER attestation chain:
   a. Identity attestations (§3.5) that were signed by the old #active key
      MUST be re-signed by the new #active key and republished.
   b. The SDK enumerates all published attestations and re-signs them
      as part of the migration transaction.

5. DESTROY old key material:
   a. After confirmation that the KeyState has propagated (verified by
      resolving the log from two relays under distinct declared
      operators, one of them in the fallback set, 09 §9.7.4.2 R11), the old
      #active private key is destroyed in the source custody provider.
   b. Destruction is best-effort for HSM-backed keys (the HSM may not support
      explicit deletion, but the key becomes inaccessible once the device
      is decommissioned).
```

**Failure semantics:**

- **Step 2 fails (authorization denied):** No state change. The old custody provider remains active. The new keypair generated in step 1 is discarded.
- **Step 3a fails (publication fails on some relays):** The SDK retries publication. The RepublishManager (§3.10.5) will propagate on its next cycle. Partial publication is safe — a peer that resolves the shorter chain derives the old key state and keeps verifying under the old `#active`, and a peer that resolves the extended chain uses the new key. The two chains do not diverge: one is a prefix of the other, so sequence settles them (`09-security-model.md` §9.7.4.2 R12) and no fork-precedence question arises.
- **Step 3b/3c fails (MLS Update or UCAN reissuance fails in some contexts):** The SDK queues failed operations for retry. A context whose log records no retirement Commit for the old `#active` holds no boundary for that key, and `09-security-model.md` §9.7.1 decides what its members do — that spec states the rule and this one cites it. The migration converges as retries succeed.
- **Step 5 fails (old key destruction fails):** The migration is still complete — the latest state-carrying event lists the new key `current` and the old one retired. The old key is orphaned, and each context bounds it on that context's own evidence: UCAN tokens signed by it are revoked, its attestations no longer verify (attestation class, `09-security-model.md` §9.7.1), and its content signatures verify under the rule `09-security-model.md` §9.7.1 states for a retired key, which this spec cites rather than restating. **A context that never watched this key sign bounds nothing and accepts nothing under it**: §9.7.1 accepts a retired key's content on the absence of a retirement Commit only where that context's Commit history also records a Commit from this identity whose leaf attestation verified under the key, and reports `Invalid{no_boundary}` otherwise.

**Multi-device coordination:** If the identity owner has multiple devices (e.g., phone + laptop + tablet), each device holds its own key material for signing. Custody migration affects only the `#active` key the key state lists — the single authoritative signing key. Other devices learn of the migration by resolving the extended key-event log (§3.10.4). After migration, only the device with the new custody provider can sign as `#active`. Other devices that need signing capability must independently generate keys and request delegation via scoped UCANs from the new `#active` key holder.

**Invariant:** At no point during migration are there zero valid signing keys for the identity, and at no point is the identity's service record left signed by a key no reader will accept — step 3a-bis republishes it under the new `#active` before step 5 destroys the old one. The old key remains `current` for every peer that has not yet resolved the `KeyState`, and the new key is `current` for every peer that has. A peer that resolved the `KeyState` before the step-3b Update reaches its context re-resolves before it rejects the identity's own Update, and waits out `LEAF_REPLACEMENT_GRACE` before it proposes Remove for the not-yet-replaced leaf (`09-security-model.md` §9.7.1 and §9.12 step 1a); without those two rules the overlap window would evict the migrating member from its own context.

## 3.3 Recovery

No seed phrases. Recovery uses social and device mechanisms:

- **Trusted device recovery:** Another device you control vouches for a new one. The trusted device enrolls the new device into the identity's device registry and distributes the Private State Key (PSK) via HPKE (§3.7.2). Recovery IS device enrollment — the same cryptographic protocol applies.
- **Social recovery:** Trusted contacts confirm your identity. After social recovery re-establishes key custody, the recovering device is enrolled as a new device (§3.7.2) and receives the PSK from any existing enrolled device. If no enrolled devices remain (all devices lost), PSK recovery requires re-keying: a new PSK is generated, existing private state history encrypted under the old PSK is permanently inaccessible (same forward-only property as §9.17.5), and the identity starts a fresh private state log.
- **Platform-backed recovery:** If custody is delegated to Apple/Google, their recovery mechanisms apply. The PSK is stored in the platform's secure key store (Keychain, Keystore — §17.8) and may be recoverable through platform backup/restore mechanisms (e.g., iCloud Keychain sync, Google Cloud Key Vault). This provides a recovery path for the PSK that does not depend on another SCP device being available.

For new users with a single device and no SCP contacts, platform-backed recovery is the practical safety net. Social and device recovery grow in value over time as users add devices and build connections. Apps should prompt for trusted recovery contacts during onboarding — the same pattern Google and Apple use today.

## 3.4 Linking Existing Identities

Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop, not as source of truth.


## 3.5 Identity Attestations

A user can publish cryptographic attestations binding their external platform identities to their DID. These attestations are the mechanism that makes bridging trustworthy and social graph import possible.

An attestation says: "The human behind DID `did:key:abc...` is the same human behind `@alice` on X." The attestation is verifiable — the user proves ownership of the external identity (e.g., by signing a challenge, posting a proof, or using OAuth) and the result is a signed statement linking the two.

Properties of identity attestations:

- **Non-fungible.** The attestation binds a specific external identity to a specific DID. It cannot be transferred, forked, or shared. This is the foundation for cross-platform identity attribution.
- **User-initiated.** Only the human creates attestations for their own identities. No third party can assert a link on someone's behalf.
- **Independently verifiable.** Any participant can verify the attestation without relying on a central authority. Verification methods vary by platform (OAuth proof, signed message, DNS record, etc.).
- **Revocable.** Users can revoke attestations at any time, severing the link.
- **Discoverable.** Other SCP participants can look up whether a given external identity maps to a known DID. Attestations are discoverable through contexts with discovery outlets (§6.2.2B) and service-record entries (§3.5.3). Reverse-lookup (external handle → DID) is provided by the `attestation_lookup` outlet in contexts with discovery outlets (§22.5).

Identity attestations enable three critical flows:

1. **Social graph import.** A user exports their follower list from X. Their local agent resolves each handle against known attestations. Contacts who have also joined SCP are automatically discoverable.
2. **Shadow identity claiming.** When a bridge connector creates a shadow identity for an external participant (see §12), a user can claim it by presenting a matching attestation. The shadow identity merges with their real DID (see §3.5.5 for the claiming protocol).
3. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.

### 3.5.0 Attestation Classes

Identity link attestations are sub-classified into two classes based on when and how the external identity ownership was verified. The class is a property of the verification method, not of the attestation envelope — the wire format (§3.5.2) is the same for both classes. The class determines the trust model: who must verify, when, and what the attestation proves on its own. See ADR-044 for the design rationale and rejected alternatives.

**Class 1: Cryptographic.** The provider's confirmation of identity ownership was cryptographically verified at attestation creation time. Verification methods: `Oauth`, `ChallengeResponse`.

- The SDK performs the verification flow (OAuth code exchange, challenge-response round trip) locally at creation time.
- On success, the SDK extracts the minimal identifying claim (`provider`, `subject_id`, `verified_at`) and signs it with the DID's signing key. This SDK-signed proof replaces the raw provider token — no JWT, no OIDC ID token, no PII is stored.
- The attestation proof is: `{ "provider": "<platform>", "subject_id": "<platform_user_id>", "verified_at": <unix_s> }` signed by the issuer's `#active` key. The signature is the one on the `IdentityLinkAttestation` envelope itself — the proof field carries the claim content, the envelope signature covers it.
- Self-attestation model: issuer == subject. The DID owner asserts "I verified this at creation time." Consumers trust the assertion because: (a) the DID key signed it, (b) the claim is minimal (no forgery incentive beyond the link itself), and (c) falsifying the link provides no benefit — shadow claiming (§3.5.5) and social graph import (§3.6) only work if the external account is genuinely controlled.
- **No raw token storage.** The SDK MUST discard the OAuth access token, refresh token, and ID token after extracting the `subject_id`. Only the minimal signed claim persists. This eliminates PII leakage — Google OIDC tokens always include `email`, Apple tokens include `email` when requested. None of that data enters the attestation.

**Class 2: Reference.** The proof is a live external resource that consumers must verify themselves. Verification methods: `SignedPost`, `DnsRecord`.

- The user places their DID string in an externally-visible location (profile bio, DNS TXT record, public post).
- The attestation's `proof` field points to the resource URL or record location. No cryptographic proof of ownership exists at creation time — the proof is the continued presence of the DID in the external resource.
- **Zero trust until verified.** A Reference attestation carries no trust weight on its own. Consumers MUST fetch the proof URL or query the DNS record and confirm the DID is present before granting any trust weight. An unverified Reference attestation is equivalent to no attestation.
- Verification is consumer-side, cached with a 1-hour TTL (§3.5.4). Consumers that cannot verify (offline, rate-limited, proof URL inaccessible) MUST treat the attestation as unverified.

The class distinction is critical for trust evaluation (§7.5). Class 1 attestations provide immediate trust signal upon DID signature verification. Class 2 attestations provide no trust signal until the consumer independently verifies the proof — they are pointers, not proofs.

### 3.5.1 Provider Registry

The following 16 platforms are supported for identity link attestations. New providers are added by spec amendment only — the set is closed to prevent proliferation of unverifiable attestation targets.

| Platform | `platform` value | Class | Verification method | Proof location | Renewal interval |
|----------|-----------------|-------|--------------------|----|-----------------|
| GitHub | `github.com` | 2 (Reference) | `SignedPost` | Profile bio containing DID | 90 days |
| X / Twitter | `x.com` | 2 (Reference) | `SignedPost` | Profile description containing DID | 90 days |
| Google | `google.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Apple | `apple.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Microsoft | `microsoft.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| LinkedIn | `linkedin.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Discord | `discord.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Reddit | `reddit.com` | 2 (Reference) | `SignedPost` | Profile bio containing DID | 90 days |
| Bluesky | `bluesky.com` | 2 (Reference) | `SignedPost` | Profile description containing DID | 90 days |
| Mastodon | `mastodon:<instance>` | 2 (Reference) | `SignedPost` | Profile bio containing DID | 90 days |
| Telegram | `telegram.com` | 1 (Cryptographic) | `ChallengeResponse` | Bot-verified round trip | 60 days |
| npm | `npm` | 2 (Reference) | `SignedPost` | Profile page containing DID | 90 days |
| PyPI | `pypi` | 2 (Reference) | `SignedPost` | Profile page containing DID | 90 days |
| Steam | `steam` | 1 (Cryptographic) | `ChallengeResponse` | Bot-verified round trip | 60 days |
| .well-known | `well-known` | 2 (Reference) | `DnsRecord` | `/.well-known/scp` endpoint containing DID | 180 days |
| DNS | `dns` | 2 (Reference) | `DnsRecord` | TXT record at `_scp-verify.<domain>` | 180 days |

**Platform value conventions:**

- OIDC providers use their token issuer domain: `google.com`, `apple.com`, `microsoft.com`, `linkedin.com`, `discord.com`.
- Social platforms use their primary domain: `github.com`, `x.com`, `reddit.com`, `bluesky.com`, `telegram.com`.
- Mastodon instances use the `mastodon:<instance>` format (e.g., `mastodon:mastodon.social`) because the Mastodon API endpoint varies by instance. The `platform_id` field SHOULD contain the Mastodon account URI (`@user@instance`).
- Package registries use the bare registry name: `npm`, `pypi`. The `platform_handle` field contains the package author username.
- `.well-known` uses the bare string `well-known`. The `platform_handle` field contains the domain name. The proof is an HTTP GET to `https://<domain>/.well-known/scp` which must return the DID string.
- DNS uses the bare string `dns`. The `platform_handle` field contains the domain name.

**`ChallengeResponse` verification method:** `ChallengeResponse` is listed as a Class 1 (Cryptographic) verification method in §3.5.0. Some platforms in the registry above use it (Telegram, Steam) for bot-verified identity linking. Beyond those platform-specific entries, `ChallengeResponse` is also platform-agnostic — it is a generic mechanism where any verifier (e.g., a context governance engine, a bridge connector, or another participant) challenges an agent to prove a capability or identity claim via a cryptographic round trip. Any context that wants to verify an agent's capabilities can use `ChallengeResponse` regardless of the platform. The `platform` field in the attestation claim is set to the verifier's choice (e.g., the context ID or verifier's domain), and the `evidence.verifier_did` field identifies the verifier that issued the challenge.

**`ChallengeResponse` creation flow:**
1. A verifier sends a random 32-byte challenge to the subject.
2. The subject signs the challenge with their Active Signing Key (`#active`).
3. The SDK constructs the proof: `{ "challenge": "<hex>", "response_signature": "<hex>" }`.
4. The full `IdentityLinkAttestation` envelope is signed by the subject's DID key.

**`ChallengeResponse` verification:** Verify `response_signature` is valid for `challenge` under the subject's DID signing key. Verify `verifier_did` is a known, trusted verifier.

**Class 1 (Cryptographic) creation flow:**

1. The SDK initiates an OAuth 2.0 authorization code flow with the OIDC provider. Minimal scope: `openid` only (no `email`, no `profile`). Apple Sign In uses the `sub` claim from the identity token.
2. On success, the SDK receives the ID token (JWT). It extracts `sub` (subject identifier) and discards the token.
3. The SDK constructs the proof content: `{ "provider": "<platform>", "subject_id": "<sub>", "verified_at": <unix_s> }`.
4. The SDK signs the full `IdentityLinkAttestation` envelope (which includes the proof content in `evidence.proof`) with the DID's signing key.
5. The SDK discards the access token, refresh token, and ID token. Only the signed attestation persists.

**Class 2 (Reference) creation flow:**

1. The user places their DID string in the platform-specific location (profile bio, DNS TXT record).
2. The SDK constructs the proof pointer: for `SignedPost`, `{ "post_url": "<url>", "nonce": "<random_hex>", "posted_at": <unix_s> }`; for `DnsRecord`, `{ "domain": "<domain>", "record_name": "_scp-verify" }`.
3. The SDK signs the full `IdentityLinkAttestation` envelope with the DID's signing key.
4. The attestation is published. It carries zero trust weight until a consumer fetches and verifies the proof.

### 3.5.2 Identity Attestation Wire Format

Identity attestations use the attestation envelope defined in §7.4.1, with identity-link-specific fields. The wire serialization is MessagePack (§17), consistent with all other SCP wire formats. The signature scope uses the §9.5.1 canonical hash construction — see "Signature scope" below.

```
 IdentityLinkAttestation {
  id:           String,          // Deterministic ID (see below), hex-encoded
  type:         "identity_link",
  issuer:       DID,             // The DID claiming the external identity
  subject:      DID,             // Same as issuer (self-attestation)
  issued_at:    u64,             // Unix timestamp (s)
  expires_at:   Option<u64>,     // Optional expiry (s). If absent, valid until revoked.
  claim: {
    platform:       String,      // Platform identifier per §3.5.1 provider registry
    platform_handle: String,     // Handle on the platform: "@alice", "alice123", etc.
    platform_id:    Option<String>, // Platform-specific immutable user ID (e.g., OIDC sub claim, Twitter user ID)
    link_type:      "self_attestation",
  },
  evidence: {
    method:         String,      // Verification method: "oauth", "signed_post", "dns_record", "challenge_response"
    proof:          String,           // Method-specific proof data (opaque — see below)
    verified_at:    u64,         // Unix timestamp (s) of last verification
    verifier_did:   Option<DID>, // DID of the verifier, if third-party verified (challenge_response only)
  },
  revocation_status: RevocationStatus, // Active or Revoked (§7.4.1). MUST be in signed scope.
  signature:    Ed25519Signature,  // Signs §9.5.1 canonical hash (see Signature scope below), using issuer's #active key
}
```

> **Proof opacity.** Verifiers MUST use the `proof` string as-is in the
> signature scope — do not parse and re-serialize. This ensures:
> (1) forward compatibility with new verification methods,
> (2) cross-implementation canonical hash determinism,
> (3) verifiers need not understand proof contents to verify signatures.

**Signature scope:** The signature covers the §9.5.1 canonical hash of `(id, attestation_type, issuer, subject, issued_at, expires_at, claim, evidence, revocation_status)` using domain separator `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`. String and DID fields use 4-byte BE length-prefixed encoding, `issued_at` uses 8-byte BE u64, `expires_at` uses the absent sentinel when not set, and sub-structures (`claim`, `evidence`, `revocation_status`) are individually serialized as MessagePack (sorted-key encoding) and included as variable-length byte fields. See §25.13 (Vector 26) for the exact construction.

**Attestation ID construction:** The `id` field is a deterministic, hex-encoded SHA-256 hash derived from the attestation's identifying fields using the canonical hash construction (§9.5.1). The domain separator `"SCP-ATTESTATION-ID-V1:"` prevents cross-protocol collision, and 4-byte big-endian length prefixes on variable-length fields prevent field boundary ambiguity (e.g., platform `"ab"` + handle `"cd"` vs platform `"a"` + handle `"bcd"`).

```
id = hex(SHA-256(
  "SCP-ATTESTATION-ID-V1:"                          (22 bytes, no length prefix)
  || BE32(len(issuer_did))  || issuer_did            (4 + N bytes)
  || BE32(len(platform))    || platform              (4 + N bytes)
  || BE32(len(platform_handle)) || platform_handle   (4 + N bytes)
  || BE64(issued_at)                                 (8 bytes)
))
```

The `issued_at` timestamp is encoded as 8-byte big-endian for deterministic cross-platform computation. See §25.16 (Vector 29) for a test vector.

**Revocation check:** Verifiers check revocation by resolving the issuer's service record (§3.10.13) and reading its `AttestationRevocations` pointer (§18.2.2, whose service-endpoint framing Track U4 reconciles with the service record). The pointer's target returns a list of revoked attestation IDs. If the attestation's `id` appears in the list, it is revoked. Additionally, the `revocation_status` field in the attestation itself is checked — if `Revoked`, the attestation is invalid regardless of the revocation endpoint.

### 3.5.3 Service-Record Attestation Entry

Identity link attestations are published as entries in the issuer's service record (§3.10.13). This enables discovery: any party resolving the service record can enumerate the issuer's identity links without querying a separate registry.

**Service-record entry format:**

```
Service {
  id:              "<did>#attestation-<platform>--<index>",  // e.g., "<identifier>#attestation-github.com--0"
  type:            "ScpIdentityLinkAttestation",
  serviceEndpoint: "<attestation_id>"                       // Hex-encoded attestation ID (§3.5.2)
}
```

**Fragment naming convention:** `attestation-<platform>--<index>` where `<platform>` is the `platform` value from the provider registry (§3.5.1) and `<index>` is a zero-based integer for disambiguation when multiple attestations exist for the same platform (e.g., multiple Mastodon instances).

**Fields:**

- `id`: Full DID URI with fragment. The fragment encodes the platform for human readability. The `<index>` disambiguates multiple attestations for the same platform.
- `type`: `ScpIdentityLinkAttestation` (constant). Consumers filter service-record entries by this type to discover identity link attestations.
- `serviceEndpoint`: The attestation ID (hex string). Consumers use this to look up the full `IdentityLinkAttestation` from the identity's attestation store on a relay.

**Maximum attestations per service record:** 64. This prevents service-record bloat — each entry adds to the record's size, which is replicated across resolvers — while providing enough headroom for users with many platform identities. The limit applies to service-record entries of type `ScpIdentityLinkAttestation` only; other entry types have their own limits.

**Bridge-layer attestation store limit:** Implementations MUST enforce the same 64-attestation-per-identity cap as the service-record layer. This unified limit ensures consistent behavior across all layers — the service record and the bridge attestation store share a single bound. The constant `MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID` (defined in `scp-ffi-common`) is the single source of truth for all bridge implementations.

**Lifecycle:** When an attestation is revoked, the corresponding entry MUST be removed from the service record. When an attestation is renewed (re-verified), the entry is unchanged — it still points to the same attestation ID. When an attestation is replaced (new attestation for the same platform+handle), the service entry's `serviceEndpoint` is updated to the new attestation ID.

### 3.5.4 Verification

Verification procedure depends on the attestation class (§3.5.0).

**Class 1 (Cryptographic) verification:**

1. Resolve the issuer's key state (§3.10.4). Read the public key it lists `current` in the `#active` role.
2. Verify the Ed25519 signature on the attestation envelope against the issuer's public key.
3. Check `revocation_status` is `Active`. If `Revoked`, reject.
4. Check `expires_at` (if present). If expired, reject.
5. Check freshness: if `evidence.verified_at` is older than the renewal interval for the verification method (§3.5.1), the attestation is stale. Stale attestations are degraded (reduced trust weight), not rejected outright.
6. **Trust the self-attestation.** Because issuer == subject, the DID key signature is sufficient. The attestation asserts "I performed OAuth verification at `verified_at` and the OIDC `sub` was `subject_id`." There is no cryptographic proof that the OAuth flow actually occurred — this is a self-attestation. It is acceptable for identity links because: (a) the claim is minimal, (b) the only use case is linking identities the user actually controls, (c) falsifying a link provides no protocol benefit (shadow claiming verifies independently, social graph import only surfaces genuine contacts).

**Class 2 (Reference) verification:**

1. Perform steps 1-5 from Class 1 verification (signature, revocation, expiry, freshness).
2. **Fetch the proof resource.** For `SignedPost`: HTTP GET the `post_url`, confirm the response body contains the issuer's DID string and the nonce. For `DnsRecord`: perform a DNS TXT lookup for `_scp-verify.<domain>`, confirm a record contains the issuer's DID string. DNSSEC validation is RECOMMENDED where the domain supports it.
3. **If fetch fails or DID is not present:** the attestation is unverified. Treat as if the attestation does not exist for trust evaluation. Do not cache a negative result — transient failures (rate limiting, DNS propagation delays) should not permanently invalidate an attestation.
4. **If fetch succeeds and DID is present:** the attestation is verified. Cache the result.

**Verification cache:**

- Consumer-side. Each consumer maintains its own cache of Reference attestation verification results.
- TTL: 1 hour. After TTL expires, the consumer MUST re-verify before granting trust weight.
- Cache key: attestation ID.
- Cache entries: `{ attestation_id, verified: bool, verified_at: u64, expires_at: u64 }`.
- Class 1 attestations do not require caching — DID signature verification is deterministic and fast.

**Renewal intervals** (SHOULD re-verify at these intervals; stale but not expired attestations are degraded, not rejected):

| Platform | Class | Renewal interval | Rationale |
|----------|-------|-----------------|-----------|
| `google.com` | 1 | 30 days | OIDC tokens expire; account may be revoked |
| `apple.com` | 1 | 30 days | OIDC tokens expire; account may be revoked |
| `microsoft.com` | 1 | 30 days | OIDC tokens expire; account may be revoked |
| `linkedin.com` | 1 | 30 days | OIDC tokens expire; account may be revoked |
| `discord.com` | 1 | 30 days | OIDC tokens expire; account may be revoked |
| `github.com` | 2 | 90 days | Profile bio may be edited; account may be suspended |
| `x.com` | 2 | 90 days | Profile description may be edited; account may be suspended |
| `reddit.com` | 2 | 90 days | Profile bio may be edited; account may be suspended |
| `bluesky.com` | 2 | 90 days | Profile description may be edited; account may be suspended |
| `mastodon:<instance>` | 2 | 90 days | Profile bio may be edited; instance may be deactivated |
| `npm` | 2 | 90 days | Profile page may be edited; account may be suspended |
| `pypi` | 2 | 90 days | Profile page may be edited; account may be suspended |
| `telegram.com` | 1 | 60 days | ChallengeResponse — no persistent proof; freshness matters |
| `steam` | 1 | 60 days | ChallengeResponse — no persistent proof; freshness matters |
| `well-known` | 2 | 180 days | HTTP endpoints are stable; domain ownership changes slowly |
| `dns` | 2 | 180 days | DNS records are stable; domain ownership changes slowly |

**ChallengeResponse renewal interval:** 60 days. ChallengeResponse attestations not tied to a specific platform (§3.5.1) use this default. For platform-specific ChallengeResponse entries (Telegram, Steam), the renewal interval is listed in the table above.

### 3.5.5 Shadow Identity Claiming Protocol

When a bridge connector creates a shadow identity for an external platform participant (§12.3), the following protocol governs claiming:

**Claiming sequence:**

1. **Eligibility check.** The claimant presents an `IdentityLinkAttestation` (§3.5.2) for the same platform and handle as the shadow identity. The bridge verifies:
   a. The attestation is valid (signature verifies, not expired, not revoked).
   b. The `platform` and `platform_handle` (or `platform_id` if available) match the shadow identity's external identity.
   c. The attestation's `evidence` has been verified within the last renewal interval (§3.5.4).

2. **Claim request.** The claimant sends a `ShadowClaimRequest` to the bridge context:
   ```
   ShadowClaimRequest {
     claimant_did:      DID,
     shadow_did:        DID,            // The shadow identity's DID
     attestation_id:    String,         // ID of the IdentityLinkAttestation
     attestation:       IdentityLinkAttestation, // Full attestation for verification
     timestamp:         u64,
     signature:         Ed25519Signature, // Signs claimant_did || shadow_did || attestation_id || timestamp
   }
   ```

3. **Bridge verification.** The bridge operator verifies:
   a. The attestation links the claimant's DID to the shadow identity's external identity.
   b. No other DID has already claimed this shadow identity.
   c. The claimant's DID is not on any block list relevant to the context.

4. **Merge execution.** On successful verification:
   a. The shadow identity's membership records in all bridge contexts are updated to reference the claimant's DID.
   b. Historical messages from the shadow identity are re-attributed to the claimant's DID in the context event log via a `ShadowClaimed { shadow_did, claimant_did, attestation_id, timestamp }` event.
   c. The shadow DID is deactivated — it cannot send new messages or be claimed by another party.
   d. The claimant inherits the shadow identity's role in the context (typically `member`; never higher than the context's default role for new members unless governance explicitly grants an upgrade).

5. **Conflict resolution.** If two claimants present valid attestations for the same shadow identity simultaneously, the first `ShadowClaimRequest` processed by the bridge wins. The second claimant receives a `SHADOW_ALREADY_CLAIMED` error (code 4040). The losing claimant MAY dispute via the bridge context's governance mechanism.

**Participation record handling.** The shadow identity's participation history (message counts, duration, event log entries) is NOT merged into the claimant's participation profile. Shadow participation is recorded under the shadow DID — the `ShadowClaimed` event establishes the link for auditing, but participation records remain separate to prevent Sybil amplification (creating shadow identities to inflate participation).

### 3.5.6 Security Considerations

**SDK-signed proofs are self-attestation summaries.** Class 1 proofs assert "I performed OAuth and the provider confirmed my identity." This is a self-attestation — there is no way for a consumer to independently verify that the OAuth flow occurred. This is acceptable ONLY for identity links, where issuer == subject. SDK-signed proofs MUST NOT be used for cross-party attestation types (endorsements, capability delegations, etc.) where the issuer and subject differ.

**No PII in attestations.** The attestation contains only: platform name, platform handle, platform user ID (opaque identifier, not email or name), and verification timestamp. No raw JWT, no OIDC claims beyond `sub`, no email addresses, no display names. The `openid`-only scope ensures the OIDC provider returns the minimum possible claim set. SDKs MUST NOT request `email` or `profile` scopes for attestation creation.

**Reference attestations carry zero trust until verified.** A Class 2 attestation with an unverified proof URL provides no trust signal whatsoever. Trust evaluation (§7.5) MUST score unverified Reference attestations at zero. This prevents an attacker from publishing a Reference attestation pointing to a URL they do not control — the attestation exists, but no consumer will trust it until they verify the proof.

**`revocation_status` in signed fields.** The `revocation_status` field is included in the signature scope (§3.5.2). This prevents re-activation: an attacker who obtains a `Revoked` attestation cannot strip the status and present it as `Active` because the signature covers `revocation_status`. However, this does NOT prevent replay of the original `Active`-signed version — the original attestation remains valid until consumers check the revocation endpoint. The revocation endpoint check (§18.2.2 `AttestationRevocations`) is ALWAYS required regardless of `revocation_status` value. The signed field is defense-in-depth, not a complete revocation mechanism.

## 3.6 Social Graph

There is no global social graph. No "friends list" primitive. No public follower count. No network-wide structure anyone can query.

Social graph data **is context state.** Each context already knows its members — their DIDs, their roles, their participation history. This is protocol state: verifiable against the context's event log, persistent, governed by context permissions. The social graph is not stored separately or owned by any agent. It is the sum of membership across contexts.

A user's view of their own social graph is **assembled from capability-gated queries** against the contexts they participate in. Your agent queries contexts for membership data, computes relationship strength from shared participation (how many contexts, how long, in what roles), and presents the result. The data lives in the contexts. The view is computed. Access is permissioned.

**Social graph sharing is capability-gated.** Sharing your social graph with others — letting someone see which contexts you're in, who you share spaces with — is governed by the same trust and capability model as any other data access. Grants are scoped however you choose:

- **Per-identity.** "Bob can see my connections. Carol cannot."
- **Per-capability scope.** "Bob can see that I'm in this context. Bob cannot see my other contexts."
- **Per-context.** "Everyone in this context can see that I'm a member. Nobody here can see what other contexts I'm in."
- **Per-category.** "Close contacts can see my full context list. Everyone else sees nothing."

This extends to relationship metadata — not just whether a connection exists, but the nature of it. Alice might see that you and Bob are both in the cooking quest. She cannot see that you and Bob also share a private finance context, unless you've granted that visibility.

**Access is through capability-gated protocol interfaces.** Social graph data is accessed through the same permission model as any other protocol data. Queries hit capability-gated interfaces; the protocol checks permissions before responding. No special mechanisms, no local caches treated as source of truth. The protocol provides query APIs for assembling and sharing graph views — these are not static data stores but permission-scoped computations over context membership.

**No new primitives required.** Social graph visibility falls out of the existing trust equation: `trust = f(identity, capability, context, metadata)`. Capability tokens authorize reading specific slices of your graph. The social graph isn't a separate system with its own privacy model — it's just another resource governed by the same model as everything else.

**Block/mute** is stored in identity private state (§3.7) — persistent, portable, encrypted.

**Blocking** operates at three tiers, each enforced through the same three cryptographic layers (§9.16, §9.17):

- **Layer 1 (key distribution denial):** Block list check denies key re-requests to blocked DIDs.
- **Layer 2 (SDK-mandated state destruction):** On block event, the blocker's SDK destroys cached keys and plaintext from the blocked party. This is a protocol requirement for compliant clients.
- **Layer 3 (access key wrapping):** Content keys are wrapped with per-member access keys. Deleting a member's access key = cryptographic revocation of stored content. See §9.17.

**Tier 1: DID-to-DID in-context (per-relationship, unilateral).** Alice blocks Dave in context X. Affects Alice's content in that context only — Dave can still see other members' content. This is the §9.16 sender-side blocking, scoped to a single context. On block: Alice rotates her sender key excluding Dave (Layer 1), Alice's SDK destroys Dave's cached content from Alice (Layer 2), Alice deletes Dave's access key for her content (Layer 3). On unblock: Alice removes Dave from her block list. Forward-only — Dave receives Alice's future content but historical content from before/during the block remains inaccessible (access keys were destroyed, not archived).

**Tier 2: DID-to-DID global (identity-level, cross-context).** Alice blocks Dave everywhere. Stored in identity private state (§3.7). Propagates to all contexts Alice and Dave share — equivalent to Tier 1 applied to every shared context simultaneously. On block: same three layers, applied across all shared contexts. On unblock: same forward-only restoration, across all shared contexts. Blocking is bidirectional: when Alice blocks Dave, both Alice's and Dave's SDKs rotate their sender keys excluding each other (§9.16.3).

**Tier 3: Governance-gated (context-level, all content).** Context governance revokes a member's content access. Goes through GovernanceEngine (propose/approve/reject per §5.9). Affects the target's access to ALL content in the context — not just one member's content. Governance actions: `RevokeAccess { did, access }`, `RestoreAccess { did, capabilities }`, `RotateContentKeys` (see ADR-031). Restoration is forward-only.

**Tier stacking:** All three tiers compose. If both Alice (Tier 1) and governance (Tier 3) have revoked Dave's access, both must be independently reversed for full restoration. Each tier's revocation and restoration is independent.

**Key difference between tiers:** Tiers 1-2 are per-relationship (Alice blocks Dave = Dave can't see Alice's content; Dave can still see Bob's content). Tier 3 is per-context (governance revokes Dave = Dave can't see ANY content in the context).

**Mute** is unidirectional. Alice mutes Dave; Alice no longer sees Dave's content. Dave is unaffected and can still see Alice. Muting is a protocol rule enforced in the SDK — apps built on the SDK inherit this behavior. Because the muter is not adversarial against themselves (they chose the mute), SDK-level enforcement is sufficient; cryptographic exclusion is not required.

## 3.7 Identity Private State

An identity has public state — its key-event log, its service record, and its published attestations — and **private state**: encrypted data that only the identity owner can read, replicated for availability and portability.

Context state handles multi-party social data. Identity private state handles single-party personal data. Together they cover every category of protocol-relevant state without requiring anything to live only on a local device.

```
Identity
├── Public State
│   ├── Key-event log (`09-security-model.md` §9.7.4.2 definitions)
│   │   ├── #0 — Identity Key (Ed25519, root of trust, offline)
│   │   ├── #active — Human Signing Key (Ed25519, hardware-backed)
│   │   └── the designation of the key that signs the service record
│   ├── Service record (§3.10.13) — relay list, private-state locations,
│   │   broadcast advertisements, self-asserted capability URIs, pointers
│   └── Published attestations (§3.5) — their own signed objects
│
└── Private State (encrypted, replicated)
    ├── Block / mute list
    ├── Graph visibility policies (default + per-identity grants)
    ├── Agent configuration defaults (cross-context preferences)
    ├── Personal annotations on other DIDs
    ├── Petnames for DIDs and contexts (§22.4) — per-identity, per `SCP` instance (ADR-048)
    ├── Notification preferences
    ├── Draft attestations (not yet published)
    └── (extensible — any identity-level private data)
```

**The human identity's key state names one operational role, `#active`** (`09-security-model.md` §9.7.4.2 definitions). An agent is a separate identity with its own key-event log, which the human's log anchors by cooperative delegation, so no agent key appears in a human's identity: ADR-063, the key-event-log identity substrate, overturns the shared-DID `#agent` verification method of ADR-039, and ADR-064, the forthcoming specification of the cooperative-delegation events, states how a delegator anchors a delegate's establishment events. `09-security-model.md` §9.1 invariant 1 is the home of that model, and this spec cites it rather than restating it.

**Encryption model.** Private state is encrypted with a dedicated symmetric **Private State Key (PSK)** — an AES-256 key used exclusively for identity private state encryption. The PSK is not derived from any signing key. Ed25519 keys are signing-only — they cannot be used for encryption. The PSK is generated independently and distributed to the identity owner's devices via HPKE (§3.7.2).

**Cryptographic specification:**

- **Algorithm:** AES-256-GCM (RFC 5116).
- **Key:** 32-byte random Private State Key (PSK), generated via CSPRNG (e.g., `OsRng`). The PSK is a raw symmetric key — it is not managed through `KeyCustody` (which handles asymmetric Ed25519/X25519 keys). One PSK per identity, shared across all enrolled devices.
- **Nonce:** 96-bit (12-byte) random nonce, generated per event via CSPRNG. Each event in the private state log gets a unique nonce. The nonce is stored alongside the ciphertext — it is not secret.
- **AAD (Additional Authenticated Data):** `did || "scp-private-state-v1" || sequence_number` where `did` is the identity's DID string encoded as 4-byte big-endian length prefix + UTF-8 bytes (per §9.5.1 encoding rules), `"scp-private-state-v1"` is the domain separator as raw UTF-8 bytes (no length prefix — fixed per version), and `sequence_number` is the event's sequence number as 8-byte big-endian u64. AAD binding prevents: (a) ciphertext from one identity being replayed against another, (b) events being reordered within the log, (c) cross-protocol confusion with other AES-256-GCM uses in SCP.
- **Domain separator:** `"scp-private-state-v1"`. Distinct from `"scp-sender-key-v1"` (§9.16.2), `"scp-access-key-v1"` (§9.17.1), and all other SCP domain separators.

```
Encryption (per event):
  nonce = random(12)
  aad = len(did) || did || "scp-private-state-v1" || sequence_number
  (ciphertext, tag) = AES-256-GCM-Seal(PSK, nonce, plaintext_event, aad)
  stored: { nonce, ciphertext, tag, sequence_number }

Decryption (per event):
  aad = len(did) || did || "scp-private-state-v1" || sequence_number
  plaintext = AES-256-GCM-Open(PSK, nonce, ciphertext, tag, aad)
  if tag verification fails → reject (tampered or wrong key)
```

**Storage model.** Same as context state: encrypted blobs stored on your published relays. Relays see "DID X has encrypted private state." Relays store and serve it. Relays cannot read, modify, or interpret it. This is encryption-as-access-control (§10.5) applied to identity rather than context — the same infrastructure, the same relay behavior, the same trust assumptions.

**Routing ID derivation.** Identity private state blobs are addressed on relays by a deterministic `routing_id` derived from the identity's DID string:

```
private_state_routing_id = HKDF-SHA-256(
    ikm:  identity_key_material,      // raw bytes of #0 public key
    salt: SHA-256("scp-private-state-salt-v1"),
    info: "scp-private-state-v1" || did_string,
    len:  32
)
```

HKDF (RFC 5869) is used instead of plain SHA-256 to prevent the relay from computing the `routing_id` from a known DID string. With plain `SHA-256("scp:private:" || did_string)`, any relay that knows a DID could identify which routing ID holds that identity's private state, enabling targeted censorship or surveillance. The HKDF derivation requires `identity_key_material` (the `#0` public key bytes), which the relay does not possess unless it has previously resolved the DID — and even then, the derivation is not obvious without knowing the salt and info strings. This provides pseudonymity for private state storage relative to relays that have not correlated the identity.

The domain separation (`"scp-private-state-v1"` info string and `"scp-private-state-salt-v1"` salt) prevents collision with other routing ID derivation schemes: key-event record routing uses `SHA-256("scp:did:" || identifier_bytes)` (§3.10.2), encrypted context routing uses HKDF from identity key material with `"scp-pseudonym"` (§9.10.4), broadcast context routing uses `SHA-256(context_id)` (§5.14), and context metadata routing uses `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` (§9.10.4.B).

The `IdentityPrivateState` entry of the identity's service record (§3.10.13) lists which relays store the private state. The `routing_id` tells the SDK how to address those blobs on those relays.

**Sync model.** Append-only event log, same pattern as context event logs. Each device appends events ("blocked DID Y at timestamp T", "granted Bob graph visibility at scope Z"). Any device that holds the PSK reconstructs current state from the log. Multi-device consistency: two phones and a laptop all hold the same PSK, all append to the same log, all converge to the same state. See §3.7.2 for how the PSK is distributed to devices.

Most identity private state operations are naturally commutative — "block X" and "block Y" produce the same result regardless of order. Simultaneous updates from multiple devices resolve without conflict in most cases. The event log records all operations; state is derived from the full log.

**Integrity.** The event log is authenticated via an append-only hash chain. Each event entry is hashed as:

```
event_hash[0] = SHA-256("SCP-PRIVATE-LOG-V1:" || event_data[0])
event_hash[i] = SHA-256("SCP-PRIVATE-LOG-V1:" || event_hash[i-1] || event_data[i])
```

The head hash (`event_hash[N-1]`) serves as the integrity root for the entire log. On each read from a relay, the device verifies the chain by recomputing hashes from the last verified checkpoint forward. If a relay has tampered with, reordered, or omitted events, the hash chain breaks and the device detects it.

**Verification procedure:**

1. The device stores the last verified `(event_count, head_hash)` tuple locally (in platform secure storage, alongside identity key material).
2. On fetch, the device receives new events from the relay starting after `event_count`.
3. The device computes `event_hash[event_count]` using the stored `head_hash` as the previous hash and the first new event's data.
4. Each subsequent event extends the chain: `event_hash[i] = SHA-256("SCP-PRIVATE-LOG-V1:" || event_hash[i-1] || event_data[i])`.
5. If the relay also returns a claimed head hash, the device verifies it matches the locally computed chain head. Mismatch indicates tampering.

The domain separator `"SCP-PRIVATE-LOG-V1:"` prevents cross-domain hash collisions with context event logs (which use the construction in §9.5). `event_data` is the serialized event bytes (MessagePack per §17). This is a linear hash chain (not a Merkle tree) because the single-owner case does not require efficient inclusion proofs or consistency proofs — the owner holds the full log and verifies sequentially. Context event logs use the full Merkle tree construction (§9.5) because multi-party verification requires proof exchange. The AES-256-GCM authentication tag provides per-event integrity verification: any modification to ciphertext, nonce, or associated data causes tag verification failure.

**Relationship to context state.** Identity private state is the single-owner degenerate case of context state. Same storage infrastructure. Same integrity model. Same relay interaction. No governance, no roles, no capability ceiling — because it's your data. The protocol doesn't need new infrastructure for this — it's the existing infrastructure with membership count of one and no access control layer (the encryption IS the access control, and only you have the key).

**Protocol-level constants (immutable):**

- **Size constraints.** Less constrained than context state. The single-owner case allows growth (block lists, annotations, agent memory, draft attestations) without imposing storage on other participants. Relays MAY enforce per-DID storage quotas as an operational concern, but the protocol does not mandate minimalism for identity private state.
- **Relay obligations.** Same storage class and retention as context events. No differentiated commitment — relays treat all encrypted blobs uniformly. A relay that stores context events for a DID stores identity private state under the same terms.
- **Key rotation.** On identity key rotation (§9.12), the PSK is rotated: generate a new PSK, re-encrypt private state events, distribute the new PSK to all enrolled devices via HPKE (§3.7.2). The old PSK is destroyed on all devices after re-encryption completes. For large private state, re-encryption is incremental: most recent events first, backfill in background. Each re-encrypted event receives a fresh random nonce.
- **Discovery pointer.** Explicit. The identity's service record (§3.10.13) carries an `IdentityPrivateState` entry listing the relays that store its private state. This cleanly disambiguates context event fetches from private state fetches without relay-side guessing. The key-event log carries no private-state location: the location is transport metadata, so it rides the service record, and changing it appends no key event (`09-security-model.md` §9.6.3).
- **Relay service endpoints.** The identity's service record (§3.10.13) carries `SCPRelay` entries listing the identity's transport-layer relay URLs — the endpoints where `TransportManager` routes encrypted blobs for this identity. Multiple entries are recommended for suppression resistance (§9.9.2). The designated service key signs that record and the key-event log carries only the designation of that key, so re-pointing a relay warms no root key (`09-security-model.md` §9.6.3, §3.10.13).

### 3.7.1 Block List Storage

Identity private state stores block lists at two granularities:

**Global block list.** DIDs blocked across all shared contexts (Tier 2). Stored as an append-only event log within identity private state:

- `BlockDID { target_did, timestamp }` — add DID to global block list.
- `UnblockDID { target_did, timestamp }` — remove DID from global block list.

The current block list is derived by replaying the event log. Both operations are commutative — "block X" and "block Y" produce the same state regardless of order. Multi-device sync is conflict-free: two devices can independently add blocks, and the union is correct.

**Per-context block list.** DIDs blocked in a specific context only (Tier 1). Same event types but scoped:

- `BlockDIDInContext { target_did, context_id, timestamp }`
- `UnblockDIDInContext { target_did, context_id, timestamp }`

**Block list propagation.** When a global block is issued (Tier 2), the SDK propagates to all shared contexts:

1. Enumerate contexts where both the blocker and the target are members.
2. For each shared context, execute the Tier 1 block protocol (§9.16.3) — rotate sender key, destroy cached content, delete access key.
3. Record the block in identity private state.

Propagation is best-effort and idempotent — if the SDK is offline for some contexts, the block executes on next connection. The identity private state event log is the authoritative record; per-context enforcement is the mechanism.

**ProtocolRepository methods.** The `Storage` trait (§17) requires these methods for block list persistence:

- `get_global_block_list(did: &DID) -> Result<Vec<DID>>`
- `is_globally_blocked(blocker: &DID, target: &DID) -> Result<bool>`
- `get_context_block_list(did: &DID, context_id: &ContextId) -> Result<Vec<DID>>`
- `is_blocked_in_context(blocker: &DID, target: &DID, context_id: &ContextId) -> Result<bool>`

These methods derive current state from the identity private state event log. Implementations MAY maintain materialized views for query performance.

**Write operations.** Block list mutations are performed through identity private state events. The SDK provides:

- `add_global_block(blocker: &DID, target: &DID) -> Result<()>` — Appends `BlockDID` event, then propagates to all shared contexts (§9.16.3).
- `remove_global_block(blocker: &DID, target: &DID) -> Result<()>` — Appends `UnblockDID` event, then propagates forward-only restoration to shared contexts.
- `add_context_block(blocker: &DID, target: &DID, context_id: &ContextId) -> Result<()>` — Appends `BlockDIDInContext` event, then executes Tier 1 block protocol.
- `remove_context_block(blocker: &DID, target: &DID, context_id: &ContextId) -> Result<()>` — Appends `UnblockDIDInContext` event, then executes forward-only restoration.

Each write triggers sender key rotation (§9.16.3), access key operations (§9.17.5), and SDK-mandated state destruction (§9.16.7) as side effects.

**Conflict resolution for same-target block/unblock.** If two devices simultaneously block and unblock the same target DID, the operations are NOT commutative. Resolution rule: **block wins.** When replaying the event log, if both `BlockDID { target: X }` and `UnblockDID { target: X }` exist with the same timestamp (within 1-second tolerance), the block takes precedence. For events with different timestamps, the later timestamp determines the current state.

### 3.7.1.1 Exhaustive Private State Event Types

All identity private state event types, organized by category:

**Block/Mute events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `BlockDID` | `target_did: DID, timestamp: u64` | Yes (different targets) | Global block (Tier 2) |
| `UnblockDID` | `target_did: DID, timestamp: u64` | Yes (different targets) | Global unblock |
| `BlockDIDInContext` | `target_did: DID, context_id: ContextId, timestamp: u64` | Yes | Per-context block (Tier 1) |
| `UnblockDIDInContext` | `target_did: DID, context_id: ContextId, timestamp: u64` | Yes | Per-context unblock |
| `MuteDID` | `target_did: DID, timestamp: u64` | Yes | Global mute |
| `UnmuteDID` | `target_did: DID, timestamp: u64` | Yes | Global unmute |
| `MuteDIDInContext` | `target_did: DID, context_id: ContextId, timestamp: u64` | Yes | Per-context mute |
| `UnmuteDIDInContext` | `target_did: DID, context_id: ContextId, timestamp: u64` | Yes | Per-context unmute |

**Graph visibility events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetDefaultGraphVisibility` | `visibility: GraphVisibility, timestamp: u64` | No | Default visibility for all DIDs |
| `GrantGraphVisibility` | `target_did: DID, scope: VisibilityScope, timestamp: u64` | Yes (different targets) | Per-DID override |
| `RevokeGraphVisibility` | `target_did: DID, timestamp: u64` | Yes | Remove per-DID override |

**Agent configuration events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetAgentConfig` | `key: String, value: MessagePackValue, timestamp: u64` | No (same key) | Key-value agent preferences |
| `DeleteAgentConfig` | `key: String, timestamp: u64` | No (same key) | Remove a preference |

**Annotation events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetAnnotation` | `target_did: DID, key: String, value: String, timestamp: u64` | No (same target+key) | Personal note on a DID |
| `DeleteAnnotation` | `target_did: DID, key: String, timestamp: u64` | No (same target+key) | Remove annotation |

**Petname events (§22.4):**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetPetname` | `target: PetnameTarget, name: String, timestamp: u64` | No (same target) | `PetnameTarget` = DID or ContextId |
| `DeletePetname` | `target: PetnameTarget, timestamp: u64` | No (same target) | Remove petname |

**Notification events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetNotificationPreference` | `scope: NotificationScope, level: NotificationLevel, timestamp: u64` | No (same scope) | `NotificationScope` = Global, PerContext(id), PerDID(did) |

**Attestation draft events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SaveDraftAttestation` | `draft_id: String, attestation: IdentityLinkAttestation, timestamp: u64` | Yes (different drafts) | Draft not yet published |
| `DeleteDraftAttestation` | `draft_id: String, timestamp: u64` | Yes | Remove draft |
| `PublishDraftAttestation` | `draft_id: String, timestamp: u64` | Yes | Mark draft as published |

**Device registry events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `EnrollDevice` | `device_id: String, device_x25519_pubkey: [u8; 32], device_name: String, enrolled_at: u64` | Yes | New device enrollment |
| `UnenrollDevice` | `device_id: String, timestamp: u64` | Yes | Device removal |

**Recovery contact events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `AddRecoveryContact` | `contact_did: DID, timestamp: u64` | Yes | Designate recovery contact |
| `RemoveRecoveryContact` | `contact_did: DID, timestamp: u64` | Yes | Remove recovery contact |

For non-commutative events (same key/target modified from multiple devices), conflict resolution is **last-timestamp-wins** with tie-breaking by lexicographic comparison of the event hash.

### 3.7.2 Multi-Device Private State Key Distribution

Identity private state is encrypted with a single PSK shared across all of the identity owner's devices. The challenge: each device has its own hardware-backed keys that cannot be exported (§9.7.2), so the PSK must be distributed TO each device rather than derived FROM a shared secret.

**Device enrollment model.** Each device generates a device-specific X25519 keypair via `KeyCustody::generate_keypair(KeyType::X25519)` at device enrollment time. This keypair is used exclusively for receiving HPKE-wrapped key material (PSK distribution, PSK rotation). The X25519 public key is published in the identity's device registry — an encrypted list within identity private state itself (bootstrapped during identity creation, see below).

**Why not derive from the Identity Key (#0)?** The Identity Key is Ed25519 (signing-only) and its private key "never [leaves] the secure element" (§9.7.2). While Ed25519-to-X25519 conversion is mathematically possible (RFC 7748, birational equivalence between Edwards and Montgomery curves), it requires access to the Ed25519 private key bytes — which hardware security modules (Secure Enclave, Android Keystore) do not export. A design that depends on Ed25519-to-X25519 conversion would fail on every hardware-backed key. The PSK is therefore an independent symmetric key, distributed via HPKE to device-specific X25519 keys that are software-managed through `KeyCustody`.

**Identity creation (first device):**

1. Generate the PSK: 32 random bytes via CSPRNG.
2. Generate a device-local X25519 keypair via `KeyCustody`.
3. Store the PSK locally in the device's secure key store.
4. Initialize the device registry in identity private state with this device's X25519 public key. The device registry is the first event in the private state log — it is encrypted with the PSK (which only this device holds at this point).
5. Publish the encrypted private state to relays.

**Adding a new device (device enrollment):**

```
Existing device (Device A) enrolls new device (Device B):

1. Device B generates an X25519 keypair via KeyCustody.
2. Device B presents its X25519 public key to Device A.
   Transport: out-of-band (QR code, local network, NFC) or via
   a standing bilateral context (§5.12.4) between the human's devices.
3. Device A verifies the enrollment request (user confirmation required).
4. Device A wraps the PSK to Device B's X25519 public key via HPKE:
   enc, sealed_psk = HPKE-Seal(
     mode: Base,
     kem: DHKEM(X25519, HKDF-SHA256),
     kdf: HKDF-SHA256,
     aead: AES-128-GCM,
     recipient_pk: device_b_x25519_pubkey,
     info: "scp-private-state-v1" || len(did) || did || "device-enroll",
     plaintext: psk
   )
5. Device A sends (enc, sealed_psk) to Device B via the same channel.
6. Device B opens the HPKE ciphertext using its X25519 private key,
   recovering the PSK.
7. Device A appends a DeviceEnrolled event to the private state log:
   DeviceEnrolled { device_x25519_pubkey, enrolled_at, enrolled_by_device }
   This event is encrypted with the PSK (readable by all enrolled devices).
8. Device B can now decrypt and append to the private state event log.
```

**HPKE suite.** Device enrollment and PSK distribution use DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM — the same HPKE suite as MLS (§9.5) and sender key distribution (§9.16.2). The `info` parameter includes the domain separator `"scp-private-state-v1"` concatenated with the DID and purpose string to prevent cross-protocol confusion with sender key HPKE (`"scp-sender-key-v1"`) or access key HPKE (`"scp-access-key-v1"`). The full `info` construction is `"scp-private-state-v1" || len(did) || did || purpose`, where `did` is preceded by a 4-byte big-endian unsigned length prefix (per §9.5.1 encoding rules) and `purpose` is a fixed-version UTF-8 string with no length prefix. The `aad` is empty (the `info` already binds the DID, and a fresh HPKE context — fresh encapsulation — is used per device, so there is no cross-recipient substitution surface).

**Purpose strings.** Two purposes are defined, distinguishing the two flows that wrap a PSK to a device key:

- `"device-enroll"` — initial PSK distribution when a device is enrolled (the flow above) and during trusted-device / social recovery (recovery IS enrollment, §3.3).
- `"psk-rotate"` — re-wrapping a freshly generated PSK to all remaining enrolled devices when a `PskRotated` event is emitted: on device removal (above) and on compromise recovery key rotation (§9.12 step 6).

The purpose string binds each HPKE ciphertext to its flow, so a `device-enroll` wrap cannot be opened in a `psk-rotate` context (different `info` produces a different HPKE key schedule, causing AEAD failure).

**Device removal:**

1. An authorized device appends a `DeviceRemoved { device_x25519_pubkey, removed_at }` event to the private state log.
2. The removing device rotates the PSK: generates a new PSK, re-wraps it via HPKE to all remaining enrolled devices' X25519 public keys, and appends a `PskRotated { wrapped_keys: Vec<(device_pubkey, hpke_ciphertext)> }` event.
3. Re-encryption of existing private state events proceeds incrementally under the new PSK (same as key rotation, §3.7 protocol-level constants).
4. The removed device's cached PSK becomes useless for future events. Historical events encrypted under the old PSK are accessible only if the removed device retained the old PSK locally — the protocol cannot force deletion on an untrusted device (same honest limitation as §9.15).

**Device registry.**

The device registry is stored within identity private state as a sequence of `DeviceEnrolled` and `DeviceRemoved` events. The current set of enrolled devices is derived by replaying the log (same pattern as block lists, §3.7.1). Each entry contains:

```
DeviceEnrolled {
    device_x25519_pubkey: [u8; 32],  // X25519 public key for HPKE
    enrolled_at: u64,                 // Unix timestamp (milliseconds)
    enrolled_by_device: [u8; 32],     // X25519 pubkey of the enrolling device
    device_label: String,             // Human-readable label ("iPhone", "Laptop")
}

DeviceRemoved {
    device_x25519_pubkey: [u8; 32],
    removed_at: u64,
}

PskRotated {
    wrapped_keys: Vec<DeviceWrappedPsk>,  // One entry per enrolled device
    rotated_at: u64,
}

DeviceWrappedPsk {
    device_x25519_pubkey: [u8; 32],
    enc: Vec<u8>,           // HPKE encapsulated key
    sealed_psk: Vec<u8>,    // HPKE-sealed PSK
}
```

**Bootstrap paradox resolution.** The device registry is itself encrypted with the PSK — so how does the first device read it? The first device generated the PSK (step 1 of identity creation) and holds it locally before any private state events exist. The first `DeviceEnrolled` event is encrypted with that PSK. Subsequent devices receive the PSK via HPKE before they need to read the log. There is no circular dependency: the PSK is always distributed out-of-band (HPKE to device key) before the device attempts to read PSK-encrypted events.

**Interaction with trusted device recovery (§3.3).** When a user recovers their identity on a new device via trusted device recovery, the recovery flow includes PSK distribution: the trusted device wraps the current PSK to the new device's X25519 public key via the same HPKE enrollment protocol above. This is the same mechanism as adding a new device — recovery IS enrollment. The recovering device generates a fresh X25519 keypair, the trusted device wraps the PSK, and the new device gains access to the full private state history.

**Interaction with key rotation (§9.12).** Step 6 of the compromise recovery protocol specifies "re-encrypt identity private state under the new key." With PSK-based encryption, this means: (a) generate a new PSK, (b) wrap the new PSK to all enrolled devices via HPKE, (c) append a `PskRotated` event, (d) re-encrypt existing events under the new PSK incrementally. If the compromise involved a device (device stolen), that device is removed first (device removal protocol above), and the PSK rotation excludes the compromised device's X25519 public key.

**ProtocolRepository methods.** The `Storage` trait (§17) requires these additional methods for PSK and device management:

- `store_private_state_key(did: &DID, psk: &Zeroizing<[u8; 32]>) -> Result<(), StoreError>`
- `load_private_state_key(did: &DID) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError>`
- `store_device_registry_event(did: &DID, seq: u64, event: &[u8]) -> Result<(), StoreError>`
- `load_device_registry(did: &DID) -> Result<Vec<DeviceRegistryEvent>, StoreError>`

The PSK MUST be stored in the platform's secure key store (Keychain on Apple, Keystore on Android, SQLCipher-encrypted storage on desktop/server — per §17.8 platform-specific key custody). The PSK is zeroized on destruction (`Zeroizing<[u8; 32]>`).

## 3.8 DID Resolution Security

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised.

**The protocol has one identifier method, and it is inception-derived.** An identifier is self-certifying through its key-event log: the identifier is the digest of the inception event's signed preimage and encodes no key (`09-security-model.md` §9.7.4.2 R13). A resolver recomputes the identifier from the served chain's inception event and verifies every later event under R3, so a served record is verifiable against the identifier without trusting any intermediary. MITM on resolution is impossible given the correct identifier. A stale head of the accepted chain is rejected by sequence, and two chains that diverge are settled by fork precedence (R6, R12). See §9.6.1 for the full specification.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

### 3.8.1 Canonical DID string form (deterministic-derivation input)

Wherever a DID string feeds a **deterministic hash preimage** — any place two independent resolvers must agree byte-for-byte or they would derive divergent identifiers (e.g. the `derived_context_id` of §5.15.8) — the DID MUST be reduced to its **canonical string form**, the single comparison form resolution yields.

**Purpose (canonical agreement, not injectivity).** With the §5.15.8 derivation now length-prefixed (§9.5.1), field-boundary injectivity is unconditional **by construction** and does **not** depend on this section. §3.8.1's sole job is **byte-agreement**: both parties MUST feed **byte-identical** DID strings into any shared preimage so they do not split-brain onto divergent identifiers. (Even with length prefixes, two encodings of the *same* logical DID are two distinct byte strings and would length-prefix to two distinct preimages — hence the canonicalization requirement remains load-bearing, but for agreement, not for disambiguating field boundaries.)

**The canonical form is the identifier's 32-byte digest** (`09-security-model.md` §9.7.4.2 R13), whose textual encoding a later revision of that section fixes together with the preimage field order. **The byte-agreement guarantee is airtight**: the identifier is a fixed-length digest, so a derivation that consumes the digest bytes admits exactly one encoding and two honest resolvers cannot diverge.

A DID string that is not the canonical form of an inception-derived identifier is **rejected at a fail-loud admission gate** — never silently coerced — so a deterministic derivation can never be fed a DID it cannot reduce. (This admission gate is about *canonical agreement*, distinct from the retired §5.15.8 colon-freedom assumption, which length-prefixing made unnecessary.)

## 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in the substrates `09-security-model.md` §9.7.4.1 item 4 names), distribution (as key state carried by the identity's key-event log), rotation (a `KeyState` or `RootRecovery` event signed by the standing root set, `09-security-model.md` §9.7.4.2 R3), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4.

## 3.10 DID Resolution

DID resolution is the trust root for identity verification (§3.8). **The SCP relay network carries identity, and the protocol runs no second resolution layer.** An identity publishes its key-event log to SCP relays through the existing PUBLISH/QUERY operations (ADR-004), addressed by a deterministic `routing_id`. An SCP-native relay validates each key-event record blob it stores and keeps one slot per (routing id, divergent suffix) (§3.10.2, `09-security-model.md` §9.7.4.2 R9), which is what makes the relay layer suppression-resistant (§3.10.8); a foreign transport that cannot validate stores the record opaquely and stays correct through client-side verification.

Resolution is self-certifying through the key-event log: the resolver recomputes the identifier from the chain's inception event and verifies every later event under the standing root (`09-security-model.md` §9.6.1, §9.7.4.2 R2 and R3). Every relay is untrusted. Trust derives from the cryptographic binding between the identifier and the inception event that produced it, not from the infrastructure serving it. An SCP-native relay MAY additionally validate the records it stores (§3.10.2) — a validating relay verifies the chain and keeps one slot per divergent suffix, which resists suppression — but this is an availability property layered on top, never a trust dependency: the resolver re-verifies every record independently and accepts nothing on the relay's word (§3.10.4).

### 3.10.1 Which Relays a Resolution Queries

A resolver queries two disjoint sets of relays, and it queries them in parallel:

| Relay set | Where the resolver learns it | Day-one availability |
|-----------|------------------------------|----------------------|
| The identity's own relays | the relay list the identity's service record carries (§3.10.13, `09-security-model.md` §9.6.3) | Only after the resolver holds that identity's service record |
| The fallback set | any entry of the SDK-shipped community relay list of `18-addressability-and-deployment.md` §18.5.1 that the identity's service record does not name (`09-security-model.md` §9.7.4.2 definitions) | Day one |

A served chain is **valid** when it recomputes to the target identifier and every one of its events verifies under `09-security-model.md` §9.7.4.2 R2 and R3. Among valid chains the resolver takes the higher-sequence head where one chain is a prefix of the other, and settles two chains that diverge by fork precedence (§9.7.4.2 R6).

Parallel query means resolution latency is the latency of the fastest relay that answers. Once a resolver holds an accepted baseline for the identifier, it cancels the remaining queries as soon as one valid response arrives; a resolver holding none satisfies R11's first-contact floor before it ends the resolution.

### 3.10.2 Relay-Based Resolution

Key-event records are published to SCP relays using the existing PUBLISH/QUERY operations (ADR-004) — no new wire types. An identity's key-event log rides in a minimal, fixed-layout **key-event record relay frame** (§9.10.12), addressed by a deterministic `routing_id`. What is new versus a plain opaque blob is a relay *behavior*: an SCP-native relay verifies the chain the frame carries and keeps one slot per (routing id, divergent suffix). This is issue #482.

**Routing ID derivation:**

```
did_routing_id = SHA-256("scp:did:" || identifier_bytes)
```

`09-security-model.md` §9.7.4.2 R13 states this derivation, and its input is the identifier's 32 raw digest bytes.

The `"scp:did:"` domain separator prevents collision with other routing ID derivation schemes in the protocol: encrypted context routing IDs use HKDF from identity key material (§9.10.4), broadcast context routing IDs use `SHA-256(context_id)` (§5.14), and context metadata routing IDs use `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` (§9.10.4.B). The domain separator ensures that a DID string can never produce a routing ID that collides with a context ID or metadata address. Because key-event records live at their own `routing_id` domain, the address is the type discriminant — the frame carries no magic tag or record-kind byte (§9.10.12).

**Publication** uses the existing PUBLISH operation (ADR-004):

```
PUBLISH {
    routing_id: did_routing_id,
    blob_ttl: 604800,
    blob: <key-event record relay frame (§9.10.12), carrying
           (identifier, value)>
}
```

**Resolution** uses the existing QUERY operation:

```
QUERY {
    routing_id: did_routing_id,
    since: null,
    limit: N          // N = 16 (implementation constant)
}
```

`limit: N` (N = 16) **dominates `limit: 1`** and costs nothing where it does not help. Against a **validating** SCP-native relay the routing ID is slot-exclusive (below) and holds at most `MAX_RETAINED_SUFFIXES` slots, one per divergent suffix. **A slot is an ordered sequence of frames**, so `N` bounds one page of frames and bounds no slot: the resolver pages the slot by the walk `09-security-model.md` §9.7.4.2 R9 states, re-issuing QUERY with `since` set to the `stored_at` of the last frame it accepted. Against a **non-validating or foreign** transport that accumulates multiple blobs per `routing_id`, `limit: N` lets the resolver retrieve up to N candidates and sift them by chain verification and fork precedence (§3.10.4 step 5) — defeating an intra-relay shadowing attempt that a single-record fetch would miss, Under an *active* flood on a non-validating relay this remains best-effort (§3.10.8 residual): N candidates may all be junk. The resolver's selection across relays (§3.10.4) still returns the genuine chain whenever any queried relay holds it.

**Relay-side validation (SCP-native relays). This subsection and its slot-exclusivity rules below are the one home of the relay's validation procedure**, and `09-security-model.md` §9.10.12 cites them and restates none of them; `09-security-model.md` §9.7.4.2 R9 is the one home of the slot key, the write rule over the assembled chain, and the eviction rule, and step 4 below applies R9 without restating it. The whole path sits behind the existing per-IP PUBLISH rate limit (ADR-004). On PUBLISH of a blob at a `routing_id`, an SCP-native relay performs the checks **cheapest-first**, so junk is rejected before any expensive work:

1. **Structural decode.** Attempt to decode the blob as a key-event record frame (§9.10.12). A blob that does not decode is not a candidate key-event record (it is governed by the slot-exclusivity rule below).
2. **Identifier→routing_id binding.** Confirm that `routing_id` equals `SHA-256("scp:did:" || identifier_bytes)` over the 32 raw digest bytes the frame's `identifier` field carries — the derivation `09-security-model.md` §9.7.4.2 R13 states. The identifier encodes no key (R13), so the relay derives no key from any frame field. This binding is the discriminant that lets a validating relay recognize a key-event record without any new wire type or knowledge of `routing_id` semantics — and it is a plain hash, cheaper than a signature verify, so it runs **before** step 3.
3. **Chain verification, on whichever of two branches the frame's first event selects** (`09-security-model.md` §9.7.4.2 R9 states the rule; this step carries the procedure). Where the frame's **first event is an inception event**, the relay recomputes the identifier from it, rejects a frame that recomputes to anything but the `identifier` field of step 2, and verifies every event of the frame under `09-security-model.md` §9.7.4.2 R2 and R3. Where the frame's **first event's predecessor digest names an event the relay already holds** at that routing id, the relay verifies the frame's events under R2 and R3 against the standing root the assembled chain carries at that named position, and recomputes no identifier — the chain it is extending recomputed to this identifier when its inception frame arrived. A frame whose first event selects neither branch is rejected. This is the relay's write authorization: the chain authorizes the write, and no key the writer supplies does.
4. **Slot placement.** For a frame that passed steps 1–3, place its events under `09-security-model.md` §9.7.4.2 R9, which is authoritative for the slot key, what a slot holds, the write rule over the assembled chain, and the eviction rule; this section restates none of it. **The frame carries no signature and no sequence number** (`09-security-model.md` §9.10.12), so chain verification plus R9 is the whole write decision and the rule compares no number beside the chain.

**Slot-exclusivity.** A validating relay does not store key-event records alongside arbitrary blobs. The moment a binding-valid frame whose chain verifies first **establishes a slot** at a `routing_id`, that `routing_id` becomes **slot-exclusive**:

- **(a)** the relay rejects any subsequent PUBLISH at that `routing_id` that is not a frame passing steps 1–4 above. The test is that positive one and no enumeration stands beside it: a chain that diverges from a stored chain **passes** step 4, because R9 gives a divergent suffix its own slot, and an enumeration that listed "a chain that does not extend the chain in an existing slot" among the rejects would hand the routing id to whichever party published first and leave every resolver holding one chain where R6 needs two;
- **(b)** when the first slot is established, the relay **evicts any pre-existing opaque blobs** stored at that `routing_id`;
- **(c)** QUERY at that `routing_id` returns **every slot the routing id holds and nothing else**, one slot per divergent suffix, a page at a time under R9's walk, because a resolver runs fork precedence over the chains it is served and a relay that returned one slot would decide that rule for it. The read path derives the slots from the stored self-certifying frames, so a cold index changes what QUERY returns in no way;
- **(d)** the relay **rejects a client-issued DELETE of any stored key-event record frame whose chain verifies** (a slot blob in particular) — a PUBLISH appends events to a slot and replaces none (`09-security-model.md` §9.7.4.2 R9), and only R9's rank eviction removes a slot; a client DELETE never removes a genuine record. (Relay-*internal* eviction, rule (b) and R9's rank eviction, is not a client DELETE and is unaffected.) Because DELETE addresses a blob by `blob_id` (`= SHA-256(blob)`) rather than by `routing_id`, and the in-memory slot index is a cache that a relay restart or a store-sharing peer node leaves cold, this gate MUST be **storage-derived, not index-derived**: on DELETE the relay reads the blob at `blob_id` and, if it structurally decodes as a key-event record frame whose chain recomputes to the frame's `identifier` and verifies under R2 and R3, rejects the DELETE regardless of index state. The chain is self-certifying, so the blob's protected status is reconstructible from the bare bytes; this makes rule (d) immune to a cold or unpersisted index. The DELETE gate runs behind the same per-IP rate limit as PUBLISH (the storage read + signature verify it performs must not be an unmetered amplification surface) and **fails closed** on a storage read error (an integrity gate must not let a transient error open a delete).

**Before** the first valid frame, the relay cannot recognize the `routing_id` as identity-domain — `SHA-256` is one-way, so it cannot distinguish a not-yet-claimed identity `routing_id` from any other opaque-blob address. Pre-seeded junk published before the victim's first key-event publish therefore sits as ordinary opaque blobs until the first binding-valid frame establishes the slot, at which point rule (b) evicts it. Once the owner has published even once, QUERY on a validating relay cannot be made to return anything but that identity's slots.

**A cold slot index changes no outcome, because every gate is storage-derived.** The in-memory slot index is a cache, and it starts empty after a relay restart or on a store-sharing peer node even where the durable blobs are still present. Both gates that a stale newcomer would otherwise defeat read storage rather than the index: QUERY (rule (c)) re-derives the slots from the stored frames, and the DELETE gate (rule (d)) re-reads and re-verifies the blob it is asked to delete. R9's write rule likewise reads the assembled chain the relay holds in storage, so a replayed frame carrying a prefix of the stored chain takes R9's idempotent-refresh case and rolls nothing back. Where the durable blob has itself expired — the owner went offline past the 6-day republish cycle — the genuine record is absent rather than suppressed, any attacker blob at that routing id fails the resolver's own chain verification (§3.10.4 step 3), resolution falls through to the identity's other relays, and the owner's next republish re-establishes the slot and re-fires rule (b). The residual is availability-only and bounded: a junk flood can push a genuine record outside a narrow QUERY page on that one relay until the index warms, which the resolver's other relays and the fallback set cover (§3.10.4). **Both gates are relay-side code**, so neither closes anything against a relay whose operator omits them; the control that covers a first contact on a single relay is `09-security-model.md` §9.7.4.2 R11's floor.


Slot-exclusivity is a relay **storage** behavior (the base relay stores multiple opaque blobs per `routing_id` with no per-`routing_id` cap, ADR-004). This spec section is authoritative for the behavior; the relay-storage mechanics (one slot per divergent suffix holding the longest chain, R9's write rule and its rank eviction, the storage-derived DELETE gate) are transcribed in the companion **ADR-004 "DID-Record Slot-Exclusivity" subsection**, whose own text still names the superseded sequence rule and the superseded frame name (implemented under #482 / SCP-RELAYRES-003). The threat-model conclusions — the flood-inert enumeration and the DELETE-rollback vector — are owned by §3.10.8; ADR-004 records how the relay storage layer realizes them.

This mirrors, and extends to a stored public record, the exact check `BRIDGE_REGISTER` already performs on the control plane — Ed25519 signature + the same `SHA-256("scp:did:" || identifier_bytes) == routing_id` binding (§10.12.4). It is an **availability and anti-suppression measure, never a trust dependency** (see the client-verify property below).

**Relay-side validation is an OPTIONAL capability of SCP-native relays.** The protocol MUST NOT require a validating relay. Foreign transports and adapters (Nostr, Matrix, etc.) that cannot validate treat the frame as an opaque blob; resolution stays correct over them via client-side verification and multi-relay publishing. The suppression-resistance property of the relay layer (§3.10.8) is delivered by validating SCP-native relays; non-validating storage contributes availability only.

**Properties:**

- **Client always re-verifies (relay untrusted).** The resolver ALWAYS authenticates a served record by the key-event log the frame's `value` carries — recompute the identifier from the inception event and verify every event under `09-security-model.md` §9.7.4.2 R2 and R3 — and never by the frame's framing bytes or the relay's acceptance; the identifier encodes no key (`09-security-model.md` §9.7.4.2 R13). Relay validation is defense-in-depth for availability; it is never a trust input. A relay that skips, botches, or lies about validation degrades availability only, never integrity.
- **Self-verifying blob payload.** The frame carries the key-event log, so a resolver authenticates the record from the blob alone — no second fetch is required to obtain the chain the verification reads.
- **Multi-relay.** A resolver can QUERY any relay that stores the target identity's key-event log. Identity owners SHOULD publish to multiple relays — their own relays plus entries of the community relay list (§18.5.1) — for availability and suppression resistance.
- **Size budget, measured on the chain.** The relay stores a key-event chain and nothing derived from it, and a chain's bytes grow with the square of its key-event count because every state-carrying event lists every key the chain ever installed (`09-security-model.md` §9.7.4.2 R8). One frame carries one contiguous chain segment, bounded by the 256KB relay blob size limit (ADR-004) less the frame's fixed prefix, and a relay serves a slot's chain as the ordered sequence of frames covering inception through head (`09-security-model.md` §9.7.4.2 R9). The keys the chain installs are bounded by `MAX_KEYS_PER_CHAIN` (`09-security-model.md` §9.18.17). The key state of 2-30KB is what a resolver derives after it assembles and verifies the chain, and it is not what the relay stores.
- **TTL and republishing.** The maximum relay blob TTL is 604800 seconds (7 days). Identity owners MUST republish to relays at least every 6 days (1-day safety margin). The RepublishManager runs that 6-day cycle, and it is the only republication cycle the protocol defines.

### 3.10.4 Resolution Protocol

The full resolution sequence:

```
1. Compute did_routing_id = SHA-256("scp:did:" || identifier_bytes)
2. QUERY did_routing_id in parallel on the identity's own relays (the relay
   list of the service record the resolver last accepted for that identity,
   where it holds one, §3.10.13) and on
   the community relays of the fallback set (§18.5.1), using the existing
   QUERY operation (ADR-004; the stored blob is a key-event record frame,
   §9.10.12).
3. For each response:
   a. Decode the key-event record frame (§9.10.12), take its `value`, and assemble
      the chain segments the slot served. Framing bytes are unsigned and
      MUST NOT be trusted; only the chain the relay values carry is verified.
   b. Recompute the identifier from the chain's inception event and DISCARD
      the response if it differs from the identifier being resolved
      (09 §9.7.4.2 R2).
   c. Verify every event of the chain under 09 §9.7.4.2 R3 — each indexed
      signature against the key at its index, each reveal against the
      standing commitment. Discard a chain that carries an
      author-attributable defect (`Invalid{at_event}`).
4. Settle the surviving chains:
   a. Where one chain is a prefix of another, take the longer; discard a
      head of the accepted chain at a strictly lower sequence, changing no
      accepted state (09 §9.7.4.2 R12).
   b. Where two chains diverge from a shared prefix, apply fork precedence
      (09 §9.7.4.2 R6) and return `Contested` where it ties (R7).
5. Where the resolver holds no accepted baseline for this identifier, it
   MUST satisfy R11's first-contact floor (09 §9.7.4.2 R11) over the chains
   that survived step 4, counting no relay that failed, timed out, or served
   a chain step 3 discarded; otherwise it returns `Inconclusive{SingleSource}`
   and adopts no head. A resolver holding an accepted baseline resolves
   against one relay, and this step does not apply to it.
6. Derive the key state from the latest state-carrying event of the chain
   adopted in step 4 (09 §9.7.4.2 R8). Resolution yields key state; the
   identity's service record is resolved separately (§3.10.13).
7. Cache result per §9.10.7 caching policy
   (24h refresh for active contacts, 7d for inactive)
```

Step 2 queries the identity's own relays and the fallback set together, never one after the other: a resolver that holds no service record for the identity knows no relay of its own to query, and a resolver that holds one still needs a relay outside that list to satisfy R11's second relay.

**Cancellation and contradiction semantics:**

The parallel query model (step 2) requires clear rules for when queries are cancelled, how contradictions are resolved, and what happens on failure:

- **First-response optimization.** When the first valid response arrives, the resolver SHOULD continue waiting for a second relay's response for up to 2 seconds rather than cancelling immediately; on a first contact step 5 binds it. Waiting lets the resolver detect a stale chain: where two relays return valid chains and one is a prefix of the other, the longer chain is authoritative (step 4a). Cancelling the slower query immediately would miss a longer chain on the slower relay, and would also hide a divergence the resolver must settle under fork precedence.
- **Two relays succeed with heads of one chain at the same sequence.** The **chain bytes** the two records carry MUST be byte-identical, and the resolver compares those and never the framing around them (`09-security-model.md` §9.10.12). Where the chains are identical the two records are one chain and the resolver settles nothing. Where the chains differ at any event, the two heads are divergent events at one sequence and the resolver settles them under fork precedence (step 4b) rather than picking one.
- **Two relays succeed with heads of one chain at different sequences.** The longer chain is authoritative. The resolver MAY re-publish the longer chain to the relay that returned the shorter one (protocol-level healing, §3.10.7).
- **One relay fails, another succeeds.** The successful response is accepted, subject to step 5's two-relay rule on a first contact. The failed relay's error is logged but does not prevent resolution. The resolver does NOT retry the failed relay synchronously — the next resolution cycle (24h for active contacts, 7d for inactive) queries it again.
- **Every relay fails.** If a cached key state exists and is less than 7 days old, it is returned with a `resolution_source: "cache"` indicator, and §9.11's auto-accept gates treat a cache older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` as unusable for a standing check. If no cache exists or the cache is older than 7 days, resolution fails with error `DID_RESOLUTION_FAILED` (code 5010). The resolver MUST NOT fabricate a document.
- **A relay returns a chain that fails verification.** The response is discarded as if that relay had failed. A chain whose recomputed identifier differs, or whose events carry an author-attributable defect, is logged at WARN level (it may indicate relay tampering). The resolver does not fall back to the failing chain under any circumstances.
- **Relay blob fails frame decoding.** A relay blob that fails any decoder rule of §9.10.12 is discarded as if that relay had failed. Malformed framing is never trusted and never partially parsed (§9.10.12 decoder rules); the resolver falls through to the other relays exactly as for a chain that fails verification.
- **Timeout.** Each relay query has a 5-second timeout. A relay that does not respond within 5 seconds is treated as a failure for that resolution attempt.

### 3.10.5 Publishing Protocol

Identity owners publish to relays on every key event they append:

```
On appending a key event to the log:
1. Build the relay payload (09 §9.6.1): the chain from the inception event
   to the new head, split into contiguous segments each fitting one frame
   (09 §9.7.4.2 R9).
2. Wrap (identifier, value) in a key-event record frame (§9.10.12) per
   segment; the publisher signs no frame (§9.10.12).
3. PUBLISH the frames to the identity's own relays and to the community
   relays of the fallback set (§18.5.1) via the existing PUBLISH operation,
   blob_ttl: 604800, one frame per segment and the segments in sequence
   order. A relay accepts a segment whose first event's predecessor it
   already holds (09 §9.7.4.2 R9), so a publisher that sent segment 2
   before segment 1 would have segment 2 rejected; on a rejection the
   publisher re-sends from the last segment the relay acknowledged.
4. RepublishManager republishes the chain and the identity's service record
   (§3.10.13) to every one of those relays every 6 days (blob_ttl is 7 days,
   1-day margin).
```

### 3.10.6 Anti-Segmentation Invariant

**Publishing to the fallback set is a MUST, not a SHOULD**: an identity publishes its chain, and its service record, to every relay its own service record lists **and** to the community relays of the fallback set (§18.5.1, §3.10.5, §3.10.13). Resolution reads both sets, and R11's first-contact floor reads community relays alone (`09-security-model.md` §9.7.4.2 R11).

The risk the MUST forecloses: an identity that published only to relays of its own would be resolvable only by a party that already holds that identity's service record, because a first-contact reader knows no relay of that identity to query. Identities would partition into islands reachable by their existing contacts and by nobody else, and a stranger's first contact — the case §9.7.4.2 R11 governs — would fail for every identity that skipped the fallback set. The network would segment without anyone intending it.

RepublishManager publishes to both relay sets on every cycle (§3.10.5), and this section adds no mechanism of its own. A publish cycle that reached no relay in the fallback set MUST be reported to the caller as a failed publication, never as a success: an SDK that reported success would leave the controller believing its chain is resolvable by a stranger when no stranger can reach it, which is the segmentation this invariant forbids.

### 3.10.7 Version Resolution

The sequence number orders one key-event chain against its own prefixes, and it does so because an event's sequence is its predecessor's plus one (`09-security-model.md` §9.7.4.2 definitions): chain order and sequence order are one order, so among heads of one chain the highest sequence is the newest, regardless of which relay served it. A verifier rejects an event whose sequence is anything but its predecessor's plus one, which is what makes that claim true rather than assumed. The sequence decides nothing between two chains that diverge from a shared prefix, because each chain's author assigned its own sequence numbers past the fork. Two owner-signed divergent chains are the root-key-compromise or equivocation case, and a resolver settles which chain it adopts by the fork-precedence rule of the security-model spec (`09-security-model.md` §9.7.4.2 R6); that rule may adopt a chain whose head sequence is lower than the head the resolver previously held (§9.7.4.2 R12).

A stale chain is detected by comparing the served head's sequence against the accepted head's (`09-security-model.md` §9.7.4.2 R12). A relay serving a stale chain is not malicious — it simply has not received the latest publish. The next republish cycle replaces it.

When two relays return valid heads of the same chain at different sequence numbers, the higher sequence is authoritative; heads of divergent chains are settled first by the fork-precedence rule (`09-security-model.md` §9.7.4.2 R6). The resolver SHOULD update its cache and MAY re-publish the winning head to the relay that returned the stale one (protocol-level healing).

### 3.10.8 Security Analysis

Resolution over the relay network preserves every security property of §9.6.1 (self-certification) and adds the resilience a validating relay supplies:

- **Self-certification preserved.** The resolver authenticates a served record by the key-event log it carries — recompute the identifier from the inception event, verify every later event under the standing root (`09-security-model.md` §9.7.4.2 R2 and R3). Every relay is untrusted; the resolver never trusts a relay's acceptance and reads no key out of the frame. §9.6.1 properties are unchanged.
- **Relay serves a stale head of the accepted chain.** Detected by sequence comparison against the accepted head (`09-security-model.md` §9.7.4.2 R12). The resolver falls through to the identity's other relays and to the fallback set. A stale chain does not compromise security — it delays propagation of key rotations, which is bounded by the 6-day republish cycle (§3.10.5).
- **Relay unresponsive, slow, or withholding.** Resolution queries all of an identity's relay URLs and the fallback set concurrently, each relay guarded by an independent per-relay timeout (§3.10.4). A single slow, hung, or withholding relay cannot block a result obtained from a faster one, and suppression by any one relay does not prevent resolution — multi-relay publishing (§9.9.2) applies to key-event records as it does to context blobs.
- **Relay serves another identity's record.** The chain recomputes to that other identity's identifier, not to the one being resolved, so step 3b of §3.10.4 discards it. Substitution would require an inception event whose signed preimage digests to the target identifier.
- **Attacker floods junk at the identity routing ID.** The `routing_id = SHA-256("scp:did:" || identifier_bytes)` is publicly derivable, so any party can PUBLISH to it. On a **validating SCP-native relay every flood variant is inert**, and `09-security-model.md` §9.7.4.2 R9 is where each variant's outcome is stated: a frame that fails validation never enters a slot; a frame carrying events the relay already holds is an idempotent refresh; a frame carrying divergent events takes its own slot, where R9's eviction rule decides what the routing id keeps; a non-frame opaque blob is rejected once a slot exists (rule (a)) and QUERY returns only the slots (rule (c)); and pre-seeded junk is evicted the moment the first valid frame establishes a slot (rule (b)). **R9's ranking is what makes the flood inert**, and R9's own paragraph on a flood of slots states why. Presence in the QUERY window is therefore controlled by the validating relay's write rule, not by the attacker's PUBLISH volume or timing.
- **Attacker DELETEs a slot blob (an integrity vector, closed by the DELETE gate).** DELETE is an unauthenticated relay operation addressing a blob by `blob_id` (`= SHA-256(blob)`), and a key-event record is public, so an attacker can compute a genuine record's `blob_id` and issue `DELETE`. Left ungated this is an **integrity** attack and not merely an availability one: the attacker deletes the genuine record from durable storage, then PUBLISHes a captured earlier frame carrying a prefix of that chain, and a relay with nothing left in storage to compare against would store that stale prefix as the whole chain — rolling the victim's key state back to a rotated-out key. The replayed frame carries a genuine prefix, so chain verification passes it; what would otherwise reject it is the client's check of the candidate head against its accepted head (`09-security-model.md` §9.7.4.2 R12), and that is defeated on a cold-cache first resolution. Slot-exclusivity rule (d) closes it: the relay rejects a DELETE of any stored frame whose chain verifies, and the gate is storage-derived, rate-limited, and fails closed on a storage read error.

- **Suppression resilience (validating SCP-native relays).** With chain verification and per-divergent-suffix slot placement (`09-security-model.md` §9.7.4.2 R9), an attacker cannot evict the genuine record by flooding, and cannot reorder it out of a bounded QUERY window (a routing id holds at most `MAX_RETAINED_SUFFIXES` slots, and the resolver pages each slot until it holds inception through head, §3.10.2). To prevent resolution, an attacker must suppress the chain on ALL of an identity's validating relays AND on the fallback set (§18.5.1), because a resolver reads both. **On integrity:** relay misbehavior is availability-only, never integrity, *because* a set of controls hold together, each covering a distinct failure mode — the client's chain verification (`09-security-model.md` §9.6.1, §9.7.4.2 R2 and R3) rejects a **forged** record; the resolver's sequence check plus fork precedence across relays (§3.10.4, §3.10.7) rejects a **stale or replayed genuine** record on any warm-cache or multi-relay resolution; and R9's write rule, read against storage rather than against the slot index, plus the **DELETE gate (rule (d))** raise the cost of the **cold-cache DELETE-purge-then-replay rollback** on a relay that runs them. **Those two are relay-side code, so they close nothing against the relay's own operator**, who omits them: the control that covers a first contact is the client-side two-relay rule of `09-security-model.md` §9.7.4.2 R11, which makes a resolver holding no baseline read the identifier from a second relay the identity's service record does not name and return `Inconclusive{SingleSource}` when it cannot. The availability-only-never-integrity claim above is therefore scoped to a warm-cache or multi-relay resolution; on a single-relay first contact the integrity control is R11's rule and nothing on the relay. A relay that omits them (a foreign or non-validating relay) provides no integrity control of its own — integrity there rests entirely on the client-side checks.
- **Residual: foreign / non-validating relays are best-effort.** A foreign transport or a non-validating relay that accumulates multiple blobs per `routing_id` can be flooded, and its bounded QUERY window can be made to omit the genuine record. Resolution over such storage alone is therefore best-effort for suppression; the resolver still recovers the genuine record via any validating relay or via multi-relay publishing (§9.9.2), and its chain verification (§3.10.4) discards the junk. What foreign/non-validating storage contributes is availability, not anti-suppression.

### 3.10.9 Privacy Properties

| Relay set | What the relay operator learns |
|-----------|-------------------------------|
| The identity's own relays | The resolver's IP address queried a specific `routing_id`. The operator can infer which identity is being resolved for any identity it already knows, because it computes the same `SHA-256("scp:did:" \|\| identifier_bytes)`. It already sees that identity's message traffic. |
| The fallback set (§18.5.1) | The resolver's IP address queried a specific `routing_id`. A community relay that stores no chain of its own learns the routing ID and nothing else about the identity. |

A resolution discloses to the identity's own relay operator nothing that operator did not already have, because that operator already carries the identity's message traffic (§9.9.1). R11's floor sends a first contact's two queries to community relays under distinct declared operators, so no single operator observes a whole first contact. A resolver that requires IP anonymity uses a VPN or Tor at the transport layer (§9.10.11).

Caching policy from §9.10.7 applies to every relay query: 24-hour refresh for active contacts, 7-day for inactive.

### 3.10.10 DidResolver Trait

The SDK exposes the resolution interface. Resolution yields key state, so the resolved type names key state and no document:

```rust
/// Key-state resolution across the SCP relay network.
/// Implements the parallel multi-relay resolution protocol (§3.10.4).
pub trait DidResolver: Send + Sync {
    fn resolve(&self, did: &str)
        -> impl Future<Output = Result<Option<ResolvedKeyState>, IdentityError>> + Send;
}

/// A resolved key state with provenance metadata.
pub struct ResolvedKeyState {
    /// The key state the adopted chain's latest state-carrying event
    /// carries (`09-security-model.md` §9.7.4.2 R8).
    pub key_state: KeyState,
    /// Sequence of the adopted chain's head. It increases along one chain
    /// and MAY decrease when fork precedence adopts a lower-sequence winner
    /// (`09-security-model.md` §9.7.4.2 R12, `Adopted{baseline_decreased}`).
    pub seq: u64,
    /// Which relays served the chain this key state derives from.
    pub source: ResolutionSource,
}

/// Provenance of a resolved key state.
pub enum ResolutionSource {
    /// Chain served by one relay, against a baseline the resolver already
    /// held. A first contact never returns this variant
    /// (`09-security-model.md` §9.7.4.2 R11).
    SingleRelay { relay_url: String },
    /// Chain served by two relays satisfying R11's first-contact floor.
    TwoRelays { relay_urls: [String; 2] },
    /// Served from local cache (the relays that served it recorded at cache time).
    Cache,
}
```

`DidResolver` queries the identity's own relays and the fallback set in parallel and settles the chains they serve under §3.10.4. A first contact below R11's floor returns `Inconclusive{SingleSource}` rather than a key state.

### 3.10.11 Bootstrap and Network Growth

The relay network is designed to be self-reinforcing as it grows:

- **Day one.** Few relays exist, so an identity publishes its chain to the community relay list of §18.5.1 and lists no relay of its own. A first contact reads two entries of that list under distinct declared operators, which is R11's floor.
- **Growth.** More relays come online and more identities publish their chains to relays of their own alongside the community relay list. A resolution reaches an identity relay first and a bootstrap relay second, so the fallback set carries less of the load.
- **Maturity.** Most identities list several relays of their own, so a resolver holding a baseline reaches one of them quickly. A first contact still reads community relays, whatever the identity's service record names (`09-security-model.md` §9.7.4.2 definitions), so growth changes what R11's floor costs in latency and never whether an identity can meet it.

### 3.10.12 Phase Integration

| Component | Phase | Crate | Notes |
|-----------|-------|-------|-------|
| `did_routing_id` derivation | Phase 1 patch | `scp-core` | Pure function, no dependencies. SHA-256 over the domain separator and the identifier's 32 digest bytes (`09-security-model.md` §9.7.4.2 R13). |
| Key-event record PUBLISH to relays | Phase 2 | `scp-core` | RepublishManager publishes each chain segment to the identity's own relays and the fallback set on a 6-day cycle (§3.10.5). |
| Key-event record QUERY from relays | Phase 2 | `scp-core` | Parallel QUERY across the identity's own relays and the fallback set (§3.10.4). |
| `DidResolver` trait | Phase 2 | `scp-core` | The resolution interface over the relay network (§3.10.10). |
| Multi-relay resolution | Phase 2 | `scp-core` | Orchestration of the parallel queries and their settlement under §3.10.4, including the two-relay rule of `09-security-model.md` §9.7.4.2 R11. |
| Key-event record relay frame (§9.10.12) | Phase 2 (#482) | `scp-protocol` | Deterministic binary encode/decode of the minimal fixed-layout key-event record frame (`KeyEventRecordV2`). Pure sync wasm-compatible type; consumed by the relay publisher + key-state resolver in `scp-identity` and by the relay-side validation path. |

### 3.10.13 The Service Record

**This section is the one home of the service record.** Every other section of this spec and of `09-security-model.md` cites it and restates none of it.

An identity's key-event log carries key material, each key's condition, the witness set and its cosigning parameters, the delegator, and the designation of the operational key that signs the service record (`09-security-model.md` §9.7.4.2 definitions). It carries no transport metadata and no service metadata. **The service record is the second owner-signed resolvable, and it carries every transport and service field the identity publishes**, and ADR-063, the inception-derived key-event-log identity substrate, splits the two records apart so that a controller re-points a relay without warming a root key.

**What the record carries.** `SCPRelay` entries — the identity's transport-layer relay URLs, where `TransportManager` routes encrypted blobs for it and where a resolver reads its key-event log (§3.10.1). `IdentityPrivateState` entries — the relays that store the identity's encrypted private-state blobs (§3.7). `SCPBroadcastContext` entries — the identity's own broadcast-context advertisements. The identity's self-asserted capability URIs. The `ParticipationStatements` pointer to context-hosted participation statements, and the `AttestationRevocations` pointer to attestation revocation status (§3.5.3). **The record carries no key, no key condition, and no witness parameter**: a root signature covers each of those in the key-event log, and a reader that found one here would be reading key state from a key weaker than the root.

**The record's bytes.** A service record is `(identifier, sequence, entries)`. Its signature preimage is `SHA-256("SCP-SERVICE-RECORD-V1:" || identifier || sequence || entries)` under the `09-security-model.md` §9.5.1 construction: the 32-byte identifier raw, `sequence` as an 8-byte big-endian `u64`, and `entries` under §9.5.1's repeated-field rule — a 4-byte big-endian entry count, then each entry in list order. `09-security-model.md` §9.18.2 registers the separator, and `09-security-model.md` §9.7.1 classifies the record in the attestation class, whose role for this structure is the service-key designation.

**Where the record lives.** A service record is addressed at its own routing derivation, `svc_routing_id = SHA-256("scp:svc:" || identifier_bytes)` over the identifier's 32 raw digest bytes, registered in `09-security-model.md` §9.18.2. That address is distinct from the key-event record's `SHA-256("scp:did:" || identifier_bytes)` (`09-security-model.md` §9.7.4.2 R13), so one QUERY returns records of one kind and neither is ever decoded as the other.

**Who signs it.** The record carries an Ed25519 signature by the operational key the identity's latest state-carrying key event designates for the service-record role, never by a root member. `09-security-model.md` §9.7.4.2 R3 rejects a state-carrying event whose designation names a key that same event does not list `current`, so the designated key is always a key the current key state lists. A reader verifies in two steps and never one: it verifies the key-event log under `09-security-model.md` §9.7.4.2 R2 and R3, reads the designation out of the verified chain, then verifies the record's signature against the designated key (`09-security-model.md` §9.6.3). **A reader holding no accepted service record for the identity applies R11's first-contact floor to the record** (`09-security-model.md` §9.7.4.2 R11) and returns `Inconclusive{SingleSource}` where it cannot meet it: a single relay can serve a genuine record truncated to an older sequence exactly as it can serve a truncated chain, and such a reader holds no high-water mark to compare against.

**How a reader settles two copies: last writer wins on the record's own sequence.** The record carries a monotonic sequence of its own, unrelated to the key-event log's sequence. The sequence is a `u64`, and **a reader rejects a record whose sequence is the maximum representable value**, so no writer can exhaust the space by writing one. **The high-water mark is keyed to the pair (identifier, the 32 public-key bytes the designation resolved to in the key state the reader adopted)** — never to the identifier alone, and never to the role name, which is `#active` for the life of every identity and would therefore reset the mark never. Among copies whose signature verifies under the currently designated key, a reader takes the highest sequence, and it rejects a copy at a sequence lower than the highest it has already accepted **under those same key bytes**. **The mark resets when the key state lists different bytes `current` in the designated role**, so a routine rotation resets it (§3.2.1 case 1) and the reader accepts the first record the new key signs at any sequence. The reset is sound because the key state that lists those bytes is root-signed (`09-security-model.md` §9.7.4.2 R3) and the old key's holder cannot produce one; a mark scoped to the identifier alone would let one record written at a high sequence by a briefly-held key block the controller's own recovery record forever. Plain sequence ordering is complete here, and the fork-precedence rule of `09-security-model.md` §9.7.4.2 R6 does not apply and MUST NOT be applied: a service record has no reveal-authorized event class, so no legitimate update ever lowers the sequence, and two signature-valid records at one sequence are the designated key's holder equivocating rather than a recovery superseding a fork. A reader that holds two such records rejects both and reports the identity's transport metadata as unresolved. **A reader holding a `Contested` verdict for the identity (`09-security-model.md` §9.7.4.2 R7) accepts no new service record for it**, because a contested identity has no adopted key state and therefore no authorized designation. **It keeps routing on the last record it accepted before it observed any event of a divergent suffix, and only while that record's designated key is `current` in the shared prefix's key state.** Where no record it holds meets both conditions, the reader routes on nothing and surfaces the identity as contested with unverified routing, which is visible and recoverable; where one does, it keeps routing on that record with the caching bound below suspended for that identity, and surfaces the identity as contested. Freezing on a record the divergence's author wrote would hand routing to whichever claimant published last before the reader noticed, and reporting every contested identity unroutable would let any party that contests an identity cut its transport.

**TTL and staleness.** A service record is stored as a relay blob under the shared `blob_ttl`, bounded by `Max blob TTL` = 604800s / 7d (`09-security-model.md` §9.18.11), and the controller republishes it on the same 6-day cycle as its chain (§3.10.5). A reader's own cached copy expires under the §9.10.7 caching policy — 24 hours for an active contact, 7 days for an inactive one — and **a reader MUST NOT route to a relay URL from a cached copy past that bound**: it re-resolves, and where it cannot it reports the identity as unroutable rather than routing on metadata it cannot refresh. A stale service record loses an identity its reachability and costs it none of its key state, because key state comes from the log. **The one exception to the routing bound is a `Contested` identity**, for which this bound is suspended and the reader keeps routing on the last record it accepted (the settlement paragraph above).

**What changing it costs, and what it does not.** A relay-endpoint change, a private-state relocation, and a capability-URI edit are each one service-record write signed by the designated operational key. Each appends no key event, requires no root signature, changes no identifier, and changes no key state. This is the property the split exists to deliver: the root set stays cold across every change to an identity's transport configuration.

**What an attacker holding the designated key can and cannot do.** It can substitute the relay list, so it can re-point traffic. **It cannot empty the fallback set of the two readers that would matter**: a first-contact resolver holds no accepted service record, so `09-security-model.md` §9.7.4.2's definitions give it the whole community relay list, and R10's ceremony floor excludes nothing the record names either. Re-pointing is fail-closed rather than a substitution of identity, because MLS group keys and not relay reachability enforce membership (`10-infrastructure-and-self-hosting.md` §10.5, encryption-as-access-control). **Which degrees do fail closed is a property of the shipped community relay list and not of any record**: a list carrying fewer than two entries under distinct declared operators fails R11's floor, and every first contact then returns `Inconclusive{SingleSource}`. The attacker cannot change a key, a key's condition, the witness set, or the designation itself, because a root signature covers each of those. **The controller's recovery is a key event designating a fresh service key, followed by a service record under it** (`09-security-model.md` §9.12), and it works at every reader because the new key's bytes reset the high-water mark. **Under a `Contested` verdict that recovery does not run**: a contested identity has no adopted key state, so a reader accepts no designation from either suffix, and an identity whose designated key was taken alongside its root has no routing recovery until the contest resolves.

**What the witness layer covers.** The service record inherits both owner-signed guarantees the key-event log carries: the owner-signed monotonic sequence and first-contact floor above, and the cosigned-head coverage `09-security-model.md` §9.7.4.3 enumerates. Meanwhile a service record's freshness rests on its signature, its sequence, the floor above, and the caching bound above, and on nothing else.


## 3.11 DID Authentication for External Services (SCPID)

SCP identities can authenticate to services outside the protocol. A relying party — SCP-native or not — can verify that a request comes from the holder of a specific DID without joining a context, understanding MLS, or running SCP infrastructure. The only requirement is the ability to resolve an SCP identity's key-event log from an SCP relay and verify an Ed25519 signature.

This is analogous to "Sign in with Ethereum" (EIP-4361) but simpler: no blockchain state, no gas, no wallet abstraction. The identity's key-event log is the identity provider, self-certifying because the identifier is the digest of its inception event (`09-security-model.md` §9.6.1).

**Relationship to existing DID-auth patterns.** SCP already uses DID-signed requests internally for context reader authentication (§6.2.2B) and handle outlet requests (§22.3.1). SCPID extracts and generalizes this pattern into a standalone protocol that external services can implement without SCP SDK dependencies.

### 3.11.1 Protocol Overview

```
Client (DID holder)                    Relying Party (service)
       |                                       |
       |  1. GET /auth/challenge                |
       | ------------------------------------>  |
       |                                       |
       |  2. { nonce, audience, expires_at }    |
       | <------------------------------------  |
       |                                       |
       |  3. Sign challenge with #active        |
       |                                       |
       |  4. POST /auth/verify                  |
       |     { did, signing_key_id, signature, ts }     |
       | ------------------------------------>  |
       |                                       |
       |  5. Resolve DID -> verify signature     |
       |                                       |
       |  6. { authenticated: true, did }       |
       | <------------------------------------  |
       |                                       |
```

The protocol is stateless from the client's perspective. The relying party issues a challenge, the client signs it, and the relying party verifies the signature against the public key the identity's current key state lists in the named role. No session state is established at the protocol level — session management (cookies, tokens, etc.) is the relying party's concern.

### 3.11.2 Challenge Format

The relying party generates a challenge:

```
ScpIdChallenge {
    protocol:   String,      // "scpid/1.0" — MUST reject unrecognized versions
    nonce:      [u8; 32],    // 32 bytes, CSPRNG-generated
    audience:   String,      // URI identifying the relying party (e.g., "https://app.example.com")
    issued_at:  u64,         // Unix timestamp (ms) when the challenge was created
    expires_at: u64,         // Unix timestamp (ms) when the challenge expires
}
```

**Field constraints:**

| Field | Constraint | Rationale |
|-------|-----------|-----------|
| `nonce` | 32 bytes, CSPRNG | Replay prevention. Must be unique per challenge. |
| `audience` | URI, max 2048 bytes UTF-8 | Audience binding. Prevents signature reuse across services. |
| `issued_at` | Unix ms, must be <= current time | Prevents pre-dated challenges. |
| `expires_at` | Unix ms, must be > `issued_at`, MUST NOT exceed 300 seconds (5 minutes) | Short-lived to minimize replay window. |

**Wire format.** Challenges are serialized as JSON for transport. The relying party chooses the transport (HTTP, WebSocket, QR code, etc.) — the protocol does not mandate a specific transport.

### 3.11.3 Response Format

The client constructs and signs the response:

```
ScpIdResponse {
    protocol:       String,   // "scpid/1.0" — MUST reject unrecognized versions
    did:            DID,      // The signer's DID
    signing_key_id: String,   // Verification method ID: "#active"
    nonce:          [u8; 32], // Echo of the challenge nonce
    audience:       String,   // Echo of the challenge audience
    signed_at:      u64,      // Unix timestamp (ms) when the client signed
    signature:      [u8; 64], // Ed25519 signature over the signed content
}
```

**Signed content construction:**

The signed content follows the §9.5.1 canonical hash construction: SHA-256 of domain-separated, length-prefixed fields. The Ed25519 signature is over the 32-byte hash, not the raw concatenation.

```
signed_bytes = SHA-256(
    "SCP-DID-AUTH-V1:"
    || BE32(len(did))              || did              // signer's DID, UTF-8
    || BE32(len(signing_key_id))   || signing_key_id   // "#active", UTF-8
    || nonce                                            // 32 bytes, fixed (no length prefix per §9.5.1)
    || BE32(len(audience))         || audience          // audience URI, UTF-8
    || signed_at as u64 BE                              // 8 bytes, big-endian
)
signature = Ed25519_sign(private_key, signed_bytes)
```

**SCPID signed content field order:**

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `did` | 4-byte BE length prefix + UTF-8 bytes |
| 2 | `signing_key_id` | 4-byte BE length prefix + UTF-8 bytes |
| 3 | `nonce` | 32 bytes raw (fixed-length, no prefix per §9.5.1) |
| 4 | `audience` | 4-byte BE length prefix + UTF-8 bytes |
| 5 | `signed_at` | 8-byte big-endian u64 |

The domain separator `"SCP-DID-AUTH-V1:"` prevents cross-protocol signature reuse. The SHA-256 wrap aligns with the majority SCP signing pattern (InnerEnvelope, BroadcastEnvelope, sender keys, access keys, sync structures, claims). The `did` and `signing_key_id` fields bind the signature to the signer's identity and to the verification method that produced it, so a relying party cannot be shown a signature transplanted from another identity or presented under a method that did not sign.

**Signing key and signing identity:**

- `#active` — the identity's one operational signing key (`09-security-model.md` §9.7.4.2 definitions). A human identity signs an SCPID response under it, and the custody substrate holding it supplies whatever local gate it offers, such as a biometric prompt.
- A delegated agent identity signs its own SCPID responses under its own `#active`. A relying party tells an agent from a human by the responding identity and not by a verification-method fragment, because a delegated identity's key state names the delegator that anchors it (`09-security-model.md` §9.7.4.2 definitions). ADR-064, the forthcoming specification of the cooperative-delegation events, states how a verifier checks that anchor; until ADR-064 lands a verifier rejects a chain that claims delegation, so no delegated agent identity resolves.

### 3.11.4 Verification Procedure

The relying party verifies a response:

```
1. Parse the ScpIdResponse.
2. Check nonce matches the issued challenge's nonce. Reject if mismatched.
   Consume the nonce (single-use). Reject replays.
3. Check audience matches the issued challenge's audience URI.
   Audience comparison MUST be exact byte-for-byte string comparison,
   not URI normalization.
4. Check the challenge has not expired: current_time <= expires_at.
   Check signed_at is within the challenge's [issued_at, expires_at] window.
5. Resolve the identity's key state:
   a. QUERY the identity's routing ID on SCP relays (§3.10.4).
   b. Recompute the identifier from the served chain's inception event and
      verify every event of the chain (§9.6.1); derive the key state from
      the chain's latest state-carrying event (`09-security-model.md`
      §9.7.4.2 R8). Resolution yields key state; it produces no DID
      document (`09-security-model.md` §9.6.1).
   c. Cache policy: the key state MUST be fresh — resolved within the last
      300 seconds. A stale key state MUST trigger a fresh resolution.
6. Read the public key the key state lists `current` in the role
   signing_key_id names.
7. Confirm signing_key_id is "#active". Reject any other value
   with KEY_NOT_AUTHORIZED. A human identity's key state names one
   operational role (`09-security-model.md` §9.1 invariant 1), so
   "#active" is the only role a relying party accepts here.
8. Confirm the key state lists that key `current` and not in any of the
   three conditions of `09-security-model.md` §9.7.1 that are not
   `current`. Reject if not.
9. Reconstruct signed_bytes from did, signing_key_id, nonce, audience,
   signed_at per §3.11.3 (SHA-256 of canonical concatenation).
10. Verify the Ed25519 (PureEdDSA, RFC 8032 §5.1.6) signature over
    signed_bytes using the extracted public key.
11. If all checks pass: the request is authenticated as originating from
    the holder of the DID's signing_key_id verification method.
```

**Error responses.** The relying party SHOULD return structured errors:

| Condition | Error | Code |
|-----------|-------|------|
| Nonce unknown, mismatched, or expired | `CHALLENGE_EXPIRED` | `SCP-IDENT-1030` |
| Audience mismatch | `AUDIENCE_MISMATCH` | `SCP-IDENT-1031` |
| `signed_at` outside challenge window or challenge expired | `TIMESTAMP_INVALID` | `SCP-IDENT-1032` |
| DID resolution failed | `DID_RESOLUTION_FAILED` | `SCP-IDENT-1033` |
| `signing_key_id` not `#active` or not in `authentication` | `KEY_NOT_AUTHORIZED` | `SCP-IDENT-1034` |
| Signature verification failed | `SIGNATURE_INVALID` | `SCP-IDENT-1035` |
| Key state stale (> 300s, refresh failed) | `KEY_STATE_STALE` | `SCP-IDENT-1036` |
| Key custody or signing operation failed | `SIGNING_FAILED` | `SCP-IDENT-1037` |
| Input validation failure | `INVALID_INPUT` | `SCP-IDENT-1038` |

**Error response guidance.** Relying parties SHOULD NOT return specific error codes to untrusted clients. Return a generic failure (e.g., HTTP 401 with `"authentication_failed"`) for all verification failures. Specific `SCP-IDENT-103x` codes are for server-side logging and debugging only. Exposing which step failed provides a verification oracle that helps attackers enumerate valid DIDs and probe key configurations.

### 3.11.5 Wire Format

**Challenge (JSON, served by relying party):**

```json
{
  "protocol": "scpid/1.0",
  "nonce": "<64 hex chars>",
  "audience": "https://app.example.com",
  "issued_at": 1741910400000,
  "expires_at": 1741910700000
}
```

**Response (JSON, sent by client):**

```json
{
  "protocol": "scpid/1.0",
  "did": "<the signer's identifier in its canonical string form, §3.8.1>",
  "signing_key_id": "#active",
  "nonce": "<64 hex chars>",
  "audience": "https://app.example.com",
  "signed_at": 1741910405000,
  "signature": "<128 hex chars>"
}
```

The `protocol` field identifies the authentication scheme and version. Relying parties MUST reject responses with unrecognized protocol versions. Version negotiation is outside scope — clients and relying parties agree on protocol version out-of-band (e.g., the challenge's `protocol` field declares what the relying party accepts).

**Protocol version binding.** The `V1` suffix in the domain separator `SCP-DID-AUTH-V1:` is the cryptographic binding for the protocol version. A new protocol version MUST use a new domain separator (e.g., `SCP-DID-AUTH-V2:`). The `protocol` field in the wire format is for human readability and version negotiation; it is not a security control — it is not included in the signed content.

### 3.11.6 Security Properties

**Replay prevention.** The nonce is single-use. The relying party MUST track issued nonces and reject any nonce presented more than once. Nonce storage can be pruned after `expires_at` — expired challenges are rejected regardless of nonce state. For distributed relying parties (multiple server instances behind a load balancer), nonce storage MUST use a strongly-consistent data store (e.g., Redis with NX-SET, database with unique constraint). Eventually-consistent stores risk double-acceptance. Alternatively, bind the challenge to a specific server instance using HMAC: `nonce = HMAC-SHA-256(server_secret, random_bytes || issued_at)`, verified without shared state. In this case, the relying party reconstructs the `ScpIdChallenge` from the HMAC nonce and stored parameters before passing it to `scpid_verify`.

**Audience binding.** The `audience` field is included in the signed content. A signature produced for `https://app-a.example.com` does not verify for `https://app-b.example.com`. This prevents cross-service signature relay attacks where an attacker presents a legitimate signature obtained from one service to another. Audience comparison MUST be exact byte-for-byte string comparison, not URI normalization. The relying party MUST publish its canonical audience URI and the client MUST use it verbatim. This matches the OIDC `aud` claim comparison model.

**Timestamp freshness.** The `signed_at` timestamp must fall within the challenge's validity window (`issued_at` <= `signed_at` <= `expires_at`). This bounds the useful lifetime of a stolen challenge to the challenge's expiry window.

**No bearer tokens.** The protocol does not produce a bearer token. Each authentication is a fresh challenge-response cycle. Session management (issuing a JWT, setting a cookie, etc.) is the relying party's responsibility and is explicitly outside this protocol's scope. This means a compromised session token does not compromise the DID — re-authentication requires the private key.

**Key compromise recovery.** If `#active` is compromised, the standing root signs a `KeyState` (`09-security-model.md` §9.7.4.2 R3) that lists a new `#active` `current` and the old key `Compromised{from: N}` (§9.12). After rotation the old key is no longer `current`, so verification step 7 rejects its signatures, and content it signed is accepted only under §9.7.1's boundary rule. Recovery latency is bounded by key-event-log propagation to the identity's relays and by the 5-minute resolution-freshness bound of §9.7.1 check 2.

**MITM resistance.** SCPID does not provide channel binding. If the transport between client and relying party is compromised (no TLS), an attacker can intercept and replay the challenge-response in real time. Relying parties MUST serve challenges and accept responses over TLS. The audience field mitigates relay attacks across services but does not replace transport-layer encryption.

**Agent vs. human distinction.** The responding identity tells the relying party whether a human or an agent signed the challenge: a human identity signs under its own `#active`, and an agent signs under the `#active` of its own delegated identity, whose key state names the human that anchors it (`09-security-model.md` §9.7.4.2 definitions). The `did` field is inside the signed content (§3.11.3), so the distinction is cryptographically authenticated. The relying party can enforce authorization policies on it — requiring a human identity for destructive operations and accepting a delegated agent identity for routine API access.

### 3.11.7 Relationship to Context Membership

SCPID and context membership are independent authentication mechanisms for different purposes:

| | SCPID | Context membership |
|---|---|---|
| **Proves** | Control of a DID's signing key | Membership in an MLS group |
| **Scope** | Per-request, stateless | Persistent, epoch-based |
| **Use case** | HTTP APIs, webhooks, external services | Protocol operations within a context |
| **Requires SCP SDK** | No (only DID resolution + Ed25519) | Yes (MLS, key packages, group state) |
| **Session state** | None (relying party's concern) | MLS epoch (protocol-managed) |

An SCP-native app will typically use **context membership** for protocol operations (messaging, governance, outlet invocation) and **SCPID** for HTTP API endpoints (REST APIs, webhooks, OAuth callbacks) that need to authenticate requests from DID holders outside the MLS channel.

### 3.11.8 SDK API Surface

The SDK provides functions for all three protocol roles. SCPID operations use `ScpIdError` rather than `IdentityError` to keep protocol-level authentication errors separate from identity-layer concerns (DID resolution, key management). This avoids polluting `scp-identity`'s error type with SCPID-specific variants.

**Challenge generation (relying party):**

```rust
/// Generate an SCPID challenge for the given audience.
///
/// Generates a 32-byte CSPRNG nonce, sets issued_at to the current time,
/// and computes expires_at from the TTL. TTL MUST NOT exceed 300 seconds.
pub fn scpid_challenge(
    audience: &str,
    ttl: Duration,
) -> Result<ScpIdChallenge, ScpIdError>;
```

**Challenge signing (client):**

```rust
/// Sign an SCPID challenge using the specified verification method.
///
/// Constructs signed_bytes per §3.11.3 (SHA-256 of canonical concatenation
/// including did and signing_key_id), signs with Ed25519, returns the response.
pub async fn scpid_sign(
    custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    did: &str,
    signing_key_id: SigningKeyId,  // Active or Agent (from scp-identity)
    challenge: &ScpIdChallenge,
) -> Result<ScpIdResponse, ScpIdError>;
```

**Response verification (relying party):**

```rust
/// Verify an SCPID response against the original challenge.
///
/// Performs the full 11-step verification procedure (§3.11.4): nonce match,
/// audience match, timestamp window, DID resolution, key extraction,
/// signing_key_id constraint, authentication relationship check,
/// signed_bytes reconstruction, Ed25519 signature verification.
///
/// The caller MUST ensure the challenge has not been previously consumed
/// (single-use enforcement). The function checks the response against the
/// challenge but does not track cross-request nonce state.
pub async fn scpid_verify(
    resolver: &dyn DidResolver,
    response: &ScpIdResponse,
    challenge: &ScpIdChallenge,
) -> Result<ScpIdAuthentication, ScpIdError>;

pub struct ScpIdAuthentication {
    pub did: String,
    pub signing_key_id: SigningKeyId,
    pub signed_at: u64,
}
```

**Non-SCP relying parties** can implement verification without the SCP SDK. The only dependencies are:
1. An SCP relay QUERY client and the key-event-log verification of §9.6.1 (recompute the identifier, verify every event).
2. SHA-256 (standard, available everywhere).
3. An Ed25519 signature verifier (PureEdDSA per RFC 8032 §5.1.6).
4. JSON parsing.

This is intentional. SCPID is designed to be implementable by services that have no other relationship with SCP.

### 3.11.9 Implementation Notes for Non-SCP Relying Parties

A service that wants to accept SCP DID authentication without running SCP software:

1. **Key-state resolution.** QUERY the identity's routing ID, `SHA-256("scp:did:" || identifier_bytes)`, on the SCP relays the identity's service record lists (§3.10.13) and on the community relays of §18.5.1; each stored blob is a key-event record frame (§9.10.12) whose `value` carries a segment of the identity's key-event log. Assemble the chain, recompute the identifier from its inception event, verify every event, and derive the key state from the latest state-carrying event (§9.6.1). A relying party that holds no prior chain for the identity reads two relays under distinct declared operators, one of them in the fallback set (`09-security-model.md` §9.7.4.2 R11). For SCPID verification, a resolved key state MUST be cached for no more than 300 seconds. The general §3.10.4 caching policy (24h/7d) does NOT apply to SCPID verification — authentication requires current key state.

2. **Reading the key from the key state.** The key state lists every operational key by role and every key the chain ever installed with its condition (`09-security-model.md` §9.7.4.2 definitions). Match `signing_key_id` to the role the key state names, confirm the key state lists that key `current`, and read its raw 32-byte Ed25519 public key. A relying party parses no DID document and needs none: ADR-063 defers the `did:scp` facade and this protocol publishes no W3C DID Core JSON for an identity.

3. **Signature verification.** Reconstruct `signed_bytes` per §3.11.3: concatenate the domain separator `"SCP-DID-AUTH-V1:"`, length-prefixed `did`, length-prefixed `signing_key_id`, raw 32-byte `nonce`, length-prefixed `audience`, and 8-byte big-endian `signed_at`. Compute SHA-256 of the concatenation. Verify the Ed25519 signature (PureEdDSA, RFC 8032 §5.1.6) over the resulting 32-byte hash. Standard libraries: `ring`, `ed25519-dalek` (Rust), `tweetnacl` (JS), `pynacl` (Python), `Crypto.Sign` (Swift).

4. **Nonce management.** Store issued nonces with their `expires_at`. Reject duplicates. Prune expired entries. For distributed deployments, use a strongly-consistent store or HMAC-based nonce generation (§3.11.6).

No SCP SDK, no MLS, and no context management. The verification path is: two relay QUERYs, the chain verification of §9.6.1, one JSON parse, one SHA-256, and one Ed25519 verify.
