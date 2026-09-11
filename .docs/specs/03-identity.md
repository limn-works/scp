# 3. Identity

## 3.1 Root of Identity

An identity's identifier is the digest of its inception event's signed preimage, and it encodes no key (`09-security-model.md` §9.7.4.2 R13). It is not a username, not an email, and not an account on someone's server.

The identifier never changes. A root change installs a fresh root set under the same identifier, so a relying party re-verifies key continuity against that set rather than reading a rename (`09-security-model.md` §9.11).

The identity publishes no W3C Decentralized Identifiers document. Key material and each key's condition live in the key-event log, and transport and service metadata live in the service record (`18-addressability-and-deployment.md` §18.2.2A, §3.10.13).

## 3.2 Key Custody

A key's custody type names the substrate that holds its private half, and `09-security-model.md` §9.7.4.1 item 4 states which custody types the SDK may offer for a pre-rotation key on each custody profile. `SecureEnclave` and `AndroidKeystore` conform on no profile, because the operational key sits in that same keystore under that same application principal. `EncryptedOfflineBackup`, `ShamirShares` and `PaperBackup` conform on the `Headless` profile alone, because each yields key bytes a holder can copy. A passkey is the default pre-rotation substrate on every other profile.

The identifier does not depend on custody, because it is the inception event's digest and encodes no key (`09-security-model.md` §9.7.4.2 R13). A controller therefore moves its operational signing capability from one substrate to another under the key custody migration protocol (§3.2.1), and every relying party keeps resolving the same identifier.

### 3.2.1 Key Custody Migration Protocol

Custody migration moves the operational signing capability from one custody provider to another — a passkey to a FIDO2 token, a secure element to a self-managed key — and the identifier does not change, because the identifier is the inception event's digest and encodes no key (`09-security-model.md` §9.7.4.2 R13). An operational-key custody migration leaves the root set unchanged; case 2 below is the one case in which the root itself changes.

**Case 1, Active Signing Key migration.** The controller generates a new key in the target custody provider, and the standing root signs a `KeyState` whose key list carries the new key `current` in the `#active` role and does not carry the replaced key at all (`09-security-model.md` §9.7.4.2 R3 for the kind and its signatures, and that section's definitions for what a key list names). A verifier reads the replaced key's condition by replaying the log: `Superseded` where a successor took the role, `Retired` where none did (`09-security-model.md` §9.7.4.2 R8). A `KeyState` names no key it does not list `current`, so it records no `Compromised` entry, and a `RootRecovery` is the one event that names a key `Compromised{from: N}`. A peer that observes the `KeyState` sets no standing against the identifier, because `09-security-model.md` §9.11 reserves `PendingReverify` for an observed `RootRecovery` and for a `Contested` verdict. A routine operational rotation is therefore transparent to peers.

**Case 2, root key change.** The root changes by a `RootRecovery`: a threshold-satisficing subset of the next set authorizes the event, a fresh root set generated under that recovery's device boundary is installed (`09-security-model.md` §9.7.4.2 R3 and R10), and the identifier does not change. Relying parties re-verify key continuity against the fresh root set (`09-security-model.md` §9.11). A planned root move that follows no compromise — a custody substrate decommissioned while its key stays unexportable — is the same event: a `RootRecovery{CoSigns}` whose key-state snapshot marks nothing compromised. Alec ruled on 2026-09-06 that the planned move is the same event as a recovery, and he gave the reason: an attacker would use a separate benign kind too, so peers could not trust the distinction.

**The migration protocol runs five ordered steps.**

1. **Initiate on the target device.** Generate the new keypair in the target custody provider and record the key's algorithm and its custody type, both of which `09-security-model.md` §9.7.4.2's definitions fix. The custody type is a declaration the requesting device wrote, and every consumer reads it as `Software` until a platform proof verifies (`27-attestations.md` §27.4.4), so no step below reads it as a hardware rating.
2. **Authorize on a device holding a threshold of the standing root.** Compose the `KeyState` carrying the complete key state and sign it with a root signature by the standing root set (`09-security-model.md` §9.7.4.2 R3 and R8).
3. **Publish, re-sign, and reissue.** Publish the extended key-event log to the identity's own relays and to the fallback set (§3.10.5). Re-sign the service record under the new key and republish it (§3.10.13): the rotation resets every reader's high-water mark for that record, and every copy the replaced key signed stops verifying the moment a reader adopts the `KeyState` of step 2. Issue MLS Update proposals in every active context (§9.7.3). Revoke every UCAN the replaced key signed and reissue under the new one.
4. **Re-sign the attestation chain.** Every identity attestation the replaced key signed is re-signed under the new key and republished (§3.5), which the SDK does as one transaction with the steps above.
5. **Destroy the replaced key material** after confirmed publication, which `09-security-model.md` §9.7.4.2 R10 defines as durable self-retention together with acceptance by at least one relay in the fallback set. A controller that destroyed on a local signature alone would leave every party that never received the event resolving the replaced key as `current`, and the identity could then sign nothing that party accepts.

**A context that watched no retirement holds no boundary.** A context whose log records no retirement Commit for the replaced `#active` holds no boundary for that key, and a member verifying content signed by that key in that context returns `ContentVerdict::Invalid{no_boundary}` (`09-security-model.md` §9.7.1 for the content rule, §9.7.4.2 R14 for the verdict type). Step 3's Updates are what create the boundary, and `09-security-model.md` §9.7.4.2 R4 admits a context the controller cannot reach.

**Invariant.** At no point during migration are there zero valid signing keys for the identity, and at no point is the service record left signed by a key no reader will accept, because step 3 republishes it under the new key before step 5 destroys the replaced one. A peer that adopted the `KeyState` before step 3's Update reaches one of its contexts waits out `LEAF_REPLACEMENT_GRACE` before it proposes Remove for the not-yet-replaced leaf (`09-security-model.md` §9.12 step 1a, §9.18.17); without that wait the overlap would evict the migrating member from its own context.

## 3.3 Recovery

**A root changes only through a `RootRecovery`**, which carries an indexed signature group from a threshold-satisficing subset of the standing next set (`09-security-model.md` §9.7.4.2 R3 for the kind and its signature groups, R10 for the procedure the controller follows).

**The three mechanisms below help a controller reach its own credentials, and none of them authorizes a root change**, because no trusted contact and no platform account holds a member of the next set.

- **Trusted device recovery:** another device the person controls vouches for a new one. The trusted device enrolls the new device into the identity's device registry and distributes the Private State Key (PSK) via HPKE (§3.7.2), so recovery is device enrollment and runs the same cryptographic protocol.
- **Social recovery:** trusted contacts confirm the person's identity, the recovering device is enrolled as a new device (§3.7.2), and it receives the PSK from an existing enrolled device. Where no enrolled device remains, PSK recovery requires re-keying: a new PSK is generated, the private state history encrypted under the old PSK is permanently inaccessible under the forward-only property of §9.17.5, and the identity starts a fresh private state log.
- **Platform-backed recovery:** where custody sits in an Apple or Google account, that platform's recovery mechanisms apply. The PSK is stored in the platform's secure key store (Keychain, Keystore — §17.8) and may be recoverable through platform backup and restore, such as iCloud Keychain sync and Google Cloud Key Vault. That path does not depend on another SCP device being available.

**Every recovery path above ends at confirmed publication.** A recovery that re-establishes custody appends a key event, and that event takes effect at each relying party the moment that party resolves the extended chain, because no rule of `09-security-model.md` §9.7.4.2 reads a witness cosignature. The recovering device still submits the event to the identity's witness set, for a separate reason: **witnessing supplies one of the two corroboration sources `09-security-model.md` §9.7.4.2's definitions state**, and it is the portable one. The other is a peer's own read of the adopted head from two community-relay-list entries under distinct declared operators. No rule reads either, so an identity whose witnesses are silent keeps its standing and every grant at every peer. A controller that wants the portable half of that evidence back replaces a silent set with a `KeyState` naming a fresh one (`09-security-model.md` §9.7.4.2 R10), which spends no pre-rotation commitment. Every relying party sets `PendingReverify` on an observed `RootRecovery`, and the exit is the out-of-band fingerprint comparison of `09-security-model.md` §9.11.

For new users with a single device and no SCP contacts, platform-backed recovery is the practical safety net. Social and device recovery grow in value over time as users add devices and build connections. Apps should prompt for trusted recovery contacts during onboarding — the same pattern Google and Apple use today.

## 3.4 Linking Existing Identities

Existing platform identities (Google, Apple, social accounts) can be linked to a protocol identity but are never the root. They serve as convenience and interop, not as source of truth.


## 3.5 Identity Attestations

A user can publish cryptographic attestations binding their external platform identities to their identifier. These attestations are the mechanism that makes bridging trustworthy and social graph import possible.

An attestation says: "The human behind the identity `<scp-identifier:alice>` is the same human behind `@alice` on X." The attestation is verifiable — the user proves ownership of the external identity (e.g., by signing a challenge, posting a proof, or using OAuth) and the result is a signed statement linking the two.

Properties of identity attestations:

- **Non-fungible.** The attestation binds one external identity to one identifier. It cannot be transferred, forked, or shared. This is the foundation for cross-platform identity attribution.
- **User-initiated.** Only the human creates attestations for their own identities. No third party can assert a link on someone's behalf.
- **Independently verifiable.** Any participant can verify the attestation without relying on a central authority. Verification methods vary by platform (OAuth proof, signed message, DNS record, etc.).
- **Revocable.** Users can revoke attestations at any time, severing the link.
- **Discoverable.** Other SCP participants can look up whether a given external identity maps to a known identifier. Attestations are discoverable through contexts with discovery outlets (§6.2.2B [no such section]) and service-record entries (§3.5.3). Reverse-lookup, from an external handle to an identifier, is provided by the `attestation_lookup` outlet in contexts with discovery outlets (§22.5).

Identity attestations enable three critical flows:

1. **Social graph import.** A user exports their follower list from X. Their local agent resolves each handle against known attestations. Contacts who have also joined SCP are automatically discoverable.
2. **Shadow identity claiming.** When a bridge connector creates a shadow identity for an external participant (see §12), a user can claim it by presenting a matching attestation. The shadow identity merges with that user's own identifier (see §3.5.5 for the claiming protocol).
3. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.

### 3.5.0 Attestation Classes

Identity link attestations are sub-classified into two classes based on when and how the external identity ownership was verified. The class is a property of the verification method, not of the attestation envelope — the wire format (§3.5.2) is the same for both classes. The class determines the trust model: who must verify, when, and what the attestation proves on its own. See ADR-044 for the design rationale and rejected alternatives.

**Class 1: Cryptographic.** The provider's confirmation of identity ownership was cryptographically verified at attestation creation time. Verification methods: `Oauth`, `ChallengeResponse`.

- The SDK performs the verification flow (OAuth code exchange, challenge-response round trip) locally at creation time.
- On success, the SDK extracts the minimal identifying claim (`provider`, `subject_id`, `verified_at`) and signs it with the identity's `#active` key. This SDK-signed proof replaces the raw provider token — no JWT, no OIDC ID token, no PII is stored.
- The attestation proof is: `{ "provider": "<platform>", "subject_id": "<platform_user_id>", "verified_at": <unix_s> }` signed by the issuer's `#active` key. The signature is the one on the `IdentityLinkAttestation` envelope itself — the proof field carries the claim content, the envelope signature covers it.
- Self-attestation model: issuer == subject. The identity's controller asserts "I verified this at creation time." Consumers trust the assertion because: (a) the `#active` key signed it, (b) the claim is minimal (no forgery incentive beyond the link itself), and (c) falsifying the link provides no benefit — shadow claiming (§3.5.5) and social graph import (§3.6) only work if the external account is genuinely controlled.
- **No raw token storage.** The SDK MUST discard the OAuth access token, refresh token, and ID token after extracting the `subject_id`. Only the minimal signed claim persists. This eliminates PII leakage — Google OIDC tokens always include `email`, Apple tokens include `email` when requested. None of that data enters the attestation.

**Class 2: Reference.** The proof is a live external resource that consumers must verify themselves. Verification methods: `SignedPost`, `DnsRecord`.

- The user places their identifier, in the textual form `09-security-model.md` §9.7.4.2 R13 defers, in an externally-visible location: a profile bio, a DNS TXT record, or a public post.
- The attestation's `proof` field points to the resource URL or record location. No cryptographic proof of ownership exists at creation time, so the proof is the continued presence of that identifier in the external resource.
- **Zero trust until verified.** A Reference attestation carries no trust weight on its own. Consumers MUST fetch the proof URL or query the DNS record and confirm the identifier is present before granting any trust weight. An unverified Reference attestation is equivalent to no attestation.
- Verification is consumer-side, cached with a 1-hour TTL (§3.5.4). Consumers that cannot verify (offline, rate-limited, proof URL inaccessible) MUST treat the attestation as unverified.

The class distinction is critical for trust evaluation (§7.5). Class 1 attestations provide immediate trust signal once the `#active` signature verifies. Class 2 attestations provide no trust signal until the consumer independently verifies the proof — they are pointers, not proofs.

### 3.5.1 Provider Registry

The following 16 platforms are supported for identity link attestations. New providers are added by spec amendment only — the set is closed to prevent proliferation of unverifiable attestation targets.

| Platform | `platform` value | Class | Verification method | Proof location | Renewal interval |
|----------|-----------------|-------|--------------------|----|-----------------|
| GitHub | `github.com` | 2 (Reference) | `SignedPost` | Profile bio carrying the identifier | 90 days |
| X / Twitter | `x.com` | 2 (Reference) | `SignedPost` | Profile description carrying the identifier | 90 days |
| Google | `google.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Apple | `apple.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Microsoft | `microsoft.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| LinkedIn | `linkedin.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Discord | `discord.com` | 1 (Cryptographic) | `Oauth` | SDK-signed OIDC claim | 30 days |
| Reddit | `reddit.com` | 2 (Reference) | `SignedPost` | Profile bio carrying the identifier | 90 days |
| Bluesky | `bluesky.com` | 2 (Reference) | `SignedPost` | Profile description carrying the identifier | 90 days |
| Mastodon | `mastodon:<instance>` | 2 (Reference) | `SignedPost` | Profile bio carrying the identifier | 90 days |
| Telegram | `telegram.com` | 1 (Cryptographic) | `ChallengeResponse` | Bot-verified round trip | 60 days |
| npm | `npm` | 2 (Reference) | `SignedPost` | Profile page carrying the identifier | 90 days |
| PyPI | `pypi` | 2 (Reference) | `SignedPost` | Profile page carrying the identifier | 90 days |
| Steam | `steam` | 1 (Cryptographic) | `ChallengeResponse` | Bot-verified round trip | 60 days |
| .well-known | `well-known` | 2 (Reference) | `DnsRecord` | `/.well-known/scp` endpoint carrying the identifier | 180 days |
| DNS | `dns` | 2 (Reference) | `DnsRecord` | TXT record at `_scp-verify.<domain>` carrying the identifier | 180 days |

**Platform value conventions:**

- OIDC providers use their token issuer domain: `google.com`, `apple.com`, `microsoft.com`, `linkedin.com`, `discord.com`.
- Social platforms use their primary domain: `github.com`, `x.com`, `reddit.com`, `bluesky.com`, `telegram.com`.
- Mastodon instances use the `mastodon:<instance>` format (e.g., `mastodon:mastodon.social`) because the Mastodon API endpoint varies by instance. The `platform_id` field SHOULD contain the Mastodon account URI (`@user@instance`).
- Package registries use the bare registry name: `npm`, `pypi`. The `platform_handle` field contains the package author username.
- `.well-known` uses the bare string `well-known`. The `platform_handle` field contains the domain name. The proof is an HTTP GET to `https://<domain>/.well-known/scp`, which must return the identifier.
- DNS uses the bare string `dns`. The `platform_handle` field contains the domain name.

**`ChallengeResponse` verification method:** the registry above names two platforms that use it, Telegram and Steam, and the mechanism is platform-agnostic beyond them. Any verifier — a context governance engine, a bridge connector, or another participant — challenges an agent to prove a capability or an identity claim over a cryptographic round trip. The verifier chooses the `platform` value, such as the context id or its own domain, and `evidence.verifier_did` names the verifier that issued the challenge.

**`ChallengeResponse` creation flow:**
1. A verifier sends a random 32-byte challenge to the subject.
2. The subject signs the challenge with their Active Signing Key (`#active`).
3. The SDK constructs the proof: `{ "challenge": "<hex>", "response_signature": "<hex>" }`.
4. The full `IdentityLinkAttestation` envelope is signed by the subject's `#active` key.

**`ChallengeResponse` verification:** Verify `response_signature` is valid for `challenge` under the subject's `#active` key. Verify `verifier_did` is a known, trusted verifier.

**Class 1 (Cryptographic) creation flow:**

1. The SDK initiates an OAuth 2.0 authorization code flow with the OIDC provider. Minimal scope: `openid` only (no `email`, no `profile`). Apple Sign In uses the `sub` claim from the identity token.
2. On success, the SDK receives the ID token (JWT). It extracts `sub` (subject identifier) and discards the token.
3. The SDK constructs the proof content: `{ "provider": "<platform>", "subject_id": "<sub>", "verified_at": <unix_s> }`.
4. The SDK signs the full `IdentityLinkAttestation` envelope, which includes the proof content in `evidence.proof`, with the identity's `#active` key.
5. The SDK discards the access token, refresh token, and ID token. Only the signed attestation persists.

**Class 2 (Reference) creation flow:**

1. The user places their identifier, in the textual form `09-security-model.md` §9.7.4.2 R13 defers, in the platform-specific location: a profile bio or a DNS TXT record.
2. The SDK constructs the proof pointer: for `SignedPost`, `{ "post_url": "<url>", "nonce": "<random_hex>", "posted_at": <unix_s> }`; for `DnsRecord`, `{ "domain": "<domain>", "record_name": "_scp-verify" }`.
3. The SDK signs the full `IdentityLinkAttestation` envelope with the identity's `#active` key.
4. The attestation is published. It carries zero trust weight until a consumer fetches and verifies the proof.

### 3.5.2 Identity Attestation Wire Format

Identity attestations use the attestation envelope defined in §7.4.1, with identity-link-specific fields. The wire serialization is MessagePack (§17), consistent with all other SCP wire formats. The signature scope uses the §9.5.1 canonical hash construction — see "Signature scope" below.

```
 IdentityLinkAttestation {
  id:           String,          // Deterministic ID (see below), hex-encoded
  type:         "identity_link",
  issuer:       Identifier,      // the identifier claiming the external identity
  subject:      Identifier,      // same as issuer (self-attestation)
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
    verifier_did:   Option<Identifier>, // the verifier's identifier, where a third party verified (challenge_response only)
  },
  revocation_status: RevocationStatus, // Active or Revoked (§7.4.1). MUST be in signed scope.
  signature:    P256Signature,     // 64 raw bytes; signs the §9.5.1 canonical hash (see Signature scope below), using issuer's #active key
}
```

> **Proof opacity.** Verifiers MUST use the `proof` string as-is in the
> signature scope — do not parse and re-serialize. This ensures:
> (1) forward compatibility with new verification methods,
> (2) cross-implementation canonical hash determinism,
> (3) verifiers need not understand proof contents to verify signatures.

**Signature scope:** The signature covers the §9.5.1 canonical hash of `(id, attestation_type, issuer, subject, issued_at, expires_at, claim, evidence, revocation_status)` using domain separator `"SCP-IDENTITY-LINK-ATTESTATION-V1:"`. String and identifier fields use 4-byte BE length-prefixed encoding, `issued_at` uses 8-byte BE u64, `expires_at` uses the absent sentinel when not set, and sub-structures (`claim`, `evidence`, `revocation_status`) are individually serialized as MessagePack (sorted-key encoding) and included as variable-length byte fields. See §25.13 (Vector 26) for the exact construction.

**Attestation ID construction:** the `id` field is a hex-encoded SHA-256 digest over the attestation's identifying fields under the canonical hash construction of `09-security-model.md` §9.5.1. The domain separator `"SCP-ATTESTATION-ID-V1:"` keeps the digest from colliding with another protocol's.

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

**Revocation check:** Verifiers check revocation by resolving the issuer's service record (§3.10.13) and reading its `AttestationRevocations` pointer (`18-addressability-and-deployment.md` §18.2.2). The pointer's target returns a list of revoked attestation IDs. If the attestation's `id` appears in the list, it is revoked. Additionally, the `revocation_status` field in the attestation itself is checked — if `Revoked`, the attestation is invalid regardless of the revocation endpoint.

### 3.5.3 Service-Record Attestation Entry

Identity link attestations are published as entries in the issuer's service record (§3.10.13). This enables discovery: any party resolving the service record can enumerate the issuer's identity links without querying a separate registry.

**Service-record entry format:**

```
Service {
  id:              "<identifier>#attestation-<platform>--<index>",
  type:            "ScpIdentityLinkAttestation",
  serviceEndpoint: "<attestation_id>"                       // Hex-encoded attestation ID (§3.5.2)
}
```

**Fragment naming convention:** `attestation-<platform>--<index>`, where `<platform>` is the `platform` value from the provider registry (§3.5.1) and `<index>` is a zero-based integer that disambiguates several attestations for one platform, such as several Mastodon instances.

**Fields:**

- `id`: the identifier followed by the fragment. The fragment encodes the platform for a human reader, and `<index>` disambiguates several attestations for one platform.
- `type`: `ScpIdentityLinkAttestation` (constant). Consumers filter service-record entries by this type to discover identity link attestations.
- `serviceEndpoint`: The attestation ID (hex string). Consumers use this to look up the full `IdentityLinkAttestation` from the identity's attestation store on a relay.

**Maximum attestations per service record:** 64. This prevents service-record bloat — each entry adds to the record's size, which is replicated across resolvers — while providing enough headroom for users with many platform identities. The limit applies to service-record entries of type `ScpIdentityLinkAttestation` only; other entry types have their own limits.

**Bridge-layer attestation store limit:** a bridge attestation store enforces that same 64-attestation cap, under the constant `MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID` that `scp-ffi-common` defines, so the service record and the store share one bound.

**Lifecycle:** When an attestation is revoked, the corresponding entry MUST be removed from the service record. When an attestation is renewed (re-verified), the entry is unchanged — it still points to the same attestation ID. When an attestation is replaced (new attestation for the same platform+handle), the service entry's `serviceEndpoint` is updated to the new attestation ID.

### 3.5.4 Verification

Verification procedure depends on the attestation class (§3.5.0).

**Class 1 (Cryptographic) verification:**

1. Resolve the issuer's key state (§3.10.4). Read the public key it lists `current` in the `#active` role.
2. Verify the P-256 signature on the attestation envelope against the issuer's public key.
3. Check `revocation_status` is `Active`. If `Revoked`, reject.
4. Check `expires_at` (if present). If expired, reject.
5. Check freshness: if `evidence.verified_at` is older than the renewal interval for the verification method (§3.5.1), the attestation is stale. Stale attestations are degraded (reduced trust weight), not rejected outright.
6. **Trust the self-attestation.** Because issuer == subject, the `#active` signature is sufficient. The attestation asserts "I performed OAuth verification at `verified_at` and the OIDC `sub` was `subject_id`." There is no cryptographic proof that the OAuth flow actually occurred — this is a self-attestation. It is acceptable for identity links because: (a) the claim is minimal, (b) the only use case is linking identities the user actually controls, (c) falsifying a link provides no protocol benefit (shadow claiming verifies independently, social graph import only surfaces genuine contacts).

**Class 2 (Reference) verification:**

1. Perform steps 1-5 from Class 1 verification (signature, revocation, expiry, freshness).
2. **Fetch the proof resource.** For `SignedPost`: HTTP GET the `post_url`, confirm the response body carries the issuer's identifier and the nonce. For `DnsRecord`: perform a DNS TXT lookup for `_scp-verify.<domain>`, confirm a record carries the issuer's identifier. DNSSEC validation is RECOMMENDED where the domain supports it.
3. **If the fetch fails or the identifier is not present:** the attestation is unverified. Treat as if the attestation does not exist for trust evaluation. Do not cache a negative result — transient failures (rate limiting, DNS propagation delays) should not permanently invalidate an attestation.
4. **If the fetch succeeds and the identifier is present:** the attestation is verified. Cache the result.

**Where an SCP SDK sits in this flow.** Step 2 belongs to the consumer, as §3.5.1 states for every Class 2 method ("a live external resource that consumers must verify themselves"). An SDK verification operation therefore takes that consumer's fetch outcome as a required input and performs every other step of this list itself. A consumer that fetched the resource and found the issuer's identifier in it reports `confirmed`, and the operation returns a verdict. A consumer that fetched nothing reports `not_fetched`, and the operation raises the step-3 state — "unverified", distinct from "rejected" — so a consumer never records a rejection this section forbids caching. A consumer that reports `confirmed` without fetching anything states a falsehood about its own step 2; no SDK can detect that, which is why step 2 names the consumer as the party that performs it.

**Verification cache:**

- Consumer-side. Each consumer maintains its own cache of Reference attestation verification results.
- TTL: 1 hour. After TTL expires, the consumer MUST re-verify before granting trust weight.
- Cache key: attestation ID.
- Cache entries: `{ attestation_id, verified: bool, verified_at: u64, expires_at: u64 }`.
- Class 1 attestations do not require caching, because signature verification is deterministic and fast.

**Renewal intervals.** The provider registry of §3.5.1 carries the interval for every platform and is the one home of those values. A consumer SHOULD re-verify at that interval, and an attestation that is stale but not expired is degraded rather than rejected. The intervals track how fast each proof decays: an OIDC token expires and its account may be revoked, a profile bio is edited and its account suspended, a `ChallengeResponse` leaves no persistent proof at all, and a DNS record or a `.well-known` endpoint changes hands only with its domain. A `ChallengeResponse` attestation that names no platform in that registry renews at 60 days.

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
     claimant_did:      Identifier,
     shadow_did:        Identifier,     // the shadow identity's identifier
     attestation_id:    String,         // ID of the IdentityLinkAttestation
     attestation:       IdentityLinkAttestation, // Full attestation for verification
     timestamp:         u64,
     signature:         P256Signature,    // Signs claimant_did || shadow_did || attestation_id || timestamp
   }
   ```

3. **Bridge verification.** The bridge operator verifies:
   a. The attestation links the claimant's identifier to the shadow identity's external identity.
   b. No other identifier has already claimed this shadow identity.
   c. The claimant's identifier is not on any block list relevant to the context.

4. **Merge execution.** On successful verification:
   a. The shadow identity's membership records in all bridge contexts are updated to reference the claimant's identifier.
   b. Historical messages from the shadow identity are re-attributed to the claimant's identifier in the context event log via a `ShadowClaimed { shadow_did, claimant_did, attestation_id, timestamp }` event.
   c. The shadow identity is deactivated — it cannot send new messages or be claimed by another party.
   d. The claimant inherits the shadow identity's role in the context (typically `member`; never higher than the context's default role for new members unless governance explicitly grants an upgrade).

5. **Conflict resolution.** If two claimants present valid attestations for the same shadow identity simultaneously, the first `ShadowClaimRequest` processed by the bridge wins. The second claimant receives a `SHADOW_ALREADY_CLAIMED` error (code 4040). The losing claimant MAY dispute via the bridge context's governance mechanism.

**Participation record handling.** The shadow identity's participation history (message counts, duration, event log entries) is NOT merged into the claimant's participation profile. Shadow participation is recorded under the shadow identity's own identifier: the `ShadowClaimed` event establishes the link for auditing, and participation records stay separate so that no party inflates participation by creating shadow identities.

### 3.5.6 Security Considerations

**SDK-signed proofs are self-attestation summaries.** Class 1 proofs assert "I performed OAuth and the provider confirmed my identity." This is a self-attestation — there is no way for a consumer to independently verify that the OAuth flow occurred. This is acceptable ONLY for identity links, where issuer == subject. SDK-signed proofs MUST NOT be used for cross-party attestation types (endorsements, capability delegations, etc.) where the issuer and subject differ.

**No PII in attestations.** The attestation contains only: platform name, platform handle, platform user ID (opaque identifier, not email or name), and verification timestamp. No raw JWT, no OIDC claims beyond `sub`, no email addresses, no display names. The `openid`-only scope ensures the OIDC provider returns the minimum possible claim set. SDKs MUST NOT request `email` or `profile` scopes for attestation creation.

**Reference attestations carry zero trust until verified.** A Class 2 attestation with an unverified proof URL provides no trust signal whatsoever. Trust evaluation (§7.5) MUST score unverified Reference attestations at zero. This prevents an attacker from publishing a Reference attestation pointing to a URL they do not control — the attestation exists, but no consumer will trust it until they verify the proof.

**`revocation_status` in signed fields.** The `revocation_status` field is included in the signature scope (§3.5.2). This prevents re-activation: an attacker who obtains a `Revoked` attestation cannot strip the status and present it as `Active` because the signature covers `revocation_status`. However, this does NOT prevent replay of the original `Active`-signed version — the original attestation remains valid until consumers check the revocation endpoint. The revocation endpoint check (§18.2.2 `AttestationRevocations`) is ALWAYS required regardless of `revocation_status` value. The signed field is defense-in-depth, not a complete revocation mechanism.

## 3.6 Social Graph

SCP holds no global social graph: no friends list, no public follower count, and no network-wide structure a party can query.

**Social graph data is context state.** Each context already knows its members, their roles, and their participation history, and that state is verifiable against the context's event log and governed by the context's permissions (§5.9). No agent owns a separate copy.

**A party's view of its own graph is computed, not stored.** The SDK queries the contexts the party participates in through the capability-gated interfaces §7 defines, derives relationship strength from shared participation — how many contexts, over how long, in what roles — and presents the result. The data stays in the contexts and the protocol checks permissions before it answers.

**Sharing that view is capability-gated**, under the same model as any other data access (§7.3). A grant is scoped per identifier ("Bob sees my connections, Carol does not"), per capability ("Bob sees that I am in this context and sees no other"), per context ("every member here sees that I am a member and sees nothing else"), or per category ("close contacts see my full list"). The scoping reaches relationship metadata as well as existence: a party may see that two identities share one context without seeing that they share another. No new primitive is required, because graph visibility falls out of the trust equation §1 states, `trust = f(identity, capability, context, metadata)`.

**Block and mute live in identity private state** (§3.7), which is persistent, portable, and encrypted.

**Blocking runs at three tiers, each enforced through the same three cryptographic layers** (§9.16, §9.17): a block-list check denies key re-requests to the blocked identity; the blocker's SDK destroys the blocked party's cached keys and plaintext, which is a protocol requirement for a compliant client; and deleting the blocked party's per-member access key revokes that party's access to stored content.

- **Tier 1, identity to identity inside one context, unilateral.** The blocker rotates its sender key to exclude the blocked identity, destroys that identity's cached content, and deletes its access key. It reaches the blocker's own content in that one context and no other member's. Unblocking is forward-only: the blocked party receives future content, and content from before and during the block stays inaccessible because its access keys were destroyed rather than archived.
- **Tier 2, identity to identity across every shared context.** Stored in identity private state, Tier 2 applies Tier 1 to every context the two identities share at once. The block is bidirectional: both SDKs rotate their sender keys to exclude each other (§9.16.3).
- **Tier 3, governance-gated, context-level.** Context governance revokes a member's access to all content in the context through the propose-and-approve path of §5.9, under the actions `RevokeAccess`, `RestoreAccess`, and `RotateContentKeys` (ADR-031). Restoration is forward-only.

Tiers 1 and 2 are per-relationship and Tier 3 is per-context, so a party Tier 3 revoked sees no content in the context while a party Tier 1 blocked still sees every other member's. The three tiers compose: where both a member and governance have revoked one party's access, each revocation is reversed independently.

**Mute is unidirectional and enforced in the SDK.** A party that mutes another stops seeing that party's content, and the muted party is unaffected. The muter is not adversarial against itself, so SDK-level enforcement suffices and cryptographic exclusion is not required.

## 3.7 Identity Private State

An identity has public state — its key-event log, its service record, and its published attestations — and **private state**: encrypted data that only the identity owner can read, replicated for availability and portability.

Context state handles multi-party social data. Identity private state handles single-party personal data. Together they cover every category of protocol-relevant state without requiring anything to live only on a local device.

```
Identity
├── Public State
│   ├── Key-event log (`09-security-model.md` §9.7.4.2 definitions)
│   │   ├── the root set — up to MAX_ROOT_SET_SIZE P-256 keys with a threshold
│   │   ├── #active — the one operational role (P-256)
│   │   └── the designation of the key that signs the service record
│   ├── Service record (§3.10.13) — relay list, private-state locations,
│   │   broadcast advertisements, self-asserted capability URIs, pointers
│   └── Published attestations (§3.5) — their own signed objects
│
└── Private State (encrypted, replicated)
    ├── Block / mute list
    ├── Graph visibility policies (default + per-identity grants)
    ├── Agent configuration defaults (cross-context preferences)
    ├── Personal annotations on other identities
    ├── Petnames for identities and contexts (§22.4) — per-identity, per `SCP` instance (ADR-048)
    ├── Notification preferences
    ├── Draft attestations (not yet published)
    └── (extensible — any identity-level private data)
```

**The human identity's key state names one operational role, `#active`** (`09-security-model.md` §9.7.4.2 definitions). An agent is a separate identity with its own key-event log, which the human's log anchors by cooperative delegation, so no key of an agent's appears in a human's identity. ADR-063, the inception-derived key-event-log identity substrate, supersedes ADR-039, the shared-DID human-agent identity model, and ADR-064, cooperative delegation, is the artifact that writes the replacing model. That model is unspecified as of 2026-09-10 (`00-open-questions.md`), and `09-security-model.md` §9.1 invariant 1 is its home, which this spec cites rather than restates.

**Encryption model.** Private state is encrypted with a dedicated symmetric **Private State Key (PSK)** — an AES-256 key used exclusively for identity private state encryption. The PSK is not derived from any signing key. An SCP signing key is an ECDSA key (`09-security-model.md` §9.5) and signs only — it never encrypts. The PSK is generated independently and distributed to the identity owner's devices via HPKE (§3.7.2).

**Cryptographic specification:**

- **Algorithm:** AES-256-GCM (RFC 5116).
- **Key:** 32-byte random Private State Key (PSK), generated via CSPRNG (e.g., `OsRng`). The PSK is a raw symmetric key — it is not managed through `KeyCustody` (which handles asymmetric P-256 signing and HPKE keys). One PSK per identity, shared across all enrolled devices.
- **Nonce:** 96-bit (12-byte) random nonce, generated per event via CSPRNG. Each event in the private state log gets a unique nonce. The nonce is stored alongside the ciphertext — it is not secret.
- **AAD (Additional Authenticated Data):** `identifier_bytes || "scp-private-state-v1" || sequence_number`, where `identifier_bytes` is the identity's 32 raw digest bytes carrying no length prefix, because §9.5.1 gives a fixed-length field none; `"scp-private-state-v1"` is the domain separator as raw UTF-8 bytes, fixed per version and carrying no length prefix; and `sequence_number` is the event's sequence number as an 8-byte big-endian u64. AAD binding prevents: (a) ciphertext from one identity being replayed against another, (b) events being reordered within the log, (c) cross-protocol confusion with other AES-256-GCM uses in SCP.
- **Domain separator:** `"scp-private-state-v1"`. Distinct from `"scp-sender-key-v1"` (§9.16.2), `"scp-access-key-v1"` (§9.17.1), and all other SCP domain separators.

```
Encryption (per event):
  nonce = random(12)
  aad = identifier_bytes || "scp-private-state-v1" || sequence_number
  (ciphertext, tag) = AES-256-GCM-Seal(PSK, nonce, plaintext_event, aad)
  stored: { nonce, ciphertext, tag, sequence_number }

Decryption (per event):
  aad = identifier_bytes || "scp-private-state-v1" || sequence_number
  plaintext = AES-256-GCM-Open(PSK, nonce, ciphertext, tag, aad)
  if tag verification fails → reject (tampered or wrong key)
```

**Storage model.** Same as context state: encrypted blobs stored on your published relays. A relay sees that one identifier has encrypted private state. Relays store and serve it. Relays cannot read, modify, or interpret it. This is encryption-as-access-control (§10.5) applied to identity rather than context — the same infrastructure, the same relay behavior, the same trust assumptions.

**Routing ID derivation.** Identity private state blobs are addressed on relays by a deterministic `routing_id`:

```
private_state_routing_id = HKDF-SHA-256(
    ikm:  private_state_key,          // the 32-byte PSK above, which no relay holds
    salt: SHA-256("scp-private-state-salt-v1"),
    info: "scp-private-state-v1" || identifier_bytes,
    len:  32
)
```

**The input is the PSK and never a public value**, and `identifier_bytes` is the identity's 32-byte inception-derived identifier (`09-security-model.md` §9.7.4.2 R13). HKDF (RFC 5869) is used instead of plain SHA-256 so that a relay holding a known identifier cannot compute the routing id and identify which blobs hold that identity's private state. **A root key is the wrong input on two counts**, and this states both rather than leaving a reader to keep the old one: the key-event model gives an identity a root **set** with a threshold rather than one `#0` key, so "the `#0` public key" names no value for an organization; and every root member is public in the log the identity publishes to its own relays, so a derivation over it gives a relay that resolved the identity the routing id for free. The PSK is held by the identity's own devices alone, so a relay that has not been given it cannot address the blobs. **A root recovery therefore moves no routing id**, because the recovery installs a fresh root set and changes no PSK; §3.7.2 states when the PSK itself rotates and what re-addressing that costs.

The domain separation (`"scp-private-state-v1"` info string and `"scp-private-state-salt-v1"` salt) prevents collision with other routing ID derivation schemes: key-event record routing uses `SHA-256("scp:did:" || identifier_bytes)` (§3.10.2), encrypted context routing uses HMAC-SHA256 keyed on the per-identity `pseudonym_secret` with `"scp-pseudonym"` (§9.10.4), which is a different secret from the PSK above, broadcast context routing uses `SHA-256(context_id)` (§5.14), and context metadata routing uses `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` (§9.10.4.B).

The `IdentityPrivateState` entry of the identity's service record (§3.10.13) lists which relays store the private state. The `routing_id` tells the SDK how to address those blobs on those relays.

**Sync model.** Append-only event log, same pattern as context event logs. Each device appends events, such as "blocked identifier Y at timestamp T" and "granted Bob graph visibility at scope Z". Any device that holds the PSK reconstructs current state from the log. Multi-device consistency: two phones and a laptop all hold the same PSK, all append to the same log, all converge to the same state. See §3.7.2 for how the PSK is distributed to devices.

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

**Relationship to context state.** Identity private state is the single-owner case of context state: the same storage, the same integrity model, and the same relay interaction, with a membership count of one and no governance, no roles, and no capability ceiling. The encryption is the access control, and the owner alone holds the PSK.

**Protocol-level constants (immutable):**

- **Size constraints.** Less constrained than context state. The single-owner case allows growth (block lists, annotations, agent memory, draft attestations) without imposing storage on other participants. Relays MAY enforce per-identity storage quotas as an operational concern, but the protocol does not mandate minimalism for identity private state.
- **Relay obligations.** Same storage class and retention as context events. No differentiated commitment — relays treat all encrypted blobs uniformly. A relay that stores context events for an identity stores that identity's private state under the same terms.
- **Key rotation.** On identity key rotation (§9.12), the PSK is rotated: generate a new PSK, re-encrypt private state events, distribute the new PSK to all enrolled devices via HPKE (§3.7.2). The old PSK is destroyed on all devices after re-encryption completes. For large private state, re-encryption is incremental: most recent events first, backfill in background. Each re-encrypted event receives a fresh random nonce.
- **Discovery pointer.** Explicit. The identity's service record (§3.10.13) carries an `IdentityPrivateState` entry listing the relays that store its private state. This cleanly disambiguates context event fetches from private state fetches without relay-side guessing. The key-event log carries no private-state location: the location is transport metadata, so it rides the service record, and changing it appends no key event (`09-security-model.md` §9.6.3).
- **Relay service endpoints.** The identity's service record (§3.10.13) carries `SCPRelay` entries listing the identity's transport-layer relay URLs — the endpoints where `TransportManager` routes encrypted blobs for this identity. Multiple entries are recommended for suppression resistance (§9.9.2). The designated service key signs that record and the key-event log carries only the designation of that key, so re-pointing a relay warms no root key (`09-security-model.md` §9.6.3, §3.10.13).

### 3.7.1 Block List Storage

Identity private state stores block lists at two granularities:

**Global block list.** Identities blocked across every shared context (Tier 2). Stored as an append-only event log within identity private state:

- `BlockDID { target_did, timestamp }` — add an identifier to the global block list.
- `UnblockDID { target_did, timestamp }` — remove an identifier from the global block list.

The current block list is derived by replaying the event log, and §3.7.1.1's table states which event types commute.

**Per-context block list.** Identities blocked in one context only (Tier 1). Same event types but scoped:

- `BlockDIDInContext { target_did, context_id, timestamp }`
- `UnblockDIDInContext { target_did, context_id, timestamp }`

**Block list propagation.** When a global block is issued (Tier 2), the SDK propagates to all shared contexts:

1. Enumerate contexts where both the blocker and the target are members.
2. For each shared context, execute the Tier 1 block protocol (§9.16.3) — rotate sender key, destroy cached content, delete access key.
3. Record the block in identity private state.

Propagation is best-effort and idempotent — if the SDK is offline for some contexts, the block executes on next connection. The identity private state event log is the authoritative record; per-context enforcement is the mechanism.

**ProtocolRepository methods.** The `Storage` trait (§17) requires these methods for block list persistence:

- `get_global_block_list(subject: &Identifier) -> Result<Vec<Identifier>>`
- `is_globally_blocked(blocker: &Identifier, target: &Identifier) -> Result<bool>`
- `get_context_block_list(subject: &Identifier, context_id: &ContextId) -> Result<Vec<Identifier>>`
- `is_blocked_in_context(blocker: &Identifier, target: &Identifier, context_id: &ContextId) -> Result<bool>`

These methods derive current state from the identity private state event log. Implementations MAY maintain materialized views for query performance.

**Write operations.** Block list mutations are performed through identity private state events. The SDK provides:

- `add_global_block(blocker: &Identifier, target: &Identifier) -> Result<()>` — appends a `BlockDID` event, then propagates to every shared context (§9.16.3).
- `remove_global_block(blocker: &Identifier, target: &Identifier) -> Result<()>` — appends an `UnblockDID` event, then propagates forward-only restoration to the shared contexts.
- `add_context_block(blocker: &Identifier, target: &Identifier, context_id: &ContextId) -> Result<()>` — appends a `BlockDIDInContext` event, then executes the Tier 1 block protocol.
- `remove_context_block(blocker: &Identifier, target: &Identifier, context_id: &ContextId) -> Result<()>` — appends an `UnblockDIDInContext` event, then executes forward-only restoration.

Each write triggers sender key rotation (§9.16.3), access key operations (§9.17.5), and SDK-mandated state destruction (§9.16.7) as side effects.

**Conflict resolution for same-target block/unblock.** Where two devices simultaneously block and unblock one target identifier, the operations are NOT commutative. Resolution rule: **block wins.** When replaying the event log, if both `BlockDID { target: X }` and `UnblockDID { target: X }` exist with the same timestamp (within 1-second tolerance), the block takes precedence. For events with different timestamps, the later timestamp determines the current state.

### 3.7.1.1 Exhaustive Private State Event Types

All identity private state event types, organized by category:

**Block/Mute events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `BlockDID` | `target_did: Identifier, timestamp: u64` | Yes (different targets) | Global block (Tier 2) |
| `UnblockDID` | `target_did: Identifier, timestamp: u64` | Yes (different targets) | Global unblock |
| `BlockDIDInContext` | `target_did: Identifier, context_id: ContextId, timestamp: u64` | Yes | Per-context block (Tier 1) |
| `UnblockDIDInContext` | `target_did: Identifier, context_id: ContextId, timestamp: u64` | Yes | Per-context unblock |
| `MuteDID` | `target_did: Identifier, timestamp: u64` | Yes | Global mute |
| `UnmuteDID` | `target_did: Identifier, timestamp: u64` | Yes | Global unmute |
| `MuteDIDInContext` | `target_did: Identifier, context_id: ContextId, timestamp: u64` | Yes | Per-context mute |
| `UnmuteDIDInContext` | `target_did: Identifier, context_id: ContextId, timestamp: u64` | Yes | Per-context unmute |

**Graph visibility events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetDefaultGraphVisibility` | `visibility: GraphVisibility, timestamp: u64` | No | Default visibility for every identity |
| `GrantGraphVisibility` | `target_did: Identifier, scope: VisibilityScope, timestamp: u64` | Yes (different targets) | Per-identity override |
| `RevokeGraphVisibility` | `target_did: Identifier, timestamp: u64` | Yes | Remove a per-identity override |

**Agent configuration events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetAgentConfig` | `key: String, value: MessagePackValue, timestamp: u64` | No (same key) | Key-value agent preferences |
| `DeleteAgentConfig` | `key: String, timestamp: u64` | No (same key) | Remove a preference |

**Annotation events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetAnnotation` | `target_did: Identifier, key: String, value: String, timestamp: u64` | No (same target+key) | Personal note on an identity |
| `DeleteAnnotation` | `target_did: Identifier, key: String, timestamp: u64` | No (same target+key) | Remove annotation |

**Petname events (§22.4):**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetPetname` | `target: PetnameTarget, name: String, timestamp: u64` | No (same target) | `PetnameTarget` = an identifier or a `ContextId` |
| `DeletePetname` | `target: PetnameTarget, timestamp: u64` | No (same target) | Remove petname |

**Notification events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SetNotificationPreference` | `scope: NotificationScope, level: NotificationLevel, timestamp: u64` | No (same scope) | `NotificationScope` = `Global`, `PerContext(id)`, `PerIdentity(identifier)` |

**Attestation draft events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `SaveDraftAttestation` | `draft_id: String, attestation: IdentityLinkAttestation, timestamp: u64` | Yes (different drafts) | Draft not yet published |
| `DeleteDraftAttestation` | `draft_id: String, timestamp: u64` | Yes | Remove draft |
| `PublishDraftAttestation` | `draft_id: String, timestamp: u64` | Yes | Mark draft as published |

**Device registry events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `EnrollDevice` | `device_id: String, device_hpke_pubkey: [u8; 65], device_name: String, enrolled_at: u64` | Yes | New device enrollment |
| `UnenrollDevice` | `device_id: String, timestamp: u64` | Yes | Device removal |

**Recovery contact events:**

| Event type | Fields | Commutative | Notes |
|-----------|--------|-------------|-------|
| `AddRecoveryContact` | `contact_did: Identifier, timestamp: u64` | Yes | Designate recovery contact |
| `RemoveRecoveryContact` | `contact_did: Identifier, timestamp: u64` | Yes | Remove recovery contact |

For non-commutative events (same key/target modified from multiple devices), conflict resolution is **last-timestamp-wins** with tie-breaking by lexicographic comparison of the event hash.

### 3.7.2 Multi-Device Private State Key Distribution

Identity private state is encrypted with a single PSK shared across all of the identity owner's devices. The challenge: each device has its own hardware-backed keys that cannot be exported (§9.7.2), so the PSK must be distributed TO each device rather than derived FROM a shared secret.

**Device enrollment model.** Each device generates a device-specific DHKEM(P-256) keypair via `KeyCustody::generate_keypair(KeyType::HpkeP256)` at device enrollment time. This keypair is used exclusively for receiving HPKE-wrapped key material (PSK distribution, PSK rotation). The HPKE public key is published in the identity's device registry — an encrypted list within identity private state itself (bootstrapped during identity creation, see below).

**Why not derive the PSK from a root member?** The root is a signing key held in a substrate that never exports it — a passkey by default (`09-security-model.md` §9.7.4.1 item 4) — so no code path can hand a device the private bytes an HPKE key would have to be derived from. A passkey and a secure element each sign and neither performs a Diffie-Hellman agreement on demand, so deriving an encryption key from the root is impossible where the root is held as SCP holds it by default. Each device therefore generates its own DHKEM(P-256) keypair for PSK distribution, and that keypair is device-local, rotatable, and revocable on device removal without touching any identity key.

**Identity creation (first device):**

1. Generate the PSK: 32 random bytes via CSPRNG.
2. Generate a device-local DHKEM(P-256) keypair via `KeyCustody`.
3. Store the PSK locally in the device's secure key store.
4. Initialize the device registry in identity private state with this device's HPKE public key. The device registry is the first event in the private state log — it is encrypted with the PSK (which only this device holds at this point).
5. Publish the encrypted private state to relays.

**Adding a new device (device enrollment):**

```
Existing device (Device A) enrolls new device (Device B):

1. Device B generates a DHKEM(P-256) keypair via KeyCustody.
2. Device B presents its HPKE public key to Device A.
   Transport: out-of-band (QR code, local network, NFC) or via
   a standing bilateral context (§5.12.4) between the human's devices.
3. Device A verifies the enrollment request (user confirmation required).
4. Device A wraps the PSK to Device B's HPKE public key:
   enc, sealed_psk = HPKE-Seal(
     mode: Base,
     kem: DHKEM(P-256, HKDF-SHA256),
     kdf: HKDF-SHA256,
     aead: AES-128-GCM,
     recipient_pk: device_b_hpke_pubkey,
     info: "scp-private-state-v1" || identifier_bytes || "device-enroll",
     plaintext: psk
   )
5. Device A sends (enc, sealed_psk) to Device B via the same channel.
6. Device B opens the HPKE ciphertext using its HPKE private key,
   recovering the PSK.
7. Device A appends a DeviceEnrolled event to the private state log:
   DeviceEnrolled { device_hpke_pubkey, enrolled_at, enrolled_by_device }
   This event is encrypted with the PSK (readable by all enrolled devices).
8. Device B can now decrypt and append to the private state event log.
```

**HPKE suite.** Device enrollment and PSK distribution use DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM — the same HPKE suite as MLS (§9.5) and sender key distribution (§9.16.2). The `info` parameter carries the domain separator `"scp-private-state-v1"`, the identifier and the purpose string, which keeps this HPKE context distinct from sender key HPKE (`"scp-sender-key-v1"`) and access key HPKE (`"scp-access-key-v1"`). The full construction is `"scp-private-state-v1" || identifier_bytes || purpose`, where `identifier_bytes` is the identity's 32 raw digest bytes carrying no length prefix and `purpose` is a fixed-version UTF-8 string carrying none either. The `aad` is empty, because the `info` already binds the identifier and each device gets a fresh encapsulation, so no cross-recipient substitution surface exists.

**Purpose strings.** Two purposes are defined, distinguishing the two flows that wrap a PSK to a device key:

- `"device-enroll"` — initial PSK distribution when a device is enrolled (the flow above) and during trusted-device / social recovery (recovery IS enrollment, §3.3).
- `"psk-rotate"` — re-wrapping a freshly generated PSK to all remaining enrolled devices when a `PskRotated` event is emitted: on device removal (above) and on compromise recovery key rotation (§9.12 step 6).

The purpose string binds each HPKE ciphertext to its flow, so a `device-enroll` wrap cannot be opened in a `psk-rotate` context (different `info` produces a different HPKE key schedule, causing AEAD failure).

**Device removal:**

1. An authorized device appends a `DeviceRemoved { device_hpke_pubkey, removed_at }` event to the private state log.
2. The removing device rotates the PSK: generates a new PSK, re-wraps it via HPKE to all remaining enrolled devices' HPKE public keys, and appends a `PskRotated { wrapped_keys: Vec<(device_pubkey, hpke_ciphertext)> }` event.
3. Re-encryption of existing private state events proceeds incrementally under the new PSK (same as key rotation, §3.7 protocol-level constants).
4. The removed device's cached PSK becomes useless for future events. Historical events encrypted under the old PSK are accessible only if the removed device retained the old PSK locally — the protocol cannot force deletion on an untrusted device (same honest limitation as §9.15).

**Device registry.**

The device registry is stored within identity private state as a sequence of `DeviceEnrolled` and `DeviceRemoved` events. The current set of enrolled devices is derived by replaying the log (same pattern as block lists, §3.7.1). Each entry contains:

```
DeviceEnrolled {
    device_hpke_pubkey: [u8; 65],   // DHKEM(P-256) public key for HPKE
    enrolled_at: u64,                 // Unix timestamp (milliseconds)
    enrolled_by_device: [u8; 65],     // HPKE pubkey of the enrolling device
    device_label: String,             // Human-readable label ("iPhone", "Laptop")
}

DeviceRemoved {
    device_hpke_pubkey: [u8; 65],
    removed_at: u64,
}

PskRotated {
    wrapped_keys: Vec<DeviceWrappedPsk>,  // One entry per enrolled device
    rotated_at: u64,
}

DeviceWrappedPsk {
    device_hpke_pubkey: [u8; 65],
    enc: Vec<u8>,           // HPKE encapsulated key
    sealed_psk: Vec<u8>,    // HPKE-sealed PSK
}
```

**Bootstrap paradox resolution.** The device registry is itself encrypted with the PSK — so how does the first device read it? The first device generated the PSK (step 1 of identity creation) and holds it locally before any private state events exist. The first `DeviceEnrolled` event is encrypted with that PSK. Subsequent devices receive the PSK via HPKE before they need to read the log. There is no circular dependency: the PSK is always distributed out-of-band (HPKE to device key) before the device attempts to read PSK-encrypted events.

**Interaction with trusted device recovery (§3.3).** When a user recovers their identity on a new device via trusted device recovery, the recovery flow includes PSK distribution: the trusted device wraps the current PSK to the new device's HPKE public key via the same enrollment protocol above. This is the same mechanism as adding a new device — recovery IS enrollment. The recovering device generates a fresh DHKEM(P-256) keypair, the trusted device wraps the PSK, and the new device gains access to the full private state history.

**Interaction with key rotation (§9.12).** Step 6 of the compromise recovery protocol specifies "re-encrypt identity private state under the new key." With PSK-based encryption, this means: (a) generate a new PSK, (b) wrap the new PSK to all enrolled devices via HPKE, (c) append a `PskRotated` event, (d) re-encrypt existing events under the new PSK incrementally. If the compromise involved a device (device stolen), that device is removed first (device removal protocol above), and the PSK rotation excludes the compromised device's HPKE public key.

**ProtocolRepository methods.** The `Storage` trait (§17) requires these additional methods for PSK and device management:

- `store_private_state_key(subject: &Identifier, psk: &Zeroizing<[u8; 32]>) -> Result<(), StoreError>`
- `load_private_state_key(subject: &Identifier) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError>`
- `store_device_registry_event(subject: &Identifier, seq: u64, event: &[u8]) -> Result<(), StoreError>`
- `load_device_registry(subject: &Identifier) -> Result<Vec<DeviceRegistryEvent>, StoreError>`

The PSK MUST be stored in the platform's secure key store (Keychain on Apple, Keystore on Android, SQLCipher-encrypted storage on desktop/server — per §17.8 platform-specific key custody). The PSK is zeroized on destruction (`Zeroizing<[u8; 32]>`).

## 3.8 Resolution Security

Resolution is the trust root for the whole protocol: where an attacker can substitute what a resolution returns, it defeats encryption, authentication and capability validation together.

**The protocol has one identifier method, and it is inception-derived.** An identifier is self-certifying through its key-event log: the identifier is the digest of the inception event's signed preimage and encodes no key (`09-security-model.md` §9.7.4.2 R13). A resolver recomputes the identifier from the served chain's inception event and verifies every later event under R3, so a served record is verifiable against the identifier without trusting any intermediary. MITM on resolution is impossible given the correct identifier. A stale head of the accepted chain is rejected by sequence, and two chains that diverge are settled by fork precedence (R6, R12). See §9.6.1 for the full specification.

**Key Continuity Verification:** Signal-style safety numbers over two identifiers, which let two parties confirm out of band that each holds the other's correct keys. See `09-security-model.md` §9.11.

### 3.8.1 The Identifier in a Deterministic Derivation

**A derivation that two independent parties must reproduce byte for byte consumes the identifier's 32 raw digest bytes** (`09-security-model.md` §9.7.4.2 R13). The `derived_context_id` of §5.15.8 is one such derivation. A fixed-length digest admits exactly one encoding, so two honest parties cannot split onto divergent values, and the length-prefix discipline of `09-security-model.md` §9.5.1 keeps the field boundaries unambiguous whatever the neighbouring fields carry.

**A preimage that takes the identifier as UTF-8 bytes is not yet computable**, because R13 defers the identifier's textual form. `09-security-model.md` §9.5.2 states that deferral once and enumerates every signed structure that waits on it, and a reader MUST NOT treat one of those preimages as computable until a later revision of R13 fixes the encoding.

## 3.9 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in the substrates `09-security-model.md` §9.7.4.1 item 4 names), distribution (as key state carried by the identity's key-event log), rotation (a `KeyState` or `RootRecovery` event signed by the standing root set, `09-security-model.md` §9.7.4.2 R3), and destruction (for ephemeral context keys). The full key lifecycle specification, including compromise recovery, is in §9.7.4.

## 3.10 Identity Resolution

Resolution returns a key state the resolver derived from a chain it verified itself. An identity publishes its key-event log to SCP relays through the PUBLISH and QUERY operations ADR-004 defines, at a deterministic routing id, and the protocol runs no second resolution layer, because ADR-063, the inception-derived key-event-log identity substrate, made that log the one source of an identity's key state.

The resolver recomputes the identifier from the inception event, verifies every later event under the standing root, settles a divergence under the root rule, and derives the key state from the latest state-carrying event at or before the head it adopted (`09-security-model.md` §9.6.1, §9.7.4.2 R2, R3, R6 and R8). No witness cosignature gates any of those steps. Every relay is untrusted, and what a validating relay adds is availability rather than a trust input (§3.10.2).

### 3.10.1 Which Relays a Resolution Queries

A resolver queries two disjoint relay sets, in parallel: the identity's own relays, which are the relay entries of the service record this resolver last accepted (§3.10.13, `09-security-model.md` §9.6.3), and the fallback set, which `09-security-model.md` §9.7.4.2's definitions state over the community relay list of `18-addressability-and-deployment.md` §18.5.1. The resolver's recognized operator set is that same shipped list read in its second role. Only the fallback set is available on day one, because a reader learns an identity's own relays only from that identity's service record. The fallback set is where a resolver fetches, which is a reachability property of its own query plan; the recognized set is whose cosigned heads it reads as evidence, which is a policy of its own.

**Every relay a first-contact resolution queries carries a proof-of-control obligation**, and the resolver's own QUERY triggers it: the resolver sets `proof_nonce`, the relay answers with a relay proof of control signed under the operator identity its community-relay-list entry declares, and `09-security-model.md` §9.7.4.2 R11 counts only the relays whose proof this resolver verified. Steps 2, 3d and 5 of §3.10.4 carry that obligation through the procedure.

Parallel query makes resolution latency the latency of the fastest relay that answers. A resolver holding an accepted baseline cancels its remaining queries once one valid response arrives; a resolver holding none satisfies R11's first-contact floor before it ends the resolution.

### 3.10.2 Relay-Based Resolution

An identity's key-event log rides in the key-event record frame `09-security-model.md` §9.10.12 states, at `routing_id = SHA-256("scp:did:" ‖ identifier_bytes)` over the identifier's 32 raw digest bytes (`09-security-model.md` §9.7.4.2 R13). That separator keeps the address from colliding with every other routing derivation the protocol runs (§9.10.4, §5.14), and it is why the frame carries no record-kind byte: the address is the type discriminant.

**Relay-side validation has one home, and it is this subsection.** `09-security-model.md` §9.10.12 cites it and restates none of it, and `09-security-model.md` §9.7.4.2 R9 is the one home of the slot key, what a slot holds, the write rule, the serving order and the eviction rule. On PUBLISH at a routing id an SCP-native relay runs four checks, cheapest first, so junk is rejected before any expensive work:

1. **Structural decode.** Decode the blob as a key-event record frame (`09-security-model.md` §9.10.12). A blob that does not decode is not a candidate key-event record.
2. **The identifier-to-routing-id binding.** Confirm that the routing id equals the registered derivation over the frame's `identifier` field. This is a plain hash, cheaper than a signature verification, and it is the discriminant that lets a relay recognize a key-event record with no new wire type.
3. **Chain verification, on whichever of two branches the frame's first event selects.** Where that event is an inception event, the relay recomputes the identifier from it, rejects a frame that recomputes to anything but the `identifier` field step 2 read, and verifies every event under `09-security-model.md` §9.7.4.2 R2 and R3. Where that event's predecessor digest names an event the relay already holds at this routing id, the relay verifies the frame's events against the standing root the assembled chain carries at that position and recomputes no identifier. A frame whose first event selects neither branch is rejected. **The chain authorizes the write, and no key the writer supplies does.**
4. **Slot placement** under `09-security-model.md` §9.7.4.2 R9, which this step applies and does not restate.

**Slot-exclusivity.** Once a binding-valid frame whose chain verifies establishes a slot at a routing id, that routing id is slot-exclusive:

- **(a)** the relay rejects any later publish there that is not a frame passing steps 1 through 4. That positive test stands alone, and no enumeration of rejects stands beside it: a chain that diverges from a stored chain passes step 4, because R9 gives a divergent suffix its own slot, and a reject list naming a non-extending chain would hand the routing id to whichever party published first and leave every resolver holding one chain where the root rule needs two. R9's own condition rides with the test: at a routing id already holding `MAX_RETAINED_SUFFIXES` rank-1 suffixes, the relay rejects the further frame, records its head event's preimage digest, and reports the residue;
- **(b)** establishing the first slot evicts the opaque blobs already stored at that routing id, which clears junk pre-seeded before the identity's first publish;
- **(c)** QUERY at that routing id returns every slot the routing id holds and nothing else, a page at a time under R9's walk, because a relay that returned one slot would decide fork precedence for the resolver;
- **(d)** the relay rejects a client delete of any stored frame whose chain verifies. The gate is **storage-derived rather than index-derived**, because a delete addresses a blob by its own digest while the slot index is a cache a restart leaves cold: the relay re-reads the blob and refuses where it decodes as a frame whose chain recomputes to its `identifier` field and verifies. The gate runs behind the same per-address rate limit as PUBLISH and **fails closed on a storage read error**. It closes an integrity vector and not merely an availability one: an attacker deletes the genuine record, republishes a captured earlier frame carrying a genuine prefix, and a relay with nothing left to compare against stores that prefix as the whole chain.

**A validating relay also stores the witness layer's two records**, at `SHA-256("scp:wit:" ‖ identifier_bytes)` and `SHA-256("scp:wcf:" ‖ identifier_bytes)` (`09-security-model.md` §9.7.4.2 R13), in the frames §9.10.12 states. It accepts one where three things hold: the signature verifies against the P-256 key that operator's community-relay-list entry declares (`18-addressability-and-deployment.md` §18.5.1); the object's `witness` names a member of the witness set the key state at that subject's head carries, on a chain the relay itself holds, so a relay holding no chain for a subject accepts no witness record for it; and the address is not already full for that pair. **The caps**, under `09-security-model.md` §9.18.17: at most one cosigned head per (subject, witness, `event_digest`), replaced only by a strictly higher `sequence`; at most `MAX_RETAINED_SUFFIXES` conflict statements per (subject, witness), evicting the lowest `observed_at` beyond that; and at most `MAX_WITNESS_SET_SIZE` × `MAX_RETAINED_SUFFIXES` objects per subject at each address, because an honest witness emits one successor per baseline and a faulty one occupies at most `MAX_RETAINED_SUFFIXES`. **The `event_digest` term is the exception to strictly-higher replacement**: a fault proof's two cosigned heads carry one `subject`, one `witness` and one `previous_cosigned_digest`, and differ in `event_digest` alone (`09-security-model.md` §9.7.4.3), so the relay keeps both, and without that term one head would replace the other and no party could assemble the pair. Both the filter and the caps are load-bearing: without the filter any party that mints an identity writes cosigned-head records for any public identifier, and without the caps a member of the standing set writes without bound. A relay an identity designates as a witness runs the one check and holds the durable per-subject state `09-security-model.md` §9.7.4.3 states, neither of which this section restates.

**The byte bound.** A validating relay retains at most `MAX_RETAINED_BYTES` of divergent-suffix bytes per identifier, MAY configure a lower per-identifier value, MUST NOT configure a higher one, and on overflow evicts the lowest-ranked retained suffix first (`09-security-model.md` §9.7.4.2 R9, §9.18.17). A lower configured value evicts only lower-ranked suffixes, so no configured value changes a verdict any party reaches.

**Relay-side validation is an optional capability of SCP-native relays, and witnessing is a separate role a relay takes only where an identity designates it.** A foreign transport that cannot validate stores the frame as an opaque blob and carries content. **First contact and resolution require SCP-native listed relays**, because R11's floor counts only community-relay-list entries serving a relay proof of control, so a party whose only transport is a foreign adapter adopts no head on any first contact. A verifier still depends on no relay for correctness, because it verifies every event itself; KERI calls that property end-verifiability in `spec-body` §End-verifiable, "KERI has no security dependency on any other infrastructure".

**A resolver MAY QUERY any relay that stores the target identity's key-event log**, whether or not the community relay list or that identity's service record names it. What a relay outside those two sets cannot do is count toward the first-contact floor or toward the fallback set.

### 3.10.4 Resolution Protocol

The resolution protocol runs seven steps.

1. **Compute the routing id**, `SHA-256("scp:did:" ‖ identifier_bytes)`.
2. **QUERY in parallel** on the identity's own relays and on the fallback set. A resolver holding no accepted baseline MUST set `proof_nonce` on every one of those queries, to 32 bytes it drew freshly for that query (`09-security-model.md` §9.10.12); a relay answers with a proof only where the query carried one, and step 5 counts no relay that served none. A resolver holding a baseline MAY omit the field. The two sets go out together and never one after the other: a resolver holding no service record knows no relay of the identity's own, and a resolver holding one still needs a relay outside that list to reach R11's second operator.
3. **For each response**: (a) decode the frame and assemble the chain segments the slot served, trusting no framing byte; (b) recompute the identifier from the inception event and discard the response where it differs (`09-security-model.md` §9.7.4.2 R2); (c) verify every event under R3, discarding a chain that carries an author-attributable defect; (d) where the response carried a relay proof, apply the five checks `09-security-model.md` §9.7.4.2's definitions state and record whether this relay counts as a proven source.
4. **Settle the surviving chains.** Where one chain is a prefix of another, take the longer, and discard a head of the accepted chain at a strictly lower sequence without changing accepted state (`09-security-model.md` §9.7.4.2 R12). Where two chains diverge from a shared prefix, apply fork precedence (R6) and return `Contested` where it ties (R7).
5. **Satisfy the first-contact floor** where the resolver holds no accepted baseline, counting no relay that failed, timed out, served a chain step 3 discarded, or that step 3d did not record as a proven source. Otherwise the resolver returns `Inconclusive{SingleSource}` and adopts no head, and that payload separates the relays reached, the operators proven, and the proofs its own clock rejected (`09-security-model.md` §9.7.4.2 R11). A resolver holding an accepted baseline resolves against one relay and this step does not bind it.
6. **Optionally read cosigned heads as evidence**, by querying `SHA-256("scp:wit:" ‖ identifier_bytes)`. No rule reads what this step returns, so a resolver that skips it returns the same key state.
7. **Derive the key state** from the latest state-carrying event at or before the adopted head (`09-security-model.md` §9.7.4.2 R8) and cache it under the §9.10.7 caching policy. Resolution yields key state; the service record is resolved separately (§3.10.13).

**Two relays serving heads of one chain at one sequence** are compared event by event over each event's preimage digest, never over the chain bytes and never over the framing. Where every position's digests agree the two records are one chain, whether or not their bytes match, because §9.5 admits a hardware signer that draws its own nonce and two encodings of one event are then ordinary. Where the digests differ at any position the two heads are divergent events at one sequence, and step 4 settles them. KERI identifies an event by its digest in the same way, under `spec-body` §SAID fields.

**Where every relay fails**, a cached key state under seven days old is returned with `HeadProvenance` unchanged and no relays reached; otherwise resolution fails with a typed error. **The resolver MUST NOT fabricate a key state.** A relay that does not answer within the per-relay timeout is a failure for that attempt, and the resolver falls through to the others rather than retrying it synchronously.

### 3.10.5 Publishing Protocol

On appending a key event the owner builds the chain from the inception event to the new head, splits it into contiguous segments each fitting one frame, publishes the frames to the identity's own relays and to the fallback set in sequence order, and submits the new head to its witness set. A relay accepts a segment whose first event's predecessor it already holds (`09-security-model.md` §9.7.4.2 R9), so a publisher that sent a later segment first has it rejected and re-sends from the last segment the relay acknowledged. Submission to a witness gates nothing: the event takes effect at each relying party the moment that party resolves the extended chain, and an identity that designates no witness skips that step (`09-security-model.md` §9.7.4.2 R10, §9.7.4.3).

**A PUT carrying a key-event record sets the wire's `retain` flag**, which is REQUIRED true for the `scp:did:` kind, and a relay rejects a PUT at that kind that does not set it (`09-security-model.md` §9.10.12). A validating relay retains the record under `09-security-model.md` §9.7.4.2 R9 and expires it never, which is what the flag declares, so no republication cycle makes the record permanent.

### 3.10.6 Anti-Segmentation Invariant

**Publishing to the fallback set is a MUST.** An identity that published only to relays of its own would be resolvable only by a party that already holds its service record, because a first-contact reader knows no relay of that identity to query, so identities would partition into islands reachable by their existing contacts and by nobody else. **A publish cycle that reached no relay in the fallback set MUST therefore be reported to the caller as a failed publication**, never as a success.

**A publish cycle that reached no witness MUST be reported as degraded and never as a failure.** An identity that publishes everywhere and submits to no witness is still resolvable by every stranger and keeps its `09-security-model.md` §9.11 standing at every peer, because no rule reads a cosignature. What it gives up is portability: a cosigned head travels to a party that did not perform the read, and a peer's own relay read does not.

### 3.10.7 Version Resolution

The sequence orders one chain against its own prefixes, because an event's sequence is its predecessor's plus one and a verifier rejects an event whose sequence is anything else (`09-security-model.md` §9.7.4.2 definitions). Among heads of one chain the highest sequence is the newest, whichever relay served it, and a resolver replaces a stale head by re-publishing the longer chain to the relay that served the shorter one.

**The sequence decides nothing between two chains that diverge from a shared prefix**, because each chain's author assigned its own sequence numbers past the fork. Fork precedence settles those (`09-security-model.md` §9.7.4.2 R6), and it may adopt a chain whose head sequence is lower than the head the resolver previously held (R12). KERI reaches the same conclusion about a sequence number in `spec-body` §First Seen Policy, where `sn` is a location and never an arbiter.

### 3.10.8 Security Analysis

**Relay misbehavior is availability-only and never integrity on a warm-cache or multi-relay resolution.** Three controls hold that together, each covering one failure mode: the resolver's own chain verification rejects a forged record (`09-security-model.md` §9.6.1, §9.7.4.2 R2 and R3); its sequence check plus fork precedence across relays rejects a stale or replayed genuine record (§3.10.4, §3.10.7); and R9's write rule read against storage, with the storage-derived delete gate of §3.10.2 rule (d), raises the cost of the cold-cache purge-then-replay rollback on a relay that runs them.

**On a single-relay first contact the integrity control is the two-proven-operator floor and nothing on the relay.** The last two controls above are relay-side code, so they close nothing against a relay whose operator omits them, and a reader holding no accepted service record takes the whole community relay list as its fallback set, which makes R11's floor a count of distinct proven operators rather than a test against a record that reader has not accepted.

**What two proven operators deliver, and what they do not.** They defeat one dishonest relay. Three inputs defeat them, because a genuine prefix truncated before the event the reader most needs verifies clean at each source and forks nothing for R6 to rank: two genuinely independent operators colluding; one adversary occupying this reader's network path to both; and one party holding a listed operator's private key, which signs a conforming relay proof of control at every relay it answers from and is neither of the first two. `09-security-model.md` §9.7.4.3 states the first of those as a supply-chain risk no protocol check covers, and the resolver-supplied nonce in the relay proof stops a replay while leaving the on-path party untouched.

**Suppression takes every relay.** To prevent resolution an attacker must suppress the chain on all of an identity's validating relays and on the fallback set, because a resolver reads both. A flood at the routing id is inert on a validating relay, and `09-security-model.md` §9.7.4.2 R9 states each variant's outcome. Over a foreign transport that accumulates many blobs at one address, suppression resistance is best-effort: such storage contributes availability, and the resolver's own chain verification discards the junk.

### 3.10.9 Privacy Properties

A relay operator that answers a resolution learns that the resolver's network address queried one routing id, and it computes the same derivation, so it can name the identity for any identity it already knows. An identity's own relay operator learns nothing it did not already hold, because it already carries that identity's message traffic (§9.9.1). R11's floor sends a first contact's queries to community relays under distinct declared operators, so no single operator observes a whole first contact. A resolver that requires network-address anonymity takes the transport-layer measures §9.10.11 states, and the §9.10.7 caching policy bounds how often it queries at all.

### 3.10.10 IdentityBackend, the Resolution Trait

**`IdentityBackend::resolve` is the protocol's one resolution entry point**, and ADR-063, the inception-derived key-event-log identity substrate, names that seam. It takes the identifier's 32 raw digest bytes and returns a `ResolutionOutcome`, which carries key state and no document. `.docs/architecture.md` states which crate implements the seam.

```rust
/// Key-state resolution across the SCP relay network (§3.10.4).
pub trait IdentityBackend: Send + Sync {
    /// `identifier` is the 32 raw digest bytes of the inception-derived
    /// identifier (`09-security-model.md` §9.7.4.2 R13), never a textual form:
    /// R13 defers that form, and every derivation this trait performs consumes
    /// the digest.
    fn resolve(&self, identifier: &[u8; 32])
        -> impl Future<Output = Result<ResolutionOutcome, IdentityError>> + Send;
}

/// Every resolution returns one of the six verdicts of
/// `09-security-model.md` §9.7.4.2 R14, so a caller routes the verdict and
/// computes the `09-security-model.md` §9.11 standing from it. An `Err` is a
/// local failure, a storage or persistence error, and never a verdict.
pub struct ResolutionOutcome {
    pub verdict: ResolutionVerdict,
    /// Present on `Confirmed` and `Adopted`, absent on every other verdict.
    pub key_state: Option<KeyState>,
    pub sources: ResolutionSources,
}

/// What a resolution learned about its sources. R11 counts a declared operator
/// only where `proven` carries it.
pub struct ResolutionSources {
    pub relays_reached: Vec<String>,
    pub declared_operators: Vec<[u8; 32]>,
    /// The declared operators whose relay proof of control this resolver
    /// verified under the five checks (`09-security-model.md` §9.7.4.2 definitions).
    pub proven: Vec<[u8; 32]>,
    pub head_provenance: HeadProvenance,
}
```

`ResolutionVerdict` and its six variants, `TieClass`, `InconclusiveCause` and `HeadProvenance` are the types `09-security-model.md` §9.7.4.2's definitions and R14 fix, and every SDK binding carries their names unchanged. This section introduces none of them and restates no variant.

**The outcome carries the verdict rather than an `Option`**, because `09-security-model.md` §9.6.4 maps `Contested`, `Inconclusive` and `Invalid` to three different standings and a caller holding one absent value cannot tell them apart. **It records the declared operators and which of them proved control**, because R11 counts a source only where its proof verified and two relay URLs may sit under one declared operator.

### 3.10.11 Bootstrap and Network Growth

On day one an identity publishes its chain to the community relay list and lists no relay of its own, so every first contact reads two entries of that list under distinct declared operators. As identities publish to relays of their own, a resolver holding a baseline reaches one of those first and the fallback set carries less of the load. A first contact still reads community relays whatever the identity's service record names (`09-security-model.md` §9.7.4.2 R11), so growth changes what R11's floor costs in latency and never whether an identity can meet it.

### 3.10.12 Phase Integration

The routing derivation is a pure function in `scp-core`; the key-event record frame is a deterministic encoder and decoder in `scp-protocol` (`09-security-model.md` §9.10.12); publication, multi-relay QUERY, and the `IdentityBackend` of §3.10.10 are the relay publisher and key-state resolver in `scp-identity`. `.docs/architecture.md` states the crate layout, and this section adds no rule.

### 3.10.13 The Service Record

**This section is the one home of the service record.** Every other section of this spec and of `09-security-model.md` cites it and restates none of it.

**What the record carries.** An identity's service record carries every transport and service field that identity publishes: its `SCPRelay` entries, the relays holding its encrypted private state, its broadcast-context advertisements, its self-asserted capability URIs, the pointer to its context-hosted participation statements, and the pointer to its attestation revocation status (`18-addressability-and-deployment.md` §18.2.2 enumerates the entry types). Those capability URIs are the self-asserted third of what the retired `SCPCapabilities` entry carried (`18-addressability-and-deployment.md` §18.2.2A); a verifier-signed challenge-verification record is an attestation (§7.3.4), and economic metadata belongs to `19-economic-governance.md` §19.9. **The record carries no key, no key condition, and no witness parameter**: a root signature covers each of those in the key-event log, and a reader that found one here would be reading key state from a key weaker than the root. KERI draws the same line, carrying endpoint and role metadata in signed reply records outside the log (`spec-body` §Reply Message Body).

**The record's bytes.** A service record is `(identifier, sequence, entries)`, and its signature preimage is

```
SHA-256("SCP-SERVICE-RECORD-V1:" ‖ identifier ‖ sequence ‖ entries)
```

under the `09-security-model.md` §9.5.1 construction: the 32-byte identifier raw, `sequence` as an 8-byte big-endian `u64`, and `entries` under the repeated-field rule. **Each entry encodes as its three strings under the variable-length rule, in the order `id`, `type`, `serviceEndpoint`.** No entry carries a type discriminator, because `type` is that discriminator. Without this encoding two bindings compute two preimages over one record and neither's signature verifies at the other. `09-security-model.md` §9.18.2 registers the separator, `09-security-model.md` §9.7.1 classifies the record in the attestation class, and `25-test-vectors.md` §25.28 pins the bytes.

**Where the record lives.** A service record is addressed at `SHA-256("scp:svc:" ‖ identifier_bytes)` over the identifier's 32 raw digest bytes (`09-security-model.md` §9.7.4.2 R13), distinct from the key-event record's address, so one QUERY returns records of one kind.

**Who signs it.** The record carries a signature by the operational key the latest state-carrying key event designates for the service-record role, never by a root member. A reader verifies in two steps and never one: it verifies the key-event log under `09-security-model.md` §9.7.4.2 R2 and R3, reads the designation out of the verified chain, then verifies the record's signature against the designated key (`09-security-model.md` §9.6.3). R3 rejects a state-carrying event whose designation names a key that event does not list `current`, so the designated key is always one the current key state lists.

**A reader holding no accepted service record applies the first-contact floor to the record**, setting `proof_nonce` on its `scp:svc:` query as §3.10.4 step 2 requires on the key-event one, and returns `Inconclusive{SingleSource}` where it cannot meet the floor. A single relay can serve a genuine record truncated to an older sequence exactly as it can serve a truncated chain, and such a reader holds no high-water mark to compare against.

**How a reader settles two copies: last writer wins on the record's own sequence**, which is monotonic and unrelated to the log's. A reader rejects a record at the maximum representable value, so no writer exhausts the space. **The high-water mark is keyed to the pair (identifier, the 33 public-key bytes the designation resolved to)**: a mark scoped to the identifier alone would let one record written at a high sequence by a briefly held key block the controller's own recovery record forever. **The mark resets when the key state lists different bytes `current` in the designated role**, so a routine rotation resets it and the reader accepts the first record the new key signs at any sequence. The reset is sound because a root signature covers the event listing those bytes and the replaced key's holder cannot produce one. **Fork precedence does not apply here and MUST NOT be applied**: a service record has no reveal-authorized event class, so no legitimate update lowers the sequence, and two signature-valid records at one sequence are the designated key's holder equivocating. A reader holding two such records rejects both and reports the identity's transport metadata as unresolved.

**A reader holding a `Contested` verdict accepts no new service record** for that identity, because a contested identity has no adopted key state and therefore no authorized designation. It keeps routing on the last record it accepted before it observed any divergent-suffix event, and only while that record's designated key is `current` in the shared prefix's key state; where no record it holds meets both conditions it routes on nothing and says so, with the caching bound suspended for that identity. Freezing on a record the divergence's author wrote would hand routing to whichever claimant published last, and reporting every contested identity unroutable would let any party that contests an identity cut its transport.

**A reader MUST NOT route to a relay URL from a cached copy past the caching bound** of §9.10.7: it re-resolves, and where it cannot it reports the identity as unroutable. A stale service record loses an identity its reachability and costs it none of its key state, because key state comes from the log.

**What changing the record costs, and what it does not.** A relay-endpoint change, a private-state relocation, and a capability-URI edit are each one service-record write signed by the designated operational key. Each appends no key event and changes no key state, so the root set stays cold across every change to an identity's transport configuration. KERI draws the same line: changing an endpoint is a reply record and not a key event. **This is the property the split exists to deliver.**

**What an attacker holding the designated key can and cannot do.** It can substitute the relay list and re-point traffic. It cannot empty the fallback set of a first-contact resolver, which takes the whole community relay list, and it cannot change a key, a key's condition, the witness set, or the designation itself. Re-pointing is fail-closed rather than a substitution of identity, because MLS group keys and not relay reachability enforce membership.

**The witness layer covers the key-event log alone and covers this record not at all** (`09-security-model.md` §9.7.4.3). What defends the record against a relay serving a genuine copy truncated to an older sequence is stated here and nowhere else: the record's own signature under the designated key, its monotonic sequence read against the reader's high-water mark, the first-contact floor above, and the caching bound above.

## 3.11 Identity Authentication for External Services (SCPID)

SCP identities can authenticate to services outside the protocol. A relying party, SCP-native or not, verifies that a request comes from the holder of one identifier without joining a context, understanding MLS, or running SCP infrastructure. It needs one capability: resolve an SCP identity's key-event log from an SCP relay and verify a P-256 signature.

This is analogous to "Sign in with Ethereum" (EIP-4361) but simpler: no blockchain state, no gas, no wallet abstraction. The identity's key-event log is the identity provider, self-certifying because the identifier is the digest of its inception event (`09-security-model.md` §9.6.1).

**Relationship to the protocol's own signed requests.** SCP already signs requests under `#active` for context reader authentication (§6.2.2B [no such section]) and for handle outlet requests (§22.3.1). SCPID extracts and generalizes this pattern into a standalone protocol that external services can implement without SCP SDK dependencies.

### 3.11.1 Protocol Overview

```
Client (identifier holder)             Relying Party (service)
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
       |  5. Resolve the identifier, verify sig |
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
    did:            Identifier, // the signer's identifier
    signing_key_id: String,   // the role that signed: "#active"
    nonce:          [u8; 32], // Echo of the challenge nonce
    audience:       String,   // Echo of the challenge audience
    signed_at:      u64,      // Unix timestamp (ms) when the client signed
    signature:      [u8; 64], // P-256 signature (r || s) over the signed content
}
```

**Signed content construction:**

The signed content follows the §9.5.1 canonical hash construction: SHA-256 of domain-separated, length-prefixed fields. The P-256 signature is over the 32-byte hash, not the raw concatenation.

```
signed_bytes = SHA-256(
    "SCP-DID-AUTH-V1:"
    || BE32(len(did))              || did              // the signer's identifier, UTF-8
    || BE32(len(signing_key_id))   || signing_key_id   // "#active", UTF-8
    || nonce                                            // 32 bytes, fixed (no length prefix per §9.5.1)
    || BE32(len(audience))         || audience          // audience URI, UTF-8
    || signed_at as u64 BE                              // 8 bytes, big-endian
)
signature = P256_ECDSA_sign(private_key, signed_bytes)   // RFC 6979 nonce, low-s
```

**SCPID signed content field order:**

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `did` | 4-byte BE length prefix + UTF-8 bytes |
| 2 | `signing_key_id` | 4-byte BE length prefix + UTF-8 bytes |
| 3 | `nonce` | 32 bytes raw (fixed-length, no prefix per §9.5.1) |
| 4 | `audience` | 4-byte BE length prefix + UTF-8 bytes |
| 5 | `signed_at` | 8-byte big-endian u64 |

**This preimage takes the identifier as UTF-8 bytes, so it waits on the textual form `09-security-model.md` §9.7.4.2 R13 defers**, and `09-security-model.md` §9.5.2 states that deferral once and enumerates every signed structure that waits on it, this one included. The domain separator `"SCP-DID-AUTH-V1:"` prevents cross-protocol signature reuse. The SHA-256 wrap aligns with the majority SCP signing pattern (InnerEnvelope, BroadcastEnvelope, sender keys, access keys, sync structures, claims). The `did` and `signing_key_id` fields bind the signature to the signer's identifier and to the role that produced it, so a relying party cannot be shown a signature transplanted from another identity or presented under a role that did not sign.

**Signing key and signing identity:**

- `#active` — the identity's one operational signing key (`09-security-model.md` §9.7.4.2 definitions). A human identity signs an SCPID response under it, and the custody substrate holding it supplies whatever local gate it offers, such as a biometric prompt.
- A delegated agent identity signs its own SCPID responses under its own `#active`. A relying party tells an agent from a human by the responding identifier and never by a fragment, because a delegated identity's key state names the delegator that anchors it (`09-security-model.md` §9.7.4.2 definitions). The delegation model states how a verifier checks that anchor, and it is unspecified as of 2026-09-10 (`00-open-questions.md`), so a verifier rejects every chain that claims delegation and no delegated agent identity resolves today.

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
      §9.7.4.2 R8). Resolution yields key state and nothing else
      (`09-security-model.md` §9.6.1).
   c. Cache policy: the key state MUST be fresh — resolved within the last
      300 seconds. A stale key state MUST trigger a fresh resolution.
6. Read the public key the key state lists `current` in the role
   signing_key_id names.
7. Confirm signing_key_id is "#active". Reject any other value
   with KEY_NOT_AUTHORIZED. A human identity's key state names one
   operational role (`09-security-model.md` §9.1 invariant 1), so
   "#active" is the only role a relying party accepts here.
8. Confirm the key state lists that key `current`
   (`09-security-model.md` §9.7.4.2 definitions). Reject if not.
9. Reconstruct signed_bytes from did, signing_key_id, nonce, audience,
   signed_at per §3.11.3 (SHA-256 of canonical concatenation).
10. Verify the P-256 ECDSA signature (FIPS 186-5, low-`s` enforced) over
    signed_bytes using the extracted public key.
11. If all checks pass: the request is authenticated as originating from
    the holder of the key the key state lists `current` in the role
    signing_key_id names.
```

**Error responses.** The relying party SHOULD return structured errors:

| Condition | Error | Code |
|-----------|-------|------|
| Nonce unknown, mismatched, or expired | `CHALLENGE_EXPIRED` | `SCP-IDENT-1030` |
| Audience mismatch | `AUDIENCE_MISMATCH` | `SCP-IDENT-1031` |
| `signed_at` outside challenge window or challenge expired | `TIMESTAMP_INVALID` | `SCP-IDENT-1032` |
| Resolution failed | `DID_RESOLUTION_FAILED` | `SCP-IDENT-1033` |
| `signing_key_id` is not `#active` | `KEY_NOT_AUTHORIZED` | `SCP-IDENT-1034` |
| Signature verification failed | `SIGNATURE_INVALID` | `SCP-IDENT-1035` |
| Key state stale (> 300s, refresh failed) | `KEY_STATE_STALE` | `SCP-IDENT-1036` |
| Key custody or signing operation failed | `SIGNING_FAILED` | `SCP-IDENT-1037` |
| Input validation failure | `INVALID_INPUT` | `SCP-IDENT-1038` |

**Error response guidance.** Relying parties SHOULD NOT return specific error codes to untrusted clients. Return a generic failure (e.g., HTTP 401 with `"authentication_failed"`) for all verification failures. Specific `SCP-IDENT-103x` codes are for server-side logging and debugging only. Exposing which step failed provides a verification oracle that helps an attacker enumerate valid identifiers and probe key configurations.

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
  "did": "<the signer's identifier, in the textual form 09-security-model.md §9.7.4.2 R13 defers>",
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

**Replay prevention.** The nonce is single-use. The relying party MUST track issued nonces and reject any nonce presented more than once, and it MAY prune a nonce after `expires_at`, because it rejects an expired challenge whatever the nonce state says. A relying party spread over several server instances MUST hold that nonce store in a strongly-consistent data store, such as Redis with NX-SET or a database with a unique constraint, because an eventually-consistent store accepts one nonce twice. Alternatively, bind the challenge to a specific server instance using HMAC: `nonce = HMAC-SHA-256(server_secret, random_bytes || issued_at)`, verified without shared state. In this case, the relying party reconstructs the `ScpIdChallenge` from the HMAC nonce and stored parameters before passing it to `scpid_verify`.

**Audience binding.** The `audience` field is included in the signed content. A signature produced for `https://app-a.example.com` does not verify for `https://app-b.example.com`. This prevents cross-service signature relay attacks where an attacker presents a legitimate signature obtained from one service to another. Audience comparison MUST be exact byte-for-byte string comparison, not URI normalization. The relying party MUST publish its canonical audience URI and the client MUST use it verbatim. This matches the OIDC `aud` claim comparison model.

**Timestamp freshness.** The `signed_at` timestamp must fall within the challenge's validity window (`issued_at` <= `signed_at` <= `expires_at`). This bounds the useful lifetime of a stolen challenge to the challenge's expiry window.

**No bearer tokens.** The protocol does not produce a bearer token. Each authentication is a fresh challenge-response cycle. Session management (issuing a JWT, setting a cookie, etc.) is the relying party's responsibility and is explicitly outside this protocol's scope. A compromised session token therefore does not compromise the identity, because re-authentication requires the private key.

**Key compromise recovery.** Where `#active` is compromised, the standing root signs a `KeyState` (`09-security-model.md` §9.7.4.2 R3) whose key list carries a fresh `#active` `current` and does not carry the compromised key at all, and a verifier reads that key's condition by replaying the log (`09-security-model.md` §9.7.4.2 R8, §9.12). After the rotation the old key is no longer `current`, so verification step 7 rejects its signatures, and content it signed is accepted only under §9.7.1's boundary rule. Recovery latency is bounded by key-event-log propagation to the identity's relays and by the 5-minute resolution-freshness bound of §9.7.1 check 2.

**MITM resistance.** SCPID does not provide channel binding. If the transport between client and relying party is compromised (no TLS), an attacker can intercept and replay the challenge-response in real time. Relying parties MUST serve challenges and accept responses over TLS. The audience field mitigates relay attacks across services but does not replace transport-layer encryption.

**Agent vs. human distinction.** The responding identity tells the relying party whether a human or an agent signed the challenge: a human identity signs under its own `#active`, and an agent signs under the `#active` of its own delegated identity, whose key state names the human identity that anchors it (`09-security-model.md` §9.7.4.2 definitions). The `did` field is inside the signed content (§3.11.3), so the distinction is cryptographically authenticated. The relying party can enforce authorization policies on it — requiring a human identity for destructive operations and accepting a delegated agent identity for routine API access. **No delegated agent identity resolves today**, because `09-security-model.md` §9.7.4.2 R3 rejects every chain whose `delegator` field is nonzero until the delegation model is specified, which it is not as of 2026-09-10 (`00-open-questions.md`), so this paragraph states the distinction that model will carry.

### 3.11.7 Relationship to Context Membership

SCPID and context membership are independent authentication mechanisms for different purposes:

| | SCPID | Context membership |
|---|---|---|
| **Proves** | Control of an identity's `#active` key | Membership in an MLS group |
| **Scope** | Per-request, stateless | Persistent, epoch-based |
| **Use case** | HTTP APIs, webhooks, external services | Protocol operations within a context |
| **Requires SCP SDK** | No (key-state resolution and P-256 ECDSA) | Yes (MLS, key packages, group state) |
| **Session state** | None (relying party's concern) | MLS epoch (protocol-managed) |

An SCP-native app will typically use **context membership** for protocol operations (messaging, governance, outlet invocation) and **SCPID** for HTTP API endpoints (REST APIs, webhooks, OAuth callbacks) that need to authenticate requests from identifier holders outside the MLS channel.

### 3.11.8 SDK API Surface

The SDK provides functions for all three protocol roles. SCPID operations use `ScpIdError` rather than `IdentityError`, which keeps protocol-level authentication errors separate from the identity layer's own concerns, resolution and key management. This avoids polluting `scp-identity`'s error type with SCPID-specific variants.

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
/// Sign an SCPID challenge under the named operational role.
///
/// Constructs signed_bytes per §3.11.3 (SHA-256 of canonical concatenation
/// including did and signing_key_id), signs with P-256 ECDSA, returns the response.
pub async fn scpid_sign(
    custody: &impl KeyCustody,
    signing_key: &KeyHandle,
    did: &str,
    signing_key_id: SigningKeyId,  // Active — the identity's one operational role
    challenge: &ScpIdChallenge,
) -> Result<ScpIdResponse, ScpIdError>;
```

**Response verification (relying party):**

```rust
/// Verify an SCPID response against the original challenge.
///
/// Performs the full 11-step verification procedure (§3.11.4): nonce match,
/// audience match, timestamp window, key-state resolution, key extraction,
/// signing_key_id constraint, condition check, signed_bytes reconstruction,
/// and P-256 signature verification.
///
/// The caller MUST ensure the challenge has not been previously consumed
/// (single-use enforcement). The function checks the response against the
/// challenge but does not track cross-request nonce state.
pub async fn scpid_verify(
    backend: &dyn IdentityBackend,
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
3. A P-256 ECDSA signature verifier (FIPS 186-5) that rejects a high-`s` signature.
4. JSON parsing.

That list is the whole dependency set, so a service with no other relationship to SCP can implement verification.

### 3.11.9 Implementation Notes for Non-SCP Relying Parties

A service that wants to accept SCP identity authentication without running SCP software:

1. **Key-state resolution.** QUERY the identity's routing ID, `SHA-256("scp:did:" || identifier_bytes)`, on the SCP relays the identity's service record lists (§3.10.13) and on the community relays of §18.5.1; each stored blob is a key-event record frame (§9.10.12) whose `value` carries a segment of the identity's key-event log. Assemble the chain, recompute the identifier from its inception event, verify every event, and derive the key state from the latest state-carrying event (§9.6.1). A relying party that holds no prior chain for the identity reads two relays under distinct declared operators, one of them in the fallback set (`09-security-model.md` §9.7.4.2 R11). For SCPID verification, a resolved key state MUST be cached for no more than 300 seconds. The general §3.10.4 caching policy (24h/7d) does NOT apply to SCPID verification — authentication requires current key state.

2. **Reading the key from the key state.** The key state lists every key `current` at the adopted position, by role and by condition, and lists no other key (`09-security-model.md` §9.7.4.2 definitions). Match `signing_key_id` to the role the key state names, confirm the key state lists that key `current`, and read its 33-byte SEC1 compressed P-256 public key. A relying party needing an earlier key's condition replays the log instead (`09-security-model.md` §9.7.4.2 R8). It parses no identity document and needs none, because the protocol publishes an identity's keys in the key-event log alone (ADR-063, the inception-derived key-event-log identity substrate).

3. **Signature verification.** Reconstruct `signed_bytes` per §3.11.3: concatenate the domain separator `"SCP-DID-AUTH-V1:"`, length-prefixed `did`, length-prefixed `signing_key_id`, raw 32-byte `nonce`, length-prefixed `audience`, and 8-byte big-endian `signed_at`. Compute SHA-256 of the concatenation. Verify the P-256 ECDSA signature over the resulting 32-byte hash, rejecting a high-`s` value (`09-security-model.md` §9.5). Standard libraries: `ring` and `p256` (Rust), the Web Crypto API's `ECDSA` with `P-256` (JS), `cryptography` (Python), and CryptoKit's `P256.Signing` (Swift).

4. **Nonce management.** Store issued nonces with their `expires_at`. Reject duplicates. Prune expired entries. For distributed deployments, use a strongly-consistent store or HMAC-based nonce generation (§3.11.6).

No SCP SDK, no MLS, and no context management. The verification path is: two relay QUERYs, the chain verification of §9.6.1, one JSON parse, one SHA-256, and one P-256 verify.
