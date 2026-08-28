# ADR-063: Context-Declared User-Authentication Gate

**Status:** Proposed (2026-08-28). The §Open questions section names the four questions a human answers before this ADR moves to Accepted, and §Decision 5 states what a verifier does until then.

**Extends:** ADR-039 (shared-DID human-agent identity model, `.docs/adrs/phase-1.md:1231`), whose Permission Model section carries four Category C mechanisms. This ADR adds a fifth.

**Relates to:** ADR-006 (platform abstraction traits, `.docs/adrs/phase-1.md:1017`) declares the `DeviceAttestation` trait. ADR-021 (UniFFI bridge, `.docs/adrs/phase-4.md:855`) declares the `DeviceAttestationProvider` callback interface. ADR-025 (Apple platform adapter, `.docs/adrs/phase-5.md:381`) decides Apple's `BiometricPolicy`. ADR-027 (Android platform adapter, `.docs/adrs/phase-6.md:217`) decides `AndroidDeviceAttestation`. Specs: §4.9.3 of `.docs/specs/04-agents.md`, §5.3.1 and §5.7 and §5.9 of `.docs/specs/05-contexts.md`, §9.3 of `.docs/specs/09-security-model.md`, §27.3.4 and §27.4.4 of `.docs/specs/27-attestations.md`.

## Context

A context declares its capability ceiling, its roles, its governance model, and a set of parameters that bound what happens inside it (§5.3, §5.5, §5.9 of the contexts spec). ADR-039 adds four of those parameters under the name Category C: `agent_keys_allowed`, an agent-restricted role, `agent_rate_limit`, and `agent_cosign_required` (`.docs/adrs/phase-1.md:1288`). A context that wants a human to authenticate on a device before a member exercises a named capability has no parameter to say so.

**The request.** Alec asked for one, verbatim on 2026-08-28: "I would like for SDKs, and more specifically, contexts, to be able to specify which actions require biometric gating if they so choose."

**Two earlier rulings bound the shape.** Alec ruled out a per-action gesture as a default, verbatim: "having to auth every action biometrically is not going to fly. so platform." He also ruled that the protocol does not choose custody for a participant, verbatim: "just let users decide" and "LET PEOPLE CHOOSE."

**A declaration that nothing checks is a false guarantee.** The "no dev/test-only stand-ins in production" tenet of `CLAUDE.md` states the reason: "Masking a missing production backend with a dev construct ships a *false guarantee*, which is strictly worse than the capability being honestly absent (absence is detectable; a nullifier lies)." A context parameter that every SDK may ignore is that shape. So the parameter is worth adding only when a verifier can check the action against something the action's signer cannot forge.

**What the shipped code offers a verifier, checked before this ADR was written.** Four findings decide the design:

1. **The per-request assertion has no verifier.** `DeviceAttestationProvider::assert_request(request_hash) -> Vec<u8>` is declared once (`crates/scp-ffi/uniffi/src/lib.rs:573`), and a workspace search finds `DeviceAttestationProvider` in exactly two places — that declaration and a module doc comment (`crates/scp-ffi/uniffi/src/lib.rs:36`). No Rust code calls `assert_request`, and the trait declares no verification method. §27.3.3 of the attestations spec derives the same absence and its open question OQ-22 records it.

2. **Neither vendor's assertion reports that a person authenticated.** Apple documents `DCAppAttestService.generateAssertion` as producing "a block of data that demonstrates the legitimacy of an instance of your app running on a device", and the decoded object Apple publishes carries a signature and an authenticator-data block holding a relying-party identifier and a counter. Google's Play Integrity verdict carries `requestDetails`, `accountDetails`, `appIntegrity`, `deviceIntegrity`, and `environmentDetails`, and Google defines the `deviceIntegrity` verdict `MEETS_DEVICE_INTEGRITY` as "The app is running on a genuine and certified Android device." Neither vendor documents a biometric field or a user-presence field. The Android adapter states the same conclusion in its own code: `assertRequest` returns a fresh Play Integrity token because "Play Integrity does not have a per-request assertion flow equivalent to App Attest assertions" (`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidDeviceAttestation.kt:117`), and its body calls `attest` with the request hash as the challenge (`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidDeviceAttestation.kt:130`).

3. **Two of the three verification paths a per-request assertion would need are closed to a peer.** §9.3 of the security spec records both: "Play Integrity requires Google's servers, introducing an operator dependency the protocol otherwise avoids", and "App Attest is per-bundle-ID, but SCP is a protocol, not an app — different SCP apps on one device get different attestation keys" (`.docs/specs/09-security-model.md:187`). A peer running a different SCP app holds no public key against which to check an App Attest assertion, and the "protocol requires no operator" tenet of `CLAUDE.md` forbids routing verification through Google.

4. **One primitive does carry a user-authentication policy to a remote reader, on one platform.** An Android Key Attestation certificate's `KeyDescription` extension encodes `noAuthRequired`, `userAuthType`, and `authTimeout`; the Trusted Execution Environment signs the enclosing chain; and a reader validates that chain without contacting a server. `AttestationPlatform::AndroidKeyAttestation` is the variant `PlatformAttestation` already names for that chain (`crates/scp-did/src/attestation.rs:130`). Apple publishes no counterpart: Apple writes of the `biometryAny` access-control flag that including it instructs "the system to make the key available only when the system can authenticate the user with Touch ID or Face ID (or a fallback passcode)", which constrains the local system, and Apple documents no certificate through which a remote reader learns which flags a key carries.

**Finding 2 decides what this feature may be called.** No shipped primitive proves to a remote verifier that a biometric gated an operation. The strongest remotely-checkable claim is that the signing key's platform requires a user-authentication gesture, and only Android's `userAuthType` distinguishes a fingerprint from a passcode. This ADR therefore names the parameter for user authentication rather than for a biometric. The narrowing is this ADR's, not Alec's; Alec asked for biometric gating, and open question 2 carries the modality question to him.

## Decision

### 1. A fifth Category C mechanism, `user_authentication_required`

A context declares `user_authentication_required` on `ContextParams`: the list of capabilities a member may exercise only when the verification method that signed the action holds a key the platform releases to a signer who has just passed a device-local authentication gesture. The default is the empty list. §4.9.3 of `.docs/specs/04-agents.md` states the normative rule; this ADR records why the rule takes that shape.

### 2. The granularity is a capability

The parameter holds `Vec<Capability>` — the type `crates/scp-protocol/src/context/roles.rs:74` declares, whose 21 built-in variants §5.3.1 of the contexts spec enumerates and whose custom entries §5.3.1.1 admits.

Four candidate vocabularies exist and three of them cannot express what a context needs to say:

- **`ActionCategory`** (`crates/scp-protocol/src/trust/custody_violation.rs:84`) carries two variants and classifies by the `{resource}` segment of a capability URI alone, so it cannot separate `governance:vote` from `governance:propose`. It also has no `CategoryC` variant and takes none: §4.9.3 states that Category C partitions nothing and is a second axis.
- **A role name** names a capability bundle that a context assigns to a member (§5.5), and a member holds one role, so a role says which capabilities a member has and cannot say which of them need a gesture. Expressing the gate through roles would need one role per gated subset of the member's capabilities, and §5.5.1 already assigns the four built-in roles by function rather than by custody.
- **A boolean** contradicts Alec's ruling that authenticating every action "is not going to fly."
- **`Capability`** is the vocabulary the ceiling holds, a role grants, a UCAN attests, and §5.3.1's "Gated by" column ties governance actions to. `Capability::new` is the single canonical parser, which §5.3.1.1 names as the mechanism that closes the ceiling grammar by construction, so a `Vec<Capability>` inherits that closure and admits no spelling the ceiling would reject.

`agent_cosign_required` already holds `Vec<Capability>` for the same reason (§4.9.3), so a fifth mechanism using anything else would introduce a sixth vocabulary into a section that has five.

### 3. The parameter lives on `ContextParams` and in structural metadata

`agent_keys_allowed`, `agent_rate_limit`, and `agent_cosign_required` are specified as `ContextParams` fields projected into the structural metadata §5.7 of the contexts spec makes visible before joining, and changed through the `metadata:edit` governance path §5.9 describes. `user_authentication_required` takes the same three placements.

Structural metadata is required rather than convenient. A member on macOS, Linux, or Windows cannot satisfy this parameter at all — §9.3 of the security spec records that those three platforms have "no App Attest or Play Integrity equivalent" (`.docs/specs/09-security-model.md:189`) — so a member who could not read the list before joining would consent to a context that silently forecloses capabilities to them. The "legibility before opt-in" tenet of `CLAUDE.md` forbids that.

### 4. The exclusion binds per action, not at admission

A member whose platform attests no user-authentication policy joins the context and never exercises a listed capability. Three facts decide against an admission-time exclusion:

- **A DID names a keypair, not a device.** §9.3 of the security spec states: "The protocol cannot distinguish hardware at the network level; a DID is a keypair, and the protocol sees bytes, not devices" (`.docs/specs/09-security-model.md:187`). A member admitted from a phone signs from a laptop an hour later, so an admission-time check certifies a property that has stopped holding by the time the action arrives.
- **A member may lawfully change the checked property after admission.** §3.2.1 of the identity spec specifies custody migration, which moves `#active` between custody providers without changing the DID.
- **The parameter names capabilities, not members.** A member who holds `messages:write` and `governance:vote` in a context that lists only `governance:vote` keeps the first and loses the second. An admission-time rejection takes both, which is a wider restriction than the context declared.

The one admission-time gate that exists cannot carry the exclusion in any case: `evaluate_sybil_resistance` satisfies `policy.require_device_attestation` when `assessment.signals` contains the `DeviceAttestation` key (`crates/scp-protocol/src/trust/sybil.rs:773`), with no token, no signature, and no DID binding. §27.4.3 of the attestations spec records that as contradiction C9.

### 5. The verifier fails closed until the proof it reads exists

A conformant verifier rejects every listed capability today. `ScpKeyCustodyAttestation`'s writer `DidDocument::set_custody_attestation` (`crates/scp-did/src/document.rs:671`) has no production caller, which §27.4.4 of the attestations spec derives and its open question OQ-23 records. The `platform_attestation` field is "Opaque to the protocol — verification is platform-specific" (`crates/scp-did/src/attestation.rs:53`) and no artifact states a verification procedure for it. All three bridges answer a device-attestation verification request with the typed error `SCP-IDENT-1016` (`crates/scp-ffi/src/identity.rs:985`, `crates/scp-ffi/uniffi/src/bridge.rs:4042`, `crates/scp-ffi/napi/src/scp.rs:4640`), and issue #2171, the production device-attestation backend, tracks the work that replaces those errors with a verifier.

Reading `KeyCustodyModel::HardwareBiometric` as satisfied while the attestation carries no verifiable proof would accept a caller-asserted enum value as a security guarantee. That is the shape the "no dev/test-only stand-ins in production" tenet forbids, and the shape `require_device_attestation` already exhibits.

## Rationale

- **A context parameter that a verifier checks is worth adding; one that it cannot check is not.** The four findings above rule out the per-request assertion path and leave the custody-attestation path, so this ADR takes the second and says what the first cannot do.
- **Matching `agent_cosign_required`'s shape keeps §4.9.3 readable.** Both mechanisms name capabilities, sit on `ContextParams`, project into structural metadata, and change through `metadata:edit`. A reader who has read one has read the frame of the other.
- **Per-action exclusion states the truth about what the protocol can observe.** The protocol observes a signature and a DID document; it does not observe a device. An admission-time gate would claim an observation the protocol never makes.
- **Failing closed keeps the absence detectable.** A context that sets the parameter today gets capabilities no member exercises, which an integration test observes. A verifier that accepted the self-declared enum would give the context a guarantee no device enforces, and nothing would observe the difference.

## Rejected alternatives

**A per-action assertion carried on the inner envelope, verified against the signer's device attestation.** This is the shape `agent_cosign_required` uses for the human co-signature, and it does not transfer. Finding 2 shows the assertion carries no evidence of a gesture on either platform. Finding 3 shows a peer cannot verify an App Attest assertion produced by a different SCP app, and cannot verify a Play Integrity token without Google. Adding the field would give a verifier bytes it cannot turn into a verdict.

**A boolean `biometric_required` on `ContextParams`.** Rejected against Alec's ruling that authenticating every action "is not going to fly," and against §5.3.1's capability vocabulary: a boolean names no action, so a context could not gate `governance:vote` while leaving `messages:write` alone.

**Excluding the member at admission.** Rejected on the three facts in §Decision 4. The strongest of the three is that the property is not stable for the member's lifetime in the context, so an admission-time verdict is a claim about the past.

**Naming the parameter for a biometric.** Rejected on finding 2. No shipped primitive proves a biometric to a remote verifier, and Android's `userAuthType` is the only attested field that distinguishes a fingerprint from a passcode. A parameter named for a biometric would state a guarantee that the value a verifier reads does not carry.

**Adding a fourth verification method to the DID document, bound to an authentication-gated key.** Rejected because ADR-039 fixes the key set at `#0`, `#active`, and `#agent` and states the structural constraint "Exactly one `#agent` verification method per DID document" (`.docs/adrs/phase-1.md:1273`), and because ADR-039 states a document-size constraint against adding keys: "DID documents are already ~1,140 bytes with 2 VMs (BEP44 v1 payload limit is 1,000 bytes, requiring bencode packing)" (`.docs/adrs/phase-1.md:1275`). Widening the key set is a decision for ADR-039 rather than for an ADR downstream of it. Open question 3 records the consequence: a single `#active` custody policy governs every `#active` signature, so a context cannot ask for a gesture on one capability and not another through custody alone.

## Open questions

§4.9.3 of `.docs/specs/04-agents.md` states all four in full, with the artifact that should decide each and what breaks while each stays open. In brief:

1. Does the protocol permit a context to penalize the absence of a device-attested custody policy? §9.3 of the security spec says the absence "is not penalizing" with no scope limit; this parameter penalizes it inside one context. §9.3 governs this ADR under the artifact flow, so §9.3 changes first or the parameter does not ship.
2. May a context require an authentication modality, and what does a context get from a member on Apple hardware?
3. Does the custody attestation state a per-signature requirement or an authentication window, and which does this parameter require?
4. Does Category C cover a restriction that binds `#active`? ADR-039 defines it as restricting "agent actions."

Question 1 can invalidate the whole mechanism, which is why this ADR's status is Proposed. Issue #2417 carries all four to a human, and stories SCP-AB-037 and SCP-AB-038 of `.docs/prds/agent-binding.json` name that issue in `blockedByIssues`, so no implementation starts before the answers land.
