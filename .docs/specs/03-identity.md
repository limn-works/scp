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

The identity layer abstracts custody. The user authenticates however they choose; under the hood it resolves to a protocol-level DID. Migration between custody methods is possible without changing identity, using the key custody migration protocol (§3.2.1). §3.2.2 states the two values a caller names when it selects a custody backend, and states what a DID document publishes about custody.

### 3.2.1 Key Custody Migration Protocol

Custody migration moves the operational signing capability from one custody provider to another (e.g., Secure Enclave to hardware security key, or passkey to self-managed key) without changing the identity (DID string). The Identity Key (`#0`) remains the root of trust throughout.

**Two cases:**

1. **Active Signing Key migration (common).** The Active Signing Key (`#active`) is rotatable by design (ADR-003 §4a). Migration generates a new `#active` key in the target custody provider and publishes an updated DID document signed by `#0`. The old `#active` key is revoked. The DID string does not change because it is derived from `#0`, not `#active`. This is the standard `rotate_active_key` operation applied to a custody change rather than a compromise.

2. **Identity Key migration (rare).** If `#0` itself must move (e.g., the Secure Enclave device is being decommissioned and the key cannot be exported), the pre-rotation key mechanism (ADR-003 §4b, §9.12) is used. This creates a new DID — identity continuity is maintained through the `alsoKnownAs` forwarding record and the `DidRotationEvent` sent to all active contexts. The pre-rotation proof cryptographically binds the old identity to the new one.

**Migration protocol (case 1 — Active Signing Key):**

```
1. INITIATE on target device:
   a. Generate new Ed25519 keypair in target custody provider.
   b. Create CustodyMigrationRequest:
      - new_active_pubkey: [u8; 32]
      - target_custody_type: enum { encrypted_file, os_keystore }   // §3.2.2
      - requested_at: u64 (Unix timestamp)

2. AUTHORIZE on device holding #0:
   a. Verify the migration request was initiated by the identity owner
      (device-local authentication — biometric, PIN, or platform credential).
   b. Construct updated DID document:
      - Replace #active verification method with new_active_pubkey.
      - Retain #0 and #agent (if present) unchanged.
      - Increment BEP44 sequence number.
   c. Sign DID document with #0 (Identity Key).

3. PUBLISH:
   a. Publish updated DID document to both resolution layers (§3.10.5).
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
   a. After confirmation that the new DID document has propagated
      (verified by resolving from at least one relay and DHT),
      the old #active private key is destroyed in the source custody provider.
   b. Destruction is best-effort for HSM-backed keys (the HSM may not support
      explicit deletion, but the key becomes inaccessible once the device
      is decommissioned).
```

**Failure semantics:**

- **Step 2 fails (authorization denied):** No state change. The old custody provider remains active. The new keypair generated in step 1 is discarded.
- **Step 3a fails (publication fails on some relays/DHT):** The SDK retries publication. The RepublishManager (§3.10.5) will propagate on its next cycle. Partial publication is safe — peers that resolve the old document continue to work; peers that resolve the new document use the new key. Both are valid until the old key is destroyed.
- **Step 3b/3c fails (MLS Update or UCAN reissuance fails in some contexts):** The SDK queues failed operations for retry. Contexts that have not received the Update continue to verify messages against the old `#active` key (still in the previously-resolved DID document). The migration converges as retries succeed.
- **Step 5 fails (old key destruction fails):** The migration is still complete — the DID document references the new key. The old key is orphaned but harmless: UCAN tokens signed by it are revoked, and peers verify against the new DID document.

**Multi-device coordination:** If the identity owner has multiple devices (e.g., phone + laptop + tablet), each device holds its own key material for signing. Custody migration affects only the `#active` key published in the DID document — the single authoritative signing key. Other devices learn of the migration by resolving the updated DID document (§3.10.4). After migration, only the device with the new custody provider can sign as `#active`. Other devices that need signing capability must independently generate keys and request delegation via scoped UCANs from the new `#active` key holder.

**Invariant:** At no point during migration are there zero valid signing keys for the identity. The old key remains valid until the new DID document propagates. The new key becomes valid upon publication. The overlap window ensures continuity.

### 3.2.2 The Custody Vocabulary

Two vocabularies name key custody, and they name different things. A caller selecting custody names a backend. A DID document publishing custody names what a stranger reading that document needs, which is whether the key can leave its store and which factor unlocks it. This subsection states both vocabularies, states that a caller writes no published value, and answers open question OQ-9 of §3.9.9.

Every claim below cites the artifact that states it. A sentence marked *Derivation:* draws a conclusion here from the cited artifacts, and it carries no authority those artifacts do not already carry. §3.2.2.1 lists the places where two artifacts state claims that cannot both hold, continuing the numbering of §3.9.8. §3.2.2.2 lists the questions this subsection does not answer, continuing the numbering of §3.9.9.

**The request side names the backend.** A caller that creates an identity names exactly one of two custody values. The vocabulary holds no third value, and a shipped build answers every other string with a typed error.

| Value | Backend it selects |
|-------|--------------------|
| `encrypted_file` | The on-disk key store SCP implements, which derives an AES-256 key from a passphrase with Argon2id and encrypts each key entry under AES-256-GCM (`crates/scp-platform/src/file.rs:1`–`:6`) |
| `os_keystore` | The operating system's own key store, which SCP reaches through the platform key-custody callback an SDK consumer supplies |

A caller choosing custody is choosing a backend, and SCP dispatches to backends it does not own — Apple Keychain and Android Keystore among them (`.docs/specs/17-persistence-and-storage.md:666`–`:667`). The two values name those backends.

*Derivation:* the criterion reaches every field in which a caller names a custody backend, and not only the argument to identity creation. `CustodyMigrationRequest.target_custody_type` in §3.2.1 above is such a field, so it carries these two values and no others.

**`platform` is not a value in this vocabulary.** Two published specifications give that word two meanings in key handling, and neither meaning is the one two SCP SDKs took it for.

W3C Web Authentication Level 3 gives it a transport meaning. §5.4.5, "Authenticator Attachment Enumeration", declares `enum AuthenticatorAttachment { "platform", "cross-platform" };` (<https://www.w3.org/TR/webauthn-3/>). §6.2.1, "Authenticator Attachment Modality", defines the first member: "A platform authenticator is attached using a client device-specific transport, called platform attachment, and is usually not removable from the client device." The axis is which transport reaches the authenticator, so two clients classify one authenticator differently. §6.2.1 states that case: "a platform authenticator integrated into a mobile device could make itself available as a roaming authenticator via Bluetooth. In this case clients running on the mobile device would recognise the authenticator as a platform authenticator, while clients running on a different client device and communicating with the same authenticator via Bluetooth would recognize it as a roaming authenticator." *Derivation:* a word whose value depends on which client is asking cannot name a key store, so this meaning is not available to a custody vocabulary.

Windows CNG gives the same word to the Trusted Platform Module. Microsoft's `NCryptOpenStorageProvider` reference gives the provider-name row as "MS_PLATFORM_CRYPTO_PROVIDER — L"Microsoft Platform Crypto Provider" — Identifies the TPM key storage provider that is provided by Microsoft." (<https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider>).

**`software` is not a value in this vocabulary, and no in-memory value belongs to it.** In-memory key custody stays gated to test builds. `crates/scp-platform/src/lib.rs:61`–`:68` places `InMemoryKeyCustody` in a module the `testing` cargo feature guards, calls that module's contents "Test-only nullifier doubles", and states why the gate is not the `software_platform` feature: "production mobile builds can enable `software_platform` (for crypto primitives) without compiling in insecure in-memory key storage."

A build compiled with the `testing` cargo feature additionally accepts the string `in_memory` at the bridge, which reaches that test-only backend. That string is a test-harness affordance and not a value of this vocabulary: no SDK enum spells it, a test that needs it passes the raw string to the bridge, and a shipped build rejects it with the typed code `SCP-IDENT-1008`.

*Derivation:* `software` fails the criterion this vocabulary applies, which is that a value names the backend it selects. The word states a property a backend lacks — hardware isolation — and names no store, so a caller reading it cannot tell which shipped backend it reaches. On Apple platforms both values in the table above hold key material that §17.8 of the persistence spec calls software-backed (`.docs/specs/17-persistence-and-storage.md:666`), so `software` would not separate them.

**Evidence that a request-side vocabulary names a substrate.** Each system below dispatches to key stores it does not own, and each names its request-side values after the substrate. These are instances that support the criterion stated above, and they do not replace it.

Java's `KeyStore` takes a type string and states, in the class documentation, that the string settles neither persistence nor mechanism: "Whether keystores are persistent, and the mechanisms used by the keystore if it is persistent, are not specified here. This allows use of a variety of techniques for protecting sensitive (e.g., private or secret) keys. Smart cards or other integrated cryptographic engines (SafeKeyper) are one option, and simpler mechanisms such as files may also be used (in a variety of formats)." (<https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html>). Its standard type strings name formats and substrates rather than security properties: the Java Security Standard Algorithm Names document lists `jceks`, `jks`, `dks`, `pkcs11`, and `pkcs12` under "KeyStore Types", giving `jks` as "The proprietary keystore implementation provided by the SUN provider." and `pkcs12` as "The transfer syntax for personal identity information as defined in PKCS #12." (<https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html>), and the JDK Providers document adds the macOS type under "The Apple Provider", whose `KeyStore` engine name is `KeychainStore` and which "provides access to the macOS Keychain" (<https://docs.oracle.com/en/java/javase/21/security/oracle-providers.html>).

Apple's Security framework names the store in `kSecAttrTokenID`, "A key whose value indicates that a cryptographic key is in an external store", whose documented value `kSecAttrTokenIDSecureEnclave` "Specifies an item should be protected by the device's Secure Enclave." (<https://developer.apple.com/documentation/security/ksecattrtokenid>, <https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave>).

HashiCorp Vault names its seal by the wrapping backend. The seal stanza takes a type — "The seal stanza configures the seal type to use for additional data protection, such as using HSM or Cloud KMS solutions to encrypt and decrypt the root key." (<https://developer.hashicorp.com/vault/docs/configuration/seal>) — and each backend has its own type string and its own page, among them `seal "pkcs11"` (<https://developer.hashicorp.com/vault/docs/configuration/seal/pkcs11>) and `seal "awskms"` (<https://developer.hashicorp.com/vault/docs/configuration/seal/awskms>).

OpenSSH names the substrate in the key type itself. `ssh-keygen`'s FIDO AUTHENTICATOR section states: "FIDO keys consist of two parts: a key handle part stored in the private key file on disk, and a per-device private key that is unique to each FIDO authenticator and that cannot be exported from the authenticator hardware. … Supported key types are ecdsa-sk and ed25519-sk." (<https://man.openbsd.org/ssh-keygen.1>).

**What `os_keystore` promises, and what it does not.** `os_keystore` states which store holds the key. It states nothing about hardware isolation, because on Apple platforms the operating system's key store holds SCP's keys in software. `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:217`–`:221` states the reason: "Apple's Secure Enclave only supports P-256 (NIST P-256 / secp256r1) key operations. SCP uses Ed25519 for signing and X25519 for key agreement; neither is supported by the Secure Enclave. All SCP identity keys on Apple platforms are therefore software-backed via Keychain." §17.8 of the persistence spec states the same in its iOS and macOS row: "Secure Enclave only supports P-256; Ed25519 keys are software-backed in Keychain" (`.docs/specs/17-persistence-and-storage.md:666`).

**A bridge that cannot reach a real platform key store fails closed.** When a caller names `os_keystore` and the bridge holds no platform key-custody callback, the bridge returns a typed error. It does not fall back to `encrypted_file`, and it does not fall back to an in-memory store. The no-dev-stand-in tenet of `CLAUDE.md` states the rule this applies: "If the real backend isn't built, the capability **fails closed** (a typed error, or an honest protocol-supported absent state) — it does NOT silently fall back to the dev stand-in."

**What this vocabulary governs, and what selects custody outside it.** These two values govern every place a caller names a custody backend across an FFI boundary. A binary that constructs a custody instance in its own code names no string: `crates/scp-node/src/main.rs:445` builds a `SqliteKeyCustody` over an encrypted SQLite database and hands it to the node builder. *Derivation:* a third shipped `KeyCustody` implementation therefore exists that this vocabulary does not name, and it needs no name here, because no caller selects it by string.

**The published side names extractability and the unlock factor.** The custody value a DID document publishes states two things: whether the key can leave the store that holds it, and which factor unlocks it. It states no storage location. A reader of that value is a stranger deciding whether to trust the participant, and that reader is deciding whether the key can leave.

**What the unlock factor may require.** Alec ruled on 2026-08-26, verbatim: "active generally would not go in hardware. it would go behind a passkey or something. having to auth every action biometrically is not going to fly. so platform. but what the hell just let users decide."

The criterion that ruling sets: an unlock factor that demands a fresh biometric reading for each signing operation is not viable for `#active`. §3.9.3 of this spec states what `#active` signs, quoting §9.7.4 of the security spec: "MLS KeyPackage attestations (§9.7.1), inner-envelope signatures, UCAN issuance". A participant produces those signatures continuously while using the protocol, so a factor that prompts once per signature stops them from using it.

*Indicators, not the test:* a factor a holder presents once per device unlock, and a factor a holder presents once per session, each satisfy the criterion; a factor that gates every call to `sign` does not. Those two cases are instances a reader meets. A backend outside both is judged against the criterion above rather than against them.

**The constraint binds what a custody value promises, and not which backend a participant may select.** Alec's own last clause is "just let users decide", and he ruled on 2026-08-25, verbatim: "LET PEOPLE CHOOSE. LIKE IS ALREADY FUCKING WRITTEN INTO THE GODDAMN PROTOCOL." The request-side vocabulary above therefore loses no value, and a participant selects either backend. *Derivation:* the criterion reaches the published side, where a value states an unlock factor a reader relies on, and it does not reach the request side, where a participant states a preference.

*Derivation:* this criterion is a second and separate reason to keep `#active` out of hardware on Apple. §3.2.2's `os_keystore` paragraph above gives the first, which is that the Secure Enclave holds no Ed25519 key. This one is independent of the curve: the shipped Apple adapter offers a mode the criterion excludes. `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:204`–`:213` states that under `BiometricPolicy.required` the Keychain item carries a `SecAccessControl` requiring `.biometryCurrentSet`, so "Face ID or Touch ID must authenticate before `sign`, `dhAgree`, or `derivePseudonym` can access the Keychain item" — one factor per signing operation. Open question OQ-14 of this spec asks what an adapter does when a participant selects that mode for `#active`.

**Evidence that extractability is the published property.** Four unrelated specifications name it, and each one puts it on the key rather than on the store.

PKCS#11 carries two attributes on private and secret key objects: "CKA_EXTRACTABLE — CK_BBOOL — CK_TRUE if key is extractable and can be wrapped" and "CKA_NEVER_EXTRACTABLE — CK_BBOOL — CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE" (PKCS #11 Specification Version 3.0, OASIS Standard, <https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html>).

W3C Web Cryptography Level 2 puts a boolean on `CryptoKey`: "extractable — Reflects the [[extractable]] internal slot, which indicates whether or not the raw keying material may be exported by the application." (<https://www.w3.org/TR/WebCryptoAPI/>). The same document states that the interface covers keys of every substrate, "pre-provisioned within software or hardware to which the user agent has access", which is what leaves extractability as the property the attribute reports.

Apple's Security framework carries `kSecAttrIsExtractable`, "A key whose value indicates the item's extractability." (<https://developer.apple.com/documentation/security/ksecattrisextractable>).

HashiCorp Vault carries `exportable` on a transit key: "exportable (bool: false) - Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled." (<https://developer.hashicorp.com/vault/api-docs/secret/transit>).

*Derivation:* the two irreversible attributes above move in opposite directions, so a rule stated over "extractability latches" without naming a direction is wrong for one of them. PKCS#11 latches `CKA_EXTRACTABLE` closed — the specification's `C_CopyObject` clause reads "a key's CKA_EXTRACTABLE attribute may be changed from CK_TRUE to CK_FALSE, but not the other way around" — and Vault latches `exportable` open. SCP's published value carries no latch, because it is recomputed from the backend in use on each publication.

**The three published values.** *Derivation:* the criterion above admits a value set and names none. The set below applies the criterion to the three custody models the published enum already separated, renaming each on the extractability-and-unlock-factor axis and taking the storage location out of each name. This mapping derives from the criterion; the criterion does not state it.

| Published value | Wire form | Replaces | What it states |
|-----------------|-----------|----------|----------------|
| `NonExtractableBiometric` | `non-extractable-biometric` | `HardwareBiometric` | The key cannot leave its store, and a biometric factor unlocks it |
| `NonExtractablePin` | `non-extractable-pin` | `HardwarePin` | The key cannot leave its store, and a knowledge factor — a PIN or a password — unlocks it |
| `ExtractablePassphrase` | `extractable-passphrase` | `Software` | The key can leave its store, and a passphrase decrypts it |

The three values state three pairs of the two properties, and the two properties admit more pairs than three. A backend that reports a pair no value above states — a key that can leave its store behind a biometric reading, a store a caller-supplied key opens, a store nothing gates — publishes no custody attestation at all. ADR-039's Enforcement Stack layer 4 already gives that absence a meaning, "Absence of attestation is itself a signal" (`.docs/adrs/phase-1.md:1302`), so a participant on such a backend costs a reader one signal and tells that reader nothing false. Open question OQ-12 of this spec asks which further pairs the published vocabulary should state.

§27.4.4 of the attestations spec governs what a consumer reads off a published custody value. This subsection states no reading rule of its own.

**The published value is derived, never declared.** `ScpKeyCustodyAttestation::derive` is the only named constructor, and it takes no custody value: it reads one off each custody backend the caller passes it. A participant running `encrypted_file` therefore cannot ask for a value stating that their key cannot leave its store, because the constructor accepts no such argument.

*Derivation:* that sentence states what the constructor does, and three paths reach the same struct without it, so it is not a guarantee about every custody value a reader meets.

1. **A parsed attestation carries whatever its publisher wrote.** `ScpKeyCustodyAttestation` derives `Deserialize`, and serde's generated implementation sets private fields, so `from_service_entry` builds one from bytes. It must: a reader parses a stranger's document with it. §27.4.4 of the attestations spec governs what a consumer concludes from a value that arrived this way, and this section states no reading rule of its own.
2. **A DID document's service vector is public.** `DidDocument.service` and the three fields of `Service` are `pub`, so a caller writes a `ScpKeyCustodyAttestation` service entry without touching the type at all.
3. **`os_keystore` derives from an answer the participant supplies.** The two facts reach `derive` through the platform key-custody callback, and an SDK consumer writes the adapter that answers it. For that backend the derivation reads a self-report, and the protocol may conclude from it only that the adapter this process injected said so. Both non-extractable values above have no other producer today, which §3.2.2.1's divergence D17 records.

The guarantee this section claims is therefore the narrow one: SCP's own key stores report themselves, and no caller names a value. Whether a reader may believe a published value is the question §27.4.4 answers, and open question OQ-15 asks what makes an `os_keystore` answer checkable.

**Evidence that a published custody property is derived and not declared.** Four systems separate what a caller asks for from what a reader is told, or replace the declaration with a proof.

Android splits the two sides across two classes. The request side takes a boolean: `public KeyGenParameterSpec.Builder setIsStrongBoxBacked (boolean isStrongBoxBacked)`, documented as "Sets whether this key should be protected by a StrongBox security chip." (<https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>). The read side returns a value the system computed: `KeyInfo.getSecurityLevel()` "Returns the security level that the key is protected by", one of the five constants `KeyProperties.SECURITY_LEVEL_UNKNOWN`, `KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE`, `KeyProperties.SECURITY_LEVEL_SOFTWARE`, `KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT`, and `KeyProperties.SECURITY_LEVEL_STRONGBOX` (<https://developer.android.com/reference/android/security/keystore/KeyInfo>).

PKCS#11 forbids an application from supplying the history attribute at all. `CKA_NEVER_EXTRACTABLE` carries the footnotes "MUST not be specified when object is created with C_CreateObject.", "MUST not be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.", and "MUST not be specified when object is unwrapped with C_UnwrapKey." The token writes it instead: `C_CreateObject` "will have … the CKA_NEVER_EXTRACTABLE attribute set to CK_FALSE" for an imported key (<https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html>).

WebAuthn reports the attachment on the response rather than echoing the request. `PublicKeyCredential.authenticatorAttachment` "reports the authenticator attachment modality in effect at the time the navigator.credentials.create() or navigator.credentials.get() methods successfully complete" (<https://www.w3.org/TR/webauthn-3/>, §5.1). *Derivation:* §5.4.5 states that the client reports the value — "clients use this to report the authenticator attachment modality used to complete a registration or authentication ceremony" — and no clause of that specification signs or attests it, so it establishes what the client observed and not what the authenticator proved.

Yubico's PIV implementation replaces the declaration with a certificate. Its attestation documentation states the purpose: "The concept of attestation is used to show that a certain asymmetric key has been generated on device and not imported." and the mechanism: "Attestation is implemented by creating a X.509 certificate for the key that is to be attested, this is only done if the key has been generated on device." (<https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>).

**What deriving leaves to the reading rule.** Alec ruled on 2026-08-25, verbatim: "either the platform proof is attached and verified, or the custody model reads as software no matter what string was written." Pull request #2408, which states that ruling in four clauses of §27.4.4 of the attestations spec, has not merged, so no merged artifact carries it as a rule and §27.4.4 as it stands states none. Deriving the published value neither replaces that ruling nor weakens it. *Derivation:* deriving removes the case the rule most often meets, which is a participant publishing a custody value their own backend does not support, and leaves the rule governing every case it still meets — among them a DID document served by a method that does not certify its own contents.

#### 3.2.2.1 Divergences This Subsection Records

Each entry quotes both artifacts and states why the two cannot both hold. The numbering continues §3.9.8.

**D14 — §3.2 lists four custody families a user may delegate to, and the vocabulary above names two backends.** §3.2 above states that "Custody is delegated to whatever the user already trusts" and lists "Device secure enclave (iOS Secure Enclave, Android Keystore)", "Platform accounts (Apple, Google) via passkey infrastructure", "Hardware security keys", and "Self-managed keys (power users who want direct control)" (`.docs/specs/03-identity.md:11`, options at `:13`–`:16`). The vocabulary above names `encrypted_file` and `os_keystore`. The two cannot both hold as statements of what a caller may select, because no value in the vocabulary reaches a hardware security key or a passkey, so a user who trusts a hardware security key cannot name it. §3.9.3 of this spec reads the four-option list as the written protocol behind Alec's ruling "LET PEOPLE CHOOSE. LIKE IS ALREADY FUCKING WRITTEN INTO THE GODDAMN PROTOCOL.", which makes the gap a question about what the protocol offers a participant rather than about how a name is spelled. Open question OQ-10 of this spec.

**D15 — three artifacts gave the custody-migration target three different value sets, and this change replaces all three.** §3.2.1 above gave the field as "target_custody_type: enum { SecureEnclave, AndroidKeystore, HardwareKey, Passkey, Software }". The shipped enum gave four different values — `PlatformManaged`, `Hardware`, `Software`, and `InMemory` (`crates/scp-runtime/src/identity/custody_migration.rs`) — and all three bridges parsed the wire strings `"platform_managed"`, `"hardware"`, `"software"`, and `"in_memory"` for it (`crates/scp-ffi/src/identity.rs`; `crates/scp-ffi/napi/src/scp.rs`; `crates/scp-ffi/uniffi/src/bridge.rs`). No two of the three sets shared a value beyond `Software`, so a caller migrating custody named a value that the spec defined and the code rejected, or the reverse. This change writes the two values above into §3.2.1, into the shipped enum, and into all three bridge parsers. The entry records what the three artifacts said before it.

**D16 — the shipped custody-migration enum carried an in-memory value on a production path, and this change removes it.** `CustodyMigrationTarget::InMemory` carried the doc comment "In-memory custody (testing only)" and sat in an enum no cargo feature gated, and all three bridges parsed `"in_memory"` into it on a shipped build. The no-dev-stand-in tenet of `CLAUDE.md` forbids that arrangement: no "`#[cfg(test)]`/`testing`-gated type, a security nullifier — may EVER be reachable on a shipped production path". A doc comment naming a value testing-only and a shipped parser accepting it cannot both hold.

**D17 — the published vocabulary states two non-extractable values, and every key-custody backend written in Rust reports that its key is extractable.** `KeyCustodyModel` states `NonExtractableBiometric`, "The private key cannot leave its store, and a biometric reading unlocks it", and `NonExtractablePin`, "The private key cannot leave its store, and a PIN unlocks it" (`crates/scp-did/src/attestation.rs:114`–`:116`, `:118`–`:119`). Every `CustodySubstrate` implementation in `crates/scp-platform/` answers the opposite. `FileKeyCustody` returns `true` because "this backend writes each private key into a file the process can read, and every signing operation decrypts the key into process memory, so the key leaves the store" (`crates/scp-platform/src/file.rs:982`–`:985`). `SqliteKeyCustody` returns `true` because "this backend writes each private key into the database as raw bytes and loads every key into process memory at construction" (`crates/scp-platform/src/sqlite/key_custody.rs:531`–`:534`). The `testing`-gated `InMemoryKeyCustody` returns `true` because "this backend holds every private key in a process-memory `HashMap`" (`crates/scp-platform/src/testing/key_custody.rs:516`–`:518`). Those three are the complete set: a workspace search for `impl CustodySubstrate` outside `crates/scp-did/` returns them and one test double.

The two cannot both hold as a statement of what a participant on a Rust-side backend publishes, because a vocabulary that states three values, two of which no shipped Rust backend can produce, leaves every such participant publishing `extractable-passphrase` or publishing nothing.

**The vocabulary is not the side that is wrong.** §17.8 of the persistence spec names two platform key stores that hold a key non-extractably: "Android Keystore (TEE-backed, API 33+ for Ed25519)" and "WebCrypto + IndexedDB (non-extractable `CryptoKey`)" (`.docs/specs/17-persistence-and-storage.md:667`–`:668`). `os_keystore` reaches those stores through the platform key-custody callback, so the substrate the two values name is a substrate SCP runs on. What no artifact supplies is a `KeyCustody` implementation written in Rust that reaches one. Narrowing the vocabulary to the backends Rust ships would delete the distinction a DID document's reader is reading for, which the no-dev-stand-in tenet of `CLAUDE.md` names the worse failure: "Masking a missing production backend with a dev construct ships a *false guarantee*, which is strictly worse than the capability being honestly absent (absence is detectable; a nullifier lies)." Open question OQ-13 of this spec.

#### 3.2.2.2 Open Questions

The numbering continues §3.9.9. Each entry names what no artifact defines, which artifact should define it, and what an implementer hits meanwhile. *Derivation:* each "Breaks meanwhile" clause reasons from the artifacts the entry cites to a consequence those artifacts do not themselves state.

**OQ-10 — May a participant put an SCP signing key in a hardware security key or behind a passkey, and if so, which value names that backend?** *Undefined:* §3.2's four-option list offers both, the request-side vocabulary above names neither, and no shipped `KeyCustody` implementation reaches either one (§3.2.2.1, divergence D14). *Should define it:* §3.2 of this spec, either by adding a value for each backend a shipped implementation reaches or by withdrawing the option from the four-option list. *Breaks meanwhile:* a participant who owns a hardware security key reads §3.2, believes the protocol admits it, and finds two values at the SDK, neither of which reaches the key they own.

**OQ-11 — What does a participant publish who runs `os_keystore` on a platform whose operating-system key store holds keys non-extractably?** *Undefined:* the published values above separate an extractable key from a non-extractable one, `os_keystore` names one request-side backend, and §17.8 of the persistence spec gives that backend different extractability on different platforms — "Apple Keychain (generic password items) | Ed25519, X25519 (software-backed)" for iOS and macOS, and "WebCrypto + IndexedDB (non-extractable CryptoKey)" for the browser (`.docs/specs/17-persistence-and-storage.md:666`, `:668`). No artifact states which of the two a platform callback reports, or how a callback tells SCP which one it is. *Should define it:* §3.2 of this spec together with the `KeyCustody` platform contract ADR-006 states, naming what a callback reports about its own extractability. *Breaks meanwhile:* one request-side value publishes the same custody claim on a platform that can release the key and on a platform that cannot, so a reader who acts on the extractability distinction acts on a value that does not carry it.

**OQ-12 — Which further pairs of extractability and unlock factor should the published vocabulary state?** *Undefined:* the two properties admit more pairs than the three values above state, and a backend reporting any other pair publishes no custody attestation. `AppleKeyCustody` reports one such pair when a caller initializes it with `BiometricPolicy.required`: `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:204`–`:213` states that the Keychain item then requires "Face ID or Touch ID" before a signing operation, `:217`–`:221` states that the key sits in the Keychain in software, and `:1020`–`:1025` returns the string `"software_biometric"` for exactly that combination. §3.2.2's unlock-factor criterion bears on the same pair from the other side: that mode gates every call to `sign`, which the criterion states is not viable for `#active`, so open question OQ-14 asks what the adapter does about the pairing while this entry asks what the vocabulary should state for it. *Should define it:* §3.2 of this spec, adding a value for each pair a shipped backend reports. *Breaks meanwhile:* a participant who turns on biometric gating over Apple Keychain publishes no custody value, and a reader cannot distinguish that participant from one who published nothing for any other reason.

**OQ-13 — Which `KeyCustody` implementation written in Rust reaches a key store that holds a key non-extractably?** *Undefined:* the published vocabulary states two non-extractable values, §17.8 of the persistence spec names Android Keystore and the browser's `CryptoKey` as key stores that hold a key non-extractably (`.docs/specs/17-persistence-and-storage.md:667`–`:668`), and every `CustodySubstrate` implementation in `crates/scp-platform/` reports an extractable key (§3.2.2.1, divergence D17). A participant reaches one of those stores only through the platform key-custody callback, which a Swift or Kotlin consumer supplies. *Should define it:* ADR-006, the platform-adapter decision, naming which Rust-side backend reaches a non-extractable store, or stating that every non-extractable store is reached through the callback and no Rust backend targets one. *Breaks meanwhile:* a `did:dht` identity created on a desktop or a server publishes `extractable-passphrase` or publishes nothing, and a reader who sorts participants by whether the key can leave sees one class where the platform table names three.

**OQ-14 — What does a platform adapter do when a participant selects a per-operation biometric factor for `#active`?** *Undefined:* §3.2.2 states that an unlock factor demanding a fresh biometric reading per signing operation is not viable for `#active`, and `AppleKeyCustody` offers exactly that mode through `BiometricPolicy.required` (`bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift:204`–`:213`). No artifact states whether the adapter refuses the pairing, warns the participant, or holds the `#active` key under a different factor from the other three keys. *Should define it:* ADR-025, the Apple platform adapter, and ADR-027, the Android platform adapter, together, since each owns what its adapter does with a policy a caller sets. *Breaks meanwhile:* a participant who turns on biometric gating gets a Face ID prompt for every message they send, and no artifact told them that before they chose.

**OQ-15 — What makes an `os_keystore` custody answer checkable by anyone but the participant?** *Undefined:* the platform key-custody callback answers both published facts, an SDK consumer writes the adapter that answers it, and the participant who publishes the value is the participant who wrote that adapter. Both non-extractable values above have that path as their only producer (§3.2.2.1, divergence D17). Alec ruled on 2026-08-25, verbatim: "either the platform proof is attached and verified, or the custody model reads as software no matter what string was written", and pull request #2408 states that ruling in §27.4.4 of the attestations spec but has not merged. *Should define it:* §27.4.4 of the attestations spec, stating the reading rule, together with ADR-025 and ADR-027 stating what proof an adapter attaches. *Breaks meanwhile:* an adapter holding a key in process memory answers that the key cannot leave its store, and no artifact tells a reader to discount that answer.

**OQ-16 — What tells a caller that the passphrase they supplied is the one the key file was written under?** *Undefined:* `FileKeyCustody::new` derives the wrapping key and reads each entry's header without decrypting an entry, so a wrong passphrase opens the store and surfaces at the first signing operation, and a key generated in between is written under the wrong wrapping key. A path holding no file yields a new empty store, so key loss and a first run report the same success. *Should define it:* §17.8 of the persistence spec, which owns the key-file format, stating whether the header carries an authenticator over the derived key. *Breaks meanwhile:* a participant who mistypes the passphrase creates a second key store beside the first, and learns it at the first signature rather than at the open.

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
- **Discoverable.** Other SCP participants can look up whether a given external identity maps to a known DID. Attestations are discoverable through contexts with discovery outlets (§6.2.2B) and DID document service entries (§3.5.3). Reverse-lookup (external handle → DID) is provided by the `attestation_lookup` outlet in contexts with discovery outlets (§22.5).

Identity attestations enable three critical flows:

1. **Social graph import.** A user exports their follower list from X. Their local agent resolves each handle against known attestations. Contacts who have also joined SCP are automatically discoverable.
2. **Shadow identity claiming.** When a bridge connector creates a shadow identity for an external participant (see §12), a user can claim it by presenting a matching attestation. The shadow identity merges with their real DID (see §3.5.5 for the claiming protocol).
3. **Cross-platform reputation continuity.** Trust judgments about a person can follow them across platforms — not because platforms share data, but because the human has cryptographically proven they're the same person.

### 3.5.0 Attestation Classes

Identity link attestations are sub-classified into two classes based on when and how the external identity ownership was verified. The class is a property of the verification method, not of the attestation envelope — the wire format (§3.5.2) is the same for both classes. The class determines the trust model: who must verify, when, and what the attestation proves on its own. See ADR-044 for the design rationale and rejected alternatives.

**Class 1: Cryptographic.** The provider's confirmation of identity ownership was cryptographically verified at attestation creation time. Verification methods: `Oauth`, `ChallengeResponse`.

- The SDK performs the verification flow (OAuth code exchange, challenge-response round trip) locally at creation time.
- On success, the SDK extracts the minimal identifying claim (`provider`, `subject_id`, `verified_at`) and signs it with the DID's signing key. This SDK-signed proof replaces the raw provider token — no JWT, no OIDC ID token, no PII is stored.
- The attestation proof is: `{ "provider": "<platform>", "subject_id": "<platform_user_id>", "verified_at": <unix_s> }` signed by the issuer's `#active` or `#agent` key. The signature is the one on the `IdentityLinkAttestation` envelope itself — the proof field carries the claim content, the envelope signature covers it.
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
2. The subject signs the challenge with their SCP signing key (`#active` or `#agent`).
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
  signature:    Ed25519Signature,  // Signs §9.5.1 canonical hash (see Signature scope below), using issuer's #active or #agent key
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

**Revocation check:** Verifiers check revocation by resolving the issuer's DID document and looking for an `AttestationRevocations` service endpoint (§18.2.2). The endpoint returns a list of revoked attestation IDs. If the attestation's `id` appears in the list, it is revoked. Additionally, the `revocation_status` field in the attestation itself is checked — if `Revoked`, the attestation is invalid regardless of the revocation endpoint.

### 3.5.3 DID Document Attestation Service Entry

Identity link attestations are published as service entries in the issuer's DID document. This enables discovery: any party resolving the DID document can enumerate the issuer's identity links without querying a separate registry.

**Service entry format:**

```
Service {
  id:              "<did>#attestation-<platform>--<index>",  // e.g., "did:dht:z...#attestation-github.com--0"
  type:            "ScpIdentityLinkAttestation",
  serviceEndpoint: "<attestation_id>"                       // Hex-encoded attestation ID (§3.5.2)
}
```

**Fragment naming convention:** `attestation-<platform>--<index>` where `<platform>` is the `platform` value from the provider registry (§3.5.1) and `<index>` is a zero-based integer for disambiguation when multiple attestations exist for the same platform (e.g., multiple Mastodon instances).

**Fields:**

- `id`: Full DID URI with fragment. The fragment encodes the platform for human readability. The `<index>` disambiguates multiple attestations for the same platform.
- `type`: `ScpIdentityLinkAttestation` (constant). Consumers filter DID document services by this type to discover identity link attestations.
- `serviceEndpoint`: The attestation ID (hex string). Consumers use this to look up the full `IdentityLinkAttestation` from the identity's attestation store (via relay or DHT).

**Maximum attestations per DID document:** 64. This prevents DID document bloat — each service entry adds to the DID document size, which is replicated across resolvers — while providing enough headroom for users with many platform identities. The limit applies to service entries of type `ScpIdentityLinkAttestation` only; other service types have their own limits.

**Bridge-layer attestation store limit:** Implementations MUST enforce the same 64-attestation-per-DID cap as the DID document layer. This unified limit ensures consistent behavior across all layers — the DID document and the bridge attestation store share a single bound. The constant `MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID` (defined in `scp-ffi-common`) is the single source of truth for all bridge implementations.

**Lifecycle:** When an attestation is revoked, the corresponding service entry MUST be removed from the DID document. When an attestation is renewed (re-verified), the service entry is unchanged — it still points to the same attestation ID. When an attestation is replaced (new attestation for the same platform+handle), the service entry's `serviceEndpoint` is updated to the new attestation ID.

### 3.5.4 Verification

Verification procedure depends on the attestation class (§3.5.0).

**Class 1 (Cryptographic) verification:**

1. Resolve the issuer's DID document. Extract the `#active` or `#agent` public key.
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

A DID has public state (keys, service endpoints, published attestations) and **private state** — encrypted data that only the identity owner can read, replicated for availability and portability.

Context state handles multi-party social data. Identity private state handles single-party personal data. Together they cover every category of protocol-relevant state without requiring anything to live only on a local device.

```
Identity (DID)
├── Public State (DID Document)
│   ├── Verification methods (§3.9)
│   │   ├── #0 — Identity Key (Ed25519, root of trust, never rotates)
│   │   ├── #active — Human Signing Key (Ed25519, rotatable)
│   │   └── #agent — Agent Signing Key (Ed25519, optional, rotatable)
│   ├── Service endpoints / relay list
│   └── Published attestations
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

The domain separation (`"scp-private-state-v1"` info string and `"scp-private-state-salt-v1"` salt) prevents collision with other routing ID derivation schemes: DID document routing uses `SHA-256("scp:did:" || did_string)` (§3.10.2), encrypted context routing uses HKDF from identity key material with `"scp-pseudonym"` (§9.10.4), broadcast context routing uses `SHA-256(context_id)` (§5.14), and context metadata routing uses `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` (§9.10.4.B).

The `IdentityPrivateState` service endpoint in the DID document (see below) lists which relays store the private state. The `routing_id` tells the SDK how to address those blobs on those relays.

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
- **Discovery pointer.** Explicit. The DID document includes a service endpoint of type `IdentityPrivateState` listing relays that store private state. This cleanly disambiguates context event fetches from private state fetches without relay-side guessing.
- **Relay service endpoints.** The DID document includes service endpoints of type `SCPRelay` listing the identity's transport-layer relay URLs — the endpoints where `TransportManager` routes encrypted blobs for this identity. Multiple entries are recommended for suppression resistance (§9.9.2). Self-certified via BEP44 signature (§9.6.3). See §18.2 for the full specification of DID document service endpoint types.

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

DID resolution is the trust root for the entire protocol. If resolution can be MITMed, every layer above — encryption, authentication, capability validation — is compromised. The security properties depend on the DID method:

**did:dht (target method):** Self-certifying. The DID string encodes the public key. DID documents are signed via BEP44 and verifiable against the DID without trusting any intermediary. MITM on resolution is impossible given the correct DID. Stale documents are rejected via sequence numbers. See §9.6 for full specification.

**did:web (fallback only):** NOT self-certifying. Security depends on DNS + TLS + server integrity. The SDK MUST use TLS pinning + TOFU (Trust On First Use) + key change alerts to mitigate. did:web exists as a fallback if did:dht libraries prove unusable — not as a planned stepping stone. See §9.6.2 for required mitigations.

**Key Continuity Verification:** Signal-style safety numbers for DIDs, enabling out-of-band verification that two parties have the correct keys for each other. See §9.11.

### 3.8.1 Canonical DID string form (deterministic-derivation input)

Wherever a DID string feeds a **deterministic hash preimage** — any place two independent resolvers must agree byte-for-byte or they would derive divergent identifiers (e.g. the `derived_context_id` of §5.15.8) — the DID MUST be reduced to its **canonical string form**, the single comparison form DID resolution yields per method.

**Purpose (canonical agreement, not injectivity).** With the §5.15.8 derivation now length-prefixed (§9.5.1), field-boundary injectivity is unconditional **by construction** and does **not** depend on this section. §3.8.1's sole job is **byte-agreement**: both parties MUST feed **byte-identical** DID strings into any shared preimage so they do not split-brain onto divergent identifiers. (Even with length prefixes, two encodings of the *same* logical DID are two distinct byte strings and would length-prefix to two distinct preimages — hence the canonicalization requirement remains load-bearing, but for agreement, not for disambiguating field boundaries.)

- **did:dht** — its self-certifying form: lowercase z-base-32 of the Ed25519 public key (§9.6.1). This is already a single canonical form; no further normalization applies. **The byte-agreement guarantee is AIRTIGHT for did:dht** (the production method): there is exactly one canonical z-base-32 encoding of a given public key, so two honest resolvers cannot diverge.
- **did:web** — canonicalized per the W3C did:web method, with the specific-id normalized per **RFC 3986 §6.2.2 syntax-based normalization** to a single byte string:
  - **Percent-encoding normalization** — decode percent-encodings of **unreserved** characters (`ALPHA / DIGIT / "-" / "." / "_" / "~"`, RFC 3986 §6.2.2.2) to their literal form; uppercase the hex digits of each remaining `%XX` triplet (RFC 3986 §6.2.2.1). This normalizes the two hex **digits** of a percent-encoding and is **orthogonal** to the host/scheme alpha-case normalization below — which lowercases literal ALPHA characters, **never** the hex digits of a percent-encoding (RFC 3986 §6.2.2.1 treats percent-encoding hex-digit case and host/scheme alpha-case as disjoint normalizations targeting different characters, so on a percent-encoded host octet they do not overlap: the `%XX` hex digits go uppercase, the unescaped host ALPHA goes lowercase).
  - **Case normalization** — lowercase the scheme and host (RFC 3986 §6.2.2.1).
  - **Host (IDN)** — normalize per **RFC 5895 / IDNA2008**: apply **NFC** normalization **before** punycode / A-label conversion; reduce an internationalized host to its A-label (punycode) form; omit the default `:443` port; the authority carries **no trailing dot**.
  - **Literal `:` separators** of the method-specific identifier are percent-encoded as **`%3A`** — still required even with length-prefixing, because the whole specific-id rides the preimage as one canonical byte string and the two sides must agree on its bytes.

A DID whose method admits **no** canonical string form (no deterministic single comparison form) is **rejected at a fail-loud method-admission gate** — never silently coerced — so a deterministic derivation can never be fed an un-normalizable DID. (This admission gate is about *canonical agreement*, distinct from the retired §5.15.8 colon-freedom assumption, which length-prefixing made unnecessary.)

**did:web residual (disclosed honestly).** did:web is **fallback-only** and **not a planned deployment path** (§3.8). Even with the RFC-3986 + RFC-5895 profile above, byte-agreement for did:web is **best-effort at the exotic margins** — adversarially-constructed hosts/paths can in principle still admit encodings two implementations normalize differently. The protocol does **not** claim did:web agreement is airtight (only did:dht is). The backstop is **defense-in-depth at the receiver**: the §5.15.8 step-4(a0) **Welcome-receipt mismatch guard** re-derives the `derived_context_id` from the receiver's own canonical inputs and **rejects** the Welcome on any mismatch, turning a canonicalization divergence into a clean local rejection rather than a silent split-brain. **Availability dual (disclosed tradeoff).** The same receive-side guard converts an *adversarially-constructed* did:web canonicalization divergence — an attacker who controls a did:web document published under a specific-id that two resolvers normalize differently — into a deterministic, **undiagnosable** pairing-denial: the §5.15.8 indistinguishable-rejection requirement (no existence/decline oracle) is in tension with diagnosability for the legitimate-but-divergent case, so a genuine honest divergence and an adversarial one are equally opaque to the rejecting party. This availability tradeoff is **accepted explicitly**, and it is **bounded**: did:web is fallback-only, and did:dht (the production method) is airtight (above) and entirely unaffected.

## 3.9 Multi-Key Architecture and Key Lifecycle

An SCP identity holds four Ed25519 keys: the Identity Key `#0`, the Human Signing Key `#active`, the Agent Signing Key `#agent`, and the pre-rotation key. This section states, for each key, what authority it carries, what it signs, what it MUST NOT sign, where its private key material lives and who chooses that, whether and how it rotates, and how it appears in the DID document.

This section governs the four keys. `.docs/spec-extraction-plan.md:62` records why it exists: the multi-key separation "is described across §3.9, §3.10, §4.2, §4.5 (ADR-039), §9.7.4, §9.8.1 (updated preimage), and §11.2.3 (prior art) but not formally specified in a single authoritative section. The protocol spec must consolidate this with wire formats, not scattered across 6+ locations." Every other artifact that names these keys cites this section instead of restating what it says. An artifact that states something this section does not cover keeps its own text.

Every claim below cites the artifact that states it. A sentence marked *Derivation:* draws a conclusion here from the cited artifacts, and it carries no authority those artifacts do not already carry. §3.9.8 lists the places where two artifacts state claims that cannot both hold. §3.9.9 lists the questions no artifact answers.

### 3.9.1 The Four Keys

| Key | Holder | Place in the DID document | Rotates |
|-----|--------|---------------------------|---------|
| `#0` — Identity Key | Human | Verification method `#0`, required | No — identity migration replaces it (§3.9.2) |
| `#active` — Human Signing Key | Human | Verification method `#active`, required | Yes, through `rotate_active_key` (§3.9.3) |
| `#agent` — Agent Signing Key | Agent software | Verification method `#agent`, optional, at most one | Yes, through `rotate_agent_key` (§3.9.4) |
| Pre-rotation key | Human | Service entry of type `PreRotationCommitment`, which publishes a hash and never the public key | Single use, replaced after each migration (§3.9.5) |

The holder column restates ADR-039's key-properties table, which gives Holder as Human, Human, and Agent software for `#0`, `#active`, and `#agent` (`.docs/adrs/phase-1.md:1267`).

ADR-039 states the trust chain: "`#0` (root of trust) authorizes `#active` and `#agent` via DID document publication. Adding/removing `#agent` is a DID document update signed by `#0`" (`.docs/adrs/phase-1.md:1261`).

The `SigningKeyId` type names the verification method that signed a protocol message. It admits exactly two values, `Active` and `Agent`, which serialize as `"#active"` and `"#agent"` (`crates/scp-did/src/lib.rs:192`). `#0` is not among them: `SigningKeyId::from_fragment` returns `None` for `"#0"` (`crates/scp-did/src/lib.rs:247`), and a unit test asserts that result (`crates/scp-did/src/lib.rs:324`). *Derivation:* a protocol message cannot name `#0` as its signer, because no `SigningKeyId` value denotes `#0`. That is the type-level form of the rule §3.9.2 states in prose.

### 3.9.2 `#0` — the Identity Key

**What it is.** The Ed25519 key whose public half the DID string encodes. §18.2.2A of the addressability spec requires the document's `id` to "match `did:dht:<z-base-32(#0 public key)>`" (`.docs/specs/18-addressability-and-deployment.md:144`). §9.7.4 of the security spec states the consequence: "The DID string is derived from this key and never changes" (`.docs/specs/09-security-model.md:701`).

**Authority.** Root of trust for the identity. ADR-039 states that `#0` "authorizes `#active` and `#agent` via DID document publication" (`.docs/adrs/phase-1.md:1261`).

**What it signs.** DID document updates and pre-rotation commitments, and nothing else. §9.7.4 states it directly: "Used ONLY for DID document updates and signing pre-rotation commitments" (`.docs/specs/09-security-model.md:701`). ADR-039's Category A assigns four actions to `#0` and `#active`: "DID document updates (add/remove keys, change services, alter relays) — requires `#0`", "Pre-rotation commitments — requires `#0`", "Identity migration (Layer 2) — requires `#0`", and "Root UCAN issuance — requires `#active`" (`.docs/adrs/phase-1.md:1280`–`:1283`). `#0` also signs the DID document update that carries out a `#active` or `#agent` rotation (ADR-003 §4a, `.docs/adrs/phase-1.md:360`; ADR-003 §4a′, `.docs/adrs/phase-1.md:369`).

**What it MUST NOT sign.** Operational actions. ADR-039's key-properties table gives `#0` the value "No" under "Signs operational actions" (`.docs/adrs/phase-1.md:1271`). §9.7.1 of the security spec applies that rule to one operational action by name: a KeyPackage attestation is "signed by the Active Signing Key (`#active`) or Agent Signing Key (`#agent`) — NOT the Identity Key (`#0`)" (`.docs/specs/09-security-model.md:619`), because "`#0` is reserved exclusively for DID document operations and pre-rotation commitments" (`.docs/specs/09-security-model.md:628`). ADR-001 gives the reason: signing KeyPackage attestations with `#active` or `#agent` "avoids requiring the hardware-backed `#0` for routine background operations (the SDK replenishes KeyPackage buffers automatically)" (`.docs/adrs/phase-1.md:106`). One shipped resolver states the opposite rule — "the identity key (`#0`) is the canonical signing key for attestations per ADR-017" (`crates/scp-protocol/src/trust/attestation.rs:676`–`:677`) — and §27.4.2 of the attestations spec already records that as contradiction C17 (`.docs/specs/27-attestations.md:515`) and routes it to open question OQ-31 of that spec (`.docs/specs/27-attestations.md:792`). This section states the rule and adds no second open question for it.

**What reads its key material without signing.** The "ONLY" above scopes `#0`'s use as a *signing* key. Three derivations consume `#0`'s key material as a hash or key-derivation input rather than asking it to sign: the per-context pseudonym, which §9.10.4 of the security spec derives "from `identity_key_material` (the DID's `#0` key)" (`.docs/specs/09-security-model.md:1055`); the SQLCipher database key of §17 (`.docs/specs/17-persistence-and-storage.md:482`); and the identity-private-state routing ID of §3.7 (`.docs/specs/03-identity.md:597`). *Derivation:* a reader who takes "Used ONLY" to cover every use of the key material reads three shipped derivations as violations, so this section states the narrower scope the sources support. §3.9.8 records that the three do not agree on whether they read the public half or the private half.

**Where its key material lives, and who chooses.** ADR-003's first acceptance criterion generates `#0` through the same custody provider as the other two operational keys — `create_identity(key_custody, pre_rotation_custody)` "Generates the operational keypairs via `key_custody` (`#0`, `#active`, and optional `#agent`)" (`.docs/adrs/phase-1.md:291`–`:293`) — so a participant who selects a custody provider selects it for `#0` as well. What no artifact offers is a per-key menu for `#0`: §9.7.4.1 item 5 presents custody options for the pre-rotation key (`.docs/specs/09-security-model.md:767`), and `ScpKeyCustodyAttestation` carries `active_key_custody` and `agent_key_custody` and no field for `#0` (`crates/scp-did/src/attestation.rs:61`). §9.7.4 states the placement: "Generated in hardware security module where available (Secure Enclave, Android Keystore). Private key never exported from the secure element" (`.docs/specs/09-security-model.md:701`). The clause "where available" is load-bearing, and two platform ADRs state where hardware backing is and is not available for an Ed25519 key. ADR-027, the Android platform adapter, states that "Apple's Secure Enclave supports only P-256; SCP identity keys (Ed25519) must be software-backed in Keychain on Apple. Android Keystore at API 33+ (Android 13+) natively supports Ed25519 via the EdDSA algorithm" (`.docs/adrs/phase-6.md:38`), and its acceptance criterion returns `custodyType = CustodyType.HARDWARE` for an Ed25519 key on API 33 and above and `CustodyType.SOFTWARE` on API 26 through 32 (`.docs/adrs/phase-6.md:416`–`:417`). ADR-025, the Apple platform adapter, stores the private key bytes "in Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`" (`.docs/adrs/phase-5.md:508`). §17.8 of the persistence spec states the same split in its platform custody table: its iOS/macOS row gives the key types as "Ed25519, X25519 (software-backed)" and notes "Secure Enclave only supports P-256; Ed25519 keys are software-backed in Keychain", while its Android row gives "Android Keystore (TEE-backed, API 33+ for Ed25519)" and its Browser row gives "WebCrypto + IndexedDB (non-extractable CryptoKey)" (`.docs/specs/17-persistence-and-storage.md:666`–`:668`).

*Derivation:* the honest statement of `#0`'s tier is therefore conditional rather than fixed. An implementation places `#0` in a hardware security module on every platform whose secure element holds an Ed25519 key, and in platform software custody on every platform whose secure element does not. §3.9.8 records that ADR-039's key-properties table states this cell without the condition.

**Why no per-key menu exists for `#0`.** §9.12 of the security spec ranks Identity Key compromise as "rare, severe" and gives it the only recovery path that does not preserve the DID: "Call `migrate_identity` (ADR-003 §4b) using the pre-rotation key from cold storage. … Creates a new DID" (`.docs/specs/09-security-model.md:1324`). *Derivation:* `#0` is the one key whose compromise no rotation repairs, so the protocol asks for the strongest custody the selected provider offers for an Ed25519 key on that platform rather than presenting a per-key menu. Its tier follows from the provider and the platform, and §3.9.8 records where one artifact states it without that condition.

**Rotation.** `#0` does not rotate. ADR-039's key-properties table gives "No (Layer 2 migration only)" under Rotatable (`.docs/adrs/phase-1.md:1269`). ADR-003 states the underlying constraint: "did:dht's Identity Key (the key that derives the DID string) is **non-rotatable** per the did:dht specification — the DID string is permanently bound to the initial public key" (`.docs/adrs/phase-1.md:355`). Identity migration replaces `#0` and creates a new DID; §3.9.5 states that path.

**Place in the DID document.** §18.2.2A of the addressability spec assigns `#0` to these arrays:

| Array | Rule | Source |
|-------|------|--------|
| `verificationMethod` | MUST include `#0` | `.docs/specs/18-addressability-and-deployment.md:145` |
| `authentication` | MUST NOT reference `#0` | `.docs/specs/18-addressability-and-deployment.md:147` |
| `assertionMethod` | Same as `authentication`, so MUST NOT reference `#0` | `.docs/specs/18-addressability-and-deployment.md:148` |
| `capabilityDelegation` | MUST reference only `#0` | `.docs/specs/18-addressability-and-deployment.md:149` |
| `capabilityInvocation` | MUST reference `#0` and `#active` | `.docs/specs/18-addressability-and-deployment.md:150` |

**Wire format of its verification method entry.** §18.2.2A gives the entry (`.docs/specs/18-addressability-and-deployment.md:86`–`:91`):

```json
{
  "id": "did:dht:<key>#0",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:dht:<key>",
  "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
}
```

`publicKeyMultibase` carries a "Multibase-encoded Ed25519 public key (prefix `z` for base58btc)" (`.docs/specs/18-addressability-and-deployment.md:146`). The shipped `VerificationMethod` struct carries the same four fields under the same JSON names (`crates/scp-did/src/document.rs:207`), and the shipped type string is `"Ed25519VerificationKey2020"` (`crates/scp-did/src/document.rs:248`).

### 3.9.3 `#active` — the Human Signing Key

**What it is.** The human's operational signing key. ADR-039's Decision block names it "`#active` — Human Signing Key (Ed25519, human's operational key)" (`.docs/adrs/phase-1.md:1256`).

**Authority.** The human's operational authority, delegated by `#0` through DID document publication (`.docs/adrs/phase-1.md:1261`). ADR-039's key-properties table gives `#active` the value "Yes" under "Signs operational actions" (`.docs/adrs/phase-1.md:1271`), and §4.5 of the agents spec states that "The human can always act directly through `#active`, and the agent acts through `#agent`" (`.docs/specs/04-agents.md:96`).

**What it signs.** §9.7.4 of the security spec lists the operations: "Used for MLS KeyPackage attestations (§9.7.1), inner-envelope signatures, UCAN issuance. It does NOT sign the MLS leaf/credential directly — the leaf is self-signed by the ephemeral MLS leaf signature key … and the DID↔leaf binding is carried by a `#active`/`#agent`-signed KeyPackage attestation" (`.docs/specs/09-security-model.md:702`). ADR-039 assigns root UCAN issuance to `#active` alone and gives the reason: "Root UCANs are the origin of all delegation chains; an agent that can issue root UCANs can grant itself arbitrary capabilities" (`.docs/adrs/phase-1.md:1283`). §3.11 of this spec adds DID authentication challenges, which `#active` or `#agent` signs (`.docs/specs/03-identity.md:299`).

**What it does besides signing.** `#active` also performs X25519 key agreement, so a participant opens an invitation sealed to them. The invitation-open path names it: "the recipient key is the invitee's Ed25519 `#active` identity key, held in custody. The one step that must touch the non-extractable private key — `dh = DH(sk_active_x25519, enc)` — is performed in custody via `KeyCustody::ed25519_to_x25519_agree(handle, enc)`" (`crates/scp-protocol/src/crypto/envelope_seal.rs:158`–`:161`), and `KeyCustody` declares that method with no default body and no hardware carve-out (`crates/scp-platform/src/traits.rs:469`). §3.9.8 records what that costs a participant who chooses hardware custody.

**What it MUST NOT sign.** DID document updates, pre-rotation commitments, and identity migration, each of which ADR-039's Category A assigns to `#0` (`.docs/adrs/phase-1.md:1280`–`:1282`). ADR-039's key-properties table gives `#active` the value "No" under "Signs DID doc updates" (`.docs/adrs/phase-1.md:1270`).

**Where its key material lives, and who chooses.** The participant chooses, and platform secure storage is the expectation.

Alec ruled on 2026-08-25, verbatim: "active generally would not go in hardware but it's an option. it would go behind a passkey or something. so platform would be the expectation." And: "LET PEOPLE CHOOSE. LIKE IS ALREADY FUCKING WRITTEN INTO THE GODDAMN PROTOCOL."

§3.2 of this spec is the written protocol the second ruling names. It states that "Custody is delegated to whatever the user already trusts" and lists four options — "Device secure enclave (iOS Secure Enclave, Android Keystore)", "Platform accounts (Apple, Google) via passkey infrastructure", "Hardware security keys", and "Self-managed keys (power users who want direct control)" (`.docs/specs/03-identity.md:11`, options at `:13`–`:16`) — and then states that "The identity layer abstracts custody. The user authenticates however they choose" (`.docs/specs/03-identity.md:18`). §9.7.4 of the security spec names the seam the choice arrives through: `#active` is "Generated via KeyCustody" (`.docs/specs/09-security-model.md:702`), and `KeyCustody` is the platform trait an SDK consumer implements or selects (`crates/scp-platform/src/traits.rs:324`).

This section therefore states no fixed custody value for `#active`. §3.2.2 of this spec states the two values a participant names — `encrypted_file` and `os_keystore` — and states that the value the `ScpKeyCustodyAttestation` service entry publishes is derived from the backend in use rather than named by the participant, so the entry records which backend holds the key and not a claim the participant wrote. §27.4.4 of the attestations spec governs what a consumer reads off a published custody value; this section states no reading rule of its own.

**Rotation.** `rotate_active_key`, ADR-003 §4a, which "Generates a new Ed25519 keypair as the new Active Signing Key", "Signs the DID document update with the **Identity Key** (NOT the old active key)", and leaves the DID string unchanged (`.docs/adrs/phase-1.md:357`–`:363`). §3.2.1 of this spec applies the same operation to a custody change (`.docs/specs/03-identity.md:26`). §9.12 of the security spec applies it to compromise (`.docs/specs/09-security-model.md:1323`). ADR-003 §4a retains the superseded key: "Retains the old key as `#retired-{sequence}` for historical verification. … the document retains at most the 2 most recent retired active keys" (`.docs/adrs/phase-1.md:359`), and the shipped rotation renames the old entry to that fragment (`crates/scp-did/src/document.rs:888`). §9.7.1 check 1 of the security spec states what a verifier does with such an entry: it "MUST NOT accept an attestation signed by any `#retired-*` verification method" (`.docs/specs/09-security-model.md:634`). §3.9.8 records that §18.2.2A of the addressability spec permits no such entry.

**Place in the DID document.**

| Array | Rule | Source |
|-------|------|--------|
| `verificationMethod` | MUST include `#active` | `.docs/specs/18-addressability-and-deployment.md:145` |
| `authentication` | MUST reference `#active` | `.docs/specs/18-addressability-and-deployment.md:147` |
| `assertionMethod` | Same as `authentication`, so MUST reference `#active` | `.docs/specs/18-addressability-and-deployment.md:148` |
| `capabilityDelegation` | MUST reference only `#0`, so it does not reference `#active` | `.docs/specs/18-addressability-and-deployment.md:149` |
| `capabilityInvocation` | MUST reference `#0` and `#active` | `.docs/specs/18-addressability-and-deployment.md:150` |

**Wire format of its verification method entry.** §18.2.2A gives the entry (`.docs/specs/18-addressability-and-deployment.md:92`–`:97`):

```json
{
  "id": "did:dht:<key>#active",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:dht:<key>",
  "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
}
```

### 3.9.4 `#agent` — the Agent Signing Key

**What it is.** An optional Ed25519 key that the human's agent software holds. ADR-039's Decision block names it "`#agent` — Agent Signing Key (Ed25519, agent software key, rotatable)" (`.docs/adrs/phase-1.md:1257`), and its structural constraint reads: "Exactly one `#agent` verification method per DID document. Verifiers reject documents with multiple `#agent` VMs. `#agent` is optional — not every DID needs an agent" (`.docs/adrs/phase-1.md:1273`).

**Authority.** Whatever the human delegates, and nothing beyond it. ADR-039's key-properties table gives `#agent` the value "Yes (within permission scope)" under "Signs operational actions" (`.docs/adrs/phase-1.md:1271`), and its Category B states who sets the scope: "All operational actions. Human sets defaults and limits per agent via UCAN `fct.scp_agent_permissions`" (`.docs/adrs/phase-1.md:1285`). `#0` authorizes the key itself through DID document publication (`.docs/adrs/phase-1.md:1261`).

**Scope.** One key per DID, not one per context. ADR-039 states the constraint and its reason: "One persistent `#agent` key per DID, not per-context. DID documents are already ~1,140 bytes with 2 VMs (BEP44 v1 payload limit is 1,000 bytes, requiring bencode packing). Per-context agent keys would exceed document size constraints at scale" (`.docs/adrs/phase-1.md:1275`).

**What it signs.** §9.7.4 of the security spec lists "agent-autonomous message signing and scoped UCAN delegation" (`.docs/specs/09-security-model.md:704`), and §9.7.1 adds KeyPackage attestations for agent-initiated joins (`.docs/specs/09-security-model.md:628`). ADR-039's Category B lists the operational actions a human may delegate: "Messaging, blocking, context creation/joining, outlet invocation, sub-UCAN minting, governance voting, spending — all configurable by the human with protocol defaults (messaging allowed, most other actions denied by default)" (`.docs/adrs/phase-1.md:1286`). §4.5 of the agents spec states the provenance this produces: "Messages signed with `#active` are human-direct; messages signed with `#agent` are agent-autonomous" (`.docs/specs/04-agents.md:96`).

**What it MUST NOT sign.** Every Category A action. ADR-039 heads that category "Protocol-Immutable (`#0` or `#active` only, agent key MUST NOT sign)" and gives the reason: "if the agent can perform these actions, it can bootstrap its own authority or modify its own constraints" (`.docs/adrs/phase-1.md:1279`). Enforcement Stack layer 3 states the network response: "all conformant verifiers reject Category A actions (DID document modifications) signed by `#agent`. Non-conformant SDKs can produce these signatures, but they cannot propagate through the network. The attempt is both rejected and logged as a custody violation" (`.docs/adrs/phase-1.md:1300`).

**Where its key material lives, and who chooses.** A software keystore holds `#agent`, and the tier is the design rather than a participant's choice. §9.7.4 of the security spec states it: "Software-held — no HSM requirement (agent runtimes typically lack hardware security)" (`.docs/specs/09-security-model.md:704`). ADR-039's Enforcement Stack layer 1 places it: "`#agent` in software keychain accessible to agent runtime" (`.docs/adrs/phase-1.md:1296`). Both platform adapters restate the placement as unconditional: ADR-025 states that "The Agent Signing Key is always software-held (Keychain, not Secure Enclave) since it is designed for autonomous agent operation" (`.docs/adrs/phase-5.md:508`), and ADR-027 states that it is "always software-held (Bouncy Castle, not Android Keystore TEE) since it is designed for autonomous agent operation and may need to be exported or rotated independently" (`.docs/adrs/phase-6.md:419`).

**Why the tier is the design.** ADR-039's Enforcement Stack layer 1 states the custody-separation property, and it conditions the property on the platform: "`#active` in hardware (Secure Enclave / Android Keystore) with session-based biometric unlock. `#agent` in software keychain accessible to agent runtime. Agent physically cannot invoke `#active` on hardware-backed platforms. On software-only platforms, isolation is process-level (different keychains, different access controls)" (`.docs/adrs/phase-1.md:1296`). *Derivation:* the separation is what places `#agent` in software the agent runtime reaches and `#active` in custody that runtime does not reach, so giving the agent runtime the human's custody tier would delete the property the layer exists to provide. Layer 1's own text states that the physical form of the separation holds on hardware-backed platforms and that software-only platforms get process-level isolation instead, so the strength of the separation varies by platform while its direction does not.

The `agent_key_custody` field of the `ScpKeyCustodyAttestation` service entry carries the agent key's published custody value, and it is absent when no agent key exists (`crates/scp-did/src/attestation.rs:68`). `ScpKeyCustodyAttestation::derive` reads that value off the custody backend holding the agent key, so a DID owner writes no value into it (§3.2.2). §27.4.4 of the attestations spec governs what a consumer reads off it.

**Rotation.** `rotate_agent_key`, ADR-003 §4a′, which replaces the `#agent` verification method, signs the update with `#0`, and "Also used for initial agent key provisioning: if no `#agent` VM exists, adds one" (`.docs/adrs/phase-1.md:366`–`:372`). §9.7.4 of the security spec states the follow-through: every scoped UCAN carrying `fct.scp_key_scope: "#agent"` under the old key "are revoked and reissued with the new key", and every active MLS group receives an Update proposal with a new credential (`.docs/specs/09-security-model.md:723`). ADR-003 §4a′ retains the superseded key as `#retired-agent-{sequence}` and keeps at most two (`.docs/adrs/phase-1.md:368`); the shipped rotation writes that fragment (`crates/scp-did/src/document.rs:1046`).

**Removal.** Removing `#agent` revokes agent access. §9.12 of the security spec states the path for a compromised agent key: "Human uses `#0` (Identity Key) to publish a new DID document removing or replacing the `#agent` verification method", then revokes the agent-scoped UCANs, issues MLS Update proposals, and publishes fresh KeyPackages (`.docs/specs/09-security-model.md:1322`).

**Place in the DID document.**

| Array | Rule | Source |
|-------|------|--------|
| `verificationMethod` | MAY include `#agent` | `.docs/specs/18-addressability-and-deployment.md:145` |
| `authentication` | MAY reference `#agent` | `.docs/specs/18-addressability-and-deployment.md:147` |
| `assertionMethod` | Same as `authentication`, so MAY reference `#agent` | `.docs/specs/18-addressability-and-deployment.md:148` |
| `capabilityDelegation` | MUST reference only `#0`, so it does not reference `#agent` | `.docs/specs/18-addressability-and-deployment.md:149` |
| `capabilityInvocation` | MUST reference `#0` and `#active`, and names no other method | `.docs/specs/18-addressability-and-deployment.md:150` |

**Wire format of its verification method entry.** §18.2.2A gives the entry (`.docs/specs/18-addressability-and-deployment.md:98`–`:103`):

```json
{
  "id": "did:dht:<key>#agent",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:dht:<key>",
  "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
}
```

### 3.9.5 The Pre-Rotation Key

**What it is.** An Ed25519 keypair generated at identity creation and committed to before it is needed, which becomes the new Identity Key when the identity migrates. §9.7.4 of the security spec states its generation and reveal: "Generated at identity creation, stored in cold/offline custody (see §9.7.4.1 for custody requirements). `SHA-256(public_key)` is published as a PreRotationCommitment in the DID document. Revealed only during Identity Key migration (ADR-003 §4b) to prove legitimate rotation" (`.docs/specs/09-security-model.md:703`). §9.7.4's rotation entry states what it becomes: identity migration "Creates a new DID with the pre-rotation key as the new Identity Key" (`.docs/specs/09-security-model.md:724`). ADR-003 §4b states the same step in the migration procedure: it "imports those bytes into operational custody as the NEW Identity Key (`#0`) of the migrated identity" (`.docs/adrs/phase-1.md:391`), and the platform trait that performs the import documents the same purpose (`crates/scp-platform/src/traits.rs:483`).

**Authority.** It carries no authority while it stays committed. It acquires `#0`'s authority at the moment migration installs it, and §3.9.2 then governs it.

**What it signs.** Nothing. The pre-rotation proof reveals a preimage rather than producing a signature: the shipped `PreRotationProof` carries a `commitment` and a `revealed_key` and no signature field, and it verifies that "`SHA-256(revealed_key)` must equal the `commitment` from the service endpoint" (`crates/scp-did/src/document.rs:1232`–`:1248`). ADR-003 §4b assigns the signature in a migration to the outgoing key: the migration proof is "signed by the OLD identity key" (`.docs/adrs/phase-1.md:384`). *Derivation:* the pre-rotation key's private half therefore does no signing before migration, and after migration it signs what §3.9.2 assigns to `#0`.

**What it MUST NOT sign.** Every protocol action, for as long as it remains a commitment. No artifact assigns it any signing duty, and §9.7.4.1 item 5(f) requires the creating device to destroy its copy once the backup is confirmed: the SDK MUST "Destroy the pre-rotation private key from the creating device's memory after backup is confirmed" (`.docs/specs/09-security-model.md:773`). *Derivation:* a key the creating device no longer holds cannot sign anything there, so the prohibition and the custody requirement enforce each other.

**Where its key material lives, and who chooses.** The participant chooses from a menu the SDK presents, and the chosen substrate MUST be isolated from the substrate that serves daily operations. §9.7.4.1 of the security spec states four requirements that bear on this:

- Generation: "The pre-rotation keypair MUST be generated on the device during identity creation, using the platform's CSPRNG. The private key MUST NOT be generated on a remote server" (`.docs/specs/09-security-model.md:740`).
- Storage isolation: "The pre-rotation private key MUST be stored separately from the Identity Key and Active Signing Key. It MUST NOT be accessible through the same custody provider or authentication flow used for daily operations" (`.docs/specs/09-security-model.md:744`).
- Recovery-authority residence: the recovery authority "MUST reside in a substrate whose compromise is **independent** of operational-custody compromise", and where no such substrate is available, "identity creation MUST fail closed with a typed error. There is no fallback to co-located operational storage" (`.docs/specs/09-security-model.md:746`, `.docs/specs/09-security-model.md:748`).
- Participant choice: the approved custody methods are a table of six — hardware security key, secondary device secure enclave, platform-backed cloud key store, encrypted offline backup, Shamir 3-of-5, and BIP39 paper backup (`.docs/specs/09-security-model.md:760`–`:763`) — and the SDK "MUST … Present the user with custody options (ordered by security as above)" and "Guide the user through the selected custody method" (`.docs/specs/09-security-model.md:767`–`:768`).

ADR-054, pre-rotation key custody substrate isolation, carries the per-profile realization of the residence rule, and it is Proposed rather than Accepted: its status line states that "the recovery-authority-residence RULE is canonical in spec §9.7.4.1 item 3a; this ADR's realization … is PROPOSED in RFC #2130" (`.docs/adrs/ADR-054-pre-rotation-custody-substrate-isolation.md:3`). §3.9.8 records where two platform ADRs state a placement the isolation requirement forbids.

**Rotation.** Single use, then replacement. §9.7.4.1 item 6 states it: "After a pre-rotation key is used for Identity Key migration (§9.12), the protocol MUST immediately generate a new pre-rotation keypair, guide the user through custody selection again, and publish a new `PreRotationCommitment`. The old pre-rotation key is destroyed after migration completes" (`.docs/specs/09-security-model.md:775`). §9.7.4.1 also states the replacement path when the key is compromised but `#0` is not: "The user MUST immediately generate a new pre-rotation keypair and publish a new `PreRotationCommitment` to their DID document" (`.docs/specs/09-security-model.md:783`).

**Place in the DID document.** The pre-rotation key is not a verification method. It appears in no verification-relationship array, and the document carries a hash of its public key rather than the public key itself: "Only the hash is published — the public key itself is never published until the pre-rotation key is used" (`.docs/specs/09-security-model.md:742`). It rides in the `service` array as an entry of type `PreRotationCommitment` (`.docs/specs/18-addressability-and-deployment.md:120`–`:124`).

**Wire format of its service entry.** §18.2.2A gives the entry (`.docs/specs/18-addressability-and-deployment.md:120`–`:124`):

```json
{
  "id": "#scp-prerotation",
  "type": "PreRotationCommitment",
  "serviceEndpoint": "<sha256-hex-of-prerotation-public-key>"
}
```

The shipped constructor writes the type string `"PreRotationCommitment"`, the fragment `#pre-rotation`, and a `serviceEndpoint` of the form `sha256:<lowercase-hex>` (`crates/scp-did/src/document.rs:373`–`:377`). §3.9.8 records the fragment divergence, and open question OQ-4 of this spec carries the endpoint form.

### 3.9.6 Key Lifecycle

Identity keys follow a defined lifecycle: generation (in hardware security modules where available), distribution (via DID document publication), rotation (DID document update with authorization chain from old key), and destruction (for ephemeral context keys). §9.7.4 of the security spec carries the full lifecycle specification, including compromise recovery (`.docs/specs/09-security-model.md:695`), and §9.7.4.1 carries the pre-rotation key's custody requirements (`.docs/specs/09-security-model.md:734`). §9.12 of the security spec carries the ordered compromise-recovery protocol (`.docs/specs/09-security-model.md:1317`).

### 3.9.7 Signing-Key Attribution on the Wire

Three protocol structures carry the verification method that signed them, so a verifier resolves the right public key without out-of-band metadata. ADR-039 names all three: `ScpCredential.signing_key_id`, `InnerEnvelope.signing_key_id`, and `SenderKeyEpochAdvance.signer_key_ref` (`.docs/adrs/phase-1.md:1325`). Each carries a `SigningKeyId`, which admits `Active` and `Agent` only (`crates/scp-did/src/lib.rs:192`). §3.11.3 of this spec carries the fourth, `ScpIdAuthentication.signing_key_id`, and states what binding it into the signed preimage buys: "a signature produced with `#agent` cannot be presented as `#active`" (`.docs/specs/03-identity.md:1528`).

### 3.9.8 Divergences This Section Records

Each entry below quotes both artifacts and states why the two cannot both hold. This section resolves none of them; each routes to a numbered open question in §3.9.9 or to the artifact that owns it. The last paragraph records the restatements this change replaced.

**D1 — ADR-039's key-properties table states `#active`'s custody as a fixed value, and §3.9.3 states it as a participant's choice.** ADR-039's key-properties table gives the Backing row as "| Backing | Hardware (SE/AKS) | Software | Software |", whose `#active` column reads "Software" (`.docs/adrs/phase-1.md:1268`). §3.9.3 above states that the participant chooses `#active`'s custody, that platform secure storage is the expectation, and that the `ScpKeyCustodyAttestation` entry records the choice. The two cannot both hold, because a fixed value and a participant's choice cannot both settle one key's custody: if the participant chooses between the two backends §3.2.2 of this spec names, then no artifact names the outcome in advance, and a cell that names "Software" excludes the outcome of one of the two choices the participant may make. §3.9.3 states the rule. This change does not edit that table cell; a separate change owns it.

**D2 — `#0`'s Backing cell states a placement one platform cannot provide.** ADR-039's key-properties table gives `#0` the Backing value "Hardware (SE/AKS)" with no platform condition (`.docs/adrs/phase-1.md:1268`). ADR-027, the Android platform adapter, states: "Apple's Secure Enclave supports only P-256; SCP identity keys (Ed25519) must be software-backed in Keychain on Apple" (`.docs/adrs/phase-6.md:38`). The two cannot both hold for an identity created on an Apple platform, because ADR-039's own Decision block gives `#0` as Ed25519 (`.docs/adrs/phase-1.md:1255`), and one Ed25519 key cannot sit in a secure element that holds no Ed25519 key while also sitting in the Keychain, where ADR-025 places it (`.docs/adrs/phase-5.md:508`). §9.7.4 of the security spec states the same placement with the condition attached — "Generated in hardware security module **where available**" (`.docs/specs/09-security-model.md:701`) — so the divergence separates the unconditioned table cell from the three artifacts that state the condition, and it does not separate the security spec from the platform ADRs. §3.9.2 states the conditional form. Two further sentences use "hardware-backed `#0`" as shorthand for the strongest tier while making a different point — ADR-001 on why a KeyPackage attestation is signed by `#active` or `#agent` (`.docs/adrs/phase-1.md:106`) and §23 of the sync spec restating the same reason (`.docs/specs/23-sync-and-offline-strategy.md:193`) — and this divergence covers that phrase wherever it appears.

**D3 — the DID document schema permits no `#retired-*` verification method, and three artifacts require one.** §18.2.2A of the addressability spec states: "`verificationMethod` | Yes | MUST include `#0` (Identity Key). MUST include `#active` (Active Signing Key). MAY include `#agent` (Agent Signing Key, optional per ADR-039). No other verification methods permitted." (`.docs/specs/18-addressability-and-deployment.md:145`). ADR-003 §4a states: "Retains the old key as `#retired-{sequence}` for historical verification. Retired key retention is bounded: the document retains at most the 2 most recent retired active keys" (`.docs/adrs/phase-1.md:359`). §9.7.1 check 1 of the security spec instructs a verifier on what to do with such an entry: it "MUST NOT accept an attestation signed by any `#retired-*` verification method" (`.docs/specs/09-security-model.md:634`). The shipped rotation writes the entry (`crates/scp-did/src/document.rs:888` for `#retired-{sequence}`, `crates/scp-did/src/document.rs:1046` for `#retired-agent-{sequence}`). These cannot all hold, because a document that retains a `#retired-1` entry carries a verification method that is none of `#0`, `#active`, or `#agent`, which §18.2.2A forbids, and a document that omits the entry loses the historical verification ADR-003 §4a requires and leaves §9.7.1 check 1 with nothing to reject. Open question OQ-1 of this spec.

**D4 — two platform ADRs route the pre-rotation key through the operational custody provider.** §9.7.4.1 item 3 of the security spec states: "The pre-rotation private key MUST be stored separately from the Identity Key and Active Signing Key. It MUST NOT be accessible through the same custody provider or authentication flow used for daily operations" (`.docs/specs/09-security-model.md:744`). ADR-025's first acceptance criterion states that `AppleKeyCustody.generateKeypair` stores private key bytes in the Keychain and is "Called four times during identity creation when agent delegation is enabled (ADR-039): Identity Key, Active Signing Key, Pre-Rotation Key, and Agent Signing Key" (`.docs/adrs/phase-5.md:508`); ADR-027's first acceptance criterion states the same four calls through `AndroidKeyCustody.generateKeypair` (`.docs/adrs/phase-6.md:419`). These cannot both hold, because one provider that generates and stores all four keys is the arrangement item 3 forbids: the pre-rotation key is then reachable through the custody provider that serves daily operations. ADR-054 states that the same rule is unmet on the FFI callback path and owns closing it there (`.docs/adrs/ADR-054-pre-rotation-custody-substrate-isolation.md:3`); no artifact reconciles the two platform ADRs' acceptance criteria with item 3. Open question OQ-2 of this spec.

**D5 — the pre-rotation service entry's fragment differs between the schema and the shipped writer.** §18.2.2A of the addressability spec gives the entry's `id` as `"#scp-prerotation"` (`.docs/specs/18-addressability-and-deployment.md:121`). The shipped constructor writes `format!("{did}#pre-rotation")` (`crates/scp-did/src/document.rs:374`). The two cannot both hold, because a resolver that selects the entry by fragment finds one spelling and not the other, and §18.2.2A requires the `service[].id` to be a "Fragment identifier … Unique within the document" (`.docs/specs/18-addressability-and-deployment.md:152`). Open question OQ-3 of this spec.

**D6 — the SQLCipher raw-key derivation reads `#0`'s private bytes, and §9.7.4 states those bytes never leave the secure element.** §17 of the persistence spec states the derivation input: "The `ikm` is the raw private key bytes of the `#0` Identity Key, retrieved from platform key custody (iOS Keychain, Android Keystore, macOS Keychain, or OS keyring)" (`.docs/specs/17-persistence-and-storage.md:482`). §9.7.4 of the security spec states the constraint: "Generated in hardware security module where available (Secure Enclave, Android Keystore). Private key never exported from the secure element" (`.docs/specs/09-security-model.md:701`). The two cannot both hold on a platform that holds `#0` in a secure element, because the derivation needs 32 bytes the secure element does not release. §17.8 of the persistence spec names two such platforms in its own custody table — Android, "Android Keystore (TEE-backed, API 33+ for Ed25519)", and Browser, "WebCrypto + IndexedDB (non-extractable CryptoKey)" (`.docs/specs/17-persistence-and-storage.md:667`–`:668`). The passphrase mode §17 defines beside the raw-key mode does not cover the case: its stated precondition is a caller "with no platform key custody and no `#0` identity key available at database-open time" (`.docs/specs/17-persistence-and-storage.md:488`), which describes a deployment that has no `#0` rather than one whose `#0` is non-exportable. Open question OQ-6 of this spec.

**D7 — the routing-ID derivation reads `#0`'s public key in the spec and its private key in the code.** §3.7 of this spec gives the input as the public half: its derivation block reads "ikm:  identity_key_material,      // raw bytes of #0 public key" (`.docs/specs/03-identity.md:597`), and the privacy argument beneath it rests on that reading — the derivation "requires `identity_key_material` (the `#0` public key bytes), which the relay does not possess unless it has previously resolved the DID" (`.docs/specs/03-identity.md:604`). The shipped function documents the private half: "`identity_key_material` — The raw bytes of the identity's `#0` key material (typically the Ed25519 private key bytes or an HSM-derived secret)" (`crates/scp-protocol/src/identity/private_state.rs:56`–`:58`). The two cannot both hold, because the public key and the private key are different byte strings and HKDF over each yields a different `routing_id`, so two implementations reading different halves address different records for one identity. They also differ in what §3.7's privacy argument claims: a relay that resolves the DID obtains the public key and can then recompute the routing ID, while it never obtains the private key. Open question OQ-7 of this spec.

**D8 — `#active` must perform Ed25519-to-X25519 key agreement, and §3.7 states that conversion fails on a hardware-backed key.** The invitation-open path requires it of `#active` (`crates/scp-protocol/src/crypto/envelope_seal.rs:158`–`:161`), and `KeyCustody::ed25519_to_x25519_agree` carries no default body and no hardware carve-out (`crates/scp-platform/src/traits.rs:469`), unlike `import_ed25519_signing_key`, whose documentation directs HSM-bound custody to "return [`PlatformError::Unsupported`]" (`crates/scp-platform/src/traits.rs:489`–`:494`). §3.7 of this spec states the constraint: Ed25519-to-X25519 conversion "requires access to the Ed25519 private key bytes — which hardware security modules (Secure Enclave, Android Keystore) do not export. A design that depends on Ed25519-to-X25519 conversion would fail on every hardware-backed key" (`.docs/specs/03-identity.md:769`). These cannot both hold for a participant who exercises the choice §3.9.3 states and puts `#active` in hardware: the invitation-open path then asks custody for an operation §3.7 says that custody cannot perform. Open question OQ-8 of this spec.

**D9 — two shipped doc comments named the severed in-memory pre-rotation backend the production default, and this change corrects them.** Before this change, `PreRotationCustodyKind::InMemory` and the `PreRotationCustody` trait documentation in `crates/scp-platform/src/traits.rs` each described `InMemoryPreRotationCustody` as the backend a shipped build uses — one calling it the default in production FFI and SDK paths, the other calling it today's shipped backend. Two artifacts state the opposite. The identity crate documents that the in-memory implementation "is now gated to the test harness only (ADR-062 §Decision 6). On a shipped (no-`testing`) build there is no real backend, so identity creation FAILS CLOSED with this typed error" (`crates/scp-identity/src/lib.rs:169`–`:172`), and `crates/scp-platform/src/lib.rs:67` gates the module that exports it behind `#[cfg(feature = "testing")]`. The two readings cannot both hold, because a module absent from a shipped build cannot be that build's default backend. The no-dev-stand-in tenet of `CLAUDE.md` makes the direction of the error the serious one: a document asserting that an in-memory recovery backstop ships states a false guarantee about the key §3.9.5 governs, and `traits.rs` is the file an SDK author reads to decide what to implement. Both comments now state the gating and the fail-closed behaviour.

**D10 — §18.2.2 says the pre-rotation commitment covers `#active`, and §9.7.4 says it covers only the Identity Key.** §18.2.2 of the addressability spec describes the service type as the "SHA-256 commitment hash for pre-rotation key (applies to `#0` and `#active` only; `#agent` is a software key with simpler rotation — no pre-rotation needed, see ADR-039)" (`.docs/specs/18-addressability-and-deployment.md:59`). §9.7.4 of the security spec assigns the reveal to one operation: the pre-rotation key is "Revealed only during Identity Key migration (ADR-003 §4b)" (`.docs/specs/09-security-model.md:703`), and rotating `#active` runs `rotate_active_key`, which §3.2.1 of this spec describes without any pre-rotation step (`.docs/specs/03-identity.md:26`). The two cannot both hold, because a commitment that "applies to `#active`" would have to be revealed when `#active` rotates, and no artifact defines a reveal on that path. This is the third instance of the reading D4 corrects. A separate change rewrites the surrounding subsection, so this change cites the line and does not edit it.

**D11 — §9.15 lets `#0` sign a key-destruction attestation, and §9.7.1 reserves `#0` from operational signing.** §9.15 of the security spec gives the field as "signature: Ed25519Signature // signed by #0 (Identity Key) or #active (Active Signing Key); NOT #agent — agents cannot sign destruction attestations (ADR-039)" (`.docs/specs/09-security-model.md:1388`). §9.7.1 of the same spec states the reservation: "`#0` is reserved exclusively for DID document operations and pre-rotation commitments (ADR-003, ADR-039)" (`.docs/specs/09-security-model.md:628`). The two cannot both hold, because a key-destruction attestation is neither a DID document operation nor a pre-rotation commitment, so the word "exclusively" excludes exactly the signature §9.15 permits. A separate change owns §9.15, so this change cites the line and does not edit it.

**D12 — a governance seed is wrapped to `#0` with HPKE, and §3.7 states that the conversion `#0` would need fails on a hardware-backed key.** §7.3.2.1 of the trust spec states the wrapping: the seed "is stored encrypted in the context's governance state, wrapped to the current admin's `#0` identity key using HPKE (X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20Poly1305)" (`.docs/specs/07-trust-validation-and-capabilities.md:278`). `#0` is Ed25519 (`.docs/adrs/phase-1.md:1255`), so unwrapping requires the same Ed25519-to-X25519 conversion §3.7 of this spec rules out: it "requires access to the Ed25519 private key bytes — which hardware security modules (Secure Enclave, Android Keystore) do not export. A design that depends on Ed25519-to-X25519 conversion would fail on every hardware-backed key" (`.docs/specs/03-identity.md:769`). The two cannot both hold on a platform that holds `#0` in a secure element, which §17.8 of the persistence spec names for Android at API 33 and above (`.docs/specs/17-persistence-and-storage.md:667`). This is divergence D8 applied to `#0` instead of `#active`. Open question OQ-8 of this spec covers both.

**D13 — one custody name resolves to platform secure storage in two SDKs and to an encrypted file in the third.** The Swift SDK documents `CustodyType.platform` as "Platform-native secure storage (Keychain on macOS/iOS, Keystore on Android, credential manager on Windows/Linux). Default." (`bindings/swift/Sources/SCP/Types.swift:21`–`:23`), and the Kotlin SDK documents `PLATFORM("platform")` with the same sentence (`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Types.kt:84`–`:87`). The Python SDK documents the same string differently: "``\"platform\"`` is a backward-compatible alias — both resolve to ``FileKeyCustody`` (Argon2id + AES-256-GCM encrypted key file at ``$HOME/.scp/keys.bin``)" (`bindings/python/scp_sdk/types.py:33`–`:35`), and its `PLATFORM` member is declared a "Backward-compatible alias for :attr:`FILE`" (`bindings/python/scp_sdk/types.py:44`, `:47`). The three cannot all hold, because one enum value names one custody model and an OS keystore is not an encrypted file on disk. This bore directly on the rule §3.9.3 states: a participant who selected the custody named for platform secure storage got it in two SDKs and got a file in the third, so the same declared choice yielded two different published custody values in the `ScpKeyCustodyAttestation` entry that records it. §3.2.2 of this spec settles it by removing `platform` from the vocabulary altogether, and this entry records what the three SDKs said before that change.

**Restatements this change replaced.** Two artifacts carried per-key claims that the sources above contradict, and this change replaced both with the rule §3.9 states. §11.2.3 of the prior-art spec described `#active` as hardware-backed and described the pre-rotation key as "a commitment to the next Human Signing Key"; `.docs/white-paper.md` carried the same two claims in its multi-key subsection and in the diagram beside it. §9.7.4 of the security spec, §9.12 of the security spec, ADR-003 §4b, and the shipped platform trait each state that identity migration installs the revealed pre-rotation key as the new Identity Key (`.docs/specs/09-security-model.md:724`; `.docs/specs/09-security-model.md:1324`; `.docs/adrs/phase-1.md:391`; `crates/scp-platform/src/traits.rs:483`), and §3.2.1 of this spec assigns replacing `#active` to `rotate_active_key`, which leaves the DID unchanged (`.docs/specs/03-identity.md:26`), while the pre-rotation mechanism runs only when "`#0` itself must move" and "creates a new DID" (`.docs/specs/03-identity.md:28`). Both artifacts now cite §3.9 instead of restating it.

### 3.9.9 Open Questions

Each entry names what no artifact defines, which artifact should define it, and what an implementer hits meanwhile. *Derivation:* every "Breaks meanwhile" clause reasons from the artifacts the entry cites to a consequence those artifacts do not themselves state.

**OQ-1 — May a DID document carry `#retired-*` verification methods, and if so, how does §18.2.2A admit them?** *Undefined:* §18.2.2A permits no verification method beyond `#0`, `#active`, and `#agent`, while ADR-003 §4a and §4a′ require up to two retired active keys and two retired agent keys, and §9.7.1 check 1 instructs verifiers about entries §18.2.2A forbids (§3.9.8, divergence D3). *Should define it:* §18.2.2A of the addressability spec, which owns the `verificationMethod` constraint. *Breaks meanwhile:* an implementer building from §18.2.2A rejects every document a shipped SCP rotation produces, and a document that satisfies §18.2.2A drops the historical verification ADR-003 §4a requires.

**OQ-2 — Which custody provider generates the pre-rotation key on Apple and Android?** *Undefined:* §9.7.4.1 item 3 forbids the operational custody provider from holding it, and ADR-025 and ADR-027 both instruct their operational provider to generate it (§3.9.8, divergence D4). *Should define it:* ADR-025 and ADR-027, whose acceptance criteria state the call, in the shape the §9.7.4.1 item 3a residence rule and the ADR-054 realization settle. *Breaks meanwhile:* an SDK built to either platform ADR's acceptance criterion produces an identity whose recovery backstop sits in the substrate §9.7.4.1 item 3 excludes it from, so a compromise of operational custody takes the recovery path with it.

**OQ-3 — Is the pre-rotation service entry's fragment `#scp-prerotation` or `#pre-rotation`?** *Undefined:* §18.2.2A gives one spelling and the shipped writer produces the other (§3.9.8, divergence D5). *Should define it:* §18.2.2A of the addressability spec, which owns the DID document schema. *Breaks meanwhile:* a resolver written against the spec finds no pre-rotation commitment in a document a shipped SDK published, so it cannot verify a pre-rotation proof at migration.

**OQ-4 — Does the pre-rotation service entry's `serviceEndpoint` carry a bare hex string or a `sha256:`-prefixed one?** *Undefined:* §18.2.2A's example gives the value as the placeholder `"<sha256-hex-of-prerotation-public-key>"` (`.docs/specs/18-addressability-and-deployment.md:123`), which does not state whether a prefix belongs inside it, and the shipped writer emits `format!("sha256:{}", hex::encode(pre_rotation_commitment))` (`crates/scp-did/src/document.rs:376`). This section states no divergence here, because the placeholder admits both readings. *Should define it:* §18.2.2A of the addressability spec. *Breaks meanwhile:* two implementations parse the same commitment differently, and the one that compares the raw endpoint string against a computed hex digest rejects a valid pre-rotation proof.

**OQ-5 — Does `capabilityInvocation` reference `#agent`, and does `capabilityDelegation` reference `#active`?** *Undefined:* §18.2.2A states "`capabilityDelegation` | Yes | MUST reference only `#0`" and "`capabilityInvocation` | Yes | MUST reference `#0` and `#active`" (`.docs/specs/18-addressability-and-deployment.md:149`–`:150`), and neither row names `#agent`. ADR-039 assigns root UCAN issuance to `#active` (`.docs/adrs/phase-1.md:1283`) and sub-delegation of scoped UCANs to `#agent` under Category B (`.docs/adrs/phase-1.md:1286`), and no artifact maps either UCAN operation onto a W3C DID verification relationship. This section states no divergence here, because no artifact claims the mapping that would make the two statements conflict. *Should define it:* §18.2.2A of the addressability spec, stating which verification relationship each UCAN operation exercises. *Breaks meanwhile:* a relying party that gates UCAN acceptance on the DID document's `capabilityDelegation` array rejects every root UCAN, because that array names only `#0` and ADR-039 assigns root UCAN issuance to `#active`.

**OQ-6 — How does a database open on a platform whose `#0` is non-exportable?** *Undefined:* §17's raw-key mode reads `#0`'s raw private bytes, §9.7.4 states those bytes never leave a secure element, and §17's passphrase mode is scoped to callers that have no `#0` at all (§3.9.8, divergence D6). *Should define it:* §17 of the persistence spec, which owns the SQLCipher key-derivation modes. *Breaks meanwhile:* an SDK on Android at API 33 or above, or in a browser, follows §17's default raw-key mode, asks custody for bytes the substrate does not release, and cannot open the encrypted database — while an SDK that exports the bytes to make the derivation work gives up the property §9.7.4 states for `#0`.

**OQ-7 — Does the identity-private-state routing ID derive from `#0`'s public key or its private key?** *Undefined:* §3.7 of this spec states the public key and builds its relay-pseudonymity argument on that reading, and the shipped function documents the private key or an HSM-derived secret (§3.9.8, divergence D7). *Should define it:* §3.7 of this spec, which owns the derivation. *Breaks meanwhile:* two implementations derive different routing IDs for one identity, so one cannot read the private state the other wrote, and the privacy property §3.7 claims holds only under the public-key reading.

**OQ-8 — What happens when a participant puts `#active` in hardware custody and then opens an invitation?** *Undefined:* §3.9.3 states the custody choice, the invitation-open path requires Ed25519-to-X25519 agreement on `#active`, and §3.7 states that conversion fails on every hardware-backed key (§3.9.8, divergence D8). *Should define it:* §5.12.3.1 of the contexts spec, which owns the invitation-open path, choosing between a separate X25519 key for invitation receipt and a stated custody restriction on `#active`. *Breaks meanwhile:* a participant who chooses the strongest custody §3.9.3 offers cannot be invited to a context, and no artifact warns them before they choose.

**OQ-9 — Does `CustodyType.platform` name an OS keystore or an encrypted key file?** *Answered by §3.2.2 of this spec:* neither, because `platform` is not a value in the custody vocabulary. §3.2.2 states the two values a caller names — `encrypted_file` for the on-disk key store SCP implements, and `os_keystore` for the operating system's own key store — and states why the word `platform` is unavailable to a custody vocabulary: W3C Web Authentication uses it for a transport modality and Windows CNG uses it for the Trusted Platform Module. The three SDK enums, the three bridge parsers, and §3.2.1's migration target now carry those two values, which is what §3.2.2.1, divergence D13, records.

## 3.10 DID Resolution Layers

DID resolution is the trust root for identity verification (§3.8). The current architecture resolves identities exclusively via Mainline DHT — BEP44 signed mutable items stored on BitTorrent's distributed hash table, a network of millions of nodes with over 20 years of operational history. This works, and it works well. But it routes all identity resolution through infrastructure SCP does not control, cannot improve, and cannot guarantee will continue to operate on terms compatible with the protocol's needs.

SCP introduces a dual-layer resolution architecture:

- **Primary: SCP relay-based resolution.** DID documents published to SCP relays via the existing PUBLISH/QUERY operations (ADR-004), addressed by a deterministic `routing_id`. An SCP-native relay validates each DID-record blob it stores and keeps a single highest-sequence slot per `routing_id` (§3.10.2), which is what makes the relay layer suppression-resistant (§3.10.8); foreign transports that cannot validate store the record opaquely and stay correct via client-side verification. Grows with the SCP network.
- **Fallback: Mainline DHT.** Existing did:dht resolution via BEP44. Works from day one. Transitions from "only path" to "fallback path" as the relay network matures.

Both layers are self-certifying: the BEP44 signature on a DID document is verified against the public key encoded in the DID string itself (§9.6.1). The storage backend — whether an SCP relay or a DHT node — is untrusted. Trust derives from the cryptographic binding between the DID and its document, not from the infrastructure serving it. An SCP-native relay MAY additionally validate the records it stores (§3.10.2) — a validating relay keeps a single highest-sequence slot, which resists suppression — but this is an availability property layered on top, never a trust dependency: the resolver re-verifies every record independently and accepts nothing on the relay's word (§3.10.4).

### 3.10.1 Resolution Priority

| Layer | Backend | Day-one availability | Latency | SCP dependency |
|-------|---------|---------------------|---------|----------------|
| 1 | SCP relays | Low (few relays exist) | Low (relay QUERY, single hop) | Yes |
| 2 | Mainline DHT | High (millions of nodes) | Higher (DHT traversal, 1-3s typical) | No |

Resolution strategy: query both layers in parallel. The first valid response wins. "Valid" means the BEP44 signature verifies against the public key encoded in the target DID AND the sequence number is greater than or equal to the last known sequence number for that DID. When both layers return valid documents, the document with the highest sequence number is accepted.

Parallel query means resolution latency is `min(relay_latency, dht_latency)`. The slower query is cancelled once the first valid response arrives.

### 3.10.2 Layer 1: SCP Relay-Based Resolution

DID documents are published to SCP relays using the existing PUBLISH/QUERY operations (ADR-004) — no new wire types. A DID document rides in a minimal, fixed-layout **DID-record relay frame** (§9.10.12), addressed by a deterministic `routing_id`. What is new versus a plain opaque blob is a relay *behavior*: an SCP-native relay validates the frame and keeps a single highest-sequence slot per `routing_id`. This is issue #482.

**Routing ID derivation:**

```
did_routing_id = SHA-256("scp:did:" || did_string)
```

The `"scp:did:"` domain separator prevents collision with other routing ID derivation schemes in the protocol: encrypted context routing IDs use HKDF from identity key material (§9.10.4), broadcast context routing IDs use `SHA-256(context_id)` (§5.14), and context metadata routing IDs use `HMAC-SHA256(context_metadata_key, context_id || "scp-metadata-v2")` (§9.10.4.B). The domain separator ensures that a DID string can never produce a routing ID that collides with a context ID or metadata address. Because DID records live at their own `routing_id` domain, the address is the type discriminant — the frame carries no magic tag or record-kind byte (§9.10.12).

**Publication** uses the existing PUBLISH operation (ADR-004):

```
PUBLISH {
    routing_id: did_routing_id,
    blob_ttl: 604800,
    blob: <DID-record relay frame (§9.10.12), carrying (public_key, seq, signature, value)>
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

`limit: N` (N = 16) **dominates `limit: 1`** and costs nothing where it does not help. Against a **validating** SCP-native relay the routing ID is slot-exclusive (below), so exactly one record is returned regardless of `N`. Against a **non-validating or foreign** transport that accumulates multiple blobs per `routing_id`, `limit: N` lets the resolver retrieve up to N candidates and sift them to the highest-sequence *valid* one (§3.10.4 step 5) — defeating an intra-relay shadowing attempt that a single-record fetch would miss, and giving a `DhtMode::Disabled` node (relay-only resolution, which the spec permits) a fighting chance against a non-validating relay. Under an *active* flood on a non-validating relay this remains best-effort (§3.10.8 residual): N candidates may all be junk. The resolver's highest-sequence-valid selection across relays and the DHT (§3.10.4) still returns the freshest genuine record whenever any queried source holds it.

**Relay-side validation (SCP-native relays).** The whole path sits behind the existing per-IP PUBLISH rate limit (ADR-004). On PUBLISH of a blob at a `routing_id`, an SCP-native relay performs the checks **cheapest-first**, so junk is rejected before any expensive work:

1. **Structural decode.** Attempt to decode the blob as a DID-record frame (§9.10.12). A blob that does not decode is not a candidate DID record (it is governed by the slot-exclusivity rule below).
2. **DID→routing_id binding.** Confirm `SHA-256("scp:did:" || did(public_key)) == routing_id`, where `did(public_key)` is the `did:dht` string derived from the frame's `public_key` (z-base-32, §9.6.1). A frame whose embedded `public_key` does not hash to the `routing_id` it is published at is rejected. This binding is the discriminant that lets a validating relay recognize a DID record without any new wire type or knowledge of `routing_id` semantics — and it is a plain hash, cheaper than a signature verify, so it runs **before** step 3.
3. **BEP44 signature.** Only for a blob that passed steps 1–2, verify the BEP44 signature over `bencode(seq, value)` against the frame's `public_key`. Ordering the binding check ahead of the signature verify means a mis-addressed or non-frame blob never costs an Ed25519 verify.
4. **Single highest-sequence slot.** For a frame that passed steps 1–3, keep a **single highest-sequence slot** per `routing_id`: reject a frame whose `seq` is lower than or equal to the stored slot's `seq` **unless** an equal-`seq` frame is byte-identical to the stored record (idempotent TTL refresh), and replace the slot only on a strictly-higher valid `seq`.

**Slot-exclusivity.** A validating relay does not store DID records alongside arbitrary blobs. The moment a binding-valid, signature-valid frame first **establishes a slot** at a `routing_id`, that `routing_id` becomes **slot-exclusive**:

- **(a)** the relay rejects any subsequent PUBLISH at that `routing_id` that is not a binding-valid, `seq`-advancing frame (a non-frame blob, a wrong-binding frame, an invalid signature, or a non-superseding `seq` — all rejected), the sole exception being a byte-identical equal-`seq` republish, which is an idempotent TTL refresh (per single-slot rule 4 above);
- **(b)** when the slot is first established, the relay **evicts any pre-existing opaque blobs** stored at that `routing_id`;
- **(c)** QUERY at that `routing_id` returns **only the single slot**;
- **(d)** the relay **rejects a client-issued DELETE of any stored binding-valid DID-record frame** (the current slot blob in particular) — only a superseding PUBLISH (a strictly-higher-`seq` binding-valid frame) may replace a slot; a client DELETE never removes a genuine record. (Relay-*internal* eviction of superseded frames on establish, rule (b), is not a client DELETE and is unaffected.) Because DELETE addresses a blob by `blob_id` (`= SHA-256(blob)`) rather than by `routing_id`, and the in-memory slot index is a cache that a relay restart or a store-sharing peer node leaves cold, this gate MUST be **storage-derived, not index-derived**: on DELETE the relay reads the blob at `blob_id` and, if it structurally decodes as a DID-record frame that binding- and signature-verifies (a genuine, self-certifying record — the routing_id it binds to is derivable from the frame's own `public_key`), rejects the DELETE regardless of index state. A DID-record frame is content-addressed and self-certifying, so its protected status is reconstructible from the bare blob bytes; this makes rule (d) immune to a cold or unpersisted index. The DELETE gate runs behind the same per-IP rate limit as PUBLISH (the storage read + signature verify it performs must not be an unmetered amplification surface) and **fails closed** on a storage read error (an integrity gate must not let a transient error open a delete).

**Before** the first valid frame, the relay cannot recognize the `routing_id` as DID-domain — `SHA-256` is one-way, so it cannot distinguish a not-yet-claimed DID `routing_id` from any other opaque-blob address. Pre-seeded junk (published *before* the victim's first DID publish) therefore simply sits as ordinary opaque blobs until the first binding-valid frame establishes the slot, at which point rule (b) evicts it. This closes the pre-seeding / non-frame-junk gap: on a validating relay, once the DID owner has published even once, QUERY cannot be made to return anything but the single genuine slot. Slot-exclusivity is a property of a *claimed* slot, and the in-memory slot index can be **cold** (empty) for two distinct reasons that have different consequences:

1. **Blob TTL-expiry** (owner offline past the 6-day republish cycle): the slot record's own blob has expired, so the genuine record is *genuinely absent* from storage. Reversion here is not a suppression bypass — there is nothing to suppress; any attacker blob still fails the resolver's DID-derived-key BEP44 verification, resolution falls through to the DHT, and the owner's next republish re-establishes the slot and re-fires rule (b).

2. **Relay restart or store-sharing peer node** (the slot index is not persisted, so it starts empty even though the durable blob is **still present** in storage): the genuine record is *present*, only the cache forgot it. This is a real, bounded, availability-only window on that one relay until the next binding-valid publish re-warms the index. Two properties keep it availability-only, never integrity: (i) the **read path is storage-authoritative** — QUERY (rule (c)) re-derives the slot from the stored self-certifying frames, so a cold-index QUERY still returns only the genuine highest-`seq` record and never surfaces co-located junk as genuine; and (ii) the **DELETE gate (rule (d)) and establish reconciliation are storage-derived**, so a replayed lower-`seq` genuine frame cannot delete or roll back the present higher-`seq` record even against a cold index. The residual — a junk flood that pushes the genuine record outside a narrow QUERY `limit` window on that single relay before the index warms — is covered by the resolver's highest-`seq`-valid selection across relays + the DHT (§3.10.4). The earlier claim that "the genuine record is already absent" applies **only** to case 1; for case 2 the record is present and the mitigation is the storage-authoritative read/DELETE gates plus multi-source resolution, not absence.

Slot-exclusivity is a relay **storage** behavior (the base relay stores multiple opaque blobs per `routing_id` with no per-`routing_id` cap, ADR-004). This spec section is authoritative for the behavior; the relay-storage mechanics (single highest-`seq` slot, eviction, cold-index reconciliation, the storage-derived DELETE gate) are transcribed in the companion **ADR-004 "DID-Record Slot-Exclusivity" subsection** (implemented under #482 / SCP-RELAYRES-003). The threat-model conclusions — the flood-inert enumeration and the DELETE-rollback vector — are owned by §3.10.8; ADR-004 records how the relay storage layer realizes them.

This mirrors, and extends to a stored public record, the exact check `BRIDGE_REGISTER` already performs on the control plane — Ed25519 signature + the same `SHA-256("scp:did:" || did_string) == routing_id` binding (§10.12.4). It is what Mainline DHT BEP44 nodes already do for mutable items. It is an **availability and anti-suppression measure, never a trust dependency** (see the client-verify property below).

**Relay-side validation is an OPTIONAL capability of SCP-native relays.** The protocol MUST NOT require a validating relay. Foreign transports and adapters (Nostr, Matrix, etc.) that cannot validate treat the frame as an opaque blob; resolution stays correct over them via client-side verification, the DHT, and multi-relay publishing. The suppression-resistance property of the relay layer (§3.10.8) is delivered by validating SCP-native relays; non-validating storage contributes availability only.

**Properties:**

- **Client always re-verifies (relay untrusted).** The resolver ALWAYS verifies the BEP44 signature against the key it derives from the DID string ITSELF (§9.6.1), and never trusts the frame-supplied `public_key` or the relay's acceptance. Relay validation is defense-in-depth for availability; it is never a trust input. A relay that skips, botches, or lies about validation degrades availability only, never integrity.
- **Why the frame carries `public_key`.** The relay holds only the one-way `routing_id` hash and cannot recover the DID or its key from it — so, exactly as `BRIDGE_REGISTER` carries `public_key` for the relay to verify against (§10.12.4), the DID-record frame carries `public_key` for the relay's binding + signature check. The client ignores this field and verifies with its own DID-derived key.
- **Self-verifying blob payload.** The frame carries the BEP44 `(value, signature, seq)` triple, not the bare document bytes. Because the signature and sequence travel inside the blob, a resolver verifies the record from the blob alone — no DHT round-trip is required to obtain the signature.
- **Multi-relay.** A resolver can QUERY any relay that stores the target DID document. Identity owners SHOULD publish to multiple relays — their own relays plus bootstrap relays from the fallback relay list (§18.5.1) — for availability and suppression resistance.
- **Size budget.** DID documents range from 2-30KB depending on attestation count and service endpoint list. The relay blob size limit is 256KB (ADR-004). Well within bounds.
- **TTL and republishing.** The maximum relay blob TTL is 604800 seconds (7 days). Identity owners MUST republish to relays at least every 6 days (1-day safety margin). The RepublishManager already handles periodic DHT republishing on a 2-hour cycle; relay republishing adds a separate 6-day cycle for relay-stored DID documents.

### 3.10.3 Layer 2: Mainline DHT (Fallback)

Existing did:dht resolution via BEP44 signed mutable items on Mainline DHT. The mechanism is unchanged from §3.8 and §9.6.1. What changes is its role: from "only resolution path" to "fallback resolution path."

The DHT layer remains essential for:

- **Day-one operation.** The SCP relay network starts small. Most DID documents will not be available on relays until the network grows. DHT availability is immediate.
- **Resolution of identities not yet publishing to SCP relays.** Older identities or identities using minimal SDK configurations may only publish to DHT. The protocol MUST resolve them.
- **Resilience when all of an identity's relays are down.** DHT provides a resolution path independent of any specific relay's availability.
- **Cross-network interoperability.** Any BEP44-capable client can resolve SCP identities without running SCP software. The DHT layer preserves this property.

### 3.10.4 Resolution Protocol

The full resolution sequence:

```
1. Compute did_routing_id = SHA-256("scp:did:" || did_string)
2. Extract public_key from DID string (z-base-32 decode per did:dht spec)
3. In parallel:
   a. QUERY did_routing_id on known SCP relays (existing QUERY operation,
      ADR-004; the stored blob is a DID-record frame, §9.10.12)
      (identity's published relays if known, else bootstrap relays from §18.5.1)
   b. DhtClient.resolve(public_key) on Mainline DHT
4. For each response, obtain the (value, signature, seq) triple:
   a. Relay response: decode the DID-record frame (§9.10.12) into
      (value, signature, seq). DHT response: the triple is native.
      Framing bytes — including the frame's own public_key — are unsigned
      and MUST NOT be trusted; only the (value, signature, seq) triple is
      used, and it is verified against the DID-derived key (step 4b), never
      the frame-supplied key.
   b. Verify the BEP44 signature over the BEP44-canonical bencoded buffer
      bencode(salt?, seq, value) — seq before value, per BEP44 (BitTorrent
      BEP 44 is authoritative for this ordering) — against public_key
      (the key derived from the DID string in step 2)
   c. Verify seq >= last_known_seq for this DID
5. Accept the valid response with highest sequence number. Within the relay
   layer, if more than one valid record is returned (a non-validating or
   foreign relay that accumulated multiple blobs), the resolver takes the
   highest-seq valid record; across layers, the overall highest-seq valid
   record wins.
6. Cache result per §9.10.7 caching policy
   (24h refresh for active contacts, 7d for inactive)
```

The relay query in step 3a targets relays in priority order: the identity's own relays (from a previously cached DID document), then bootstrap relays. If the resolver has no prior knowledge of the identity's relays, only bootstrap relays are queried for the relay layer — the DHT layer provides the backup.

**Cancellation and contradiction semantics:**

The parallel query model (step 3) requires clear rules for when queries are cancelled, how contradictions are resolved, and what happens on failure:

- **First-response optimization.** When the first valid response arrives, the resolver SHOULD continue waiting for the second layer's response for up to 2 seconds (not cancel immediately). This allows the resolver to detect stale documents: if both layers return valid documents, the higher sequence number is authoritative (step 5). Cancelling the slower query immediately would miss a fresher document on the slower layer.
- **Both layers succeed, same sequence number.** The documents MUST be byte-identical (same key signs both, same content). If they differ despite identical sequence numbers, this indicates a bug in the publishing implementation. The resolver MUST log a warning and accept either document (they should be identical; if not, neither is more authoritative).
- **Both layers succeed, different sequence numbers.** The higher sequence number is authoritative. The resolver MAY re-publish the fresher document to the layer that returned the stale one (protocol-level healing, §3.10.7).
- **One layer fails, one succeeds.** The successful response is accepted. The failed layer's error is logged but does not prevent resolution. The resolver does NOT retry the failed layer synchronously — the next resolution cycle (24h for active contacts, 7d for inactive) will attempt both layers again.
- **Both layers fail.** If a cached document exists and is less than 7 days old, the cached document is returned with a `resolution_source: "cache"` indicator. If no cache exists or the cache is older than 7 days, resolution fails with error `DID_RESOLUTION_FAILED` (code 5010). The resolver MUST NOT fabricate a document.
- **One layer returns invalid signature.** The response is discarded as if the layer had failed. An invalid signature is logged at WARN level (it may indicate relay tampering). The resolver does not fall back to the invalid document under any circumstances.
- **Relay blob fails frame decoding.** A relay blob that does not decode as a valid DID-record frame (§9.10.12) — shorter than the 105-byte fixed prefix, carrying an empty `value`, exceeding the bounded `value` length, or an unrecognized `version` — is discarded as if the relay had failed. Malformed framing is never trusted and never partially parsed (§9.10.12 decoder rules); the resolver falls through to the other layer exactly as for an invalid signature.
- **Timeout.** Each layer query has a 5-second timeout. If a layer does not respond within 5 seconds, it is treated as a failure for that resolution attempt.

### 3.10.5 Publishing Protocol

Identity owners publish to both layers on every DID document create or update:

```
On DID document create or update:
1. Serialize DID document
2. Sign via BEP44 (Ed25519 signature over the BEP44-canonical bencoded buffer
   bencode(salt?, seq, value) — the sequence number precedes the value,
   `3:seqi<seq>e1:v<value>`, per the BEP44 spec, which is authoritative for
   this ordering; did:dht uses no salt)
3. In parallel:
   a. Wrap (public_key, seq, signature, value) in a DID-record frame
      (§9.10.12) and PUBLISH the frame bytes to SCP relays (own relays +
      bootstrap relays) via the existing PUBLISH operation, blob_ttl: 604800.
      The frame is transport framing around `value` — it is NEVER part of the
      bencoded signed bytes.
   b. DhtClient.publish(public_key, signature, doc_bytes, seq) to Mainline DHT
4. RepublishManager schedules:
   - Relay republishing: every 6 days (blob_ttl is 7 days, 1-day margin)
   - DHT republishing: every 2 hours (existing cycle, unchanged)
```

Both layers receive identical document bytes and identical BEP44 signatures. The signed payload is the same regardless of storage backend — this is a direct consequence of the self-certification property. A document retrieved from a relay and a document retrieved from the DHT are byte-identical and verify identically. The DID-record frame wraps `value` for transport but does not enter the signed bytes; the `(value, signature, seq)` triple carried to both layers is byte-identical (§9.10.12).

### 3.10.6 Anti-Segmentation Invariant

**Publishing to both layers is a MUST, not a SHOULD.** Resolution from both layers is a SHOULD (performance optimization — parallel query is faster but not required for correctness).

The risk: if the DHT layer works well enough and relay-based resolution is "just faster," developers may skip DHT publishing as unnecessary overhead. If this becomes widespread, identity resolution fragments — some DIDs resolvable only on relays, others only on DHT. A resolver that checks only one layer misses identities published only on the other. The network splits into two resolution namespaces without anyone intending it.

The SDK prevents this by default. RepublishManager publishes to both layers on every cycle. Disabling either layer requires explicit opt-out (`RepublishConfig::disable_dht()` or `RepublishConfig::disable_relay()`) and the SDK MUST log a warning when either is disabled. The warning states: "DID resolution layer disabled. This identity may not be resolvable by all peers."

**The DHT *backend* is a selected provider capability (§17.17).** The rule above governs whether the DHT *layer* is published to; the choice of which DHT *backend implementation* serves that layer is a further instance of the general capability-selection principle in §17.17. In particular, an in-memory DHT backend is a **security nullifier**, not a durability-only development affordance (§17.17.3, SCP-CAPSEL-8013): it silently empties the DHT resolution namespace — the extreme case of the segmentation this invariant forbids — so a rotation or revocation never propagates (§3.9, §3.10.7). It MUST therefore be provably absent from shipped production artifacts (SCP-CAPSEL-8012), and the DHT backend selection MUST be explicit and fail closed (SCP-CAPSEL-8000/8001), never silently defaulted to the in-memory arm.

### 3.10.7 Version Resolution

The BEP44 sequence number is the sole authority for document freshness. The highest valid sequence number wins, regardless of which layer served it. Split-brain is impossible: the sequence number is monotonically increasing, and only the identity owner (holder of the Ed25519 private key) can increment it.

Stale documents are detected by comparing the received sequence number against the last known sequence number for that DID. A relay or DHT node serving a stale document is not malicious — it simply has not received the latest publish. The stale document is overwritten on the next republish cycle.

When both layers return valid documents with different sequence numbers, the higher sequence number is authoritative. The resolver SHOULD update its cache and MAY re-publish the fresher document to the layer that returned the stale one (protocol-level healing).

### 3.10.8 Security Analysis

The dual-layer architecture preserves all security properties of §9.6.1 (self-certification) while adding relay-layer resilience:

- **Self-certification preserved.** The BEP44 signature is verified against the public key encoded in the DID string. The storage backend (relay or DHT) is untrusted; the resolver never trusts a relay's acceptance or a frame-supplied key. §9.6.1 properties are unchanged.
- **Relay serves stale document.** Detected by sequence number comparison. The resolver falls through to other relays or DHT. Stale documents do not compromise security — they delay propagation of key rotations, which is bounded by the republish cycle (6 days for relays, 2 hours for DHT).
- **Relay unresponsive, slow, or withholding.** Resolution queries all of an identity's relay URLs plus the DHT concurrently, each relay guarded by an independent per-relay timeout (§3.10.4). A single slow, hung, or withholding relay cannot block a result obtained from a faster relay or the DHT, and suppression by any one source does not prevent resolution — multi-relay publishing (§9.9.2) applies to DID documents as it does to context blobs.
- **Relay serves wrong DID's document.** The BEP44 signature does not verify against the target DID's public key. Rejected immediately. The routing ID is derived from the DID string, but verification is against the DID's key — substitution is cryptographically impossible.
- **Attacker floods junk at the DID routing ID.** The `routing_id = SHA-256("scp:did:" || did_string)` is publicly derivable, so any party can PUBLISH to it. On a **validating SCP-native relay every flood variant is inert**, because the relay keeps a single highest-sequence slot and makes the `routing_id` slot-exclusive once claimed (§3.10.2):
  - **Junk frame** (malformed, wrong binding, or bad signature) — rejected at validation; never enters the slot.
  - **Valid-looking frame with a stale or equal `seq`** — rejected by the single-slot rule; displacing the genuine record requires a higher-`seq` frame signed by the DID's private key, which the attacker does not hold.
  - **Non-frame opaque junk blob** — rejected once the slot exists (slot-exclusivity rule (a)); QUERY returns only the slot (rule (c)).
  - **Pre-seeded junk** (published *before* the victim's first DID publish, while the relay cannot yet recognize the `routing_id` as DID-domain since `SHA-256` is one-way) — evicted the moment the first binding-valid frame establishes the slot (rule (b)).

  This is precisely why the relay layer is suppression-resistant: presence-in-the-QUERY-window is controlled by the validating relay's write rule, not by the attacker's PUBLISH volume or timing.
- **Attacker DELETEs the slot blob (an integrity vector, closed by the DELETE gate).** DELETE is an unauthenticated relay operation addressing a blob by `blob_id` (`= SHA-256(blob)`), and a DID record is public — so an attacker can compute the genuine record's `blob_id` and issue `DELETE`. Left ungated this is an **integrity** attack, not merely availability: on a cold index (a restarted relay or a store-sharing peer, §3.10.2) the attacker DELETEs the genuine highest-`seq` record from durable storage, then PUBLISHes a captured older lower-`seq` genuine frame; cold-index establish reconciliation, finding the genuine record gone, **establishes that stale newcomer** (it has no higher-`seq` record left in storage to reconcile against) — rolling the victim's DID document back to a rotated-out/revoked key. Note the replayed frame is *owner-signed*, so it passes the client's BEP44 verification; what would otherwise reject it is the client's `seq`-monotonicity check, but that is defeated on a cold-cache first resolution — which is why the relay-side DELETE gate, not client re-verification, is the control that closes this vector. This is closed by **slot-exclusivity rule (d) (§3.10.2): the relay rejects a DELETE of the current slot blob**, and the gate is **storage-derived** (it re-reads and re-verifies the blob's self-certifying bytes), so it holds even against a cold index. The gate is rate-limited (its storage read + signature verify is not an unmetered amplification surface) and fails closed on a storage error. With rule (d), a DELETE cannot purge a genuine record and the rollback is foreclosed.
- **Suppression resilience (validating SCP-native relays).** With single-slot validation, an attacker cannot evict the genuine record by flooding, and cannot reorder it out of a bounded QUERY window (there is at most one record to return). To prevent resolution, an attacker must suppress the DID document on ALL of an identity's validating relays AND all reachable DHT nodes — the DHT being independently suppression-resistant for the same structural reason (BEP44 nodes validate on write and keep one highest-`seq` slot per key). This "all relays AND the DHT" claim holds for validating relays. **On integrity:** relay misbehavior is availability-only, never integrity, *because* a set of controls hold together, each covering a distinct failure mode — the client's BEP44 re-verification against the DID-derived key (§9.6.1) rejects a **forged** record; the resolver's `seq`-monotonicity + highest-`seq`-across-relays-and-DHT selection (§3.10.4, §3.10.7) rejects a **stale/replayed genuine** record on any warm-cache or multi-source resolution; and the storage-derived, cold-index-immune establish reconciliation + **DELETE gate (rule (d))** close the **cold-cache DELETE-purge-then-replay rollback** that the first two do not cover on a single-source first contact. It is not an unconditional property of the relay: it is delivered by those controls together. A relay that omits them (a foreign/non-validating relay) provides no integrity control of its own — integrity there rests entirely on the client-side checks (§9.6.1 + seq-monotonicity + DHT).
- **Residual: foreign / non-validating relays are best-effort.** A foreign transport or a non-validating relay that accumulates multiple blobs per `routing_id` can be flooded, and its bounded QUERY window can be made to omit the genuine record. Resolution over such storage alone is therefore best-effort for suppression; the resolver still recovers the genuine record via any validating relay, via multi-relay publishing (§9.9.2), or via the DHT, and its highest-seq-valid selection (§3.10.4) discards the junk. What foreign/non-validating storage contributes is availability, not anti-suppression.

### 3.10.9 Privacy Properties

| Layer | What the backend learns |
|-------|------------------------|
| SCP relay | Resolver's IP address queried a specific `routing_id`. The relay can infer which DID is being resolved if the relay knows the DID (it can compute the same `SHA-256("scp:did:" \|\| did_string)` for known DIDs). |
| Mainline DHT | Resolver's IP address queried a public key. DHT routing traffic makes isolation harder (§9.10.7). |

Adding relay-based resolution does not degrade privacy relative to DHT-only resolution. It adds one additional observer (the relay operator) who, for identities hosted on that relay, already sees message traffic for that identity. The DID resolution query does not reveal information the relay operator did not already have.

Caching policy from §9.10.7 applies to both layers: 24-hour refresh for active contacts, 7-day for inactive. The local Mainline DHT node on desktop (§9.10.7) continues to provide resolution privacy for DHT queries.

### 3.10.10 DidResolver Trait

The SDK exposes a unified resolution interface that composes both layers:

```rust
/// Unified DID resolution across SCP relays and Mainline DHT.
/// Implements the parallel dual-layer resolution protocol (§3.10.4).
pub trait DidResolver: Send + Sync {
    fn resolve(&self, did: &str)
        -> impl Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send;
}

/// A resolved DID document with provenance metadata.
pub struct ResolvedDidDocument {
    /// The verified DID document.
    pub document: DidDocument,
    /// BEP44 sequence number. Monotonically increasing.
    pub seq: u64,
    /// Which resolution layer served this document.
    pub source: ResolutionSource,
}

/// Provenance of a resolved DID document.
pub enum ResolutionSource {
    /// Resolved via QUERY to an SCP relay.
    ScpRelay { relay_url: String },
    /// Resolved via Mainline DHT BEP44 lookup.
    MainlineDht,
    /// Served from local cache (original source recorded at cache time).
    Cache,
}
```

`DidResolver` composes the relay QUERY path with `DhtClient::resolve()` internally. The existing `DidMethod::resolve()` interface continues to work for single-layer DHT resolution — `DidResolver` is an additive layer, not a replacement. Code that only needs DHT resolution (e.g., interoperability tools) can use `DidMethod` directly.

### 3.10.11 Bootstrap and Network Growth

The dual-layer architecture is designed to be self-reinforcing as the SCP network grows:

- **Day one.** DHT dominates. Relay-layer queries mostly fail because few relays exist and few identities have published DID documents to relays. Resolution latency is DHT latency. The protocol works identically to the pre-§3.10 architecture.
- **Growth.** More relays come online. More identities publish to relays. Relay-layer resolution begins succeeding more often, and faster than DHT traversal. DHT queries still run in parallel as backup.
- **Maturity.** Relay-layer resolution is primary for most identities. DHT latency becomes irrelevant because relay responses arrive first. DHT serves as an availability backstop and interoperability bridge for non-SCP clients.
- **DHT is never removed.** The cost of maintaining DHT publishing is one BEP44 put every 2 hours — negligible. The benefit is permanent: a resolution path that works even if every SCP relay is unreachable. Removing it would violate the anti-segmentation invariant (§3.10.6).

### 3.10.12 Phase Integration

| Component | Phase | Crate | Notes |
|-----------|-------|-------|-------|
| `did_routing_id` derivation | Phase 1 patch | `scp-core` | Pure function, no dependencies. SHA-256 of domain-separated DID string. |
| DID document PUBLISH to relays | Phase 2 | `scp-core` | RepublishManager gains relay publishing cycle alongside existing DHT cycle. |
| DID document QUERY from relays | Phase 2 | `scp-core` | Extends existing DID resolution path with relay QUERY before/parallel to DHT. |
| `DidResolver` trait | Phase 2 | `scp-core` | Unified interface composing relay + DHT resolution. |
| Parallel dual-layer resolution | Phase 2 | `scp-core` | Orchestration of parallel queries with first-valid-wins semantics. |
| DID-record relay frame (§9.10.12) | Phase 2 (#482) | `scp-protocol` | Deterministic binary encode/decode of the minimal fixed-layout DID-record frame (`DidRecordV1`). Pure sync wasm-compatible type; consumed by the relay publisher + DID resolver in `scp-identity` and by the relay-side validation path. |

## 3.11 DID Authentication for External Services (SCPID)

SCP identities can authenticate to services outside the protocol. A relying party — SCP-native or not — can verify that a request comes from the holder of a specific DID without joining a context, understanding MLS, or running SCP infrastructure. The only requirement is the ability to resolve a `did:dht` document (a single DHT lookup) and verify an Ed25519 signature.

This is analogous to "Sign in with Ethereum" (EIP-4361) but simpler: no blockchain state, no gas, no wallet abstraction. The DID document is the identity provider, self-certified via BEP44 signatures on the DHT.

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
       |  3. Sign challenge with #active/#agent |
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

The protocol is stateless from the client's perspective. The relying party issues a challenge, the client signs it, and the relying party verifies the signature against the DID document's public key. No session state is established at the protocol level — session management (cookies, tokens, etc.) is the relying party's concern.

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
    signing_key_id: String,   // Verification method ID: "#active" or "#agent"
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
    || BE32(len(signing_key_id))   || signing_key_id   // "#active" or "#agent", UTF-8
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

The domain separator `"SCP-DID-AUTH-V1:"` prevents cross-protocol signature reuse. The SHA-256 wrap aligns with the majority SCP signing pattern (InnerEnvelope, BroadcastEnvelope, sender keys, access keys, sync structures, claims). The `did` and `signing_key_id` fields bind the signature to the signer's identity and key role, preventing signature transplant across DIDs and key confusion between `#active` and `#agent`.

**Signing key selection:**

- `#active` — human-initiated authentication, appropriate for sensitive actions. §3.9.3 states where its key material lives and who chooses that; a relying party that needs a specific custody model reads the DID document's `ScpKeyCustodyAttestation` entry under the rules of §27.4.4 of the attestations spec rather than assuming one from the fragment.
- `#agent` — agent-initiated authentication. Software-held, no biometric gate. Appropriate for autonomous background operations. The relying party MAY distinguish between `#active` and `#agent` values of `signing_key_id` for authorization decisions (e.g., requiring `#active` for account-level changes). Because `signing_key_id` is included in the signed content (§3.11.3), this distinction is cryptographically authenticated — a signature produced with `#agent` cannot be presented as `#active`.

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
5. Resolve the DID document:
   a. Resolve did via DHT (BEP44 lookup) or SCP relay QUERY (§3.10.4).
   b. Verify the BEP44 signature on the DID document (§9.6.1).
   c. Cache policy: the DID document MUST be fresh — fetched within the last
      300 seconds or cached with valid TTL. Stale documents MUST trigger
      a fresh resolution.
6. Extract the public key for signing_key_id from the DID document's
   verificationMethod array.
7. Confirm signing_key_id is one of "#active" or "#agent". Reject any
   other value with KEY_NOT_AUTHORIZED.
8. Confirm signing_key_id is listed in the DID document's "authentication"
   relationship. Reject if not.
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
| `signing_key_id` not `#active`/`#agent` or not in `authentication` | `KEY_NOT_AUTHORIZED` | `SCP-IDENT-1034` |
| Signature verification failed | `SIGNATURE_INVALID` | `SCP-IDENT-1035` |
| DID document stale (> 300s, refresh failed) | `DID_DOCUMENT_STALE` | `SCP-IDENT-1036` |
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
  "did": "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
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

**Key compromise recovery.** If `#active` is compromised, the identity owner rotates it via DID document update signed by `#0` (§9.12). After rotation, the old key is no longer in the DID document's `authentication` relationship. Verification step 7 rejects signatures from the old key. Recovery latency is bounded by DID document propagation time (republish cycle: 2 hours for DHT, 6 days for relays, or immediate via manual republish).

**MITM resistance.** SCPID does not provide channel binding. If the transport between client and relying party is compromised (no TLS), an attacker can intercept and replay the challenge-response in real time. Relying parties MUST serve challenges and accept responses over TLS. The audience field mitigates relay attacks across services but does not replace transport-layer encryption.

**Agent vs. human distinction.** The `signing_key_id` field tells the relying party whether the human's `#active` key or the agent's `#agent` key signed the challenge. §3.9.3 and §3.9.4 state where each key's material lives; the field names the key, and it carries no custody claim of its own. Because `signing_key_id` is included in the signed content (§3.11.3), this distinction is cryptographically authenticated. The relying party can enforce authorization policies based on this distinction — e.g., requiring `#active` for destructive operations and accepting `#agent` for routine API access.

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
1. A `did:dht` resolver (BEP44 lookup — libraries exist for most languages).
2. SHA-256 (standard, available everywhere).
3. An Ed25519 signature verifier (PureEdDSA per RFC 8032 §5.1.6).
4. JSON parsing.

This is intentional. SCPID is designed to be implementable by services that have no other relationship with SCP.

### 3.11.9 Implementation Notes for Non-SCP Relying Parties

A service that wants to accept SCP DID authentication without running SCP software:

1. **DID resolution.** Use any `did:dht` resolver library. The DID document is a BEP44 signed mutable item on Mainline DHT. Libraries: `did-dht` (Rust), `@decentralized-identity/did-dht` (JS), or raw BEP44 lookups via any DHT client. For SCPID verification, DID documents MUST be cached for no more than 300 seconds. The general §3.10.4 caching policy (24h/7d) does NOT apply to SCPID verification — authentication requires current key state.

2. **DID document parsing.** The document is W3C DID Core JSON (§18.2.2A). Extract the `verificationMethod` array and `authentication` relationship. Match `signing_key_id` to a verification method, confirm it appears in `authentication`, extract `publicKeyMultibase`. Decoding: strip the `z` prefix (multibase indicator for base58btc), base58btc-decode the remainder to get the raw 32-byte Ed25519 public key.

3. **Signature verification.** Reconstruct `signed_bytes` per §3.11.3: concatenate the domain separator `"SCP-DID-AUTH-V1:"`, length-prefixed `did`, length-prefixed `signing_key_id`, raw 32-byte `nonce`, length-prefixed `audience`, and 8-byte big-endian `signed_at`. Compute SHA-256 of the concatenation. Verify the Ed25519 signature (PureEdDSA, RFC 8032 §5.1.6) over the resulting 32-byte hash. Standard libraries: `ring`, `ed25519-dalek` (Rust), `tweetnacl` (JS), `pynacl` (Python), `Crypto.Sign` (Swift).

4. **Nonce management.** Store issued nonces with their `expires_at`. Reject duplicates. Prune expired entries. For distributed deployments, use a strongly-consistent store or HMAC-based nonce generation (§3.11.6).

No SCP SDK, no MLS, no context management, no relay connections. The entire verification path is: one DHT lookup + one JSON parse + one SHA-256 + one Ed25519 verify.
