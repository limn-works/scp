# Phase 6 Architecture Decision Records — Android, Kotlin, Scale Hardening, Advanced Governance

**Date:** February 23, 2026
**Phase goal:** Android platform, Kotlin SDK, scale hardening, security audit, advanced governance, offline strategy.
**Timeline:** Weeks 21+

**Note:** Phase 6 follows Phases 1-5 implementation. All ADRs in this phase — ADR-027 (Android), ADR-028 (Kotlin), ADR-029 (Offline/Sync), ADR-030 (Event Log Pruning), ADR-031 (Multi-Admin Governance), ADR-038 (Content Access Key Layer), ADR-043 (Protocol Constants), ADR-044 (Attestation Two-Class Model), ADR-045 (Fuzzing Infrastructure), and ADR-066 (Governance Leaves Ride the MLS Commit) — are Decided.

**Dependencies between ADRs:**

```
Phase 1-5 ADRs
       |
       ├── ADR-027 (Android) <── ADR-021 (UniFFI) + ADR-025 (Apple reference)
       │        |
       │        v
       ├── ADR-028 (Kotlin) <── ADR-027 + ADR-021 + ADR-026 (Swift reference)
       │
       ├── ADR-029 (Offline/Sync) <── Phase 1-2 implementation + empirical data
       ├── ADR-030 (Event Log Pruning) <── Phase 2 event log + empirical data
       ├── ADR-031 (Multi-Admin Governance) <── Phase 2 UCAN + single-admin governance
       ├── ADR-038 (Content Access Key Layer) <── ADR-007 (Sender Keys) + ADR-031 (Governance)
       ├── ADR-043 (Protocol Constants) <── Phase 1-5 implementation + empirical data
       ├── ADR-044 (Attestation Two-Class Model) <── §3.5 (Identity Attestations) + §7.4.1 (Attestation Format)
       └── ADR-045 (Fuzzing Infrastructure) <── Phase 1-5 parsers + ADR-043 (Protocol Constants) + §9 (Crypto)
```

---

## ADR-027: Android Platform Adapter

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling); 2026-09-29 (SCP-307, the hardware pseudonym secret); 2026-10-10 (SCP-307, identity generation creates that secret, and the agreement-key helpers of the sketch take the `HpkeP256` name); 2026-09-27 (the device-attestation binding and the named verifier); 2026-10-10 (the custody request vocabulary: the adapter is reached as `os_keystore`, with edits to the Decision's `PlatformAdapter.kt` item, the SDK injection point, the ADR-028 item of the Dependencies list and acceptance criterion 12, each of which marks its own); 2026-10-11 (`UniffiKeyCustody` implements `uniffi.scp.KeyCustodyProvider` over `AndroidKeyCustody`, an edit to the custody request vocabulary amendment, which marks its own); 2026-10-12 (the FCM wake signal of `10-infrastructure-and-self-hosting.md` §10.7.1 step 5 and the push call order, with edits to the Decision's `AndroidPushProvider.kt` item and FCM payload paragraph, the `AndroidPushProvider.kt` code block and acceptance criterion 10, each of which marks its own); 2026-10-20 (SCP-307: the custody class is recorded per key at mint from the security level Keystore reports; the agreement-key floor is API 31; P-256 signing uses `DIGEST_NONE`; the `kotlin-android-instrumented` emulator lane; the adapter's custody is single-process; an abandoned mint's sweep is best-effort; a pending id reads as absent; every destruction reports `SOFTWARE_ONLY`; a P-256 key's role lives in its record, with edits to the 2026-09-10 amendment, the Context, the Decision's `AndroidKeyCustody.kt` item, the Minimum API level, the Rationale, the `AndroidKeyCustody.kt` code block, the ADR-025 item of the Dependencies list and acceptance criteria 1 to 5 and 13, each of which marks its own) — see the amendments below.

**Amendment (2026-09-10 — every SCP key is ECDSA on P-256).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. This ADR's Rationale called hardware-backed Ed25519 at API 33 and above "a direct win over Apple, where Secure Enclave's P-256 limitation forces software key storage". **That paragraph is withdrawn.** The gap it named came from SCP's own curve choice and not from either vendor's hardware: Apple's Secure Enclave performs P-256 operations, Android Keystore has held P-256 keys in the Trusted Execution Environment since API 23, and SCP signed with a curve only one of the two implemented. Under the ruling both adapters hold every SCP signing key in the operating system's platform signer, and ADR-025, the Apple platform adapter, carries the matching amendment. Whether that signer holds a given key in hardware is a fact about the key, which this adapter reads from `KeyInfo` when it mints the key and records (acceptance criterion 1). (Amended 2026-10-20; this sentence previously read "Under the ruling both adapters hold every SCP signing key in hardware, and ADR-025, the Apple platform adapter, carries the matching amendment.") Two further consequences follow for this ADR. The Bouncy Castle software fallback for API levels 26 through 32 has nothing left to fall back from, because Keystore holds a P-256 signing key at every API level this SDK supports; it survives only for key agreement below API 31, which is the first level at which Keystore performs ECDH. And the root member is held by a passkey through the platform's credential provider (`09-security-model.md` §9.7.4.1 item 4), so `AndroidKeyCustody` neither generates nor stores it.

**Amendment (2026-09-29 — SCP-307, the hardware pseudonym secret).** For a Keystore identity key, `pseudonym_secret` is a 256-bit Keystore HMAC-SHA256 key that identity generation (`generate_identity_keypair`, amended 2026-10-10; this clause previously named `generate_keypair`) creates beside the identity key, non-exportable and usable without user authentication. The HMAC that yields the §9.10.4 context seed runs inside Keystore: the adapter passes the Keystore key to `Mac.init`, so the secret never enters process memory. Nothing is derived from a signature. The `derivePseudonym` sketch below is superseded on four points: its `// HKDF (software) or TEE-sign (hardware)` comment; its `SecretKeySpec(pseudonymSecret, ...)`, which would hold the hardware secret as exported bytes; its `seedToScalar(seed)` call, which names no Kotlin function; and its `PseudonymKeyHandle` return. The adapter turns the seed into the pseudonym point with the UniFFI export `uniffi.scp.p256PseudonymPoint(contextSeed)`, and a Bouncy Castle software identity derives its point with `uniffi.scp.p256SoftwarePseudonymPoint`. `derivePseudonym` returns that 33-byte point and stores no pseudonym key (§9.10.4.A). Destroying the identity deletes the secret before the identity key, so a failed destroy leaves the identity present and a retry deletes both. Derivation confirms that the identity key exists before it uses the secret, and a Keystore identity key generated before the secret existed fails pseudonym derivation with `SCP-CRYPTO-4006` (§9.10.4.A).

**Amendment (2026-09-27 — the Play Integrity request binds the identifier and the context challenge, and the package's verifier vouches for the token).** `09-security-model.md` §9.3.1, reading a device attestation, owns the construction and the reader's procedure, and this ADR carries them into the Android adapter. First, the adapter issues a Standard integrity request whose `requestHash` is the lowercase hexadecimal form of the binding digest, which the Rust core computes and passes as the shipped trait's `challenge`, `D = SHA-256("SCP-DEVICE-ATTESTATION-V1:" ‖ BE32(56) ‖ identifier_text ‖ BE32(n) ‖ context_id ‖ challenge)`, where `identifier_text` is the identifier's `scp:` text form, `context_id` is the UTF-8 bytes of the context's id, and `challenge` is the context's 32-byte `device_attestation_challenge`. That replaces the `Base64(SHA-256(clientDataJSON))` nonce of acceptance criterion 7, which named no identifier. The code block this ADR carried also contradicted its own text: the text names the Standard API, and the code called the Classic API's `IntegrityTokenRequest.builder().setNonce(nonce)`. The code block below now calls the Standard API. Second, no peer can decode a Standard token, because Google decodes one only for the Cloud project linked to the requesting app. The verifier for a package is therefore the party whose Cloud project Google links to it, in practice the app's developer, and a context that weights Play Integrity lists each accepted package with its signing-certificate digest and that verifier's identifier in `ContextSybilPolicy.accepted_android_packages`, which governance sets. The verifier publishes a `PlayIntegrityVerifier` entry in its own service record carrying the package name, its Cloud project number and an HTTPS URL, and the owner sends the token to that URL in one HTTPS `POST` whose JSON request and response §9.3.1 defines byte for byte. The verifier decodes the token, checks `requestHash`, that `requestPackageName` and `appIntegrity.packageName` equal the request's package name, `PLAY_RECOGNIZED`, a single `certificateSha256Digest`, and `MEETS_DEVICE_INTEGRITY`, and signs a verdict under `"SCP-PLAY-INTEGRITY-VERDICT-V1:"` that carries the package name's SHA-256 and the signing certificate's digest. Each reader checks that pair against the context's `accepted_android_packages`. The SDK publishes the token and the verdict together in one `ScpDeviceAttestation` service-record entry, and a reader that cannot verify the verdict returns `Unverifiable` and counts no signal. Third, the assertion path carries the assertion digest `A = SHA-256("SCP-DEVICE-ASSERTION-V1:" ‖ BE32(len(m)) ‖ m)` and no longer routes through `attest` with an empty device ID, so no assertion token's `requestHash` equals the hexadecimal form of a `D`. Fourth, the SDK builds the adapter for each call with the Cloud project number the verifier's `PlayIntegrityVerifier` entry carries, because the verifier can decode no token requested under another project, and a reader's `Verified` for a Play Integrity entry is trust in that verifier and no platform proof it checks. The context accepts or changes a package's verifier only by a governance action its event log records. The shipped `AndroidDeviceAttestation` still builds the JSON document; story SCP-111 of `.docs/prds/main.json` stands in progress until it changes, and story SCP-316, still pending, specifies the reader, and no code verifies a device attestation yet.

**Amendment (2026-10-10 — the custody request vocabulary).** `03-identity.md` §3.2.2 defines the two values a caller passes to create an identity, `encrypted_file` and `os_keystore`, and Alec accepted that vocabulary on 2026-08-28. A caller reaches `AndroidKeyCustody` with `os_keystore`, by passing it as the `KeyCustodyProvider` of `identity_create_with_custody`, and the identity handle then reports `os_keystore`. That path requires the UniFFI-generated `uniffi.scp.KeyCustodyProvider`, which `UniffiKeyCustody` in `scp-kt-android` implements over an `AndroidKeyCustody`. (Amended 2026-10-11; this sentence previously read "That path requires `AndroidKeyCustody` to implement the UniFFI-generated `uniffi.scp.KeyCustodyProvider`; its own KDoc records that it implements the `scp-kt-android` package's `KeyCustodyProvider` instead and that no code passes it to the Rust engine.") This ADR wanted a platform adapter that a custody request selects, and the `os_keystore` path is that selection, so §3.2.2 satisfies this ADR and does not supersede it. The string `"platform"` that this ADR's Decision, SDK injection point, Dependencies list and acceptance criterion 12 named is not a request value, and §3.2.2 has every bridge answer it with `SCP-VALID-7005`. `os_keystore` promises no hardware backing, because which keys the host store holds in hardware depends on the key and the provider (§3.2.2); acceptance criterion 1 already reports `CustodyType.SOFTWARE` for an agreement key below API 31.

**Amendment (2026-10-12 — the FCM wake signal and the push call order).** This ADR's `AndroidPushProvider.kt` code block gave a push sender a body that addressed the device through a top-level `to` field beside the `data` map. That field belongs to FCM's legacy HTTP API, which Google shut down; the HTTP v1 API addresses a device through `message.token` and rejects a body with no `message` object. Step 5 of `10-infrastructure-and-self-hosting.md` §10.7.1 now holds a wake-signal table whose FCM row gives the HTTP v1 request, with `android.priority` set to `HIGH` on every wake, and this ADR cites that row. The `data` map `{"scp": "1"}` and the receipt rule of acceptance criterion 10 stand unchanged: §10.7.1 step 5 states the same rule as the FCM device receipt rule. The ADRs never stated which side starts each push path, so acceptance criterion 10 now states the call order of the UniFFI `PushProvider` callback: the app calls the Rust core, and the Rust core calls the provider.

### Context

SCP's platform adapter layer (ADR-006) abstracts device-specific capabilities behind four traits: `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage`. These traits are exposed as UniFFI callback interfaces (ADR-021), allowing Kotlin implementations to be injected into the Rust engine. The Android adapter implements all four traits using Android's native platform security stack.

Android and Apple reach the same key-custody floor. Android Keystore has generated and used EC P-256 keys since API 23 and holds each at whatever security level the device provides: the Trusted Execution Environment or StrongBox on most devices, and software KeyMint on an emulator or a low-end device, which is still the operating system's platform signer under `09-security-model.md` §9.5. Apple's Secure Enclave performs P-256 operations, so on both platforms the operating system's signer holds every SCP signing key once every SCP key is a P-256 key (§9.5). The adapter records each key's custody class at mint from the level Keystore reports for that key: `"hardware"` for the TEE, StrongBox or an unknown secure level, and `"software"` otherwise. (Amended 2026-10-20; these sentences previously read "Android Keystore has generated and used EC P-256 keys inside the Trusted Execution Environment since API 23, and Apple's Secure Enclave performs P-256 operations, so every SCP signing key is hardware-held on both platforms once every SCP key is a P-256 key (`09-security-model.md` §9.5).") The two adapters differ in their key-agreement floor and in their attestation service, not in whether a signing key reaches hardware: Keystore performs ECDH from API 31, and below that level this adapter agrees keys in software. Until 2026-09-10 this paragraph named a fundamental difference, which the amendment above traces to SCP's superseded curve rather than to either vendor's hardware.

Android's hardware security landscape has two tiers: TEE (Trusted Execution Environment), present on virtually all modern Android devices, and StrongBox, an isolated secure element chip present on a subset of flagship devices. StrongBox operations are dramatically slower (10-100x) than TEE operations. For SCP's frequent signing operations during protocol participation, StrongBox latency is prohibitive. TEE-backed Keystore is the correct default.

### Decision

Implement the Android platform adapter in Kotlin at `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/`. Five files implement the four platform traits plus a factory:

- **`AndroidKeyCustody.kt`** — `KeyCustodyProvider` implementation using Android Keystore. EC P-256 signing keys in Keystore at every supported API level; Keystore key agreement at API 31+, with a Bouncy Castle software P-256 agreement key below it. TEE-backed by default; StrongBox explicitly opt-out. The adapter runs in the app's main process only (acceptance criterion 1). (Amended 2026-10-20; the last sentence is new.)
- **`AndroidDeviceAttestation.kt`** — `DeviceAttestationProvider` implementation using Play Integrity Standard API. Standard (server-side, low-latency) preferred over Classic (offline, high-cost) attestation.
- **`AndroidPushProvider.kt`** — `PushProvider` implementation using Firebase Cloud Messaging. Opaque data-only message: the FCM row of the §10.7.1 step 5 wake-signal table, whose `data` map is `{"scp": "1"}` (amended 2026-10-12; this item previously gave the payload as `{"data": {"scp": "1"}}` and cited no table). No context ID, sender identifier, or message content in any notification payload.
- **`AndroidStorage.kt`** — `StorageProvider` implementation using SQLCipher. The SQLCipher key is derived as `17-persistence-and-storage.md` §17.6 requires: a non-exportable HMAC-SHA-256 key in Android Keystore MACs a fixed label, and HKDF-SHA-256 expands that MAC output into the 32-byte key. Key ID: `scp.storage.key`. (Amended 2026-10-12; this item previously named a TEE-backed AES-256 Keystore key.)
- **`PlatformAdapter.kt`** — `AndroidPlatformAdapter` factory. `AndroidPlatformAdapter.make()` constructs and injects all four providers. Called by the Kotlin SDK when the caller requests `os_keystore` custody (`03-identity.md` §3.2.2). (Amended 2026-10-10; this item previously ended "Called by the Kotlin SDK's `SCP.create()` when `custody = "platform"`.")

**Minimum API level:** API 26 (Android 8.0) for the SDK. Keystore has held EC P-256 signing keys since API 23, at the security level the device provides, so every device this SDK supports holds a signing key in Keystore; the key's handle reports `CustodyType.HARDWARE` when `KeyInfo` places it in the TEE, StrongBox or an unknown secure level, and `CustodyType.SOFTWARE` otherwise. API 31 (Android 12) is the first level at which Keystore performs ECDH, so a device on API 26-30 holds its key-agreement key as a software Bouncy Castle P-256 key with `CustodyType.SOFTWARE`. (Amended 2026-10-20; this paragraph previously read "Keystore has backed EC P-256 signing keys in hardware since API 23, so every device this SDK supports reports `CustodyType.Hardware` for a signing key. API 31 (Android 12) is the first level at which Keystore performs ECDH, so a device on API 26-32 holds its key-agreement key as a software Bouncy Castle P-256 key with `CustodyType.Software`.")

**TEE vs StrongBox policy:** TEE is the default and only option. StrongBox is not used. StrongBox operations are dramatically slower — 10-100x latency increase over TEE for signing — which would make SCP protocol participation visibly laggy. There is no user-visible opt-in to StrongBox.

**Play Integrity:** Standard integrity requests (server-side verification via the Play Integrity API). Classic attestation (which generates a signed APK certificate chain verifiable offline) is not used — it requires a server round-trip to Google's servers for each attestation and has stricter quotas. Standard provides fresh device verdicts sufficient for SCP's attestation requirements.

**FCM payload:** Data-only message with no notification fields. The relay sends the FCM row of the wake-signal table in `10-infrastructure-and-self-hosting.md` §10.7.1 step 5 through the FCM HTTP v1 API, and that row's `data` map is `{"scp": "1"}`. (Amended 2026-10-12; this paragraph previously gave the payload as `{"data": {"scp": "1"}}` and cited no table.) The `scp` field value `"1"` is the wake signal. The app wakes, connects to the SCP relay, and pulls envelopes. No context ID, sender identifier, message preview, or any SCP-specific content appears in the FCM payload (§10.7 opacity requirement).

### Rationale

- **P-256 signing keys are held by Keystore at every supported API level:** Android Keystore generates an EC P-256 key with `ECGenParameterSpec("secp256r1")` from API 23 at the security level the device provides, so the private bytes never leave Keystore and every signature happens there. On an emulator or a low-end device that level is software KeyMint, still the platform signer of `09-security-model.md` §9.5, and the adapter records `"software"` for such a key from `KeyInfo` rather than claiming hardware from the key type. (Amended 2026-10-20; this item previously read "**P-256 signing keys are hardware-backed at every supported API level:** Android Keystore generates an EC P-256 key with `ECGenParameterSpec("secp256r1")` inside the TEE from API 23, so the private bytes never leave the TEE and every signature happens there.") This ADR previously claimed a direct win over Apple on this point; the amendment at the head of the ADR withdraws that claim and states why.
- **Software agreement key below API 31:** API 26 is the SDK minimum (matching the JVM 11+ target and Android 8.0). `KeyProperties.PURPOSE_AGREE_KEY` arrived at API 31, so on API 26-30 Keystore signs and cannot perform ECDH (amended 2026-10-20; this clause previously read "on API 26-32 Keystore signs in hardware"); the adapter therefore generates the key-agreement key with Bouncy Castle, stores it encrypted in EncryptedSharedPreferences (Jetpack Security), and reports `CustodyType.Software` for that key alone.
- **TEE over StrongBox:** StrongBox is present on a fraction of devices and operates orders of magnitude slower than TEE. SCP signs messages during every send operation and during key agreement. StrongBox latency would accumulate visibly in normal usage. The TEE provides hardware isolation with acceptable latency. StrongBox is not offered as an option — "opt-in slowness" is a footgun.
- **Play Integrity Standard over Classic:** Standard integrity requests return a verdict signed by Google's servers, sufficient for SCP's attestation purpose. Classic attestation (APK certificate chain) requires a dedicated Google Play Developer API call per attestation with stricter rate limits and is designed for offline scenarios SCP does not have. Standard is lower-cost, lower-latency, and simpler.
- **FCM data-only payload for opacity:** FCM notification payloads visible to the device OS (notification fields) must contain no SCP-meaningful content. A data-only message with `{"scp": "1"}` carries no information except "wake up and pull" — satisfying §10.7. The FCM data payload is not displayed to the user, not logged by the OS notification system, and carries no identifying information.
- **SQLCipher with a Keystore-rooted key:** SQLCipher provides transparent full-database encryption. Its key is derived as `17-persistence-and-storage.md` §17.6 requires; the `AndroidStorage.kt` item under Decision and the `AndroidStorage` class KDoc state the derivation. (Amended 2026-10-12; this item previously described a Keystore AES-256 key that wrapped the SQLCipher key material through AES-GCM.)
- **Private keys never cross the FFI boundary:** Every P-256 signature and every P-256 ECDH agreement happens inside `AndroidKeyCustody.kt`. The Rust engine calls the UniFFI callback interface methods with data to sign and receives signatures back. Raw private key bytes stay inside the Kotlin adapter: a Keystore key stays inside Keystore at the security level Keystore reports for it, and the API 26-30 agreement scalar lives in EncryptedSharedPreferences and enters process memory during agreement. Kotlin cannot wipe these copies of that scalar's material: the immutable `BigInteger` private value Bouncy Castle holds for the key's life, in a key pair that stays in one process-wide cache until the key is destroyed or the process exits, including after the `AndroidKeyCustody` instance that loaded it is dropped, and every `BigInteger` its arithmetic derives from it; the `ByteArray` that `BigIntegers.asUnsignedByteArray` takes from `BigInteger.toByteArray` and drops; the Base64 `String` the preferences file stores and the buffers Base64 encoding and decoding allocate; the plaintext buffers EncryptedSharedPreferences and its Tink AEAD allocate when they encrypt or decrypt a value; the decrypted values `SharedPreferences.getAll` returns, which is why restore reads each recorded id with `getString` and never calls `getAll`; and the `BigInteger` the ECDH computation returns. The adapter zeroes every intermediate `ByteArray` it allocates itself. On API 26-30 Bouncy Castle multiplies the peer point by the scalar with a variable-time windowed NAF, so code that can time agreements on the device learns about the scalar. (Amended 2026-10-20; this sentence previously read "Raw private key bytes stay inside the Kotlin adapter, inside the Android Keystore TEE.")
- **Kotlin over Rust for Android platform code:** Android Keystore, Play Integrity, and FCM are Java/Kotlin APIs with no Rust bindings. Writing thin Kotlin adapters that call these APIs and satisfy the UniFFI callback interfaces is the correct approach — it uses the idiomatic Android API surface without maintaining a JNI bridge to Rust Android Keystore bindings.

### Implementation

**File layout:**

```
bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/
  AndroidKeyCustody.kt        — KeyCustodyProvider: Android Keystore P-256, software agreement key
  AndroidDeviceAttestation.kt — DeviceAttestationProvider: Play Integrity Standard API
  AndroidPushProvider.kt      — PushProvider: FCM registration, opaque data payload
  AndroidStorage.kt           — StorageProvider: SQLCipher, key derived per §17.6
  PlatformAdapter.kt          — AndroidPlatformAdapter.make() factory, injects all four
```

**`AndroidKeyCustody.kt` — P-256 key generation via Android Keystore:**

(Amended 2026-10-20: the sample now signs with `NONEwithECDSA` over the bridge's 32-byte digest under a key authorised for `DIGEST_NONE` and returns Keystore's DER unchanged, reads each Keystore key's custody class from `KeyInfo`, and generates the API 26-30 agreement key with Bouncy Castle's lightweight `ECKeyPairGenerator` and commits its scalar. It previously signed with `SHA256withECDSA`, which hashes the bridge's precomputed digest a second time, converted the DER itself through `derToRawLowS`, returned `CustodyType.HARDWARE` for every Keystore key, and asked the JCA for an `"EC"` generator from the `"BC"` provider, which Android's platform build strips. Its `destroyKey` and `dhAgree` chose the store from the handle's custody class, which a software KeyMint key contradicts, and `destroyKey` returned nothing; both now dispatch on the record's backing, and `destroyKey` reports `SOFTWARE_ONLY` (acceptance criterion 4). The agreement-key lookup also threw `SCP-CRYPTO-4002` for an absent key, a code no custody operation uses for it. Acceptance criteria 1 to 5 state the record, the rollback and the peer checks the sample leaves out.)

```kotlin
class AndroidKeyCustody : KeyCustodyProvider {

    override fun generateKeypair(keyType: KeyType): KeyHandle {
        val keyId = UUID.randomUUID().toString()
        return if (keyType == KeyType.P256_SIGN) {
            generateKeystoreP256Signing(keyId)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            generateKeystoreHpkeP256(keyId)
        } else {
            // Keystore performs ECDH from API 31; below it the agreement key is software.
            generateSoftwareHpkeP256(keyId)
        }
    }

    private fun generateKeystoreP256Signing(keyId: String): KeyHandle {
        val spec = KeyGenParameterSpec.Builder(
            "scp.key.$keyId",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_NONE)  // the bridge passes a 32-byte digest
            .setUserAuthenticationRequired(false)  // SCP requires background processing
            .build()
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        keyPairGenerator.initialize(spec)
        val privateKey = keyPairGenerator.generateKeyPair().private
        // The custody class is the level Keystore reports for this key, never the key type.
        val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            .getKeySpec(privateKey, KeyInfo::class.java)
        val secure = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel in setOf(
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_STRONGBOX,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
            )
        } else {
            info.isInsideSecureHardware
        }
        return KeyHandle(id = keyId, custodyType = if (secure) CustodyType.HARDWARE else CustodyType.SOFTWARE)
    }

    private fun generateSoftwareHpkeP256(keyId: String): KeyHandle {
        // Bouncy Castle lightweight P-256 agreement key for API 26-30. The 32-byte scalar is
        // committed to EncryptedSharedPreferences before the handle is returned.
        val curve = SECNamedCurves.getByName("secp256r1")
        val pair = ECKeyPairGenerator().apply {
            init(ECKeyGenerationParameters(ECDomainParameters(curve), SecureRandom()))
        }.generateKeyPair()
        val scalar = BigIntegers.asUnsignedByteArray(32, (pair.private as ECPrivateKeyParameters).d)
        try {
            check(prefs.edit().putString("scp.p256.$keyId", Base64.encodeToString(scalar, Base64.NO_WRAP)).commit())
        } finally {
            scalar.fill(0)
        }
        softwareKeys[keyId] = pair
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        require(data.size == 32)  // the bridge's SHA-256 digest; anything else is SCP-CRYPTO-4060
        val entry = KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }
            .getEntry("scp.key.${keyHandle.id}", null) as KeyStore.PrivateKeyEntry
        // NONEwithECDSA signs the digest as given; SHA256withECDSA would hash it again.
        // Keystore returns DER, and the Rust bridge converts it to the 64-byte low-s form of
        // §9.5 and verifies it strictly before any caller sees it.
        return Signature.getInstance("NONEwithECDSA").apply {
            initSign(entry.privateKey)
            update(data)
        }.sign()
    }

    override fun publicKey(keyHandle: KeyHandle): ByteArray {
        val entry = KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }
            .getEntry("scp.key.${keyHandle.id}", null) as KeyStore.PrivateKeyEntry
        // §9.5 of the security spec fixes the 33-byte SEC1 compressed encoding.
        return compressSec1(entry.certificate.publicKey as ECPublicKey)
    }

    override fun destroyKey(keyHandle: KeyHandle): DestructionAttestation {
        // The record, never the handle's custody class, names where the key lives.
        when (records.get(keyHandle.id)?.backing) {
            Backing.KEYSTORE ->
                KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("scp.key.${keyHandle.id}")
            Backing.SOFTWARE -> check(prefs.edit().remove("scp.p256.${keyHandle.id}").commit())
            null -> throw ScpException("Key not found: ${keyHandle.id}", "SCP-CRYPTO-4006")
        }
        softwareKeys.remove(keyHandle.id)
        records.remove(keyHandle.id)
        // Keystore issues no proof that it destroyed a key, so §9.15 rates every destruction software-only.
        return DestructionAttestation(method = DestructionMethod.SOFTWARE_ONLY, confirmed = true)
    }

    override fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray {
        // Keystore agrees at API 31+, at its reported level; below it the key is software. The record's
        // backing, never the handle's custody class, picks the store.
        val record = records.get(keyHandle.id)
            ?: throw ScpException("P-256 agreement key not found: ${keyHandle.id}", "SCP-CRYPTO-4006")
        val privateKey = when (record.backing) {
            Backing.KEYSTORE ->
                (KeyStore.getInstance("AndroidKeyStore")
                    .apply { load(null) }
                    .getEntry("scp.key.${keyHandle.id}", null) as KeyStore.PrivateKeyEntry).privateKey
            Backing.SOFTWARE -> softwareKeys.getValue(keyHandle.id).private
        }
        // The shared secret is the 32-byte x-coordinate of the agreed P-256 point.
        return KeyAgreement.getInstance("ECDH").apply {
            init(privateKey)
            doPhase(decodeSec1P256(peerPublic), true)
        }.generateSecret()
    }

    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle {
        // Algorithm: seed = HMAC-SHA256(pseudonymSecret, contextId || "scp-pseudonym")
        // pseudonym_keypair = P256_keygen(seed_to_scalar(seed))  // §9.10.4 of the security spec
        //
        // The HMAC key is the 32-byte pseudonymSecret, NEVER the public key — public key
        // bytes would be a membership-enumeration oracle (§9.10.4.A).
        //
        // SOFTWARE keys (Bouncy Castle): pseudonymSecret = HKDF-SHA256(
        //   ikm = p256_private_scalar, salt = "scp-pseudonym-secret-v1", info = "", len = 32).
        //   This matches Rust `derive_pseudonym_secret()` exactly, so software pseudonyms are
        //   cross-platform deterministic (pinned by §25.19 vectors).
        //
        // HARDWARE keys (Keystore TEE): private bytes are non-exportable, so
        //   pseudonymSecret = an associated 32-byte symmetric key generated inside the TEE at
        //   generate_keypair — never SHA-256 over a signature, because an ECDSA hardware signer
        //   draws its own nonce. Hardware pseudonyms are device-local BY DESIGN
        //   and are NOT expected to match other devices or the software vectors.
        val pseudonymSecret = derivePseudonymSecret(keyHandle)  // HKDF (software) or TEE-sign (hardware)
        val mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(pseudonymSecret, "HmacSHA256"))
            update(contextId)
            update("scp-pseudonym".toByteArray())
        }
        val seed = mac.doFinal()
        pseudonymSecret.fill(0)  // zeroize secret after use
        // §9.10.4 of the security spec fixes the seed-to-scalar step: expand to 48 bytes with
        // HKDF-Expand-SHA256, read big-endian, reduce modulo n - 1, add one.
        val pseudonymKeypair = p256KeypairFromScalar(seedToScalar(seed))
        val pseudonymId = UUID.randomUUID().toString()
        softwareKeys[pseudonymId] = pseudonymKeypair
        return PseudonymKeyHandle(id = pseudonymId, custodyType = CustodyType.SOFTWARE)
    }

    private val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()
    private val records = KeyRecords(prefs)  // {type, backing, custody, role} per P-256 key, criterion 1
}
```

**`AndroidDeviceAttestation.kt` — Play Integrity Standard API:**

The sample implements the shipped UniFFI trait `DeviceAttestationProvider` (`crates/scp-ffi/uniffi/src/lib.rs`), whose methods are `attest(challenge, device_id)` and `assert_request(request_hash)`. The Rust caller computes the binding digest `D` of `09-security-model.md` §9.3.1 and passes it where the trait takes `challenge`, and computes the assertion digest `A` and passes it as `request_hash`. The adapter hashes neither again, hashes no identifier, and does not read `device_id`. Every failure leaves the adapter as `ScpException`, as the shipped `AndroidDeviceAttestation.kt` does for the Play Integrity errors it catches, because a UniFFI callback that throws any other exception panics the Rust caller; the sample's `wrapped` also converts a missing Google Play services installation and a failed `require`. Open question OQ-22 of `27-attestations.md` §27.7, which of the two shipped traits is normative, stays open, and this sample decides nothing about it. `cloudProjectNumber` is the Google Cloud project number in the `PlayIntegrityVerifier` entry of the verifier the context's `accepted_android_packages` names for the app's package, and the SDK constructs the adapter with it for each call: Google decodes a Standard token only for the Cloud project it was requested under, so a token requested under any other project is one the verifier cannot decode.

```kotlin
class AndroidDeviceAttestation(
    private val context: Context,
    // The package verifier's Google Cloud project number, from its PlayIntegrityVerifier
    // service-record entry (09-security-model.md §9.3.1).
    private val cloudProjectNumber: Long,
) : DeviceAttestationProvider {

    // challenge = D, computed by the Rust caller; deviceId is not read (OQ-22 stays open).
    override suspend fun attest(challenge: ByteArray, deviceId: ByteArray): ByteArray =
        wrapped { requestStandardToken(challenge, "challenge must be the 32-byte binding digest D") }

    // requestHash = A = SHA-256("SCP-DEVICE-ASSERTION-V1:" || BE32(len(m)) || m), computed by the Rust caller.
    override suspend fun assertRequest(requestHash: ByteArray): ByteArray =
        wrapped { requestStandardToken(requestHash, "requestHash must be the 32-byte assertion digest A") }

    // A UniFFI callback that throws anything but ScpException panics the Rust caller, so every
    // failure (missing Play services, an IllegalArgumentException from require) leaves as ScpException.
    private suspend fun wrapped(block: suspend () -> ByteArray): ByteArray =
        try {
            block()
        } catch (e: ScpException) {
            throw e
        } catch (e: Exception) {
            throw ScpException("Play Integrity token request failed", CODE_ATTESTATION_FAILED, e)
        }

    private suspend fun requestStandardToken(digest: ByteArray, sizeMessage: String): ByteArray {
        require(digest.size == 32) { sizeMessage }
        val hex = digest.joinToString("") { "%02x".format(it) }
        val provider = withContext(Dispatchers.IO) {
            IntegrityManagerFactory.createStandard(context)
                .prepareIntegrityToken(
                    PrepareIntegrityTokenRequest.builder()
                        .setCloudProjectNumber(cloudProjectNumber)
                        .build()
                )
                .await()
        }
        val response = provider.request(
            StandardIntegrityTokenRequest.builder().setRequestHash(hex).build()
        ).await()
        // For attest, the SDK POSTs this token to the package verifier's HTTPS URL for a
        // verdict, then publishes token and verdict in the context's one ScpDeviceAttestation entry.
        return response.token().toByteArray(Charsets.UTF_8)
    }

    companion object {
        internal const val CODE_ATTESTATION_FAILED = "SCP-ATTEST-9001"
    }
}
```

**`AndroidPushProvider.kt` — FCM data-only payload:**

```kotlin
class AndroidPushProvider(private val context: Context) : PushProvider {

    override suspend fun register(): String {
        return withContext(Dispatchers.IO) {
            FirebaseMessaging.getInstance().token.await()
        }
    }

    override fun handleNotification(payload: Map<String, String>): WakeSignal {
        // FCM data payload: {"scp": "1"}
        // The value "1" is the wake signal. No context ID or sender information is present.
        val scpField = payload["scp"]
            ?: throw ScpException("FCM payload missing 'scp' field", "SCP-TRANS-5001")
        if (scpField != "1") {
            throw ScpException("FCM payload 'scp' field has unexpected value: $scpField", "SCP-TRANS-5002")
        }
        return WakeSignal.Pull  // connect to relay and pull pending envelopes
    }
}

// The relay sends the FCM row of the wake-signal table in
// 10-infrastructure-and-self-hosting.md §10.7.1 step 5 through the FCM HTTP v1 API — opaque, data-only:
// POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send
// {
//   "message": {
//     "token": "<fcm_token>",
//     "data": { "scp": "1" },
//     "android": { "priority": "HIGH" }
//   }
// }
// No "notification" key. No content visible to Android notification shade.
// (Amended 2026-10-12; this block previously showed the legacy FCM API's body,
// which addressed the device with a top-level token field and had no "message" object.)
```

**`AndroidStorage.kt` — SQLCipher with a §17.6-derived key:**

```kotlin
class AndroidStorage(private val context: Context) : StorageProvider {

    private val db: SupportSQLiteDatabase by lazy { openEncryptedDatabase() }

    private fun openEncryptedDatabase(): SupportSQLiteDatabase {
        val encryptionKey = getOrCreateStorageKey()
        val factory = SupportFactory(encryptionKey)
        return Room.databaseBuilder(context, ScpDatabase::class.java, "scp.db")
            .openHelperFactory(factory)
            .build()
            .openHelper
            .writableDatabase
    }

    private fun getOrCreateStorageKey(): ByteArray {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val keyAlias = "scp.storage.key"

        if (!keyStore.containsAlias(keyAlias)) {
            val keySpec = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)  // background access required
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
                .apply { init(keySpec) }
                .generateKey()
        }

        // §17.6 SQLCipher key derivation. Keystore MACs a fixed label (HMAC is deterministic
        // and takes no nonce); HKDF-SHA-256 expands the MAC output under the §17.6 salt and info.
        // The identifier is SHA-256 of the database directory's absolute path, because the
        // database opens before any identity loads. The key reaches SQLCipher as the raw-key
        // literal x'<64 hex>', so SQLCipher runs no second KDF.
        // (Amended 2026-10-12; this sketch previously encrypted the label with AES-GCM under a
        // fixed all-zero IV and truncated the output, which §17.6 does not permit.)
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
        val ikm = Mac.getInstance("HmacSHA256").apply { init(secretKey) }
            .doFinal("scp-storage-passphrase".toByteArray(Charsets.UTF_8))
        val dbDir = context.noBackupFilesDir
        val sha256 = MessageDigest.getInstance("SHA-256")
        val okm = hkdfSha256(
            ikm = ikm,
            salt = sha256.digest("SCP-SQLCIPHER-KEY-V1".toByteArray(Charsets.UTF_8)),
            info = "scp-sqlcipher:".toByteArray(Charsets.UTF_8) +
                sha256.digest(dbDir.absolutePath.toByteArray(Charsets.UTF_8)),
            length = 32,
        )
        return rawKeyLiteral(okm)  // "x'<64 hex>'" as ASCII bytes
    }

    override fun store(key: String, data: ByteArray) {
        db.execSQL("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", arrayOf(key, data))
    }

    override fun retrieve(key: String): ByteArray? {
        return db.query("SELECT value FROM kv WHERE key = ?", arrayOf(key))
            .use { cursor -> if (cursor.moveToFirst()) cursor.getBlob(0) else null }
    }

    override fun delete(key: String) {
        db.execSQL("DELETE FROM kv WHERE key = ?", arrayOf(key))
    }

    override fun listKeys(prefix: String): List<String> {
        return db.query("SELECT key FROM kv WHERE key LIKE ? ORDER BY key ASC", arrayOf("$prefix%"))
            .use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(cursor.getString(0))
                }
            }
    }

    override fun deletePrefix(prefix: String): Long {
        db.execSQL("DELETE FROM kv WHERE key LIKE ?", arrayOf("$prefix%"))
        return db.query("SELECT changes()", emptyArray())
            .use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else 0L }
    }

    override fun exists(key: String): Boolean {
        return db.query("SELECT 1 FROM kv WHERE key = ? LIMIT 1", arrayOf(key))
            .use { cursor -> cursor.moveToFirst() }
    }
}
```

**`PlatformAdapter.kt` — factory:**

```kotlin
object AndroidPlatformAdapter {

    fun make(context: Context): AndroidPlatformAdapter {
        return AndroidPlatformAdapterImpl(
            keyCustody = AndroidKeyCustody(),
            deviceAttestation = AndroidDeviceAttestation(context),
            push = AndroidPushProvider(context),
            storage = AndroidStorage(context),
        )
    }
}
```

**SDK injection point** (in the Kotlin SDK, `SCP.kt`). (Amended 2026-10-10: the sketch below predates `03-identity.md` §3.2.2. Its `"platform"` default and its `"in_memory"` arm are withdrawn: a caller selects this adapter with the request value `os_keystore`, the SDK's custody type carries no `in_memory` member, and every bridge answers `"platform"` with `SCP-VALID-7005`.)

```kotlin
suspend fun SCP.Companion.create(
    context: Context,
    custody: String = "platform",
): SCP {
    val adapter = when (custody) {
        "platform" -> AndroidPlatformAdapter.make(context)
        "in_memory" -> InMemoryPlatformAdapter.make()
        else -> throw ScpException("Unknown custody type: $custody", "SCP-IDENT-1001")
    }
    return SCP(NativeLib.scpCreate(adapter))
}
```

**Gradle dependencies** for the platform module:

```kotlin
// In bindings/kotlin/scp-kt-android/build.gradle.kts
dependencies {
    implementation("com.google.android.play:integrity:1.4.0")
    implementation("com.google.firebase:firebase-messaging-ktx:24.1.0")
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")
    implementation("androidx.sqlite:sqlite-ktx:2.4.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")  // P-256 agreement key for API 26-30
    implementation("androidx.security:security-crypto:1.1.0-alpha06")  // EncryptedSharedPreferences
}
```

### Dependencies

- **ADR-006 (Platform Abstraction Traits):** `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage` trait signatures implemented here. The UniFFI callback interface names (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) map directly to these traits.
- **ADR-021 (UniFFI Bridge):** Platform traits are exposed as UniFFI callback interfaces. `AndroidKeyCustody`, `AndroidDeviceAttestation`, `AndroidPushProvider`, and `AndroidStorage` are Kotlin implementations of those callback interfaces, injected from Kotlin into the Rust engine. Five callback interfaces total: `KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `DeviceAttestationProvider`, `MessageListener`.
- **ADR-025 (Apple Platform Adapter):** Structural reference. Both adapters implement the same four traits via the same UniFFI callback interface pattern, and since the curve ruling of 2026-09-10 both hold every SCP signing key in the platform signer, at the custody class each records per key (amended 2026-10-20; this clause previously read "both hold every SCP signing key in hardware"). They differ in attestation service and in the API level at which the platform performs key agreement.
- **ADR-028 (Kotlin SDK):** The Kotlin SDK calls `AndroidPlatformAdapter.make(context)` when the caller requests `os_keystore` custody (`03-identity.md` §3.2.2); this item previously named the `SCP.create()` factory and `custody = "platform"` (amended 2026-10-10). The SDK owns the injection point; the platform adapter owns the implementations.

### Acceptance Criteria

1. **`AndroidKeyCustody.generateKeypair(keyType)`:**
   - For a P-256 signing key at every supported API level: generates the key in `AndroidKeyStore` using `KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")` with `ECGenParameterSpec("secp256r1")` and `KeyProperties.DIGEST_NONE`. Returns `KeyHandle` whose `custodyType` is the class recorded for the key, below.
   - For a P-256 agreement key on API 31+: generates the key in `AndroidKeyStore` with `KeyProperties.PURPOSE_AGREE_KEY`. Returns `KeyHandle` whose `custodyType` is the class recorded for the key.
   - For a P-256 agreement key on API 26-30: generates a Bouncy Castle software key and commits its 32-byte scalar to `EncryptedSharedPreferences` before it returns. Returns `KeyHandle` with `custodyType = CustodyType.SOFTWARE`.
   - The store for an agreement key is chosen by the probe `Build.VERSION.SDK_INT >= 31`, read once when the adapter is constructed, never by catching a failure. A Keystore agreement-key create that fails on API 31+ fails the mint and never falls back to software.
   - Before it creates anything, the adapter commits a record for the key holding `{type, backing, custody, role}`, with `backing` either Keystore or software and `custody` pending until the key exists. `role` is the role the key is minted in, committed in the same write that reserves the record, so no role outlives its record, and every read of a P-256 key's role reads the record. It then settles `custody` to `"hardware"` when `KeyInfo` places the key in the TEE, StrongBox or an unknown secure level (`securityLevel` from API 31, `isInsideSecureHardware` below it), and to `"software"` otherwise and for every software key. Every later operation dispatches on the record's type and backing, never on the probe or the handle, and the handle's `custodyType` comes from the record.
   - A mint that fails after the record is committed rolls back: it deletes the alias or the scalar and confirms the deletion by re-reading. When it cannot confirm the deletion it keeps the record and throws `ScpException("SCP-CRYPTO-4060")` naming the key id, and `destroyKey` on that id retries. A record whose process tag (pid and process start time) differs from the current process's is left by an earlier process that died mid-mint, because the adapter runs in one process (below), and it is swept, alias or scalar included, when an adapter is constructed; an adapter never sweeps the current process's own pending record. The sweep is best-effort per record: a record whose key or record it cannot remove stays pending, the adapter logs its id with `Log.w` and no key material, and construction succeeds, because removing an orphan cleans up an inert leak on which no §9.15 guarantee depends. A record that does not decode fails only the operations on its own id.
   - An id whose record is pending reads as absent: every operation on it but `destroyKey` throws `ScpException("SCP-CRYPTO-4006")`, and the bridge's custody query reports `"in_memory"`.
   - **Single process.** `AndroidKeyCustody` runs in the app's main process only. `SharedPreferences.commit()` writes the committing process's whole cached map, so two processes over one preferences file lose each other's records and roles whatever else the adapter checks. Construction in any other process throws `ScpException("SCP-CRYPTO-4060")` whose message names this rule. The adapter reads its process name with `Application.getProcessName()` from API 28 and from `ActivityManager.runningAppProcesses` by pid below it, compares it with `applicationInfo.processName`, and refuses when it cannot read the name.
   - (Amended 2026-10-20; the first three items previously returned `CustodyType.HARDWARE` for every Keystore key, named no digest, and said the software key was stored without saying when, and the five items after them did not exist.)
   - For the root member: generates nothing. `09-security-model.md` §9.7.4.1 item 4 places the root in the platform credential provider as a passkey.
   - Called twice during identity creation: for the Active Signing Key and for the Pre-Rotation Key.

2. **`AndroidKeyCustody.sign(keyHandle, data)`:**
   - Requires `data` to be the bridge's 32-byte digest, retrieves `PrivateKeyEntry` from `AndroidKeyStore`, calls `Signature.getInstance("NONEwithECDSA")` under a key authorised for `KeyProperties.DIGEST_NONE`, and returns the platform signer's output, DER or raw. Input that is not 32 bytes throws `ScpException("SCP-CRYPTO-4060")`. (Amended 2026-10-20; this item previously read "Retrieves `PrivateKeyEntry` from `AndroidKeyStore`, calls `Signature.getInstance("SHA256withECDSA")`", which hashed the bridge's digest a second time.) The Rust bridge converts the output to the 64-byte raw `r || s` form of `09-security-model.md` §9.5 with `s` in the low half of the group order, and verifies it strictly against the key's public key before any caller sees it. (Amended 2026-10-19; this item previously read "converts the DER output to the 64-byte raw `r || s` form of `09-security-model.md` §9.5, and normalizes `s` into the low half of the group order.")
   - Rejects a request to sign under an agreement-only handle with `ScpException("SCP-CRYPTO-4060")`. (Amended 2026-10-20; this item previously named `PlatformError.wrongKeyType`, which the Kotlin surface does not have.)
   - Returns `ScpException("SCP-CRYPTO-4006")` if handle not found.

3. **`AndroidKeyCustody.publicKey(keyHandle)`:**
   - Extracts the P-256 public point from the Keystore certificate, or from the software key pair. A signing key returns the 33-byte SEC1 compressed encoding of `09-security-model.md` §9.5; an agreement key returns the 65-byte SEC1 uncompressed encoding HPKE uses. (Amended 2026-10-20; this item previously read "Extracts the P-256 public point from the Keystore certificate and returns the 33-byte SEC1 compressed encoding of `09-security-model.md` §9.5.")

4. **`AndroidKeyCustody.destroyKey(keyHandle)`:**
   - For a Keystore key: calls `KeyStore.deleteEntry("scp.key.${id}")`, then confirms with `containsAlias`.
   - For a software key: removes the committed scalar with `commit()`, confirms by re-reading the preferences, and drops the in-memory key pair.
   - A deletion it cannot confirm throws `ScpException("SCP-CRYPTO-4060")` and keeps the key's record, so a retry can act on it. It accepts a key whose record is still pending and an alias with no record.
   - The destruction attestation's method is `DestructionMethod.SOFTWARE_ONLY` for every key, the rule ADR-025 criterion 9 states for Apple: Keystore deletes a key it holds but issues no proof that it did, and §9.15 of `09-security-model.md` rates a destruction without a verified platform proof as software-only.
   - (Amended 2026-10-20; the first two items previously read "For hardware handles: calls `KeyStore.deleteEntry("scp.key.${id}")`." and "For software handles: removes from in-memory map.", and the last two did not exist.)
   - Key destruction is verifiable: subsequent `sign()` or `publicKey()` calls return `ScpException("SCP-CRYPTO-4006")`.

5. **`AndroidKeyCustody.dhAgree(keyHandle, peerPublic)`:**
   - Before the key is used, requires the peer key to be 65 bytes, uncompressed (prefix `0x04`), and a valid point on P-256 other than infinity (Bouncy Castle `SecP256R1Curve.decodePoint` and `isValid`); any other peer throws `ScpException("SCP-CRYPTO-4060")`.
   - Performs P-256 ECDH in `AndroidKeyStore` for a key the record says Keystore holds, building the peer key from `X509EncodedKeySpec` over the fixed P-256 SubjectPublicKeyInfo prefix and the 65-byte point, and through Bouncy Castle for a software key. Returns the 32-byte x-coordinate of the agreed point, left-padded to 32 bytes.
   - Rejects a request to agree under a signing-only handle with `ScpException("SCP-CRYPTO-4060")`.
   - The returned secret is a `ByteArray` the adapter does not wipe; the caller owns it. For a software key the agreement also leaves an immutable `BigInteger` that Kotlin cannot wipe.
   - (Amended 2026-10-20; the first and fourth items did not exist, and the third previously named `PlatformError.wrongKeyType`.)

6. **`AndroidKeyCustody.derivePseudonym(keyHandle, contextId)`:**
   - Computes `HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`. Derives a P-256 keypair from the first 32 bytes through the seed-to-scalar step of §9.10.4 of the security-model spec.
   - Returns the 33-byte compressed pseudonym point (amended 2026-09-29, SCP-307: no pseudonym key or handle exists).
   - **pseudonym_secret definition (IMPORTANT):** The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key — public key bytes are public and would be a membership-enumeration oracle (§9.10.4.A). For a **software** key (Bouncy Castle), `pseudonym_secret = HKDF-SHA256(p256_private_scalar, salt="scp-pseudonym-secret-v1", info="", len=32)`, byte-identical to Rust `derive_pseudonym_secret()`, so software pseudonyms are cross-platform deterministic (pinned by §25.19 vectors). For **hardware** keys (Keystore TEE), private key bytes are non-exportable, so `pseudonym_secret` is an associated 32-byte symmetric key generated inside the TEE at `generate_keypair` — a device-local secret, never `SHA-256` over a signature, because an ECDSA hardware signer draws its own nonce and would yield a different secret on every call (§9.5 of the security-model spec). **Hardware pseudonyms are device-local by design** and are intentionally NOT identical across devices or to the software vectors; cross-device pseudonym identity is not a protocol requirement, since the TEE key never leaves the device. This matches ADR-006 acceptance criterion 6 (§9.10.4.A).

7. **`AndroidDeviceAttestation.attest(challenge, deviceId)`:**
   - Implements the shipped UniFFI trait method `attest(challenge, device_id)`. The Rust caller passes the binding digest `D` of `09-security-model.md` §9.3.1 as `challenge`; the adapter rejects a `challenge` that is not 32 bytes and does not read `deviceId`. OQ-22 of `27-attestations.md` §27.7, the choice of trait, stays open.
   - Calls the Play Integrity Standard API through `IntegrityManagerFactory.createStandard(context)`, `prepareIntegrityToken` with the `cloudProjectNumber` of the package verifier's `PlayIntegrityVerifier` entry, and `StandardIntegrityTokenProvider.request`.
   - `requestHash` is the lowercase hexadecimal form of `D`. (Amended 2026-09-27; this criterion previously set a Classic `nonce` of `Base64(SHA-256(clientDataJSON))` that named no identifier.)
   - Returns the raw integrity token bytes. The SDK obtains a verdict for the token by one HTTPS `POST` to the URL in the package verifier's `PlayIntegrityVerifier` entry, in the §9.3.1 request format, and publishes both as the context's one `play-integrity` entry in the §9.3.1 format. No peer decodes the token; each reader verifies the verdict and returns `DeviceAttestationVerdict`, and a `Verified` from it is trust in the package's verifier.
   - The SDK requests a new token and verdict before the entry passes the context's `device_attestation_max_age_secs`, and when its own entry reads `Rejected{VerdictSignatureInvalid}` after the verifier rotates its key.
   - Every failure, a missing Google Play services installation and a `challenge` of the wrong size included, throws `ScpException` with code `SCP-ATTEST-9001`, because a UniFFI callback that throws any other exception panics the Rust caller.
   - On a device without Google Play services, `attest` throws and the SDK publishes no entry, so a reader returns `Absent`.

8. **`AndroidDeviceAttestation.assertRequest(requestHash)`:**
   - Implements the shipped UniFFI trait method `assert_request(request_hash)`. The Rust caller passes the assertion digest `A = SHA-256("SCP-DEVICE-ASSERTION-V1:" ‖ BE32(len(m)) ‖ m)` of `09-security-model.md` §9.3.1, never the caller's bytes, so no assertion's `requestHash` equals the hexadecimal form of any `D`.
   - Issues a fresh Standard integrity token whose `requestHash` is the lowercase hexadecimal form of `A`. It does not route through `attest`. (Amended 2026-09-27.)
   - Returns integrity token bytes.

9. **`AndroidPushProvider.register()`:**
   - Calls `FirebaseMessaging.getInstance().token.await()`.
   - Returns FCM registration token string.

10. **`AndroidPushProvider.handleNotification(payload)`:**
    - Validates `payload["scp"] == "1"`.
    - Returns `WakeSignal.Pull` on valid payload.
    - Throws `ScpException("SCP-TRANS-5001")` if `scp` field is absent.
    - Throws `ScpException("SCP-TRANS-5002")` if `scp` field has unexpected value.
    - No context ID, sender identifier, or message content is present in or extracted from the payload.
    - **Call order.** The app starts both push paths, and the Rust core calls the UniFFI `PushProvider` callback inside each. (Amended 2026-10-12; acceptance criterion 10 stated no call order before this item.)
      - Enabling push: the app calls the exported `push_enable(provider)` with its `AndroidPushProvider`. The Rust core calls `provider.registerPush()`, signs one `PushRegistration` (§10.7.1) carrying the returned FCM registration token for each relay in the relay set, each over that relay's canonical URL (`09-security-model.md` §9.5.2), and publishes each registration to its own relay.
      - Handling a wake: FCM delivers the data message to `FirebaseMessagingService.onMessageReceived`. The app passes the JSON serialization of the message's data map to the exported `push_handle_wake(payload)`. The Rust core calls `provider.handleNotification(payload)`, which applies the receipt rule above and returns the wake signal bytes or throws `ScpError`. On a thrown `ScpError`, the Rust core makes no relay connection. On wake signal bytes, the Rust core connects to the relay set, pulls every pending envelope under a 25-second deadline, and returns a `WakeOutcome` of `NewData`, `NoData` or `Failed`. The app finishes its wake work when `push_handle_wake` returns.
      - The wake's pull is the push-wake pull mode of ADR-029 §2. The wake dials the union of the persisted `relay_urls` of every Active context and queries each context only at the relays its own `relay_urls` name. The pull signs and publishes nothing. The member DID is the bridge's local identity, the DID its `NodeMlsFactory` holds. No cover traffic runs on the wake's connections (`09-security-model.md` §9.10.6). (Amended 2026-10-23; acceptance criterion 10 previously named no relay set, member DID, publishing rule or cover-traffic rule for the wake.)
      - Neither `push_enable` nor `push_handle_wake` exists yet. Stories PUSH-015 and PUSH-016 of `.docs/prds/push.json` add them.

11. **`AndroidStorage.store(key, data)` / `retrieve(key)` / `delete(key)` / `listKeys(prefix)` / `deletePrefix(prefix)` / `exists(key)`:**
    - All operations on a SQLCipher database whose 32-byte key is derived as `17-persistence-and-storage.md` §17.6 requires: HKDF-SHA-256 over the Keystore MAC of a fixed label, salt `SHA-256("SCP-SQLCIPHER-KEY-V1")`, info `"scp-sqlcipher:"` followed by the SHA-256 digest of the database directory's absolute path, passed to SQLCipher as the raw-key literal `x'<64 hex>'`. Two storage directories derive two keys; one directory derives the same key on every open.
    - Storage key is generated in `AndroidKeyStore` under alias `scp.storage.key` as a non-exportable 256-bit HMAC-SHA-256 key (`PURPOSE_SIGN`, `DIGEST_SHA256`), TEE-backed where the device's KeyMint is, no user authentication required. (Amended 2026-10-12; these two items previously named an AES-256-GCM key.)
    - `listKeys(prefix)` returns keys in lexicographic order (required for KeyPackage buffer management and event log range queries).
    - `deletePrefix(prefix)` returns count of deleted keys.

12. **`AndroidPlatformAdapter.make(context)`:**
    - Constructs `AndroidKeyCustody`, `AndroidDeviceAttestation` (for each call, with the `cloudProjectNumber` of the package verifier's `PlayIntegrityVerifier` entry), `AndroidPushProvider`, `AndroidStorage`.
    - Returns assembled adapter. Throws `ScpException` with descriptive message if any provider fails to initialize (e.g., Play Integrity unavailable, FCM not configured).
    - Called by the Kotlin SDK when the caller requests `os_keystore` custody (`03-identity.md` §3.2.2). (Amended 2026-10-10; this item previously read "Called by Kotlin SDK `SCP.create(context, custody = "platform")`.")

13. **Conformance test suite:**
    - Same conformance macros as the in-memory adapter (ADR-006): `key_custody_conformance!()`, `device_attestation_conformance!()`, `push_provider_conformance!()`, `storage_conformance!()`.
    - Key-custody tests run in the CI lane `kotlin-android-instrumented` on x86_64 AOSP emulator images at API 30, where the agreement key is software, and API 33, where Keystore performs agreement. They check that each key's recorded custody class equals what `KeyInfo` reports for it, that signatures verify strictly through the Rust bridge, and that agreement matches an independent ECDH. Each leg passes the instrumentation argument `expectSoftwareKeyInfo=true`, under which the custody test also requires `KeyInfo` to report a non-secure level, as an AOSP emulator's software KeyMint does; a run on a real device omits the argument. The custody tests run in the test app's main process, as the single-process rule of criterion 1 requires.
    - Play Integrity tests need Google Play services, which an AOSP image does not have, so no lane runs them and this criterion is unmet for them.
    - (Amended 2026-10-20; these items previously read "Hardware tests run on API 33+ physical device or API 33 emulator with Play Store." and "Software fallback tests run on API 26-32 emulator — verify `CustodyType.SOFTWARE` reported, valid signatures produced.")
    - FCM tests use Firebase Test Lab or mock `FirebaseMessaging` via dependency injection.
    - SQLCipher tests verify database is not readable without the Keystore-derived key (open raw SQLite file, confirm unreadable).

14. **Private key isolation:**
    - No P-256 private key bytes appear in logs, crash reports, or cross the UniFFI FFI boundary.
    - The Rust engine receives only signatures and public keys — never private key material.

### Scope

```
bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/ — 5 files, ~25 functions
```

| File | Functions |
|------|-----------|
| `AndroidKeyCustody.kt` | `generateKeypair`, `sign`, `publicKey`, `destroyKey`, `dhAgree`, `derivePseudonym`, `custodyType` + internal helpers |
| `AndroidDeviceAttestation.kt` | `attest`, `assertRequest` |
| `AndroidPushProvider.kt` | `register`, `handleNotification` |
| `AndroidStorage.kt` | `store`, `retrieve`, `delete`, `listKeys`, `deletePrefix`, `exists` + `getOrCreateStorageKey`, `openEncryptedDatabase` |
| `PlatformAdapter.kt` | `make` |

---

## ADR-028: Kotlin SDK

**Status:** Decided

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, made resolution return a key state, and an example here writes a named placeholder where an identifier's text form (`03-identity.md` §3.1) would stand.

### Context

The UniFFI bridge (ADR-021) generates raw Kotlin bindings from the Rust protocol engine. While functional, the generated surface is not idiomatic Kotlin — it lacks coroutine suspension, `Flow<T>` streams, Android lifecycle awareness, Jetpack Compose integration, and the ergonomic patterns Kotlin developers expect. The Android platform adapter (ADR-027) provides the `KeyCustody`, `PushProvider`, `Storage`, and `DeviceAttestationProvider` implementations injected into the Rust engine via UniFFI callback interfaces.

The Kotlin SDK ergonomics layer wraps the generated bindings to produce an idiomatic Kotlin API that feels native to the platform: `suspend` functions throughout, `Flow<Message>` for streaming, `LifecycleOwner`-aware cleanup, `@Composable`-ready state holders, and one `suspend` teardown per resource with no `AutoCloseable` (amended; see the `AutoCloseable` bullet under Rationale). The ergonomics layer is pure Kotlin — zero protocol logic, zero duplication of Rust behavior. This mirrors the ADR-014 (Python SDK) and ADR-026 (Swift SDK) pattern: flat FFI bridge → idiomatic language wrapper.

Kotlin 2.x with JVM 11+ is the baseline. The SDK targets both Android (API 26+) and JVM (server-side, tests). Android-specific lifecycle integration is opt-in — the core SDK runs on any JVM without Android dependencies.

### What This ADR Will Decide

- **Coroutine dispatcher strategy:** Which operations run on `Dispatchers.IO` vs `Dispatchers.Default`.
- **Flow vs Channel** for streaming (`Flow` preferred for cold streams, `Channel` for hot).
- **Android lifecycle integration:** `LifecycleOwner`-aware cleanup of SCP resources.
- **Jetpack Compose integration:** State holders, `remember` patterns.
- **Maven Central publishing configuration** (`works.limn:scp-kt`).

### Decision

Implement the Kotlin SDK as the `works.limn:scp-kt` package at `bindings/kotlin/`. The SDK module imports the UniFFI-generated `NativeLib.kt` from `internal/`, re-exports its types through the ergonomics layer in `src/main/kotlin/works/limn/scp/`, and builds a pure Kotlin ergonomics layer on top. The top-level entry point is `Scp` — a class that initializes the identity and injects the Android platform adapter. `Context` is the primary interactive type — exposing `Flow<Message>` for streaming and `AutoCloseable` / explicit `close()` lifecycle.

**Dispatcher strategy:**
- All FFI calls (blocking Rust operations) execute on `Dispatchers.IO` via `withContext(Dispatchers.IO)`. This is the designated dispatcher for blocking I/O operations in Kotlin coroutines — it is backed by a thread pool sized for blocking work.
- Business logic computations that don't cross the FFI boundary use `Dispatchers.Default` (CPU-bound work, data mapping, serialization).
- UI/state updates on Android use `Dispatchers.Main` only when explicitly dispatching to the main thread (e.g., from a `ViewModel`). The SDK never dispatches to `Dispatchers.Main` internally.

**Flow vs Channel:**
- `Flow<Message>` via `callbackFlow { }` is the streaming primitive for message reception. `callbackFlow` creates a cold stream backed by a `Channel` internally, but exposes a `Flow` API to callers. Cold stream semantics are correct: the UniFFI subscription starts when the flow is collected and stops (`awaitClose`) when the collector cancels. This matches the lifecycle of a context subscription.
- Raw `Channel` is not exposed in the public API. The internal `callbackFlow` uses a `Channel` with `Channel.BUFFERED` capacity (64 items) to absorb burst delivery from the Rust engine without dropping messages.

**Android lifecycle integration:**
- Android lifecycle integration is implemented via an extension function `Context.asFlow(lifecycleOwner: LifecycleOwner): Flow<Message>` in a separate `scp-kt-android` artifact. This artifact depends on `androidx.lifecycle:lifecycle-runtime-ktx` — a dependency the core SDK does not take on, keeping the JVM artifact Android-free.
- The extension launches collection in `lifecycleOwner.lifecycleScope` and cancels when the `LifecycleOwner` reaches `DESTROYED`. This prevents resource leaks when an `Activity` or `Fragment` is destroyed while a context subscription is live.
- `ViewModel`-based usage is the recommended pattern: hold the `SCP` instance and its context handles in a `ViewModel` that extends `ScpViewModel` (amended: ADR-048 removed `Context` from the Kotlin surface), expose `Flow<Message>` as a `StateFlow<List<Message>>` using `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())`. The `ViewModel.onCleared()` override launches `leave` for every tracked context, and then the held `SCP` instance's `shutdown`, on a scope it never cancels and returns without waiting (amended: `viewModelScope` is already cancelled when `onCleared()` runs, and blocking `onCleared()` on a teardown deadlocks or risks an ANR; see the `AutoCloseable` bullet under Rationale).

**Jetpack Compose integration:**
- The core artifact `works.limn:scp-kt` takes no Compose dependency. `works.limn:scp-kt-android` carries the Compose state holders (SCP-118), and they build on standard Kotlin patterns the SDK already provides: `Flow<Message>` collected via `collectAsState()`, and resources held in `remember { }` blocks whose `DisposableEffect` `onDispose` launches their `suspend` teardown on a scope that disposal never cancels, then returns (amended; see the `AutoCloseable` bullet under Rationale).
- Recommended pattern: collect a context's messages through `rememberIncomingMessages(hotStreams, contextHandle)` over an `ScpHotStreams`, as the next bullet and the Compose sketch under Implementation show (amended: ADR-048 removed `Context` and its `receiveFlow()` from the Kotlin surface).
- Hot streams shared across composables (amended): `works.limn:scp-kt-android` exposes hot streams through three public entry points. `ScpHotStreams(bindings, scope, ioDispatcher)` constructs its own `HotStreamFactory` over `bindings` on `ioDispatcher`, which defaults to `Dispatchers.IO`, and its own coordinator on `scope`, and exposes neither. `rememberContextEvents(hotStreams, contextHandle)` and `rememberIncomingMessages(hotStreams, contextHandle)` key each subscription by stream kind and context handle, so no caller chooses a key. An application container, or a ViewModel that every navigation destination shares, holds one `ScpHotStreams` and passes it to every composable that shows a context's streams, so every screen showing one context's stream shares one Rust subscription. The coordinator counts live mounts per key and, when the last mount under a key leaves, releases that subscription on `scope` without blocking `onDispose`; it logs a release that throws instead of propagating it (`.docs/standards/sdk-common.md` §Cleanup error handling). Once every composable that passed an `ScpHotStreams` has left composition, its owner calls that instance's suspend `close()` and then cancels `scope`. `close()` refuses every later start, waits for each running start and for each stop launched before it reached that stop's key, and then calls `HotStreamFactory.stopAll()`, which attempts every release it still holds and logs each failure, so a subscription whose stop a cancelled `scope` skipped, or whose stop `close()` did not wait for, is released too. `close()` runs under `NonCancellable`, so an owner may call it from a cancelled coroutine. The KDoc of `ScpHotStreamCoordinator` in `compose/StateHolders.kt` states which `onStop` lambdas the coordinator drops and how it orders stops, and `.docs/lessons/kotlin/hot-stream-subscription-ownership.md` records the defects this shape prevents.
- Context lifecycle in Compose: `rememberScpContext(contextHandle, identityHandle) { ctxH, idH -> teardownScope.launch { runCatching { bridge.context.leave(ctxH, idH) }.onFailure { Log.w(TAG, "leave failed after disposal", it) } } }`. When the composable leaves the composition, `ScpContextHolder.dispose()` cancels the holder's scope and then calls that callback, which launches `leave` on `teardownScope`. `teardownScope` outlives the composable and disposal never cancels it, so `onDispose` never blocks the composition thread (amended; see the `AutoCloseable` bullet under Rationale). The launched block logs a `leave` failure instead of throwing it, because an exception escaping a root launch reaches the thread's uncaught-exception handler, which on Android kills the process (`.docs/standards/sdk-common.md` §Cleanup error handling).

**Maven Central publishing:**
- Published as `works.limn:scp-kt` on Maven Central.
- Android-specific lifecycle extension published as `works.limn:scp-kt-android`.
- AAR artifact for Android targets. JAR artifact for JVM targets. Both include bundled native libraries (`.so` for Android ABIs, `.so`/`.dylib`/`.dll` for JVM targets) in the JAR resources directory.
- GPG signing required for Maven Central upload. Signing performed in CI using a key stored in GitHub Actions secrets.

**Flat delegation pattern — no logic in Kotlin:** Every Kotlin SDK method calls exactly one UniFFI bridge function. Zero protocol logic lives in the Kotlin layer. This prevents divergence between the Rust engine and the Kotlin surface and ensures one implementation of every operation.

### Rationale

- **`Dispatchers.IO` for all FFI calls:** The UniFFI-generated bindings call into native Rust code via JNA. JNA calls are blocking — they block the calling thread until the Rust function returns. Kotlin's `Dispatchers.IO` is designed for exactly this: a thread pool that accepts blocking calls without starving the coroutine scheduler. Calling FFI on `Dispatchers.Default` (the CPU thread pool) would starve cooperative tasks; calling on `Dispatchers.Main` would block the UI thread. `Dispatchers.IO` is the one correct choice.
- **`callbackFlow` over raw `Channel` or `StateFlow`:** Message streaming from the Rust engine is callback-driven: the UniFFI callback interface calls `onMessage()` from a Rust thread. `callbackFlow` is the idiomatic Kotlin bridge from callback APIs to `Flow`. It handles back-pressure via channel buffering, propagates cancellation by calling `awaitClose`, and integrates with structured concurrency automatically. `StateFlow` would only expose the latest message (wrong semantics). A raw `Channel` exposed as public API would force callers to manage collection manually (wrong ergonomics).
- **Lifecycle-in-extension-artifact, not in core:** Android lifecycle (`LifecycleOwner`, `lifecycleScope`) is an Android-only API. Taking this dependency in the core SDK would force JVM targets (server-side, tests) to depend on Android-specific artifacts. Separating it into `scp-kt-android` keeps the core SDK usable on any JVM and keeps the Android extension small and focused.
- **One suspending teardown, and no `AutoCloseable`, for each hand-written type whose teardown crosses the FFI boundary (amended; see below):** Kotlin/JVM resource management follows the `AutoCloseable` / `use { }` pattern, and this ADR originally applied it to `Context`: `context.use { }` for automatic cleanup, with `AutoCloseable.close()` as a synchronous safety net that launched a `close()` coroutine and cancelled the internal scope, matching the `deinit` + `close()` pattern in the Swift SDK. **That rule no longer holds, for the reason stated in the amendment below.** `SCP`, `Relay`, `Node`, and `ScpHotStreams` expose their teardown as one `suspend` function and implement no `AutoCloseable`. The classes UniFFI generates, such as `Scp`, keep the synchronous `close()` UniFFI gives them.

  **Amendment (this ADR stays Decided; this bullet supersedes the rule above).** `AutoCloseable.close()` is synchronous, and `use { }` treats its return as the end of the teardown, so a `close()` whose teardown reaches the Rust engine can keep that promise only by blocking its calling thread. A lifecycle callback that cannot suspend, `ScpViewModel.onCleared()` or the `onDispose` callback a composable passes to `rememberScpContext`, promises no finished teardown, so it launches the `suspend` teardown on a scope that outlives it and returns. `SCP.shutdown(bridge, timeout)` suspends on its bridge's injected `ioDispatcher` through `CoroutineBridge.ffiCallSuspend`, and reaches the Rust engine through the UniFFI-generated `Scp` object. Five other teardowns suspend the same way, but no production class implements the bindings interface each one calls, so today each reaches only a test source set's stub and never the Rust engine: a subscription flow's release, when its collector cancels, runs `withContext` on that dispatcher over `ContextBindings` or `EventContextBindings`; `ScpViewModel`'s `leave` runs through `CoroutineBridge.context` over `ContextBindings`; `Relay.shutdown()` and `Node.shutdown()` run through `CoroutineBridge.ffiCall` over `ServerBindings` (`.docs/standards/sdk-capability-matrix.json` marks every Server operation `"kotlin": false`); and `ScpHotStreams.close()` releases every subscription its `HotStreamFactory` still holds through `HotStreamFactory.stopAll()`, on that factory's injected dispatcher, over `EventContextBindings`. Blocking a caller on a teardown that suspends on an injected `ioDispatcher` fails in two ways:
  - A caller that injects a `StandardTestDispatcher` parks the one thread that advances that dispatcher's scheduler, so the work the `close()` waits for can never run and `close()` never returns. This repository observed it, as a hang in `ScpViewModel.onCleared()`'s tests.
  - An Android caller blocks a main thread, which risks an ANR.

  A bounded wait does not rescue the pattern: it still blocks a calling thread, and blocking an Android main thread up to a timeout risks an ANR, so it trades a deadlock for an ANR rather than removing a blocking wait. `.docs/lessons/kotlin/oncleared-must-not-block-its-caller.md` records the observed deadlock and the ANR risk.

  `Context`, the type the superseded rule named, no longer exists on the Kotlin surface — ADR-048 replaced the free-function façade and its `Context` type with per-instance methods on `SCP`. `SCP.shutdown(bridge, timeout)` is `suspend` and takes a `CoroutineBridge`, so a synchronous `close()` could neither obtain that bridge nor honour that deadline. `Relay` and `Node` follow the same rule, so that their teardown already suspends when a production `ServerBindings` implementation lands.

  This changes what a caller writes. The lifecycle invariant in `.docs/standards/sdk-common.md` §Lifecycle invariant (leave contexts, destroy key material, close transports, flush events) is unchanged, and a caller reaches it from a coroutine rather than from a `use { }` block. Each of the three `shutdown` functions sets its shutdown flag inside its bridge call, once its teardown call returns, so a teardown call that throws leaves the object reading as live, and a cancellation the bridge raises after a finished teardown leaves it reading as shut down. `.docs/standards/sdk-common.md` §Resource Lifecycle carries the same rule in its per-language table, and §"Kotlin: why no `Closeable`" states why.
- **No Compose dependencies in SDK:** Compose APIs (`@Composable`, `State<T>`, `collectAsState()`) require the Compose compiler plugin and runtime. Shipping a Compose dependency in the SDK would force every consumer to adopt Compose or deal with unused transitive dependencies. Compose integration is trivially achieved with standard `Flow.collectAsState()` and `DisposableEffect` — patterns that are Compose-idiomatic without SDK involvement.
- **`Scp` class (not object/singleton) as top-level entry point:** `Scp` holds per-identity state (the identity handle, the platform adapter). Multiple `Scp` instances in a process are valid (e.g., in tests, or in apps that support account switching). A Kotlin `object` singleton would prevent this. The factory pattern `Scp.create()` is a `companion object` method — idiomatic for async factory construction in Kotlin.
- **Kotlin 2.x, JVM 11+:** Kotlin 2.x is the current stable release with full coroutines support, improved type inference, and the K2 compiler. JVM 11 is required by Android Gradle Plugin 8+ and covers all modern JVM targets. JVM 11 features (e.g., `List.of()`, `String.isBlank()`) are available; no Java 8 compatibility mode needed.

### Implementation

**Language:** Kotlin 2.x

**Package:** `bindings/kotlin/` published as `works.limn:scp-kt` on Maven Central.

**Dependencies from UniFFI:** `identityCreate()`, `identityLoad()`, `identityResolve()`, `contextCreate()`, `contextJoin()`, `contextLeave()`, `contextClose()`, `contextSend()`, `contextSubscribe()` (callback interface), `outletRegister()`, `outletInvoke()`, `outletVerify()`, `ucanValidate()`, `ucanMint()`, `ucanRevoke()`, `eventLogQuery()`, `eventLogVerify()`, `transportConnect()`, `transportStatus()`, and the `ScpError` enum — all from `internal/NativeLib.kt`.

**File layout:**

```
bindings/kotlin/
  build.gradle.kts                         # Root Gradle build (multi-module)
  settings.gradle.kts                      # Module declarations
  scp-kt/
    build.gradle.kts                       # SDK core module (JVM + Android)
    src/
      main/kotlin/works/limn/scp/
        SCP.kt                             # Scp class — top-level entry point, factory, context creation
        Identity.kt                        # Identity class, ResolutionOutcome data class
        Context.kt                         # Context class, Flow<Message>, AutoCloseable lifecycle
        Outlets.kt                           # OutletDefinition, TestVector data classes
        Trust.kt                           # evaluateTrust(), TrustEvaluation data class
        EventLog.kt                        # EventLog class, Event, Proof, Checkpoint data classes
        Transport.kt                       # TransportConfig data class, transport helpers
        Types.kt                           # Shared types: Message, Provenance, Capability, ContextParams
        Ucan.kt                            # ucanValidate(), ucanMint(), ucanRevoke() top-level functions
        Mcp.kt                             # serveMcp(), McpClient class
        Errors.kt                          # ScpException hierarchy
        internal/
          NativeLib.kt                     # UniFFI-generated native bindings (auto-generated, do not edit)
      main/resources/
        works/limn/scp/native/
          linux-x86-64/libscp_ffi.so
          linux-aarch64/libscp_ffi.so
          osx-x86-64/libscp_ffi.dylib
          osx-aarch64/libscp_ffi.dylib
          win32-x86-64/scp_ffi.dll
      test/kotlin/works/limn/scp/
        IdentityTest.kt
        ContextTest.kt
        OutletsTest.kt
        UcanTest.kt
        TransportTest.kt
        EventLogTest.kt
        McpTest.kt
        conformance/
          ConformanceTest.kt               # Cross-language conformance test suite runner
  scp-kt-android/
    build.gradle.kts                       # Android lifecycle extension module
    src/
      main/kotlin/works/limn/scp/android/
        ContextLifecycle.kt                # Context.asFlow(LifecycleOwner) extension
        ScpViewModel.kt                    # Base ViewModel with SCP resource management
```

**`build.gradle.kts` (SDK core module):**

```kotlin
plugins {
    kotlin("jvm") version "2.0.0"
    kotlin("plugin.serialization") version "2.0.0"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
    id("maven-publish")
    id("signing")
}

group = "works.limn"
version = "0.1.0"

kotlin {
    jvmToolchain(11)
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
    implementation("net.java.dev.jna:jna:5.18.1")  // UniFFI JNA dependency

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

tasks.test {
    useJUnitPlatform()
}
```

**`SCP.kt` — top-level entry point:** (amended: this sketch's `AutoCloseable` and synchronous `close()` are superseded by the `AutoCloseable` bullet under Rationale)

```kotlin
/**
 * Top-level SCP SDK entry point. Initialize once per identity.
 *
 * @param custody Key custody method: "platform" (Android Keystore / JVM keystore)
 *                or "in_memory" (software keys, testing only).
 */
class Scp private constructor(private val identityHandle: IdentityHandle) : AutoCloseable {

    val identity: Identity = Identity(identityHandle)

    companion object {
        /**
         * Create an SCP instance. Generates a new identity if none exists for this device.
         * On Android with custody = "platform", injects AndroidPlatformAdapter.
         * On JVM with custody = "in_memory", uses software keys (testing only).
         */
        suspend fun create(
            custody: String = "platform",
            platformAdapter: PlatformAdapter? = null,
        ): Scp = withContext(Dispatchers.IO) {
            val handle = NativeLib.identityCreate(
                custody = custody,
                keyCustody = platformAdapter?.keyCustody,
                storage = platformAdapter?.storage,
                pushProvider = platformAdapter?.pushProvider,
                deviceAttestation = platformAdapter?.deviceAttestation,
            )
            Scp(handle)
        }
    }

    /** Create a new context. */
    suspend fun createContext(params: ContextParams): Context = withContext(Dispatchers.IO) {
        val handle = NativeLib.contextCreate(identity = identityHandle, params = params.toRecord())
        Context(handle)
    }

    /** Join an existing context by ID. */
    suspend fun joinContext(id: String): Context = withContext(Dispatchers.IO) {
        val handle = NativeLib.contextJoinById(identity = identityHandle, contextId = id)
        Context(handle)
    }

    override fun close() {
        // Synchronous cleanup — cancels internal scope, releases handles.
        identityHandle.destroy()
    }
}
```

**`Identity.kt`:**

```kotlin
/**
 * An SCP identity (identifier). Holds the signing key handle — never exposes private key bytes.
 * Constructed by Scp.create(). Use Scp.identity to access.
 */
class Identity internal constructor(internal val handle: IdentityHandle) {

    val identifier: ByteArray get() = handle.identifier()
    val custodyType: String get() = handle.custodyType()

    companion object {
        /** Load an existing identity from storage. */
        suspend fun load(identifier: ByteArray): Identity = withContext(Dispatchers.IO) {
            Identity(NativeLib.identityLoad(identifier))
        }
    }

    /** Resolve another identity's key state. */
    suspend fun resolve(identifier: ByteArray): ResolutionOutcome = withContext(Dispatchers.IO) {
        ResolutionOutcome.fromRecord(NativeLib.identityResolve(identifier))
    }

    /** Rotate this identity's signing key. Returns an updated Identity with the same identifier. */
    suspend fun rotateKey(): Identity = withContext(Dispatchers.IO) {
        Identity(NativeLib.identityRotateKey(identity = handle))
    }
}

/** A key state resolved from an identity's key-event log. */
data class ResolutionOutcome(
    val verdict: ResolutionVerdict,
    // Present on Confirmed and Adopted, absent on every other verdict.
    val keyState: KeyState?,
    val sources: ResolutionSources,
    val resolvedAt: Long,  // Unix milliseconds
) {
    companion object {
        internal fun fromRecord(record: ResolutionOutcomeRecord): ResolutionOutcome = ResolutionOutcome(
            verdict = ResolutionVerdict.fromRecord(record.verdict),
            keyState = record.keyState?.let(KeyState::fromRecord),
            sources = ResolutionSources.fromRecord(record.sources),
            resolvedAt = record.resolvedAt,
        )
    }
}
```

**`Context.kt`:** (amended: this sketch's `AutoCloseable`, its synchronous `close()`, and the release in `awaitClose`'s lambda are superseded by the `AutoCloseable` bullet under Rationale)

```kotlin
/**
 * An active SCP context. Send messages, receive streams, invoke outlets.
 * Always call close() when done. Use the use { } block or DisposableEffect in Compose.
 */
class Context internal constructor(internal val handle: ContextHandle) : AutoCloseable {

    val contextId: String get() = handle.contextId()
    val state: String get() = handle.state()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /** Send a message to this context. */
    suspend fun send(payload: ByteArray): Unit = withContext(Dispatchers.IO) {
        if (state != "active") throw ContextException("Context is not active", "SCP-CTX-2001")
        handle.send(payload)
    }

    /**
     * Cold Flow of incoming messages. Collection begins the UniFFI subscription;
     * cancellation ends it. Use callbackFlow for cold semantics with buffer.
     */
    fun receiveFlow(): Flow<Message> = callbackFlow {
        handle.subscribe(object : MessageListener {
            override fun onMessage(message: ScpMessage) {
                trySend(Message.fromRecord(message))
            }
            override fun onError(error: ScpError) {
                close(ScpException.fromFfi(error))
            }
            override fun onComplete() {
                close()
            }
        })
        awaitClose { handle.unsubscribe() }
    }.buffer(Channel.BUFFERED)

    /** Invoke a registered outlet in this context. Returns the outlet output as JSON. */
    suspend fun invokeOutlet(outletId: String, inputJson: String): String = withContext(Dispatchers.IO) {
        handle.invokeOutlet(outletId, inputJson)
    }

    /** Register an outlet through an outlet Commit or a RegisterOutlet proposal (ADR-010 criterion 2 amendment, ADR-066 decision 31). */
    suspend fun registerOutlet(definition: OutletDefinition): OutletRegistrationOutcome = withContext(Dispatchers.IO) {
        handle.registerOutlet(definition.toRecord())
    }

    /** Leave this context gracefully (member action). */
    suspend fun leave(): Unit = withContext(Dispatchers.IO) {
        handle.leave()
    }

    /** Close this context (admin action). Terminates the context for all members. */
    suspend fun closeContext(): Unit = withContext(Dispatchers.IO) {
        handle.closeContext()
    }

    /**
     * AutoCloseable.close() — synchronous cleanup. Schedules a leave() coroutine
     * and cancels the internal scope. Prefer calling leave() or closeContext() explicitly
     * for graceful teardown.
     */
    override fun close() {
        scope.launch { runCatching { leave() } }
        scope.cancel()
        handle.destroy()
    }
}
```

**`Errors.kt` — exception hierarchy:**

```kotlin
/**
 * Base exception for all SCP errors. Carries a structured error code (SCP-{CATEGORY}-{NUMBER}).
 */
open class ScpException(
    message: String,
    val code: String,
) : Exception(message) {

    companion object {
        internal fun fromFfi(error: ScpError): ScpException = when (error) {
            is ScpError.Identity -> IdentityException(error.message, error.code)
            is ScpError.Context -> ContextException(error.message, error.code)
            is ScpError.Permission -> PermissionException(error.message, error.code)
            is ScpError.Crypto -> CryptoException(error.message, error.code)
            is ScpError.Transport -> TransportException(error.message, error.code)
            is ScpError.Outlet -> OutletException(error.message, error.code)
            is ScpError.Validation -> ValidationException(error.message, error.code)
        }
    }
}

class IdentityException(message: String, code: String) : ScpException(message, code)
class ContextException(message: String, code: String) : ScpException(message, code)
class PermissionException(message: String, code: String) : ScpException(message, code)
class CryptoException(message: String, code: String) : ScpException(message, code)
class TransportException(message: String, code: String) : ScpException(message, code)
class OutletException(message: String, code: String) : ScpException(message, code)
class ValidationException(message: String, code: String) : ScpException(message, code)
```

**`Types.kt` — data carrier types:**

```kotlin
/** An incoming SCP message. Immutable data class — safe to pass across coroutine boundaries. */
data class Message(
    val senderDid: String,
    val content: ByteArray,
    val timestamp: Long,       // Unix milliseconds
    val sequence: Long,
    val contextId: String,
    val provenance: Provenance? = null,
) {
    companion object {
        internal fun fromRecord(record: ScpMessage): Message = Message(
            senderDid = record.senderDid,
            content = record.content,
            timestamp = record.timestamp,
            sequence = record.sequence,
            contextId = record.contextId,
            provenance = record.provenance?.let(Provenance::fromRecord),
        )
    }

    // ByteArray equals/hashCode must be overridden in data classes
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Message) return false
        return senderDid == other.senderDid && content.contentEquals(other.content) &&
               timestamp == other.timestamp && sequence == other.sequence &&
               contextId == other.contextId && provenance == other.provenance
    }

    override fun hashCode(): Int {
        var result = senderDid.hashCode()
        result = 31 * result + content.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + contextId.hashCode()
        result = 31 * result + (provenance?.hashCode() ?: 0)
        return result
    }
}

/** Context creation parameters. */
data class ContextParams(
    val ceiling: List<String>,
    val outlets: List<OutletDefinition> = emptyList(),
    val governance: String = "single_admin",
    val ttlMs: Long? = null,
    val memoryScope: String = "full",
)
```

**`Ucan.kt` — top-level UCAN functions:**

```kotlin
/** Validate a UCAN token for a capability in a context. Throws PermissionException if invalid. */
suspend fun ucanValidate(token: String, capability: String, contextId: String): Unit =
    withContext(Dispatchers.IO) {
        NativeLib.ucanValidate(token = token, capability = capability, contextId = contextId)
    }

/** Mint a UCAN token delegating capabilities to a member identifier. Returns the token string. */
suspend fun ucanMint(
    identity: Identity,
    memberDid: String,
    capabilities: List<String>,
): String = withContext(Dispatchers.IO) {
    NativeLib.ucanMint(identity = identity.handle, memberDid = memberDid, capabilities = capabilities)
}

/** Revoke a previously minted UCAN token. */
suspend fun ucanRevoke(identity: Identity, tokenId: String): Unit = withContext(Dispatchers.IO) {
    NativeLib.ucanRevoke(identity = identity.handle, tokenId = tokenId)
}
```

**Android lifecycle extension (`scp-kt-android` module):**

```kotlin
// ContextLifecycle.kt — in works.limn.scp.android package

/**
 * Collects messages from this Context as a Flow, scoped to a LifecycleOwner.
 * Collection starts in STARTED state; cancels when the owner reaches DESTROYED.
 * Prevents resource leaks in Activities and Fragments.
 */
fun Context.asLifecycleFlow(
    owner: LifecycleOwner,
    minActiveState: Lifecycle.State = Lifecycle.State.STARTED,
): Flow<Message> = receiveFlow().flowWithLifecycle(owner.lifecycle, minActiveState)
```

```kotlin
// ScpViewModel.kt — in works.limn.scp.android package

/**
 * Base ViewModel that leaves every tracked context and shuts down the SCP instance it holds
 * in scpInstance when the ViewModel is cleared.
 */
abstract class ScpViewModel : ViewModel() {

    // Set by the subclass, so the constructor keeps zero arguments: a Java subclass calls
    // super(). scpInstance is the SCP instance onCleared() shuts down; scpBridge is the
    // bridge its shutdown runs on.
    protected var scpInstance: SCP? = null
    protected var scpBridge: CoroutineBridge? = null

    private val contextsLock = Any()
    private val activeContexts = mutableListOf<TrackedContext>()
    private var cleared = false // written and read only under contextsLock

    // viewModelScope is already cancelled when onCleared() runs, so a launch there never
    // runs. Cleanup gets its own scope, which nothing cancels.
    private val cleanupJob = SupervisorJob()
    private val cleanupScope = CoroutineScope(cleanupJob + Dispatchers.Unconfined)

    // Serializes onCleanupFailure across onCleared()'s cleanup coroutine and each coroutine a
    // post-clear trackContext launches; a Mutex suspends a waiter instead of blocking its thread.
    private val cleanupFailureLock = Mutex()

    // A context tracked after onCleared() is left at once: Android clears a ViewModel once,
    // so nothing else would ever leave it.
    fun trackContext(context: TrackedContext): TrackedContext {
        val alreadyCleared = synchronized(contextsLock) {
            if (!cleared) activeContexts.add(context)
            cleared
        }
        if (alreadyCleared) launchLeave(listOf(context))
        return context
    }

    override fun onCleared() {
        super.onCleared()
        val contexts = synchronized(contextsLock) {
            cleared = true
            activeContexts.toList().also { activeContexts.clear() }
        }
        // Dispatch and return: blocking the main thread on a teardown deadlocks or
        // risks an ANR (see the amended Rationale bullet).
        launchLeave(contexts, shutdownAfter = true)
    }

    private fun launchLeave(
        contexts: List<TrackedContext>,
        shutdownAfter: Boolean = false,
    ) {
        // UNDISPATCHED runs the coroutine on the calling thread up to its first suspension. A
        // default start, from a caller already inside a Dispatchers.Unconfined coroutine (a
        // retry from onCleanupFailure), would queue it until that caller suspends, and an
        // inline bridge's leave would then run after trackContext returns.
        cleanupScope.launch(start = CoroutineStart.UNDISPATCHED) {
            for (ctx in contexts) {
                val failure = runCatching { ctx.bridge.context.leave(ctx.handle, ctx.identityHandle) }
                    .exceptionOrNull() ?: continue
                // A throwing override must not stop the remaining leaves.
                cleanupFailureLock.withLock { runCatching { onCleanupFailure(ctx, failure) } }
                    .onFailure { Log.w("ScpViewModel", "onCleanupFailure threw", it) }
            }
            val scp = scpInstance
            val bridge = scpBridge
            if (shutdownAfter && scp != null && bridge != null) {
                // A leave needs the engine that shutdown stops, so shutdown waits for every
                // other cleanup coroutine: a post-clear trackContext's leave, and a retry an
                // onCleanupFailure override launched through trackContext. A leave launched
                // while this loop waits is joined too; one launched after it ends is not.
                val self = coroutineContext.job
                while (true) {
                    val others = cleanupJob.children.filter { it !== self }.toList()
                    if (others.isEmpty()) break
                    others.joinAll()
                }
                runCatching { scp.shutdown(bridge) }
                    .onFailure { Log.w("ScpViewModel", "SCP shutdown failed during ViewModel cleanup", it) }
            }
        }
    }

    /**
     * Called once per context whose leave() threw, with whatever it threw. The default body
     * logs at warning level (sdk-common.md §Cleanup error handling); an app overrides it to
     * record, retry, or report a departure that did not land.
     */
    protected open fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        Log.w("ScpViewModel", "leave failed during ViewModel cleanup", cause)
    }
}
```

**Jetpack Compose integration pattern (`works.limn:scp-kt-android` state holders):**

```kotlin
// In a composable — scp-kt-android's state holders over standard Flow + Compose APIs

// The app's ViewModel owns the scope that leave runs on; nothing cancels that scope.
class MyContextViewModel : ScpViewModel() {
    val teardownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
}

// The app container builds one ScpHotStreams, on a scope it never cancels, and passes it to
// every screen, so every screen showing one context's stream shares one Rust subscription.
// An owner that does cancel that scope first calls hotStreams.close() from a coroutine, once
// every screen that passed it has left composition.
@Composable
fun ContextScreen(
    contextHandle: Long,
    identityHandle: Long,
    bridge: CoroutineBridge,
    hotStreams: ScpHotStreams,
) {
    val viewModel: MyContextViewModel = viewModel()

    // Leaving composition cancels the holder's scope, then launches leave on a scope that
    // outlives this composable, so onDispose returns without blocking.
    rememberScpContext(contextHandle, identityHandle) { ctxH, idH ->
        viewModel.teardownScope.launch {
            // A leave failure is logged, never thrown: an exception escaping this launch reaches
            // the thread's uncaught-exception handler, which on Android kills the process.
            runCatching { bridge.context.leave(ctxH, idH) }
                .onFailure { Log.w("MyContextScreen", "leave failed after disposal", it) }
        }
    }

    // Released when the last screen collecting this context's incoming messages through
    // hotStreams leaves.
    val incoming by rememberIncomingMessages(hotStreams, contextHandle)
    // rememberScpEventList keeps the newest 100 messages and discards its list when its flow
    // changes, so a new contextHandle starts an empty list instead of appending to the old one.
    val messages = incoming?.let { rememberScpEventList(it).value }.orEmpty()

    LazyColumn {
        items(messages) { message ->
            MessageItem(message)
        }
    }
}
```

**Maven Central publishing configuration:**

```kotlin
// In scp-kt/build.gradle.kts

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "works.limn"
            artifactId = "scp-kt"
            version = project.version.toString()

            from(components["java"])

            pom {
                name.set("SCP SDK for Kotlin")
                description.set("Kotlin SDK for the Shared Context Protocol")
                url.set("https://github.com/limn/scp")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("limn")
                        name.set("Limn")
                        email.set("dev@limn.dev")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/limn/scp.git")
                    developerConnection.set("scm:git:ssh://github.com/limn/scp.git")
                    url.set("https://github.com/limn/scp")
                }
            }
        }
    }
    repositories {
        maven {
            name = "MavenCentral"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_CENTRAL_USERNAME")
                password = System.getenv("MAVEN_CENTRAL_TOKEN")
            }
        }
    }
}

signing {
    useInMemoryPgpKeys(
        System.getenv("GPG_KEY_ID"),
        System.getenv("GPG_PRIVATE_KEY"),
        System.getenv("GPG_PASSPHRASE"),
    )
    sign(publishing.publications["mavenJava"])
}
```

**Consumer usage:**

```kotlin
// build.gradle.kts (consumer)
dependencies {
    implementation("works.limn:scp-kt:0.1.0")
    // Optional Android lifecycle extension:
    implementation("works.limn:scp-kt-android:0.1.0")
}
```

### Dependencies

- **ADR-021 (UniFFI Bridge):** The Kotlin SDK wraps the UniFFI-generated `NativeLib.kt`. Every SDK public method calls exactly one UniFFI bridge function. The bridge defines the flat function surface (`identityCreate`, `contextCreate`, etc.), opaque object handles (`IdentityHandle`, `ContextHandle`), value records (`ScpMessage`, `ContextParams`), the `ScpError` sealed class, and the `MessageListener` callback interface.
- **ADR-027 (Android Platform Adapter):** The `AndroidPlatformAdapter` (implemented in ADR-027) is instantiated by `Scp.create(custody = "platform", platformAdapter = AndroidPlatformAdapter.make(context))` and injected into the Rust engine via UniFFI callback interfaces. The Kotlin SDK `Scp.create()` factory accepts a `PlatformAdapter` parameter; ADR-027 provides the Android-specific implementation.
- **ADR-006 (Platform Abstraction):** Platform trait definitions (`KeyCustody`, `PushProvider`, `Storage`, `DeviceAttestationProvider`) shape the UniFFI callback interface contracts that the Kotlin platform adapter implements.
- **ADR-026 (Swift SDK):** Parallel reference. Same flat delegation pattern, same "no logic in the wrapper layer" principle, same FFI bridge → idiomatic language wrapper architecture. Key differences: Kotlin uses `suspend` functions and `Flow<Message>` where Swift uses `async/await` and `AsyncStream<Message>`; Kotlin uses one `suspend` teardown and no `AutoCloseable` (amended; see Rationale) where Swift uses `deinit` + `close()`; Kotlin uses `@Observable`-equivalent via `StateFlow` where Swift uses `@Observable` macro.
- **ADR-014 (Python SDK) / ADR-013 (PyO3 Bridge):** The ergonomics layer pattern — flat FFI bridge → idiomatic language wrapper — is established here and applied to Kotlin. Kotlin SDK mirrors the structural choices (no logic in the wrapper layer, delegation only) and the type category decisions (opaque handles for crypto state, data classes for data).
- **ADR-022 (TypeScript SDK):** Parallel patterns: `Flow<Message>` (Kotlin) mirrors `AsyncIterable<Message>` (TypeScript); the `suspend` teardown (Kotlin) mirrors `Symbol.asyncDispose` (TypeScript). Conformance test suite is shared.

### Acceptance Criteria

1. **Module builds for all JVM targets:**

   ```bash
   ./gradlew build -Pscp.uniffi.cargoFeatures=testing
   ./gradlew test -Pscp.uniffi.cargoFeatures=testing
   ```

   Both commands exit 0. Zero ktlint violations. Zero detekt findings.

2. **`Scp.create()` factory:**
   - `Scp.create(custody = "in_memory")` returns an `Scp` instance with a 32-byte `identity.identifier`.
   - `Scp.create(custody = "platform", platformAdapter = AndroidPlatformAdapter.make(context))` returns an `Scp` instance with hardware-backed identity on API 33+.
   - `Scp.create()` with an unknown custody string throws `IdentityException` with code `"SCP-IDENT-1001"`.

3. **`Identity` operations:**

   ```kotlin
   val scp = Scp.create(custody = "in_memory")
   assertEquals(32, scp.identity.identifier.size)
   assertEquals("in_memory", scp.identity.custodyType)

   val outcome = scp.identity.resolve(scp.identity.identifier)
   assertTrue(doc.verificationMethods.isNotEmpty())

   val rotated = scp.identity.rotateKey()
   assertEquals(scp.identity.identifier, rotated.identifier)  // the identifier is stable; key material rotates
   ```

4. **`Context` lifecycle:**
   - `scp.createContext(params)` returns a `Context` with `state == "active"`.
   - `context.send(payload)` delivers an encrypted message (no throw for valid payload and active state).
   - `context.leave()` completes without throwing for a valid active context.
   - After `close()`, `send()` throws `ContextException` with code `"SCP-CTX-2001"`.
   - A `Relay.shutdown()` or `Node.shutdown()` whose `ServerBindings` teardown call throws (in `ServerTest`, the test source set's `StubServerBindings`, the only implementer) leaves `isShutdown` false, and one whose caller is cancelled after a finished teardown leaves `isShutdown` true — verified by `ServerTest`. `SCP.shutdown` meets the same two conditions for its internal `isShutdown` flag, verified by `ScpShutdownTest`.
   - `SCP.shutdown(bridge, timeout)`, `Relay.shutdown()`, and `Node.shutdown()` are `suspend` functions, and none of `SCP`, `Relay`, or `Node` implements `AutoCloseable` (amended; see Rationale).

5. **Message streaming via `Flow<Message>`:**

   ```kotlin
   val context = scp.createContext(ContextParams(ceiling = listOf("messages:read", "messages:write")))
   val received = mutableListOf<Message>()

   val job = launch {
       context.receiveFlow().collect { message ->
           received.add(message)
       }
   }

   repeat(3) { i -> context.send("message $i".toByteArray()) }
   context.closeContext()
   job.join()

   assertEquals(3, received.size)
   ```

6. **Dispatcher isolation:**
   - SDK code that dispatches a blocking FFI call or a subscription release through `withContext` runs it on an injected `ioDispatcher` that defaults to `Dispatchers.IO` — verified by `ScpHotStreamRemountTest`'s `ScpHotStreams subscribes and releases on its injected dispatcher`, in `scp-kt-android`'s `compose/StateHoldersTest.kt`. It builds an `ScpHotStreams` on a `StandardTestDispatcher` and checks that the event-stream subscribe and unsubscribe of the `HotStreamFactory` that instance constructs run only when that dispatcher runs them, on the thread that advances its scheduler.
   - `receiveFlow()` does not block the calling thread — verified by calling it from a single-threaded test dispatcher and confirming the call returns immediately.

7. **`ScpException` hierarchy:**
   - All UniFFI `ScpError` variants map 1:1 to `ScpException` subclasses.
   - Each subclass has `message: String` and `code: String`.
   - Error codes follow the `SCP-{CATEGORY}-{NUMBER}` format.
   - `ScpException.fromFfi(error)` returns the correct subclass for each `ScpError` variant.
   - Exceptions thrown from bridge functions surface as `ScpException` subclasses (not raw UniFFI types) in the ergonomics layer.

8. **UCAN operations:**
   - `ucanMint(identity, memberDid, capabilities)` returns a non-empty token string.
   - `ucanValidate(token, capability, contextId)` does not throw for a valid token and matching capability.
   - `ucanValidate(token, capability, contextId)` throws `PermissionException` for an invalid or expired token.
   - `ucanRevoke(identity, tokenId)` does not throw for a valid token ID.

9. **Outlet operations:**

   ```kotlin
   val outletId = context.registerOutlet(OutletDefinition(
       name = "summarize",
       description = "Summarize text",
       inputSchema = mapOf("type" to "object", "properties" to mapOf("text" to mapOf("type" to "string"))),
       outputSchema = mapOf("type" to "object", "properties" to mapOf("summary" to mapOf("type" to "string"))),
       operator = scp.identity.identifier,
   ))
   assertTrue(outletId.startsWith("outlet-"))
   ```

10. **Event log queries:**

    ```kotlin
    val log = context.eventLog()
    val events = log.query(since = System.currentTimeMillis() - 3_600_000)
    assertTrue(events.all { it.contextId == context.contextId })

    val checkpoint = log.checkpoint()
    assertTrue(checkpoint.merkleRoot.isNotEmpty())
    ```

11. **Android lifecycle integration (scp-kt-android):**
    - `context.asLifecycleFlow(lifecycleOwner)` returns a `Flow<Message>` that cancels when the `LifecycleOwner` reaches `DESTROYED`.
    - Verified by creating a `TestLifecycleOwner`, collecting the flow in a test coroutine, moving the owner to `DESTROYED`, and asserting the flow completes.
    - `ScpViewModel.onCleared()` launches `leave()` for every tracked context on a scope it never cancels and returns without waiting for those calls (amended; see Rationale). A `leave()` that throws, whatever it throws, does not stop the remaining calls: each throwable goes to `ScpViewModel.onCleanupFailure(context, cause)`, a `protected open` hook whose default body logs at warning level, and a throw from an override is logged and does not stop them either. `onCleanupFailure` calls never overlap: a `Mutex` serializes them across `onCleared()`'s cleanup coroutine and each coroutine that a `trackContext` call after clear launches. An override may therefore update unsynchronized state, although successive calls can run on different threads. ScpViewModelTest verifies the serialization in `onCleanupFailure calls from parallel cleanup coroutines never overlap`. A waiting coroutine suspends rather than blocking its thread: `an inline-bridge failure waits for a running onCleanupFailure and runs on its thread` fails under a blocking lock, because `trackContext` would block the test thread before the running call is released. Each cleanup coroutine starts undispatched on the thread that calls `onCleared()` or `trackContext`, so when `trackContext` leaves a context over a bridge whose I/O dispatcher runs inline, such as `Dispatchers.Unconfined`, that `leave` and its `onCleanupFailure` call run on the calling thread before `trackContext` returns, unless another cleanup coroutine holds the lock; the waiting call then runs later, on the thread that releases it. `an inline leave retried from onCleanupFailure runs before trackContext returns` fails under a default start, which queues a retry launched from inside an unconfined cleanup coroutine until the retrying override returns. `onCleared()` also shuts down the `SCP` instance the ViewModel holds in `scpInstance`, when the subclass has set `scpInstance` and `scpBridge`, on its own cleanup coroutine, after its own `leave()` calls, once no other cleanup coroutine is running. It waits for each coroutine that a `trackContext` call after clear launched, including a retry that an `onCleanupFailure` override launched through `trackContext`. A cleanup coroutine launched after the shutdown starts is not ordered before it.

12. **Jetpack Compose integration (`works.limn:scp-kt-android` state holders; `works.limn:scp-kt` takes no Compose dependency):**
    - The module-internal `rememberScpHotStream`, which `rememberContextEvents` and `rememberIncomingMessages` call, recomposes with the flow its `start` returned — verified in `StateHoldersTest`.
    - `ScpHotStreams` releases each stream when the last mount of that stream leaves, and a coordinator scope cancelled while a non-cancellable `onStop` runs logs nothing and completes the `Job` of each departure that stop covers normally — verified in `StateHoldersTest.kt` by `ScpHotStreams releases each stream when the last mount of that stream leaves` and `a scope cancelled while a non-cancellable onStop runs reports every onStop as run`. A stop that held no `onStop` logs no skip on a cancelled scope — verified by `a stop that held no onStop reports no skip on a cancelled scope`. `ScpHotStreams` subscribes and releases on the dispatcher it is given — verified by `ScpHotStreams subscribes and releases on its injected dispatcher`. `ScpHotStreams.close()` waits for a stop already launched and releases a subscription whose stop a cancelled scope skipped — verified by `closing ScpHotStreams waits for a launched stop` and `closing ScpHotStreams releases a subscription whose stop a cancelled scope skipped`. A caller that is already cancelled gets the same release — verified by `closing ScpHotStreams from a cancelled caller still waits for a pending stop and releases the rest`. `HotStreamFactory.stopAll()` attempts every release after one throws and logs that failure — verified in `StreamsTest.kt` by `stopAll releases every subscription after one unsubscribe throws`.
    - When a composable holding `rememberScpContext` leaves the composition, `ScpContextHolder.dispose()` cancels the holder's scope before it calls `onDispose` — verified with `ComposeContentTestRule` by `rememberScpContext disposes scope on cleanup` in `StateHoldersTest`. That scope is therefore already cancelled inside the callback, so the documented pattern launches `leave` on a scope the caller owns and disposal never cancels.
    - `rememberScpHotStream`'s disposal returns while its `onStop` is still suspended, and a start that reaches its key's mutex after its own mount's stop does not run — verified in `StateHoldersTest.kt`.
    - A `start` that throws is logged, never reaches the thread's uncaught-exception handler, leaves that mount's `State` null, and still has its `onStop` run on disposal, including a `start` that throws `CancellationException` while its mount is composed — verified in `StateHoldersTest.kt` by `rememberScpHotStream logs a throwing start, keeps State null, and still runs onStop` and `rememberScpHotStream logs a start that throws CancellationException while mounted`.

13. **No logic in Kotlin layer:**
    - Code review: every public SDK method body contains exactly one `NativeLib.*` call (plus `withContext` and error mapping). No branching protocol logic exists in any ergonomics-layer file.

14. **Test suite passes:**

    ```bash
    ./gradlew test -Pscp.uniffi.cargoFeatures=testing
    ./gradlew test -Pscp.uniffi.cargoFeatures=testing -Ptarget=android  # Android instrumented tests (requires connected device or emulator)
    ```

    All tests use JUnit 5 (`@Test`, `runTest`). No JUnit 4.

15. **Conformance tests:**
    - The cross-language conformance test suite (from `scaffold/shared.md`) passes for Kotlin.
    - A context created by the Kotlin SDK is joinable by the Python SDK, Swift SDK, and TypeScript SDK (verified with shared test vectors from `tests/conformance/`).
    - Messages sent from Kotlin are receivable by Python, Swift, and TypeScript SDK consumers.

16. **Maven Central distribution:**

    ```kotlin
    // In a consumer's build.gradle.kts
    dependencies {
        implementation("works.limn:scp-kt:0.1.0")
    }
    ```

    `./gradlew dependencies` resolves successfully. No Rust toolchain required by the consumer. Native libraries for all five platforms (Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64) are bundled in the JAR resources.

### Scope

**Files (~14):**

| File | Purpose |
|------|---------|
| `scp-kt/build.gradle.kts` | Gradle module build — dependencies, publishing, signing, ktlint, detekt |
| `src/main/kotlin/works/limn/scp/SCP.kt` | `Scp` class — top-level entry point, `create()` factory, `createContext()`, `joinContext()` |
| `src/main/kotlin/works/limn/scp/Identity.kt` | `Identity` class — `identifier`, `custodyType`, `load()`, `resolve()`, `rotateKey()`; `ResolutionOutcome` data class |
| `src/main/kotlin/works/limn/scp/Context.kt` | `Context` class — `send()`, `receiveFlow()`, `invokeOutlet()`, `registerOutlet()`, `leave()`, `closeContext()`, `AutoCloseable` |
| `src/main/kotlin/works/limn/scp/Outlets.kt` | `OutletDefinition`, `TestVector`, `OutletVerificationResult` data classes |
| `src/main/kotlin/works/limn/scp/Trust.kt` | `evaluateTrust()`, `TrustEvaluation` data class |
| `src/main/kotlin/works/limn/scp/EventLog.kt` | `EventLog` class, `Event`, `Proof`, `Checkpoint` data classes |
| `src/main/kotlin/works/limn/scp/Transport.kt` | `TransportConfig` data class, transport helpers |
| `src/main/kotlin/works/limn/scp/Types.kt` | `Message`, `Provenance`, `Capability`, `ContextParams` data classes |
| `src/main/kotlin/works/limn/scp/Ucan.kt` | `ucanValidate()`, `ucanMint()`, `ucanRevoke()` top-level suspend functions |
| `src/main/kotlin/works/limn/scp/Mcp.kt` | `serveMcp()`, `McpClient` class |
| `src/main/kotlin/works/limn/scp/Errors.kt` | `ScpException` hierarchy, `ScpException.fromFfi()` mapping |
| `src/main/kotlin/works/limn/scp/internal/NativeLib.kt` | UniFFI-generated bindings (auto-generated, never edit manually) |
| `scp-kt-android/src/main/kotlin/works/limn/scp/android/ContextLifecycle.kt` | `Context.asLifecycleFlow()` extension + `ScpViewModel` base class |

**Estimated functions:** ~30 public functions/methods, ~12 public types (classes + data classes + exception hierarchy), ~6 internal helpers.

---

## ADR-029: Offline/Sync Strategy

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling).

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, left an identity one operational role, so a verifier resolves a member's key from that member's key state (`09-security-model.md` §9.1 invariant 1, `03-identity.md` §3.10.4).

**Amendment (2026-09-10 — queued-operation signatures are ECDSA on P-256).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. Each `signature` field on this ADR's queued-operation and reconciliation structures carries the type `P256Signature`, and its signature-validity check verifies an ECDSA signature on P-256 against the member's resolved verification method. The offline queue model, the three reconnection cases, and the relay backfill path are untouched.

### Context

Architecture.md §6 explicitly flags offline MLS re-sync as "the hardest unsolved problem" with High likelihood and High impact. Members offline for extended periods accumulate pending MLS proposals and Commits. The group state advances without them — epochs increment, sender keys rotate, members join and leave, governance actions execute. When the offline member reconnects, they must reconcile their stale local state with the group's current state. The difficulty is that MLS requires sequential epoch processing (each Commit depends on the previous epoch's key schedule), forward secrecy means old epoch keys are destroyed after the grace window (ADR-001 criterion 6), and relays are untrusted infrastructure that may or may not retain the full message history.

SCP's design makes this simultaneously harder and easier than in traditional messaging systems. Harder: devices are full protocol participants (§10.2), not thin clients that can ask a server for the current state. There is no authoritative server — only relays holding encrypted blobs and peers holding decrypted state. Easier: the verifiable event log (ADR-011) provides a cryptographic mechanism for state reconciliation — two members can compare Merkle roots and prove exactly where their views diverge. The protocol's minimal state footprint (§10.3) means what needs syncing is small: membership, roles, tokens, outlet registrations, governance, and event hashes — not content.

This ADR defines the offline/sync strategy across three time horizons (hours, days, weeks), resolves conflict semantics for concurrent offline operations, specifies the MLS epoch catch-up protocol, and defines when and how group state resets occur.

### Scope

**What this ADR covers:**

- Client-side message queue for outbound messages during disconnection.
- Reconnection protocol: relay catch-up, MLS epoch reconciliation, event log sync.
- Offline duration tiers and the strategy for each (hours, days, weeks).
- MLS group state reset: trigger conditions, initiation protocol, member lifecycle during reset.
- Conflict resolution for concurrent offline governance and membership changes.
- Sender key re-acquisition after missed rotations.
- Multi-device sync coordination for offline/online transitions.

**What this ADR does NOT cover:**

- Content storage and retrieval (app-layer, §10.6).
- Event log pruning and checkpointing (ADR-030).
- Multi-admin governance conflict resolution beyond single-admin (ADR-031).
- Real-time media session recovery (§10.9.1 — media sessions are ephemeral and do not survive disconnection).

### Decision

Implement a three-tier offline/sync strategy in `scp-core/sync/` that classifies offline durations and applies progressively stronger reconciliation mechanisms. The tiers are: **Tier 1 (Short offline, < 4 hours)** using relay buffering and sequential MLS catch-up; **Tier 2 (Extended offline, 4 hours to 7 days)** using state snapshot comparison and delta sync with selective epoch reconstruction; and **Tier 3 (Long offline, > 7 days)** using forced re-join via MLS group state reset. All tiers use the Merkle event log (ADR-011) as the authoritative state reconciliation mechanism and the relay's store-and-forward capability (ADR-004) as the primary message recovery path.

#### 1. Client-Side Outbound Queue

When the SDK detects disconnection (all relay WebSocket connections lost), outbound messages are queued locally rather than dropped.

The outbound queue operates as follows:

- Messages are serialized to their inner envelope form (signed, padded) and stored in `ProtocolRepository` under `queue/{context_id}/{seq:020d}`. The inner envelope is fully constructed (including signature and padding) but NOT MLS-encrypted — MLS encryption requires the current epoch's key schedule, which may advance while offline. MLS encryption is applied at drain time using the then-current epoch.
- The queue is bounded at 1,000 messages per context and 10,000 messages total across all contexts. When full, the oldest messages are dropped with a `QueueOverflow` event emitted to the application layer.
- Queue entries include a `queued_at` timestamp. On reconnection, entries older than the context's `blob_ttl` (or 7 days if no TTL) are discarded — they would expire on relays before delivery anyway.
- The queue drains automatically on reconnection, after MLS epoch catch-up completes. Messages are MLS-encrypted with the current epoch's key schedule and sent in queue order.

```rust
pub struct QueuedMessage {
    pub context_id: ContextId,
    pub inner_envelope: Vec<u8>,  // Serialized, signed, padded inner envelope
    pub queued_at: u64,           // Unix timestamp when queued
    pub sequence: u64,            // Local queue sequence (for ordering)
}

pub struct OutboundQueue {
    store: Arc<ProtocolRepository>,
    per_context_limit: usize,     // Default: 1_000
    total_limit: usize,           // Default: 10_000
}
```

#### 2. Reconnection Protocol

On reconnection (at least one relay WebSocket connection re-established), the SDK executes the following ordered protocol:

**Phase 1 — Relay catch-up.** For each active context, re-issue `SUBSCRIBE` with `since` = last received `stored_at` minus 5-second overlap (ADR-004 Connection Recovery). Process all backfilled blobs. Deduplicate by `blob_id` (ADR-012 dedup cache). This recovers all messages that relays retained during the offline period.

**Phase 2 — MLS epoch reconciliation.** For each context, compare the local MLS epoch number against the epoch numbers in received messages. If the local epoch is behind, enter the epoch catch-up procedure (section 3 below). If epochs match, the context is current.

**Phase 3 — Event log sync.** For each context, exchange consistency checkpoints (ADR-011 criterion 8) with online members. Compare Merkle roots. If roots match at the same event count, the logs are consistent. If they diverge, identify the first divergent event and resolve (section 5 below).

**Phase 4 — Sender key re-acquisition.** For each context, check for `SenderKeyEpochAdvance` events received during catch-up. For any sender whose key epoch has advanced beyond the locally cached version, issue `SenderKeyRequest` (ADR-007 criterion 4c) to obtain the current key. Messages encrypted with missed sender key epochs are buffered until the key is obtained or a 60-second timeout expires. After timeout, those messages are marked as `UnrecoverableSenderKey` and the application layer is notified.

**Phase 5 — MLS Update.** After catch-up is complete, the SDK issues an MLS Update proposal in each active context (§9.7.3: "SDK SHOULD issue an Update after re-establishing connectivity following an offline period"). This provides post-compromise security for the reconnecting member. The member merges the Update Commit and publishes it through the same broadcast and retry queue as every other Commit it issues (ADR-049): a publish that fails keeps the Commit queued for retry, and Phase 5 then fails the context, because no peer can follow the member into the new epoch until the Commit reaches a relay (spec §23.3 Phase 5).

**Phase 6 — Queue drain.** Drain the outbound queue for each context. Each queued inner envelope is MLS-encrypted with the current epoch's key schedule and sent. If a queued message references a context that no longer exists (closed or expired while offline), the message is discarded with a `ContextGone` notification to the application layer.

**Push-wake pull mode.** A silent push that wakes a device (`10-infrastructure-and-self-hosting.md` §10.7.1) runs a pull-only form of this protocol. iOS gives a woken app about 30 seconds, and a woken device must not change what its peers or its relays observe, so the pull mode reads and signs nothing beyond what Phases 1, 2 and 4 need. (Added 2026-10-23 for story PUSH-016.)

1. The Rust core applies the device receipt rule of §10.7.1 for the push platform. A rejected payload returns `SCP-TRANS-5080` before the core opens any connection.
2. The core restores every persisted Active context that is not resident. No earlier `connect` call is needed. A process with no known context runs the startup restore, which restores contexts and then replays unresolved sagas (§17.16.4). A process that already knows a context restores each missing context alone, with no saga replay, because a replay in a live process would reconcile its in-flight sagas as crashed. A context is resident when its actor runs or a crash record holds it for respawn. A persisted Active context that is still not resident after this step, because its restore failed, fails the wake: the pull cannot reach that context, so `NoData` would report traffic the wake never pulled. (Amended 2026-10-23; this step previously restored only when no context was resident, so one failed restore blocked every later wake.)
3. The core dials once, on a transient transport with no cover traffic (`09-security-model.md` §9.10.6), the union of the persisted relay sets of the Active contexts (ADR-025 criterion 4). The transient transport's connection budget is the size of that union, so it keeps one connection per dialed relay and evicts none. It never installs that transport as the instance transport, and it drops the transport when the wake returns. A relay whose dial fails fails only the contexts whose relay set names it. (Amended 2026-10-23; this step previously named neither the budget nor which contexts a failed dial fails.)
4. For each Active context the core runs Phase 1, Phase 2 and Phase 4. Phase 1 queries each relay in that context's own persisted relay set, and no other relay, for the shared routing ID and for each pseudonym routing ID the member holds: the current one, and the previous one while its grace period runs (`09-security-model.md` §9.10.4.1). A blob that two of those relays store enters the buffer once. Its `since` is the stored `sync/{context_id}/last_relay_contact` minus the 5-second overlap, or 0 when no value is stored. Phase 2 feeds the Phase 1 buffer to the actor until a pass accepts nothing. Phase 4 re-feeds the Phase 1 buffer to the actor and publishes no `SenderKeyRequest`. The actor handles every envelope the pull feeds it in pull-only delivery mode: it applies the envelope's receive-side effects and sends nothing, so a sender-key answer that a delivered `KeyRequest` queues stays queued until the next full reconnection sends it. (Amended 2026-10-23; Phase 1 previously queried every connected relay for every context, and the step named no delivery mode.)
5. The pull runs no Phase 3 checkpoint exchange, no Phase 5 Update, no Phase 6 drain, and neither the Tier 2 nor the Tier 3 engine, and it sends no queued sender-key answer. The device therefore signs, ratchets its MLS send state for, and publishes nothing, and the pull-mode code takes no `CommandSigner`. The pull leaves `EpochState.needs_reconnect` set, so the next full reconnection still runs every phase, and one that ends in `FullyCaughtUp`, `FastForwarded` or `Reset` sends every queued sender-key answer. (Amended 2026-10-23; this step previously did not name the queued sender-key answer.)
6. After Phases 2 and 4 have fed every blob of a context's Phase 1 buffer to the actor, and the actor reached a verdict on every blob, the core writes the time it took before Phase 1 to `sync/{context_id}/last_relay_contact`. The actor reaches a verdict on a blob when it accepts the blob or refuses it as invalid for the group: a replay, an undecryptable blob, or a Commit that fits no epoch. A refusal is a verdict because the 5-second overlap of step 4 returns blobs the previous wake already delivered, which the actor refuses as replays on every later wake. The actor reaches no verdict when the delivery never reaches a judgment on the blob: the actor is busy, crashed, poisoned, unregistered or shut down, or its key custody, transport, event log or store fails. Phase 4 delivers every blob of the buffer, so it is each blob's last attempt; a blob whose Phase 4 delivery reaches no verdict fails the context. A context whose pull fails, or that the deadline stops before Phase 4 ends, keeps its stored value, so the next wake pulls again what this one did not deliver. A failure in one context does not stop the pull of another. (Amended 2026-10-23; the core previously wrote the value as soon as Phase 1 succeeded, before any delivery, and then after Phase 4 whether or not the actor reached a verdict on each blob.)
7. One 25-second deadline covers the restore, the dial, and every query and delivery. The wake returns `NewData` when the actor accepted at least one application envelope in any context, including a context the deadline stopped. Otherwise it returns `Failed` when any of the following holds, and `NoData` when none does. A `Failed` wake whose contexts failed lists each failed context with its own code, `SCP-TRANS-5096` to `SCP-TRANS-5101`, so a host can tell a context with no relay from one whose actor reached no verdict. (Amended 2026-10-23; this step previously listed fewer causes, gave `Failed` precedence over a delivery in another context, and gave a context's failure no code of its own.)
   - the instance is shut down, or holds no supervisor or no local member DID;
   - the restore of step 2, or the listing of the Active contexts, fails;
   - a persisted Active context is not resident after step 2;
   - a suspend or shutdown cancels the dial of step 3;
   - a context names no relay, or a relay in its set failed to dial;
   - a context's Phase 1 query, or the read or write of its `last_relay_contact`, fails;
   - the actor reached no verdict on a blob of a context's buffer (step 6);
   - the deadline expires.

#### 3. MLS Epoch Catch-Up (Tier 1 and Tier 2)

MLS requires sequential epoch processing — each Commit depends on the previous epoch's key schedule. An offline member at epoch E who reconnects to find the group at epoch E+N must process all N intermediate Commits in order.

**Commit recovery sources (tried in order):**

1. **Relay backfill.** MLS Commits are sent as MLS `PrivateMessage` under the `PURE_CIPHERTEXT` wire policy (ADR-057 T3; Commit messages are not application messages; they are protocol messages delivered via the transport layer). Relays store them like any other blob. If the relay's retention covers the offline period, all Commits are recoverable.
2. **Peer request.** If relays have expired some Commits (blob_ttl elapsed), the reconnecting member broadcasts a `CommitRangeRequest { context_id, from_epoch, to_epoch }` as an MLS application message (using their current epoch keys — they can still encrypt at their stale epoch). Online members who have persisted the Commit messages respond with the missing Commits. This is a best-effort protocol — members are not required to retain raw Commit messages beyond the MLS grace window.
3. **Welcome-based fast-forward.** If the epoch gap is too large (> 100 epochs or no member can provide the full Commit chain), the reconnecting member is treated as a new joiner. An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage, effectively re-adding them to the group at the current epoch. The member's old leaf node is removed. This is the Tier 2 fallback — it preserves membership and context continuity but the member loses access to messages encrypted in epochs between their stale epoch and the current epoch (forward secrecy is maintained).

**Amendment (2026-10-18, ADR-066): the fast-forward is a reset the member requested.** "Any member with `MemberInvite` capability" no longer holds. Removing the old leaf is a Remove, so the member that generates the Welcome holds both `MemberInvite` and `MemberRemove`, as for the Tier 3 reset of §4. The reconnecting member asks for the re-add with a signed `ResetRequest` whose reason is `CatchUpFailed`, and the one Commit that removes the old leaf and adds the new one carries that request in its governance block and records the re-add as one `MemberReset` leaf, as the §4 amendment states. No member fast-forwards another without that request or an executed `ResetMember` governance action. `23-sync-and-offline-strategy.md` §23.4.1 states the procedure, and `07-trust-validation-and-capabilities.md` §7.3.1.1 steps 1.6, 1.7, and 2 state what every receiver checks.

**Epoch catch-up limits:**

- The SDK processes at most 100 sequential Commits per catch-up attempt. If more than 100 Commits are pending, the SDK switches to Welcome-based fast-forward.
- Each Commit is processed within a 5-second timeout. Commits that fail to process (corrupted, missing dependencies) are logged as `EpochCatchUpFailure` and the SDK falls through to the next recovery source.
- The 100-Commit limit is a practical bound. In a context with 24-hour PCS Update intervals and 10 members, 100 Commits represents roughly 10 days of activity. Contexts with higher churn (frequent joins/leaves) may hit this limit sooner.

```rust
pub struct EpochCatchUpState {
    pub context_id: ContextId,
    pub local_epoch: u64,
    pub target_epoch: u64,
    pub commits_processed: u64,
    pub status: CatchUpStatus,
}

pub enum CatchUpStatus {
    /// Sequential Commit processing in progress.
    Processing,
    /// All epochs caught up successfully.
    Complete,
    /// Fell back to Welcome-based fast-forward.
    FastForwarded { skipped_from: u64, skipped_to: u64 },
    /// Catch-up failed — context may need group reset.
    Failed { reason: String },
}

pub struct CommitRangeRequest {
    pub context_id: ContextId,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub requester_did: [u8; 32],
    pub signature: P256Signature,
}

pub struct CommitRangeResponse {
    pub context_id: ContextId,
    pub commits: Vec<Vec<u8>>,  // Serialized MLS Commit messages, in epoch order
    pub responder_did: [u8; 32],
    pub signature: P256Signature,
}
```

#### 4. MLS Group State Reset (Tier 3)

When a member has been offline for more than 7 days, or when the epoch catch-up procedure fails (no recovery source can provide the Commit chain and no member can generate a Welcome), the member triggers a group state reset for their participation.

**Group state reset is NOT a group-wide operation.** It affects only the offline member's participation. The group continues operating normally. The reset is equivalent to: the offline member leaves and immediately re-joins.

**Trigger conditions (any one triggers reset):**

1. Offline duration exceeds 7 days (measured from last successful relay interaction timestamp, persisted in `ProtocolRepository`).
2. Epoch catch-up fails: relay backfill, peer request, and Welcome-based fast-forward all failed.
3. The context's governance model explicitly requests reset (future: ADR-031 governance action).

**Reset protocol:**

1. The reconnecting member publishes a `ResetRequest { context_id, member_did, last_known_epoch, reason, nonce, timestamp, signature }` via the relay (not MLS-encrypted — the member may not be able to encrypt at the current epoch). The member signs the request with its Active Signing Key. The `nonce` is 16 random bytes (CSPRNG) and the `timestamp` is the current Unix time in seconds. The signature covers all fields except the signature itself via the canonical hash construction (§9.5.1) with domain separator `"SCP-RESET-REQUEST-V1:"`.

   **Anti-replay validation.** Because ResetRequest is not MLS-encrypted, it is visible to relays and any network observer. Without replay protection, an attacker who captures a valid ResetRequest can replay it to force-remove and re-add the member repeatedly, disrupting their session. The relay (or any recipient processing the request) MUST validate:

   - **(a) Signature validity.** Verify the P-256 signature against the key the member's key state lists `Current` in the `#active` role (resolve `member_did`, derive the key state).
   - **(b) Timestamp freshness.** Reject requests where `|relay_clock - timestamp| > 30 seconds`. This matches the freshness window used for `AccessKeyRequest` (§9.17) and `SenderKeyRequest` (§9.16.2) validation. The 30-second window accommodates reasonable clock skew while limiting the replay window.
   - **(c) Nonce uniqueness.** Maintain a deduplication cache of `(member_did, nonce)` pairs with a 60-second TTL. Reject any request whose nonce has been seen within the TTL window. The 60-second TTL is 2x the freshness window, ensuring that even a request accepted at the edge of the 30-second window cannot be replayed after nonce eviction. Cache capacity: bounded at 10,000 entries with oldest-first eviction (matching the `NonceDedup` pattern used for `SenderKeyRequest` in `scp-core/crypto/sender_keys/key_protocol.rs`).

   All three checks MUST pass before the request is forwarded to or processed by an admin. This is the same defense-in-depth pattern used for sender key requests (§9.16.2) and access key requests (§9.17).

2. An online member with `MemberRemove` + `MemberInvite` capabilities (typically admin) processes the reset: (a) removes the offline member's stale leaf node via MLS `remove_member()`, (b) immediately re-adds the member using a fresh KeyPackage via MLS `add_member()`, (c) distributes the new Welcome message via relay.
3. The reconnecting member processes the Welcome, joining the group at the current epoch. They request sender keys for all current members via the pull-based protocol (ADR-007 criterion 4c).
4. The reconnecting member's outbound queue is drained using the new epoch's key schedule.
5. A `MemberReset` event (distinct from `MemberLeft` + `MemberJoined`) is appended to the event log, recording the reset reason, old epoch, new epoch, and the admin who processed it.

**What the reset member loses:**

- Access to messages encrypted in epochs between their last known epoch and the current epoch. Forward secrecy is preserved — old epoch keys were destroyed per ADR-001 criterion 6.
- Any pending governance proposals they initiated while offline (proposals reference specific epochs).
- Queue entries that reference the old epoch (re-queued messages are re-encrypted with the new epoch).

**What the reset member retains:**

- Their identifier.
- Their role in the context (the admin re-assigns the same role during re-add).
- Their event log history up to the last known epoch.
- Context metadata (params, outlets, ceiling) — this is public and queryable via the metadata routing ID (ADR-004).

```rust
pub struct ResetRequest {
    pub context_id: ContextId,
    pub member_did: [u8; 32],
    pub last_known_epoch: u64,
    pub reason: ResetReason,
    /// 16 random bytes (CSPRNG). Prevents replay of captured requests.
    pub nonce: [u8; 16],
    /// Unix timestamp (seconds) when the request was created.
    /// Recipients reject requests older than 30 seconds.
    pub timestamp: u64,
    pub signature: P256Signature,
}

pub enum ResetReason {
    /// Offline duration exceeded the 7-day threshold.
    ExtendedOffline { offline_duration_secs: u64 },
    /// Epoch catch-up failed after exhausting all recovery sources.
    CatchUpFailed { attempted_sources: Vec<String> },
    /// Governance-initiated reset.
    GovernanceAction { proposal_id: String },
}
```

**Amendment (2026-10-18, ADR-066): the reset request is signed once, carried in the reset Commit, and executes once.** Five statements of this section no longer hold.

- *Trigger condition 3 and `ResetReason::GovernanceAction`.* A reset that governance orders is an executed `ResetMember` action (ADR-031 §2), which the Commit's `GovernanceActionExecuted` leaf authorizes. It has no `ResetRequest`, so no request carries a governance reason, and `ResetReason` has two variants, `ExtendedOffline` and `CatchUpFailed`.
- *Reset protocol step 1: the request's fields and preimage.* The request carries `context_id`, `member_did`, `last_known_epoch`, `reset_counter`, `member_since`, `reason`, `nonce`, `timestamp`, and `signature`. The `ResetRequest` preimage of `09-security-model.md` §9.5.2 defines every field's order and encoding, with the separator `"SCP-RESET-REQUEST-V2:"` and `reason` as its text form; it is the one definition, and the struct above is read with those two added fields. The member picks a `reset_counter` greater than every counter it signed during its current membership, and `member_since` is its join point. The relay checks (a) to (c) are unchanged and protect the relay path only.
- *Step 2: what binds the reset.* The member that processes the reset holds both `MemberRemove` and `MemberInvite`, and the one Commit that removes the stale leaf and adds the new one carries the member's request in its governance block (`07-trust-validation-and-capabilities.md` §7.3.1.1). Every receiver accepts the request only when its signature verifies under the member's `#active` key, its `member_since` equals the member's join point, its `reset_counter` is greater than the member's reset counter floor, and its `last_known_epoch` is at most the Commit's sending epoch (step 1.7). Executing the request raises the floor to its `reset_counter`, so the request executes once and every request with an equal or lower counter is void; a member that misses its Welcome signs a new request with a higher counter.
- *Step 5: what the `MemberReset` leaf records.* The leaf records the reset member and the request's `last_known_epoch`, `reset_counter`, and `reason`, each a value the member signed, and its `actor_did` is the member that processed it. It records no new epoch: the Commit that carries it fixes that epoch, and a value the request did not sign would be a field no receiver could check. Every receiver derives the leaf from the Commit's Remove and Add proposals and the carried request, and rejects a Commit whose leaf differs (§7.3.1.1 step 1.6).
- *"What the reset member loses": pending proposals.* The reset is not a departure. Proposals the member made and votes it cast stay pending, with their `anchor_seq` and `proposal_id`, but their signatures stop matching the member's replaced leaf key, so the member re-signs them (`05-contexts.md` §5.9.1). The member keeps its role and join point, and the reset assigns no role, so "the admin re-assigns the same role during re-add" is read as "the re-add leaves the role unchanged".

#### 5. Conflict Resolution

Concurrent offline operations create conflicts when two or more members make incompatible changes while unable to observe each other's actions. SCP resolves conflicts using three principles: (a) the Merkle event log order is authoritative (§9.14), (b) MLS epoch boundaries are synchronization points (§9.8.3), and (c) governance actions are serialized through the admin role (Phase 2 single-admin model).

**Conflict categories and resolution:**

**5a. Concurrent messages (no conflict).** Messages from different senders in the same epoch are ordered by `(epoch, sender_generation_number, timestamp)` per §9.8.3. Messages queued while offline receive fresh sequence numbers at drain time. No conflict — messages are independent.

**5b. Concurrent membership changes.** *Replaced 2026-10-24 by ADR-067.* Two members can each make a Commit for one epoch. Every member processes both, keeps the parent state and both children, and chooses the canonical child by least (rank, cth) (`07-trust-validation-and-capabilities.md` §7.3.1.1 "Concurrent Commits and fork merge"). The losing child's changes return as re-applications that any member carries, and a Commit that no relay stored is rebuilt and sent again at once on the device's new tip.

**5c. Concurrent governance changes.** *Replaced 2026-10-24 by ADR-067.* Governance changes made on two branches of one epoch are merged by ADR-067's G, not frozen: a restrictive-only change never drops, and each other conflicting pair is settled by G's pair table, with `ConcurrentChangeDropped` telling the author which change lost and why. A late sibling that wins at a device after another device deleted the parent splits the group, and both sides detect the split through `ForkNotice` (`09-security-model.md` §9.9.3). The person on one side recovers by sending a `ResetRequest` with reason `CatchUpFailed`, which a member on the other side holding `MemberRemove` and `MemberInvite` executes; the device accepts the Welcome only when the joined group's epoch table shows, at the epoch after the fork, a child that beats its own canonical child on (rank, cth) (`23-sync-and-offline-strategy.md` §23.4.1). No context enters a `GovernanceConflict` state.

**5d. Concurrent sender key rotations.** If a sender rotates their key while a peer is offline, the peer requests the new key on reconnection (Phase 4 of the reconnection protocol). If the sender rotated multiple times, only the current key is needed — intermediate keys are irrelevant (messages encrypted with intermediate keys during the offline period are recovered via relay backfill before the sender key was rotated, or are unrecoverable if the relay expired them).

**5e. Context closure or expiry during offline.** If a context was closed or expired while the member was offline, the reconnecting member discovers this during relay catch-up (the `ContextClosing`, `ContextClosed`, or `ContextExpired` events are in the backfill). The member processes the closure locally, destroys key material per the context's memory scope, and discards any queued messages for that context.

**Amendment (2026-10-18, ADR-066).** A governance Commit carries no `ContextClosing` leaf (ADR-011 amendment in `phase-2.md`). The reconnecting member detects a close when it processes, during epoch catch-up, the Commit whose `GovernanceActionExecuted` leaf records a `CloseContext` action, and detects expiry from the `ttl_deadline` of its governance state (`05-contexts.md` §5.10), never from a `ContextClosing` or `ContextExpired` leaf in the backfill. Step 16 of the scenario below reads the same way.

#### 6. Event Log Reconciliation

The Merkle event log (ADR-011) is the authoritative state record. After relay catch-up and epoch reconciliation, the SDK verifies event log consistency:

1. **Exchange checkpoints.** The reconnecting member generates a `ConsistencyCheckpoint` (ADR-011 criterion 8) from their local log state and sends it to the context. Online members compare and respond with their own checkpoints.
2. **Compare Merkle roots.** If roots match at the same event count, the logs are consistent — no further action.
3. **Behind.** If the reconnecting member's event count is less than the group's (the expected case after offline), the member obtains the missing events through the Phase 1 relay backfill (`SUBSCRIBE` with `since`, ADR-004) — relays are untrusted dumb pipes, so there is no distinct event-range request/response wire message and no peer-supplied proof. The backfilled suffix events are independently authenticated by the normal MLS receive path (per-event signature, sequence ordering, and `prev_hash` chain; spec §23.13). The member then verifies catch-up integrity **locally**: it computes a Merkle consistency proof (RFC 6962 §2.1.2; ADR-011) via `verify_consistency` that its pre-gap last-known checkpoint root is a prefix of the root it reaches by replaying the backfilled events, and gates that reached root (constant-time `ct_eq`) against the single already-authenticated signed `ConsistencyCheckpoint` target root (membership + the P-256 signature, spec §23.12 / §9.9.3). This is the same-log catch-up integrity check, distinct from cross-member equivocation detection (spec §23.7 step 3, §9.9.3). Note: `CommitRangeRequest` (above) is the MLS *Commit* epoch catch-up mechanism (§23.16.2) and is unrelated to event-log event recovery — the two MUST NOT be conflated.
4. **Divergent.** If Merkle roots differ at the same event count, equivocation has occurred (a relay showed different histories to different members, per §9.9.3). The reconnecting member raises a `EquivocationDetected` alert. Resolution follows the relay consistency protocol (§9.9.3): identify the divergent relay, flag it in reliability scoring (ADR-012), and exchange Merkle **inclusion** proofs to attribute the divergence. This is NOT a majority vote — any divergence between any two honest members detects equivocation regardless of how many peers agree with the attacker. **Amendment (2026-10-24, ADR-067):** a divergence at the exact fork point F of an honest fork is not equivocation when the member authenticated that fork itself, by processing two valid children of one parent from different MLS sender leaf indices that append different leaves at F, or by truncating its own log at F on a switch, and confirmed that the other log's leaf F−1 equals its own. That divergence raises no alert and flags no relay. The excuse lapses, and the response above applies, when an all-relay fetch completes without that evidence or when the member deletes the parent state. Every divergence at another position gets the response above (`09-security-model.md` §9.9.3).

#### 7. Multi-Device Coordination

Multi-device sync during offline/online transitions follows the principle from §10.8: "the protocol delivers the same encrypted envelopes to all devices; the client decides how to present them."

Each device independently runs the reconnection protocol. There is no device-to-device coordination at the protocol level. However, the SDK provides hooks for client-layer coordination:

- **Reconnection deduplication.** If multiple devices reconnect simultaneously and all issue MLS Updates, the resulting epoch churn is harmless but wasteful. The SDK emits a `ReconnectionStarted { device_id, context_id }` event to the identity's private state log (§3.7, encrypted, synced across devices). Devices observing another device's reconnection event within a 30-second window defer their own MLS Update to avoid redundant epoch advances.
- **Queue deduplication.** Each queued message includes a content-addressable hash (`payload_hash` from ADR-002). If multiple devices queued the same message (e.g., user typed a message on phone, then opened laptop), the first device to drain delivers the message; the second device recognizes the duplicate `payload_hash` in the event log and discards the queued copy.

### Rationale

**Why three tiers instead of one unified strategy:**

The core tension is between simplicity and correctness. A single strategy that handles all offline durations either (a) is too conservative (always resets, losing message history even for short disconnections) or (b) is too optimistic (always tries sequential catch-up, hanging indefinitely when hundreds of epochs have passed). The three-tier approach matches the strategy to the problem scale:

- Tier 1 (< 4 hours) handles the common case — mobile devices sleeping, brief network outages, moving between WiFi and cellular. This is 95%+ of offline events. Relay buffering covers it with zero special handling beyond the existing connection recovery protocol (ADR-004).
- Tier 2 (4 hours to 7 days) handles the uncommon but important case — devices left offline overnight, travel without connectivity, hardware issues. Welcome-based fast-forward provides a clean recovery at the cost of losing access to messages encrypted in the skipped epoch range. This is an acceptable trade-off: the messages exist in the relay (if not expired) but cannot be decrypted due to forward secrecy. The member is informed of the gap.
- Tier 3 (> 7 days) handles the rare but catastrophic case — extended disconnection where relays have expired all buffered messages and no peer can reconstruct the Commit chain. Group state reset is the only option. This is the "hardest problem" case, and the answer is: treat it as a re-join, preserving identity and role but accepting the gap.

**Why 100-epoch catch-up limit:**

Sequential Commit processing is O(N) in the number of missed epochs. Each Commit requires tree ratcheting (MLS tree-based key management). At 100 Commits, this is several seconds of processing on mobile hardware. Beyond 100, the user experience degrades unacceptably, and the probability of encountering a corrupted or missing Commit in the chain increases. The Welcome-based fast-forward is O(1) — processing a single Welcome message regardless of how many epochs were missed.

**Why group reset is per-member, not group-wide:**

A group-wide reset would destroy all members' current key material and force everyone to re-establish. This is catastrophic for a group where only one member went offline. Per-member reset (leave + re-join) affects only the offline member's key state while the rest of the group continues uninterrupted.

**Why queued messages are not MLS-encrypted until drain:**

The MLS epoch may advance while the member is offline. Encrypting at queue time would bind the message to a stale epoch, making it undecryptable by members who have advanced. By deferring MLS encryption to drain time, queued messages are encrypted with the current (post-catch-up) epoch, ensuring all current members can decrypt them.

**Conflict resolution — why Merkle log order is authoritative:**

The alternative approaches (vector clocks, CRDTs, consensus protocols) all add complexity that SCP's architecture does not need. SCP's event log already provides a total order via the hash chain. The single-admin governance model (Phase 2) eliminates most governance conflicts by construction. The remaining conflicts (concurrent membership proposals) are resolved by MLS's natural serialization through Commits. Merkle log order is the tie-breaker because it is already the system of record — no new mechanism is needed.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (reconnection timers, concurrent relay catch-up, queue drain)
- **Crate:** `scp-core`
- **Module:** `scp-core/sync/`
- **Persistence:** Via `ProtocolRepository` (§17.4) for queue state, last-seen timestamps, and catch-up progress. Key conventions:
  - `queue/{context_id}/{seq:020d}` — queued outbound messages
  - `sync/{context_id}/last_relay_contact` — last successful relay interaction timestamp, as local Unix seconds. The supervisor holds the one store of the value, derived from the same storage handle as its saga journal and MLS storage, and every reader and writer goes through it. The member's first state writes it: creating a context, joining by Welcome, and importing a context each write the current time, then the context's first snapshot, before the actor starts and before the operation returns, so no stored snapshot lacks a value. An operation that fails or times out after either write starts no actor and puts back what it replaced: the value and snapshot stored before it began, or no record where none was stored. It removes a snapshot it wrote before the value it wrote, and keeps the value when removing the snapshot fails. A create whose context id names a running context fails before it writes either record. After that, three paths advance it: a full reconnection after it clears `needs_reconnect`, a push-wake pull after Phases 2 and 4 have fed every blob of the context's Phase 1 buffer to the actor, and a live subscription after the actor accepts a delivered envelope. Restoring a context from local persistence writes nothing, because the stored value measures the time the member was offline. A full reconnection reads it to classify the offline tier; no caller supplies the value. A Phase 1 query that starts from a first contact does not reach blobs the relay stored before that contact: an application message sent at the Welcome epoch after the add-Commit and before the joiner processed the Welcome, and a message sent between an export and its import. Closing that gap needs a timestamp the member can trust, such as a signed time in the invitation bundle or the context export; that is an open question. (Amended 2026-10-23; this item previously named no writer and no reader, and then named no first write.)
  - `sync/{context_id}/catch_up_state` — in-progress catch-up state (survives process restart)

### Dependencies

- **ADR-001 (MLS):** MLS epoch processing, Commit handling, Welcome message processing, Update proposal generation. The epoch catch-up and group reset protocols are built directly on MLS group operations.
- **ADR-004 (Native Relay):** Relay `SUBSCRIBE` with `since` parameter for backfill. Relay blob TTL determines the maximum Tier 1 offline duration. Connection recovery with exponential backoff (1s to 30s cap).
- **ADR-007 (Sender Keys):** Sender key re-acquisition via pull-based protocol after missed `SenderKeyEpochAdvance` events.
- **ADR-008 (Context Lifecycle):** Context state machine determines valid operations during catch-up. Context closure/expiry events discovered during reconnection trigger local cleanup.
- **ADR-011 (Event Log):** Merkle tree consistency checkpoints for state reconciliation. Inclusion proofs for verifying recovered events. Event log as authoritative ordering for conflict resolution.
- **ADR-012 (Multi-Transport):** Multi-relay subscription recovery. Relay reliability scoring — degraded relays that failed to retain messages during offline period are penalized.
- **ProtocolRepository (§17.4):** Queue persistence, sync state persistence, event log range queries for catch-up.

### Acceptance Criteria

1. **`OutboundQueue` struct and operations:**

```rust
pub struct OutboundQueue {
    store: Arc<ProtocolRepository>,
    per_context_limit: usize,
    total_limit: usize,
}

impl OutboundQueue {
    pub fn new(store: Arc<ProtocolRepository>) -> Self;
    pub async fn enqueue(&self, msg: QueuedMessage) -> Result<(), QueueError>;
    pub async fn drain(&self, context_id: &ContextId, mls_group: &mut MlsGroup) -> Result<Vec<OuterEnvelope>, QueueError>;
    pub async fn discard_expired(&self, context_id: &ContextId, max_age_secs: u64) -> Result<u64, QueueError>;
    pub async fn discard_context(&self, context_id: &ContextId) -> Result<u64, QueueError>;
    pub async fn queue_depth(&self, context_id: &ContextId) -> Result<u64, QueueError>;
    pub async fn total_depth(&self) -> Result<u64, QueueError>;
}
```

   - `enqueue` stores a `QueuedMessage` in `ProtocolRepository`. Returns `QueueError::ContextFull` or `QueueError::TotalFull` if limits are reached (oldest messages dropped).
   - `drain` MLS-encrypts each queued message with the current epoch and returns sealed outer envelopes ready for transport. Drains in queue order. Removes drained entries from storage.
   - `discard_expired` removes entries older than `max_age_secs`. Returns count discarded.
   - `discard_context` removes all entries for a context (used on context closure/expiry). Returns count discarded.

2. **`ReconnectionCoordinator` struct:**

```rust
pub struct ReconnectionCoordinator {
    context_manager: Arc<ContextManager>,
    transport_manager: Arc<TransportManager>,
    queue: Arc<OutboundQueue>,
    store: Arc<ProtocolRepository>,
}

impl ReconnectionCoordinator {
    pub async fn on_reconnect(&self) -> ReconnectionReport;
}

pub struct ReconnectionReport {
    pub contexts_synced: Vec<ContextSyncResult>,
    pub messages_drained: u64,
    pub messages_discarded: u64,
    pub total_duration_ms: u64,
}

pub struct ContextSyncResult {
    pub context_id: ContextId,
    pub tier: OfflineTier,
    pub epochs_caught_up: u64,
    pub events_recovered: u64,
    pub messages_unrecoverable: u64,
    pub outcome: SyncOutcome,
}

pub enum OfflineTier {
    Short,     // < 4 hours
    Extended,  // 4 hours to 7 days
    Long,      // > 7 days
}

pub enum SyncOutcome {
    FullyCaughtUp,
    FastForwarded { skipped_epochs: u64 },
    Reset,
    ContextGone,  // Context was closed/expired while offline
    Failed { reason: String },
}
```

   - `on_reconnect` executes the six-phase reconnection protocol for all active contexts. Returns a report detailing per-context sync results.
   - Each context is synced concurrently (tokio tasks), with a 120-second overall timeout. Contexts that timeout are marked as `Failed`.

> **ADR-029 Addendum — Reconnection driver location after the ADR-049 actor refactor.** ADR-049 replaced `ContextManager` with a per-context actor (state behind a mailbox; the actor's `ContextTransportProvider` is send-only). Buffered-message retrieval (relay SUBSCRIBE/QUERY-since) is owned by `TransportManager` at the FFI/SDK relay-client layer. Therefore the reconnection driver — the concrete impl of `SyncPhaseDriver` (Tier 1), `SnapshotTransport` (Tier 2), `ResetTransport` (Tier 3) — is constructed and driven at the FFI/SDK layer (same layer as `context_subscribe`). It reads relay-buffered messages/snapshots from `TransportManager`, reaches actor-owned state (MLS epoch, Commit/Welcome processing, checkpoint build/compare, event-log, queue drain) via `Supervisor` commands/queries — never by widening `ContextTransportProvider` — and consumes `EpochState.needs_reconnect` (spec §23.11). `ReconnectionCoordinator` no longer holds `Arc<ContextManager>`/`Arc<TransportManager>`; it is parameterized on a `SyncPhaseDriver` supplied by the relay-client layer. The shipped driver departs from the six-phase protocol (§2) and the tier engines in six ways. Phase 1 issues QUERY with `since` instead of re-issuing SUBSCRIBE. Phase 2 needs a target epoch, but the driver records no epoch on a retrieved message, so the coordinator reports the context `Failed` ("epoch state unavailable") before Phase 3; GitHub issue #3051 tracks this. Phase 4 re-feeds the Phase 1 buffer to the actor and publishes no `SenderKeyRequest`. Phase 5 publishes nothing from the driver: the driver asks the Supervisor for the Update, and the actor merges the Update Commit and publishes it through its Commit broadcast and retry queue, so a publish that fails keeps the Commit queued and fails the context (§2 Phase 5). (Amended 2026-10-23; the driver previously published the Commit the actor returned, and reported the Update issued when that publish failed.) Phase 6 drains nothing, because no production code writes to the outbound queue. The Tier 2 engine reports a context caught up when a relay snapshot exists, without applying the snapshot; GitHub issue #3055 tracks this. The Tier 3 engine fails every context at once with `ReJoinUnavailable` and leaves `needs_reconnect` set, because no shipped path can complete a re-join: none publishes the member's `ResetRequest`, none has an admin process one, and none applies a re-add Welcome to a context the member already holds, which needs the `StateReconstructor` of §5; GitHub issue #3058 tracks the re-join. (Amended 2026-10-23; the engine previously polled the relay for the Welcome window and reported a reset whenever the local MLS epoch advanced, which an ordinary Commit also does.) A context with no stored `last_relay_contact` is reported `Failed` with the reason that no relay contact is recorded, and keeps `needs_reconnect` set: every path that gives a member a context writes the value, so a missing value is a store fault, and no tier is inferred from it. A context whose stored value cannot be read is reported `Failed` the same way, with the reason that the read failed. Either failure ends only that context; the full reconnection classifies and reconnects every other context. A full reconnection writes no value for a context it did not classify, so it does not heal a missing value; a push-wake pull does, because it queries that context from `since` 0 (§2 push-wake pull mode, step 4) and writes the value once its pull completes (step 6). (Amended 2026-10-23; a missing value previously classified as Tier 3, because the classification read it as 0.) Every full reconnection that ends a context in `FullyCaughtUp`, `FastForwarded` or `Reset` sends that context's queued sender-key answers, which a push-wake pull leaves queued (§2 push-wake pull mode, steps 4 and 5), and reads each context's `last_relay_contact` from the store. (Amended 2026-10-23; this sentence previously read "The six-phase protocol (§2) and tier engines are behaviorally unchanged; only the ownership/wiring location is restated.") This supersedes the field list in ADR-029 §2 AC 2.

3. **`epoch_catch_up(context_id, local_epoch, target_epoch) -> Result<CatchUpStatus, SyncError>`**

   - Implements the three-source epoch catch-up: relay backfill, peer request, Welcome-based fast-forward.
   - Processes at most 100 sequential Commits with 5-second per-Commit timeout.
   - Falls back to Welcome-based fast-forward if sequential processing fails or the gap exceeds 100 epochs.
   - Returns `CatchUpStatus` indicating the outcome.

4. **`request_group_reset(context_id, reason) -> Result<(), SyncError>`**

   - Publishes a `ResetRequest` to the relay.
   - Waits for a Welcome message (60-second timeout).
   - On receipt, processes the Welcome, re-acquires sender keys, drains the queue.
   - Appends `MemberReset` event to the local event log.

5. **`sync_event_log(context_id) -> Result<EventSyncResult, SyncError>`**

   - Exchanges `ConsistencyCheckpoint` with online members (signature-verified per spec §23.12).
   - If behind, recovers missing events through the Phase 1 relay backfill (`SUBSCRIBE` with `since`, ADR-004) — no peer-supplied event-range wire message.
   - Authenticates each backfilled event via the normal MLS receive path (signature, sequence ordering, `prev_hash` chain; spec §23.13), then verifies catch-up integrity locally with a Merkle consistency proof (`verify_consistency`) gated against the signed `ConsistencyCheckpoint` target root.
   - Raises `EquivocationDetected` if Merkle roots diverge at the same event count (cross-member; spec §9.9.3).

6. **Offline tier classification:**

```rust
pub fn classify_offline_duration(last_relay_contact: u64, now: u64) -> OfflineTier {
    let duration_secs = now.saturating_sub(last_relay_contact);
    match duration_secs {
        0..=14_400 => OfflineTier::Short,          // < 4 hours
        14_401..=604_800 => OfflineTier::Extended,  // 4 hours to 7 days
        _ => OfflineTier::Long,                     // > 7 days
    }
}
```

7. **Event types added to `EventType` enum (ADR-011):**

```rust
// Additions to EventType in scp-core/event_log/
MemberReset {
    member_did: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    reason: ResetReason,
    processed_by: [u8; 32],
},
QueueDrained {
    member_did: [u8; 32],
    message_count: u64,
    discarded_count: u64,
},
```

8. **Integration test (exercises all tiers):**

```
1. Alice and Bob create identities and a context (ADR-008).
2. Alice and Bob exchange messages (verify baseline).

--- Tier 1 test ---
3. Bob goes offline (transport disconnected).
4. Alice sends 5 messages while Bob is offline.
5. Bob reconnects. Relay backfill delivers all 5 messages.
   Bob processes MLS catch-up (if any epoch advanced). Bob's event log syncs.

--- Tier 2 test ---
6. Bob goes offline again. Simulate 50 epoch advances (members joining/leaving/updating).
7. Bob reconnects. Sequential catch-up processes all 50 Commits.
   Bob's event log catches up. Bob drains any queued messages.

8. Bob goes offline again. Simulate 150 epoch advances (exceeds 100-Commit limit).
9. Bob reconnects. Sequential catch-up processes first 100, then falls back to
   Welcome-based fast-forward. Bob re-joins at current epoch.
   Bob's event log records the fast-forward gap.

--- Tier 3 test ---
10. Bob goes offline. Simulate relay expiry of all buffered messages (TTL elapsed)
    AND epoch gap > 100 AND no peer can provide Commits.
11. Bob reconnects. Tier classification = Long. Bob issues ResetRequest.
    Alice (admin) processes reset: removes Bob, re-adds Bob with fresh Welcome.
    Bob joins at current epoch, re-acquires sender keys, drains queue.
    Event log records MemberReset.

--- Conflict resolution test ---
12. Bob and Alice both go offline simultaneously.
13. Both queue governance-irrelevant messages.
14. Both reconnect. Both drain queues. Messages interleave by timestamp.
    No conflict — messages from different senders are independent.

--- Context closure while offline ---
15. Bob goes offline. Alice closes the context.
16. Bob reconnects. Relay backfill contains ContextClosing + ContextClosed events.
    Bob processes closure, discards queued messages for that context, destroys keys.
```

### Scope

**Files (~5-7):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `OfflineTier`, tier classification, re-exports |
| `queue.rs` | `OutboundQueue`, `QueuedMessage`, queue persistence, drain logic |
| `reconnect.rs` | `ReconnectionCoordinator`, six-phase reconnection protocol, `ReconnectionReport` |
| `epoch_catch_up.rs` | `EpochCatchUpState`, three-source catch-up, `CommitRangeRequest`/`Response`, Welcome-based fast-forward |
| `reset.rs` | `ResetRequest`, `ResetReason`, group state reset protocol, `MemberReset` event |
| `event_sync.rs` | Merkle root comparison, local consistency-proof verification (`verify_consistency`) of relay-backfilled events against the signed `ConsistencyCheckpoint` target, equivocation detection |
| `conflict.rs` | Conflict classification, resolution strategies, governance conflict handling |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers.

---

## ADR-030: Event Log Pruning and Checkpointing

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling).

**Amendment (2026-09-10 — the checkpoint signature is ECDSA on P-256).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. The checkpoint signature this ADR defines is an ECDSA signature on P-256 over the same `SHA-256(context_id || checkpoint_seq || …)` preimage, and both `signature` fields carry the type `P256Signature`. The pruning boundary, the checkpoint cadence, and the retention rule are untouched.

### Context

Every SCP context maintains an append-only Merkle event log (ADR-011) that records all protocol events — membership changes, governance actions, outlet invocations, messages, role assignments, block notifications, and consistency checkpoints. The log is the foundation for participation validation (§7.3.1), equivocation detection (§9.9.3), and the trust model's Layer 2 (verifiable participation records, §7.3.2). Its append-only structure is what makes claims about context history verifiable rather than trust-dependent.

The problem is that event logs grow without bound. A long-lived context with active participants accumulates millions of events. Each event is a leaf in the Merkle tree, with interior nodes stored for proof generation (ADR-011, key convention: `context/{context_id}/event/{seq:020d}` for events, `context/{context_id}/event_tree/{level}/{index}` for tree nodes — §17.3). On mobile devices with constrained storage, maintaining full history for every active context is unsustainable. A context with 1 million events at ~200 bytes per event plus Merkle tree overhead consumes hundreds of megabytes for a single context.

The core tension is that pruning contradicts the append-only property that makes the log verifiable. Deleting old events means their content cannot be independently re-verified. The protocol must balance verifiability (full history provable) with storage reality (unbounded growth is not viable on resource-constrained clients). The solution is checkpointing: periodically capturing a signed snapshot of the full context state anchored to a specific Merkle root, then pruning events behind the checkpoint while retaining enough Merkle tree structure to prove that pruned events were once part of the log.

### Scope

**What this ADR covers:**

- Pruning strategies: time-based, size-based, and event-type-based criteria for removing old events from local storage.
- Checkpoint creation: full context state snapshots anchored to a Merkle root at a specific sequence number.
- State reconstruction: loading a checkpoint and replaying post-checkpoint events to recover current state.
- Merkle proof interaction: how pruning affects proof validity and how "pruned proofs" work.
- Governance of pruning policies: how contexts configure and enforce pruning rules.
- Storage key management: how pruning interacts with the `ProtocolRepository` key convention (§17.3).

**What this ADR does NOT cover:**

- Offline/sync strategy for reconnecting members (ADR-029).
- Multi-admin governance models (ADR-031).
- Content storage and retrieval (app-layer, §10.6 — event logs store protocol events and content hashes, not content itself).
- Relay-side storage management (relays manage blob TTL independently per ADR-004).

### Decision

Implement a checkpoint-and-prune system in `scp-core/event_log/` that creates signed state snapshots at configurable intervals and allows pruning of events behind checkpoints according to per-context policy. Pruning removes event payloads and optionally Merkle tree leaf data from local storage, but retains the Merkle tree's interior nodes so that inclusion proofs for pruned events remain verifiable against the checkpoint's Merkle root. The pruning policy is a context parameter set at creation or modified via governance, with a protocol-enforced minimum retention period of 30 days.

#### 1. Checkpoint Structure

A checkpoint captures the complete, deterministic context state at a specific event log sequence number. Checkpoints are published to the event log as a special `Checkpoint` event type so that all members observe and can verify them.

**Amendment (2026-10-20, ADR-066 decision 24): a Commit carries the checkpoint.** In an encrypted context a checkpoint reaches the log as a `Checkpoint` leaf (`EventType` tag 79) that a checkpoint Commit carries, and `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6 derives it. The leaf's payload, `CheckpointPayload`, holds every field below except `context_id`, `creator_did`, and `state_snapshot`: it holds the snapshot's digest, `state_snapshot_hash`, in place of the snapshot, and the leaf's `actor_did`, the committer, is `creator_did`. Every member that processes the Commit recomputes `merkle_root`, `last_event_hash`, and the snapshot digest from its own state, checks the quorum and every signature, and rejects the Commit on any mismatch, so every live member validates the checkpoint, not only its signers. A Broadcast context has no MLS group and no Commit, and its checkpoint stays the durable artifact this section describes.

```rust
pub struct Checkpoint {
    /// The context this checkpoint belongs to.
    pub context_id: ContextId,
    /// The event log sequence number this checkpoint covers (inclusive).
    /// All events from 0 through checkpoint_seq are summarized.
    pub checkpoint_seq: u64,
    /// The Merkle root of the event log at checkpoint_seq.
    pub merkle_root: [u8; 32],
    /// The total number of events in the log at checkpoint time.
    pub event_count: u64,
    /// The hash of the last event at checkpoint_seq (hash chain tip).
    pub last_event_hash: [u8; 32],
    /// Full context state snapshot — deterministically serialized.
    pub state_snapshot: ContextStateSnapshot,
    /// The identifier of the checkpoint creator.
    pub creator_did: DID,
    /// The creator's key-state head when it signed (09 §9.7.1
    /// log-anchored row; checkpoint signature preimage amendment below).
    pub creator_key_state_head: [u8; 32],
    /// Unix timestamp of checkpoint creation.
    pub created_at: u64,
    /// P-256 signature over the 09 §9.5.1 canonical hash under
    /// "SCP-STATE-CHECKPOINT-V1:" (checkpoint signature preimage
    /// amendment below).
    pub signature: P256Signature,
    /// Optional governance quorum signatures (for multi-admin contexts, ADR-031).
    /// In single-admin contexts, this is empty and creator_did must be the admin.
    pub cosignatures: Vec<CosignedCheckpoint>,
}

pub struct CosignedCheckpoint {
    pub signer_did: DID,
    /// The cosigner's key-state head when it signed.
    pub key_state_head: [u8; 32],
    pub signature: P256Signature,
}

pub struct ContextStateSnapshot {
    /// Current membership: identifier -> role mapping.
    pub membership: Vec<(DID, RoleName)>,
    /// Current capability ceiling.
    pub capability_ceiling: Vec<Capability>,
    /// Ceiling policy (locked, governed, admin-only).
    pub ceiling_policy: CeilingPolicy,
    /// Governance model and configuration (ADR-031 §2).
    pub governance: GovernanceModelConfig,
    /// Memory scope.
    pub memory_scope: MemoryScope,
    /// ADR-066: the TTL deadline in Unix seconds (None if no TTL or
    /// if promoted). Replaces the relative `ttl_remaining_secs`.
    pub ttl_deadline_unix: Option<u64>,
    /// ADR-066 decision 31: the registered outlets' headers (spec 05
    /// §5.4.1), which commit-ordered outlet leaves set.
    pub outlets: Vec<OutletRegistrationHeader>,
    /// The MLS epoch (ADR-066 decision 24(h)); in a Broadcast context,
    /// the authors group's (ADR-066 decision 38).
    pub mls_epoch: u64,
    /// Context mode (Encrypted or Broadcast).
    pub context_mode: ContextMode,
    /// Parent context IDs (empty for root contexts).
    pub parent_context_ids: Vec<ContextId>,
    /// ADR-066 decision 28: every revoked UCAN token CID, in base32lower
    /// text form, which `TokenRevoked` leaves add.
    pub ucan_revocations: Vec<String>,
    /// ADR-066: each member's join point, the `sequence` of the
    /// `MemberJoined` leaf that added it when it was not a member.
    /// A `MemberReset` leaf leaves it unchanged.
    pub member_since: Vec<(DID, u64)>,
    /// ADR-066: per conflict key, the `sequence` of the latest
    /// `GovernanceActionExecuted` leaf whose action holds the key.
    pub governance_change_seqs: Vec<(GovernanceConflictKey, u64)>,
    /// ADR-066 and spec 05 §5.9 invariant 2: every executed proposal ID.
    pub executed_proposals: Vec<[u8; 32]>,
    /// ADR-066: per member, the highest `reset_counter` of a reset
    /// request executed during its current membership; a reset request
    /// is accepted only with a greater counter. 0 for a member no
    /// requested reset has executed for.
    pub reset_counter_floors: Vec<(DID, u64)>,
    /// ADR-066 decisions 20 and 21: per proposer and recorded action
    /// kind, the recorded proposal ID and the `sequence` of the
    /// `GovernanceProposalRecorded` leaf that recorded it.
    pub recorded_proposals: Vec<(DID, RecordedProposalKind, [u8; 32], u64)>,
    /// ADR-066 decision 22: the economic policy in effect (spec 19
    /// §19.3), None when the context has none.
    pub economic_policy: Option<EconomicPolicy>,
    /// ADR-066 decision 38: the root over `read_bans`, each leaf
    /// SHA-256(0x00 || identifier text), and its count.
    pub read_ban_root: [u8; 32],
    pub read_ban_count: u64,
}
```

**Amendment (2026-10-21, ADR-066 decision 38): broadcast contexts.** A broadcast context's owner and authors form an MLS group (`05-contexts.md` §5.14.13), so `mls_epoch` is a `u64` in every context, the authors group's epoch in a broadcast context. `read_ban_root` is the RFC 6962 Merkle root over the identifiers of `read_bans` (`07-trust-validation-and-capabilities.md` §7.3.1.1), sorted in ascending order of their 56-byte text forms, with each leaf hash SHA-256(0x00 ‖ the text form), and SHA-256 of the empty string for an empty set, which every encrypted context has; `read_ban_count` is the set size. The snapshot holds the root, not the set, because no rule bounds how many subscribers a broadcast context bans. Whoever sends the snapshot to a joining author or a rebuilding member sends the full set beside it, and the receiver checks it against the root and the count before it adopts the snapshot. serialize(`state_snapshot`) writes the root as a 32-byte binary and the count as an unsigned integer. The snapshot carries nothing about subscribers, whose registrations each author keeps in its own registry (`05-contexts.md` §5.14.3).

**Amendment (2026-10-18, ADR-066): snapshot types.** `governance` is ADR-031 §2's `GovernanceModelConfig`, the type the ADR-031 §2 amendment and ADR-066 decision 17 name; no ADR defines the `GovernanceConfig` this struct named before. Every identifier the snapshot holds (the `membership`, `member_since`, and `reset_counter_floors` keys) is a `DID` in its 56-byte text form (`03-identity.md` §3.1), as ADR-031's identifier amendment states for that ADR's types; it was `[u8; 32]`. The canonical encoding below writes each such identifier as a `str 8` of its 56 bytes. `Checkpoint.creator_did` and `CosignedCheckpoint.signer_did` are `DID`s in the same text form; they were `[u8; 32]`. The checkpoint signature's input takes the `09-security-model.md` §9.5.1 form that the checkpoint signature preimage amendment below states, and each cosigner signs that form with its own `key_state_head` (ADR-031, checkpoint cosignatures). Neither `creator_did` nor `signer_did` is an input; a verifier resolves the signing key from `creator_did`, or from a cosignature's `signer_did`. serialize(`state_snapshot`) changes too: it now writes every identifier in the snapshot as its 56-byte text form where it wrote 32 bytes, and it includes `recorded_proposals`, so a checkpoint over the same state signs different bytes than it did under the old types. `25-test-vectors.md` prints no vector of this signature: Vector 33 pins the §23.16.1 consistency checkpoint, a different structure, and pins no signature.

**Amendment (2026-10-17, ADR-066).** The snapshot carries the governance state a receiver reads when it authorizes a governance Commit (`07-trust-validation-and-capabilities.md` §7.3.1.1): `member_since`, `governance_change_seqs`, `executed_proposals`, `reset_counter_floors`, and `ttl_deadline_unix`. Without them, a member rebuilt from a checkpoint could not compute a member's join point, the conflict check, proposal replay protection, or reset-request replay protection, or the `old_deadline_unix` of an `ExtendTtl` Commit's `TtlExtended` leaf, because the leaves those values come from may lie before the checkpoint. `GovernanceConflictKey` is one of `role:X`, `read:X`, `write:X`, or `ceiling`, where X is a member's identifier, as §7.3.1.1 defines. Replaying a post-checkpoint leaf updates the first three fields from the leaf's own `sequence`, and `reset_counter_floors` from checked leaf values only: a `MemberJoined` leaf sets the joining member's floor to 0, a `MemberReset` leaf with a `reset_counter` sets the member's floor to that counter, which step 1.7 checked against the signed request, a `MemberReset` leaf that a `ResetMember` action derived leaves it unchanged, and a `MemberLeft` leaf removes the member's entry. A `TtlExtended` leaf sets `ttl_deadline_unix` to its `new_deadline_unix`, and the `GovernanceActionExecuted` leaf of a `PromoteContext` action sets it to nil. A member adopts the snapshot of the checkpoint it rebuilds from, the latest `Checkpoint` leaf included under the committed log head (ADR-066 decision 27), only when its `ttl_deadline_unix` equals the deadline the latest such leaf at or before that checkpoint gives, or the creation timestamp plus `ttl` when there is none (`05-contexts.md` §5.10), so the checkpoint quorum cannot extend or remove the TTL. A member adopts only the latest checkpoint and walks no earlier one (the adoption paragraph below), so the adopted checkpoint is the only one checked against a TTL leaf. Pruning invariant 6 keeps the leaf that the adopted checkpoint's check needs. **Amendment (2026-10-18, ADR-066):** `ttl_deadline_unix` replaces `ttl_remaining_secs`, a relative value that differed with the time each member serialized it, and it is the absolute deadline every member holds (`05-contexts.md` §5.10). A `MemberReset` leaf, which records an ADR-029 Tier 3 reset or a Tier 2 Welcome-based fast-forward of a member that stays in the group, changes none of the first three: a reset is not a departure, and the member keeps its join point and every conflict key that names it. **Amendment (2026-10-18, ADR-066):** the field was `reset_floors`, an epoch floor that a request's `last_known_epoch` had to exceed and that the reset Commit's epoch set. It is replaced by the counter floor, because the epoch that floor read was a leaf value no request signed (ADR-066 decision 12).

The five fields follow the canonical MessagePack encoding the snapshot already uses, with integers in their shortest MessagePack form, and each list is sorted so that every member serializes the same state to the same bytes:

- `member_since` is an array of two-element arrays `[identifier, sequence]`, where `identifier` is the member's identifier in its 56-byte text form as a `str 8` and `sequence` a uint, sorted by `identifier` as unsigned bytes in ascending order. A member appears once.
- `GovernanceConflictKey` encodes as a two-element array `[tag, identifier]`: `tag` is a uint, 0 for `role`, 1 for `read`, 2 for `write`, 3 for `ceiling`; `identifier` is the member's identifier in its 56-byte text form as a `str 8` when `tag` is 0, 1, or 2, and `nil` when `tag` is 3. A key with a tag of 4 or above, a tag of 0 to 2 with anything but a 56-byte `str 8` identifier, or a tag of 3 with anything but `nil`, is malformed. `governance_change_seqs` is an array of `[key, sequence]`, sorted by the encoded bytes of `key` in ascending order. A key appears once.
- `executed_proposals` is an array of 32-byte `bin 8` proposal IDs, sorted as unsigned bytes in ascending order, without duplicates.
- `reset_counter_floors` encodes as `member_since` does, an array of `[identifier, counter]` sorted by `identifier`, with `counter` a uint.
- `ttl_deadline_unix` is a uint, or nil for a context with no TTL or a promoted one.

A receiver that deserializes a snapshot whose lists are unsorted or hold a duplicate, or whose `member_since` or `reset_counter_floors` identifiers are not exactly the identifiers in `membership`, rejects it as malformed.

**Amendment (2026-10-19, ADR-066 decisions 20 and 21): recorded proposals.** The snapshot also carries `recorded_proposals`, the governance state `07-trust-validation-and-capabilities.md` §7.3.1.1 names: one entry per member and recorded action kind with a recorded proposal, holding the proposer's identifier, the kind, the `proposal_id`, and the `sequence` of the `GovernanceProposalRecorded` leaf that recorded it (`05-contexts.md` §5.9 invariant 5). `RecordedProposalKind` is the enum of the two recorded action kinds, `ModifyCeiling` and `SetEconomicPolicy`. Without the field, a member rebuilt from a checkpoint taken between a recording Commit and its executing Commit would reject the executing Commit, which every live member accepts. Replaying a post-checkpoint leaf updates it as §7.3.1.1 states: a `GovernanceProposalRecorded` leaf sets its proposer's entry of its kind, replacing any earlier entry of that kind; the `GovernanceActionExecuted` leaf of a recorded action removes the entry it executes, and that of a `ModifyCeiling` also removes every other `ModifyCeiling` entry; a `MemberLeft` leaf removes both of its subject's entries. It encodes as an array of four-element arrays `[identifier, kind, proposal_id, sequence]`, with `identifier` a 56-byte `str 8`, `kind` the variant name as a string (`ModifyCeiling` or `SetEconomicPolicy`), `proposal_id` a 32-byte `bin 8`, and `sequence` a uint, sorted by `identifier` and then by `kind`, each as unsigned bytes in ascending order. A snapshot whose list is unsorted, names one identifier and kind twice, names another kind, or names an identifier not in `membership` is malformed. **Amendment (2026-10-20, ADR-066 decision 27).** A member adopts the field with the rest of the snapshot, by the checkpoint leaf's inclusion under the committed log head, and checks no entry against the leaf it names: every member computed the set from its own state and checked the snapshot's digest before it merged the checkpoint Commit, so a checkpoint quorum cannot write in a proposal no Commit recorded. Pruning invariant 7, which kept each named leaf for the check this amendment removes, is withdrawn.

**Amendment (2026-10-20, ADR-066 decision 22): the economic policy in effect.** The snapshot also carries `economic_policy`, the governance state `07-trust-validation-and-capabilities.md` §7.3.1.1 names: the `19-economic-governance.md` §19.3 `EconomicPolicy` in effect at the checkpoint, or none. It is the genesis `economic_policy` of the `ContextParams` that the creator's invitation-bundle signature authenticates (`05-contexts.md` §5.12.3.1), until a Commit executes a `SetEconomicPolicy`; it is then the `policy` of the action that the latest such Commit's `GovernanceActionExecuted` leaf records. Without the field, a member rebuilt from a checkpoint after the `SetEconomicPolicy` leaf was pruned would hold the genesis policy while every live member holds the executed one, the divergence ADR-066 decision 19 rejected. Replaying a post-checkpoint leaf updates it: the `GovernanceActionExecuted` leaf of a `SetEconomicPolicy` sets it to that action's `policy`. It encodes as a `bin` holding the RFC 8785 bytes of the `EconomicPolicy` object, its identifiers in text form, or as nil when the context has no economic policy. The committed `0xFF02` extension's `economic_policy_hash` is the SHA-256 of that encoding, or of the 4 bytes `null` when it is nil (`05-contexts.md` §5.13.3 "Economic policy" and rule 12). A member that rebuilds from a checkpoint replays the leaves after it and grants no right until the policy it ends with hashes to the committed value, and an importer or restorer checks the snapshot's field against it. A checkpoint quorum therefore cannot write in a policy no Commit executed, change `locked`, or skip the recording epoch of ADR-066 decision 21, because every member validated the Commit that set the committed hash.

**Amendment (2026-10-20, ADR-066 decisions 28, 30, and 31): outlets, revocations, and no blocks.** The snapshot holds no `blocks`: Alec ruled on 2026-10-20 that in-context blocks leave the snapshot, and a block stays a per-relationship record no Commit orders (`09-security-model.md` §9.16.3 step 7, decision 30). `outlets` and `ucan_revocations` are governance state that commit-ordered leaves set (`07-trust-validation-and-capabilities.md` §7.3.1.1): an `OutletRegistered` leaf adds its header, an `OutletUpdated` leaf replaces the header of its `outlet_id`, an `OutletRemoved` leaf removes its outlet, and a `TokenRevoked` leaf adds its CID. Replaying a post-checkpoint leaf applies the same change. `outlets` encodes as an array of `OutletRegistrationHeader` positional arrays (`05-contexts.md` §5.4.1), sorted by `outlet_id` as unsigned bytes in ascending order, and `ucan_revocations` as an array of `str` CIDs in `base32lower` multibase text form, sorted as unsigned bytes in ascending order. A snapshot with either list unsorted or holding a duplicate `outlet_id` or CID is malformed. Every signer computes both from leaves every member holds, so two signers at one leaf count compute the same digest.

**Amendment (2026-10-19, ADR-066): checkpoint signature preimage.** The checkpoint signature and every cosignature are P-256 signatures (`09-security-model.md` §9.5) over the §9.5.1 canonical hash under the domain separator `"SCP-STATE-CHECKPOINT-V1:"` (§9.18.2): SHA-256(`"SCP-STATE-CHECKPOINT-V1:"` ‖ BE32(len(`context_id`)) ‖ `context_id` ‖ BE64(`checkpoint_seq`) ‖ `merkle_root` ‖ BE64(`event_count`) ‖ `last_event_hash` ‖ SHA-256(serialize(`state_snapshot`)) ‖ BE64(`created_at`) ‖ `key_state_head`), where `context_id` is the UTF-8 bytes of its text form, `key_state_head` is the signer's own (next amendment), `merkle_root`, `last_event_hash`, the snapshot digest, and `key_state_head` are fixed-length 32-byte fields, and every integer is 8-byte big-endian. The form this struct's comment gave before, SHA-256(`context_id` || `checkpoint_seq` || … || `created_at`), had no domain separator and no length prefix on `context_id`. Every field after `context_id` has a fixed width, so those bytes parse one way within this structure; but with no separator, a signature over them could be presented as a signature of another structure whose preimage has the same bytes, and §9.5.1 requires both the separator and the length prefix on every variable-length field. The separator is new, so it starts at V1, and no signature made under the old form verifies under it. `creator_did` and `signer_did` stay outside the preimage.

**Amendment (2026-10-20, ADR-066): the checkpoint signature is log-anchored evidence.** The separator is in the log-anchored evidence class of `09-security-model.md` §9.7.1, and every signature on a checkpoint carries its signer's `key_state_head`: the creator's in `creator_key_state_head`, each cosigner's in its `CosignedCheckpoint.key_state_head`, each the value the §9.7.1 log-anchored row constructs from that signer's own key state when it signs. The preimage above ends with that field, and each signer signs it with its own `key_state_head`, so the creator and the cosigners sign different hashes over the same checkpoint fields. The amendment above put the separator in the content class on the claim that a checkpoint reaches every member as a `Checkpoint` leaf a Commit orders. A Commit carries that leaf in an encrypted context (the Commit-leaf amendment above, ADR-066 decision 24), but that does not settle the class: only the members that process the Commit verify its signatures in the epoch that orders it. A checkpoint is a durable artifact: a joiner, or a member rebuilding, fetches the leaf and counts its quorum after the epoch whose Commit carried it, and a member re-serves it for as long as pruning keeps it. Under the content class, a signer that later rotates its `#active` would void its signature for every joiner that receives the checkpoint after that rotation's boundary, so the joiner could not count the quorum and could not rebuild. Every signature on a checkpoint, the creator's and each cosigner's, verifies against the key that held `#active` at the position its signer's `key_state_head` names: the signature verifies iff that key was `Current` there, and a key the signer's state now lists `Superseded` or `Retired` keeps it valid. Where the signer's state lists the key `Compromised{from: N}`, the verifier accepts the signature only when first-seen holds as §9.7.1 defines it: the verifier verified the checkpoint against an adopted chain for that signer that did not yet carry N, and recorded it with that verification. A verifier that received the checkpoint earlier but resolved the signer's chain only after that chain carried N does not count the signature. A signature that fails these tests does not count toward the quorum. **Amendment (2026-10-20, ADR-066 decision 27).** These tests now bind only a verifier outside the group, which holds no committed log head. A member that processes the checkpoint Commit verifies every signature under the key it resolved from the `0xFF03` attestation on the signer's leaf in the Commit's sending epoch and reads no key-event log (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6). Members can disagree on a signer's leaf at the Commit where it enters their trees, and a Welcome joiner, an importer, or a restorer holds no resolved key for a leaf already in the tree, so members do not yet all reach one verdict on a checkpoint; SCP-315 owns the fix (`09-security-model.md` §9.7.1, "Known gap: members can resolve different keys for one attestation"). A joiner, an importer, and a restorer accept the `Checkpoint` leaf by its inclusion under the committed `log_head_hash`, verify none of its signatures, and count no quorum (the next paragraph), so no member meets a committed checkpoint that falls short, and none rebuilds from an earlier checkpoint. The separator keeps V1: it was introduced in the same change, before any implementation signed under it.

A member rebuilding state adopts a checkpoint's snapshot, every field of it including membership, roles, the governance configuration, the capability ceiling, the five governance fields, `recorded_proposals`, `economic_policy`, `outlets`, and `ucan_revocations`, only when its digest equals the `state_snapshot_hash` of the latest `Checkpoint` leaf included under the `log_head_hash` that the group context it joins, imports, or restores under commits (`05-contexts.md` §5.13.3 rule 14). **Amendment (2026-10-20, ADR-066 decision 27).** This replaces the quorum count of decision 25: the member counts no checkpoint quorum and verifies no checkpoint signature. Every member that merged the checkpoint Commit computed that snapshot from its own state, checked its digest, and checked the quorum and every signature against its own state (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6), and the committed log head proves the leaf is the one those members validated. The member then applies the leaves after the checkpoint, accepting each by its inclusion under the committed head, and grants no right until the governance policy, ceiling, economic policy, and governance state it ends with hash to the committed values (§5.13.3 rules 3, 4, 12, and 13). A member never walks earlier checkpoints and never rebuilds from an earlier one, because no committed checkpoint lacks its quorum; pruning invariant 3 still keeps every checkpoint leaf. A member never prunes a leaf after the latest checkpoint (rule 1 below) or its latest TTL leaf, the latest `TtlExtended` leaf or `GovernanceActionExecuted` leaf of a `PromoteContext` action, because every member derives the TTL deadline from that leaf, and a rebuilt member checks the snapshot's `ttl_deadline_unix` against it (pruning invariant 6). No member keeps a `GovernanceProposalRecorded` leaf for the snapshot's sake (pruning invariant 7, withdrawn). A member that cannot obtain these leaves grants no right in the context, as ADR-066 decision 7 requires. Before decision 27, a member counted the latest checkpoint's quorum against the committed voters, verified each kept leaf under its own `key_state_head`, and rebuilt from the first leaf when the latest checkpoint fell short. That let the adding committer append forged leaves after the checkpoint, let one key later marked `Compromised` lock joiners out, and stopped every joiner of a `Unanimity` context once two voters joined between checkpoints.


**Checkpoint creation rules:**

- In single-admin contexts (Phase 2 governance), only the admin can create checkpoints. The checkpoint is signed by the admin's Active Signing Key.
- In multi-admin contexts (ADR-031), checkpoints require signatures from a governance quorum (e.g., M-of-N admins). The `cosignatures` field carries additional signer attestations.
- Members receiving a checkpoint verify the signature(s) against known admin identifier(s), then verify that the `merkle_root` matches their local Merkle root at `checkpoint_seq`. If it matches, the checkpoint is trusted. If it diverges, the member raises an equivocation alert (same mechanism as §9.9.3 consistency checkpoint divergence).
- The `state_snapshot` is deterministically serialized (sorted keys, canonical MessagePack encoding) so that any member can independently compute `SHA-256(serialize(state_snapshot))` and verify the signature covers the correct state.

**Amendment (2026-10-20, ADR-066 decision 26): no sender key epochs.** The snapshot holds no `sender_key_epochs`. A sender key epoch advances by a `SenderKeyEpochAdvance` application message (`09-security-model.md` §9.16.3), which has no order across senders that every member shares, so two signers that compute the snapshot at one leaf count can hold different epochs and their digests differ; a checkpoint whose snapshot held them could miss its quorum whenever an advance was in flight. `09-security-model.md` §9.16.1 also keeps receive-side epoch state on the node that holds it and gives it no authority elsewhere. A joiner learns each member's epoch from that member's messages (`09-security-model.md` §9.16.2, "New member join").

**Amendment (2026-10-20, ADR-066 decision 24): creating and validating a checkpoint in an encrypted context.** The creator is a member that ADR-031 §9 lets sign a checkpoint: the admin in `SingleAdmin`, a member of `signers` in `Threshold`, and a member holding `GovernanceVote` in `Majority` and `Unanimity`. It fixes the checkpoint at its current leaf count N: `event_count` is N, `checkpoint_seq` is N − 1, and the snapshot is its state after the leaf at N − 1, with `mls_epoch` the epoch that the Commit appending that leaf created. It signs the checkpoint. In every model but `SingleAdmin` it sends the checkpoint's fields and the snapshot to the other signers as MLS application messages in the context, and a signer cosigns only when its own leaf count is N and its own Merkle root, head leaf hash, and snapshot digest equal the checkpoint's. Once the creator holds the quorum ADR-031 §9 requires, it sends the checkpoint Commit itself, carrying the `Checkpoint` leaf with its signature and the gathered cosignatures, while its own leaf count is still N. When a Commit that appends a leaf merges first, every receiver would reject the checkpoint Commit, because its `event_count` no longer equals the receiver's leaf count; the creator discards that checkpoint and starts again at the new count. When a Commit that appends no leaf merges first, the creator sends the same leaf in the next epoch. The one-hour window of ADR-031 §9 is local to the creator and the cosigners. No receiver reads it, because the requirement that `event_count` equal the receiver's own leaf count bounds a checkpoint's staleness without a clock. Every member that processes the checkpoint Commit validates it under `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6, which replaces the third bullet above for that Commit: the member recomputes `merkle_root`, `last_event_hash`, and the snapshot digest from its own state, checks the quorum and every signature against its own state, and rejects the Commit on any mismatch, leaving its epoch and log unchanged and recovering through ADR-029. A member that accepts the Commit appends the leaf at sequence N, records the checkpoint as one whose quorum it verified, and stores the snapshot it computed beside the leaf at the §4d storage key, because the leaf carries only the snapshot's digest. In an encrypted context the checkpoint a rebuilding member adopts is a `Checkpoint` leaf, and a joiner accepts it by its inclusion under the committed log head as §5 steps 1 and 2 state (decision 27).

#### 2. Pruning Strategies

Pruning removes event data from local storage to reclaim space. Three pruning strategies are supported, and they compose: a context's pruning policy can combine multiple strategies with OR semantics (prune when any condition is met).

**2a. Time-based pruning.** Prune events older than a configured duration. Events with `timestamp` older than `now - retention_duration` are eligible for pruning, provided they are behind a valid checkpoint.

```rust
pub struct TimeBasedPolicy {
    /// Minimum age before an event becomes prunable.
    /// Protocol minimum: 30 days (2_592_000 seconds). Contexts may set higher.
    pub retention_secs: u64,
}
```

**2b. Size-based pruning.** Prune when the event log exceeds a configured size. The oldest events behind a valid checkpoint are pruned first until the log is within bounds.

```rust
pub struct SizeBasedPolicy {
    /// Maximum number of events to retain locally. When exceeded,
    /// oldest events behind a checkpoint are pruned.
    pub max_event_count: u64,
    /// Maximum total storage bytes for event log data (events + tree nodes).
    /// When exceeded, oldest events behind a checkpoint are pruned.
    pub max_storage_bytes: u64,
}
```

**2c. Event-type-based retention tiers.** Different event types have different retention priorities. Governance and membership events are retained longer than message events because they define the context's structural evolution and are essential for state reconstruction verification.

```rust
pub struct EventTypeRetention {
    /// Governance and structural events: ContextCreated, MemberJoined, MemberLeft,
    /// RoleAssigned, GovernanceAction, ContextClosing, ContextClosed, ContextExpired,
    /// MemberBlocked, Checkpoint.
    /// These are retained for the full retention period (or indefinitely if no
    /// time-based policy).
    pub structural_retention_multiplier: f64,  // Default: 3.0x the base retention

    /// Operational events: MessageSent, OutletInvoked, OutletVerified,
    /// ConsistencyCheckpoint, AbsenceProofRequested.
    /// These are retained for the base retention period.
    pub operational_retention_multiplier: f64,  // Default: 1.0x
}
```

Event-type retention interacts with time-based pruning: the effective retention for a structural event is `retention_secs * structural_retention_multiplier`. A context with a 30-day base retention and a 3.0x structural multiplier retains governance events for 90 days while message events are prunable after 30 days.

**Pruning invariants (enforced mechanically):**

1. Events are never pruned unless they are behind a valid, locally-verified checkpoint. No checkpoint = no pruning.
2. The protocol-enforced minimum retention period is 30 days. A context cannot configure a retention shorter than 30 days. This ensures participation validation (§7.3.1) has sufficient history for meaningful evaluation.
3. Pruning never removes checkpoint events themselves. Checkpoints are retained indefinitely (they are small and serve as trust anchors). **Amendment (2026-10-20, ADR-066 decision 24).** In an encrypted context the checkpoint event is the `Checkpoint` leaf, at most 15,605 bytes with 95 cosignatures (`07-trust-validation-and-capabilities.md` §7.3.1.1, the leaf bound), and the member keeps the snapshot it stored beside the leaf for as long as it keeps the leaf, because the leaf carries only the snapshot's digest.
4. Pruning is always local. A member's decision to prune does not affect other members' logs. Members who need full history can retain it regardless of the context's pruning policy.
5. The hash chain is preserved: even when event payloads are pruned, the `prev_hash` chain continuity is maintained through retained leaf hashes.
6. **Amendment (2026-10-18, ADR-066).** Pruning never removes a context's latest TTL leaf: its latest `TtlExtended` leaf or `GovernanceActionExecuted` leaf of a `PromoteContext` action. Every member derives the TTL deadline from that leaf (`05-contexts.md` §5.10), so a member that pruned it would derive a shorter deadline than the other members and destroy its keys early. An earlier `TtlExtended` leaf may be pruned once a later TTL leaf has a sequence at or below a valid checkpoint's. The latest TTL leaf at or before the latest valid checkpoint is then never pruned: a later TTL leaf at or below a valid checkpoint would itself be that leaf. That is the leaf a rebuilt member's snapshot check reads (§1 amendment), and that check applies only to the checkpoint the member adopts.
7. **Amendment (2026-10-19, ADR-066 decisions 20 and 21), withdrawn 2026-10-20 (ADR-066 decision 27).** A rebuilt member now adopts the snapshot by the checkpoint leaf's inclusion under the committed log head and checks no entry against the leaf it names, and a live member validates an executing Commit against its own `recorded_proposals`, which needs no leaf, so pruning treats these leaves as it treats any other. The rule read: Pruning never removes a `GovernanceProposalRecorded` leaf that an entry of `recorded_proposals` names, in the member's own governance state or in the snapshot of the latest valid checkpoint. A rebuilt member adopts that checkpoint's snapshot only when each entry matches the leaf it names (§1 amendment), and a live member validates an executing `ModifyCeiling` or `SetEconomicPolicy` against its own entries. An entry leaves the set only at a Commit that executes it, executes another `ModifyCeiling` when the entry is a `ModifyCeiling`, records a later proposal of the same kind from the same proposer, or removes the proposer (`07-trust-validation-and-capabilities.md` §7.3.1.1); its leaf may then be pruned under rules 1 to 5 once no entry of the latest valid checkpoint's snapshot names it. The set holds at most one entry per member for each of the two kinds, so this rule keeps at most two leaves per member in the member's own set and two in the checkpoint's snapshot.
8. **Amendment (2026-10-20, ADR-066 decision 22), withdrawn the same day.** This rule kept a context's latest `GovernanceActionExecuted` leaf of a `SetEconomicPolicy`, so that a rebuilt member could check the snapshot's `economic_policy` against it. The `0xFF02` extension now commits the policy as `economic_policy_hash` (`05-contexts.md` §5.13.3 rule 12), and a rebuilt member checks the policy it ends with against that hash, as it checks the ceiling against `ceiling_hash`, so pruning treats that leaf as it treats any other.

#### 3. Checkpoint Scheduling

Checkpoints are created at configurable intervals, balancing proof compaction benefit against checkpoint creation cost.

```rust
pub struct CheckpointPolicy {
    /// Create a checkpoint every N events. Default: 10_000.
    pub event_interval: u64,
    /// Create a checkpoint every N seconds. Default: 86_400 (24 hours).
    pub time_interval_secs: u64,
    /// Minimum events since last checkpoint before a new one is created.
    /// Prevents checkpoint spam in low-activity contexts. Default: 100.
    pub min_events_since_last: u64,
}
```

Checkpoint creation is triggered by the context admin's SDK when either the event interval or time interval is reached, provided the minimum event threshold since the last checkpoint is met. For low-activity contexts (fewer than 100 events per day), checkpoints are created at the time interval even if the event threshold is not met — the time interval serves as an upper bound on checkpoint staleness.

When a checkpoint is created, it is appended to the event log as a `Checkpoint` event type (extending the `EventType` enum from ADR-011). This ensures all members receive and can verify the checkpoint through normal event log synchronization.

**Amendment (2026-10-20, ADR-066 decision 24).** In an encrypted context the schedule above triggers creation at the SDK of any member that may create a checkpoint (§1 creation amendment), not only the admin's, and the leaf is appended only by the checkpoint Commit the creator sends once it holds the quorum. `Checkpoint` is `EventType` tag 79, and its parameters live in its payload, `CheckpointPayload` (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6), not in the type.

#### 4. Merkle Proof Interaction

Pruning event payloads does not invalidate inclusion proofs for pruned events, provided the Merkle tree's interior nodes are retained. This is the key insight that makes pruning compatible with verifiability.

**4a. Proof layers after pruning:**

The Merkle tree (ADR-011) has three layers of data:

1. **Event payloads** — the serialized `Event` structs. These are what pruning removes.
2. **Leaf hashes** — `SHA-256(serialize(event))` for each event. These are 32 bytes each and are retained after pruning.
3. **Interior nodes** — hash pairs at each tree level. These are retained after pruning.

After pruning, the leaf hashes and interior nodes remain. An inclusion proof for a pruned event still works: the verifier provides the event's leaf hash (which the prover retains), and the proof path through interior nodes to the root is unchanged.

**What is lost after pruning:** The ability to independently recompute the leaf hash from the event payload. A verifier who never saw the original event cannot verify that a claimed leaf hash corresponds to a specific event. They can only verify that *some* event with that leaf hash was included in the log at that position.

**4b. Pruned proofs:**

A "pruned proof" proves that an event was included in the log at a specific position, verified against a checkpoint's Merkle root rather than the current root.

```rust
pub struct PrunedInclusionProof {
    /// The leaf hash of the pruned event.
    pub leaf_hash: [u8; 32],
    /// The leaf index in the log.
    pub leaf_index: u64,
    /// Standard Merkle inclusion proof path (sibling hashes + directions).
    pub path: Vec<ProofStep>,
    /// The checkpoint Merkle root this proof verifies against.
    pub checkpoint_root: [u8; 32],
    /// The checkpoint sequence number.
    pub checkpoint_seq: u64,
}
```

Verification: recompute the root from `leaf_hash` and `path`. If the computed root equals `checkpoint_root`, and the checkpoint itself is trusted (signature verified), then the event was in the log at `leaf_index` as of `checkpoint_seq`.

**4c. Full proof chains:**

For events that span a checkpoint boundary (some events before the checkpoint, some after), a full proof chain combines a pruned proof (against the checkpoint root) with a standard inclusion proof (against the current root) and the checkpoint event's own inclusion proof linking the two roots.

```rust
pub struct FullProofChain {
    /// Proof of the event against the checkpoint's Merkle root.
    pub pruned_proof: PrunedInclusionProof,
    /// Proof that the checkpoint event itself is in the current log.
    pub checkpoint_inclusion: InclusionProof,
    /// The checkpoint (contains the Merkle root used by pruned_proof).
    pub checkpoint: Checkpoint,
}
```

Verification steps:
1. Verify `checkpoint.signature` against the checkpoint creator's identifier.
2. Verify `checkpoint_inclusion` — the checkpoint event is in the current log.
3. Verify `pruned_proof.checkpoint_root == checkpoint.merkle_root`.
4. Verify `pruned_proof` — the target event was in the log at `checkpoint_seq`.

This three-step chain provides the same assurance as a direct inclusion proof: the event was part of the log's history, the checkpoint is authentic, and the checkpoint is itself part of the current log.

**Amendment (2026-10-20, ADR-066 decision 24).** Step 1 counts the checkpoint's full quorum as the §1 amendments state, not the creator's signature alone, and in an encrypted context the checkpoint event of step 2 is the `Checkpoint` leaf.

**4d. Interior node retention strategy:**

After pruning, interior nodes from the Merkle tree are compacted. For a pruned region of the tree (all leaves behind a checkpoint), only the nodes on proof paths that connect to the checkpoint root need to be retained. In practice, the simplest strategy is to retain all interior nodes — at 32 bytes per node and O(n) total nodes for n leaves, the overhead is modest compared to event payloads. For a log with 1 million events, interior nodes consume approximately 64 MB (2n nodes * 32 bytes). If this proves excessive on mobile, a future optimization can prune interior nodes whose subtrees are entirely behind two consecutive checkpoints, retaining only the subtree roots.

Storage key convention for checkpoint-related data (extending §17.3):

```
context/{context_id}/checkpoint/{seq:020d}           -- checkpoint data
context/{context_id}/checkpoint_meta/latest           -- latest checkpoint sequence
context/{context_id}/pruning_policy                   -- current pruning policy
context/{context_id}/prune_cursor                     -- last pruned sequence number
```

#### 5. State Reconstruction from Checkpoints

When a member joins a context with a long history, or when a member's local state is corrupted, they can reconstruct the current context state from the most recent checkpoint plus post-checkpoint events rather than replaying the entire log from genesis.

**Reconstruction protocol:**

1. **Obtain the latest checkpoint.** Query the context's event log (via relay QUERY or peer request) for the most recent `Checkpoint` event. **Amendment (2026-10-20, ADR-066 decision 27).** In an encrypted context the member counts no signature quorum and verifies no checkpoint signature: it accepts the latest `Checkpoint` leaf by its inclusion under the `log_head_hash` that the group context it joins, imports, or restores under commits (`05-contexts.md` §5.13.3 rule 14), because every member validated that leaf's quorum and signatures before it merged the Commit that carried it (§1 adoption paragraph).
2. **Verify checkpoint consistency.** Compute or request the current Merkle root from an online member (via consistency checkpoint exchange, ADR-011 criterion 8). Verify that the checkpoint event is included in the current log via standard inclusion proof. **Amendment (2026-10-20, ADR-066 decision 24).** In an encrypted context, a Welcome joiner reads no online member's root: it checks that SHA-256 of the Welcome's `0xFF04` extension body equals the committed `log_head_hash`, and then checks the `Checkpoint` leaf's inclusion in the log whose leaf count, Merkle root, and head that body carries (`07-trust-validation-and-capabilities.md` §7.3.1.1, "The members a Commit adds"), checks by an RFC 6962 consistency proof that the leaf's `merkle_root` is the root of that log's first `event_count` leaves, and adopts the snapshot it fetched only when SHA-256(serialize(snapshot)) equals the leaf's `state_snapshot_hash`.
3. **Load state snapshot.** Deserialize the checkpoint's `ContextStateSnapshot`. This provides complete context state as of the checkpoint: membership, roles, governance, outlets, ceilings, UCAN revocations, and the governance state ADR-066 adds (join points, conflict sequences, the executed-proposal set, the reset counter floors, the TTL deadline, the recorded proposals, and the economic policy in effect). It holds no sender key epochs (§1 amendment, ADR-066 decision 26). **Resolved (2026-10-20):** `outlets` and `ucan_revocations` derive from commit-ordered leaves (ADR-066 decisions 31 and 28), and the snapshot holds no `blocks` (decision 30), so every signer computes the same snapshot at one leaf count (`00-open-questions.md`, "Checkpoint snapshot fields that no Commit orders"). Step 4 accepts each post-checkpoint event by its inclusion under the committed log head (decision 27).
4. **Replay post-checkpoint events.** Request events from `checkpoint_seq + 1` through the current event count. Verify each event against the Merkle tree (hash chain integrity, inclusion proof). Apply each event's state mutation to the snapshot.
5. **Verify final state.** After replay, the reconstructed state should be consistent with the current Merkle root and the latest consistency checkpoint from online members.

**Reconstruction is not the same as sync.** ADR-029 covers reconnection and sync for members who were part of the context and went offline. State reconstruction is for members who either (a) are joining a context with a long history, (b) have lost local state, or (c) are recovering from storage corruption. The checkpoint provides a known-good starting point; the replay provides the delta.

```rust
pub struct StateReconstructor {
    store: Arc<ProtocolRepository>,
}

impl StateReconstructor {
    /// Reconstruct context state from a checkpoint and post-checkpoint events.
    pub async fn reconstruct(
        &self,
        checkpoint: &Checkpoint,
        post_checkpoint_events: &[Event],
        current_merkle_root: &[u8; 32],
    ) -> Result<ReconstructedState, ReconstructionError>;
}

pub struct ReconstructedState {
    pub context_state: ContextStateSnapshot,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub events_replayed: u64,
}

pub enum ReconstructionError {
    /// Checkpoint signature verification failed.
    InvalidCheckpoint(String),
    /// Hash chain broken during event replay.
    BrokenHashChain { expected: [u8; 32], got: [u8; 32], at_seq: u64 },
    /// Final state does not match expected Merkle root.
    StateMismatch { expected_root: [u8; 32], computed_root: [u8; 32] },
    /// Missing events in the replay sequence.
    MissingEvents { from_seq: u64, to_seq: u64 },
}
```

#### 6. Governance of Pruning Policies

The pruning policy is a context parameter, set at creation or modified through the context's governance model. It is included in the context's publicly visible metadata (§5.7) so prospective members can evaluate the context's data retention posture before joining.

```rust
pub struct PruningPolicy {
    /// Time-based pruning. None = no time-based pruning.
    pub time_based: Option<TimeBasedPolicy>,
    /// Size-based pruning. None = no size-based pruning.
    pub size_based: Option<SizeBasedPolicy>,
    /// Event-type retention multipliers.
    pub event_type_retention: EventTypeRetention,
    /// Checkpoint creation schedule.
    pub checkpoint_schedule: CheckpointPolicy,
    /// Whether members are allowed to request full log history from peers.
    /// Default: true. If false, peers SHOULD NOT serve events behind their
    /// most recent checkpoint to other members.
    pub allow_full_history_requests: bool,
}
```

**Governance rules:**

- **Setting at creation.** The context creator includes `PruningPolicy` in `ContextParameters`. If omitted, the default policy applies: no time-based pruning, no size-based pruning, default checkpoint schedule (every 10,000 events or 24 hours), structural events retained 3x longer than operational events, full history requests allowed.
- **Modifying via governance.** The pruning policy can be modified through the context's governance model (admin decision in single-admin, governance vote in multi-admin). Changes are recorded in the event log as a `GovernanceAction` event.
- **Protocol minimum.** The protocol enforces a 30-day minimum for `time_based.retention_secs`. Governance cannot set a shorter retention. This floor ensures participation validation (§7.3.1) and equivocation detection (§9.9.3) have meaningful history to work with.
- **Structural event floor.** Governance and membership events (structural events) cannot have an effective retention shorter than 90 days (`structural_retention_multiplier` is clamped to produce at least 90 days of structural event retention). This ensures that context governance history — who joined, who left, what roles changed, what governance actions occurred — is preserved long enough for accountability.
- **Member autonomy.** A member's SDK can retain the full unprocessed event log locally regardless of the context's pruning policy. The pruning policy governs what the protocol considers the minimum retention obligation and what peers are expected to serve. A member who wants full history retains it; a member on a constrained device prunes according to policy.

**Default pruning policy:**

```rust
impl Default for PruningPolicy {
    fn default() -> Self {
        Self {
            time_based: None,         // No time-based pruning by default
            size_based: None,          // No size-based pruning by default
            event_type_retention: EventTypeRetention {
                structural_retention_multiplier: 3.0,
                operational_retention_multiplier: 1.0,
            },
            checkpoint_schedule: CheckpointPolicy {
                event_interval: 10_000,
                time_interval_secs: 86_400,
                min_events_since_last: 100,
            },
            allow_full_history_requests: true,
        }
    }
}
```

**Context templates (§5.12) with pruning presets:**

- `ephemeral`: 30-day retention, 50,000 max events, checkpoints every 5,000 events.
- `conversation`: 90-day retention, 100,000 max events, checkpoints every 10,000 events.
- `persistent` / `full`: No time-based or size-based pruning (default policy). Full history retained.
- `high_volume`: 30-day retention, 500,000 max events, checkpoints every 10,000 events, structural multiplier 5.0x.

#### 7. Pruning Execution

Pruning is a local operation performed by the SDK. It is never triggered by relays or remote peers. The SDK runs a background pruning task that evaluates the pruning policy periodically.

```rust
pub struct PruningExecutor {
    store: Arc<ProtocolRepository>,
}

impl PruningExecutor {
    /// Evaluate the pruning policy for a context and prune eligible events.
    /// Returns a report of what was pruned.
    pub async fn prune(
        &self,
        context_id: &ContextId,
        policy: &PruningPolicy,
        now: u64,
    ) -> Result<PruneReport, PruneError>;
}

pub struct PruneReport {
    pub context_id: ContextId,
    /// Number of event payloads removed.
    pub events_pruned: u64,
    /// Bytes reclaimed from storage.
    pub bytes_reclaimed: u64,
    /// The sequence number of the checkpoint used as the pruning boundary.
    pub pruned_up_to_checkpoint: u64,
    /// The sequence number of the oldest retained event payload.
    pub oldest_retained_seq: u64,
}

pub enum PruneError {
    /// No valid checkpoint exists — cannot prune.
    NoCheckpoint,
    /// All events are within the minimum retention period.
    NothingToPrune,
    /// Storage operation failed.
    StorageError(String),
}
```

**Pruning algorithm:**

1. Load the latest verified checkpoint for the context.
2. Determine the eligible pruning boundary: `min(checkpoint_seq, oldest_event_meeting_retention_criteria)`. Events beyond the checkpoint cannot be pruned (no checkpoint to anchor proofs). Events within the retention window cannot be pruned.
3. For each event from the oldest to the pruning boundary:
   a. Check event-type retention: if the event is structural and within the structural retention window, skip.
   b. Delete the event payload from `ProtocolRepository` (key: `context/{context_id}/event/{seq:020d}`).
   c. Retain the leaf hash in a compact index (key: `context/{context_id}/pruned_leaf/{seq:020d}`, value: 32-byte hash). This enables pruned proofs.
4. Update the prune cursor: `context/{context_id}/prune_cursor` = highest pruned sequence number.
5. Optionally compact interior tree nodes (Phase 6 optimization — retain all by default).

**Pruning frequency:** The background task runs every 6 hours. On mobile platforms, it defers to when the device is charging and on Wi-Fi (if the platform adapter exposes this information). Pruning is not time-critical — a few hours of delay does not affect correctness.

### Rationale

**Why checkpoint-based pruning instead of rolling windows:**

A rolling window (keep last N events, discard older) breaks Merkle proof continuity. There is no anchor point to verify that pruned events were once part of the log. Checkpoints provide this anchor: the checkpoint's signed Merkle root is the verifiable claim that "all events up to sequence S produced this root." Pruned proofs work because the Merkle tree structure (leaf hashes + interior nodes) is retained even when payloads are removed.

**Why 30-day minimum retention:**

Participation validation (§7.3.1) computes records from event log history. A 30-day minimum ensures at least one month of participation data is available for trust evaluation. Shorter windows would make participation records unreliable — a participant could misbehave, wait for pruning, and have no verifiable participation record of the misbehavior. The 30-day floor is a practical balance between storage and accountability. Contexts that need longer accountability windows (governance, financial) set longer retention.

**Why event-type tiers:**

Governance and membership events are small (a role assignment is ~200 bytes) and structurally critical (they define who can do what in the context). Message events are more numerous and less structurally important after verification. Retaining structural events 3x longer than operational events costs minimal storage (structural events are typically <5% of total events by count) while preserving the governance audit trail. This is the same principle as database archival: metadata about the data outlives the data itself.

**Why checkpoints are published to the event log:**

Publishing checkpoints as event log entries makes them discoverable through the same mechanisms as any other event: relay subscription, peer sync, and event range queries. It also means checkpoints are included in the Merkle tree, so their authenticity is verifiable by the same proof machinery. A checkpoint event's inclusion in the log proves it was created when claimed and observed by all members.

**Why pruning is local-only:**

SCP's trust model treats relays as untrusted dumb pipes (§9.9.1). Relays should not influence what clients retain. Similarly, other members should not be able to force a client to prune — that would be a censorship vector (force prune evidence of misbehavior). Pruning is always the local member's decision, constrained by the protocol's minimum retention floor. The pruning policy is a recommendation that the SDK follows by default, not an enforcement mechanism.

**Why members can retain full history:**

The "member autonomy" principle ensures that pruning is a storage optimization, not a privacy guarantee. A context cannot promise that its event log will disappear after 30 days — any member who was present could have retained the full log. This is by design: SCP prioritizes accountability and verifiability over retroactive deletion. If a context needs content destruction guarantees, it uses ephemeral memory scope (§5.11) which destroys encryption keys, not event log hashes.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (background pruning task, checkpoint creation)
- **Crate:** `scp-core`
- **Module:** `scp-core/event_log/` (extends existing event log module from ADR-011)
- **Persistence:** Via `ProtocolRepository` (§17.4). Key conventions:
  - `context/{context_id}/checkpoint/{seq:020d}` — serialized `Checkpoint` structs
  - `context/{context_id}/checkpoint_meta/latest` — latest checkpoint sequence number
  - `context/{context_id}/pruning_policy` — serialized `PruningPolicy`
  - `context/{context_id}/prune_cursor` — last pruned sequence number
  - `context/{context_id}/pruned_leaf/{seq:020d}` — retained leaf hashes for pruned events

### Dependencies

- **ADR-011 (Event Log):** The checkpoint-and-prune system extends the Merkle event log. Checkpoints are a new `EventType`. Pruned proofs use the existing `InclusionProof` structure verified against a checkpoint root instead of the current root.
- **ADR-008 (Context Lifecycle):** Pruning policy is a context parameter. Context creation includes optional `PruningPolicy` in `ContextParameters`. Context closure triggers final checkpoint creation before key destruction (for ephemeral/summary memory scopes).
- **ADR-009 (Roles):** Checkpoint creation requires the admin role (or governance quorum in multi-admin contexts).
- **ADR-029 (Offline/Sync):** State reconstruction from checkpoints provides the fast-start path for members who missed many events during extended offline periods. The `StateReconstructor` complements the `ReconnectionCoordinator` — reconnecting members can load the latest checkpoint instead of replaying the full log.
- **ProtocolRepository (§17.4):** Storage and retrieval of checkpoints, pruning policy, prune cursor, and retained leaf hashes. Range queries via `list_keys` with zero-padded sequence numbers.

### Acceptance Criteria

1. **`Checkpoint` struct and event type (extends ADR-011 `EventType` enum):**

```rust
// Addition to EventType in scp-core/event_log/
Checkpoint {
    checkpoint_seq: u64,
    merkle_root: [u8; 32],
    state_snapshot_hash: [u8; 32],  // SHA-256 of serialized ContextStateSnapshot
},
```

2. **`create_checkpoint(event_log, context_state, signing_key) -> Result<Checkpoint, CheckpointError>`**

   - Captures the current Merkle root, event count, and last event hash from the event log.
   - Serializes the full `ContextStateSnapshot` deterministically.
   - Signs the checkpoint with the provided signing key, the admin's Active Signing Key.
   - Appends the checkpoint as a `Checkpoint` event to the event log. **Amendment (2026-10-20, ADR-066 decision 24):** in an encrypted context the creator does not append it; the checkpoint Commit appends the `Checkpoint` leaf at every member, and the variant carries no fields, because its payload is `CheckpointPayload` (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6).
   - Persists the checkpoint to `ProtocolRepository` at `context/{id}/checkpoint/{seq:020d}`.
   - Updates `context/{id}/checkpoint_meta/latest`.
   - Returns the signed checkpoint.

3. **`verify_checkpoint(checkpoint, admin_public_key, event_log) -> Result<bool, CheckpointError>`**

   - Verifies the checkpoint signature against the admin's public key.
   - Verifies the `merkle_root` matches the event log's root at `checkpoint_seq`.
   - Verifies `state_snapshot_hash` matches `SHA-256(serialize(checkpoint.state_snapshot))`.
   - Returns true if all verifications pass.

4. **`PruningPolicy` struct and validation:**

   - `validate_policy(policy) -> Result<(), PolicyError>`: Rejects policies with `time_based.retention_secs < 2_592_000` (30 days). Rejects policies where the effective structural retention is less than 90 days. Clamps `structural_retention_multiplier` to produce at least 90 days.

5. **`PruningExecutor::prune(context_id, policy, now) -> Result<PruneReport, PruneError>`**

   - Loads the latest checkpoint. Returns `PruneError::NoCheckpoint` if none exists.
   - Computes the pruning boundary from the intersection of checkpoint coverage and retention policy.
   - Iterates events from oldest to boundary, respecting event-type retention tiers.
   - Deletes event payloads from `ProtocolRepository`.
   - Retains leaf hashes at `context/{id}/pruned_leaf/{seq:020d}`.
   - Updates `prune_cursor`.
   - Returns a `PruneReport` with statistics.

6. **`prove_pruned_inclusion(event_log, leaf_hash, leaf_index, checkpoint) -> Result<PrunedInclusionProof, EventLogError>`**

   - Generates a Merkle inclusion proof for a pruned event using the retained leaf hash and interior nodes.
   - The proof verifies against the checkpoint's `merkle_root`.

7. **`build_full_proof_chain(pruned_proof, checkpoint, event_log) -> Result<FullProofChain, EventLogError>`**

   - Combines a pruned inclusion proof with the checkpoint's own inclusion proof in the current log.
   - Returns a `FullProofChain` that can be verified by any third party with access to the current Merkle root.

8. **`StateReconstructor::reconstruct(checkpoint, events, current_root) -> Result<ReconstructedState, ReconstructionError>`**

   - Verifies the checkpoint signature.
   - Loads the `ContextStateSnapshot` from the checkpoint.
   - Replays each post-checkpoint event, verifying hash chain continuity.
   - Applies each event's state mutation to the snapshot.
   - Verifies the final Merkle root matches `current_root`.
   - Returns the reconstructed state.

9. **Background checkpoint and pruning tasks:**

   - `CheckpointScheduler`: monitors event count and time since last checkpoint. Triggers `create_checkpoint` when thresholds are met. Runs as a tokio background task.
   - `PruningTask`: runs every 6 hours. Evaluates the pruning policy for each active context and calls `PruningExecutor::prune`. Defers on mobile when not charging (if platform adapter reports power state).

10. **Integration test:**

```
1. Alice creates an identity and a context with a pruning policy:
   time-based 30-day retention, checkpoint every 100 events.
2. Alice and Bob exchange 250 messages (250 events in the log).
3. Verify: checkpoint was created automatically at event 100 and event 200.
4. Verify: both checkpoints are in the event log as Checkpoint events.
5. Verify: checkpoint state_snapshot matches actual context state at those points.
6. Simulate time advance of 31 days.
7. Run pruning. Verify: events 0-199 (behind the checkpoint at 200, older
   than 30 days) are pruned. Events 200-249 are retained.
8. Verify: event payloads for 0-199 are gone from ProtocolRepository.
9. Verify: leaf hashes for 0-199 are retained in pruned_leaf/ keys.
10. Generate a pruned inclusion proof for event 50 against checkpoint at 200.
    Verify it succeeds.
11. Build a full proof chain for event 50. Verify it validates against
    the current Merkle root.
12. Carol joins the context. Carol reconstructs state from the latest
    checkpoint (200) + events 200-249. Verify Carol's reconstructed state
    matches Alice and Bob's current state.
13. Verify: governance events (MemberJoined for Bob) with structural
    retention multiplier 3.0x would be retained for 90 days even as
    message events are pruned at 30 days.
```

### Scope

**Files (~5-7):**

| File | Purpose |
|------|---------|
| `checkpoint.rs` | `Checkpoint`, `ContextStateSnapshot`, `CosignedCheckpoint`, `create_checkpoint`, `verify_checkpoint`, `CheckpointScheduler` |
| `pruning.rs` | `PruningPolicy`, `TimeBasedPolicy`, `SizeBasedPolicy`, `EventTypeRetention`, `PruningExecutor`, `PruneReport`, policy validation |
| `pruned_proof.rs` | `PrunedInclusionProof`, `FullProofChain`, `prove_pruned_inclusion`, `build_full_proof_chain` |
| `reconstruct.rs` | `StateReconstructor`, `ReconstructedState`, `ReconstructionError`, state replay logic |
| `policy.rs` | `CheckpointPolicy`, default policies, template presets, policy governance integration |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers.

---

## ADR-031: Multi-Admin Governance Models

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling); 2026-10-12 (the pseudonym rotation policy action).

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, left an identity one operational key, so the one-identity-one-vote rule has no second key to deduplicate across (`09-security-model.md` §9.1 invariant 1).

**Amendment (2026-09-10 — the governance-proposal signature is ECDSA on P-256).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. The `signature` field on this ADR's governance-proposal structure carries the type `P256Signature`. The threshold models, the approval flow, and the admin-set rules are untouched.

**Amendment (2026-10-12 — the pseudonym rotation policy is a governance action).** Section 3's `GovernanceAction` enum gains `ModifyPseudonymRotationPolicy { new_policy: Option<PseudonymRotationPolicy> }`. The action sets, changes or removes `ContextParams.pseudonym_rotation`, the per-context rotation policy that `09-security-model.md` §9.10.4.1 (pseudonym rotation) defines. That section states which policies are valid, and states that removing the policy freezes each member's current routing ID. The proposal flow, the quorum rules and the admin-set rules are untouched.

### Context

Phase 2 governance (ADR-008) uses a single-admin model: one identity holds all governance authority, and governance actions are serialized through that admin. This works for bilateral contexts, small groups, and contexts where a clear authority is appropriate. It becomes a bottleneck and a single point of failure for larger, more collaborative contexts: if the admin goes offline, no governance changes can occur (ADR-029 section 5c explicitly acknowledges this); if the admin acts unilaterally in ways members disagree with, the only recourse is exit (§9.2.1); and if the admin's key is compromised, the entire context's governance is compromised.

Real-world collaborative contexts — working groups, DAOs, multi-party negotiations, open-source project spaces, community moderation teams — require shared governance. Different contexts have different governance needs: a 3-person team might want 2-of-3 approval for membership changes; a community might want majority vote; a high-stakes financial context might require unanimity for ceiling changes. The spec (§5.9) explicitly declares governance as a pluggable interface with multiple models, and the sketch defines the three-method contract (`propose`, `approve`, `reject`) that all models must implement. ADR-029 section 5c already references multi-admin governance and defines the conflict resolution semantics (Merkle log order is authoritative; simultaneous conflicting proposals trigger a `GovernanceConflict` state requiring manual resolution). ADR-030 defines checkpoint cosignatures from governance quorums. This ADR completes the governance system by defining the concrete models, the proposal lifecycle, quorum rules, voting windows, deadlock recovery, and the UCAN delegation model for multi-admin contexts.

### Scope

**What this ADR covers:**

- The `GovernanceEngine` trait: the pluggable interface all governance models implement.
- The `GovernanceProposal` lifecycle: creation, voting, resolution, expiry, cancellation.
- Four concrete governance models: single-admin (Phase 2 baseline, formalized), threshold (M-of-N), majority, and unanimity.
- Governance model selection at context creation (immutable for lifetime).
- Quorum rules, voting windows, and timeout handling per model.
- Vote semantics: order-independent, withdrawal permitted, one vote per eligible voter.
- Deadlock recovery: what happens when quorum is unreachable.
- UCAN delegation in multi-admin contexts: who holds governance UCANs, how authority is distributed.
- Interaction with MLS epochs: governance proposals are MLS application messages; approvals do not trigger epoch advances.
- Interaction with ADR-029 (offline/sync): concurrent governance conflict resolution.
- Interaction with ADR-030 (pruning): checkpoint cosignature requirements per governance model.
- Event log event types for the governance proposal lifecycle.

**What this ADR does NOT cover:**

- Weighted voting (deferred — requires a token or stake mechanism not present in SCP v1).
- Delegated/representative governance (deferred — same complexity class as weighted voting).
- Cross-context governance federation (out of scope — contexts are isolated).
- Custom/pluggable governance implementations beyond the four built-in models (the trait is extensible, but only the four built-in models are specified here).

### Decision

Implement a pluggable governance engine in `scp-core/governance/` that defines a `GovernanceEngine` trait with four built-in implementations: `SingleAdmin`, `Threshold`, `Majority`, and `Unanimity`. Every context declares its governance model at creation; the model is immutable for the context's lifetime. All governance models implement the same three-method interface (`propose`, `approve`, `reject`) from the sketch. Proposals are structured event log entries with typed payloads, configurable voting windows, and deterministic resolution. Vote collection is order-independent and withdrawal is permitted. Deadlock recovery uses an automatic fallback to preserve context liveness.

#### 1. Governance Engine Trait

The governance engine is the pluggable interface that all governance models implement. The `ContextManager` delegates all governance decisions to the engine.

```rust
/// The pluggable governance interface. All governance models implement this trait.
/// The trait is object-safe to enable dynamic dispatch via `Box<dyn GovernanceEngine>`.
pub trait GovernanceEngine: Send + Sync {
    /// Submit a new governance proposal. Returns the proposal ID.
    /// The proposer must hold `GovernancePropose` capability (UCAN-validated).
    fn propose(
        &self,
        proposer: &DID,
        action: GovernanceAction,
        context: &GovernanceContext,
    ) -> Result<ProposalId, GovernanceError>;

    /// Cast an approval vote on a pending proposal.
    /// The voter must hold `GovernanceVote` capability (UCAN-validated).
    fn approve(
        &self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError>;

    /// Cast a rejection vote on a pending proposal.
    /// The voter must hold `GovernanceVote` capability (UCAN-validated).
    fn reject(
        &self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError>;

    /// Withdraw a previously cast vote (approval or rejection).
    /// Only the original voter can withdraw. Only valid while proposal is Pending.
    fn withdraw_vote(
        &self,
        proposal_id: &ProposalId,
        voter: &DID,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError>;

    /// Cancel a pending proposal. Only the original proposer can cancel.
    /// Returns Cancelled status on success, error if proposal is not Pending
    /// or if the caller is not the proposer.
    fn cancel(
        &self,
        proposal_id: &ProposalId,
        proposer: &DID,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError>;

    /// Check whether a proposal has reached resolution (quorum met, rejected,
    /// or expired). Called after each vote and periodically by the SDK.
    fn resolve(
        &self,
        proposal_id: &ProposalId,
        context: &GovernanceContext,
    ) -> Result<ProposalStatus, GovernanceError>;

    /// Return the governance model configuration for metadata publication.
    fn model_config(&self) -> GovernanceModelConfig;

    /// Return the set of identifiers eligible to vote on proposals in this model.
    fn eligible_voters(&self, context: &GovernanceContext) -> Vec<DID>;
}

/// Read-only context snapshot provided to the governance engine.
/// The engine never mutates context state directly — it returns decisions
/// that the ContextManager executes.
pub struct GovernanceContext {
    pub context_id: ContextId,
    pub members: Vec<(DID, RoleName)>,
    pub admin_dids: Vec<DID>,
    pub current_epoch: Option<u64>,
    pub now: u64,
}
```

#### 2. Governance Model Configuration

The governance model is declared at context creation via `ContextParams.governance` and is immutable. Changing the governance model requires creating a new context. This prevents governance bait-and-switch — members join knowing exactly how decisions are made.

```rust
/// Governance model selection. The variant is set at context creation and never
/// changes; five governance actions change its fields (ADR-066 amendment below).
/// Included in context metadata (§5.7) — visible before opt-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceModelConfig {
    /// Single admin holds all governance authority. Phase 2 baseline.
    /// The creator is the initial (and only) admin. Admin transfer is
    /// a governance action that replaces the admin.
    SingleAdmin {
        admin_did: DID,
    },

    /// M-of-N threshold approval. A fixed set of designated signers;
    /// a proposal passes when at least `threshold` of them approve.
    /// One identity = one vote. A vote
    /// carries the weight of the identity that signed it and not of a key.
    Threshold {
        /// The set of identifiers authorized to vote. These identifiers must hold
        /// the `GovernanceVote` capability.
        signers: Vec<DID>,
        /// Minimum number of approvals required. Must satisfy:
        /// 1 <= threshold <= signers.len().
        threshold: u32,
        /// Voting window in seconds. Proposals that do not reach
        /// quorum within this window expire. Default: 86_400 (24 hours).
        voting_window_secs: u64,
    },

    /// Majority vote among all context members holding `GovernanceVote`
    /// capability. Proposal passes when approvals > 50% of eligible voters.
    Majority {
        /// Voting window in seconds. Default: 86_400 (24 hours).
        voting_window_secs: u64,
        /// Minimum participation threshold in basis points (1–10000).
        /// E.g., 5000 = 50%. The proposal is only valid if at least
        /// this fraction of eligible voters cast a vote (approve or reject).
        /// Default: 5000 (50%). Using u32 basis points instead of f64 so
        /// GovernanceModelConfig can derive Eq.
        min_participation_bps: u32,
    },

    /// Unanimity among all context members holding `GovernanceVote`
    /// capability. Every eligible voter must approve. A single rejection
    /// defeats the proposal immediately.
    Unanimity {
        /// Voting window in seconds. Default: 172_800 (48 hours).
        /// Longer default because unanimity requires every voter.
        voting_window_secs: u64,
    },
}
```

**Validation at context creation:**

- `Threshold`: `signers` must be non-empty, `threshold` must be in `[1, signers.len()]`, all signer identifiers must be among the context's initial members, `voting_window_secs` must be in `[300, 604_800]` (5 minutes to 7 days).
- `Majority`: `min_participation_bps` must be in `(0, 10000]`, `voting_window_secs` must be in `[300, 604_800]`.
- `Unanimity`: `voting_window_secs` must be in `[300, 604_800]`.

**Amendment (2026-10-17, ADR-066).** One Commit carries at most `MAX_GOVERNANCE_APPROVALS` (96) approvals, so creation and `ReconfigureGovernance` also reject a `Majority` context with more than 191 eligible voters and a `Unanimity` context with more than 96 (`05-contexts.md` §5.9 invariant 4). A `Threshold` `threshold` stays within its 64-signer cap, below 96. **Amendment (2026-10-18, ADR-066):** a context with a TTL has at most 96 members under every model, `Threshold` included, voters or not, because `ExtendTtl` and `PromoteContext` need an approval from every current member (§4 amendment below); creation rejects a context with a TTL whose initial membership exceeds 96, and an action that would add a 97th member is rejected.

**Amendment (2026-10-18, ADR-066): the variant is fixed, its fields are not.** A context's `GovernanceModelConfig` variant is set at creation and never changes, so the governance model stays immutable. Five actions change its fields: `TransferAdmin` sets `admin_did`; `AddSigner`, `RemoveSigner`, and the `RemoveInactiveSigner` of a `ReconfigureGovernance` change `signers`; and `ModifyThreshold` and the `ReduceThreshold` of a `ReconfigureGovernance` set `threshold`. No action changes `voting_window_secs` or `min_participation_bps`. `signers` is a set, held in ascending order of the UTF-8 bytes of its identifiers' text forms. The context's current `GovernanceModelConfig` is the governance policy whose hash the `0xFF02` extension commits (`05-contexts.md` §5.13.3, "Governance policy"), and the `governance` field of ADR-030's `ContextStateSnapshot` holds it.

#### 3. Governance Proposal Lifecycle

Every governance action goes through the proposal lifecycle. In `SingleAdmin`, the propose step auto-resolves (the admin's proposal is simultaneously the approval). In multi-admin models, proposals are created, voted on, and resolved.

```rust
/// Unique identifier for a governance proposal.
/// Format: SHA-256(context_id || proposer_did || action_hash || timestamp).
pub type ProposalId = [u8; 32];

/// A governance proposal. Created by `propose()`, stored in the event log
/// and in `ProtocolRepository` for active tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: ProposalId,
    pub context_id: ContextId,
    pub proposer_did: DID,
    pub action: GovernanceAction,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub voting_deadline: u64,
    pub approvals: Vec<SignedVote>,
    pub rejections: Vec<SignedVote>,
    /// Epoch at which the proposal was created. Proposals are valid only
    /// for the epoch in which they were created and subsequent epochs.
    /// If the group resets (ADR-029 Tier 3), pending proposals are
    /// invalidated because the epoch context has changed.
    pub created_at_epoch: Option<u64>,
}

/// A signed vote on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVote {
    pub voter_did: DID,
    pub vote: VoteType,
    pub timestamp: u64,
    pub signature: P256Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoteType {
    Approve,
    Reject,
}

/// The status of a governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal is open for voting.
    Pending,
    /// Proposal reached quorum and was approved. The action will be executed.
    Approved,
    /// Proposal was rejected (explicit rejection or failed to reach quorum).
    Rejected { reason: RejectionReason },
    /// Proposal expired before reaching quorum.
    Expired,
    /// Proposal was cancelled by the proposer before resolution.
    Cancelled,
    /// Proposal was invalidated (e.g., epoch reset, proposer removed).
    Invalidated { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RejectionReason {
    /// More rejections than approvals (Majority model).
    MajorityRejected,
    /// Any single rejection (Unanimity model).
    UnanimityBroken { rejector: DID },
    /// Threshold of rejections reached making approval impossible
    /// (Threshold model: rejections > signers - threshold).
    ApprovalImpossible,
    /// Insufficient participation within voting window (Majority model).
    InsufficientParticipation,
}

/// Typed governance actions. Every governance change is one of these variants.
/// The governance engine evaluates proposals containing these actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    /// Add a member to the context.
    AddMember { did: DID, role: RoleName },
    /// Remove a member from the context.
    RemoveMember { did: DID, reason: Option<String> },
    /// Change a member's role.
    ChangeRole { did: DID, new_role: RoleName },
    /// Register a new outlet, or replace a registered one with the same
    /// outlet_id. ADR-066 decision 31: carries the header of spec 05
    /// §5.4.1, not the full registration; executes only when the outlet
    /// registration policy routes the change, or by any proposer's choice.
    RegisterOutlet { registration: OutletRegistrationHeader },
    /// Remove an outlet.
    RemoveOutlet { outlet_id: OutletId },
    /// ADR-066 decisions 31 and 35: replace the outlet registration
    /// rule list (spec 05 §5.4). Conflict key: none.
    SetOutletRegistrationPolicy { policy: OutletRegistrationPolicy },
    /// Modify the capability ceiling (only if ceiling_policy is Governed).
    ModifyCeiling { new_ceiling: Vec<Capability> },
    /// Close the context.
    CloseContext { reason: Option<String> },
    /// Extend TTL (requires unanimous member consent per §5.10).
    ExtendTtl { additional_secs: u64 },
    /// Modify pruning policy (ADR-030).
    ModifyPruningPolicy { new_policy: PruningPolicy },
    /// Transfer single-admin authority (SingleAdmin model only).
    TransferAdmin { new_admin: DID },
    /// Add a new signer to the threshold set (Threshold model only).
    AddSigner { did: DID },
    /// Remove a signer from the threshold set (Threshold model only).
    RemoveSigner { did: DID },
    /// Modify the threshold value (Threshold model only).
    ModifyThreshold { new_threshold: u32 },
    /// Create a child context (§5.13).
    CreateChildContext { params: Box<ContextParams> },
    /// Establish an outlet interface with another context (§6.2).
    EstablishOutletInterface { interface: OutletInterface },
    /// Initiate governance-triggered member reset (ADR-029).
    ResetMember { did: DID, reason: String },
    /// Resolve a governance conflict (see section 7).
    ResolveConflict { proposal_a: ProposalId, proposal_b: ProposalId, resolution: ConflictResolution },
    /// Promote a context from ephemeral to persistent (§5.10).
    /// Requires unanimous consent from ALL current members regardless of
    /// governance model — protocol-level override enforced by ContextManager.
    PromoteContext,
    /// Revoke a member's read access to context content (§9.17).
    /// Full scope: retroactive (destroy access keys for historical + future content).
    /// FutureOnly scope: exclude from future content key distribution only.
    /// Does NOT remove the member — they remain for governance/presence.
    /// Requires `MemberBan` capability in the context's ceiling (§5.3).
    /// In broadcast contexts: removes subscriber from registry, adds to all
    /// authors' block lists, forces key rotation on all authors (§5.14.8).
    RevokeReadAccess { did: DID, scope: RevocationScope },
    /// Restore a member's read access to context content (§9.17).
    /// Always forward-only — historical content from before/during revocation
    /// remains inaccessible (access keys were destroyed, not archived).
    /// Requires `MemberBan` capability in the context's ceiling (§5.3).
    RestoreReadAccess { did: DID },
    /// Revoke a member's write access to context content (§9.17).
    /// Full scope: stop publishing + suppress historical content.
    /// FutureOnly scope: stop future publishing only.
    RevokeWriteAccess { did: DID, scope: RevocationScope },
    /// Restore a member's write access to context content (§9.17).
    /// Always forward-only — previously suppressed content remains suppressed.
    RestoreWriteAccess { did: DID },
    /// Context-wide content key rotation (§9.17).
    /// Not identifier-targeted — rotates keys for all members.
    /// Use after compromise detection, bulk revocations, or periodic hygiene.
    RotateContentKeys { reason: Option<String> },
    /// Block an author in a broadcast context (§5.14.8).
    /// Removes the author from the broadcast context, destroying their sender
    /// key and preventing future publishing. Requires governance approval.
    BlockAuthor { did: DID, reason: Option<String> },
    /// Deadlock recovery: modify governance parameters without changing model type.
    /// Uses fallback quorum (majority-of-active) regardless of original model.
    /// See section 10 (Deadlock Recovery).
    ReconfigureGovernance { changes: Vec<GovernanceReconfigAction>, justification: DeadlockJustification },
    /// Set or update the context's economic policy (§19.3, ADR-033).
    /// Requires the economic policy to not be locked.
    SetEconomicPolicy { policy: EconomicPolicy },
    /// Approve a spending authorization for a member (§19.5, ADR-033).
    ApproveSpend { spender: DID, amount: Amount, purpose: String },
    /// Lock the context's economic policy, making it immutable (§19.3).
    /// Once locked, the economic policy cannot be changed through governance.
    LockEconomicPolicy,
    /// Set, change or remove the context's pseudonym rotation policy
    /// (`ContextParams.pseudonym_rotation`, 09-security-model.md §9.10.4.1).
    /// `None` stops every later rotation, and each member keeps the routing ID
    /// it holds. The action changes no MLS state.
    ModifyPseudonymRotationPolicy { new_policy: Option<PseudonymRotationPolicy> },
}

/// Scope of content access revocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationScope {
    /// Retroactive: destroy access keys for historical content AND
    /// exclude from future content key distribution.
    Full,
    /// Forward-only: exclude from future content key distribution.
    /// Historical content remains accessible with existing cached keys.
    FutureOnly,
}
```

**Amendment (2026-10-18, ADR-066): identifier fields are text-form identifiers.** Every identifier in this ADR's types has the type `DID`, the identifier in its 56-byte text form (`03-identity.md` §3.1), which RFC 8785 serializes as a JSON string in `action_bytes`. That covers the direct fields of `GovernanceAction` (`did`, `new_admin`, `spender`); the fields nested inside an action's `action_bytes`, which are `GovernanceReconfigAction::RemoveInactiveSigner.did`, `DeadlockJustification.unavailable_dids` and the identifier of each `missed_windows` pair (§10), and the `admin_did` and `signers` of a `GovernanceModel`; and the identifiers of the engine, record, and event types (`proposer`, `voter`, `members`, `admin_dids`, `proposer_did`, `voter_did`, `rejector`, `executor_did`). `ProposalId` alone stays `[u8; 32]`, because it is a hash. The types in this ADR typed these identifiers `[u8; 32]`, which RFC 8785 would serialize as an array of integers and which no receiver could check against `05-contexts.md` §5.9.1 check 3. A proposer and every receiver reject an action whose identifier field is not a valid 56-byte text form.

#### 4. Proposal Resolution Rules Per Model

**4a. SingleAdmin.** The admin's `propose()` call simultaneously creates and approves the proposal. The `approve()`/`reject()` methods are no-ops (return the current status). This preserves backward compatibility with Phase 2 behavior — single-admin governance is immediate and serialized.

**4b. Threshold (M-of-N).** A proposal passes when `threshold` signers from the `signers` set have approved. Resolution is checked after every vote:

- If `approvals.len() >= threshold`: status becomes `Approved`.
- If `rejections.len() > signers.len() - threshold`: approval is mathematically impossible, status becomes `Rejected { reason: ApprovalImpossible }`.
- If `now > voting_deadline` and neither condition met: status becomes `Expired`.

Votes are order-independent — the Mth approval resolves the proposal regardless of when or in what order the M votes arrived. Only the identities the `signers` set names can vote. A signer can withdraw their vote and re-vote (changing from approve to reject or vice versa) while the proposal is `Pending`.

**4c. Majority.** A proposal passes when approvals exceed 50% of eligible voters (all members holding `GovernanceVote` capability). Resolution:

- Let `eligible = eligible_voters.len()`, `participation = approvals.len() + rejections.len()`.
- If `participation / eligible < min_participation` when `now > voting_deadline`: status becomes `Rejected { reason: InsufficientParticipation }`.
- If `approvals.len() > eligible / 2`: status becomes `Approved` (early resolution — majority reached before deadline).
- If `rejections.len() >= eligible / 2`: status becomes `Rejected { reason: MajorityRejected }` (early rejection — approval impossible).
- If `now > voting_deadline` and `participation / eligible >= min_participation` and `approvals > rejections`: status becomes `Approved`.
- If `now > voting_deadline` and `participation / eligible >= min_participation` and `approvals <= rejections`: status becomes `Rejected { reason: MajorityRejected }`.

The eligible voter set is computed at proposal creation time and frozen for the proposal's lifetime. Members who join after proposal creation do not vote on it; members who leave have their votes removed.

**Amendment (2026-10-17, ADR-066).** A receiver decides whether a proposal executes from the executing Commit's contents alone (`07-trust-validation-and-capabilities.md` §7.3.1.1). The Commit carries the approvals the model requires, and every voter it does not carry counts as not approving. The eligible voters are the members holding `GovernanceVote` in the receiver's state before the executing Commit. This replaces the frozen set of the paragraph above: a member that left does not count, and a member that joined after the proposal was created may vote. A frozen set compares join points with the proposal's creation point, and the only creation point a receiver can check is the proposal's `anchor_seq`, which the proposer chooses, so a proposer that named an early anchor would drop every recent joiner. Adding a new member and removing a member are governance actions, so no proposer moves the count without the approvals that change needs; a member that leaves on its own removes only its own vote. The ADR-029 Tier 2 fast-forward and Tier 3 reset re-add a member that stays in the group, change no member, role, or join point, and so execute without approvals. The deadline arm of this section (approvals exceed rejections at minimum participation) needs the rejections, which an executor can omit without detection, so the Commit cannot prove it. Whether that arm survives is an open question in `00-open-questions.md`; until it is settled, a `Majority` proposal executes only when approvals exceed half of the eligible voters.

**4d. Unanimity.** Every eligible voter must approve. A single rejection defeats the proposal immediately:

- If all eligible voters have approved: status becomes `Approved`.
- If any eligible voter rejects: status becomes `Rejected { reason: UnanimityBroken { rejector } }`.
- If `now > voting_deadline` and not all have voted: status becomes `Expired`.

Unanimity is required by the spec (§5.10) for TTL extension and context promotion. The `ExtendTtl` and `PromoteContext` governance actions always require unanimity regardless of the context's governance model — this is a protocol-level override enforced by the `ContextManager`, not by the governance engine.

**Amendment (2026-10-18, ADR-066): the TTL override needs every current member.** Alec picked the option "Every member", which read: "Keep the spec's rule. Members joined expecting the context to expire, so none of them can have it extended or made permanent without their approval. The cost: every context with a TTL is limited to 96 members, including members who have no vote." `ExtendTtl` and `PromoteContext` therefore need an approval from every current member, in every model, `Threshold` included, and a member that holds no `GovernanceVote`, or under `Threshold` is no signer, approves them with the same vote record (`05-contexts.md` §5.9.1). The executing Commit carries all of them, at most 96 because a context with a TTL has at most 96 members (§2 amendment above, `07-trust-validation-and-capabilities.md` §7.3.1.1, the approvals table). This supersedes the earlier reading that under `Threshold` the override needs every signer. Every other `Threshold` approval counts only from a signer that is a current member holding `GovernanceVote`.

#### 5. Voting Windows and Timeout Handling

Every proposal has a `voting_deadline = created_at + voting_window_secs`. The voting window is configured per governance model at context creation and applies uniformly to all proposals in that context.

**Amendment (2026-10-17, ADR-066).** A proposal record carries no creation time; it carries `anchor_seq`, the commit-ordered leaf count its proposer held. Each member's engine starts the voting window when it accepts the proposal, and uses it only to decide locally when the proposal is `Expired`; no receiver's verdict on a Commit reads it, because a time the proposer chose cannot bound what every receiver accepts. A vote stops counting at a Commit sent after its `expires_epoch`, which the vote signs, or once the voter has replaced its leaf key, which is how a voter withdraws (`07-trust-validation-and-capabilities.md` §7.3.1.1). The epoch reset below replaces the reset member's leaf, so its earlier votes stop counting by the same rule.

**Timeout processing.** The SDK runs a background task (`GovernanceTimeoutTask`) that checks active proposals every 60 seconds. When a proposal's deadline passes without resolution, the task calls `resolve()` which transitions the proposal to `Expired` or `Rejected` (depending on model-specific rules). The timeout task also handles:

- **Proposer departure.** If the proposer leaves the context while a proposal is `Pending`, the proposal is `Invalidated`. The proposer's departure does not retroactively invalidate an already-approved proposal.
- **Voter departure.** If an eligible voter leaves the context, their vote is removed from the tally. This may change the resolution — if a Unanimity proposal had all approvals and one voter leaves, the proposal remains approved (the voter approved before leaving). If a voter leaves without having voted, the eligible voter set shrinks, which may make quorum easier to reach (Majority) or harder (Unanimity).
- **Epoch reset.** If a member undergoes a group state reset (ADR-029 Tier 3), their votes on pending proposals are invalidated (the reset changes their epoch context). The proposal is not automatically invalidated — other votes remain valid.

#### 6. UCAN Delegation in Multi-Admin Contexts

In single-admin governance, the context creator holds the root UCAN authority and delegates all capabilities. In multi-admin governance, UCAN authority is distributed:

**Root UCAN issuer.** The context creator remains the root UCAN issuer. This is a cryptographic necessity — the UCAN delegation chain must have a single root of trust (ADR-009 step 4: "root token's `iss` is the context creator's identifier"). The creator is not a privileged governor — they are the key ceremony initiator. One identity = one vote. The governance engine deduplicates by identifier, not by key.

**Governance capability distribution.** At context creation, the creator mints `GovernancePropose` and `GovernanceVote` UCAN tokens for each identifier that the governance model designates as a voter:

- `Threshold`: each identifier in `signers` receives `GovernancePropose` + `GovernanceVote`.
- `Majority`: each member whose role includes `GovernanceVote` capability receives those tokens at role assignment.
- `Unanimity`: same as Majority — all members with `GovernanceVote` in their role.

**Governance action execution.** When a proposal is approved, the governance engine returns the decision to the `ContextManager`. The `ContextManager` executes the action using the creator's root authority — it mints new UCANs, revokes old ones, modifies membership, etc. The governance engine does not execute actions; it only decides whether they are approved. This separation ensures that UCAN chains remain valid (the root issuer signs all delegations) while governance authority is distributed (multiple identifiers vote on whether to authorize the action).

**Signer set modification (Threshold model).** When a `Threshold` proposal to add or remove a signer is approved, the `ContextManager` mints or revokes `GovernanceVote` UCANs accordingly. Adding a signer requires the new identifier to already be a context member. Removing a signer does not remove them from the context — it only removes governance authority. The `threshold` value is validated after modification: if removing a signer would make `threshold > signers.len()`, the removal is rejected.

#### 7. Governance Conflict Resolution

ADR-029 section 5c defines the conflict scenario: two admins both offline simultaneously propose conflicting governance actions. When both reconnect, both proposals are committed to the event log. The first proposal committed to the Merkle log wins; the second is rejected as conflicting.

**Amendment (2026-10-17, ADR-066).** "Committed first" means merged first in MLS epoch order, and only one Commit merges per epoch. A Commit that loses the race for an epoch never merges anywhere; its executor re-checks the action against the state the winning Commit produced (the proposal is unexecuted, the proposer and executor are still members, the approvals still meet the model with removed voters dropped, and the action does not conflict: a listed action counts as executed after the proposal when its `GovernanceActionExecuted` leaf's `sequence` is at or after the proposal's `anchor_seq`, and an action about a member that joined or rejoined at or after `anchor_seq` conflicts too) and sends it again at the new epoch if it passes, or marks the proposal `Invalidated` if it fails. Every receiver applies the same conflict check before it merges (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 2). Two proposals can therefore never land at one sequence, and a mutual removal resolves by epoch order: the first removal removes the other proposer, whose Commit then fails the membership check. The governance freeze for mutual removal and for a simultaneous commit, the `GovernanceConflictDetected` and `GovernanceConflictResolved` events, the `GovernanceConflict` event, and the `ResolveConflict` action below no longer arise, and are removed. The conflict list below still decides which actions conflict.

**Amendment (2026-10-24, ADR-067).** The amendment above is corrected: more than one Commit can merge for one epoch, because two members can commit at it without seeing each other, and no relay or member can prevent that. "Committed first" means first on ADR-067's canonical path. A mutual removal made on two branches does not resolve by epoch order: both Removes are restrictive-only, so ADR-067's G keeps both. Cross-branch pairs are settled by ADR-067's G. On one branch, the re-check and the conflict check above still apply.

**Conflict detection.** The `GovernanceEngine` detects conflicts when two `Approved` proposals in the event log are incompatible:

- Two `RemoveMember` proposals targeting each other's proposers (mutual removal).
- Two `ChangeRole` proposals for the same identifier with different target roles.
- Two `ModifyCeiling` proposals with different ceiling sets.
- A `RemoveMember` and a `ChangeRole` for the same identifier.
- A `RevokeReadAccess` and a `RestoreReadAccess` for the same identifier (mutually contradictory).
- A `RevokeWriteAccess` and a `RestoreWriteAccess` for the same identifier (mutually contradictory).
- Two `RevokeReadAccess` proposals for the same identifier with different scopes (Full vs FutureOnly).
- Two `RevokeWriteAccess` proposals for the same identifier with different scopes (Full vs FutureOnly).
- An `AddMember` for X and a `RemoveMember` for X (ADR-067, conflict key `member:X`).

**Conflict resolution.** When a conflict is detected:

1. The proposal with the lower event log sequence number (earlier in Merkle log) wins. This is deterministic — all members compute the same winner.
2. The losing proposal's status becomes `Invalidated { reason: "Conflicting proposal {winner_id} committed first" }`.
3. A `GovernanceConflict` event is appended to the event log recording both proposal IDs, the winner, and the resolution method.
4. If the losing proposer still wants their action, they must re-propose with awareness of the winning proposal's effects.

**Mutual removal (always GovernanceFreeze).** When two proposals each remove the other's proposer (`RemoveMember { did: B }` proposed by A, and `RemoveMember { did: A }` proposed by B), the conflict always triggers a governance freeze regardless of leaf index ordering. Rationale: executing the first removal invalidates the authority of the second proposer, creating a paradox — if A's removal of B wins by log order, B no longer has authority to have proposed removing A, but B's proposal is already committed. This circular dependency cannot be resolved by simple ordering. The freeze includes ALL conflicting proposals in the set, not just the mutual-removal pair, so that no conflicts are silently dropped.

**Simultaneous commit (same sequence number).** If two conflicting proposals land at the exact same event log sequence (extremely rare — requires both to be appended in the same batch), the protocol enters a `GovernanceConflict` state:

1. The context is frozen for new governance actions — no new proposals accepted EXCEPT `ResolveConflict`. Message sending and outlet invocation continue normally.
2. A `GovernanceConflictDetected` event is emitted.
3. Resolution requires an explicit `ResolveConflict` governance action from any identity with `GovernanceVote` capability. The resolution specifies which proposal wins. `ResolveConflict` is explicitly exempt from the governance freeze — it is the designated mechanism for lifting the freeze.
4. The `ResolveConflict` action itself follows the context's governance model (requires threshold/majority/unanimity). This prevents unilateral conflict resolution.
5. If no resolution is reached within the voting window, both proposals are invalidated and the governance freeze is lifted. The context returns to its pre-proposal state.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Accept one proposal, invalidate the other.
    AcceptProposal { winner_id: ProposalId },
    /// Invalidate both proposals, return to pre-proposal state.
    InvalidateBoth,
}
```

#### 8. Interaction with MLS Epochs

Governance proposals and votes are MLS application messages (in Encrypted contexts) or broadcast messages (in Broadcast contexts). They do not trigger MLS epoch advances. ~~Only membership changes (add/remove) and MLS Updates trigger Commits.~~

**Amendment (2026-10-17, ADR-066): the struck clause no longer holds.** Every executed governance action triggers a Commit, membership change or not; an action that adds or removes no member uses a Commit with no proposals and an UpdatePath. The reason: application messages from different senders have no order every member shares, so a demotion applied from an application message and the demoted admin's next action could be applied in different orders at different members, and their role states would fork. A Commit fixes one order at every member, because a member cannot read a message of the new epoch before it has processed the Commit. The Commit carries the action's proposal, its signed approving votes, and its event-log leaves in one fixed-size encrypted block (`07-trust-validation-and-capabilities.md` §7.3.1.1), and the proposal and vote messages themselves are specified in `05-contexts.md` §5.9.1.

However, governance actions that result in membership changes (approved `AddMember` or `RemoveMember` proposals) do trigger MLS operations, which advance the epoch. The sequence is:

1. Proposal approved (governance decision).
2. `ContextManager` executes the membership change (MLS `add_member()`/`remove_member()`).
3. MLS Commit advances the epoch.
4. `GovernanceActionExecuted` event appended to event log (records proposal ID, action, executor identifier, resulting epoch). **Amendment (2026-10-18, ADR-066):** the leaf records `target_did`, `action_type`, `proposal_id`, and `action_bytes`, each derived from the executed proposal; the executor is the leaf's `actor_did`, and the leaf records no resulting epoch, because the Commit that carries it fixes the epoch and a receiver could not check a value the committer wrote (acceptance criterion 7 amendment).

**Amendment (2026-10-17, ADR-066).** The executor builds the `GovernanceActionExecuted` leaf and every other leaf of the action before step 3 and sends them in the Commit, so step 4 happens at every member as it processes that Commit; a non-committer applies the action only by processing the Commit.

Pending proposals are NOT invalidated by epoch advances. A proposal created at epoch E is valid at epoch E+N — the proposal references a governance action, not an epoch-specific state. A group state reset (ADR-029 Tier 3) does not invalidate them either. **Amendment (2026-10-17, ADR-066):** the reset re-adds a member that stays in the group, with its role and join point unchanged, so a pending proposal the reset member made or voted on stays pending; its signatures stop matching the member's replaced leaf key, and the member re-signs them (`05-contexts.md` §5.9.1).

#### 9. Interaction with Checkpointing (ADR-030)

ADR-030 defines checkpoint cosignatures for multi-admin contexts. The requirement is:

- In `SingleAdmin` contexts, only the admin signs checkpoints. `cosignatures` is empty.
- In `Threshold` contexts, checkpoints require `threshold` signatures from the signer set. The checkpoint creator collects signatures by distributing the checkpoint to other signers, who verify it and cosign the hash that ADR-030 §1's checkpoint signature preimage amendment gives with each signer's own `key_state_head`.
- In `Majority` contexts, checkpoints require signatures from >50% of eligible voters.
- In `Unanimity` contexts, checkpoints require signatures from all eligible voters.

Checkpoint cosignature collection follows the same voting-window pattern as governance proposals but with a shorter default window (1 hour). If the cosignature quorum is not reached, the creator flags the checkpoint `PartiallyAttested`; no member adopts or prunes against a checkpoint short of its quorum. **Amendment (2026-10-20, ADR-066 decision 24).** In an encrypted context a checkpoint short of its quorum is never committed: the checkpoint Commit carries the full quorum, and every receiver rejects one that lacks it (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6). `PartiallyAttested` is a flag local to the creator, for a checkpoint whose window closed short of the quorum; that checkpoint reaches no log, and no member prunes against it. The window is local to the creator and the cosigners, and no receiver reads it.

#### 10. Deadlock Recovery

Deadlock occurs when the governance model requires votes from members that are permanently unavailable (key loss, extended offline beyond Tier 3, deliberate non-participation).

**Detection.** A governance model is in deadlock when:

- `Threshold`: fewer than `threshold` signers are active context members (signers who left or were removed are no longer eligible).
- `Majority`: fewer than `ceil(eligible_voters * min_participation_bps / 10000)` members are responsive (no vote cast within 3 consecutive voting windows).
- `Unanimity`: any eligible voter has been offline beyond the Tier 3 threshold (7+ days) with no response to proposals.

**Recovery protocol.** When deadlock is detected:

1. Any member with `GovernancePropose` capability can propose a `GovernanceAction::ReconfigureGovernance` action via the standard `propose()` interface. This is a governance action that modifies the governance model's parameters (e.g., reducing `threshold`, removing inactive signers) without changing the model type.
2. The `ReconfigureGovernance` proposal follows a fallback quorum: the remaining active voters use majority-of-active as the quorum rule, regardless of the original governance model. The governance engine detects the `ReconfigureGovernance` variant and applies the fallback quorum instead of the context's normal resolution rules. This prevents a dead signer from permanently blocking all governance.
3. The fallback is logged as a `GovernanceDeadlockRecovery` event in the event log with full justification (which signers are unavailable, how long, what the original quorum was).
4. Members who disagree with the deadlock recovery can exercise exit-as-veto (§9.2.1) — leave the context.

```rust
// ReconfigureGovernance is now a GovernanceAction variant (see section 2).
// Supporting types:

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceReconfigAction {
    /// Remove an inactive signer (Threshold model).
    RemoveInactiveSigner { did: DID },
    /// Reduce the threshold (Threshold model). New value must be
    /// >= 1 and <= remaining active signers.
    ReduceThreshold { new_threshold: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockJustification {
    /// The identifiers that are unavailable.
    pub unavailable_dids: Vec<DID>,
    /// Evidence of unavailability: consecutive missed voting windows.
    pub missed_windows: Vec<(DID, u32)>,
    /// Timestamp of deadlock detection.
    pub detected_at: u64,
}
```

**Deadlock recovery constraints:**

- The governance model TYPE is never changed by deadlock recovery. A `Threshold` context remains `Threshold`. To change the model type, create a new context.
- The fallback quorum (majority-of-active) requires at least 2 active voters. If only 1 voter remains, they effectively have single-admin authority — this is logged and visible to all members.
- Deadlock recovery proposals have a 48-hour voting window (double the default) to give absent members time to respond before their authority is reduced.

### Rationale

**Why four models, not more:**

The four models — SingleAdmin, Threshold, Majority, Unanimity — cover the practical governance space for SCP contexts. SingleAdmin is the Phase 2 baseline, needed for backward compatibility and simple contexts. Threshold is the most commonly requested multi-admin pattern ("2-of-3 admins") and has the simplest, most predictable semantics. Majority scales to larger groups where threshold enumeration is impractical. Unanimity satisfies the spec's requirement for TTL extension (§5.10) and ceiling changes in high-stakes contexts. Weighted voting and delegated governance were considered but deferred: they require a stake/token mechanism or a delegation graph that SCP v1 does not provide, and they add complexity without clear demand from the initial use cases.

**Why governance model is immutable:**

Changing the governance model after creation is a fundamental change to the opt-in contract. Members joined knowing "this context uses 2-of-3 threshold governance." Switching to majority vote changes the power dynamics retroactively. Making the model immutable prevents governance bait-and-switch — the same principle behind immutable capability ceilings (ADR-009). If a different governance model is needed, create a new context and migrate. The threshold value and signer set CAN be modified through governance (they are parameters within the model, not the model itself), but the model type cannot.

**Why order-independent votes with withdrawal:**

Order-independent votes are simpler to reason about: the Mth approval triggers resolution regardless of when it arrives. Order-sensitive votes (where the sequence of approvals matters) add complexity without benefit — the governance decision is the same regardless of whether Alice or Bob approved first. Vote withdrawal enables members to change their mind based on new information (e.g., discussion in the context about the proposal). Without withdrawal, a premature approval is irreversible, which discourages early voting.

**Why Merkle log order for conflict resolution:**

ADR-029 section 5c already establishes Merkle log order as the authoritative ordering for concurrent operations. Using the same mechanism for governance conflicts maintains consistency — no new conflict resolution primitive is needed. The determinism is critical: all members compute the same winner from the same log, so there is no disagreement about which proposal won.

**Why the fallback quorum for deadlock recovery:**

Without a deadlock recovery mechanism, a Threshold(3-of-5) context where 3 signers lose their keys is permanently frozen — no governance action can ever pass. The fallback quorum (majority of remaining active voters) is the least disruptive recovery: it preserves the model type, requires majority agreement among the remaining participants, and is fully logged. The alternative — no recovery, context must be abandoned — wastes the context's history, outlet registrations, and ongoing work. The 48-hour voting window for recovery proposals gives absent members extra time to return, reducing false deadlock detection.

**Why the context creator remains the UCAN root:**

UCAN delegation chains require a single root issuer (ADR-016 step 4). Distributing root authority across multiple identifiers would require multi-signature UCAN tokens, which the UCAN spec does not support. The creator-as-root pattern is already established in Phase 2 and works well: the creator's cryptographic role (root issuer) is decoupled from their governance role (which may be no more than any other signer in a Threshold model). The creator cannot unilaterally mint capabilities that bypass governance — all capability changes go through the governance engine.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (voting window timers, deadlock detection background task)
- **Crate:** `scp-core`
- **Module:** `scp-core/governance/`
- **Persistence:** Via `ProtocolRepository` (§17.4). Key conventions:
  - `context/{context_id}/governance/config` — serialized `GovernanceModelConfig`
  - `context/{context_id}/governance/proposal/{proposal_id_hex}` — active proposals
  - `context/{context_id}/governance/proposal_index/pending` — list of pending proposal IDs
  - `context/{context_id}/governance/proposal_index/resolved` — list of resolved proposal IDs
  - `context/{context_id}/governance/deadlock_state` — deadlock detection state

### Dependencies

- **ADR-008 (Context Lifecycle):** The `ContextManager` delegates governance decisions to the `GovernanceEngine`. Context creation includes `GovernanceModelConfig` in `ContextParams`. The governance model constrains which context operations require proposals (all multi-admin operations) vs. which are immediate (message sending, outlet invocation — these are UCAN-authorized, not governance-gated).
- **ADR-009 (Roles/UCAN):** `GovernancePropose` and `GovernanceVote` are capabilities in the `Capability` enum. Governance UCAN tokens are minted at role assignment and validated on every `propose()`, `approve()`, and `reject()` call. The capability ceiling bounds governance capabilities the same as any other capability.
- **ADR-011 (Event Log):** Governance proposals, votes, resolutions, conflicts, and deadlock recoveries are event log entries. The Merkle log provides the authoritative ordering for conflict resolution.
- **ADR-016 (UCAN Validation):** The full 11-step UCAN validation pipeline applies to governance operations. Governance UCANs follow the same delegation chain, nonce uniqueness, and revocation rules as all other UCANs.
- **ADR-029 (Offline/Sync):** Concurrent governance conflict resolution (section 5c) is formalized by this ADR. Group state resets invalidate pending proposals. Reconnecting members catch up on governance state through event log sync.
- **ADR-030 (Event Log Pruning):** Checkpoint cosignature requirements are defined per governance model. `GovernanceAction` events are structural events with 3x retention multiplier.

### Acceptance Criteria

1. **`GovernanceEngine` trait and `GovernanceModelConfig` enum:**

```rust
// GovernanceEngine trait with propose/approve/reject/withdraw_vote/resolve/model_config/eligible_voters.
// GovernanceModelConfig with SingleAdmin, Threshold, Majority, Unanimity variants.
// Validation: GovernanceModelConfig::validate() -> Result<(), GovernanceError>
//   - Threshold: 1 <= threshold <= signers.len(), signers non-empty, window in [300, 604_800]
//   - Majority: min_participation_bps in (0, 10000], window in [300, 604_800]
//   - Unanimity: window in [300, 604_800]
```

2. **`GovernanceProposal` struct and `GovernanceAction` enum:**

   - `GovernanceProposal` with `proposal_id`, `context_id`, `proposer_did`, `action`, `status`, `created_at`, `voting_deadline`, `approvals`, `rejections`, `created_at_epoch`.
   - `GovernanceAction` with all 30 variants listed in section 3 (including content access actions: RevokeReadAccess, RestoreReadAccess, RevokeWriteAccess, RestoreWriteAccess, RotateContentKeys; broadcast action: BlockAuthor; economic actions: SetEconomicPolicy, ApproveSpend, LockEconomicPolicy; outlet action: SetOutletRegistrationPolicy, ADR-066 decision 31; pseudonym action: ModifyPseudonymRotationPolicy) and `RevocationScope` enum (Full, FutureOnly). Section 3 lists no migration action; the migration actions of spec 05 §5.11A are not counted in the 30.
   - `ProposalStatus` with `Pending`, `Approved`, `Rejected`, `Expired`, `Cancelled`, `Invalidated`.
   - Proposals are persisted to `ProtocolRepository` on creation and on every status change.

3. **`SingleAdminEngine` implementation:**

   - `propose()` creates a proposal and immediately sets status to `Approved` if the proposer is the admin. Returns `GovernanceError::NotAdmin` if proposer is not the admin.
   - **Content access revocation cool-down:** `RevokeReadAccess` and `RevokeWriteAccess` actions in `SingleAdmin` contexts MUST deliver the revocation notification to the affected member before executing the access key deletion. This prevents silent, instant silencing with no recourse. The affected member receives the notification and can exercise exit-as-veto (§9.2.1) or appeal to other context members. The cool-down does not apply to multi-admin models (which already require governance approval from multiple parties).
   - `approve()`/`reject()` return current status (no-op).
   - `cancel()` sets status to `Cancelled` if the proposal is `Pending` and the caller is the admin. Returns error otherwise.
   - `eligible_voters()` returns `[admin_did]`.

4. **`ThresholdEngine` implementation:**

   - `propose()` creates a `Pending` proposal. The proposer's vote counts as the first approval.
   - `approve()` adds a `SignedVote` if the voter is in `signers` and has not already voted. Calls `resolve()`.
   - `reject()` adds a rejection vote. Calls `resolve()`.
   - `resolve()` returns `Approved` if `approvals.len() >= threshold`, `Rejected` if `rejections.len() > signers.len() - threshold`, `Expired` if past deadline.
   - `withdraw_vote()` removes the voter's vote. Returns error if proposal is not `Pending`.
   - `eligible_voters()` returns the `signers` set.

5. **`MajorityEngine` implementation:**

   - `propose()` creates a `Pending` proposal. Freezes the eligible voter set at creation time.
   - `approve()`/`reject()` add votes if voter is in the frozen eligible set.
   - `resolve()` applies the resolution rules from section 4c: early approval if > 50%, early rejection if approval impossible, participation check at deadline.
   - `eligible_voters()` returns all members with `GovernanceVote` capability at the time of the call.

6. **`UnanimityEngine` implementation:**

   - `propose()` creates a `Pending` proposal. Freezes the eligible voter set.
   - `approve()` adds approval. If all eligible voters have approved, status becomes `Approved`.
   - `reject()` immediately sets status to `Rejected { reason: UnanimityBroken { rejector } }`.
   - `resolve()` returns `Expired` if past deadline and not all have voted.

7. **Event types added to `EventType` enum (ADR-011):**

```rust
// Additions to EventType in scp-core/event_log/
GovernanceProposalCreated {
    proposal_id: ProposalId,
    proposer_did: DID,
    action: GovernanceAction,
    voting_deadline: u64,
},
GovernanceVoteCast {
    proposal_id: ProposalId,
    voter_did: DID,
    vote: VoteType,
},
GovernanceVoteWithdrawn {
    proposal_id: ProposalId,
    voter_did: DID,
},
GovernanceProposalResolved {
    proposal_id: ProposalId,
    status: ProposalStatus,
    executor_did: Option<DID>,
    resulting_epoch: Option<u64>,
},
GovernanceConflictDetected {
    proposal_a: ProposalId,
    proposal_b: ProposalId,
},
GovernanceConflictResolved {
    winner_id: Option<ProposalId>,
    resolution: ConflictResolution,
},
GovernanceDeadlockRecovery {
    justification: DeadlockJustification,
    changes: Vec<GovernanceReconfigAction>,
},
GovernanceActionExecuted {
    proposal_id: ProposalId,
    action: GovernanceAction,
    executor_did: DID,
    resulting_epoch: Option<u64>,
},
```

**Amendment (2026-10-17, ADR-066).** The `GovernanceActionExecuted` leaf carries the action as `action_bytes: Vec<u8>`, the proposal's exact RFC 8785 bytes that the proposer signed into `proposal_id`, verbatim, in place of a decoded `action`, beside `target_did` (the member the action targets, empty when it targets none) and `action_type` (the `GovernanceAction` variant name), which the consequence engine reads. Its payload is `[target_did, action_type, proposal_id, action_bytes]`, in that order, with `proposal_id` and `action_bytes` as MessagePack binaries (`serde_bytes`). `target_did` is the action's `did` field in text form, or `new_admin` for `TransferAdmin`, and the empty string for an action with neither; `action_type` is the variant name; `proposal_id` is the one every receiver recomputes. **Amendment (2026-10-18, ADR-066):** `executor_did` and `resulting_epoch` are removed. The executor is the leaf's `actor_did`, which every receiver checks is the committer, and the Commit that carries the leaf fixes the epoch; a receiver could not check either field against anything the voters signed. Every receiver derives each field and rejects a Commit whose leaf differs (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6). A member that applies the leaf decodes the action from `action_bytes`. The executing Commit's block carries the proposal without `action_bytes` (`05-contexts.md` §5.9.1, block proposal record), so this leaf is the action's one copy in the Commit, and every receiver recomputes `proposal_id` from it (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.3).

8. **Governance timeout background task:**

   - `GovernanceTimeoutTask` runs every 60 seconds per context with active proposals.
   - Calls `resolve()` on each pending proposal to check for expiry.
   - Detects voter departures and adjusts tallies.
   - Detects deadlock conditions (consecutive missed voting windows per voter).

9. **Protocol-level unanimity override for TTL extension and context promotion:**

   - When a `GovernanceAction::ExtendTtl` proposal is created in a non-Unanimity context, the `ContextManager` overrides the governance model's resolution rules and requires approval from ALL current members (not just governance voters). This enforces §5.10's requirement that TTL extension requires unanimous consent.
   - When a `GovernanceAction::PromoteContext` proposal is created in a non-Unanimity context, the same unanimity override applies. This enforces §5.10's requirement that promotion from ephemeral to persistent requires consent from all current members.
   - **Amendment (2026-10-18, ADR-066).** The executing Commit carries the consent as approvals from every current member, in every model, `Threshold` included, and a member without `GovernanceVote` approves with a `05-contexts.md` §5.9.1 vote record (Alec's ruling of 2026-10-18, §4 amendment). Every receiver of the Commit enforces the override (`07-trust-validation-and-capabilities.md` §7.3.1.1 steps 1.4 and 1.5), not only the `ContextManager` that creates the proposal.

10. **Integration test:**

```
1. Alice creates a context with Threshold(2-of-3, signers: [Alice, Bob, Carol]).
2. Verify: Alice, Bob, Carol all receive GovernancePropose + GovernanceVote UCANs.
3. Alice proposes AddMember { did: Dave, role: "member" }.
   Event log records GovernanceProposalCreated.
   Alice's proposal counts as first approval.
4. Dave is NOT yet a member (proposal is Pending, 1-of-2 approvals).
5. Bob approves. Proposal reaches threshold (2-of-3). Status -> Approved.
   Event log records GovernanceVoteCast, GovernanceProposalResolved.
   ContextManager executes: Dave is added via MLS add_member().
6. Dave is now a member with role "member".

--- Rejection test ---
7. Alice proposes RemoveMember { did: Dave }.
8. Bob rejects. Carol rejects. Rejections (2) > signers (3) - threshold (2) = 1.
   Proposal status -> Rejected { reason: ApprovalImpossible }.
   Dave remains a member.

--- Vote withdrawal test ---
9. Alice proposes ChangeRole { did: Dave, new_role: "observer" }.
10. Bob approves (1-of-2 needed). Before Carol votes, Bob withdraws.
    Approvals drop to 1 (Alice only). Proposal still Pending.
11. Carol approves. Threshold met. Proposal Approved.

--- Expiry test ---
12. Alice proposes CloseContext. Voting window: 300 seconds.
13. Simulate time advance past voting window. No quorum reached.
    GovernanceTimeoutTask fires. Proposal status -> Expired.

--- Conflict test ---
14. Alice and Bob both go offline.
15. Alice proposes ChangeRole { did: Dave, role: "admin" }.
    Bob proposes RemoveMember { did: Dave }.
16. Both reconnect. Both proposals committed to event log.
    Alice's proposal has lower sequence number -> wins.
    Bob's proposal -> Invalidated.
    GovernanceConflictDetected event recorded.

--- Unanimity test ---
17. Create a separate context with Unanimity governance.
18. Alice proposes AddMember { did: Eve }.
19. Bob approves. Carol approves. Alice already approved (proposer).
    All eligible voters approved. Status -> Approved.
20. Alice proposes RemoveMember { did: Eve }.
21. Bob rejects. Status -> Rejected { reason: UnanimityBroken { rejector: Bob } }.

--- Majority test ---
22. Create a context with Majority governance, min_participation: 0.5.
    Members: Alice, Bob, Carol, Dave, Eve (5 eligible voters).
23. Alice proposes RegisterOutlet { ... }.
24. Alice, Bob, Carol approve (3/5 > 50%). Early resolution -> Approved.

--- Deadlock recovery test ---
25. Create a Threshold(3-of-4, signers: [Alice, Bob, Carol, Dave]) context.
26. Carol and Dave leave the context.
27. Alice proposes AddMember. Only Alice and Bob can vote.
    threshold (3) > active signers (2). Deadlock detected.
28. Alice proposes ReconfigureGovernance: remove Carol, remove Dave,
    reduce threshold to 2.
29. Fallback quorum: majority of active voters (2). Alice + Bob approve.
    Governance reconfigured. GovernanceDeadlockRecovery event logged.
30. Alice re-proposes AddMember. Now 2-of-2 threshold. Alice + Bob approve.
    Proposal passes.
```

### Scope

**Files (~6-8):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `GovernanceEngine` trait, `GovernanceModelConfig`, `GovernanceAction`, `ProposalStatus`, `GovernanceProposal`, re-exports |
| `single_admin.rs` | `SingleAdminEngine` — auto-approve on propose, admin transfer |
| `threshold.rs` | `ThresholdEngine` — M-of-N vote collection, signer set management, threshold modification |
| `majority.rs` | `MajorityEngine` — majority vote, participation threshold, frozen voter set |
| `unanimity.rs` | `UnanimityEngine` — all-or-nothing voting, immediate rejection on any dissent |
| `proposal.rs` | `GovernanceProposal` lifecycle, `SignedVote`, vote withdrawal, proposal persistence, conflict detection |
| `deadlock.rs` | Deadlock detection, `ReconfigureGovernance`, fallback quorum, `DeadlockJustification` |
| `timeout.rs` | `GovernanceTimeoutTask`, periodic proposal resolution, voter departure handling, epoch invalidation |

**Estimated functions:** ~25-30 public functions, ~15-20 internal helpers.

## ADR-038: Content Access Key Layer

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling).

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, left an identity one operational key, so the access-key lookup has one key to find (`09-security-model.md` §9.1 invariant 1).

**Amendment (2026-09-10 — access-key distribution runs over DHKEM(P-256)).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. The access-key distribution is DHKEM(P-256, HKDF-SHA256) under HPKE Base mode, the ephemeral wrapping keypair a requester generates is a DHKEM(P-256) keypair, and the request's `signature` field carries the type `P256Signature`. The pull-based model, the `info` and AAD constructions, and the per-epoch rotation are untouched.

### Context

The sender-side key layer (ADR-007, §9.16) provides selective readability through key distribution denial: when Alice blocks Dave, she rotates her sender key and denies Dave's re-request. This prevents Dave from decrypting Alice's future messages. However, it has three gaps:

1. **No retroactive enforcement.** Dave retains cached sender keys from before the block and can continue decrypting historical messages. The block is future-only at Layer 1.
2. **No SDK-mandated cleanup.** The protocol does not require Dave's SDK to destroy cached material. A non-compliant SDK could retain everything.
3. **No relay-level enforcement.** The relay stores ciphertext encrypted with the sender key. Anyone who retains the sender key can decrypt it, even after a block — the relay cannot distinguish authorized from unauthorized decryption.

PR #243 review identified that these gaps are unacceptable for the protocol's user promise: "if you're blocked, you can't see anything — past or future." Three additional enforcement layers are needed: SDK-mandated destruction (Layer 2, specified in §9.16.7), access key wrapping (Layer 3, this ADR), and governance-gated content access control (ADR-031 content access actions).

This ADR specifies Layer 3: the per-member access key wrapping model that provides cryptographic revocation of stored content.

### Scope

**What this ADR covers:**

- Per-member access key lifecycle (generation, distribution, revocation, restoration).
- Content Encryption Key (CEK) generation and wrapping with AES-256-KW.
- Revocation mechanics: Full (retroactive) and FutureOnly.
- Restoration mechanics: forward-only, no re-wrapping of historical content.
- Interaction with MLS (encrypted contexts) and sender keys (broadcast contexts).
- Wire format for wrapped content.
- Performance characteristics and scaling guidance.
- SDK-mandated destruction requirements (cross-reference to §9.16.7).

**What this ADR does NOT cover:**

- Sender-side key rotation protocol (ADR-007).
- Governance proposal lifecycle for content access actions (ADR-031).
- Identity-level block list storage and propagation (§3.7.1).
- MLS group management (ADR-001).

### Decision

Implement a per-member access key wrapping layer in `scp-core/crypto/access_keys/`. Each context member holds an AES-256 access key generated at join time. Content Encryption Keys (CEKs) are wrapped with each intended recipient's access key using AES-256-KW (RFC 3394). Deleting a member's access key from all compliant clients makes stored ciphertext undecryptable — cryptographic revocation that the sender-key layer alone cannot provide.

#### 1. Key Types

```rust
/// Per-member access key for content decryption in a context.
/// Generated at join time, destroyed on revocation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccessKey {
    /// AES-256 key material (32 bytes).
    key: [u8; 32],
    /// Context this key belongs to.
    context_id: ContextId,
    /// The identifier this key belongs to.
    member_did: [u8; 32],
    /// Epoch counter — incremented on rotation (restoration generates new key).
    epoch: u64,
}

/// Content Encryption Key — ephemeral, per-message.
/// Generated fresh for each message, used once, then discarded.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentEncryptionKey {
    key: [u8; 32],
}

/// A CEK wrapped (encrypted) with a member's access key.
pub struct WrappedCek {
    /// Truncated SHA-256 of the member's identifier (first 8 bytes).
    /// Used as lookup key in the wrapped_ceks map.
    pub member_id: [u8; 8],
    /// AES-256-KW wrapped CEK (40 bytes: 32-byte key + 8-byte integrity check).
    pub wrapped_key: [u8; 40],
}
```

#### 2. Access Key Lifecycle

**Generation.** When `AddMember` executes (via governance), the executor generates a fresh random 32-byte AES-256 access key for the new member. The access key is distributed via HPKE Base mode (RFC 9180) using the same pull-based protocol and suite as sender keys (ADR-007, §9.16.2): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The new member sends an `AccessKeyRequest`, the key holder responds with `AccessKeyResponse` containing the HPKE-sealed access key. The HPKE `info` parameter MUST use a distinct domain separator: `info = "scp-access-key-v1" || context_id || member_did || epoch_bytes`. The `aad` parameter is: `aad = context_id || member_did || epoch_bytes`. Where `epoch_bytes` is the 8-byte big-endian encoding of the access key epoch. Sender keys use `"scp-sender-key-v1"` and broadcast keys use `"scp-broadcast-key-v1"`. This prevents cross-protocol key confusion where a compromised access key response could be replayed as a sender key response — different `info` values produce different HPKE key schedules.

**Distribution.** Access keys are distributed via two new wire types:

```rust
pub struct AccessKeyRequest {
    pub requester_did: [u8; 32],
    pub context_id: ContextId,
    pub epoch: u64,
    pub timestamp: u64,  // Unix milliseconds; requests older than 30s are rejected
    pub wrapping_pubkey: HpkeP256PublicKey,  // Ephemeral, per-request
    /// Which operational role signed: "#active".
    pub signing_key_id: String,
    /// P-256 signature over: SHA-256(context_id || requester_did || signing_key_id || epoch || timestamp || wrapping_pubkey)
    /// using the requester's Active Signing Key. Prevents replay and impersonation.
    pub signature: P256Signature,
}

pub struct AccessKeyResponse {
    pub context_id: ContextId,
    pub member_did: [u8; 32],
    pub epoch: u64,
    pub hpke_sealed_key: Vec<u8>,
    pub ephemeral_pubkey: HpkeP256PublicKey,
}
```

**Normal operation.** On each message send:

1. Generate a fresh CEK (32 random bytes).
2. Encrypt the message content with AES-256-GCM using the CEK.
3. For each intended recipient: wrap the CEK with AES-256-KW using the recipient's access key. The wrapping operation is signed by the sender's Active Signing Key.
4. Publish: `{ ciphertext, nonce, wrapped_ceks }`. Integrity is verified by the AES-256-GCM authentication tag — no separate content hash is stored.

On receive:

1. Look up own `member_id` (truncated identifier hash) in `wrapped_ceks`. Note: the lookup is by identifier and not by signing key, so every operation an identity performs shares one access key.
2. Unwrap the CEK with own access key using AES-256-KW.
3. Decrypt the ciphertext with AES-256-GCM using the unwrapped CEK. The AEAD authentication tag verifies integrity.

**Revocation (Full).** On `RevokeReadAccess { did, scope: Full }` or identity-level block:

1. Broadcast `AccessKeyRevoked { did, scope: Full, timestamp }` event.
2. All compliant SDKs delete the target's access key from their local key store.
3. The target's SDK destroys its own access key (Layer 2, §9.16.7).
4. Future messages do not include a wrapped CEK for the target.
5. Historical wrapped CEKs for the target are now permanently undecryptable — the access key needed to unwrap them no longer exists on any compliant client.

**Revocation (FutureOnly).** On `RevokeReadAccess { did, scope: FutureOnly }`:

1. Add the target to the exclusion list for future CEK wrapping.
2. Future messages do not include a wrapped CEK for the target.
3. The target retains their existing access key — historical content remains decryptable.

**Restoration.** On `RestoreReadAccess { did }` or unblock:

1. Generate a NEW access key for the target (new epoch).
2. Distribute via pull-based protocol.
3. Future messages include a wrapped CEK for the target using the new key.
4. Historical wrapped CEKs used the old (destroyed) access key — permanently inaccessible.

**Context-wide rotation.** On `RotateContentKeys { reason }`:

1. Generate new access keys for ALL members.
2. Distribute via pull-based protocol.
3. Members retain old access keys for historical decryption.
4. Future content uses new CEKs wrapped with new access keys.

#### 3. Encryption Layer Ordering

**Encrypted contexts:**

```
Send:    plaintext → AES-GCM(CEK) → {ciphertext, wrapped_ceks} → sender_key_encrypt → MLS_encrypt → relay
Receive: relay → MLS_decrypt → sender_key_decrypt → unwrap_cek → AES-GCM_decrypt(CEK) → plaintext
```

**Broadcast contexts:**

```
Send:    plaintext → AES-GCM(CEK) → {ciphertext, wrapped_ceks} → broadcast_key_encrypt → relay
Receive: relay → broadcast_key_decrypt → unwrap_cek → AES-GCM_decrypt(CEK) → plaintext
```

The access key layer sits innermost (closest to plaintext) because it provides per-member selectivity that is independent of the group-level encryption (MLS/broadcast key) and the sender-level selectivity (sender key).

#### 4. Wire Format

```rust
/// Content with per-member access-key-wrapped CEKs.
pub struct WrappedContent {
    /// AES-256-GCM encrypted content.
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Per-recipient wrapped CEKs.
    /// Key: first 8 bytes of SHA-256(member_did) — prevents identifier publication.
    /// Value: AES-256-KW wrapped CEK (40 bytes).
    pub wrapped_ceks: Vec<WrappedCek>,
}
// Integrity is verified by AES-256-GCM's authentication tag.
// No separate content_hash field — storing SHA-256(plaintext) alongside
// ciphertext would create a plaintext confirmation oracle for low-entropy
// messages, allowing attackers to verify guesses without the access key.
```

The `wrapped_ceks` field uses a `Vec<WrappedCek>` (not a HashMap) for deterministic serialization and to avoid hash-table overhead in the wire format. Recipients scan linearly for their `member_id` — for typical context sizes (<1000 members), linear scan is faster than hash lookup.

#### 5. SDK-Mandated Destruction Cross-Reference

Layer 2 (§9.16.7) and Layer 3 (this ADR) are complementary:

- **Layer 2** requires the target's SDK to destroy cached material from the blocker.
- **Layer 3** requires all SDKs to destroy the target's access key.

Together: the target cannot decrypt historical content (Layer 3 — access key gone from all clients) AND the target's local cache is purged (Layer 2 — cached plaintext destroyed). Each layer handles a distinct threat surface that the other cannot:

| Layer | Uniquely handles |
|-------|-----------------|
| 1 (key denial) | Immediate future message protection, O(1) |
| 2 (SDK destruction) | Cached plaintext on target's device (compliance, not cryptographic) |
| 3 (access key) | Retroactive ciphertext revocation at relay |

The layers are not redundant — they cover distinct failure modes.

### Rationale

**Why AES-256-KW (RFC 3394) for key wrapping:**

AES-256-KW is the standard key-wrapping algorithm used by JOSE/JWE, CMS, and HPKE. It provides integrity protection (8-byte check value) without requiring a nonce or IV — the wrapping is deterministic, which simplifies the wire format (no per-recipient nonce storage). The 40-byte output (32 key + 8 check) is compact. Alternative: HPKE per recipient — more complex, requires per-recipient ephemeral keypairs, larger wire format. AES-256-KW is simpler and sufficient because the access keys are symmetric (no need for public-key wrapping).

**Why per-message CEKs:**

A per-message CEK limits the blast radius of key compromise: one compromised CEK reveals one message, not the entire conversation. This is standard practice (Signal, MLS, age). The alternative — reusing a content key across multiple messages — would make the access key revocation mechanism less granular.

**Why truncated identifier hashes in wrapped_ceks:**

Publishing full identifiers in the wrapped_ceks map would leak membership information to anyone who can observe the ciphertext (relays, network observers). The truncated 8-byte hash provides a lookup key that the recipient can compute from their own identifier but that does not reveal the identifier to observers. Collision probability for 8-byte hashes is ~1 in 10^18 — negligible for any practical context size.

**Why forward-only restoration:**

The access key is destroyed on Full revocation and not archived. Re-wrapping historical CEKs with a new access key would require: (1) all senders to re-encrypt historical messages, which is impractical for large histories; and (2) retaining old access keys somewhere, which defeats the purpose of destruction. Forward-only restoration is the correct design: it enforces the user promise that blocked content is gone, and it avoids the complexity and security risks of historical re-wrapping.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (for pull-based key distribution)
- **Crate:** `scp-core`
- **Module:** `scp-core/crypto/access_keys/`
- **Persistence:** Via `ProtocolRepository` (§17.4). Key conventions:
  - `context/{context_id}/access_key/{did_hex}` — member's access key (encrypted at rest)
  - `context/{context_id}/access_key/{did_hex}/epoch` — current epoch counter
  - `context/{context_id}/access_key/exclusion_list` — identifiers excluded from future wrapping
  - `context/{context_id}/access_key/revocation_log` — append-only revocation events

### Dependencies

- **ADR-007 (Sender Key Layer):** Pull-based key distribution protocol reused for access key distribution. `AccessKeyRequest`/`AccessKeyResponse` follow the same pattern as `SenderKeyRequest`/`SenderKeyResponse`.
- **ADR-001 (MLS):** Access key layer sits inside MLS encryption in encrypted contexts.
- **ADR-008 (Context Lifecycle):** Access key generation triggered by `AddMember` governance action.
- **ADR-031 (Governance):** `RevokeReadAccess`, `RestoreReadAccess`, `RevokeWriteAccess`, `RestoreWriteAccess`, `RotateContentKeys` governance actions trigger access key operations.
- **ADR-011 (Event Log):** `AccessKeyRevoked`, `AccessKeyRestored`, `ContentKeysRotated` events.

### Acceptance Criteria

1. **Access key generation and distribution:**

   - `AccessKey` struct with 32-byte AES-256 key, context_id, member_did, epoch.
   - `generate_access_key(context_id, member_did) -> AccessKey` generates a cryptographically random key.
   - `AccessKeyRequest`/`AccessKeyResponse` wire types follow the pull-based protocol pattern from ADR-007.
   - Distribution uses HPKE Base mode (RFC 9180) with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Info: `"scp-access-key-v1" || context_id || member_did || epoch_bytes`. AAD: `context_id || member_did || epoch_bytes`. Same suite as sender key distribution (§9.16.2).

2. **CEK generation and wrapping:**

   - `ContentEncryptionKey::generate() -> ContentEncryptionKey` generates a fresh 32-byte random key.
   - `wrap_cek(cek, access_key) -> WrappedCek` uses AES-256-KW (RFC 3394), producing 40-byte output.
   - `unwrap_cek(wrapped_cek, access_key) -> Result<ContentEncryptionKey, CryptoError>` verifies integrity check.
   - `wrap_content(plaintext, recipients: &[AccessKey]) -> WrappedContent` generates CEK, encrypts content, wraps CEK for each recipient.
   - `unwrap_content(wrapped: &WrappedContent, access_key: &AccessKey) -> Result<Vec<u8>, CryptoError>` finds own wrapped CEK, unwraps, decrypts (AEAD tag verifies integrity).

3. **Full revocation:**

   - On `RevokeReadAccess { did, scope: Full }`: target's access key is deleted from all members' local stores.
   - `AccessKeyRevoked { did, scope: Full }` event emitted.
   - Future messages exclude the target from wrapped_ceks.
   - Historical wrapped CEKs for the target are permanently undecryptable.

4. **FutureOnly revocation:**

   - On `RevokeReadAccess { did, scope: FutureOnly }`: target added to exclusion list.
   - Future messages exclude the target from wrapped_ceks.
   - Target retains access key for historical content.

5. **Restoration:**

   - On `RestoreReadAccess { did }`: new access key generated (new epoch), distributed via pull protocol.
   - Future messages include wrapped CEK for target.
   - Historical content remains inaccessible (old access key destroyed).

6. **Context-wide rotation:**

   - On `RotateContentKeys`: all access keys rotated, old keys retained by members for historical decryption.
   - New access keys distributed via pull protocol.

7. **Layer ordering:**

   - In encrypted contexts: access key wrapping occurs before sender key encryption, which occurs before MLS encryption.
   - In broadcast contexts: access key wrapping occurs before broadcast key encryption.

8. **Wire format:**

   - `WrappedContent` struct serializable via MessagePack.
   - `member_id` is first 8 bytes of SHA-256(member_did).
   - Serialization round-trip test passes.

9. **Integration test:**

```
1. Create a context with Alice, Bob, Dave.
2. Alice sends a message. Bob and Dave can decrypt (both have access keys).
3. Governance revokes Dave's read access (scope: Full).
4. Dave's access key is deleted from Alice's and Bob's key stores.
5. Dave cannot decrypt the message from step 2 (access key gone).
6. Alice sends a new message. Bob can decrypt. Dave cannot (excluded from wrapped_ceks).
7. Governance restores Dave's read access.
8. Dave receives a new access key.
9. Alice sends another message. Dave can decrypt (new access key).
10. Dave still cannot decrypt the messages from steps 2 and 6 (old access key destroyed).
```

### Scope

**Files (~4-5):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `AccessKey`, `ContentEncryptionKey`, `WrappedCek`, `WrappedContent`, re-exports |
| `wrapping.rs` | AES-256-KW wrap/unwrap, CEK generation, content encryption/decryption |
| `lifecycle.rs` | Access key generation, distribution (pull-based), revocation, restoration, rotation |
| `wire.rs` | `AccessKeyRequest`, `AccessKeyResponse`, serialization |
| `exclusion.rs` | Exclusion list management, member_id computation |

**Estimated functions:** ~15-20 public functions, ~10 internal helpers.

---

## ADR-043: Protocol Constants Reclassification

**Status:** Decided

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, removed the record whose expiry fixed this republish interval, so the interval is no longer a protocol constant, and the identity layer republishes its key-event log and its service record to relays instead (`03-identity.md` §3.10.5).

### Context

The Protocol Constants Registry (§9.18) promoted many implementation defaults to protocol-level constants. Constants like `MAX_SEQUENTIAL_COMMITS`, `RECONNECTION_TIMEOUT`, `SENDER_KEY_TIMEOUT`, `RECONNECTION_DEDUP_WINDOW`, and the nesting depth ceiling have no security or correctness basis for their specific values. The session cap default of 5 was a placeholder. The relay blob TTL is the relay operator's business. Several timeouts are hardware-dependent.

This creates unnecessary rigidity: independent implementations cannot tune for their deployment without breaking spec compliance. A nesting depth ceiling of 3 blocks real hierarchies. A protocol hard max chain depth of 5 prevents contexts from allowing deeper provenance chains when that is the correct tradeoff.

### Decision

Reclassify protocol constants into three tiers:

**Tier 1 — Protocol Invariants** (fixed, all implementations MUST agree):

| Constant | Value | Rationale |
|----------|-------|-----------|
| `SENDER_KEY_GRACE` | 30s | ADR-001 criterion 6: "not configurable — it bounds the forward secrecy window." Explicit decision not to make configurable. |
| `BUCKET_SIZES` | [256, 1024, 4096, 16384, 65536, 262144] | Interop requirement — implementations MUST use identical bucket sizes, otherwise relays distinguish implementations by ciphertext size, defeating padding. |
| Cryptographic primitives | (§9.18.1) | Algorithm choices are protocol-level. |
| Domain separators | (§9.18.2) | Hash domain separation is protocol-level. |

**Tier 2 — Configurable Parameters** (protocol defines mechanism + range, deployers/contexts set value):

| Constant | Default | Range | Rationale |
|----------|---------|-------|-----------|
| Nesting depth | Unbounded (no limit) | [1, u32 max] | Context-configurable via `ContextParams::max_nesting_depth`. `None` = unbounded. Costs are borne by participants, not the protocol. |
| Chain depth | 8 | [1, 255] (u8) | Context-configurable via `ContextParams::max_chain_depth`. No protocol hard max — `PROTOCOL_HARD_MAX_CHAIN_DEPTH` removed. Provenance degrades with depth, but that is an information-quality signal (provenance tiers handle this), not a protocol integrity concern. Default raised from 3 to 8 (3 was unnecessarily conservative). |
| Session cap per caller | 1000 | [1, u32 max] | Context-configurable via `ContextParams::session_cap`. Sessions are lightweight. `u32` (not `usize`) for cross-platform serialization (usize is 32-bit on WASM, UniFFI does not support it). Default raised from 5 to 1000. |
| Relay blob TTL | 604800s (operator config) | [1, infinity] | Relay operator's business. No protocol floor on TTL itself. |
| Relay republish interval | Derived: `max(ttl - 86400, ttl / 2, 60)` | Derived | At 7-day TTL: 518400s (current value). At 1-hour TTL: 1800s. Floor of 60s prevents spin loop at very small TTLs. |

**Tier 3 — Implementation Recommendations** (removed from spec normative language, SDK defaults):

| Constant | Old Value | Rationale |
|----------|-----------|-----------|
| `MAX_SEQUENTIAL_COMMITS` | 100 | Hardware-dependent; already configurable via `SyncPolicy`. Time-bounded, not count-bounded. |
| `RECONNECTION_TIMEOUT` | 120s | Already just an error enum value. SDK decides retry strategy. |
| `SENDER_KEY_TIMEOUT` | 60s | Already configurable via `SyncPolicy`. SDK decides retry strategy. |
| `RECONNECTION_DEDUP_WINDOW` | 30s | Implementation detail. Already configurable via `SyncPolicy`. |

**Key decisions:**

1. `SENDER_KEY_GRACE` (30s) stays as a protocol invariant per ADR-001 criterion 6. This is an explicit decision not to make it configurable — it bounds the forward secrecy window.

2. `PROTOCOL_HARD_MAX_CHAIN_DEPTH` is removed. Chain depth is a context concern, not a protocol integrity concern. Provenance quality naturally degrades with depth (§24), which is the correct signal — agents decide how to weight it.

3. `MAX_NESTING_DEPTH` is removed as a protocol ceiling. Same rationale as chain depth — nesting costs are borne by participants, not the protocol. Contexts may set their own limit via `ContextParams::max_nesting_depth`.

4. `DID_DOCUMENT_BLOB_TTL_SECS` (resolver.rs:344) is intentionally independent from `RELAY_BLOB_TTL_SECS`. It is the identity layer's own publication TTL, used by the healing publisher, and remains unchanged. A validating relay retains a key-event record and never expires one (`03-identity.md` §3.10.5), so the TTL binds the service record alone.

### Migration

All changes are backwards-compatible relaxations:

- **Nesting depth:** No protocol ceiling. `ContextParams { max_nesting_depth: None }` means no limit. Contexts wanting the old limit set `Some(3)`.
- **Chain depth:** Hard max removed. `ContextParams { max_chain_depth: None }` resolves to default 8 (was 3). Existing contexts relying on default 3 see a higher effective limit — a relaxation, not a tightening. Contexts wanting the old limit set `Some(3)`.
- **Session cap:** Default raised 5 to 1000. `ContextParams { session_cap: None }` resolves to 1000. Contexts wanting a lower limit set `Some(n)`.
- **Relay TTL:** Relay-side config. Existing relays keep current behavior until operators update.

No protocol versioning mechanism is required for this change set.

### Rejected Alternative

**Keep all as protocol constants.** Rejected because: (a) it conflates protocol integrity requirements with deployment preferences, (b) it forces all implementations to use arbitrary values with no security basis, (c) it prevents legitimate use cases (deep nesting hierarchies, high session counts, operator-tuned relay TTLs).

### Acceptance Criteria

1. Each constant categorized as invariant, configurable, or recommendation in spec §9.18.
2. §9.18 restructured into three subsections: Protocol Invariants (§9.18.A), Configurable Parameters (§9.18.B), Implementation Recommendations (§9.18.C).
3. `PROTOCOL_HARD_MAX_CHAIN_DEPTH` removed from code; `DEFAULT_MAX_CHAIN_DEPTH` changed from 3 to 8.
4. `MAX_NESTING_DEPTH` removed as protocol ceiling; `ContextParams::max_nesting_depth` added.
5. `DEFAULT_SESSION_CAP_PER_CALLER` changed from 5 to 1000; `ContextParams::session_cap` added.
6. All spec sections referencing old values updated (§9.2.1, §5.13.8, §6.2.1, §24.1, §24.4, §23).
7. Tests updated to reflect new defaults and absence of hard protocol ceilings.

---

## ADR-044: Attestation Two-Class Model and Provider Registry

**Status:** Decided

**Amended 2026-09-10.** ADR-063, inception-derived self-certifying identity over a key-event log, publishes an identity-link attestation as an entry of the identity's service record (`03-identity.md` §3.5.3 and §3.10.13).

### Context

Identity link attestations (§3.5) bind external platform identities to SCP identifiers. The original spec treated all attestation verification methods uniformly: OAuth, signed posts, DNS records, and challenge-response all shared the same trust model. In practice, these methods have fundamentally different trust properties:

- **OAuth and challenge-response** produce cryptographic proof of identity ownership at creation time. The SDK performs the OAuth code exchange, receives a signed ID token, and can extract a verified subject identifier. The proof is ephemeral — it exists at creation time but is not externally re-verifiable later.
- **Signed posts and DNS records** are live external resources. No cryptographic proof exists at creation time. The proof is the continued presence of the identifier in the external resource, and consumers must fetch it to verify.

The original §3.5.2 defined two alternative `proof` formats for OAuth attestations: (a) the raw JWT from the OIDC provider, or (b) an SDK-signed summary. The raw JWT path is problematic:

1. **PII leakage.** Google OIDC tokens always include `email`. Apple tokens include `email` when the `email` scope is requested. Embedding raw JWTs in attestations stores PII in a protocol object that is replicated, cached, and potentially shared across untrusted consumers.
2. **Token expiry mismatch.** JWTs expire (typically in 1 hour). An attestation containing an expired JWT requires verifiers to either (a) accept expired JWTs (defeating the purpose of JWT expiry), or (b) reject the attestation after 1 hour (defeating the purpose of attestations).
3. **Verification requires JWKS.** Verifiers must fetch the OIDC provider's JWKS to validate the JWT. This creates a runtime dependency on external infrastructure for attestation verification.

Additionally, the original spec did not define how attestations are published, leaving discovery underspecified.

### Decision

**Two attestation classes** as sub-classifications of `AttestationType::IdentityLink`:

**Class 1: Cryptographic.** Verification methods: `Oauth`, `ChallengeResponse`. The provider's confirmation was cryptographically verified at creation time. The SDK extracts the minimal claim (`provider`, `subject_id`, `verified_at`), signs the full attestation envelope with the identifier key, and discards the raw token. The proof is an SDK-signed self-attestation: "I verified this at creation time." Consumers check the identifier signature; no external fetch required.

**Class 2: Reference.** Verification methods: `SignedPost`, `DnsRecord`. The proof is a live external resource. The attestation points to a URL or DNS record. Consumers MUST fetch and verify the proof before granting trust weight. Unverified Reference attestations carry zero trust.

**SDK-signed proof format (Class 1).** The `evidence.proof` field contains `{ "provider": "<platform>", "subject_id": "<sub>", "verified_at": <unix_s> }`. The envelope signature covers this field. No raw JWT is stored. The SDK requests `openid` scope only — no `email`, no `profile`.

**Provider registry.** Seven initial providers: `github.com` (Class 2), `x.com` (Class 2), `google.com` (Class 1), `apple.com` (Class 1), `microsoft.com` (Class 1), `mastodon:<instance>` (Class 2), `dns` (Class 2). New providers by spec amendment only.

**Service-record entries.** Type `ScpIdentityLinkAttestation`. Fragment `attestation-<platform>--<index>`. Max 10 per service record.

**`revocation_status` in signed scope.** The `revocation_status` field replaces the separate `revocation` object in the wire format. It is included in the signature scope, preventing replay of revoked attestations as active.

**Verification cache for Reference attestations.** Consumer-side, 1-hour TTL. Class 1 attestations need no cache (signature verification is deterministic).

### Rationale

The class distinction is not a new attestation type — it is a sub-classification within `IdentityLink`. This is deliberate. `AttestationType` has stable numeric tags (§7.4.1, `attestation_type_tag`). Adding a new variant would require a new tag and break the existing tag stability guarantee. Instead, the class is derived from the verification method, which is already a field in the wire format. Any consumer can determine the class by inspecting `evidence.method`.

The self-attestation model is acceptable for identity links specifically because issuer == subject. The identity's controller is the only party with incentive to create the attestation, and the only party who can perform the OAuth flow. Falsifying a link provides no protocol benefit: social graph import only surfaces contacts who genuinely control both identities.

### Rejected Alternatives

**1. Raw JWT embedding.** Rejected. PII exposure (Google always includes `email` in ID tokens). Token expiry creates verification timing issues. Runtime JWKS dependency for every verifier. The SDK-signed summary provides the same identity-linking function without any of these problems.

**2. Operator-witnessed attestation.** A trusted third-party operator verifies the OAuth flow and co-signs the attestation. Rejected because: (a) it requires a third party, violating the "protocol requires no operator" tenet; (b) it creates a centralized verification bottleneck; (c) the self-attestation model is sufficient for the identity-link use case (issuer == subject).

**3. Attestation class as separate `AttestationType` variant.** Adding `CryptographicIdentityLink` and `ReferenceIdentityLink` as new `AttestationType` variants. Rejected because: (a) `AttestationType` has stable numeric tags used in canonical hash computation — adding variants is a breaking protocol change; (b) the class is derivable from `evidence.method`, making a new variant redundant; (c) all existing code that handles `IdentityLink` attestations would need branching on two types instead of one.

### Security Analysis

**Self-attestation attack surface.** A malicious user could create a Class 1 attestation claiming to have performed OAuth verification without actually doing so. The attestation would have a valid signature. Defense: (a) the claim is "I control external account X" — the only use case (social graph import) independently verifies the external identity, so a false claim has no effect; (b) the `subject_id` in the proof is meaningless without the external platform recognizing it, limiting social engineering; (c) stale attestations (past renewal interval) are degraded, forcing periodic re-verification.

**Reference attestation spoofing.** An attacker publishes a Reference attestation pointing to a URL containing another user's identifier. Defense: Reference attestations carry zero trust until the consumer verifies the proof. The consumer checks that the identifier in the external resource matches the attestation's `issuer`. The attacker cannot place the victim's identifier in the victim's profile.

**Revocation replay.** An attacker intercepts a revoked attestation and strips `revocation_status: Revoked`. Defense: `revocation_status` is in the signature scope. Stripping it invalidates the signature. The original `Active` attestation still has a valid signature, but consumers check the revocation endpoint (§18.2.2) for the attestation ID.

### Acceptance Criteria

1. §3.5.0 defines Class 1 (Cryptographic) and Class 2 (Reference) with verification method mapping.
2. §3.5.1 defines the provider registry with 7 initial providers, platform value conventions, and creation flows for each class.
3. §3.5.2 wire format includes `revocation_status` in the signature scope (replaces separate `revocation` object).
4. §3.5.3 defines the `ScpIdentityLinkAttestation` service-record entry format with its fragment naming convention and max-10 limit.
5. §3.5.4 defines class-specific verification procedures: Class 1 (signature-only), Class 2 (signature + proof fetch). Verification cache specified with 1-hour TTL.
6. §3.5.6 documents security properties: no PII, self-attestation scope limits, zero-trust for unverified Reference attestations, revocation replay prevention.
7. No new `AttestationType` variant introduced — class is derived from `evidence.method`.

**Migration note.** Changing the canonical signing bytes (replacing `revocation` with `revocation_status`) requires incrementing the domain separator from `SCP-IDENTITY-LINK-ATTESTATION-V1:` to `V2` per §9.5.1. No production attestations exist, so no backward compatibility is needed. The V2 separator is adopted in this spec change. The implementation PR uses V2 from the start.

---

## ADR-045: Fuzzing Infrastructure

**Status:** Decided. **Amended:** 2026-09-10 (the P-256 curve ruling).
**Date:** April 2026
**PRs:** #1643 (initial 18 targets), #1644 (size-gate fixes), #1645 (CI workflows), #1652 (documentation follow-up)

**Amendment (2026-09-10 — the deep fuzz targets build real P-256 keys).** ADR-063, inception-derived self-certifying identity over a key-event log, carries the curve ruling in §The curve and the root's custody, which names §9.5 of `09-security-model.md` as the home of its reason, and carries the provenance of the curve it superseded in §Alternatives considered. The two fuzz targets that build real key material — the T4 validation-depth tier and `fuzz_validate_ucan_deep.rs` — generate real P-256 keys. The target taxonomy, the tier gating, and the CI workflow routing are untouched.

### Context

SCP's relay is explicitly an untrusted dumb pipe — any TCP connection can deliver bytes to the wire parser. Post-MLS decryption is a second trust boundary because authentication success does not imply that the plaintext is well-formed. A third boundary exists at resolution/discovery (DHT poisoning, adversarial UCAN chains). Parser panics at any of these boundaries are P0 security bugs.

Property-based testing (proptest) covers algebraic properties of individual types and is already required (see `.docs/standards/rust.md` §Testing). Proptest does not provide: (a) coverage-guided mutation, (b) dictionary-assisted byte-level fuzzing of wire formats, or (c) continuous regression as the protocol evolves. cargo-fuzz (libFuzzer) fills this gap.

The security audit phase (Phase 6) surfaced three categories of parser risk:

1. **`#[serde(flatten)]` + `rmpv::Value` buffering.** MessagePack deserialization via `rmp-serde` with `#[serde(flatten)]` buffers the entire message into an intermediate `rmpv::Value` before field extraction. Without a size gate *before* `rmp_serde::from_slice`, a 4-byte "this blob is 4 GiB" header causes an OOM-abort before any application code runs. Found and fixed in PR #1644.

2. **Replica drift.** Fuzz targets that re-implement private production functions (CID format, `build_sender_aad`, ceiling format) drift silently as the production code evolves. Three HIGH-severity bugs were found in `fuzz_validate_ucan_deep` (Round 1 review) because the replica was stale.

3. **`InMemoryNonceTracker` clock coupling.** `InMemoryNonceTracker::check_replay` uses `SystemClock` directly, not an injected clock. Fuzz targets that exercise replay detection are therefore non-deterministic. Discovered during `fuzz_validate_ucan_deep` wiring.

The plan for the fuzzing infrastructure was reviewed by 7 agents before implementation began. The key structural decision — standalone `fuzz/` crate vs. per-crate `fuzz/` dirs vs. workspace member — required explicit consensus because it affects how CI is structured, how nightly Rust is isolated, and how the corpus is organized.

### Decision

**Standalone `fuzz/` crate at repo root, not a workspace member.**

`fuzz/Cargo.toml` contains `[workspace]`, explicitly opting out of the root workspace. The fuzz crate depends on production crates via path dependencies:

```toml
[workspace]

scp-protocol = { path = "../crates/scp-protocol", features = ["testing"] }
scp-transport = { path = "../crates/scp-transport" }
scp-runtime   = { path = "../crates/scp-runtime",  features = ["testing"] }
scp-event-log = { path = "../crates/scp-event-log" }
```

**Four-tier target strategy.** 27 targets total across four tiers:

| Tier | Focus | Strategy | CI cadence |
|------|-------|----------|-----------|
| T1 — Wire Format Parsers | B1 relay wire, B2 post-MLS | Raw bytes + dict | Nightly, 15 min/target |
| T2 — Content Trust Boundaries | B2 inner content, B3 resolution | Raw bytes + dict | Nightly, 5 min/target |
| T3 — Invariant & Differential | Security properties, roundtrips | Mix raw + Arbitrary | Local / `workflow_dispatch` |
| T4 — Validation Depth & State | Paths requiring semantic validity | Arbitrary + real P-256 | Local / `workflow_dispatch` |

**Trust boundaries:**
- **B1:** Relay wire protocol — any unauthenticated TCP connection
- **B2:** Post-MLS decryption — authenticated but untrusted plaintext
- **B3:** Resolution/discovery — network adversary, DHT poisoning

**Raw bytes + dicts for T1/T2; Arbitrary only for T3/T4.**

For parser and deserializer targets (T1/T2), the fuzzer receives a raw `&[u8]` slice and a libFuzzer dictionary of field names and structural MessagePack bytes. This gives libFuzzer direct mutation-coverage feedback — every mutated byte in the input corresponds to a byte in the parser's input. Wrapping in an `Arbitrary` type would cause the fuzzer to mutate the `Arbitrary` binary encoding, not the parser input, breaking the coverage feedback loop.

`Arbitrary` is reserved for T3/T4 where raw bytes cannot reach the code path (e.g., merkle proof verification requires a structurally consistent proof, or differential targets require two semantically distinct inputs).

**Invariant catalog I1–I10 as governance artifact.** The security invariants are defined once in `fuzz/README.md` and `fuzz/AGENTS.md`, and referenced by target. Any new target must map to at least one invariant. Adding, weakening, or removing an invariant requires human approval.

**CI cadence:**
- **Nightly** (`.github/workflows/fuzz.yml`, 03:00 UTC): T1 targets 15 min each, T2 targets 5 min each. All targets parallel. Corpus cached per-target with `actions/cache`; `cargo fuzz cmin` runs after each campaign.
- **Weekly deep-fuzz** (Saturday 00:00 UTC or `workflow_dispatch`): T1 targets only, 2 hours each,
  AddressSanitizer enabled (cargo-fuzz default). This entry read "+ UBSan on Saturdays" until
  2026-08-23, and the job it described set `RUSTFLAGS="-Zsanitizer=address,undefined"` and died at
  cargo-fuzz's first rustc invocation on every run: rustc accepts no `undefined` sanitizer, and its
  error names the values it does accept (`address`, `cfi`, `dataflow`, `hwaddress`, `kcfi`,
  `kernel-address`, `kernel-hwaddress`, `leak`, `memory`, `memtag`, `safestack`,
  `shadow-call-stack`, `thread`, `realtime`). Run 32634187570 recorded it. No deep-fuzz campaign
  had ever run, so the weekly lane now runs the same AddressSanitizer over the longer budget.
- **Per-PR compilation check** (`cargo check` on the fuzz crate): catches API breakage without running the fuzzer. Runs in `.github/workflows/ci.yml` as `fuzz-build`. `fuzz/rust-toolchain.toml` names the nightly the crate compiles on and records the condition for unpinning it; no command and no workflow repeats that channel.

### Rationale

**Why standalone crate, not workspace member?**

libFuzzer requires `rustc +nightly`. Adding `fuzz/` to the root workspace would force every `cargo clippy --workspace`, `cargo test --workspace`, and `cargo build --workspace` call to require nightly — or to skip the fuzz crate with `--exclude`, which is easily forgotten. The standalone crate cleanly separates the nightly build surface from the stable workspace. Clippy lints from the workspace `[workspace.lints]` do not apply to the fuzz crate; the fuzz crate uses `#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]` at the target level because the libFuzzer harness uses panics for crash detection.

The 7-reviewer consensus during plan review confirmed this trade-off: corpus centralization (one `fuzz/corpus/` tree) and simpler CI matrix outweigh the mild awkwardness of a separate manifest path.

**Why not per-crate `fuzz/` directories?**

Per-crate directories fragment the corpus: `scp-protocol/fuzz/corpus/` and `scp-runtime/fuzz/corpus/` have no cross-pollination by default. Many wire-format fuzz targets exercise code paths across multiple crates (e.g., `fuzz_outer_envelope` calls into `scp-protocol` and `scp-transport`). A single `fuzz/` at the repo root with one corpus tree enables cross-pollination between related targets and avoids duplicate harness boilerplate.

**Why not `Arbitrary`-everywhere?**

The libFuzzer mutation engine works by flipping bytes in the input and observing which new coverage edges are discovered. For a raw-bytes target this works perfectly: a bit flip in a MessagePack field-name byte might cross a branch in the parser. For an `Arbitrary`-wrapped target, the mutation happens in the `Arbitrary` binary encoding — the actual parser input may not change at all, or may change in unrelated ways. This breaks the coverage-guided feedback loop that makes libFuzzer effective at finding parsing bugs.

`Arbitrary` remains the right choice for T3/T4 where the target cannot accept arbitrary bytes (e.g., `fuzz_merkle_proof` needs a structurally consistent proof; `fuzz_canonical_hash_differential` needs two semantically distinct `InnerEnvelopeParams`).

### Security Invariant Catalog (I1–I10)

These invariants are the governance artifact for the fuzzing infrastructure. Every target maps to one or more of these invariants. Adding a new invariant requires an ADR amendment or a new ADR. Removing or weakening an existing invariant requires human approval.

| ID | Invariant | Current coverage |
|----|-----------|-----------------|
| I1 | No panic on any untrusted input | All 27 targets |
| I2 | No unbounded allocation (bounded by protocol constants from ADR-043) | T1–T6, T10–T11, T14–T15 |
| I3 | Cryptographic signatures unforgeable (no structural bypass) | T16, T18 |
| I4 | Nonce replay prevention: accepted nonce never re-accepted | Future T20 (blocked: `InMemoryNonceTracker` uses `SystemClock`) |
| I5 | Epoch monotonicity: no rollback | Future T19 |
| I6 | Timestamps outside `[now - max_age, now + skew]` always rejected | T18 |
| I7 | Capabilities outside ceiling always rejected | T18 (wired but not exercised with non-empty chain) |
| I8 | Delegation chain verification terminates (depth ≤ 32) | T18 (empty `prf`, no chain walked) |
| I9 | Different `(context_id, sender_did)` → different AAD | T17 |
| I10 | Different `InnerEnvelopeParams` → different canonical hash | T16 |

I4 and I5 are blocked on clock injection into `InMemoryNonceTracker`.

### Rejected Alternatives

**1. Per-crate `fuzz/` directories.** Rejected because: (a) corpus fragmentation — each crate has its own corpus with no cross-pollination; (b) duplicate harness boilerplate across crates; (c) CI matrix complexity — each crate would need its own fuzz workflow; (d) cross-crate targets (e.g., envelope parsing exercises `scp-protocol` + `scp-transport`) don't have a natural home.

**2. `Arbitrary`-everywhere (all targets use structured generation).** Rejected because: (a) breaks libFuzzer mutation-coverage feedback for parser targets — the fuzzer mutates the `Arbitrary` encoding, not the parser input; (b) parser bugs (the primary security risk at B1) are best found by raw byte fuzzing + dictionaries; (c) `Arbitrary` types must be maintained in sync with production types — they drift (see `.docs/lessons/fuzz-replica-production-type-drift.md`). Reserved for T3/T4 where raw bytes cannot reach the code path.

**3. Workspace member with `cfg(fuzzing)` feature flag.** Adding `fuzz/` to the root workspace with a feature flag to enable nightly-only code paths. Rejected because: (a) nightly is required by `libfuzzer-sys` at the crate level, not just by feature-gated code — the workspace would need nightly for all builds; (b) `cargo clippy --workspace` would cover fuzz targets, requiring the fuzz-specific `#![allow(...)]` suppression to be workspace-level or per-file.

**4. AFL++ instead of cargo-fuzz/libFuzzer.** Rejected because: (a) cargo-fuzz is the idiomatic Rust fuzzing tool with best LLVM coverage integration; (b) AFL++ requires a separate build system integration; (c) structured `Arbitrary` generation is a cargo-fuzz/libFuzzer first-class feature via `libfuzzer-sys`.

### Implementation

```
fuzz/                        # Standalone cargo-fuzz crate (not workspace member)
├── Cargo.toml               # [workspace] block, path deps to production crates
├── Cargo.lock               # Separate lock file — fuzzer deps don't pollute root lockfile
├── README.md                # Operator docs: quick start, target inventory, crash workflow
├── src/
│   └── lib.rs               # Shared Arbitrary types (ArbMerkleProof, ArbCanonicalHashInput, …)
├── fuzz_targets/            # 19 target files
│   ├── fuzz_outer_envelope.rs          # T1/B1 — raw bytes
│   ├── fuzz_inner_envelope.rs          # T1/B2 — raw bytes
│   ├── fuzz_client_message.rs          # T1/B1 — raw bytes
│   ├── fuzz_relay_message.rs           # T1/B1 — raw bytes
│   ├── fuzz_sender_key_dist.rs         # T1/B2 — raw bytes
│   ├── fuzz_scp_credential.rs          # T1/B2 — raw bytes
│   ├── fuzz_parse_ucan.rs              # T2/B3 — raw UTF-8
│   ├── fuzz_scp_uri.rs                 # T2/B3 — raw UTF-8
│   ├── fuzz_capability_uri.rs          # T2/B3 — raw UTF-8
│   ├── fuzz_broadcast_content.rs       # T2/B2 — raw bytes
│   ├── fuzz_deserialize_export.rs      # T2/B2 — raw bytes
│   ├── fuzz_outer_envelope_roundtrip.rs # T3/B1 — raw bytes, I1+roundtrip+hash stability
│   ├── fuzz_sender_header_roundtrip.rs  # T3/B1 — raw bytes, I1+parse→build→parse identity
│   ├── fuzz_chunk_envelope.rs           # T3/B2 — raw bytes, I1+I2
│   ├── fuzz_merkle_proof.rs             # T3/B3 — Arbitrary, I1+I2+bit-flip sensitivity
│   ├── fuzz_merkle_proof_random.rs      # T3/B3 — Arbitrary, I1
│   ├── fuzz_canonical_hash_differential.rs # T3/B2 — Arbitrary, I1+I10
│   ├── fuzz_aad_differential.rs         # T3/B2 — Arbitrary, I1+I9  (target 18)
│   └── fuzz_validate_ucan_deep.rs       # T4/B3 — Arbitrary+real P-256, I1+I3+I6+I7+I8
├── dicts/                   # libFuzzer dictionaries (one per target family)
│   ├── msgpack_outer_envelope.dict
│   ├── msgpack_inner_envelope.dict
│   ├── msgpack_client_message.dict
│   ├── msgpack_relay_message.dict
│   ├── msgpack_sender_key.dict
│   ├── msgpack_credential.dict
│   ├── msgpack_broadcast.dict
│   ├── msgpack_export.dict
│   ├── ucan_jwt.dict
│   ├── scp_uri.dict
│   └── capability_uri.dict
└── corpus/                  # Seed corpora (checked in); crash artifacts (gitignored)
    └── <target>/            # One directory per target
```

### Acceptance Criteria

1. `cd fuzz && cargo fuzz list` lists all 27 targets.
2. `cd fuzz && cargo check` succeeds on a CI runner whose default toolchain is stable, because rustup applies the toolchain file of the directory a command runs in and `fuzz/rust-toolchain.toml` names the nightly.
3. Fuzz crate is NOT listed in root `Cargo.toml` `[workspace] members`.
4. `.github/workflows/fuzz.yml` runs T1 targets (15 min) and T2 targets (5 min) nightly, and T1 targets for 2 hours each weekly, both under AddressSanitizer.
5. `.github/workflows/ci.yml` includes a `fuzz-build` job that compiles the fuzz crate on the channel `fuzz/rust-toolchain.toml` names, and the job repeats that channel nowhere.
6. Security invariants I1–I10 are documented in `fuzz/README.md` with current coverage status.
7. `fuzz/AGENTS.md` exists with agent-facing conventions: standalone crate caution, nightly requirement, raw-bytes-vs-Arbitrary guidance, dictionary format, invariant catalog.
8. All T1/T2 targets use raw bytes (`|data: &[u8]|`). All T3/T4 targets that require semantic structure use `Arbitrary`.
9. `fuzz/Cargo.lock` is committed (separate from root `Cargo.lock`).
10. Crash workflow documented: reproduce → minimize (`fuzz tmin`) → file issue → add regression `#[test]`.

---

## ADR-066: Governance Leaves Ride the MLS Commit

**Status:** Decided 2026-10-17, by Alec's rulings of that date.
**Date:** 2026-10-17
**Spec:** `07-trust-validation-and-capabilities.md` §7.3.1 (the leaf timestamp) and §7.3.1.1 (executability, competing Commits, the block, receiver processing, joiners), `05-contexts.md` §5.9 invariants 3, 4, and 5, §5.9.1 (proposal and vote messages), §5.10, and §5.10.1 (the TTL deadline and consent), §5.12.3.1 step 4 and §5.13.3 rules 10 and 11 (the committed `ttl` and promotion policy), §5.13.3 "Governance policy" and rules 3, 4, and 8 (the committed governance policy), §5.3.2 (the governed ceiling change), `09-security-model.md` §9.5.2 (preimages), §9.7.1 (the Commit row of the MLS mapping, and the log-anchored class of the checkpoint separator, whose signatures verify under `#active`), §9.18.2, §9.18.3, §9.18.7, and §9.18.10 (registries and constants), `19-economic-governance.md` §19.3 and §19.4 (the governed economic policy change), `05-contexts.md` §5.13.3 "Economic policy" and rule 12 (the committed economic policy), `05-contexts.md` §5.13.3 "Governance state" and rule 13 (the committed governance state), `09-security-model.md` §9.16.2 "New member join" (the sender key epoch a joiner learns), `09-security-model.md` §9.5.2 Event and §9.7.1 (the log-anchored class of the event separator, and the first-seen test), `23-sync-and-offline-strategy.md` §23.13 (event verification), `05-contexts.md` §5.13.3 "Log head" and rule 14 (the committed log head), §5.4 "Registration and its policy" and §5.4.1 (the outlet header and the V3 preimage), §5.9 invariant 5 item 7, `07-trust-validation-and-capabilities.md` §7.3.1.1 "With a revocation" and "With an outlet change", `09-security-model.md` §9.5.2 (UCAN revocation), §9.12 step 3, and §9.16.3 step 7 (the block record).
**Amends:** ADR-008 (`close_context` appends no `ContextClosing` leaf in a Commit); ADR-018 acceptance criteria 3 and 4 (TTL extension and promotion execute only in a Commit every member approved); ADR-009 (`assign_role` appends no `RoleAssigned` leaf in a Commit); ADR-011 (which leaves record an executed governance action, and criterion 1: `Event` carries `signing_key_id` and `key_state_head` and is signed under `"SCP-EVENT-V2:"`); ADR-029 §3 (the Welcome-based fast-forward), §4 (the reset request and the `MemberReset` leaf), and §5e (closure detection on reconnect); ADR-030 §1 (`ContextStateSnapshot`, its identifier types and those of `Checkpoint` and `CosignedCheckpoint`, `recorded_proposals`, `economic_policy`, the checkpoint signature preimage, the signers' `key_state_head` fields, the quorum counted against the committed voters with no chain walk, decision 25, and no `sender_key_epochs`, decision 26), §2 (pruning invariant 6, the latest TTL leaf, invariant 7, the recorded proposals' leaves, and invariant 8, the latest economic policy leaf, added and withdrawn), and §5; ADR-030 §1, §2 invariant 3, §3, §4c, §5 step 2, and acceptance criterion 2 (a Commit carries the checkpoint as a `Checkpoint` leaf that every member validates, decision 24); ADR-031 §9 (each cosigner signs with its own `key_state_head`, and a checkpoint short of its quorum is never committed, decision 24); ADR-030 §1 adoption, §2 invariant 7 withdrawn, and §5 steps 1 to 4 (leaves and the checkpoint accepted by inclusion under the committed log head, decision 27); ADR-016 (UCAN revocation by a `TokenRevoked` leaf, with no `RevocationList` merge and no application-message distribution, decision 28); ADR-008 (`ContextParams.outlet_registration_policy`, decision 31); ADR-010 criterion 2 (registration by Commit, decision 31); ADR-031 §3 (`RegisterOutlet` carries the outlet header, and `SetOutletRegistrationPolicy`, decision 31); ADR-030 §1 (`ContextStateSnapshot` loses `blocks`, decision 30); ADR-031 §2 (the voter limits), §3 (identifier fields of `GovernanceAction` are text-form `DID`s), §4 (unanimity under `Threshold`), §4c, §5, §7, §8, and acceptance criteria 7 (the `GovernanceActionExecuted` payload) and 9; ADR-049 §9 (the single-source TTL deadline, read from the unpruned latest TTL leaf, and the retired bilateral reset); ADR-051; ADR-057 T3; `05-contexts.md` §5.3.2 (a governed ceiling change takes effect at the executing Commit, with no notification period, and an earlier Commit must record its proposal); `19-economic-governance.md` §19.3 and §19.4 (a governed economic policy change, the pricing formula included, takes effect at the executing Commit, with no notification period, and an earlier Commit must record its proposal, and the lock is enforced).

### Context

A context's event log is the source of each member's role and rights (§7.2.2 of the trust spec fills the capability cache from role assignments, and §7.3.1 makes role assignments and governance actions commit-ordered leaves). The runtime appends those leaves at the committer only. A member that did not commit a membership change records no role for the member someone else added, so it rejects that member's messages with `MemberNotFound`, and no existing path delivers the leaf to it: §7.3.2 stated that receive-side replication is dormant.

ADR-031 §8 sends governance proposals and votes as MLS application messages and sends a Commit only for a membership change or a key update. A role change by `ChangeRole` therefore reaches no other member at all, and a vote reaches each member in whatever order the relays deliver it. The runtime appends proposal and vote events to each member's own log, and assigns each member's proposal sequence from a counter local to that member, so two honest members' logs already differ.

### Decision

Alec ruled on 2026-10-17: the event log is the source of a member's role and rights; the committer carries the signed governance leaves in the MLS Commit's authenticated data; each receiver verifies the leaves, authorizes them against its own governance state, and appends them before it merges the Commit, grants no rights until it has verified them, and deduplicates against them on any later delivery path. He then chose design C1, and ruled that votes travel in the Commit. After four review rounds of a design that split large approval sets across Commits, he ruled: "Let's go with 96 cap and no split for now, threshold for more. we can revisit later." 96 approvals did not fit a 16,384-byte block beside a proposal, and asked to choose between 96 and 65 he picked "96, 32 KB block": "Keep your 96. Every rights-changing Commit carries a fixed 32 KB block instead of 16 KB, and the 8 KB action limit stays." An 8 KB action then did not fit beside 96 approvals while the block carried it in both the proposal and the `GovernanceActionExecuted` leaf. He asked "Is repeating necessary?", and to the proposal that the Commit carry the action once, in the leaf, he answered "Yes". Decisions 6, 11, and 13 apply these rulings.

1. **Proposals and votes are application messages.** A governance proposal and a governance vote travel as MLS application messages, as ADR-031 §8 says, with the `InnerEnvelope` message types `GovernanceProposal` (`0x06`) and `GovernanceVote` (`0x07`) of §5.9.1. Each is signed under its sender's MLS leaf key. They let members see and approve a proposal, and change no member's rights.
2. **Every rights-changing action executes as a Commit.** When a governance action executes, the executor sends a Commit carrying the action's proposal, the signed approving votes, and the action's signed leaves. Membership changes execute this way too. An action that adds or removes no member uses a Commit with no proposals and an UpdatePath.
3. **The Commit alone decides.** In a multi-admin context, every receiver checks the quorum from the Commit's contents alone, against its own pre-Commit governance state. The Commit carries the approvals the model requires, and every voter it does not carry counts as not approving, so no receiver's verdict depends on which vote messages it happened to receive.
4. **Key state every member shares.** A vote or proposal signature verifies only under the signer's leaf in the receiver's ratchet tree of the Commit's sending epoch, bound to the signer's identifier by the verified §9.7.1 `0xFF03` attestation. The committer's identity comes from the `0xFF03` attestation on its leaf in that tree, the leaf whose key signs the Commit, never from its self-asserted credential; a Commit whose UpdatePath leaf carries an attestation for a different identifier is rejected. A leaf's own signature verifies under the key the member resolved for that attestation. No check resolves a key over the network.
5. **Epoch order decides conflicts.** ADR-031 §7's "committed first" means merged first in MLS epoch order. A Commit that loses the race for an epoch is re-checked against the new state by its executor and sent again or invalidated, and every receiver applies the same conflict check before it merges. **Amendment (2026-10-24, ADR-067):** more than one Commit can be made for one epoch, and no member can stop it. Every member processes every valid child of an epoch, and "merged first in MLS epoch order" means first on the canonical path, whose child at each epoch is the valid child with the least (rank, cth). A losing child's changes return as re-applications on the canonical path, and the merge function G of ADR-067 settles each pair that conflicts across the two branches. A Commit that no relay stored is re-checked and sent again as this decision states.
6. **One fixed-size encrypted block in every Commit.** MLS sends `authenticated_data` in the clear (RFC 9420 §6.3), and §9.10.1 makes roles and governance actions confidential, so the block is AES-128-GCM under `MLS-Exporter("SCP-GOVERNANCE-LEAF-V1", context_id, 16)` from the sending epoch, with the group ID, the epoch, and the sender's leaf index in its additional data. Every Commit, key-update and periodic Update Commits included, carries one 32,805-byte block over a 32,768-byte padded plaintext, so a Commit's length tells a relay nothing about governance. Every governance action travels whole in the one Commit that executes it: the block holds the proposal, every required approval, and the leaves. An action that does not fit is not executable.
7. **Fail closed, deduplicate by sequence.** A receiver grants no right before it has verified the leaf that grants it and never assumes a default role. A leaf that arrives again by replication or reconciliation and hashes the same as the held leaf is discarded; one that hashes differently is handled as §9.9.3 equivocation.
8. **Joiners rebuild and check.** A member added by a Commit receives the Welcome, whose GroupInfo carries the log's count, Merkle root, and last leaf hash (`scp_event_log_head`, `0xFF04`). The joiner rebuilds the log as ADR-030 §5 reconstructs state and grants no right until its rebuilt log matches.
9. **Proposal lifecycle records leave the canonical log.** `GovernanceProposalCreated`, `GovernanceVoteCast`, `GovernanceVoteWithdrawn`, and `GovernanceProposalResolved` become local `ContextEvent`s, because no Commit orders them. The ADR-057 T3 `SCPT` blob is retired, because the leaf carries the committer's timestamp.
10. **Authorization reads only state every member holds identically.** Every check a receiver runs on a governance Commit reads the Commit, the receiver's MLS state in the sending epoch, and governance state that the commit-ordered leaves determine and a checkpoint snapshot carries: membership and roles, each member's join point, one sequence per conflict key, each member's reset counter floor, the TTL deadline, and the executed-proposal set. No check reads a clock, a timestamp a sender chose, or a leaf a checkpoint lets a member prune. A proposal names `anchor_seq`, the commit-ordered leaf count its proposer held, in place of a creation time; a conflict is an action executed at a sequence at or after the anchor. A vote names `expires_epoch`, the last epoch whose Commit may carry it, and a voter withdraws by replacing its leaf key. A member's join point moves only when it joins as a non-member; an ADR-029 reset or fast-forward does not move it. Eligibility is the `GovernanceVote` holders before the executing Commit, except for the two TTL actions of decision 15. A leaf's timestamp is the committer's annotation, and no receiver bounds it. **Amendment (2026-10-24, ADR-067):** the governance state a check reads now includes the journal with each entry's `prior` values, the key ledger, the epoch table, the admitted fork records, the open imports, and the pending joiners, and `merge_state_hash` commits all of them (`05-contexts.md` §5.13.3 rule 16). A re-applied change is checked against the state at its fork point, rebuilt from the journal, and against the key its signer held there. Withdrawal by replacing a leaf key rests on an Update that rotates `signature_key`, and no Update does: `propose_update` passes `LeafNodeParameters::default()`.
11. **At most 96 approvals per Commit.** By Alec's rulings above, no action spans two Commits, and contexts that need more voters use `Threshold`. The 32,764 body bytes hold the block proposal record (168 bytes), 96 vote records of 169 bytes (16,224), leaves of up to `MAX_GOVERNANCE_LEAF_BYTES` (15,616), and 5 bytes of array headers: 32,013 bytes, with 751 to spare. Decision 14 fixes every leaf a Commit carries, so the leaves have a largest size: 9,001 bytes beside an 8,192-byte action, 6,595 for `ExtendTtl` with 96 consenting members, 9,715 for 16 requested resets, and 15,609 for a checkpoint with 95 cosignatures (decision 24); 15,616 holds each, and no action the §5.9.1 checks accept needs more. `MAX_GOVERNANCE_APPROVALS` is 96 and is the limit that binds. Context creation and `ReconfigureGovernance` reject a `Majority` context above 191 eligible voters, a `Unanimity` context above 96, and a `SingleAdmin`, `Majority`, or `Unanimity` context with a TTL above 96; under `Threshold`, `ExtendTtl` and `PromoteContext` need every signer, at most 64 (the coordinator's call of 2026-10-18). Every receiver rejects an action that would raise the eligible voters past the context's limit, and a `ReconfigureGovernance` whose resulting configuration breaks it.
12. **A reset needs the member's own request, which executes once.** A `MemberReset` leaf that executes no proposal is authorized only when the Commit's block carries the reset member's own signed `ResetRequest`, whose one preimage `09-security-model.md` §9.5.2 defines under `"SCP-RESET-REQUEST-V2:"`, and every receiver verifies it under the member's `#active` identity key; the committer holds both `member:invite` and `member:remove`; and the re-added leaf's `0xFF03` attestation is newer than the leaf it replaces. The request carries `reset_counter`, which the member raises with every request it signs during a membership, and `member_since`, its join point. A receiver accepts it only when `reset_counter` exceeds the member's `reset_counter_floor`, `member_since` equals the member's join point, and `last_known_epoch` is at most the Commit's sending epoch; executing it sets the floor to its `reset_counter` (the coordinator's call of 2026-10-18). A floor set from the reset Commit's epoch would read a value no request signs, and a request signed during an earlier membership would match a new one's epoch range. The `MemberReset` leaf repeats only signed values: the member, `last_known_epoch`, `reset_counter`, and `reason`. A reset that a `ResetMember` governance action orders executes as that action, under the model's approvals. A member holding only `member:invite` can no longer reset a voter onto a consumed KeyPackage.
13. **The action travels once.** The executing Commit's `GovernanceActionExecuted` leaf carries the proposal's exact `action_bytes`, and the block carries the proposal as a block proposal record without them (`05-contexts.md` §5.9.1). A receiver takes `action_bytes` from that leaf as received, runs the RFC 8785 and I-JSON checks on those bytes, never on a re-encoding, recomputes `proposal_id` from them, and verifies the proposer's signature and every vote against that `proposal_id`; a Commit carrying a proposal without exactly one such leaf is rejected. The `GovernanceProposal` message (`0x06`) still carries `action_bytes`, so a voter reads the action before it votes. A committer therefore can no longer execute an action that differs from the one the voters signed: the bytes every member applies are the bytes `proposal_id` hashes.
14. **Every leaf is derived.** A receiver derives the exact leaves a Commit must carry from the decoded action, the Commit's MLS proposals, the carried reset requests, and its own pre-Commit state, and rejects a Commit whose leaves differ from them in count, order, type, or any field but the signature it verifies and the timestamp it does not read (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6). With a proposal, `AddMember` derives one `MemberJoined`, `RemoveMember` one `MemberLeft`, `ResetMember` one `MemberReset`, and `ExtendTtl` one `TtlExtended`, each fixing the Add and Remove proposals the Commit may carry, and the `GovernanceActionExecuted` leaf comes last; every other action carries no Add or Remove and only that leaf. With no proposal, a Remove and an Add of the same member derive a `MemberReset` from the carried request, any other Remove derives a `MemberLeft`, and an unpaired Add is rejected. The `GovernanceActionExecuted` payload is `[target_did, action_type, proposal_id, action_bytes]`, every field derived from the proposal; it holds no executor or resulting epoch, because no receiver could check them. A committer can then add no leaf the action did not approve, such as a `RoleAssigned` beside a `ChangeRole`, and every value rebuilt from the log was checked when the leaf was accepted.
15. **Every member approves a TTL extension or a promotion.** On 2026-10-18 Alec picked the option "Every member", which read: "Keep the spec's rule. Members joined expecting the context to expire, so none of them can have it extended or made permanent without their approval. The cost: every context with a TTL is limited to 96 members, including members who have no vote." `ExtendTtl` and `PromoteContext` need a signed approval from every current member, carried in the executing Commit, in every model, `Threshold` included, and a member that holds no `GovernanceVote` approves them with the same §5.9.1 vote record (`07-trust-validation-and-capabilities.md` §7.3.1.1). Every context with a TTL has at most 96 members, enforced at creation, at every action that adds a member, and by every receiver (`05-contexts.md` §5.9 invariant 4). The carried approvals replace the `TTLExtensionConsent` message and its 24-hour consent deadline, which no receiver could check: a member that does not approve blocks the action, and its approval lapses at its `expires_epoch` (`05-contexts.md` §5.10.1). Every member derives the TTL deadline from the context's latest TTL leaf, which no member prunes, and a rebuilt member adopts a checkpoint snapshot only when its `ttl_deadline_unix` matches that leaf, so a live member, a restarted member, and a rebuilt member derive the same `TtlExtended` leaf, and no checkpoint quorum can extend or remove the TTL (ADR-049 amendment, ADR-030 pruning invariant 6). A proposer re-sends every pending proposal after every Commit that adds a member, so an added member that the requirement counts can approve it (`05-contexts.md` §5.9.1), and every receiver rejects a `PromoteContext` in a `no_promotion` context or one with no TTL.
16. **The `0xFF02` extension commits the TTL and the promotion policy.** The extension gains `ttl_secs` and `promotion_policy`, and every member installs the TTL-deadline base and the promotion policy from them, never from an invitation bundle or a snapshot (`05-contexts.md` §5.13.3 rule 10). A Commit changes the extension only as its derived leaves require (rule 11): the Commit whose derived leaves change the governance policy or the ceiling in effect carries the GroupContextExtensions proposal that updates `governance_policy_hash` or `ceiling_hash` to the value every receiver derives from the action, no other Commit carries one, and every other field, `ttl_secs`, `promotion_policy`, `context_id`, `creator_did`, `creation_timestamp_secs`, `ceiling_policy`, and the parent lineage, never changes. A Welcome joiner checks the two hashes against the state it rebuilds, because its bundle carries the genesis parameters. Decision 15's deadline equality and the `PromoteContext` policy check both read these values, and before this decision a joiner took them from the bundle, which only the inviter signed, so one malicious member could give a joiner a TTL base or a policy no other member holds. The coordinator required the values to be authenticated by the group context on 2026-10-18; the coordinator required the hash updates and the immutable fields of rule 11 on the same date; the choice of two committed fields over a hash, deriving the expected extension from the Commit's leaves, and moving the joiner's hash check to its rebuilt state are the architect agent's.
17. **The `0xFF02` governance policy is ADR-031's `GovernanceModelConfig`.** `governance_policy_hash` is the SHA-256 of the RFC 8785 form of the context's current `GovernanceModelConfig` (ADR-031 §2), with `signers` sorted and each identifier in its text form (`05-contexts.md` §5.13.3, "Governance policy"). Exactly five actions change it, `TransferAdmin`, `AddSigner`, `RemoveSigner`, `ModifyThreshold`, and `ReconfigureGovernance`, so only a Commit whose derived leaves execute one of them updates the hash (rule 11). The type holds no list that membership determines, so a Commit that adds or removes a member, or changes a member's role, leaves the extension unchanged. Under `SingleAdmin` the hash commits the current admin, so a joiner checks the admin it rebuilds from the log against a value the group committed. An importer and a restorer check rules 3 and 4 against the governance and ceiling of the checkpoint snapshot they adopt, because the snapshot's context parameters can hold the genesis values. The coordinator required the type to be defined on 2026-10-18; the choice of `GovernanceModelConfig`, committing `admin_did`, and the sorted `signers` are the architect agent's.
18. **A governed ceiling change takes effect at the executing Commit.** On 2026-10-18 Alec picked the option "At execution", which read: "The new ceiling takes effect in the Commit that executes the ModifyCeiling. Members can leave at any time while the proposal is open for voting, before it executes. Every member can check this, and no timer is needed. Cost: the promise changes from 'you get 72 hours after approval' to 'you can leave while the vote is open'. A Majority vote can collect its approvals quickly, so the time to leave can be short." `05-contexts.md` §5.3.2 drops its 72-hour notification period, the `CeilingChangeNotification` message, and the `DepartedDuringCeilingChange` record: members learn of a `ModifyCeiling` when its proposal is sent and may leave before it executes, and the new ceiling is in effect from the Commit that executes it, whose GroupContextExtensions proposal carries the new `ceiling_hash` (rule 11). The period was a wall-clock timer that decision 10 forbids a receiver to read. The event types `CeilingModified` and `CeilingModificationPending` keep their registry values, and no Commit carries `CeilingModified` (decision 14); decision 20 gives `CeilingModificationPending` to the recording Commit, and decision 21 renames it `GovernanceProposalRecorded`. Deleting the timer code, and the operation that applied a pending ceiling, in SCP-329 is the architect agent's placement.
19. **A governed economic policy change takes effect at the executing Commit.** On 2026-10-18 Alec picked the option "At execution", which read: "The new economic policy takes effect in the Commit that executes it. Members can leave while the proposal is open for voting. This matches the ceiling ruling, every member can check it, and no timer is needed. Cost: the per-context economic_policy_notification_period_secs setting goes away, and a fast Majority vote leaves members little time to leave." `19-economic-governance.md` §19.3 drops its 86,400-second minimum notification period and the `economic_policy_notification_period_secs` setting: members learn of a `SetEconomicPolicy` when its proposal is sent and may leave before it executes, and the new policy is in effect from the Commit that executes it, whose `GovernanceActionExecuted` leaf records it (decision 14). The period was a wall-clock timer that decision 10 forbids a receiver to read. §19.4's pricing formula is the `pricing_formula` field of `EconomicPolicy`, so a formula change follows the same rule. The event types `EconomicPolicyChanged` and `EconomicPolicyApplied` keep their registry values, and no Commit carries either. Deleting the timer code in SCP-329, beside the ceiling timer of decision 18, is the architect agent's placement. Decision 21 puts a recording Commit before the executing Commit.
20. **A governed ceiling change takes two Commits.** On 2026-10-19 Alec picked the option "Two Commits", which read: "A ModifyCeiling proposal must be recorded in an earlier Commit's governance block before a later Commit can execute it. Receivers reject an execution whose proposal they have not seen in an earlier epoch, so every member is guaranteed at least one epoch to see the proposal and leave, under every governance model. Cost: each ceiling change takes two Commits, and the window is one epoch, which can still be short." A recording Commit carries the `ModifyCeiling`'s block proposal record, no votes, and one derived `CeilingModificationPending` leaf, which decision 21 renames `GovernanceProposalRecorded`, holding the proposer's identifier, `anchor_seq`, `proposal_id`, and `action_bytes`; only the proposer may send it (decision 21), it needs no approvals, and the proposer's SDK sends it when it creates the proposal (`07-trust-validation-and-capabilities.md` §7.3.1.1 steps 1.3, 1.6, and 2). Every receiver holds the recorded proposals in `recorded_proposals` and rejects a Commit that executes a `ModifyCeiling` absent from it (`05-contexts.md` §5.3.2 and §5.9 invariant 5). The checkpoint snapshot carries the set and pruning invariant 7 keeps each entry's leaf, so a rebuilt member validates the execution as a live member does (ADR-030 §1 and §2 amendments). A recorded proposal leaves the set when it executes, when any other `ModifyCeiling` executes, when its proposer records another, or when its proposer leaves; the §5.9.1 proposal expiry reads each engine's clock, so no receiver applies it to the set. The block constants are unchanged, because a recording Commit's body is at most 8,755 bytes. The ruling covered ceilings only; decision 21 extends the mechanism to the economic policy change. Decision 18's rule that the new ceiling takes effect at the executing Commit stands.
21. **A governed economic policy change takes two Commits, and only the proposer records a proposal.** On 2026-10-19 Alec picked the option "Two Commits" for the economic policy change, which read: "Apply the ceiling mechanism to SetEconomicPolicy: the proposal is recorded in an earlier Commit, and receivers reject an execution without that record. Every member gets at least one epoch under every governance model. Cost: each economic-policy change takes two Commits, and the recording state, pruning rule and snapshot field are extended to a second action." A `SetEconomicPolicy`, a §19.4 pricing formula change included, is recorded and executed as decision 20 records and executes a `ModifyCeiling`, through one mechanism: the leaf is renamed `GovernanceProposalRecorded`, keeping tag 38 and its payload `[proposer_did, anchor_seq, proposal_id, action_bytes]`, and it names its action by the `GovernanceAction` variant its `action_bytes` decode to; the governance state and the snapshot field become `recorded_proposals`, keyed by proposer and action kind (`07-trust-validation-and-capabilities.md` §7.3.1.1, `05-contexts.md` §5.9 invariant 5, `19-economic-governance.md` §19.3, ADR-030 §1 and pruning invariant 7). The ruling did not state how the two kinds interact, and this decision sets it. They are independent: a recording replaces only its proposer's entry of the same kind; an executed `ModifyCeiling` removes every `ModifyCeiling` entry, because each then conflicts through the key `ceiling`; an executed `SetEconomicPolicy` removes only its own entry, because `SetEconomicPolicy` holds no conflict key and every other recorded economic proposal stays executable; a `MemberLeft` leaf removes both of its subject's entries. A recording Commit's committer must be the proposer, for both actions, and every receiver rejects any other recording (§7.3.1.1 steps 1.3 and 2). When any member holding `GovernancePropose` could record, a member could replace a proposer's recorded proposal with an older proposal the same proposer had signed, and receivers would then reject the execution of the proposal the voters approved. The block constants are unchanged: the leaf's new name has 26 characters, as the old one did, and `MAX_GOVERNANCE_ACTION_BYTES` bounds a `SetEconomicPolicy`'s `action_bytes` as it bounds a `ModifyCeiling`'s, so a recording body stays at most 8,755 bytes. Decision 19's rule that the new policy takes effect at the executing Commit stands.
22. **The economic policy in effect is governance state, and governance never sets or clears `locked`.** Before this decision the economic policy in effect was in neither the §7.3.1.1 governance state nor the ADR-030 snapshot. A member rebuilt from a checkpoint after the `SetEconomicPolicy` leaf was pruned would hold the genesis policy while live members hold the executed one, which decision 19 rejected, and no receiver could check the policy's `locked` flag, because no state it reads held it. The governance state and the snapshot now hold `economic_policy` (`07-trust-validation-and-capabilities.md` §7.3.1.1, ADR-030 §1). It starts as the genesis `economic_policy` of the `ContextParams` that the creator's bundle signature authenticates (`05-contexts.md` §5.12.3.1), and the `GovernanceActionExecuted` leaf of each `SetEconomicPolicy` sets it to that action's `policy`. The `0xFF02` extension commits it as `economic_policy_hash`, the SHA-256 of its RFC 8785 form, or of the 4 bytes `null` when the context has none (`05-contexts.md` §5.13.3 "Economic policy" and rule 12). The Commit that executes a `SetEconomicPolicy` carries the GroupContextExtensions proposal that updates it (rule 11), the recording Commit carries none, and a Welcome joiner, an importer, and a restorer grant no right until the policy they rebuilt or adopted hashes to the committed value. Every receiver rejects the recording or execution of a `SetEconomicPolicy` when the policy in effect has `locked` true, and when the action's `policy` sets `locked` true (§7.3.1.1 step 1.3). `19-economic-governance.md` §19.3 reads: "Creator MAY lock economic policy at creation — "always free forever" or "price locked at $X forever." Voluntary commitment, not the default. The lock is itself immutable (once locked, cannot unlock)." That text names the creator at creation as the only party that sets the lock and makes the lock irreversible, so a governance action neither clears it nor sets it; that governance cannot set the lock is this decision's reading of that text, which names no other party and no other time to set it; §19.3 states no such sentence. The architect agent chose the committed hash over a retained leaf. The first form of this decision gave the extension no field, kept the latest `SetEconomicPolicy` leaf (ADR-030 pruning invariant 8), and checked the snapshot against it, on the claim that the policy was checkable at join without a committed field. That claim was false. A joiner verifies the leaves after the latest checkpoint only by their committers' signatures, and a forged `GovernanceActionExecuted` leaf of a `SetEconomicPolicy` signed after that checkpoint carries no approvals the joiner can check, so the adding committer alone could set the joiner's price. The committed hash closes that, because every member validated the Commit that set it. It also makes the retained leaf unnecessary, and invariant 8 is withdrawn: the joiner checks the policy it ends with against the group context, as it checks the ceiling, which no retained leaf backs, and a snapshot policy that a later executed `SetEconomicPolicy` replaced is overwritten during replay before that check. The cost is one GroupContextExtensions proposal in each Commit that executes a `SetEconomicPolicy`.
23. **Every event-log leaf is log-anchored evidence.** A member rebuilding from a checkpoint holds no Commit history, so under the content class of `09-security-model.md` §9.7.1 it reports `Invalid{NoBoundary}` (§9.7.1, "No boundary here") for every leaf whose committer has since retired the signing key. It could then not rebuild after any routine rotation, because it must verify the leaves ADR-030 pruning invariants 6 and 7 keep and the leaves after the latest checkpoint. `Event` therefore gains `key_state_head`, its actor's own (ADR-011 criterion 1, as this decision amends it), and its signature moves to `"SCP-EVENT-V2:"`, whose §9.5.2 preimage ends with `signing_key_id` and `key_state_head` and which is in the log-anchored class. `23-sync-and-offline-strategy.md` §23.13 ¶1 verifies each event at the position that field names, and `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6 requires the committer's attested key to hold its role as `Current` there. A key the actor's state now lists `Superseded` or `Retired` keeps the leaf valid. A key it lists `Compromised{from: N}` keeps the leaf valid only under first-seen, so a joiner that resolves the actor's chain after N still cannot verify that actor's earlier leaves; that outcome is open, and this decision does not settle it. **Amended by decision 27:** no member verifies a kept leaf under its `key_state_head` any more. A member that processes the Commit verifies the leaf under the key it resolved from its committer's epoch-`E` attestation, a key that members can disagree on at the Commit where that leaf enters their trees and that a Welcome joiner, an importer, or a restorer does not hold, until SCP-315 closes that gap (`09-security-model.md` §9.7.1, "Known gap: members can resolve different keys for one attestation"), and a joiner, an importer, and a restorer accept it by inclusion under the committed log head, so the outcome reaches only a verifier outside the group, and §7.3.1.1 step 1.6 no longer reads the committer's key-event log. Decision 25 removes the walk over earlier checkpoints, so the outcome now reaches only the leaves invariants 6 and 7 keep and the leaves after the latest checkpoint. Each leaf grows by 34 bytes, so `MAX_GOVERNANCE_LEAF_BYTES` rises from 9,216 to 9,728, which holds the 9,715-byte leaves of 16 requested resets, and the body still held 96 approvals with 6,639 bytes to spare; decision 24 raises the cap again, to 15,616. The architect agent chose one mechanism for every kept leaf, the leaf's own anchor, over the checkpoint quorum attesting to retained leaves, for the reasons the rejected alternatives give.
24. **A Commit carries the checkpoint.** Alec ruled on 2026-10-20, choosing the option "Commit leaf", which read: "A Commit can carry a Checkpoint leaf that holds the snapshot digest and the gathered cosignatures. Every receiver recomputes the Merkle root and the snapshot digest from its own state, and rejects a mismatch, so every live member validates the checkpoint, not only the signing quorum. ADR-030's leaf, inclusion-proof and pruning text stays true. Cost: a new derivation rule, one Commit per checkpoint, and about 152 bytes per signature, so 96 signers need about 14.6 KB. That exceeds today's 9,216-byte leaf cap, so the block arithmetic has to be redone." `07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6 derives the leaf, `Checkpoint` (`EventType` tag 79). Its payload holds `checkpoint_seq`, `merkle_root`, `event_count`, `last_event_hash`, the snapshot's digest `state_snapshot_hash`, `created_at`, the creator's `creator_key_state_head` and `signature`, and the cosignatures, each `[signer_did, key_state_head, signature]`; it never holds the snapshot. Each receiver derives `checkpoint_seq`, `event_count`, `merkle_root`, `last_event_hash`, and `state_snapshot_hash` from its own state, checks the quorum and every signature, and rejects the Commit on a mismatch. The ruling's figures are estimates: a cosignature encodes in 159 bytes, a checkpoint with 95 cosignatures in a 15,605-byte leaf and a 15,609-byte leaves array, and the 9,216-byte cap it names is the figure before decision 23 raised it to 9,728. The architect agent made these calls inside the ruling. (a) The leaf covers the receiver's state before the Commit: `event_count` is N, `checkpoint_seq` is N − 1, and the leaf sits at sequence N, so every receiver that holds the same N leaves derives the same values. A receiver rejects a checkpoint Commit whose head leaf is already a `Checkpoint` leaf, so a checkpoint never covers only another checkpoint. (b) The creator is the committer, named by the leaf's `actor_did`, so the payload carries no `creator_did`. (c) A checkpoint Commit carries the full ADR-031 §9 quorum, and a checkpoint short of it is never committed, so `PartiallyAttested` becomes a flag local to the creator; amending ADR-031 §9 this way keeps every committed checkpoint valid for pruning and gives a rebuilding member one kind of checkpoint. (d) Every quorum is at most 96, by the voter limits of decision 11, so a leaf carries at most 95 cosignatures, and `MAX_GOVERNANCE_LEAF_BYTES` rises to 15,616, one cap for every leaves array; the full body is then 32,013 bytes with 751 to spare, a requested-reset body 22,630, and a checkpoint body 15,613. (e) The creator gathers cosignatures as MLS application messages and sends the Commit itself while its leaf count still equals `event_count`; when a leaf-bearing Commit lands first, it starts again. (f) The one-hour cosignature window stays local to the creator and the cosigners, and no receiver reads it, because the requirement that `event_count` equal the receiver's leaf count bounds staleness without a clock. (g) A checkpoint Commit carries that one leaf and nothing else in its block, no Add, Remove, or GroupContextExtensions proposal, so the snapshot each receiver computes is the state the signers signed. Decision 27 amends this: the Commit carries the one GroupContextExtensions proposal that changes only `log_head_hash`, which no snapshot field holds, so the snapshot is still the state the signers signed. (h) The snapshot's `mls_epoch` is the epoch that the Commit appending the leaf at `checkpoint_seq` created, or 0 when group creation appended it, so a Commit that appends no leaf does not change the digest. (i) The signature stays in the log-anchored class, because a joiner and a rebuilding member verify the leaf after its epoch (ADR-030 §1 log-anchored amendment). Decision 27 amends this: a joiner and a rebuilding member accept the leaf by inclusion, and the class serves only a verifier outside the group. (j) A Broadcast context has no Commit, and its checkpoint stays the ADR-030 durable artifact. Decision 23's open outcome, a joiner that resolves a committer's chain after a `Compromised` entry, is not settled by this decision; decision 27 settles it for members.
25. **The group context commits the governance state.** Alec ruled on 2026-10-20, choosing the option "Digest in 0xFF02", which read: "Commit a digest of the governance state (members, roles, voters) in the 0xFF02 context extension, which every Commit's GroupContext carries. A joiner reads the voters from the GroupContext it joins under, so it no longer walks the checkpoint chain. Joiners already trust that GroupContext for the log head, the ceiling hash and the economic-policy hash, so this adds no new trust. Cost: 32 bytes, plus one hash check on every Commit that changes governance state. An old compromised key can no longer lock anyone out." The `0xFF02` extension gains `governance_state_hash`, the SHA-256 of the RFC 8785 form of `{"members":[[identifier, role name], …],"voters":[identifier, …]}`, both arrays in ascending order of the identifiers' UTF-8 bytes (`05-contexts.md` §5.13.3 "Governance state"). Rule 11 makes every receiver recompute it before it merges a Commit, and a Commit whose derived leaves change the membership, a role, or the voters carries the GroupContextExtensions proposal that sets it. Rule 13 makes a joiner, an importer, and a restorer check it, beside rules 10 and 12. A member that rebuilds counts the latest checkpoint's quorum against the voters this hash commits and the configuration `governance_policy_hash` commits (ADR-030 §1 adoption amendment and §5 step 1), so it walks no earlier checkpoint, and pruning keeps no leaf for a walk. The architect agent made four choices within the ruling. The value holds `voters` beside the roles, because no extension commits the role definitions a member would otherwise derive the voters from; decision 29 now commits them, and `voters` stays because the ruling names it. The value holds no other governance field, because the ruling names members, roles, and voters. The counting member leaves itself out of the eligible signers when the snapshot under test does not list it, because a member the checkpoint predates cannot have signed it. When the latest checkpoint falls short of the count, the member rebuilds from the first leaf when it holds every leaf, and otherwise grants no right until a checkpoint signed by the current voters exists. Two facts beside the ruling, which are the architect agent's and not part of it. The field's JCS form takes up to 154 bytes, not 32, because RFC 8785 writes each of the 32 bytes as a decimal number, as it does for the extension's other three hashes. The log head a joiner checks travels in the `0xFF04` extension of the GroupInfo that the adding committer signs (`07-trust-validation-and-capabilities.md` §7.3.1.1, "The members a Commit adds"), not in the group context, while the ceiling hash and the economic policy hash are in the group context. ADR-030 pruning invariants 6 and 7 stay, because no committed hash covers `ttl_deadline_unix` or `recorded_proposals`. **Amended by decision 27:** the group context now commits the log head, the joiner counts no quorum, and invariant 7 is withdrawn; invariant 6 stays.
26. **The checkpoint snapshot holds no sender key epochs.** The architect agent decided this from the artifacts. A sender key epoch advances by a `SenderKeyEpochAdvance` application message (`09-security-model.md` §9.16.3), and ADR-011 admits to the canonical log only records every member appends identically and in one order. Two signers that compute the snapshot at one leaf count can therefore hold different epochs, so a snapshot that held them could miss its quorum whenever an advance was in flight. `09-security-model.md` §9.16.1 already keeps receive-side epoch state on the node that holds it, with no authority elsewhere. The `sender_key_epochs` field is removed from `ContextStateSnapshot` (ADR-030 §1 amendment), and a joiner learns each member's epoch from the header of that member's first message or its next `SenderKeyEpochAdvance` (`09-security-model.md` §9.16.2, "New member join"). The snapshot's `outlets`, `blocks`, and `ucan_revocations` fields share the problem, because a registration by `outlet:register`, a block, and a UCAN revocation each travel outside a Commit; how each reaches every member in one order was open (`00-open-questions.md`, "Checkpoint snapshot fields that no Commit orders"). Decisions 28, 30, and 31 resolve it: a revocation and an outlet change ride a Commit, and the snapshot holds no `blocks`. The snapshot's `mls_epoch` stays, because decision 24(h) fixes it to the epoch the Commit appending the leaf at `checkpoint_seq` created, and every member that processed that Commit holds that epoch.
27. **The group context commits the event-log head, and members take kept leaves by inclusion.** Alec ruled on 2026-10-20, choosing the option "Commit log head", which read: "Put log_head_hash = SHA-256(count || merkle_root || head) in the 0xFF02 GroupContext extension, recomputed by every receiver on each Commit that appends leaves. A joiner then accepts every kept leaf by inclusion, with no leaf signature to verify. That closes the forged-suffix defect, the lockout from a retained TTL leaf whose committer was later marked compromised, and the Unanimity deadlock when two voters join between checkpoints. Because a checkpoint leaf's inclusion proves every member validated it at commit time, joiners never read cosigners' key logs, which removes the split. Cost: one GroupContextExtensions proposal on every Commit that appends a leaf. The value is a hash, so a relay learns nothing from it." The `0xFF02` extension gains `log_head_hash`, SHA-256(BE64(`count`) ‖ `merkle_root` ‖ `head`) of the commit-ordered event log (`05-contexts.md` §5.13.3 "Log head"). Rule 11 makes every receiver recompute it on each Commit whose block carries a leaf, and rule 14 makes a joiner, an importer, and a restorer check the log they rebuild or hold against it and accept each leaf by its inclusion, verifying no leaf signature and counting no checkpoint quorum (`07-trust-validation-and-capabilities.md` §7.3.1.1, "The members a Commit adds"; ADR-030 §1 adoption and §5). The architect agent made these calls within the ruling. (a) The log is the commit-ordered log whose `sequence` and `prev_hash` step 1.6 sets, the log ADR-011 makes identical at every member. (b) The preimage has no domain separator, as the ruling's formula has none; it is a hash input, not a signed preimage, and it is exactly the 72-byte `0xFF04` body, so `0xFF04` stays as the carrier of the preimage, and the committed hash carries the trust. (c) A checkpoint Commit carries the one GroupContextExtensions proposal too, which amends decision 24(g); it changes only `log_head_hash`, which no snapshot field holds. (d) The cosignature split, where two honest receivers that had adopted different heads of a signer's key-event log reached different verdicts on one Commit, is closed only up to a gap: a member that processes a Commit verifies every leaf signature and every checkpoint signature under the key it resolved when it verified the `0xFF03` attestation on the signer's leaf in the Commit's sending epoch, and reads no key-event log (step 1.6). The attestation sits in the ratchet tree every member holds, but it names the role `#active`, not a key, and each member resolved that role against its own view of the signer's key state when the leaf entered or was replaced in its tree. Every member that admitted the leaf holds the key the attestation's signature verifies under, because checks 1 and 3 of §9.7.1 admit the leaf only then. But a member that processes the Commit bringing the leaf after the signer rotated `#active`, or with a fresher cache of the signer's key state, rejects the leaf and so a Commit the others accept, and a Welcome joiner, an importer, or a restorer holds no resolved key for a leaf already in the tree. SCP-315 owns the fix (`09-security-model.md` §9.7.1, "Known gap: members can resolve different keys for one attestation"). A signer whose `#active` rotated replaces its leaf before it signs again, by a Commit whose block is empty when the signer commits it itself (`09-security-model.md` §9.12 step 2). The architect agent chose the empty block over signing that Commit's leaves under the key of the leaf being replaced, because that key is the one the rotation retired, possibly compromised or no longer held, and a leaf signed under the new key fails every receiver's check against the replaced leaf's key. `key_state_head` stays in every preimage, for a verifier outside the group. (e) The forged suffix closes: the joiner checks the `0xFF04` body against the hash every member computed before it merged the Commit, and its epoch secrets derive from the group context that holds that hash (RFC 9420 §8), so an adding committer that writes another hash places the joiner in an epoch no other member holds. Until the joiner hears from another member it cannot tell, which is the trust MLS already gives the committer that sends a Welcome. (f) The lockout from a kept TTL leaf whose committer was later marked `Compromised` closes, because no joiner verifies a kept leaf's signature. (g) The `Unanimity` deadlock when two voters join between checkpoints closes, because no joiner counts a quorum. (h) Decision 23's open outcome closes for members; it remains for a verifier outside the group, which holds no committed head. (i) ADR-030 pruning invariant 7 is withdrawn and the adoption check of `recorded_proposals` against its leaves removed, because the snapshot's digest sits in an included `Checkpoint` leaf every member validated. Invariant 6 stays, because every member derives the TTL deadline from the latest TTL leaf (§7.3.1.1), and the check of the snapshot's `ttl_deadline_unix` against that leaf stays with it. The ruling's cost is one GroupContextExtensions proposal per leaf-bearing Commit: 1 byte of `ProposalOrRef` type, 2 of proposal type, 2 of the extension list's length, 2 of extension type, and 2 of the extension data's length, so 9 bytes plus the `0xFF02` extension's JCS length L while L is under 16,384, plus any other group-context extension the list carries; L grows by 146 bytes for this field. Beside the ruling, a Commit that carries a GroupContextExtensions proposal must carry an UpdatePath (RFC 9420 §12.4 and the "Path Required" column of §17.4), so every leaf-bearing Commit, an `AddMember` one included, carries a path: under the DHKEM(P-256) suite that is 185 bytes for each path node with one resolution node, at least 1,295 bytes for the seven path nodes of a 96-member group plus the 2-byte length of the nodes vector, a lower bound because blank nodes enlarge a resolution, plus the committer's new LeafNode. Decision 32 puts the proposal, and so the path, on every Commit.
28. **A Commit carries each UCAN revocation.** Alec ruled on 2026-10-20, choosing the option "Commit leaf", which read: "A Commit carries a TokenRevoked leaf authorized by the token's issuer or the context creator, so every member and joiner refuses a revoked token from the same epoch on. Cost: one epoch and one Commit per revocation." `07-trust-validation-and-capabilities.md` §7.3.1.1 "With a revocation" derives the leaf, `TokenRevoked` (`EventType` tag 7), whose payload is `[token_cid, token_payload]`, and step 2 authorizes it with no approval in every model when the committer is the token's `iss` or the committed `creator_did`. The governance state and the snapshot hold `ucan_revocations`, which only grows. The architect agent made these calls within the ruling. (a) The leaf carries the UCAN payload as well as its CID, so every receiver recomputes the CID (`09-security-model.md` §9.5.2, "UCAN CID computation") and reads `iss` from the bytes the CID covers; a leaf carrying only a CID would leave the issuer check to the committer's word. (b) `MAX_REVOKED_TOKEN_BYTES` is 8,192, which puts the leaves array at 8,507 bytes, within `MAX_GOVERNANCE_LEAF_BYTES`. (c) A revocation Commit carries that one leaf and nothing else in its block, like a checkpoint Commit, so the one epoch per revocation is the ruling's cost and no more. (d) ADR-016's `RevocationList` union merge and its distribution as MLS application messages are retired, in ADR-016, `09-security-model.md` §9.5.2 and §9.12 step 3, and `26-conformance-suite.md`. (e) The revoker denies the token from the moment it builds the revocation Commit and resends the Commit until one carrying the leaf merges; the state `RevocationPending` and its rollback to `Active` are retired with the merge. (f) A Broadcast context has no MLS group, and its revocation stays as ADR-016 states.
29. **The group context commits the role definitions, folded into the governance state hash.** The architect agent decided this from the artifacts. A joiner took the role definitions from the genesis context parameters that only the inviter's bundle signature authenticates, so definitions that keep the committed voters but give a role another capability, such as `member:invite`, would give the joiner rights no other member grants. The governance state hash's value gains `roles`, each custom `RoleDefinition` of the genesis `ContextParams` as a name and its sorted capabilities (`05-contexts.md` §5.13.3 "Governance state"), and rule 13 checks it with the rest of the value. The definitions are folded into `governance_state_hash`, not given a field of their own, because no `GovernanceAction` changes a role definition (ADR-031 §3), so a separate hash would never change after creation, and every field of `0xFF02` rides each GroupContextExtensions proposal, which decision 27 puts on every leaf-bearing Commit: a separate field would cost 146 more bytes on each one and buy nothing. Built-in roles are not listed, because §5.5.1 fixes them.
30. **In-context blocks leave the checkpoint snapshot.** Alec ruled on 2026-10-20, choosing the option that read: "The snapshot loses `blocks`, and cosigners agree. Enforcement doesn't change. Bans still ride Commits. Spec 09 step 7's MemberBlocked record stays an application message, so a joiner never learns of an earlier in-context block." `ContextStateSnapshot` loses `blocks` (ADR-030 §1), and `09-security-model.md` §9.16.3 step 7 states that the `MemberBlocked` record is an application message that no Commit derives and no snapshot holds. The ruling rests on `09-security-model.md` §9.16.4: "Blocking is a per-relationship decision, not a group decision." Enforcement is the blocker's sender-key rotation (§9.16.3), which no governance state reads.
31. **One outlet registration mechanism, and a context policy that routes some changes to a vote.** Alec ruled on 2026-10-20: "If we can't differentiate then do it by role. But it would be nice to differentiate by some context config so that certain outlet additions, likely by capability or read access, get sent to vote". Every detail below is the architect agent's design under that ruling. An outlet is registered, changed, or removed only by a Commit carrying an `OutletRegistered`, `OutletUpdated`, or `OutletRemoved` leaf (`05-contexts.md` §5.4, "Registration and its policy"; `07-trust-validation-and-capabilities.md` §7.3.1.1 "With an outlet change"). A holder of `outlet:register` sends that Commit with no vote, unless the context's outlet registration policy routes the change; a routed change executes only as a `RegisterOutlet` or `RemoveOutlet` action, whose executing Commit derives the same leaf. The policy, `OutletRegistrationPolicy { vote_actions, vote_context_readers, vote_priced }`, is a required field of the genesis `ContextParams`, changes only by a `SetOutletRegistrationPolicy` action, and is folded into `governance_state_hash`. Its three keys are signed fields a receiver checks from the header: `kind`, for the capability an outlet exposes, `outlet_call` for an Action outlet that may change context state; the new `reads_context`, for Alec's read access; and a positive cost or a pricing formula. No registration field declared read access, so `OutletRegistration` gains `reads_context`, and the operator's preimage moves to `"SCP-OUTLET-REGISTRATION-V3:"` with `reads_context_byte` after `kind_byte` (§5.4.1), and decision 33 adds `key_state_head` after `registered_at_be`. No field declares a capability an outlet requires, because an outlet acts through the invoker's handle under the invoker's capabilities. A change matches when any header it adds, replaces, or removes matches. A leaf and a `RegisterOutlet` action carry the `OutletRegistrationHeader`, every term of the V3 preimage with each hash already computed, because one registration's two schemas may reach 128 KiB; the header's leaf array is at most 1,521 bytes, and a `RegisterOutlet` Commit's leaves at most 10,521, with decision 33's `key_state_head` included. The registrant sends the full registration as an application message, and a member invokes an outlet only once it holds a body that matches the header and whose operator signature verifies, as log-anchored evidence by decision 33. No receiver verifies the operator signature when it processes the Commit, because the operator need not be a member and its key-event log is not group state. ADR-010 criterion 2 and every SDK's `registerOutlet` submit through this path with the caller's identity and return `Registered` or `Proposed`; no SDK registers an outlet only in its local registry. Removal and change follow the same policy, so every mutation §5.4 names is a leaf every member holds. Decision 35 replaces the three booleans with a rule list, makes `reads_context` a set of read areas, adds `declared_capabilities`, and raises the two sizes to 3,569 and 12,569 bytes.
32. **Every Commit carries the GroupContextExtensions proposal, and every Commit's ciphertext is padded to a multiple of 4,096 bytes.** Decision 27 put one GroupContextExtensions proposal, and with it an UpdatePath, on every Commit whose block carries a leaf, and `09-security-model.md` §9.10.3 padded no Commit, so a relay could tell a leaf-bearing Commit from one with an empty block, such as a periodic key update, by its length, which partly undid the fixed 32,768-byte block. RFC 9420 §12.4 already requires an UpdatePath on a Commit that covers no proposals, so a Commit with an empty block carried a path too; the proposal and its extension were the difference, together with whatever the path's resolution added. The architect agent's design: rule 11 puts exactly one GroupContextExtensions proposal on every Commit, carrying the extensions unchanged when the block is empty (`05-contexts.md` §5.13.3 rule 11), and every committer zero-pads the `PrivateMessageContent` of every Commit so that its `PrivateMessage` `ciphertext`, the padded content plus the 16-byte AEAD tag, is a multiple of `COMMIT_PADDING_MULTIPLE`, 4,096 bytes (RFC 9420 §6.3.1; `09-security-model.md` §9.10.3 "Commits" and §9.18.A). Commits are `PrivateMessage` under `PURE_CIPHERTEXT` (ADR-057 T3), so the padding is the MLS layer's own; the block sits in `authenticated_data`, outside it, at a fixed size. 4,096 is the §9.10.3 4 KB bucket. It costs at most 4,095 bytes per Commit, about 12.5% of the 32,809 bytes the block adds, and it hides within one multiple the differences in path length that blank nodes and LeafNode size cause. No receiver checks the padding, because it protects the Commit against a relay, and a committer that omits it exposes only the length of its own Commit. The rule names the ciphertext, not the content, because RFC 9420 §6.3.1 leaves the padding length to the sender and openmls 0.9.0 pads the content plus the AEAD tag to the multiple it is configured with, so a rule over the content alone cannot be met through it. openmls reads that multiple from the group's join configuration for every message the group encrypts, so the committer sets it for each Commit it creates and clears it afterwards. Application messages get no MLS padding: a `PrivateMessage` carries its `content_type` in the clear (RFC 9420 §6.3), so padding them would not hide which messages are Commits. The open question on Commit length is removed from `00-open-questions.md`. Rejected: padding without the proposal on every Commit leaves the proposal's 9 + L bytes as a difference that crosses a multiple whenever the rest of the content sits within 9 + L bytes of a boundary, so the length still leaks for some Commits. The proposal without padding leaves path-size differences readable. A multiple of 256 or 1,024 bytes lets a relay read the path-size changes that the tree's blank nodes cause. A multiple of 16,384 bytes costs up to 16,383 bytes per Commit, about half the block. Leaving the leak open keeps a signal that the fixed block exists to remove. **Amendment (2026-10-24, ADR-067):** every Commit changes `merge_state_hash` (`05-contexts.md` §5.13.3 rules 11 and 16), so a Commit with an empty block carries the proposal with that one field changed, not with its extensions unchanged.
33. **The operator's registration signature is log-anchored evidence.** Decision 31 had each member verify the operator's signature on an outlet registration body before it invokes the outlet, under the operator's key, and put the `"SCP-OUTLET-REGISTRATION-V3:"` separator in no class of `09-security-model.md` §9.7.1, so the default class applied. Members verify a body when it reaches them, at different times (`05-contexts.md` §5.4, "Registration and its policy"); after the operator rotates `#active`, a member that verifies later rejects a body that a member that verified earlier accepted, and the two disagree on whether the outlet can be invoked. The architect agent's design: the V3 preimage gains the operator's `key_state_head` after `registered_at_be`, the header array gains it before `signature`, and the separator joins the log-anchored class, so the signature verifies iff the key that held the operator's `#active` was `Current` at that position, and a later rotation changes no member's verdict, whenever the member verifies (§5.4.1). A key the operator's state lists `Compromised{from: N}` follows that class's first-seen test, the one case in which two members' verdicts can still differ, as for every log-anchored artifact. A member that cannot resolve the operator's key state through that position holds no verified body yet and does not invoke the outlet. The domain stays V3, because it was introduced in the same change, before any implementation signed under it. The header grows by 34 bytes, so an outlet leaf array is at most 1,521 bytes and a `RegisterOutlet` Commit's leaves at most 10,521, both under `MAX_GOVERNANCE_LEAF_BYTES`, and the header array's 14 elements still take a 1-byte array header. Rejected: verifying the signature once, when the receiver processes the Commit that adds the leaf, and recording the verdict in governance state, gives every member one verdict but makes each receiver read the operator's key-event log during Commit processing. That log is not group state, so two receivers holding different heads of it would fork on the Commit, the split decision 27 removed for members (`07-trust-validation-and-capabilities.md` §7.3.1.1 step 1.6), and an operator log that a receiver cannot reach would block the Commit at that receiver.
34. **The `0xFF02` extension carries no context mode.** The extension had a `context_mode` byte, 0 for `Encrypted` and 1 for `Broadcast`, and rule 11 listed it among the genesis facts no Commit changes. A broadcast context has no MLS group (`05-contexts.md` §5.14), and the extension exists only in an MLS group's context, so the value 1 can never occur and the byte commits nothing. The architect agent's design: the field is removed, and rule 10 makes a member reject an MLS group whose context parameters name `Broadcast`, the check the byte stood in for (`05-contexts.md` §5.13.3 rules 10 and 11). The ADR-030 `ContextStateSnapshot` keeps its `context_mode`, because a snapshot also describes a broadcast context. Rejected: keeping the field with the value 0 alone leaves a byte every member writes and checks that can hold one value. Keeping the value 1 leaves a case no MLS group can reach, and a check for it that no test can run against a real group. Decision 38 reverses this decision: a broadcast context's authors group is an MLS group, and its extension carries `context_mode` 1.
35. **The outlet registration policy is a rule list.** Alec ruled on 2026-10-21: "Yes to all granularity options/rule list for outlets". Every detail below is the architect agent's design under that ruling. Decision 31's three booleans become `OutletRegistrationPolicy { rules }`, at most 32 rules whose RFC 8785 form is at most 4,096 bytes, so a `SetOutletRegistrationPolicy` action fits `MAX_GOVERNANCE_ACTION_BYTES` (`05-contexts.md` §5.4, "Registration and its policy"). A rule names the changes it reads (add, update, remove), the fields an update must change, and conditions on a header the change touches: its kinds, its read areas, its declared capabilities, a price above a floor or in another currency, a payee other than the operator, a pricing formula, and an operator outside a list. A rule requires a vote or a role. Every rule that matches applies: one that requires a vote sends the change to a `RegisterOutlet` or `RemoveOutlet` action, and otherwise the committer needs `outlet:register` and a role every matching role rule lists, so a rule added to the policy never loosens what the others require. `reads_context` becomes a `ContextReadAreas` byte, one bit each for the messages, the event log, the membership, and the outlet registry, with all four when absent. The registration and the header gain `declared_capabilities`, the §5.3.1 capabilities the invoker's handle lets the executor exercise, at most 2,048 bytes, and the preimage gains `capabilities_hash` after `reads_context_byte` (§5.4.1). Decision 31 said no field declares a capability an outlet requires; an outlet still holds no capability of its own, but it now declares which of the invoker's it uses, because Alec's ruling of decision 31 names capability as a routing key and no signed field carried one. An executor that reads outside its areas gets `protocol.context-read-violation`, and one that exercises an undeclared capability gets `protocol.capability-not-declared`. The domain stays V3, as decision 33 kept it, because no implementation has signed under it. The header array grows to 15 elements, still a 1-byte array header, and by at most 2,048 bytes, so an outlet leaf array is at most 3,569 bytes and a `RegisterOutlet` Commit's leaves at most 12,569, both under `MAX_GOVERNANCE_LEAF_BYTES`.
36. **A governance read revocation and a content key rotation bind a sender key rotation to their executing Commit.** Alec ruled on 2026-10-21: "Yes to ban rotate commit". Every detail below is the architect agent's design under that ruling. The executing Commit of `RevokeAccess` with `Read` or `Both`, and of `RotateContentKeys`, creates MLS epoch F. Every member that keeps read access rotates its sender key and publishes its advance, with a pushed entry for every chain except the revoked identity's (decision 37), before it encrypts any message in epoch F or later. A key's bound epoch is the MLS epoch of the message that carried its advance; a `SenderKeyResponse` carries it as `bound_epoch`, inside its HPKE `aad`. A receiver rejects a message sent in epoch M under a key bound below F, the latest binding epoch at or before M (decision 39), so no member's message after the Commit is readable under a key the revoked identity holds, and every member reads the boundary from the one Commit all of them merged (`09-security-model.md` §9.16.10). The rotations are application messages, and the Commit carries no new leaf.
37. **A block stays an application message, and the advance carries the new key.** Alec ruled on 2026-10-21: "Yes to block app msg but it needs to become effective asap so blockees lose read access immediately upon being blocked and I don't want confusing epoch delivery fragmentation". Every detail below is the architect agent's design under that ruling. Every `SenderKeyResponse` starts a push chain between the key holder and the requesting device, seeded by an HPKE export from that response, so no sender key is sealed to the stable wrapping key, which `09-security-model.md` §9.16.1 keeps out of sender key distribution, and no keri-owned key is involved. A `SenderKeyEpochAdvance` gains `pushed`, one 60-byte entry per chain the sender keeps, each the new key sealed under the chain's next message key (§9.16.9). The blocker drops its chains with the blocked identity and publishes the advance before any message under the new key, so every member it keeps installs the key from the message that announces it: the blocked identity cannot read the blocker's next message, and no member waits on a request and response, the epoch delivery fragmentation the ruling excludes. A member with no chain falls back to the request of §9.16.2. The blocked identity's own rotation excludes the blocker the same way. An advance is exempt from the 64 KiB management payload cap.
38. **A broadcast context's owner and authors form an MLS group.** Alec ruled on 2026-10-21: "Yes author mls". Every detail below is the architect agent's design under that ruling. Before it, a broadcast context had no MLS group (decision 24(j), decision 34), so its bans, its restores, and its subscriber registrations reached each member as relay messages that no Commit ordered, each member wrote a ban to its own ban record, and a `KeyEpochAdvance` leaf whose append failed left that member's log one leaf short with no repair. The owner and every author now form the authors group, which `07-trust-validation-and-capabilities.md` §7.3.1.1 governs as it governs an encrypted context's group, with the additions of `05-contexts.md` §5.14.13. Subscribers stay outside it and read through per-author broadcast keys. (a) An author joins only by an `AddMember` that names a `messages:write` role, and a `ChangeRole` or `RevokeAccess` that takes away an author's write right removes its leaf. (b) A subscriber joins and leaves by a signed registration record that any author carries in a registration Commit, in `registrations`, the fifth item of the block body. The body has five items in every context, which adds one byte to each figure of decision 24(d): the full body is 32,014 bytes with 750 to spare, a requested-reset body 22,631, a recording body 8,756, and a checkpoint body 15,614. A Commit carries at most 16 records in at most `MAX_SUBSCRIBER_REGISTRATION_BYTES` (26,368), and receivers verify no join's subscriber or UCAN signature, for decision 33's reason; decision 39 makes them verify a departure. (c) The governance state gains `subscribers` and `read_bans`, outside `governance_state_hash`, and the ADR-030 snapshot gains their Merkle roots and counts, with the sets sent beside it. (d) A ban, a restore, and a `RotateContentKeys` execute as authors-group Commits. After a ban or a rotation every author rotates under decision 36's binding before its next envelope and announces the key in a `BroadcastEpochAdvance` that pushes it on decision 37's chains. `ReadAccessRevoked`, `ReadAccessRestored`, `ContentKeysRotated`, and `WriteAccessRevoked` stay local `ContextEvent`s, because the `GovernanceActionExecuted` leaf already records each action. (e) A subscriber verifies the authors group's state by a chain of checkpoints that authors publish under their broadcast keys; each checkpoint carries the previous checkpoint's quorum beside its own, and no Commit may leave the members unable to meet the latest checkpoint's quorum. (f) The authors group travels at the HKDF routing ID of `09-security-model.md` §9.10.4, and registrations, advances, and envelopes at the public one. (g) The `0xFF02` extension carries `context_mode` again, after `promotion_policy`, and rule 10 requires it to equal the mode of the context parameters a member installs (`05-contexts.md` §5.13.3), which reverses decision 34. This decision supersedes decision 24(j) and decision 34. No key epoch advance is a log record, by decisions 36 and 37, so the `KeyEpochAdvance` event type is removed and its tag 18 retired (`00-open-questions.md`, "`KeyEpochAdvance` records").

    **Amendment (2026-10-21): the authors group orders only the authors' governance.** Alec narrowed this decision on 2026-10-21: "Subscribers do not need to know who is banned.. again it feels like you are inventing problems for the broadcast case that don't really exist", "Broadcasts are basically read only contexts with some governance and open/closed-ness defaults", "(Read only unless you are an author)", and "I am confused. Why are you trying to redesign broadcast contexts". He then answered "Yes……" to this resolution: the authors-only MLS group orders the authors' governance log, and everything else about broadcast stays as it was before this decision. (b) and (e) are withdrawn. A subscriber registers by the identity-signed request of an open context or the admin-issued `messages:read` UCAN of a gated one, outside the governance log, and each author keeps its own subscriber registry (`05-contexts.md` §5.14.3 and §5.14.4). No Commit carries a registration, so the block body keeps four items and the figures of decision 24(d) stand. No subscriber reads a checkpoint: a subscriber verifies an author by the envelope's signature and the author's `messages:write` UCAN (§5.14.5). (c) narrows to `read_bans`, which the governance state gains outside `governance_state_hash`, with its root and count in the snapshot, because every author refuses a banned identity and a joining author must learn the bans. Under (f), registrations travel at the public `routing_id` as relay messages, as they did before this decision. The authors group's Commits carry only the governance actions authors take: an author's grant and removal, a ban and its restore, a `RotateContentKeys`, a revocation, and an outlet change. (a), (d), and (g) stand, and subscribers learn nothing of a ban.

39. **Read access and key boundaries close the gaps decisions 36 to 38 left.** The cryptographer's reviews of decisions 36 to 38 found the defects below, and none needs a new ruling; every fix is the architect agent's design under those decisions and the amendment to decision 38. (a) A revoked or expired `messages:read` UCAN left a gated subscriber's push chains in place, so an author's next advance still carried its key. Each author now checks the subscriber's UCAN, each proof's CID against the authors group's `ucan_revocations`, and the UCAN's `exp` by the author's own clock, at each key request and before each push, and drops its chains with a subscriber that fails (`05-contexts.md` §5.14.4). The author's own clock decides, because the check is that author's alone and no receiver judges it. A set of subscribers that a Commit removes a revoked subscriber from was rejected under the amendment to decision 38. (b) No rule read a `BroadcastEpochAdvance`'s `bound_epoch`. A broadcast key response now binds `bound_epoch` in its HPKE `aad` (`05-contexts.md` §5.14.2), and an author merges the authors group before it seals and seals only under a key bound at or above the latest binding epoch it merged (§5.14.13). No subscriber checks the bound, because no subscriber learns of a ban. No reader rule takes a key back from its holder, so an author that a relay keeps from a ban discloses what it seals until it catches up. (c) A key holder that crashed between sealing and persisting `ck_{i+1}` could seal two keys under one `k_i` with the zero nonce. It now persists the new key, the epoch, the advance's bytes, and the next chain keys before it publishes, and `k_i` takes the epoch (`09-security-model.md` §9.16.9). (d) Decision 36's F was the latest binding epoch the receiver merged, which rejected a message sent before a revocation and delivered after it. F is now the latest binding epoch at or before the message's epoch (`09-security-model.md` §9.16.10). (e) The outlet policy's `price_above.amount` was a JSON number in `governance_state_hash`; it is now ADR-060's decimal string, `"0"` for the amount zero (`05-contexts.md` §5.13.3). (f) §5.14.12 now states the subscriber-visibility residual: a registration, a key request, and each pushed entry's `chain_id` are visible at the public `routing_id`. (g) A member that joins by Welcome, an importer, and a restorer merged none of the binding Commits before their entry, so each knew no binding epoch and accepted a message sent after a revocation under a key the revoked identity holds. The `0xFF02` extension now carries `binding_epoch`, which only a binding Commit changes, and each such member installs it (`05-contexts.md` §5.13.3 rule 15, `09-security-model.md` §9.16.10). A snapshot field was rejected, because a joiner adopts the latest checkpoint's snapshot, which misses a binding Commit made after that checkpoint.
### Rejected Alternatives

- **(A) A Commit per action, with no proposal or vote messages.** Each proposal and each vote is itself a Commit carrying a leaf, so every member sees every step in one order. That needs no application-message types and no executability rule. It costs one epoch advance, and a full UpdatePath, per vote: a 64-signer `Threshold` proposal costs 65 epochs where C1 costs one, and every vote waits its turn in the single-committer-per-epoch race, so concurrent voters keep losing Commits and retrying. It also makes every vote a canonical leaf, so the log grows with deliberation rather than with decisions.
- **(B) Application messages with no Commit.** Proposals, votes, and executed actions all travel as application messages, and each member applies an action when its own tally says the action passed. That costs no epoch advance. It fails because the order across senders is not fixed: a demotion and the demoted admin's next action can be applied in different orders at different members, so one member accepts the action and another rejects it, and role state forks with no honest member at fault. ADR-031 §8 as written had this flaw for every action that changed no membership.
- **ADR-051 DAG ordering.** Governance leaves join the causal DAG that orders application events, and every member linearizes them identically. That needs no new Commit traffic. But the DAG's order is fixed only at a causally stable cut, after every member has seen every concurrent branch; before that, two members holding different frontiers apply different role states, which is the fork of (B) for the time it takes the cut to stabilize. The DAG also orders events against each other, not against the MLS epoch, so a message sent under a new role can still be decrypted before the role change is ordered. And a delivery path that later carries the leaf still races the Commit, which reopens the gap this record closes.
- **A role guessed at the receiver.** A non-committer that has processed an add-Commit assigns the new member a default role such as `member`. It costs nothing on the wire. It is a fail-open: §5.5.1 gives `member` `messages:write` and outlet invocation, so a context that admitted someone as `observer` would see that member write at every non-committer, and the receiver's role state would hold a role no signed leaf records.
- **A separate role field in the Commit.** The committer binds only the new member's role into the Commit's authenticated data, as ADR-057 T3 binds a timestamp. That is smaller than a full leaf. But the role is then recorded twice, in that field and in the leaf, and the two can disagree, and every further rights-changing action would need a field of its own.
- **Sender-chosen times for authorization.** The proposal names `created_at`, a vote names `expires_at`, and a receiver compares them with the timestamp T of the Commit's `GovernanceActionExecuted` leaf. That needs no new state. But the proposer chooses `created_at` and the executor chooses T: a backdated proposal drops recent joiners from eligibility, a forward-dated one escapes the conflict rule, a T set early counts an expired or withdrawn vote, and a T set to a far-future time wedges every later Commit, because each receiver required each leaf's timestamp to be no earlier than its log head's.
- **Epochs as the anchor and the conflict clock.** The proposal names the MLS epoch it was created in. A live receiver knows every epoch, but a member rebuilt from a checkpoint replays leaves that do not name the epoch whose Commit carried them, so it could not rebuild the conflict state. Every leaf names its sequence. Votes still expire by epoch, because only a live receiver checks a vote.
- **A voter set frozen by join point.** Eligible voters are the members whose join point is at or before the proposal's anchor, as ADR-031 §4c froze the set at creation. That keeps late joiners from voting. It costs a check the proposer controls: the anchor is the proposer's choice, so an anchor named early drops every recent joiner, which is the backdating attack moved from the clock to the log.
- **Conflicts over the full action history.** A receiver compares the proposal against every action executed since its anchor, pair by pair, under the ADR-031 §7 list. That is exact. It needs every executed action since the oldest live anchor, which a checkpoint lets a member prune, so a rebuilt member would decide differently from a live one. One sequence per conflict key gives the same answer for every listed pair, adds only pairs whose second action changes nothing, and fits in the snapshot.
- **Splitting an action across Commits.** An approval set too large for one block is cut at record boundaries into up to 64 parts, sent in consecutive Commits, staged by every receiver, and re-checked at the final part. That carried at least 6,000 approvals. It needed a part header, durable staging, a final-part re-check, re-carried re-signed votes, five ways for a transfer to end, a 256-epoch bound, and a rule that committers hold adds and resets while a transfer is staged, which receivers could not check. Review found that an invite holder could end every multi-part vote with resets, that a proposer could stall adds for 256 epochs, and that routine key updates in a large context voided staged votes faster than the executor could re-carry them. Alec ruled it out for now.
- **Size buckets up to 256 KiB.** The block grows to the smallest §9.10.3 bucket that holds the action, up to 262,144 bytes, the example relay entry's `max_blob_size` (`18-addressability-and-deployment.md`). That holds about 1,500 votes in one Commit. But the bucket tells a relay which Commits execute large governance actions and roughly their approval count, and a fixed 262,144-byte block on every Commit costs 8 times what 32,768 costs. A fixed 32,768-byte block leaks nothing, because every Commit carries one.
- **BLS aggregate signatures.** Every approval is merged into one 96-byte BLS12-381 signature with a bitmap of the voters, so a Commit holds any number of approvals. It fails the 2026-09-10 move of every SCP key to P-256: no Secure Enclave, passkey, TPM, or WebCrypto implementation holds a BLS12-381 key, so every voter's voting key would be a software key, the kind that move removed. It also needs a second key per member with a proof of possession against rogue-key attacks.
- **65 approvals in a 16 KiB block.** The block stays at 16,384 bytes, `MAX_GOVERNANCE_ACTION_BYTES` falls to 2,048, and the cap is the 65 approvals that fit beside the largest proposal and its leaves. That costs half as much per Commit. Alec chose 96 approvals in a 32 KiB block with the 8 KB action limit kept.
- **Carrying the action in both the proposal and the leaf.** The block's proposal record keeps `action_bytes`, and the `GovernanceActionExecuted` leaf holds the action again. That needs no second record type. But the action is carried twice, which at 8,192 bytes leaves too little room for 96 approvals in 32 KiB, and the two copies can disagree, so every receiver must also check that they match.
- **A reset that moves the join point.** A `MemberReset` leaf sets the member's join point to its own sequence, as a rejoin does. That treats every leaf that adds a member alike. But a member can request its own reset (`23-sync-and-offline-strategy.md` §23.5.2), so any member could cancel every pending action that names it, such as its own demotion, by asking for a reset, since conflict rule 2 rejects an action whose subject joined at or after the anchor.
- **A reset floor set from the reset Commit's epoch.** A receiver accepts a request only when its `last_known_epoch` exceeds the member's floor, and a reset sets the floor to the epoch it creates. That needs no counter. But the floor then comes from a leaf value no request signs, which a committer could write as it chose, and a request the member signed during an earlier membership names an epoch range a new membership can reach again. A signed per-member counter that the executed request sets needs no unsigned value.
- **Per-action leaves beside the `GovernanceActionExecuted` leaf.** The Commit carries the ADR-011 leaf of each action, such as `RoleAssigned` for `ChangeRole`, as the committer builds it. That keeps every consumer of those leaves unchanged. But no receiver checked which leaves a Commit carried, so a committer could add a leaf no vote approved, such as a role assignment beside an unrelated action, and every receiver would apply it. Deriving each leaf from the action closes that, and recording the action once in `action_bytes` leaves nothing for a second leaf to add except where a rule reads it, as `05-contexts.md` §5.10 reads `TtlExtended`.
- **Consent from eligible voters only.** `ExtendTtl` and `PromoteContext` need every eligible voter under `SingleAdmin`, `Majority`, and `Unanimity`, and every signer under `Threshold`, and `05-contexts.md` §5.10 and §5.10.1 are amended to that rule. That keeps a context with a TTL bounded only by its voter limit. But a member without `GovernanceVote` joined expecting the context to expire and could then have it extended or made permanent without its approval. Alec chose every member (decision 15).
- **The TTL deadline derived from the log.** Each member derives its deadline from the create base and the `TtlExtended` leaves in its log, as ADR-049 did. That adds no snapshot field. But a member rebuilt from a checkpoint after an extension leaf was pruned derives a shorter deadline, so it rejects the next honest `ExtendTtl` Commit, whose derived `old_deadline_unix` differs, and destroys its keys early. Taking the deadline from the snapshot alone fails differently: a live member that pruned against a checkpoint it never adopted has no snapshot to read, and the checkpoint quorum, the admin alone under `SingleAdmin`, could write a later deadline or none. The latest TTL leaf is kept through pruning instead, every member derives the deadline from it, and the snapshot's `ttl_deadline_unix` must match it.
- **A hash of the genesis parameters in `0xFF02`.** The extension commits `SHA-256(JCS(context_params))`, which binds `ttl`, the promotion policy, and every other parameter at once. But roles, outlets, and the economic policy change by governance after creation, so a later joiner holds current parameters whose hash differs from the genesis one, and it would need the genesis parameters as well, which only the inviter supplies. Two fields commit exactly the two genesis values the governance checks read.
- **The bundle signature alone.** The joiner keeps trusting `ttl` and the promotion policy because `genesis_params_hash` in the bundle preimage covers them. That needs no extension change. But any member can sign a bundle (`05-contexts.md` §5.13.3 rule 8), so the signature proves only that one member chose the values.
- **Blocks sized to their contents.** Each Commit carries a block padded to the smallest §9.10.3 bucket that fits, and a Commit with no governance action carries none. That saves bytes on every key-update Commit. But a relay then sees which Commits execute governance and roughly how many votes they carry, which §9.10.1 makes confidential.
- **The code's `GovernanceModel` as the governance policy.** The hash covers `ContextParams.governance` as the shipped code types it, whose `Majority` and `Unanimity` variants carry `eligible_voters`. That needs no new hash input. But the voter list changes whenever a member gains or loses `GovernanceVote`, so every such add, removal, and `ChangeRole` Commit would carry a GroupContextExtensions proposal, and the list would record a second time the membership and roles the leaves already fix. Its `SingleAdmin` variant also names no admin.
- **`SingleAdmin` without its admin.** The hash covers `GovernanceModelConfig` with `admin_did` left out, so the `SingleAdmin` hash stays a constant and a `TransferAdmin` Commit carries no GroupContextExtensions proposal. That saves one proposal per transfer. But a joiner then takes the current admin from the event log with no committed value to check it against, and the hashed value would no longer be the configuration ADR-031 defines, so two types would describe one governance policy.
- **The 24-hour economic policy period kept.** The new policy takes effect at least 24 hours after its event, or after the longer `economic_policy_notification_period_secs` a context sets, as §19.3 said. That gives members a day after the vote to leave before new pricing applies. But each receiver would decide when the policy changes by reading its own clock, which decision 10 forbids, so members could charge different prices for the same message.
- **A ceiling change in one Commit.** The Commit that first carries a `ModifyCeiling`'s proposal also executes it, as decision 18 first stood. That costs one Commit per change. But under `SingleAdmin` the admin needs no approvals, and no receiver can check that a proposal message was ever sent, so the new ceiling could take effect with no notice to any member. Alec chose two Commits (decision 20).
- **A recorded proposal that expires with its voting window.** A recorded `ModifyCeiling` leaves the recorded set when the §5.9.1 voting window ends. That bounds how long its leaf is kept. But the window ends at each member's own clock, which decision 10 forbids a receiver to read, so members would hold different recorded sets and reach different verdicts on the executing Commit.
- **A second recording mechanism for the economic policy.** An economic leaf type, set, snapshot field, and pruning rule beside the ceiling ones. It records the same fields under the same checks, so every rule of decision 20 would exist twice, and the two copies could drift. Decision 21 generalizes the one mechanism.
- **One recorded proposal per proposer across both kinds.** A recording replaces the proposer's entry whatever its kind. That keeps one entry per member. But a proposer could not hold a ceiling proposal and an economic proposal open at once, although the two never conflict, and recording one would silently drop the other.
- **Any member holding `GovernancePropose` sends the recording Commit.** A proposal could then be recorded while its proposer is offline. But a third party could record the proposer's older signed proposal over its newer one, and receivers would reject the execution the voters approved. Decision 21 lets only the proposer record.
- **The snapshot alone carries the economic policy, with nothing committed.** A rebuilt member would adopt the snapshot's `economic_policy` under the checkpoint quorum and check it against nothing. That needs no extension field and no retained leaf. But a quorum could install a policy no Commit executed, clear `locked`, or skip decision 21's recording epoch, and a forged leaf after the checkpoint could change the policy unseen.
- **A retained `SetEconomicPolicy` leaf in place of a committed hash.** Pruning keeps the latest `GovernanceActionExecuted` leaf of a `SetEconomicPolicy` (the withdrawn ADR-030 pruning invariant 8), and a rebuilt member checks the snapshot against it. That adds no GroupContextExtensions trigger to rule 11. But it checks only the snapshot: a forged executed leaf signed after the latest checkpoint carries no approvals a joiner can check, so the adding committer could still set the joiner's price.
- **The checkpoint quorum attests to the retained leaves.** A joiner accepts a retained leaf by its Merkle inclusion under the `merkle_root` of a quorum-attested checkpoint, in place of the leaf's own signature. That adds no field to `Event`. But it covers only leaves at or before a checkpoint, and the leaves after the latest checkpoint have none. A leaf after a checkpoint that changes the voters would be attested by the quorum those voters form, so a forged `TransferAdmin` leaf could name the signer that then attests it. And the checks of ADR-030 pruning invariants 6 and 7 exist so that a quorum cannot write in a value no Commit executed, which a leaf the same quorum attests cannot check.
- **A key-state head in the Commit.** The governance block carries the committer's head once, for all its leaves. That costs 32 bytes per Commit instead of 34 per leaf. But a joiner never receives the Commit, and pruning keeps leaves, not Commits, so the head would be gone when the leaf is verified.
- **A governed `SetEconomicPolicy` may set `locked`.** Members could vote to lock pricing for good. But §19.3 names the creator at creation as the one who sets the lock, and a lock a quorum sets binds every later member to a policy that member never saw at join.
- **The 72-hour period kept.** The new ceiling takes effect 72 hours after approval, as §5.3.2 said. That gives every member three days to leave after the vote completes. But each receiver would decide when the ceiling changes by reading its own clock, which decision 10 forbids, so members could apply the new ceiling at different Commits and their authorization checks would fork.
- **A 4,096-byte block.** The fixed block drops to the 4,096-byte bucket. That costs about 4.1 KB per Commit where 32,768 costs 32.8 KB. But 4,092 body bytes hold 24 votes and nothing else, fewer than a 64-signer `Threshold` approval set.
- **A separate cap for checkpoint leaves.** `MAX_GOVERNANCE_LEAF_BYTES` stays 9,728 for every Commit, and a checkpoint Commit has its own 15,616-byte cap. That leaves 6,639 spare bytes in an executing Commit. But a receiver would check a different limit by Commit kind, and both limits fit one 32,764-byte body, so the second limit buys only spare bytes no Commit uses.
- **A partially attested checkpoint committed with a flag.** The checkpoint Commit carries whatever cosignatures the window gathered, and receivers record it as `PartiallyAttested`. That commits every checkpoint a creator makes. But a member could not prune against it, a rebuilding member would meet checkpoints it must skip, and a creator alone could fill the log with checkpoints no quorum signed.
- **Counting a checkpoint's quorum against the voters its own snapshot names.** A rebuilding member reads the voters from the snapshot under test, and the group context commits nothing new. But a creator could write itself in as the only signer, and forged leaves after the checkpoint, such as a `TransferAdmin` the adding committer signed, could carry the forged voters back to the true current ones, so the result would still match every committed hash (decision 25).
- **A digest that also covers `member_since`, the conflict sequences, the reset floors, the TTL deadline, and the recorded proposals.** A joiner could then check every governance field against the group context, and ADR-030 pruning invariants 6 and 7 would lose their reason. But the ruling names members, roles, and voters, and every Commit that executes an action would then change the hash and carry a GroupContextExtensions proposal (decision 25).
- **A digest of members and roles only, from which a member derives the voters.** The hash input is smaller. But the role definitions that map a role to `GovernanceVote` come from the genesis context parameters that only the inviter's bundle signature authenticates, so a joiner given other definitions would derive other voters from the same committed roles (decision 25).
- **Keeping the walk over earlier checkpoints for a joiner the latest checkpoint predates.** A joiner that arrives after the voters changed could still adopt the latest checkpoint. But the walk must verify every earlier checkpoint's signatures, one key later marked `Compromised` stops it for every later joiner (decision 23), and members must keep every checkpoint leaf and every voter-changing leaf between them (decision 25).
- **Keeping `sender_key_epochs` and having each signer copy the creator's values.** The snapshot keeps every field ADR-030 gave it. But the cosigners would sign epochs they cannot check, and a joiner would trust the creator's view of other members' epochs, which §9.16.1 gives no authority beyond its own node (decision 26).
- **A receiver bound on `created_at`.** A receiver rejects a checkpoint whose `created_at` lies more than the one-hour window before its clock. That bounds staleness by time. But receivers' clocks differ, so two members could reach different verdicts on one Commit, and the requirement that `event_count` equal the receiver's leaf count already rejects a stale checkpoint.

- **The log head in `0xFF04` alone.** The joiner checks its rebuilt log against the GroupInfo extension the adding committer signs, and the group context commits nothing new. That costs no GroupContextExtensions proposal. But only the adding committer vouches for the head, so it alone can append forged leaves after the latest checkpoint (decision 27).
- **A GroupContextExtensions proposal on every Commit.** Every Commit, an empty-block one included, carries the proposal, so a relay cannot tell which Commits append leaves. That hides more than decision 27 does. But the ruling names the Commits that append leaves, and a proposal on every key-update Commit is a cost the ruling did not choose; the length difference is reported to Alec as open.
- **Live receivers check each signature at the signer's `key_state_head`.** A receiver resolves the committer's and each cosigner's key-event log at the head the leaf names, as step 1.6 required before decision 27. That lets a leaf outlive its committer's rotation without an Update. But a key-event log is not group state: two honest receivers that had adopted different heads of one signer's log reached different verdicts on one Commit, and their groups forked.
- **Revocations as application messages under a union merge.** ADR-016 as it stood: each member merges the revocation lists it receives. That costs no epoch. But members hold different sets at one leaf count, so two signers of a checkpoint compute different snapshots, and a joiner learns no revocation made before it joined (decision 28).
- **A separate `roles_hash` in `0xFF02`.** The definitions get their own field. That keeps the governance state hash's value smaller. But the definitions never change after creation, and every field rides each GroupContextExtensions proposal, which decision 27 puts on every leaf-bearing Commit, so the field adds 146 bytes to each for nothing (decision 29).
- **Blocks as commit-ordered leaves.** Each block rides a Commit, and the snapshot keeps `blocks`. A joiner then learns of earlier blocks. Alec chose otherwise, because a block is a per-relationship decision, not a group decision (decision 30).
- **Outlet registration by role alone.** Every holder of `outlet:register` registers with no vote. That needs no policy. It is the fallback Alec named for a context that cannot differentiate, and the signed `kind`, `reads_context`, and cost fields let it differentiate (decision 31).
- **The full registration in the leaf.** The leaf carries the whole `OutletRegistration`, so every member holds the schemas from the Commit. But two schemas may reach 128 KiB, beyond the 15,616-byte leaves array.
- **Receivers verify the operator's signature.** Each receiver resolves the operator's key and rejects a Commit whose header signature fails. That keeps unsigned headers out of the log. But the operator need not be a member, and two receivers holding different heads of its key-event log would fork, the split decision 27 closes; a member checks the signature before it invokes the outlet instead.
- **A first-match ordered rule list.** The first rule that matches decides, as in a packet filter. That lets a narrow rule exempt a case from a broader one. But a rule placed ahead of another loosens it without changing it, and a joiner must evaluate the order to know which changes need a vote; when every matching rule applies, a rule can only add a requirement (decision 35).
- **Read access as one boolean.** Decision 31's `reads_context` costs one bit. But a rule cannot tell an outlet that reads only the outlet registry from one that reads every message, a granularity the ruling of decision 35 accepted.
- **Each member rotates when it applies the revocation, with no bound.** That needs no new field. But a member that rotates late keeps sending under a key the revoked identity holds, and no receiver can tell that message from one sent before the revocation (decision 36).
- **The committer carries every member's new key in the Commit.** One message delivers every key. But each member's key is that member's to send, and it would have to reach the committer before the Commit (decision 36).
- **Seal the new key to each member's stable wrapping key.** That needs no chain state. But §9.16.1 keeps sender keys off the stable wrapping key, which lives for years, so one later compromise of it would open every sender key ever pushed to it (decision 37).
- **The pull path alone.** That costs no bytes per member. But each member reads the blocker's next message only after a request and a response, members hold the new key at different times, and the blocker must either wait or send messages some members cannot yet read, the fragmentation the ruling of decision 37 excludes.
- **Broadcast governance outside MLS, as relay messages.** That needs no group. But relay messages have no order every member shares, so two authors can apply a ban and a restore in different orders, and a leaf append that fails leaves one member's log short with no repair.
- **Subscribers in the group.** Every subscriber would then read the context's governance from its Commits. But every Commit and the ratchet tree grow with the subscriber count, the member limits of decision 11 would cap subscribers, and §5.14 promises unbounded subscribers.
- **The mode outside the extension, admitted by rule 10 alone.** A member would read the mode from the context parameters it installs. But a joiner takes those from a bundle that only its inviter signs, so one author could hand a joiner the wrong mode, and the joiner would accept or reject `AddMember` Commits that every other member decides the other way.

### Consequences

- A non-committer holds the same role and membership state, the same commit-ordered log, and the same executed-proposal set as the committer once it has processed the Commit.
- Every executed governance action costs one epoch advance, which also refreshes the group's keys. Every Commit grows by 32,809 bytes, the block plus its 4-byte size, because the block sits in `authenticated_data`, outside the content §9.10.3 pads (decision 32); a relay delivers that to every other member.
- A `Majority` proposal executes only when approvals exceed half of the eligible voters, until `00-open-questions.md` settles whether ADR-031 §4c's deadline arm survives.
- A voter withdraws an approval by replacing its leaf key, so withdrawing costs the voter one Commit, and it re-signs every other vote it keeps. The withdrawal reaches every action not yet executed.
- A leaf timestamp is the committer's claim. No receiver bounds it, and nothing that authorizes reads it, so it is evidence of what the committer's clock said and nothing more.
- A member that joins while a proposal is pending may vote on it and raises the count a `Majority` or `Unanimity` proposal needs.
- A member that changes its leaf key re-signs its pending proposals and votes.
- `MAX_GOVERNANCE_ACTION_BYTES` falls from 65,535 to 8,192, and the leaves of one Commit take at most 15,616 bytes, which a checkpoint with 95 cosignatures needs (decision 24).
- Every checkpoint in an encrypted context costs one Commit, and every member that processes it validates it against its own state. A checkpoint whose cosignatures arrive after a leaf-bearing Commit is discarded and made again.
- One Commit carries at most 96 approvals. A `Unanimity` context has at most 96 eligible voters and a `Majority` context at most 191; a context that needs more voters uses `Threshold`, whose approvals come from at most 64 signers. Under the deadlock fallback, a `Threshold` context with more than 191 eligible voters needs more than 96 approvals, so the fallback cannot execute there. `00-open-questions.md` records the cap for revisiting, as Alec asked.
- A context with a TTL has at most 96 members under every model, including members who have no vote, because every member approves an `ExtendTtl` or `PromoteContext`. A member without `GovernanceVote` can block either action. A context that needs more members has no TTL, or is promoted first.
- The event log holds each executed action's exact signed bytes and its `proposal_id` in its `GovernanceActionExecuted` leaf, so a member rebuilt from leaves applies the same bytes a live member applied. The log does not hold the proposer or `anchor_seq`, so no member can recompute `proposal_id` from the log; the leaf's `proposal_id` is the value every receiver recomputed and checked when it accepted the Commit.
- A joiner adopts the snapshot of the latest `Checkpoint` leaf included under the committed log head and counts no quorum (decision 27, which amends decision 25). Members keep every leaf after the latest checkpoint and the leaves ADR-030 pruning invariants 3 and 6 keep, and keep no leaf for a walk over earlier checkpoints; invariant 7 is withdrawn.
- A Commit that adds or removes a member or changes a role or the voters carries a GroupContextExtensions proposal, and every receiver hashes the resulting members, roles, and voters before it merges. A joiner that a change of voters postdates the latest checkpoint still adopts that checkpoint, because it accepts the leaf by inclusion under the committed log head and counts no quorum (decision 27).
- No checkpoint snapshot carries sender key epochs, so a joiner requests a member's sender key only once it has seen that member's epoch in a message header or an epoch advance (decision 26).
- In a `Unanimity` context, a checkpoint reaches its quorum only when every eligible voter cosigns, so one voter that never cosigns stops all pruning after the last checkpoint, and the log grows without bound for as long as that voter stays. ADR-066 sets no bound; `00-open-questions.md` records it.
- A reset requires the reset member's own signed request or an executed `ResetMember` action, and a re-added leaf newer than the one it replaces. Receivers verify the re-added leaf's `0xFF03` attestation as it enters the tree, so the reset check works only where that verification is wired.
- A signed reset request that no Commit executes stays usable until a request with a higher `reset_counter` executes or the member leaves; it has no expiry a receiver can check, because no receiver reads a clock. A member that holds both `member:invite` and `member:remove` and has captured such a request can execute it later with any fresh KeyPackage of the member whose attestation is newer than the member's current leaf. That disrupts the member, which loses the epochs between and must process a Welcome, but it cannot impersonate the member, because only the member holds the new leaf's private key. The member voids its outstanding requests by having a request with a higher counter executed. The relay's 30-second freshness check limits capture on the relay path only.
- The governance freeze for mutual removal and for a simultaneous commit, and the `ResolveConflict` action, no longer arise.
- A broadcast context's owner and authors form an MLS group that this record governs, and its Commits carry only the governance actions authors take; subscribers stay outside it, register with each author as before, and learn nothing of a ban (decision 38 and its amendment).
- Every Commit carries one GroupContextExtensions proposal and an UpdatePath (decisions 27 and 32), so an `AddMember` Commit, which needed no path before, now carries one, and a Commit with an empty block carries the proposal with its extensions unchanged except `merge_state_hash`, which ADR-067 has every Commit change. §9.10.3 pads every Commit so that its ciphertext is a multiple of 4,096 bytes, so a relay cannot tell a leaf-bearing Commit from one with an empty block by its length, and each Commit costs at most 4,095 bytes of padding.
- A joiner, an importer, and a restorer verify no kept leaf's signature and count no checkpoint quorum; they rest on the committed log head that every member computed (decision 27).
- Every UCAN revocation costs one Commit and one epoch, and every member and joiner refuses the token from that epoch (decision 28).
- A joiner never learns of a block made before it joined (decision 30).
- An outlet registered by a holder of `outlet:register` needs no vote unless the context's policy routes it, and a member invokes an outlet only once it holds a body matching the committed header (decision 31).
- A context's outlet policy sends a change to a vote or to a role by its kind, read areas, declared capabilities, price, payee, pricing formula, operator, and updated fields, and an outlet executor is held to the areas and capabilities it declares (decision 35).
- After a governance read revocation or a content key rotation, no member's message is readable under a key the revoked identity holds, and each member sends one advance (decision 36).
- A block takes effect at the blocker's next message, because every member it keeps holds the new key from the advance; an advance grows by 60 bytes per member device (decision 37).

### Acceptance Criteria

The stories that implement this record list their criteria in `.docs/prds/main.json` under the gate `gate-gov-commit`: SCP-331 (wire types and preimages), SCP-328 (the block codec), SCP-332 (engine intake and executability), SCP-335 (the Commit's approval count and conflict check, and, under ADR-067, G, the signed-leaf import, and the re-check in the losing branch's state), SCP-336 (signed leaves), SCP-333 (proposal and vote message routing), SCP-329 (the committer), SCP-330 (the receiver), SCP-337 (state reconstruction for a joiner), SCP-334 (the Welcome extension and the joiner gate), SCP-338 (the `0xFF02` fields the creator writes, the log head among them), and SCP-342 (outlet changes by Commit and the SDK registration path); `.docs/prds/outlet.json` SCP-OUT-040 builds the V3 outlet preimage, the registration header, and the policy type (decision 31).

---

## ADR-067: Concurrent Commits and fork merge

**Status:** Decided 2026-10-24, by Alec's ruling of that date (option 2).
**Date:** 2026-10-24
**Spec:** `07-trust-validation-and-capabilities.md` §7.3.1 (the leaf sequence) and §7.3.1.1 "Concurrent Commits and fork merge" (terms, choice, obligations, the fork record, the import, the re-check, G), `05-contexts.md` §5.9 invariant 2 and §5.13.3 rules 11 and 16 (`merge_state_hash`), `09-security-model.md` §9.5.2 (the `ForkNotice` and `DepartureRequest` preimages and the fork record), §9.7.2 (fork retention, the retained and excluded secrets, the PPRF), §9.9.3 and §9.9.4 (fork evidence), §9.10.1, and §9.14, `10-infrastructure-and-self-hosting.md` §10.8.1 (the device Add identity), `23-sync-and-offline-strategy.md` §23.4.1 (receipt rules and split recovery), §23.5.4, §23.6.1, §23.7, §23.8, and §23.16.3, and `25-test-vectors.md` §25.33 (Vectors 71 to 79).
**Amends:** ADR-066 decisions 5 and 10 and its acceptance-criteria wording for SCP-335; ADR-031 §7 and its 2026-10-17 amendment; ADR-029 §5b, §5c, and §6 step 4; ADR-001 criterion 6.

### Context

`admit_and_merge_own_commit` (`crates/scp-mls/src/group.rs`) merges the committer's own Commit before the committer publishes it, and `add_member`, `remove_member`, and `reset_member` call it. When two members commit at one epoch N, each member merges its own Commit, and each member's openmls then rejects the other member's Commit as `WrongEpoch`, so the group splits for good. `crates/scp-mls/src/encrypt.rs` documents that a Commit from a past epoch returns `DecryptionFailed`.

Nothing on main detects that split. A `ConsistencyCheckpoint` is an MLS application message (`09-security-model.md` §9.9.3), so it fails to decrypt across the split, and §9.9.4 never fires. Three sites would handle an honest fork as equivocation: spec 07 "Deduplication with replication", spec 07 "The members a Commit adds", and spec 23 §23.7 step 4, which also flags a relay in ADR-012 reliability scoring.

ADR-066 decision 5 had answered the race with "Epoch order decides conflicts": a Commit that loses the race for an epoch never merges, and its executor re-checks and resends it. That rule assumes that every member sees one Commit per epoch. No relay and no member can make that true without an ordering party that is online when a Commit is made, and on 2026-10-24 Alec ruled "We can’t rely on daily presence".

### Decision

On 2026-10-24 Alec asked "Why can't repairs be synchronized instead of overwritten?" and then chose option 2 ("2"). Under option 2, any member commits at any time with no quorum, no witness, no trusted party, no turn, and no pause. When two Commits exist for one epoch, every member keeps both branches' keys while it processes the fork, as draft-kohbrok-mls-dmls does, picks one branch by a fixed rule, and re-applies the losing branch's changes on top of the winning branch. A fixed merge function settles every true conflict between two changes, and the app tells the people involved which change lost and why. The repair removes and re-adds no device. The r6 plan carries forward the 2026-10-21 ruling that a re-joiner whose Commit loses "rebuilds its Commit against the new epoch and sends it again", with no pause and no turn.

The decisions below apply those rulings. The normative protocol is in `07-trust-validation-and-capabilities.md` §7.3.1.1 "Concurrent Commits and fork merge", which defines every term this record uses. Two review rounds on 2026-10-24 left twelve findings that the orchestrator settled, and each settlement is written into the mechanism it changes.

#### Terms

- **State S_x** is the MLS group state and the §7.3.1.1 governance state after the Commit that created epoch x. A Commit for epoch e is a child of S_e.
- **ids(S_e)** is the member identities of S_e in ascending UTF-8 byte order, and n_e = |ids(S_e)|.
- **rank(C)** of a child C of S_e by identity I is (pos(I) − e) mod n_e. An External Commit by a non-member has rank n_e.
- **cth(C)** is the `confirmed_transcript_hash` of the state C creates. H(C) is the SHA-256 of C's `MLSMessage` bytes.
- **Canonical child, canonical path, tip.** At a state with more than one valid child, the canonical child is the valid child with the least (rank, cth). The canonical path follows canonical children, and the tip is the last state on it.
- **Current.** A device is current at time t when it has held a live subscription to every reachable listed relay since some time a < t, and a fetch from each of those relays, started at or after a, completed before t. Connected time is the seconds during which a device is current.
- **Non-tip age** of S_x at device d is d's connected time since d first held a child of S_x.
- **Native execution** is the Commit that first executes a change. seen(x) is the set of change identities executed on x's native path before x, and x ∥ y holds when neither is in the other's `seen`.
- **Fork point F** is the leaf count that the canonical log and a losing branch L share; L's first leaf has `sequence` F. F is a log count in the epoch table. **e_F** is the last canonical epoch whose log count is F; for an F above every Commit's leaves, e_F is c, the parent epoch of the carrying Commit. A record carried by a child of S_c has depth c − e_F.
- **K(e)** = 2·n_e + 8 canonical Commits.

| Constant | Value | Role |
|---|---|---|
| `D_MAX` | 10 s | Delivery bound of assumption A1 |
| `FORK_RETAIN_SECS` (W) | 600 s of connected time | Non-tip deletion |
| `FORK_RETAIN_WALL_SECS` | 604,800 s (7 days) of local time | Non-tip deletion |
| `K(e)` | 2·n_e + 8 canonical Commits | Admission depth and import deadline |
| `MERGE_CARRY_ITEMS` | 8 (`00-open-questions.md` "Fork-merge carry cap", resolved 2026-10-24) | Pending items one Commit carries before its own action |

| Change | Change identity |
|---|---|
| Governance action or recording | `proposal_id` |
| Reset request | (X, `reset_counter`) |
| Token revocation | `token_cid` |
| Device Add | the `0xFF03` credential hash |
| Departure | the `DepartureRequest` hash |
| ff03 re-seat | `key_package_hash` |
| Update, checkpoint, fork record | none |

#### Mechanisms

1. **M1, retention.** A device keeps every parent state and its children. It deletes a non-tip state S_x at the earlier of two moments: S_x's non-tip age passes W, or 7 days of local time pass after the device first held a child of S_x. A retained state holds the punctured PPRF, the device's own tree private keys, the public tree and GroupContext, `sender_data_secret`, the unconsumed secret-tree nodes and the handshake ratchet tail, `membership_key` only where the context uses PublicMessage, every exporter-derived key ADR-066 reads at that epoch, decision 6's governance block key among them (each derived before `exporter_secret` is dropped), and the external HPKE private key. It holds none of `epoch_secret`, `init_secret`, the unpunctured PPRF seed, the resumption PSK, `exporter_secret`, `epoch_authenticator`, `external_secret`, `encryption_secret` once the secret tree is expanded, the application ratchets, or the parent's `confirmation_key` (a sibling's confirmation tag is checked under the child epoch's `confirmation_key`, and a late application message at the parent epoch falls under ADR-001's grace window). A device persists retained states in `BranchStore`, keyed by `state_id = SHA-256(group_id ‖ BE64 epoch ‖ cth)`, in the SQLCipher store with `PRAGMA secure_delete = ON`, and runs `PRAGMA wal_checkpoint(TRUNCATE)` after each deletion. A device also keeps, per epoch, a path index of H and cth of every valid child and H of every refused Commit for 7 days of local time, and the public leaves, proposal and vote records, and `MLSMessage` bytes of every non-canonical child until its branch settles or its fork point passes K(e_F) with no admitted record. Deletion is local and decides no verdict. A device offline for more than 7 days runs the `23-sync-and-offline-strategy.md` §23.5.1 reset on reconnect.
2. **M2, choice.** At each held state with more than one valid child, the canonical child is the valid child with the least (rank, cth). The choice reads only the children.
3. **M2r, rank rotation.** rank(C) rotates with the epoch, so each identity has rank 0 once in every n_e consecutive epochs while ids is unchanged.
4. **M3, obligations.** The pending set holds the changes a losing branch executed that canonical has neither executed, settled, nor placed in X; the unrecorded losing children; and the import leaves still needed. Every honest device follows five obligations:
   1. **Re-issue.** A change that a losing branch executed returns only as a re-application through an admitted record, and any member, its author included, may carry it. A change that no branch executed is re-issued natively with its original identity and records, after the spec 07 "Competing Commits" re-check and the "Conflicts" gate; an Add uses a fresh KeyPackage, and a change whose identity canonical already executed or settled is not re-issued. The author re-commits an Update from its canonical leaf. `AddMember` for X, a device Add for X, `RemoveMember` for X, and X's departure hold the conflict key `member:X`, which the state keeps after X leaves, so an Add of X loses to a Remove of X executed at or after the Add's `anchor_seq`, and a fresh re-invite anchored after the Remove still passes.
   2. **Carry.** Every honest Commit carries at most `MERGE_CARRY_ITEMS` (8) pending items that fit in the block body beside the member's own action, and then that action, so the action always fits. It carries them in this order: unrecorded records it holds, up to four; the oldest needed import leaves; re-applications whose evidence is complete. A carrier skips an item that is not admissible, whose evidence checks fail, or that does not fit beside the action, so no item blocks a carrier.
   3. **Record.** The author device of each losing child C' sends a record of C' in its next Commit, and sends a record-only Commit at once when it has nothing else to send. Every other holder carries the record under obligation 2 and sends no record-only Commit.
   4. **Send barrier (M11).** A holder of a pending restrictive-only change commits it before its next application message.
   5. **Causal order.** A re-application is not carried until every change in its `seen` that is in U has been executed or settled on canonical.

   SingleAdmin authority (spec 07 step 2) admits another member as committer of a re-application when the proposer's block proposal record verifies and the proposer held the capability at native execution. Another member may commit a recording as a re-application, and the receiver rejects it when canonical holds a recording by the same proposer, of the same kind, at an equal or later `anchor_seq` (`05-contexts.md` line on recordings, spec 07 step 1.3).
5. **M4, fresh tips and the rank-0 window.** A device publishes a child of S_t when S_t is its tip, it holds no child of S_t, and it is current. A device may also publish a child of a state S_t on its canonical path when its identity has rank 0 at S_t, it obtained S_t from the first copy of S_t's Commit it received, delivered by live push while it was current, it publishes within D_MAX of that moment, it holds no child of S_t by its own identity, and the Commit carries a pending item or rebuilds a Commit of its own that lost. A backlog or fetched state gets the fresh-tip rule only. A device sends at most one window Commit per pending item or rebuild, at the oldest eligible state. A device whose Commit loses rebuilds it at once on its new tip and sends the rebuild under whichever rule allows a send first; when neither rule allows one, it rebuilds on the next state it holds. The rebuild of a losing child that a relay stored is the child's record plus the obligation 1 re-application, and only a Commit no relay stored is re-issued natively.
6. **M5a, admission by depth.** A body item 5, `merge`, holds up to four fork records and one run of import leaves. A record is a MessagePack array of `fork_count` F, `end_count`, and `end_leaf_hash`. A receiver admits a record carried by a child of S_c when F ≥ 1 and canonical holds leaf F−1, F is a log count in the epoch table, c − e_F ≤ K(e_F), and `end_count` − F ≤ K(e_F) · `MERGE_CARRY_ITEMS`. Admission ignores who the recorder is. An exact repeat changes nothing. Records with one F and different ends are each admitted, their coverage is the union, and re-applications de-duplicate by change identity. A record deeper than K is rejected at every device.
7. **M5b, signed leaves.** A carrier supplies L's leaves in runs of whole leaves, with the `LeafNode` and `0xFF03` attestation of every leaf an L Commit added or replaced whose holder committed a later leaf on L, and the leaves of every nested source a `ConcurrentReapplied` leaf on L names. A receiver accepts a run when the first leaf has `sequence` F and a `prev_hash` equal to the hash of canonical leaf F−1 (from its log or an RFC 6962 inclusion proof against its committed root), each later `prev_hash` chains, and each leaf's signature verifies by spec 07 step 1.6 under the key the key ledger or a verified carried `LeafNode` gives for the leaf's `actor_did` at that point of L. The import completes when its last leaf has count `end_count` and hash `end_leaf_hash` and every nested source is present. For an L change y, the committers' own signatures over `prev_hash` fix seen(y).
8. **M5c, re-check in L's state.** The receiver builds the governance state at F by undoing, newest first, the journal entries after F with their `prior` values, then applies L's changes in L order. Before each re-applied change it runs spec 07 steps 1.3 to 1.5 and the "Conflicts" gate on that state, and verifies proposal and vote signatures under the key ledger or the carried `LeafNode`s. A change that fails is dropped with a `ConcurrentDrop` leaf, and the Commit is not rejected. The journal's `prior` covers every key steps 1.3 to 1.5 read: membership, the UCAN revocation set, and `member_since`. A leafless Commit changes no state the re-check or G reads, which is why e_F may pass over leafless Commits.
9. **M5d, deadline.** An admitted import expires when K(e_F) canonical Commits pass after its last progress, a carried leaf or a re-application. `end_count` sets neither the deadline nor the journal pin.
10. **M6, the merge function G.** G is unchanged from the r4 plan of 2026-10-24 and is specified in spec 07: the dropped set D (D-a author, D-b approver, D-c unordered conflict, D-d dependency), under which restrictive-only changes never fall in D; values V over the `seen` frontier; serial semantics as on main plus the `member:X` row; the classes, the orders, and the zero-holder rule; and the 47-row pair table that spec 25 carries as vectors. When one change identity executes natively on two branches, the execution on the branch whose child at the shared parent has the lower (rank, cth) holds, which at every device is the canonical path's execution; an import never re-executes an identity canonical executed, and a `ConcurrentDrop` leaf records the skip. The rule reads no byte a committer chooses.
11. **M8, tree reconciliation.** After each Commit the leaves match G's membership: the Commit carries a Remove proposal for every leaf whose identity or device G says is absent, or it is invalid. A member or device that G says is present but has no leaf is a pending joiner, which any member adds with a fresh KeyPackage from the joiner's buffer. The committer emits `WelcomeGenerated` after accept.
12. **M9, receipt and fetch.** After a device obtains any parent, it fetches every child of that parent from every listed relay, and it republishes its canonical child once per switch, a child it authored included. `23-sync-and-offline-strategy.md` §23.4.1 states receipt rules 1 to 4.
13. **M10, `DepartureRequest`.** A leaving member signs a `DepartureRequest` under its leaf `signature_key`, so that any member can re-execute a departure from a losing branch after the member has uninstalled.
14. **M11, send barrier.** Obligation 4 above.
15. **M12, PPRF puncture.** The child `init_secret` follows draft-kohbrok-mls-dmls-03 §4: `parent_init_secret = DeriveSecret(epoch_secret, "parent_init")`, `commit_confirmation = DeriveSecret(path_secret[n], "conf")`, and `init_secret_[n] = DeriveChildSecret(PPRF, "child_init", commit_confirmation, GroupContext_[n])`, over a tree of depth 8·Nh = 256 read MSB first, each node expanded by `ExpandWithLabel(node, "tree", "left" | "right", Nh)`. A device punctures each child as soon as it derives it. An External Commit's child stays derivable until its parent is deleted.
16. **M13, `merge_state_hash`.** A new `0xFF02` field commits the SHA-256 of the RFC 8785 form of the journal with the key ledger, the epoch table, the records, the imports with their received leaves and deadlines, and the pending joiners (`05-contexts.md` §5.13.3 rule 16), so a joiner checks the state it rebuilds. The hashed epoch table stops at the parent epoch of the Commit that carries the hash, because that Commit's own row holds its cth, which the Commit cannot commit. Each Commit therefore adds a row to the hashed table, so every Commit changes `merge_state_hash`, and the GroupContextExtensions proposal of a Commit with an empty block changes that one field (ADR-066 decision 32 amendment).
17. **M14, own Commit.** The committer builds on a scratch copy, persists the staged Commit encrypted in `BranchStore`, publishes to every listed relay, and merges it as a child of S_x when any listed relay accepts it or any fetch returns its bytes. After the merge it republishes with backoff to every listed relay that has neither accepted nor returned the Commit. It resends the unchanged bytes only while S_x is its tip and no all-relay fetch shows another child of S_x. When a fetch shows another child of S_x and no relay returned its bytes, it keeps the staged Commit as a candidate child and re-issues the candidate's changes at once on its new tip; the collision rule of G settles an identity that the candidate later executes too.
18. **M15, `ForkNotice`.** A signed plaintext relay blob tells members on the other side of a refusal or a split, and starts one fetch. A notice never changes state, never counts as fork evidence, and never picks a reset target. `09-security-model.md` §9.5.2 and §9.9.3 give its preimage, drop rules, and effects.
19. **M16, exact-position fork evidence.** A device d excuses a log disagreement at position s only when d confirms that the other log's leaf F−1 equals its own, and s equals a fork point F that d authenticated itself: (i) d processed two valid children of one parent with log count F that append different leaves at F and whose MLS sender leaf indices differ, or (ii) d truncated its log at F on a switch. A member-signed leaf at F that d did not process only starts a fetch. An excused disagreement raises no alert, sends no `EquivocationAlert`, applies no `equivocation_policy`, and flags no relay. The excuse lapses, and the disagreement gets the full response it gets on main, when an all-relay fetch completes without giving d (i) or (ii), or when d deletes S_e. Every disagreement at another position gets the full response. Six entry points apply the predicate: spec 07 "Deduplication with replication" and "The members a Commit adds", spec 23 §23.7 steps 3 and 4, and spec 09 §9.9.3 and §9.9.4.

#### Retention of governance state, joiners, and the event log

- **Journal and epoch table.** An epoch row holds the epoch, its log count, the committer identity, n_e, and cth. A journal entry holds `id`, `pos`, `class`, `writes`, `prior` (each written key's previous value), `reads`, `author`, `cap_used`, `cap_source`, `approvers`, `requirement`, `takes`, `deps`, `values`, and the key-ledger fields. Both keep every epoch e ≥ min{e′ : tip − e′ ≤ K(e′)}, plus every entry after the F of an admitted import that has neither completed nor expired. Retention is a function of canonical state, so every device evicts the same entries.
- **Joiners.** A re-applied Add uses a fresh KeyPackage from the joiner's buffer, and the committer emits `WelcomeGenerated` after accept. A joiner that holds two groups for one context reads each group's epoch table at the first epoch after the shared log prefix and keeps the group whose child there has the lower (rank, cth). A group whose journal shows the joiner's Add as a re-application, with an import equal to the other group's log after the prefix, wins. While neither rule decides, the joiner sends on neither group's governance.
- **Event log.** The canonical log is the leaves of the canonical path in order: only one Commit per epoch is on the canonical path, and its committer assigns the sequence numbers of its leaves. A re-application takes new sequence numbers and begins with a `ConcurrentReapplied` leaf, and `ConcurrentDrop` leaves record what fell in D or failed the re-check. On a switch, a device adopts the retained governance state, truncates its log at F and writes a truncation record (M16 evidence (ii)), and keeps the truncated leaves as `BranchLeaf` records it serves to other devices.

#### Necessity of each mechanism

A mechanism stays only when removing it breaks honest convergence, a ruling, forward secrecy, determinism, or an item of the plan's contract. Each smallest case is a context of 2 to 7 members with 1 to 3 devices each.

| # | Mechanism | Smallest case | Without it | With it |
|---|---|---|---|---|
| M1 | Keep every parent and its children; delete at the earlier of W connected and 7 days local | 2×1: Alice and Bob both commit at epoch 5 | A permanent `WrongEpoch` split; without the 7-day limit, a stolen offline device keeps keys for as long as it stays offline | Both devices process both children, and retained keys die within 7 days |
| M2 | Choice by least (rank, cth) | Same case | No agreement on the tree | One function of the child set |
| M2r | Rank rotation by epoch | 2×1: Alice's automation commits every 20 s | Bob loses every race to Alice, whose identity sorts lower | Bob has rank 0 once in every n_e epochs |
| M3 | Re-application obligations | 3×1: Bob's `ChangeRole` loses, and Bob goes offline | The change stays lost | The next honest Commit carries it |
| M4 | Fresh-tip rule and rank-0 window | 2×1: Bob reconnects 60 s after C_E while Alice's automation chains Commits | An honest late sibling; without the window, Bob starves, which the 2026-10-21 re-joiner ruling forbids | Every honest Commit is fresh by Lemma 2, and Bob wins at his rank-0 epoch with no wait |
| M5a | Fork record admitted by depth ≤ K(e_F) | 3×1: H releases a branch after 200 canonical Commits | A week of Alice's acts is voided | The record fails at every device |
| M5b | Leaves verified under their committers' signatures, with carried `LeafNode`s | 3×1: Bob, added on P, removes Dave on P; Carol removes Alice on L | A carrier re-chains leaves, and Bob's Remove does not verify in world L | F and `seen` come from signed `prev_hash` chains, and Bob's leaf verifies in both worlds |
| M5c | Re-check of each re-applied change in L's state | 3×1: member M, without `member:remove`, records a fabricated Remove(Alice) | M gets a right it never held | The change fails steps 1.3 to 1.5 and is dropped |
| M6 | Merge function G | 3×1: mutual removal | The branch decides who stays | Both Removes hold |
| M8 | Tree reconciliation with fresh KeyPackages | 3×1: Bob adds Dan on L | Dan is lost, or a KeyPackage is reused | Dan is added from his buffer |
| M9 | Fetch every child of an obtained parent; republish, the author included | 2×2: a relay serves C' to one device only | Two devices of one person diverge | Both hold C' within 2D |
| M10 | `DepartureRequest` | Carol leaves on L and uninstalls | Her Remove cannot be re-applied | Any member re-executes her record |
| M11 | Send barrier | Bob removes Eve on L | Eve reads canonical messages | Bob commits first |
| M12 | PPRF puncture | A device is compromised after C | Consumed keys re-derive | Only unseen siblings stay derivable |
| M13 | `merge_state_hash` | A joiner during a fork | A false journal | The joiner checks the hash |
| M14 | Merge on accept or on own bytes returned; republish to every relay that lacks the Commit; keep the staged Commit as a candidate | 2×1: relay R stores Bob's C_b, and the acknowledgement is lost | Bob wipes C_b and splits silently | Bob counts R's copy as an accept |
| M15 | `ForkNotice` | 3×1: Alice deleted S_e, and Carol holds it | Divergence nobody sees | Both sides show `GroupSplit` |
| M16 | Exact-position fork evidence at every equivocation and relay-flag entry point | 2×1: an honest fork | `suspend_write` or an ADR-012 flag hits an honest party | No response for the authenticated divergence at F, and the full response for every other divergence |

#### X and Theorem S

A change from a losing branch is in X when no record covering its leaves is admitted while its depth is at most K(e_F), or when every admitted import that covers it has expired. Both conditions read canonical bytes only. The signed `ConcurrentReapplied` leaves on L fix nested sources, so no carrier decides a nested expiry.

**Theorem S.** Let P and L be the change sets two branches executed after F. When the pending set is empty, the governance state on either canonical choice is G((P ∪ L) \ X). Under Lemma 4's premises, X = ∅.

*Proof.* (1) Each Commit sets the state to G of its executed set, with U = P ∪ L in both worlds. (2) seen(x) is fixed at native execution, the committers' signed `prev_hash` chain carries it, and a re-application adds no edge. (3) ∥, the journal facts, D, and V are therefore equal in both worlds, and the re-check in L's state reads only the journal and L's signed records, which are equal in both worlds. (4) When one change identity executes natively on two branches, the collision rule keeps the execution on the branch whose child at the shared parent has the lower (rank, cth), a fact equal in both worlds. (5) Bob's leaf verifies in world L under the carried `LeafNode` of his Add, and restrictive-only changes never fall in D, so Bob's Remove(Dave) holds in both worlds. (6) Obligation 5 keeps every executed set causally closed, and the skip rule of obligation 2 keeps every carrier unblocked, so the repair terminates. (7) Nested forks give x ∥ y without an `origin` field. A history with no fork gives D = ∅ and equals main, except for the `member:X` row.

#### Convergence

**Assumptions.** A1: bytes an honest device publishes reach every connected honest device within D ≤ D_MAX, through at least one listed relay that also returns stored bytes on fetch. A2: honest devices follow this record.

**Lemma 2 (honest freshness).** Every honest Commit at S_t reaches every connected honest device while that device's non-tip age of S_t is at most D_MAX + 2D ≤ 30 s < W. Let p_first be the publish time of the first child of S_t.
- *Fresh-tip case.* The author, current at publish time c, held no child published before c − D, so p_first ≥ c − D. The Commit arrives everywhere by c + D, so the age is at most 2D.
- *Rank-0-window case.* The author obtained S_t at time f from the first copy of S_t's Commit, delivered by live push while it was current. By A1 that copy arrived within D of the publish time of S_t's Commit, which precedes p_first, so no child of S_t was published before f − D, and p_first ≥ f − D. The author publishes at c ≤ f + D_MAX, and the Commit arrives by c + D. The age is at most f + D_MAX + D − (f − D) = D_MAX + 2D. A backlog or fetched state never opens the window.

Offline devices do not age, and deletion requires an age above W.

**Lemma 4 (record latency).** Assume A1 and A2, that ids is unchanged over e + 1 to e + 2·n_e, and that the author device a of a losing child C' of S_e stays connected for 2D after it publishes C' at p'. Then a record of C' lands at depth at most 2·n_e < K(e_F).
1. Every current device that holds S_e and builds a Commit after p' + D holds C' (A1) and carries its record (obligation 2).
2. a holds the winning child C by p_C + D, so from S_{e+1} onward a knows that C' lost.
3. Rank rotation gives a's identity rank 0 at one epoch t in every n_e consecutive epochs. At t, a publishes a record Commit under the fresh-tip rule or the rank-0 window. That Commit wins at every device, because rank 0 is below every other identity's rank and Lemma 2 delivers it while every device holds S_t.
4. After p' + D every honest Commit carries the record. Before p' + D, another device of a's identity can win on cth without the record, and that failure is R10.
5. The record therefore lands within 2·n_e epochs of e + 1. The commit rate never enters, and depth from e_F ≥ e is no larger. The +8 in K is margin that the proof does not use.

Every honest canonical Commit after the record carries at least one needed leaf or re-application (obligation 2), and an import expires only after K(e_F) canonical Commits without progress. An import therefore expires only when at least K canonical Commits come from members that do not carry: hostile members (R3) or devices that do not hold C' (R10).

**Theorem C.** Under A1 and A2, once honest members stop creating changes, every honest device reaches one canonical path whose state is G(P ∪ L). Connected devices hold equal child sets (Lemma 2) and choose equally (Lemma 1: the choice is a function of the child set). Returning holders fetch every child. Devices that return to an older state fetch ancestors and switch. Concurrent carriers de-duplicate by change identity. Lemma 3: let Φ be the pending changes plus the needed import leaves plus the unrecorded children; every canonical carrier lowers Φ.

| Event | Bound |
|---|---|
| Every connected device holds every child and has one tip | p_first + D_MAX + 2D |
| Record on canonical | Depth at most 2·n_e (Lemma 4) |
| Each item carried | The next honest Commit after the item becomes carryable |
| Keys deleted | W connected or 7 days local |

Forks happen at about n(n−1)·D/86,400 per day with daily Updates: 4.6 × 10⁻⁵ at n = 2 and D = 2 s, 9.7 × 10⁻³ at n = 21 and D = 2 s, and 0.049 at n = 21 and D = 10 s.

#### Late siblings and split recovery

A valid child C' of S_e that reaches an honest device after another honest device deleted S_e has, by Lemma 2, an author that is not honest under A1: a hostile member, a relay that withheld the bytes, or an author whose only accepting relay failed before the author went offline. When C' loses at every holder at depth at most K, any holder records it, and it executes as concurrent (R2, R4). When C' loses at depth above K, no device admits a record, and C' has no effect. When C' wins at a holder, the holder switches, the deleters refuse its Commits, and both sides detect the split through `ForkNotice` rule (b). The person on one side recovers by sending a `ResetRequest` with reason `CatchUpFailed`, which a member on the other side holding `MemberRemove` and `MemberInvite` executes. The device accepts the Welcome only when the joined group's epoch table shows, at e + 1, a child that beats its own canonical child on (rank, cth).

A re-join by `ResetRequest` executes at the next Commit of any honest holder of both capabilities. A device's own Commit wins at the first epoch where its identity has rank 0, which is within n_t canonical epochs while ids is unchanged, and at once in a quiet group. No device waits.

#### Residuals (accepted)

| # | Residual | Condition | Effect |
|---|---|---|---|
| R1 | Late split | A hostile release, a withholding relay, a partition beyond retention, or an author whose only accepting relay failed before the author went offline | A split that both sides detect; a deleter that was offline detects it on return |
| R2 | Removed member's window | A member A, removed at or after e, releases a sibling of S_e carrying restrictive-only changes; it reaches a holder within the holder's retention, a holder records it, and the record lands at depth at most K(e_F) | A's restrictive-only change takes effect, within A's rights at S_e |
| R3 | Hostile delay | Nonstop commits, bursts, rank steering by invites, or hostile Commits that carry no pending items | Re-joins, repairs, and import deadlines are delayed; an expired import places its changes in X |
| R4 | Fabrication within K | One member records signed leaves forking at any F with depth at most K(e_F), alone or through a second identity it added while it held `member:invite`; the fabricated branch can also execute another member's passed proposal, because spec 07 lets any executor execute it | The fabricated changes execute as concurrent with at most K(e_F) canonical Commits, limited to the rights the authors held at F (M5c); the collision rule keeps canonical's execution of an identity canonical executed |
| R5 | Attestation key disagreement | Members resolve different keys for one attestation (SCP-315, the attestation key-binding story) | Different valid-child sets, as for every Commit on main |
| R6 | Non-member External Commit | It has rank n_e | A nonstop committer delays an outsider's External Commit join |
| R7 | Zero holders | Mutual removal leaves no holder of a capability | The same state a serial history reaches |
| R8 | Recovery without capability | A split side with no holder of both capabilities | That side cannot execute a reset |
| R9 | Reset into a hostile side | A hostile member released a winning late sibling and holds both capabilities | It can execute a requested reset, and `GroupSplit` lists that side's members |
| R10 | Record outruns Lemma 4 | Lemma 4's premises fail and at least K canonical Commits come from devices that do not hold C': an honest loser disconnects within D after publishing while another device chains K Commits before it holds C', identity churn keeps every Lc identity off rank 0, or post-fork joiners commit K times before any holder does | Those changes go to X, and `ConcurrentChangeExpired` tells the author to propose again |

R10 is accepted. No K counted in Commits covers the commit rate times D, and a time-based K is impossible because the protocol has no convergent clock (`09-security-model.md` §9.14, spec 07 "Receiver processing"). R10 is detected absence: the author learns of it, so the loss is never silent. An earlier draft's residual for an excuse resting on a member-signed leaf is gone, because such a leaf now only starts a fetch (M16).

#### Security across a fork

A compromised device exposes only retained non-tip material, for at most W of connected time and at most 7 days of local time. No consumed key is recoverable, except an External Commit's child until its parent is deleted, and no retained state holds a secret from the excluded list of M1. Post-compromise security is as on main once the repair's Commits carry UpdatePaths. An import is fixed by its committers' signatures, checked against the rights at F, and admitted only within K.

#### What people see

| Person | Event and text |
|---|---|
| Author or subject of a dropped change | `ConcurrentChangeDropped`: "Your change to [X] didn't take effect. At the same time [Y] [did Z], and [rule]." |
| Author of a change in X | `ConcurrentChangeExpired`: "Your change to [X] couldn't be re-applied. Propose it again." |
| Author of a change being re-applied | `ConcurrentChangePending`: "Your change to [X] is being re-applied after a simultaneous change." |
| Admins, after reconciliation | `ConcurrentAdminActionUndone`: "[A] was removed at the same time as [A] added [X], so [X] was removed." |
| Mutual removal | `ConcurrentRemovalStands`: "[A] removed you at the same time you removed [A]. Both removals stand." |
| No holder of a capability | `GovernanceUnavailable`: "No one in this group can [action] anymore." |
| Joiner | Gap marker: "Messages sent before you were added aren't available." |
| Joiner whose Add was dropped | `JoinCancelled`: "[A] removed you from [context] at the same time you were added." |
| Member with a verified `GroupSplit` list | `GroupSplit { members, can_rejoin }`: "[Members] are on a different branch of this group that your device can no longer read. You can ask to rejoin their branch. Your device then resets." When `can_rejoin` is false, the second sentence is "No one on their branch can re-add you." |

### Rejected Alternatives

- **A commit-ordering quorum or witnesses.** A quorum of members or of witness relays and nodes would sign which Commit comes first, so one Commit per epoch would merge. Alec ruled on 2026-10-24 "We can’t rely on daily presence", and a quorum needs members or witnesses online for a Commit to take effect.
- **ADR-051 causal-DAG ordering.** Commits would join the causal DAG that orders application events. The DAG orders events within one key schedule, but two Commits at one epoch create two key schedules, so the DAG gives no tree both branches share.
- **Seals, representatives, and builders.** A member would seal a branch, or a representative or builder chosen per epoch would build every Commit. Each makes one member's presence a condition for a Commit to take effect, which the 2026-10-24 ruling on daily presence excludes.
- **A depth cap on the fork tree, anchor-window bridges, and per-receiver records.** Each made a verdict depend on what one receiver held, so two honest receivers could reach different verdicts on one Commit, which ADR-066 decision 10 forbids.
- **A `dmls_epoch` header.** Each Commit would name its DMLS epoch in its header. RFC 9420 already binds the epoch in the GroupContext, and a second epoch field gives a receiver nothing to check that cth does not.
- **Device or builder weight in the choice.** A child would win by the number of devices or by builder rank. A member who adds devices or builders then wins every race, so the choice would reward the person who controls the most leaves.
- **KeyPackage reuse in a re-applied Add.** The re-applier would reuse the KeyPackage of the native Add. A KeyPackage is single-use (`ADR-049-actor-per-context.md` "Two-anchor single-use model", and `KeyPackageReplay` in `crates/scp-runtime/src/crypto/mls/production_backend.rs`), so reuse breaks the init-key secrecy every joiner relies on.
- **Re-adding a member after a dropped Remove, and a last-admin guard.** The repair would re-add a member a concurrent Remove took out, or refuse a Remove that leaves no admin. Both contradict Alec's ruling that the repair removes and re-adds no device, and a serial history already reaches the zero-holder state (R7).
- **`HeadAttestation` and r4 placement.** A member would attest the head it holds, and a Commit would be placed by that attestation. The attestation reads what a device holds now, not what was published when, so a returning holder admitted a week-old branch.
- **The foreign-recorder rule.** Only a member that committed on neither branch could record a fork. When every identity committed on L, no honest recorder existed, and one L member could void an import through the de-duplication slot.
- **Rank-gated pacing and the governance wait.** A member would wait for its rank turn before committing, and a governance change would wait for the members of L. Both are a turn and a pause, which the 2026-10-21 re-joiner ruling forbids.
- **Time-based lateness.** A record would be admitted for a period of local time after its fork. The protocol has no convergent clock (`09-security-model.md` §9.14), so two members would admit or reject one record by different clocks.

### Consequences

- Two members that commit at one epoch no longer split the group: every member processes both children, every member chooses the same canonical child, and the losing child's changes return as re-applications.
- Every device keeps each parent state for up to W of connected time or 7 days of local time, about 10 KB each, persisted encrypted with `secure_delete`. ADR-001's 30-second grace window still governs in-branch late messages.
- The journal and epoch table keep every epoch from the oldest still-admissible one, plus the pins of open imports, at most 2·n + 9 entries plus pins, about 15 KB at n = 21.
- A fork record costs 45 bytes in body item 5, and each losing child costs one record-only Commit from its author device.
- An honest fork raises no equivocation alert and flags no relay. A relay that partitions members with real Commits still meets the full §9.9.3 response once an all-relay fetch completes without fork evidence.
- Verdicts read no clock: SCP-357's openmls patch threads `LeafNodeLifetimePolicy::Skip` through `[patch.crates-io]`, because openmls reads `SystemTime::now()` through `Lifetime::validate()`.
- Withdrawal and re-signing by key rotation (`05-contexts.md` §5.9.1, ADR-066 decision 10) rest on an Update that rotates `signature_key`, and no Update does: `propose_update` (`crates/scp-mls/src/ratchet.rs`) passes `LeafNodeParameters::default()`. This record builds nothing on rotation.

### Acceptance Criteria

The stories that implement this record list their criteria in `.docs/prds/main.json` under the gate `gate-fork-merge`, whose stories build on `gate-gov-commit`: SCP-357 (the openmls patch), SCP-350 (`BranchStore` and two-clock deletion), SCP-351 (choice, the fresh-tip rule, and the rank-0 window), SCP-352 (the obligations), SCP-353 (receipt, republish, `ForkNotice`, and M16), SCP-354 (tree reconciliation), SCP-355 (`DepartureRequest`), SCP-356 (the notices), SCP-358 (the simulation), SCP-359 (log truncation and `BranchLeaf`), SCP-360 (the journal, key ledger, epoch table, records, imports, deadlines, and `merge_state_hash`), and SCP-361 (the `member:X` row). Under `gate-gov-commit`, SCP-328, SCP-329, SCP-330, SCP-334, SCP-335, and SCP-337 carry this record's amendments to their criteria.
