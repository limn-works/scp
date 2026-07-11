# Phase 6 Architecture Decision Records — Android, Kotlin, Scale Hardening, Advanced Governance

**Date:** February 23, 2026
**Phase goal:** Android platform, Kotlin SDK, scale hardening, security audit, advanced governance, offline strategy.
**Timeline:** Weeks 21+

**Note:** Phase 6 follows Phases 1-5 implementation. All ADRs in this phase — ADR-027 (Android), ADR-028 (Kotlin), ADR-029 (Offline/Sync), ADR-030 (Event Log Pruning), ADR-031 (Multi-Admin Governance), ADR-038 (Content Access Key Layer), ADR-043 (Protocol Constants), ADR-044 (Attestation Two-Class Model), and ADR-045 (Fuzzing Infrastructure) — are Decided.

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

**Status:** Decided

### Context

SCP's platform adapter layer (ADR-006) abstracts device-specific capabilities behind four traits: `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage`. These traits are exposed as UniFFI callback interfaces (ADR-021), allowing Kotlin implementations to be injected into the Rust engine. The Android adapter implements all four traits using Android's native platform security stack.

Android and Apple differ fundamentally in key custody capability. Apple's Secure Enclave supports only P-256; SCP identity keys (Ed25519) must be software-backed in Keychain on Apple. Android Keystore at API 33+ (Android 13+) natively supports Ed25519 via the EdDSA algorithm. This means SCP identity keys on Android 13+ are TEE-backed in hardware — a stronger security posture than the Apple adapter. This is the defining architectural difference between the two platform adapters.

Android's hardware security landscape has two tiers: TEE (Trusted Execution Environment), present on virtually all modern Android devices, and StrongBox, an isolated secure element chip present on a subset of flagship devices. StrongBox operations are dramatically slower (10-100x) than TEE operations. For SCP's frequent signing operations during protocol participation, StrongBox latency is prohibitive. TEE-backed Keystore is the correct default.

### Decision

Implement the Android platform adapter in Kotlin at `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/`. Five files implement the four platform traits plus a factory:

- **`AndroidKeyCustody.kt`** — `KeyCustodyProvider` implementation using Android Keystore. Ed25519 (`EdDSA`) at API 33+; software Ed25519 fallback (Bouncy Castle) for API 26-32. X25519 wrapping keys always software-managed. TEE-backed by default; StrongBox explicitly opt-out.
- **`AndroidDeviceAttestation.kt`** — `DeviceAttestationProvider` implementation using Play Integrity Standard API. Standard (server-side, low-latency) preferred over Classic (offline, high-cost) attestation.
- **`AndroidPushProvider.kt`** — `PushProvider` implementation using Firebase Cloud Messaging. Opaque data-only payload: `{"data": {"scp": "1"}}`. No context ID, sender DID, or message content in any notification payload.
- **`AndroidStorage.kt`** — `StorageProvider` implementation using SQLCipher. Database encryption key derived from a 32-byte symmetric key stored in Android Keystore (TEE-backed AES-256). Key ID: `scp.storage.key`.
- **`PlatformAdapter.kt`** — `AndroidPlatformAdapter` factory. `AndroidPlatformAdapter.make()` constructs and injects all four providers. Called by the Kotlin SDK's `SCP.create()` when `custody = "platform"`.

**Minimum API level:** API 26 (Android 8.0) for the SDK. API 33 (Android 13) required for hardware-backed Ed25519. Devices on API 26-32 use a software Bouncy Castle Ed25519 key with `CustodyType.Software`.

**TEE vs StrongBox policy:** TEE is the default and only option. StrongBox is not used. StrongBox operations are dramatically slower — 10-100x latency increase over TEE for signing — which would make SCP protocol participation visibly laggy. There is no user-visible opt-in to StrongBox.

**Play Integrity:** Standard integrity requests (server-side verification via the Play Integrity API). Classic attestation (which generates a signed APK certificate chain verifiable offline) is not used — it requires a server round-trip to Google's servers for each attestation and has stricter quotas. Standard provides fresh device verdicts sufficient for SCP's attestation requirements.

**FCM payload:** Data-only message with no notification fields. Payload: `{"data": {"scp": "1"}}`. The `scp` field value `"1"` is the wake signal. The app wakes, connects to the SCP relay, and pulls envelopes. No context ID, sender DID, message preview, or any SCP-specific content appears in the FCM payload (§10.7 opacity requirement).

### Rationale

- **Ed25519 hardware-backed at API 33+:** Android Keystore at API 33+ natively supports the `EdDSA` algorithm with `Ed25519` parameter spec. This is a direct win over Apple, where Secure Enclave's P-256 limitation forces software key storage. Hardware-backed Ed25519 means the private key bytes never leave the TEE — signing operations happen inside the secure enclave. This is the strongest possible custody for SCP identity keys.
- **Software fallback for API 26-32:** API 26 is the SDK minimum (matches JVM 11+ target and Android 8.0, sufficient market coverage). On API 26-32, EdDSA is not available in AndroidKeyStore. Bouncy Castle provides software Ed25519. Keys are stored encrypted in EncryptedSharedPreferences (Jetpack Security) as the next-best alternative to hardware backing. `CustodyType.Software` is reported accurately.
- **TEE over StrongBox:** StrongBox is present on a fraction of devices and operates orders of magnitude slower than TEE. SCP signs messages during every send operation and during key agreement. StrongBox latency would accumulate visibly in normal usage. The TEE provides hardware isolation with acceptable latency. StrongBox is not offered as an option — "opt-in slowness" is a footgun.
- **Play Integrity Standard over Classic:** Standard integrity requests return a verdict signed by Google's servers, sufficient for SCP's attestation purpose. Classic attestation (APK certificate chain) requires a dedicated Google Play Developer API call per attestation with stricter rate limits and is designed for offline scenarios SCP does not have. Standard is lower-cost, lower-latency, and simpler.
- **FCM data-only payload for opacity:** FCM notification payloads visible to the device OS (notification fields) must contain no SCP-meaningful content. A data-only message with `{"scp": "1"}` carries no information except "wake up and pull" — satisfying §10.7. The FCM data payload is not displayed to the user, not logged by the OS notification system, and carries no identifying information.
- **SQLCipher with TEE-derived key:** SQLCipher provides transparent full-database encryption. The encryption key is a 32-byte AES-256 key generated by Android Keystore (TEE-backed). The Keystore key never leaves the TEE; it encrypts/decrypts the SQLCipher key material via a Keystore-wrapped AES-GCM operation. This gives the database a hardware-rooted chain of trust without requiring SQLCipher itself to understand Android Keystore.
- **Private keys never cross the FFI boundary:** All Ed25519 signing and X25519 DH operations happen inside `AndroidKeyCustody.kt`. The Rust engine calls the UniFFI callback interface methods with data to sign and receives signatures back. Raw private key bytes stay inside the Kotlin adapter, inside the Android Keystore TEE.
- **Kotlin over Rust for Android platform code:** Android Keystore, Play Integrity, and FCM are Java/Kotlin APIs with no Rust bindings. Writing thin Kotlin adapters that call these APIs and satisfy the UniFFI callback interfaces is the correct approach — it uses the idiomatic Android API surface without maintaining a JNI bridge to Rust Android Keystore bindings.

### Implementation

**File layout:**

```
bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/
  AndroidKeyCustody.kt        — KeyCustodyProvider: Android Keystore Ed25519, software fallback
  AndroidDeviceAttestation.kt — DeviceAttestationProvider: Play Integrity Standard API
  AndroidPushProvider.kt      — PushProvider: FCM registration, opaque data payload
  AndroidStorage.kt           — StorageProvider: SQLCipher + TEE-derived AES-256 key
  PlatformAdapter.kt          — AndroidPlatformAdapter.make() factory, injects all four
```

**`AndroidKeyCustody.kt` — Ed25519 key generation via Android Keystore (API 33+):**

```kotlin
class AndroidKeyCustody : KeyCustodyProvider {

    override fun generateKeypair(keyType: KeyType): KeyHandle {
        val keyId = UUID.randomUUID().toString()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && keyType == KeyType.ED25519) {
            generateKeystoreEd25519(keyId)
        } else if (keyType == KeyType.ED25519) {
            generateSoftwareEd25519(keyId)
        } else {
            // X25519 wrapping keys are always software-managed
            generateSoftwareX25519(keyId)
        }
    }

    private fun generateKeystoreEd25519(keyId: String): KeyHandle {
        val spec = KeyGenParameterSpec.Builder(
            "scp.key.$keyId",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(EdDSAParameterSpec(EdDSAParameterSpec.Ed25519))
            .setDigests()  // EdDSA does not require explicit digest
            .setUserAuthenticationRequired(false)  // SCP requires background processing
            .build()
        val keyPairGenerator = KeyPairGenerator.getInstance("EdDSA", "AndroidKeyStore")
        keyPairGenerator.initialize(spec)
        keyPairGenerator.generateKeyPair()
        return KeyHandle(id = keyId, custodyType = CustodyType.HARDWARE)
    }

    private fun generateSoftwareEd25519(keyId: String): KeyHandle {
        // Bouncy Castle Ed25519 for API 26-32; key stored in EncryptedSharedPreferences
        val keyPair = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        softwareKeys[keyId] = keyPair
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            val entry = KeyStore.getInstance("AndroidKeyStore")
                .apply { load(null) }
                .getEntry("scp.key.${keyHandle.id}", null) as KeyStore.PrivateKeyEntry
            Signature.getInstance("EdDSA").apply {
                initSign(entry.privateKey)
                update(data)
            }.sign()
        } else {
            val keyPair = softwareKeys[keyHandle.id]
                ?: throw ScpException("Key not found: ${keyHandle.id}", "SCP-CRYPTO-4001")
            Ed25519Signer().apply {
                init(true, keyPair.private)
                update(data, 0, data.size)
            }.generateSignature()
        }
    }

    override fun publicKey(keyHandle: KeyHandle): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            val entry = KeyStore.getInstance("AndroidKeyStore")
                .apply { load(null) }
                .getEntry("scp.key.${keyHandle.id}", null) as KeyStore.PrivateKeyEntry
            val encoded = entry.certificate.publicKey.encoded
            check(encoded.size == 44) { "Expected 44-byte X.509 Ed25519 SPKI, got ${encoded.size}" }
            encoded.takeLast(32).toByteArray()  // raw 32-byte Ed25519 pubkey
        } else {
            val keyPair = softwareKeys[keyHandle.id]
                ?: throw ScpException("Key not found: ${keyHandle.id}", "SCP-CRYPTO-4001")
            (keyPair.public as Ed25519PublicKeyParameters).encoded
        }
    }

    override fun destroyKey(keyHandle: KeyHandle) {
        if (keyHandle.custodyType == CustodyType.HARDWARE) {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("scp.key.${keyHandle.id}")
        } else {
            softwareKeys.remove(keyHandle.id)
        }
    }

    override fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray {
        // X25519 wrapping keys are always software-managed
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException("X25519 key not found: ${keyHandle.id}", "SCP-CRYPTO-4002")
        return X25519Agreement().apply {
            init(keyPair.private)
        }.let {
            val agreement = ByteArray(it.agreementSize)
            it.calculateAgreement(X25519PublicKeyParameters(peerPublic), agreement, 0)
            agreement
        }
    }

    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle {
        // Algorithm: seed = HMAC-SHA256(pseudonymSecret, contextId || "scp-pseudonym")
        // pseudonym_keypair = Ed25519_keygen(seed[0..32])   // seed is an RFC-8032 Ed25519 seed
        //
        // The HMAC key is the 32-byte pseudonymSecret, NEVER the public key — public key
        // bytes would be a membership-enumeration oracle (§9.10.4.A).
        //
        // SOFTWARE keys (Bouncy Castle, API 26-32): pseudonymSecret = HKDF-SHA256(
        //   ikm = ed25519_private_seed, salt = "scp-pseudonym-secret-v1", info = "", len = 32).
        //   This matches Rust `derive_pseudonym_secret()` exactly, so software pseudonyms are
        //   cross-platform deterministic (pinned by §25.19 vectors).
        //
        // HARDWARE keys (Keystore TEE, API 33+): private bytes are non-exportable, so
        //   pseudonymSecret = SHA-256(TEE_sign("scp-pseudonym-secret-v1")) — a device-local
        //   secret computed inside the TEE. Hardware pseudonyms are device-local BY DESIGN
        //   and are NOT expected to match other devices or the software vectors.
        val pseudonymSecret = derivePseudonymSecret(keyHandle)  // HKDF (software) or TEE-sign (hardware)
        val mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(pseudonymSecret, "HmacSHA256"))
            update(contextId)
            update("scp-pseudonym".toByteArray())
        }
        val seed = mac.doFinal()
        pseudonymSecret.fill(0)  // zeroize secret after use
        val pseudonymKeypair = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(FixedSecureRandom(seed)))
        }.generateKeyPair()
        val pseudonymId = UUID.randomUUID().toString()
        softwareKeys[pseudonymId] = pseudonymKeypair
        return PseudonymKeyHandle(id = pseudonymId, custodyType = CustodyType.SOFTWARE)
    }

    private val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()
}
```

**`AndroidDeviceAttestation.kt` — Play Integrity Standard API:**

```kotlin
class AndroidDeviceAttestation(private val context: Context) : DeviceAttestationProvider {

    override suspend fun attest(challenge: ByteArray, deviceId: ByteArray): ByteArray {
        val clientDataJSON = "{\"challenge\":\"${Base64.encodeToString(challenge, Base64.NO_WRAP)}\",\"deviceId\":\"${Base64.encodeToString(deviceId, Base64.NO_WRAP)}\",\"type\":\"scp-device-attestation-v1\"}"
        val nonce = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(clientDataJSON.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP
        )
        val integrityTokenResponse = withContext(Dispatchers.IO) {
            IntegrityManagerFactory.create(context)
                .requestIntegrityToken(
                    IntegrityTokenRequest.builder()
                        .setNonce(nonce)
                        .build()
                )
                .await()
        }
        // Return the integrity token (JWT) for server-side verification
        return integrityTokenResponse.token().toByteArray(Charsets.UTF_8)
    }

    override suspend fun assert(requestHash: ByteArray): ByteArray {
        // Play Integrity does not have a per-request assertion flow equivalent to App Attest assertions.
        // For assertion-equivalent use cases, a fresh Standard integrity token is requested.
        return attest(challenge = requestHash, deviceId = ByteArray(0))
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

// Relay sends this FCM message structure — opaque, data-only:
// {
//   "to": "<fcm_token>",
//   "data": {
//     "scp": "1"
//   }
// }
// No "notification" key. No content visible to Android notification shade.
```

**`AndroidStorage.kt` — SQLCipher with TEE-derived key:**

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
            val keySpec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)  // background access required
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(keySpec) }
                .generateKey()
        }

        // Derive a 32-byte SQLCipher passphrase by encrypting a fixed label with the Keystore key.
        // The actual key bytes never leave the TEE — this pattern uses AES-GCM with a deterministic
        // IV to produce a stable 32-byte value for the SQLCipher passphrase.
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, ByteArray(12)))  // fixed IV for determinism
        }
        return cipher.doFinal("scp-storage-passphrase".toByteArray(Charsets.UTF_8)).take(32).toByteArray()
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

**SDK injection point** (in the Kotlin SDK, `SCP.kt`):

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
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")  // Ed25519 fallback for API 26-32
    implementation("androidx.security:security-crypto:1.1.0-alpha06")  // EncryptedSharedPreferences
}
```

### Dependencies

- **ADR-006 (Platform Abstraction Traits):** `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage` trait signatures implemented here. The UniFFI callback interface names (`KeyCustodyProvider`, `DeviceAttestationProvider`, `PushProvider`, `StorageProvider`) map directly to these traits.
- **ADR-021 (UniFFI Bridge):** Platform traits are exposed as UniFFI callback interfaces. `AndroidKeyCustody`, `AndroidDeviceAttestation`, `AndroidPushProvider`, and `AndroidStorage` are Kotlin implementations of those callback interfaces, injected from Kotlin into the Rust engine. Five callback interfaces total: `KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `DeviceAttestationProvider`, `MessageListener`.
- **ADR-025 (Apple Platform Adapter):** Structural reference. Both adapters implement the same four traits via the same UniFFI callback interface pattern. Key difference: Android 13+ achieves hardware-backed Ed25519 (unavailable on Apple due to Secure Enclave P-256 constraint).
- **ADR-028 (Kotlin SDK):** The Kotlin SDK's `SCP.create()` factory calls `AndroidPlatformAdapter.make(context)` when `custody = "platform"`. The SDK owns the injection point; the platform adapter owns the implementations.

### Acceptance Criteria

1. **`AndroidKeyCustody.generateKeypair(keyType)`:**
   - For `KeyType.ED25519` on API 33+: generates key in `AndroidKeyStore` using `KeyPairGenerator.getInstance("EdDSA", "AndroidKeyStore")` with `EdDSAParameterSpec(Ed25519)`. Returns `KeyHandle` with `custodyType = CustodyType.HARDWARE`.
   - For `KeyType.ED25519` on API 26-32: generates Bouncy Castle software key. Stores in `EncryptedSharedPreferences`. Returns `KeyHandle` with `custodyType = CustodyType.SOFTWARE`.
   - For `KeyType.X25519`: generates Bouncy Castle software X25519 key. Returns `KeyHandle` with `custodyType = CustodyType.SOFTWARE`.
   - Called four times during identity creation when agent delegation is enabled (ADR-039): Identity Key, Active Signing Key, Pre-Rotation Key, and Agent Signing Key. The Agent Signing Key is always software-held (Bouncy Castle, not Android Keystore TEE) since it is designed for autonomous agent operation and may need to be exported or rotated independently.

2. **`AndroidKeyCustody.sign(keyHandle, data)`:**
   - For hardware handles: retrieves `PrivateKeyEntry` from `AndroidKeyStore`, calls `Signature.getInstance("EdDSA")`, returns 64-byte signature.
   - For software handles: signs via Bouncy Castle `Ed25519Signer`. Returns 64-byte signature.
   - Returns `ScpException("SCP-CRYPTO-4001")` if handle not found.

3. **`AndroidKeyCustody.publicKey(keyHandle)`:**
   - For hardware handles: extracts raw 32-byte Ed25519 public key from Keystore certificate.
   - For software handles: returns `Ed25519PublicKeyParameters.encoded`.

4. **`AndroidKeyCustody.destroyKey(keyHandle)`:**
   - For hardware handles: calls `KeyStore.deleteEntry("scp.key.${id}")`.
   - For software handles: removes from in-memory map.
   - Key destruction is verifiable: subsequent `sign()` or `publicKey()` calls return `ScpException("SCP-CRYPTO-4001")`.

5. **`AndroidKeyCustody.dhAgree(keyHandle, peerPublic)`:**
   - Performs X25519 ECDH via Bouncy Castle `X25519Agreement`. Returns 32-byte shared secret.
   - X25519 key must have been generated with `KeyType.X25519`.

6. **`AndroidKeyCustody.derivePseudonym(keyHandle, contextId)`:**
   - Computes `HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`. Derives an Ed25519 keypair from the first 32 bytes (interpreted as an RFC-8032 seed).
   - Returns `PseudonymKeyHandle` with `custodyType = CustodyType.SOFTWARE` (the derived pseudonym keypair is always software-managed, even for a hardware identity key).
   - **pseudonym_secret definition (IMPORTANT):** The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key — public key bytes are public and would be a membership-enumeration oracle (§9.10.4.A). For **software** keys (API 26-32, Bouncy Castle), `pseudonym_secret = HKDF-SHA256(ed25519_private_seed, salt="scp-pseudonym-secret-v1", info="", len=32)`, byte-identical to Rust `derive_pseudonym_secret()`, so software pseudonyms are cross-platform deterministic (pinned by §25.19 vectors). For **hardware** keys (API 33+, Keystore TEE), private key bytes are non-exportable, so `pseudonym_secret = SHA-256(TEE_sign("scp-pseudonym-secret-v1"))` — a device-local secret computed inside the TEE. **Hardware pseudonyms are device-local by design** and are intentionally NOT identical across devices or to the software vectors; cross-device pseudonym identity is not a protocol requirement, since the TEE key never leaves the device. This matches ADR-006 acceptance criterion 6 (§9.10.4.A).

7. **`AndroidDeviceAttestation.attest(challenge, deviceId)`:**
   - Calls Play Integrity Standard API via `IntegrityManagerFactory.create(context).requestIntegrityToken(...)`.
   - Nonce is `Base64(SHA-256(clientDataJSON))` where `clientDataJSON = '{"challenge":"<base64(challenge)>","deviceId":"<base64(deviceId)>","type":"scp-device-attestation-v1"}'` (fields in this exact order, RFC 4648 base64 NO_WRAP).
   - Returns raw integrity token bytes (JWT for server-side verification).

8. **`AndroidDeviceAttestation.assert(requestHash)`:**
   - Issues a fresh Standard integrity token using `requestHash` as the challenge.
   - Returns integrity token bytes.

9. **`AndroidPushProvider.register()`:**
   - Calls `FirebaseMessaging.getInstance().token.await()`.
   - Returns FCM registration token string.

10. **`AndroidPushProvider.handleNotification(payload)`:**
    - Validates `payload["scp"] == "1"`.
    - Returns `WakeSignal.Pull` on valid payload.
    - Throws `ScpException("SCP-TRANS-5001")` if `scp` field is absent.
    - Throws `ScpException("SCP-TRANS-5002")` if `scp` field has unexpected value.
    - No context ID, sender DID, or message content is present in or extracted from the payload.

11. **`AndroidStorage.store(key, data)` / `retrieve(key)` / `delete(key)` / `listKeys(prefix)` / `deletePrefix(prefix)` / `exists(key)`:**
    - All operations on SQLCipher database encrypted with a TEE-derived 32-byte AES-256 key.
    - Storage key is generated in `AndroidKeyStore` under alias `scp.storage.key` with AES-256-GCM, TEE-backed, no user authentication required.
    - `listKeys(prefix)` returns keys in lexicographic order (required for KeyPackage buffer management and event log range queries).
    - `deletePrefix(prefix)` returns count of deleted keys.

12. **`AndroidPlatformAdapter.make(context)`:**
    - Constructs `AndroidKeyCustody`, `AndroidDeviceAttestation`, `AndroidPushProvider`, `AndroidStorage`.
    - Returns assembled adapter. Throws `ScpException` with descriptive message if any provider fails to initialize (e.g., Play Integrity unavailable, FCM not configured).
    - Called by Kotlin SDK `SCP.create(context, custody = "platform")`.

13. **Conformance test suite:**
    - Same conformance macros as the in-memory adapter (ADR-006): `key_custody_conformance!()`, `device_attestation_conformance!()`, `push_provider_conformance!()`, `storage_conformance!()`.
    - Hardware tests run on API 33+ physical device or API 33 emulator with Play Store.
    - Software fallback tests run on API 26-32 emulator — verify `CustodyType.SOFTWARE` reported, valid signatures produced.
    - FCM tests use Firebase Test Lab or mock `FirebaseMessaging` via dependency injection.
    - SQLCipher tests verify database is not readable without the Keystore-derived key (open raw SQLite file, confirm unreadable).

14. **Private key isolation:**
    - No Ed25519 private key bytes appear in logs, crash reports, or cross the UniFFI FFI boundary.
    - The Rust engine receives only signatures and public keys — never private key material.

### Scope

```
bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/ — 5 files, ~25 functions
```

| File | Functions |
|------|-----------|
| `AndroidKeyCustody.kt` | `generateKeypair`, `sign`, `publicKey`, `destroyKey`, `dhAgree`, `derivePseudonym`, `custodyType` + internal helpers |
| `AndroidDeviceAttestation.kt` | `attest`, `assert` |
| `AndroidPushProvider.kt` | `register`, `handleNotification` |
| `AndroidStorage.kt` | `store`, `retrieve`, `delete`, `listKeys`, `deletePrefix`, `exists` + `getOrCreateStorageKey`, `openEncryptedDatabase` |
| `PlatformAdapter.kt` | `make` |

---

## ADR-028: Kotlin SDK

**Status:** Decided

### Context

The UniFFI bridge (ADR-021) generates raw Kotlin bindings from the Rust protocol engine. While functional, the generated surface is not idiomatic Kotlin — it lacks coroutine suspension, `Flow<T>` streams, Android lifecycle awareness, Jetpack Compose integration, and the ergonomic patterns Kotlin developers expect. The Android platform adapter (ADR-027) provides the `KeyCustody`, `PushProvider`, `Storage`, and `DeviceAttestationProvider` implementations injected into the Rust engine via UniFFI callback interfaces.

The Kotlin SDK ergonomics layer wraps the generated bindings to produce an idiomatic Kotlin API that feels native to the platform: `suspend` functions throughout, `Flow<Message>` for streaming, `LifecycleOwner`-aware cleanup, `@Composable`-ready state holders, and `AutoCloseable` resource management. The ergonomics layer is pure Kotlin — zero protocol logic, zero duplication of Rust behavior. This mirrors the ADR-014 (Python SDK) and ADR-026 (Swift SDK) pattern: flat FFI bridge → idiomatic language wrapper.

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
- `ViewModel`-based usage is the recommended pattern: create `Scp` and `Context` in a `ViewModel`, expose `Flow<Message>` as a `StateFlow<List<Message>>` using `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())`. The `ViewModel.onCleared()` override calls `context.close()`.

**Jetpack Compose integration:**
- No Compose-specific artifacts or dependencies in the SDK. Compose integration is achieved through standard Kotlin patterns the SDK already provides: `Flow<Message>` collected via `collectAsState()`, and `AutoCloseable` resources managed in `remember { }` blocks with `DisposableEffect` for cleanup.
- Recommended pattern: `val messages by context.receiveFlow().collectAsState(initial = emptyList())`.
- Context lifecycle in Compose: `DisposableEffect(contextId) { onDispose { context.close() } }` ensures the context is closed when the composable leaves the composition.

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
- **`AutoCloseable` + explicit `close()` for resource management:** Kotlin/JVM resource management follows the `AutoCloseable` / `use { }` pattern. `Context` implements `AutoCloseable` so callers can use `context.use { }` blocks for automatic cleanup. The explicit `close()` suspend function performs graceful teardown (leave the MLS group, flush the event log, cancel the flow). `AutoCloseable.close()` is the synchronous safety net — it launches a `close()` coroutine and cancels the internal scope. This matches the `deinit` + `close()` pattern in the Swift SDK.
- **No Compose dependencies in SDK:** Compose APIs (`@Composable`, `State<T>`, `collectAsState()`) require the Compose compiler plugin and runtime. Shipping a Compose dependency in the SDK would force every consumer to adopt Compose or deal with unused transitive dependencies. Compose integration is trivially achieved with standard `Flow.collectAsState()` and `DisposableEffect` — patterns that are Compose-idiomatic without SDK involvement.
- **`Scp` class (not object/singleton) as top-level entry point:** `Scp` holds per-identity state (the identity handle, the platform adapter). Multiple `Scp` instances in a process are valid (e.g., in tests, or in apps that support account switching). A Kotlin `object` singleton would prevent this. The factory pattern `Scp.create()` is a `companion object` method — idiomatic for async factory construction in Kotlin.
- **Kotlin 2.x, JVM 11+:** Kotlin 2.x is the current stable release with full coroutines support, improved type inference, and the K2 compiler. JVM 11 is required by Android Gradle Plugin 8+ and covers all modern JVM targets. JVM 11 features (e.g., `List.of()`, `String.isBlank()`) are available; no Java 8 compatibility mode needed.

### Implementation

**Language:** Kotlin 2.x

**Package:** `bindings/kotlin/` published as `works.limn:scp-kt` on Maven Central.

**Dependencies from UniFFI:** `identityCreate()`, `identityLoad()`, `identityResolve()`, `contextCreate()`, `contextJoin()`, `contextLeave()`, `contextClose()`, `contextSend()`, `contextSubscribe()` (callback interface), `toolRegister()`, `toolInvoke()`, `toolVerify()`, `ucanValidate()`, `ucanMint()`, `ucanRevoke()`, `eventLogQuery()`, `eventLogVerify()`, `transportConnect()`, `transportStatus()`, and the `ScpError` enum — all from `internal/NativeLib.kt`.

**File layout:**

```
bindings/kotlin/
  build.gradle.kts                         # Root Gradle build (multi-module)
  settings.gradle.kts                      # Module declarations
  scp-kt/
    build.gradle.kts                       # SDK core module (JVM + Android)
    src/
      main/kotlin/works/limn/scp/
        Scp.kt                             # Scp class — top-level entry point, factory, context creation
        Identity.kt                        # Identity class, DIDDocument data class
        Context.kt                         # Context class, Flow<Message>, AutoCloseable lifecycle
        Tools.kt                           # ToolDefinition, TestVector data classes
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
        ToolsTest.kt
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

**`Scp.kt` — top-level entry point:**

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
 * An SCP identity (DID). Holds the signing key handle — never exposes private key bytes.
 * Constructed by Scp.create(). Use Scp.identity to access.
 */
class Identity internal constructor(internal val handle: IdentityHandle) {

    val did: String get() = handle.did()
    val custodyType: String get() = handle.custodyType()

    companion object {
        /** Load an existing identity from storage. */
        suspend fun load(did: String): Identity = withContext(Dispatchers.IO) {
            Identity(NativeLib.identityLoad(did))
        }
    }

    /** Resolve another identity's DID document. */
    suspend fun resolve(did: String): DIDDocument = withContext(Dispatchers.IO) {
        DIDDocument.fromRecord(NativeLib.identityResolve(did))
    }

    /** Rotate this identity's signing key. Returns an updated Identity with the same DID. */
    suspend fun rotateKey(): Identity = withContext(Dispatchers.IO) {
        Identity(NativeLib.identityRotateKey(identity = handle))
    }
}

/** A resolved DID document. */
data class DIDDocument(
    val did: String,
    val verificationMethods: List<VerificationMethod>,
    val services: List<ServiceEndpoint>,
    val resolvedAt: Long,  // Unix milliseconds
) {
    companion object {
        internal fun fromRecord(record: DIDDocumentRecord): DIDDocument = DIDDocument(
            did = record.did,
            verificationMethods = record.verificationMethods.map(VerificationMethod::fromRecord),
            services = record.services.map(ServiceEndpoint::fromRecord),
            resolvedAt = record.resolvedAt,
        )
    }
}
```

**`Context.kt`:**

```kotlin
/**
 * An active SCP context. Send messages, receive streams, invoke tools.
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

    /** Invoke a registered tool in this context. Returns the tool output as JSON. */
    suspend fun invokeTool(toolId: String, inputJson: String): String = withContext(Dispatchers.IO) {
        handle.invokeTool(toolId, inputJson)
    }

    /** Register a tool in this context. Returns the assigned tool ID. */
    suspend fun registerTool(definition: ToolDefinition): String = withContext(Dispatchers.IO) {
        handle.registerTool(definition.toRecord())
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
            is ScpError.Tool -> ToolException(error.message, error.code)
            is ScpError.Validation -> ValidationException(error.message, error.code)
        }
    }
}

class IdentityException(message: String, code: String) : ScpException(message, code)
class ContextException(message: String, code: String) : ScpException(message, code)
class PermissionException(message: String, code: String) : ScpException(message, code)
class CryptoException(message: String, code: String) : ScpException(message, code)
class TransportException(message: String, code: String) : ScpException(message, code)
class ToolException(message: String, code: String) : ScpException(message, code)
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
    val tools: List<ToolDefinition> = emptyList(),
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

/** Mint a UCAN token delegating capabilities to a member DID. Returns the token string. */
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
 * Base ViewModel that manages Scp and Context lifecycle.
 * Extend this to get automatic cleanup when the ViewModel is cleared.
 */
abstract class ScpViewModel : ViewModel() {

    protected var scpInstance: Scp? = null
    private val activeContexts = mutableListOf<works.limn.scp.Context>()

    protected fun trackContext(context: works.limn.scp.Context): works.limn.scp.Context {
        activeContexts.add(context)
        return context
    }

    override fun onCleared() {
        super.onCleared()
        viewModelScope.launch {
            activeContexts.forEach { runCatching { it.leave() } }
            activeContexts.clear()
            scpInstance?.close()
            scpInstance = null
        }
    }
}
```

**Jetpack Compose integration pattern (no SDK changes required):**

```kotlin
// In a composable — no SDK modifications needed; uses standard Flow + Compose APIs

@Composable
fun ContextScreen(contextId: String) {
    val viewModel: MyContextViewModel = viewModel()
    val context = remember(contextId) { viewModel.getContext(contextId) }

    // Collect the Flow as Compose State
    val messages by context.receiveFlow()
        .collectAsStateWithLifecycle(initialValue = emptyList<Message>())

    // Cleanup when the composable leaves composition
    DisposableEffect(contextId) {
        onDispose { context.close() }
    }

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
- **ADR-026 (Swift SDK):** Parallel reference. Same flat delegation pattern, same "no logic in the wrapper layer" principle, same FFI bridge → idiomatic language wrapper architecture. Key differences: Kotlin uses `suspend` functions and `Flow<Message>` where Swift uses `async/await` and `AsyncStream<Message>`; Kotlin uses `AutoCloseable` + `close()` where Swift uses `deinit` + `close()`; Kotlin uses `@Observable`-equivalent via `StateFlow` where Swift uses `@Observable` macro.
- **ADR-014 (Python SDK) / ADR-013 (PyO3 Bridge):** The ergonomics layer pattern — flat FFI bridge → idiomatic language wrapper — is established here and applied to Kotlin. Kotlin SDK mirrors the structural choices (no logic in the wrapper layer, delegation only) and the type category decisions (opaque handles for crypto state, data classes for data).
- **ADR-022 (TypeScript SDK):** Parallel patterns: `Flow<Message>` (Kotlin) mirrors `AsyncIterable<Message>` (TypeScript); `AutoCloseable.close()` (Kotlin) mirrors `Symbol.asyncDispose` (TypeScript). Conformance test suite is shared.

### Acceptance Criteria

1. **Module builds for all JVM targets:**

   ```bash
   ./gradlew build
   ./gradlew test
   ```

   Both commands exit 0. Zero ktlint violations. Zero detekt findings.

2. **`Scp.create()` factory:**
   - `Scp.create(custody = "in_memory")` returns an `Scp` instance with `identity.did` starting with `"did:dht:"`.
   - `Scp.create(custody = "platform", platformAdapter = AndroidPlatformAdapter.make(context))` returns an `Scp` instance with hardware-backed identity on API 33+.
   - `Scp.create()` with an unknown custody string throws `IdentityException` with code `"SCP-IDENT-1001"`.

3. **`Identity` operations:**

   ```kotlin
   val scp = Scp.create(custody = "in_memory")
   assertTrue(scp.identity.did.startsWith("did:dht:"))
   assertEquals("in_memory", scp.identity.custodyType)

   val doc = scp.identity.resolve(scp.identity.did)
   assertTrue(doc.verificationMethods.isNotEmpty())

   val rotated = scp.identity.rotateKey()
   assertEquals(scp.identity.did, rotated.did)  // DID is stable; key material rotates
   ```

4. **`Context` lifecycle:**
   - `scp.createContext(params)` returns a `Context` with `state == "active"`.
   - `context.send(payload)` delivers an encrypted message (no throw for valid payload and active state).
   - `context.leave()` completes without throwing for a valid active context.
   - After `close()`, `send()` throws `ContextException` with code `"SCP-CTX-2001"`.
   - `context.use { }` block calls `AutoCloseable.close()` on exit — verified by collecting the flow and asserting it completes after the block exits.

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
   - All `withContext(Dispatchers.IO)` wraps are present on every FFI-calling method. Verified by running all suspend functions from a `Dispatchers.Main`-confined test coroutine and confirming no `BlockingThreadException` is thrown.
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

9. **Tool operations:**

   ```kotlin
   val toolId = context.registerTool(ToolDefinition(
       name = "summarize",
       description = "Summarize text",
       inputSchema = mapOf("type" to "object", "properties" to mapOf("text" to mapOf("type" to "string"))),
       outputSchema = mapOf("type" to "object", "properties" to mapOf("summary" to mapOf("type" to "string"))),
       operator = scp.identity.did,
   ))
   assertTrue(toolId.startsWith("tool-"))
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
    - `ScpViewModel.onCleared()` calls `leave()` on all tracked contexts and `close()` on the `Scp` instance.

12. **Jetpack Compose integration (no SDK artifact required):**
    - `context.receiveFlow().collectAsStateWithLifecycle(initialValue = emptyList())` compiles and recomposes correctly when messages arrive.
    - `DisposableEffect(contextId) { onDispose { context.close() } }` calls `close()` when the composable leaves the composition — verified with `ComposeContentTestRule`.

13. **No logic in Kotlin layer:**
    - Code review: every public SDK method body contains exactly one `NativeLib.*` call (plus `withContext` and error mapping). No branching protocol logic exists in any ergonomics-layer file.

14. **Test suite passes:**

    ```bash
    ./gradlew test
    ./gradlew test -Ptarget=android  # Android instrumented tests (requires connected device or emulator)
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
| `src/main/kotlin/works/limn/scp/Scp.kt` | `Scp` class — top-level entry point, `create()` factory, `createContext()`, `joinContext()` |
| `src/main/kotlin/works/limn/scp/Identity.kt` | `Identity` class — `did`, `custodyType`, `load()`, `resolve()`, `rotateKey()`; `DIDDocument` data class |
| `src/main/kotlin/works/limn/scp/Context.kt` | `Context` class — `send()`, `receiveFlow()`, `invokeTool()`, `registerTool()`, `leave()`, `closeContext()`, `AutoCloseable` |
| `src/main/kotlin/works/limn/scp/Tools.kt` | `ToolDefinition`, `TestVector`, `OutletVerificationResult` data classes |
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

**Status:** Decided

### Context

Architecture.md §6 explicitly flags offline MLS re-sync as "the hardest unsolved problem" with High likelihood and High impact. Members offline for extended periods accumulate pending MLS proposals and Commits. The group state advances without them — epochs increment, sender keys rotate, members join and leave, governance actions execute. When the offline member reconnects, they must reconcile their stale local state with the group's current state. The difficulty is that MLS requires sequential epoch processing (each Commit depends on the previous epoch's key schedule), forward secrecy means old epoch keys are destroyed after the grace window (ADR-001 criterion 6), and relays are untrusted infrastructure that may or may not retain the full message history.

SCP's design makes this simultaneously harder and easier than in traditional messaging systems. Harder: devices are full protocol participants (§10.2), not thin clients that can ask a server for the current state. There is no authoritative server — only relays holding encrypted blobs and peers holding decrypted state. Easier: the verifiable event log (ADR-011) provides a cryptographic mechanism for state reconciliation — two members can compare Merkle roots and prove exactly where their views diverge. The protocol's minimal state footprint (§10.3) means what needs syncing is small: membership, roles, tokens, tool registrations, governance, and event hashes — not content.

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

**Phase 5 — MLS Update.** After catch-up is complete, the SDK issues an MLS Update proposal in each active context (§9.7.3: "SDK SHOULD issue an Update after re-establishing connectivity following an offline period"). This provides post-compromise security for the reconnecting member.

**Phase 6 — Queue drain.** Drain the outbound queue for each context. Each queued inner envelope is MLS-encrypted with the current epoch's key schedule and sent. If a queued message references a context that no longer exists (closed or expired while offline), the message is discarded with a `ContextGone` notification to the application layer.

#### 3. MLS Epoch Catch-Up (Tier 1 and Tier 2)

MLS requires sequential epoch processing — each Commit depends on the previous epoch's key schedule. An offline member at epoch E who reconnects to find the group at epoch E+N must process all N intermediate Commits in order.

**Commit recovery sources (tried in order):**

1. **Relay backfill.** MLS Commits are sent as MLS `PublicMessage` (Commit messages are not application messages; they are protocol messages delivered via the transport layer). Relays store them like any other blob. If the relay's retention covers the offline period, all Commits are recoverable.
2. **Peer request.** If relays have expired some Commits (blob_ttl elapsed), the reconnecting member broadcasts a `CommitRangeRequest { context_id, from_epoch, to_epoch }` as an MLS application message (using their current epoch keys — they can still encrypt at their stale epoch). Online members who have persisted the Commit messages respond with the missing Commits. This is a best-effort protocol — members are not required to retain raw Commit messages beyond the MLS grace window.
3. **Welcome-based fast-forward.** If the epoch gap is too large (> 100 epochs or no member can provide the full Commit chain), the reconnecting member is treated as a new joiner. An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage, effectively re-adding them to the group at the current epoch. The member's old leaf node is removed. This is the Tier 2 fallback — it preserves membership and context continuity but the member loses access to messages encrypted in epochs between their stale epoch and the current epoch (forward secrecy is maintained).

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
    pub requester_did: DID,
    pub signature: Ed25519Signature,
}

pub struct CommitRangeResponse {
    pub context_id: ContextId,
    pub commits: Vec<Vec<u8>>,  // Serialized MLS Commit messages, in epoch order
    pub responder_did: DID,
    pub signature: Ed25519Signature,
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

1. The reconnecting member publishes a `ResetRequest { context_id, member_did, last_known_epoch, reason, nonce, timestamp, signature }` via the relay (not MLS-encrypted — the member may not be able to encrypt at the current epoch). The request is signed by the member's Active Signing Key or Agent Signing Key (ADR-039) for authentication — either key is accepted since both are valid verification methods on the member's DID. The `nonce` is 16 random bytes (CSPRNG) and the `timestamp` is the current Unix time in seconds. The signature covers all fields except the signature itself via the canonical hash construction (§9.5.1) with domain separator `"SCP-RESET-REQUEST-V1:"`.

   **Anti-replay validation.** Because ResetRequest is not MLS-encrypted, it is visible to relays and any network observer. Without replay protection, an attacker who captures a valid ResetRequest can replay it to force-remove and re-add the member repeatedly, disrupting their session. The relay (or any recipient processing the request) MUST validate:

   - **(a) Signature validity.** Verify the Ed25519 signature against the member's DID document (resolve `member_did`, check `#active` or `#agent` verification method).
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

- Their DID and identity.
- Their role in the context (the admin re-assigns the same role during re-add).
- Their event log history up to the last known epoch.
- Context metadata (params, tools, ceiling) — this is public and queryable via the metadata routing ID (ADR-004).

```rust
pub struct ResetRequest {
    pub context_id: ContextId,
    pub member_did: DID,
    pub last_known_epoch: u64,
    pub reason: ResetReason,
    /// 16 random bytes (CSPRNG). Prevents replay of captured requests.
    pub nonce: [u8; 16],
    /// Unix timestamp (seconds) when the request was created.
    /// Recipients reject requests older than 30 seconds.
    pub timestamp: u64,
    pub signature: Ed25519Signature,
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

#### 5. Conflict Resolution

Concurrent offline operations create conflicts when two or more members make incompatible changes while unable to observe each other's actions. SCP resolves conflicts using three principles: (a) the Merkle event log order is authoritative (§9.14), (b) MLS epoch boundaries are synchronization points (§9.8.3), and (c) governance actions are serialized through the admin role (Phase 2 single-admin model).

**Conflict categories and resolution:**

**5a. Concurrent messages (no conflict).** Messages from different senders in the same epoch are ordered by `(epoch, sender_generation_number, timestamp)` per §9.8.3. Messages queued while offline receive fresh sequence numbers at drain time. No conflict — messages are independent.

**5b. Concurrent membership changes.** MLS serializes membership changes through Commits. Only one Commit can advance the epoch. If two members propose Add/Remove simultaneously, the first Commit to be processed wins; the second proposal becomes invalid (it references a stale epoch) and must be re-proposed. The reconnecting member detects this during epoch catch-up and re-issues any stale proposals.

**5c. Concurrent governance changes.** In Phase 2 (single-admin), governance changes are serialized through the admin. If the admin is offline, no governance changes can occur — this is by design. If a non-admin proposes a governance action while the admin is offline, the proposal is queued in the event log and processed when the admin reconnects. There is no conflict because governance is single-threaded.

For future multi-admin governance (ADR-031): if two admins both offline propose conflicting role changes, the conflict is resolved by Merkle log order — the first proposal to be committed to the log wins. The second admin's proposal is rejected as conflicting and must be re-proposed with awareness of the first. If both proposals are committed simultaneously (same event log sequence), the protocol treats this as a log fork — equivocation detection (§9.9.3) fires and the context enters a `GovernanceConflict` state requiring manual resolution by an admin with sufficient capability. This is the "governance deadlock = context fork" outcome from the stub — but formalized: the context is not forked automatically. Instead, it is frozen (no new governance actions) until an admin resolves the conflict.

**5d. Concurrent sender key rotations.** If a sender rotates their key while a peer is offline, the peer requests the new key on reconnection (Phase 4 of the reconnection protocol). If the sender rotated multiple times, only the current key is needed — intermediate keys are irrelevant (messages encrypted with intermediate keys during the offline period are recovered via relay backfill before the sender key was rotated, or are unrecoverable if the relay expired them).

**5e. Context closure or expiry during offline.** If a context was closed or expired while the member was offline, the reconnecting member discovers this during relay catch-up (the `ContextClosing`, `ContextClosed`, or `ContextExpired` events are in the backfill). The member processes the closure locally, destroys key material per the context's memory scope, and discards any queued messages for that context.

#### 6. Event Log Reconciliation

The Merkle event log (ADR-011) is the authoritative state record. After relay catch-up and epoch reconciliation, the SDK verifies event log consistency:

1. **Exchange checkpoints.** The reconnecting member generates a `ConsistencyCheckpoint` (ADR-011 criterion 8) from their local log state and sends it to the context. Online members compare and respond with their own checkpoints.
2. **Compare Merkle roots.** If roots match at the same event count, the logs are consistent — no further action.
3. **Behind.** If the reconnecting member's event count is less than the group's (the expected case after offline), the member obtains the missing events through the Phase 1 relay backfill (`SUBSCRIBE` with `since`, ADR-004) — relays are untrusted dumb pipes, so there is no distinct event-range request/response wire message and no peer-supplied proof. The backfilled suffix events are independently authenticated by the normal MLS receive path (per-event signature, sequence ordering, and `prev_hash` chain; spec §23.13). The member then verifies catch-up integrity **locally**: it computes a Merkle consistency proof (RFC 6962 §2.1.2; ADR-011) via `verify_consistency` that its pre-gap last-known checkpoint root is a prefix of the root it reaches by replaying the backfilled events, and gates that reached root (constant-time `ct_eq`) against the single already-authenticated signed `ConsistencyCheckpoint` target root (membership + Ed25519, spec §23.12 / §9.9.3). This is the same-log catch-up integrity check, distinct from cross-member equivocation detection (spec §23.7 step 3, §9.9.3). Note: `CommitRangeRequest` (above) is the MLS *Commit* epoch catch-up mechanism (§23.16.2) and is unrelated to event-log event recovery — the two MUST NOT be conflated.
4. **Divergent.** If Merkle roots differ at the same event count, equivocation has occurred (a relay showed different histories to different members, per §9.9.3). The reconnecting member raises a `EquivocationDetected` alert. Resolution follows the relay consistency protocol (§9.9.3): identify the divergent relay, flag it in reliability scoring (ADR-012), and exchange Merkle **inclusion** proofs to attribute the divergence. This is NOT a majority vote — any divergence between any two honest members detects equivocation regardless of how many peers agree with the attacker.

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
  - `sync/{context_id}/last_relay_contact` — last successful relay interaction timestamp
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

> **ADR-029 Addendum — Reconnection driver location after the ADR-049 actor refactor.** ADR-049 replaced `ContextManager` with a per-context actor (state behind a mailbox; the actor's `ContextTransportProvider` is send-only). Buffered-message retrieval (relay SUBSCRIBE/QUERY-since) is owned by `TransportManager` at the FFI/SDK relay-client layer. Therefore the reconnection driver — the concrete impl of `SyncPhaseDriver` (Tier 1), `SnapshotTransport` (Tier 2), `ResetTransport` (Tier 3) — is constructed and driven at the FFI/SDK layer (same layer as `context_subscribe`). It reads relay-buffered messages/snapshots from `TransportManager`, reaches actor-owned state (MLS epoch, Commit/Welcome processing, checkpoint build/compare, event-log, queue drain) via `Supervisor` commands/queries — never by widening `ContextTransportProvider` — and consumes `EpochState.needs_reconnect` (spec §23.11). `ReconnectionCoordinator` no longer holds `Arc<ContextManager>`/`Arc<TransportManager>`; it is parameterized on a `SyncPhaseDriver` supplied by the relay-client layer. The six-phase protocol (§2) and tier engines are behaviorally unchanged; only the ownership/wiring location is restated. This supersedes the field list in ADR-029 §2 AC 2.

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
    member_did: DID,
    old_epoch: u64,
    new_epoch: u64,
    reason: ResetReason,
    processed_by: DID,
},
QueueDrained {
    member_did: DID,
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

**Status:** Decided

### Context

Every SCP context maintains an append-only Merkle event log (ADR-011) that records all protocol events — membership changes, governance actions, tool invocations, messages, role assignments, block notifications, and consistency checkpoints. The log is the foundation for participation validation (§7.3.1), equivocation detection (§9.9.3), and the trust model's Layer 2 (verifiable participation records, §7.3.2). Its append-only structure is what makes claims about context history verifiable rather than trust-dependent.

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
    /// DID of the checkpoint creator.
    pub creator_did: DID,
    /// Unix timestamp of checkpoint creation.
    pub created_at: u64,
    /// Ed25519 signature over SHA-256(context_id || checkpoint_seq ||
    /// merkle_root || event_count || last_event_hash ||
    /// SHA-256(serialize(state_snapshot)) || created_at).
    pub signature: Ed25519Signature,
    /// Optional governance quorum signatures (for multi-admin contexts, ADR-031).
    /// In single-admin contexts, this is empty and creator_did must be the admin.
    pub cosignatures: Vec<CosignedCheckpoint>,
}

pub struct CosignedCheckpoint {
    pub signer_did: DID,
    pub signature: Ed25519Signature,
}

pub struct ContextStateSnapshot {
    /// Current membership: DID -> role mapping.
    pub membership: Vec<(DID, RoleName)>,
    /// Current capability ceiling.
    pub capability_ceiling: Vec<Capability>,
    /// Ceiling policy (locked, governed, admin-only).
    pub ceiling_policy: CeilingPolicy,
    /// Governance model identifier and configuration.
    pub governance: GovernanceConfig,
    /// Memory scope.
    pub memory_scope: MemoryScope,
    /// TTL remaining (None if no TTL or if persistent).
    pub ttl_remaining_secs: Option<u64>,
    /// Registered tools.
    pub tools: Vec<OutletRegistration>,
    /// Active sender key epochs per member.
    pub sender_key_epochs: Vec<(DID, u64)>,
    /// Current MLS epoch (None for Broadcast contexts).
    pub mls_epoch: Option<u64>,
    /// Active block relationships: (blocker, blocked).
    pub blocks: Vec<(DID, DID)>,
    /// Context mode (Encrypted or Broadcast).
    pub context_mode: ContextMode,
    /// Parent context IDs (empty for root contexts).
    pub parent_context_ids: Vec<ContextId>,
    /// Active UCAN revocations.
    pub ucan_revocations: Vec<String>,
}
```

**Checkpoint creation rules:**

- In single-admin contexts (Phase 2 governance), only the admin can create checkpoints. The checkpoint is signed by the admin's Active Signing Key or Agent Signing Key (ADR-039).
- In multi-admin contexts (ADR-031), checkpoints require signatures from a governance quorum (e.g., M-of-N admins). The `cosignatures` field carries additional signer attestations.
- Members receiving a checkpoint verify the signature(s) against known admin DID(s), then verify that the `merkle_root` matches their local Merkle root at `checkpoint_seq`. If it matches, the checkpoint is trusted. If it diverges, the member raises an equivocation alert (same mechanism as §9.9.3 consistency checkpoint divergence).
- The `state_snapshot` is deterministically serialized (sorted keys, canonical MessagePack encoding) so that any member can independently compute `SHA-256(serialize(state_snapshot))` and verify the signature covers the correct state.

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
    /// ConsistencyCheckpoint, KeyEpochAdvance, AbsenceProofRequested.
    /// These are retained for the base retention period.
    pub operational_retention_multiplier: f64,  // Default: 1.0x
}
```

Event-type retention interacts with time-based pruning: the effective retention for a structural event is `retention_secs * structural_retention_multiplier`. A context with a 30-day base retention and a 3.0x structural multiplier retains governance events for 90 days while message events are prunable after 30 days.

**Pruning invariants (enforced mechanically):**

1. Events are never pruned unless they are behind a valid, locally-verified checkpoint. No checkpoint = no pruning.
2. The protocol-enforced minimum retention period is 30 days. A context cannot configure a retention shorter than 30 days. This ensures participation validation (§7.3.1) has sufficient history for meaningful evaluation.
3. Pruning never removes checkpoint events themselves. Checkpoints are retained indefinitely (they are small and serve as trust anchors).
4. Pruning is always local. A member's decision to prune does not affect other members' logs. Members who need full history can retain it regardless of the context's pruning policy.
5. The hash chain is preserved: even when event payloads are pruned, the `prev_hash` chain continuity is maintained through retained leaf hashes.

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
1. Verify `checkpoint.signature` against the checkpoint creator's DID.
2. Verify `checkpoint_inclusion` — the checkpoint event is in the current log.
3. Verify `pruned_proof.checkpoint_root == checkpoint.merkle_root`.
4. Verify `pruned_proof` — the target event was in the log at `checkpoint_seq`.

This three-step chain provides the same assurance as a direct inclusion proof: the event was part of the log's history, the checkpoint is authentic, and the checkpoint is itself part of the current log.

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

1. **Obtain the latest checkpoint.** Query the context's event log (via relay QUERY or peer request) for the most recent `Checkpoint` event. Verify its signature against the admin's DID.
2. **Verify checkpoint consistency.** Compute or request the current Merkle root from an online member (via consistency checkpoint exchange, ADR-011 criterion 8). Verify that the checkpoint event is included in the current log via standard inclusion proof.
3. **Load state snapshot.** Deserialize the checkpoint's `ContextStateSnapshot`. This provides complete context state as of the checkpoint: membership, roles, governance, tools, ceilings, blocks, and sender key epochs.
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
   - Signs the checkpoint with the provided signing key (admin's Active Signing Key or Agent Signing Key per ADR-039).
   - Appends the checkpoint as a `Checkpoint` event to the event log.
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

**Status:** Decided

### Context

Phase 2 governance (ADR-008) uses a single-admin model: one DID holds all governance authority, and governance actions are serialized through that admin. This works for bilateral contexts, small groups, and contexts where a clear authority is appropriate. It becomes a bottleneck and a single point of failure for larger, more collaborative contexts: if the admin goes offline, no governance changes can occur (ADR-029 section 5c explicitly acknowledges this); if the admin acts unilaterally in ways members disagree with, the only recourse is exit (§9.2.1); and if the admin's key is compromised, the entire context's governance is compromised.

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

    /// Return the set of DIDs eligible to vote on proposals in this model.
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
/// Governance model selection. Set at context creation, immutable thereafter.
/// Included in context metadata (§5.7) — visible before opt-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceModelConfig {
    /// Single admin holds all governance authority. Phase 2 baseline.
    /// The creator is the initial (and only) admin. Admin transfer is
    /// a governance action that replaces the admin DID.
    SingleAdmin {
        admin_did: DID,
    },

    /// M-of-N threshold approval. A fixed set of designated signers;
    /// a proposal passes when at least `threshold` of them approve.
    /// One DID = one vote regardless of signing key (ADR-039). A vote
    /// signed by `#agent` counts the same as one signed by `#active`.
    Threshold {
        /// The set of DIDs authorized to vote. These DIDs must hold
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

- `Threshold`: `signers` must be non-empty, `threshold` must be in `[1, signers.len()]`, all signer DIDs must be among the context's initial members, `voting_window_secs` must be in `[300, 604_800]` (5 minutes to 7 days).
- `Majority`: `min_participation_bps` must be in `(0, 10000]`, `voting_window_secs` must be in `[300, 604_800]`.
- `Unanimity`: `voting_window_secs` must be in `[300, 604_800]`.

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
    pub signature: Ed25519Signature,
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
    /// Register a new tool.
    RegisterOutlet { registration: OutletRegistration },
    /// Remove a tool.
    RemoveOutlet { outlet_id: OutletId },
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
    /// Establish a tool interface with another context (§6.2).
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
    /// Not DID-targeted — rotates keys for all members.
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

#### 4. Proposal Resolution Rules Per Model

**4a. SingleAdmin.** The admin's `propose()` call simultaneously creates and approves the proposal. The `approve()`/`reject()` methods are no-ops (return the current status). This preserves backward compatibility with Phase 2 behavior — single-admin governance is immediate and serialized.

**4b. Threshold (M-of-N).** A proposal passes when `threshold` signers from the `signers` set have approved. Resolution is checked after every vote:

- If `approvals.len() >= threshold`: status becomes `Approved`.
- If `rejections.len() > signers.len() - threshold`: approval is mathematically impossible, status becomes `Rejected { reason: ApprovalImpossible }`.
- If `now > voting_deadline` and neither condition met: status becomes `Expired`.

Votes are order-independent — the Mth approval resolves the proposal regardless of when or in what order the M votes arrived. Only DIDs in the `signers` set can vote. A signer can withdraw their vote and re-vote (changing from approve to reject or vice versa) while the proposal is `Pending`.

**4c. Majority.** A proposal passes when approvals exceed 50% of eligible voters (all members holding `GovernanceVote` capability). Resolution:

- Let `eligible = eligible_voters.len()`, `participation = approvals.len() + rejections.len()`.
- If `participation / eligible < min_participation` when `now > voting_deadline`: status becomes `Rejected { reason: InsufficientParticipation }`.
- If `approvals.len() > eligible / 2`: status becomes `Approved` (early resolution — majority reached before deadline).
- If `rejections.len() >= eligible / 2`: status becomes `Rejected { reason: MajorityRejected }` (early rejection — approval impossible).
- If `now > voting_deadline` and `participation / eligible >= min_participation` and `approvals > rejections`: status becomes `Approved`.
- If `now > voting_deadline` and `participation / eligible >= min_participation` and `approvals <= rejections`: status becomes `Rejected { reason: MajorityRejected }`.

The eligible voter set is computed at proposal creation time and frozen for the proposal's lifetime. Members who join after proposal creation do not vote on it; members who leave have their votes removed.

**4d. Unanimity.** Every eligible voter must approve. A single rejection defeats the proposal immediately:

- If all eligible voters have approved: status becomes `Approved`.
- If any eligible voter rejects: status becomes `Rejected { reason: UnanimityBroken { rejector } }`.
- If `now > voting_deadline` and not all have voted: status becomes `Expired`.

Unanimity is required by the spec (§5.10) for TTL extension and context promotion. The `ExtendTtl` and `PromoteContext` governance actions always require unanimity regardless of the context's governance model — this is a protocol-level override enforced by the `ContextManager`, not by the governance engine.

#### 5. Voting Windows and Timeout Handling

Every proposal has a `voting_deadline = created_at + voting_window_secs`. The voting window is configured per governance model at context creation and applies uniformly to all proposals in that context.

**Timeout processing.** The SDK runs a background task (`GovernanceTimeoutTask`) that checks active proposals every 60 seconds. When a proposal's deadline passes without resolution, the task calls `resolve()` which transitions the proposal to `Expired` or `Rejected` (depending on model-specific rules). The timeout task also handles:

- **Proposer departure.** If the proposer leaves the context while a proposal is `Pending`, the proposal is `Invalidated`. The proposer's departure does not retroactively invalidate an already-approved proposal.
- **Voter departure.** If an eligible voter leaves the context, their vote is removed from the tally. This may change the resolution — if a Unanimity proposal had all approvals and one voter leaves, the proposal remains approved (the voter approved before leaving). If a voter leaves without having voted, the eligible voter set shrinks, which may make quorum easier to reach (Majority) or harder (Unanimity).
- **Epoch reset.** If a member undergoes a group state reset (ADR-029 Tier 3), their votes on pending proposals are invalidated (the reset changes their epoch context). The proposal is not automatically invalidated — other votes remain valid.

#### 6. UCAN Delegation in Multi-Admin Contexts

In single-admin governance, the context creator holds the root UCAN authority and delegates all capabilities. In multi-admin governance, UCAN authority is distributed:

**Root UCAN issuer.** The context creator remains the root UCAN issuer. This is a cryptographic necessity — the UCAN delegation chain must have a single root of trust (ADR-009 step 4: "root token's `iss` is the context creator's DID"). The creator is not a privileged governor — they are the key ceremony initiator. One DID = one vote regardless of which signing key (`#active` or `#agent`) casts the vote (ADR-039). The governance engine deduplicates by DID, not by key.

**Governance capability distribution.** At context creation, the creator mints `GovernancePropose` and `GovernanceVote` UCAN tokens for each DID that the governance model designates as a voter:

- `Threshold`: each DID in `signers` receives `GovernancePropose` + `GovernanceVote`.
- `Majority`: each member whose role includes `GovernanceVote` capability receives those tokens at role assignment.
- `Unanimity`: same as Majority — all members with `GovernanceVote` in their role.

**Governance action execution.** When a proposal is approved, the governance engine returns the decision to the `ContextManager`. The `ContextManager` executes the action using the creator's root authority — it mints new UCANs, revokes old ones, modifies membership, etc. The governance engine does not execute actions; it only decides whether they are approved. This separation ensures that UCAN chains remain valid (the root issuer signs all delegations) while governance authority is distributed (multiple DIDs vote on whether to authorize the action).

**Signer set modification (Threshold model).** When a `Threshold` proposal to add or remove a signer is approved, the `ContextManager` mints or revokes `GovernanceVote` UCANs accordingly. Adding a signer requires the new DID to already be a context member. Removing a signer does not remove them from the context — it only removes governance authority. The `threshold` value is validated after modification: if removing a signer would make `threshold > signers.len()`, the removal is rejected.

#### 7. Governance Conflict Resolution

ADR-029 section 5c defines the conflict scenario: two admins both offline simultaneously propose conflicting governance actions. When both reconnect, both proposals are committed to the event log. The first proposal committed to the Merkle log wins; the second is rejected as conflicting.

**Conflict detection.** The `GovernanceEngine` detects conflicts when two `Approved` proposals in the event log are incompatible:

- Two `RemoveMember` proposals targeting each other's proposers (mutual removal).
- Two `ChangeRole` proposals for the same DID with different target roles.
- Two `ModifyCeiling` proposals with different ceiling sets.
- A `RemoveMember` and a `ChangeRole` for the same DID.
- A `RevokeReadAccess` and a `RestoreReadAccess` for the same DID (mutually contradictory).
- A `RevokeWriteAccess` and a `RestoreWriteAccess` for the same DID (mutually contradictory).
- Two `RevokeReadAccess` proposals for the same DID with different scopes (Full vs FutureOnly).
- Two `RevokeWriteAccess` proposals for the same DID with different scopes (Full vs FutureOnly).

**Conflict resolution.** When a conflict is detected:

1. The proposal with the lower event log sequence number (earlier in Merkle log) wins. This is deterministic — all members compute the same winner.
2. The losing proposal's status becomes `Invalidated { reason: "Conflicting proposal {winner_id} committed first" }`.
3. A `GovernanceConflict` event is appended to the event log recording both proposal IDs, the winner, and the resolution method.
4. If the losing proposer still wants their action, they must re-propose with awareness of the winning proposal's effects.

**Mutual removal (always GovernanceFreeze).** When two proposals each remove the other's proposer (`RemoveMember { did: B }` proposed by A, and `RemoveMember { did: A }` proposed by B), the conflict always triggers a governance freeze regardless of leaf index ordering. Rationale: executing the first removal invalidates the authority of the second proposer, creating a paradox — if A's removal of B wins by log order, B no longer has authority to have proposed removing A, but B's proposal is already committed. This circular dependency cannot be resolved by simple ordering. The freeze includes ALL conflicting proposals in the set, not just the mutual-removal pair, so that no conflicts are silently dropped.

**Simultaneous commit (same sequence number).** If two conflicting proposals land at the exact same event log sequence (extremely rare — requires both to be appended in the same batch), the protocol enters a `GovernanceConflict` state:

1. The context is frozen for new governance actions — no new proposals accepted EXCEPT `ResolveConflict`. Message sending and tool invocation continue normally.
2. A `GovernanceConflictDetected` event is emitted.
3. Resolution requires an explicit `ResolveConflict` governance action from any DID with `GovernanceVote` capability. The resolution specifies which proposal wins. `ResolveConflict` is explicitly exempt from the governance freeze — it is the designated mechanism for lifting the freeze.
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

Governance proposals and votes are MLS application messages (in Encrypted contexts) or broadcast messages (in Broadcast contexts). They do not trigger MLS epoch advances — only membership changes (add/remove) and MLS Updates trigger Commits.

However, governance actions that result in membership changes (approved `AddMember` or `RemoveMember` proposals) do trigger MLS operations, which advance the epoch. The sequence is:

1. Proposal approved (governance decision).
2. `ContextManager` executes the membership change (MLS `add_member()`/`remove_member()`).
3. MLS Commit advances the epoch.
4. `GovernanceActionExecuted` event appended to event log (records proposal ID, action, executor DID, resulting epoch).

Pending proposals are NOT invalidated by epoch advances. A proposal created at epoch E is valid at epoch E+N — the proposal references a governance action, not an epoch-specific state. The only exception is group state reset (ADR-029 Tier 3), which invalidates pending proposals because the member's relationship to the group has fundamentally changed.

#### 9. Interaction with Checkpointing (ADR-030)

ADR-030 defines checkpoint cosignatures for multi-admin contexts. The requirement is:

- In `SingleAdmin` contexts, only the admin signs checkpoints. `cosignatures` is empty.
- In `Threshold` contexts, checkpoints require `threshold` signatures from the signer set. The checkpoint creator collects signatures by distributing the checkpoint hash to other signers, who verify and cosign.
- In `Majority` contexts, checkpoints require signatures from >50% of eligible voters.
- In `Unanimity` contexts, checkpoints require signatures from all eligible voters.

Checkpoint cosignature collection follows the same voting-window pattern as governance proposals but with a shorter default window (1 hour). If cosignature quorum is not reached, the checkpoint is still valid with the creator's signature alone but is flagged as `PartiallyAttested` — members can decide how much weight to give it.

#### 10. Deadlock Recovery

Deadlock occurs when the governance model requires votes from DIDs that are permanently unavailable (key loss, extended offline beyond Tier 3, deliberate non-participation).

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
    /// DIDs that are unavailable.
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

Without a deadlock recovery mechanism, a Threshold(3-of-5) context where 3 signers lose their keys is permanently frozen — no governance action can ever pass. The fallback quorum (majority of remaining active voters) is the least disruptive recovery: it preserves the model type, requires majority agreement among the remaining participants, and is fully logged. The alternative — no recovery, context must be abandoned — wastes the context's history, tool registrations, and ongoing work. The 48-hour voting window for recovery proposals gives absent members extra time to return, reducing false deadlock detection.

**Why the context creator remains the UCAN root:**

UCAN delegation chains require a single root issuer (ADR-016 step 4). Distributing root authority across multiple DIDs would require multi-signature UCAN tokens, which the UCAN spec does not support. The creator-as-root pattern is already established in Phase 2 and works well: the creator's cryptographic role (root issuer) is decoupled from their governance role (which may be no more than any other signer in a Threshold model). The creator cannot unilaterally mint capabilities that bypass governance — all capability changes go through the governance engine.

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

- **ADR-008 (Context Lifecycle):** The `ContextManager` delegates governance decisions to the `GovernanceEngine`. Context creation includes `GovernanceModelConfig` in `ContextParams`. The governance model constrains which context operations require proposals (all multi-admin operations) vs. which are immediate (message sending, tool invocation — these are UCAN-authorized, not governance-gated).
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
   - `GovernanceAction` with all 30 variants listed in section 3 (including content access actions: RevokeReadAccess, RestoreReadAccess, RevokeWriteAccess, RestoreWriteAccess, RotateContentKeys; broadcast action: BlockAuthor; economic actions: SetEconomicPolicy, ApproveSpend, LockEconomicPolicy; migration actions: ProposeContextMigration, AcceptContextMigration) and `RevocationScope` enum (Full, FutureOnly).
   - `ProposalStatus` with `Pending`, `Approved`, `Rejected`, `Expired`, `Cancelled`, `Invalidated`.
   - Proposals are persisted to `ProtocolRepository` on creation and on every status change.

3. **`SingleAdminEngine` implementation:**

   - `propose()` creates a proposal and immediately sets status to `Approved` if the proposer is the admin DID. Returns `GovernanceError::NotAdmin` if proposer is not the admin.
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

8. **Governance timeout background task:**

   - `GovernanceTimeoutTask` runs every 60 seconds per context with active proposals.
   - Calls `resolve()` on each pending proposal to check for expiry.
   - Detects voter departures and adjusts tallies.
   - Detects deadlock conditions (consecutive missed voting windows per voter).

9. **Protocol-level unanimity override for TTL extension and context promotion:**

   - When a `GovernanceAction::ExtendTtl` proposal is created in a non-Unanimity context, the `ContextManager` overrides the governance model's resolution rules and requires approval from ALL current members (not just governance voters). This enforces §5.10's requirement that TTL extension requires unanimous consent.
   - When a `GovernanceAction::PromoteContext` proposal is created in a non-Unanimity context, the same unanimity override applies. This enforces §5.10's requirement that promotion from ephemeral to persistent requires consent from all current members.

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

**Status:** Decided

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
    /// DID this key belongs to.
    member_did: DID,
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
    /// Truncated SHA-256 of the member's DID (first 8 bytes).
    /// Used as lookup key in the wrapped_ceks map.
    pub member_id: [u8; 8],
    /// AES-256-KW wrapped CEK (40 bytes: 32-byte key + 8-byte integrity check).
    pub wrapped_key: [u8; 40],
}
```

#### 2. Access Key Lifecycle

**Generation.** When `AddMember` executes (via governance), the executor generates a fresh random 32-byte AES-256 access key for the new member. The access key is distributed via HPKE Base mode (RFC 9180) using the same pull-based protocol and suite as sender keys (ADR-007, §9.16.2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. The new member sends an `AccessKeyRequest`, the key holder responds with `AccessKeyResponse` containing the HPKE-sealed access key. The HPKE `info` parameter MUST use a distinct domain separator: `info = "scp-access-key-v1" || context_id || member_did || epoch_bytes`. The `aad` parameter is: `aad = context_id || member_did || epoch_bytes`. Where `epoch_bytes` is the 8-byte big-endian encoding of the access key epoch. Sender keys use `"scp-sender-key-v1"` and broadcast keys use `"scp-broadcast-key-v1"`. This prevents cross-protocol key confusion where a compromised access key response could be replayed as a sender key response — different `info` values produce different HPKE key schedules.

**Distribution.** Access keys are distributed via two new wire types:

```rust
pub struct AccessKeyRequest {
    pub requester_did: DID,
    pub context_id: ContextId,
    pub epoch: u64,
    pub timestamp: u64,  // Unix milliseconds; requests older than 30s are rejected
    pub wrapping_pubkey: X25519PublicKey,  // Ephemeral, per-request
    /// Which verification method signed: "#active" or "#agent" (ADR-039).
    pub signing_key_id: String,
    /// Ed25519 signature over: SHA-256(context_id || requester_did || signing_key_id || epoch || timestamp || wrapping_pubkey)
    /// using the requester's Active Signing Key or Agent Signing Key (ADR-039). Prevents replay and impersonation.
    pub signature: Ed25519Signature,
}

pub struct AccessKeyResponse {
    pub context_id: ContextId,
    pub member_did: DID,
    pub epoch: u64,
    pub hpke_sealed_key: Vec<u8>,
    pub ephemeral_pubkey: X25519PublicKey,
}
```

**Normal operation.** On each message send:

1. Generate a fresh CEK (32 random bytes).
2. Encrypt the message content with AES-256-GCM using the CEK.
3. For each intended recipient: wrap the CEK with AES-256-KW using the recipient's access key. The wrapping operation is signed by the sender's Active Signing Key or Agent Signing Key (ADR-039).
4. Publish: `{ ciphertext, nonce, wrapped_ceks }`. Integrity is verified by the AES-256-GCM authentication tag — no separate content hash is stored.

On receive:

1. Look up own `member_id` (truncated DID hash) in `wrapped_ceks`. Note: the lookup is by DID, not by signing key — both `#active` and `#agent` operations on the same DID share the same access key (ADR-039).
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
    /// Key: first 8 bytes of SHA-256(member_did) — prevents DID publication.
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

**Why truncated DID hashes in wrapped_ceks:**

Publishing full DIDs in the wrapped_ceks map would leak membership information to anyone who can observe the ciphertext (relays, network observers). The truncated 8-byte hash provides a lookup key that the recipient can compute from their own DID but that does not reveal the DID to observers. Collision probability for 8-byte hashes is ~1 in 10^18 — negligible for any practical context size.

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
  - `context/{context_id}/access_key/exclusion_list` — DIDs excluded from future wrapping
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
   - Distribution uses HPKE Base mode (RFC 9180) with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Info: `"scp-access-key-v1" || context_id || member_did || epoch_bytes`. AAD: `context_id || member_did || epoch_bytes`. Same suite as sender key distribution (§9.16.2).

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

### Context

The Protocol Constants Registry (§9.18) promoted many implementation defaults to protocol-level constants. Constants like `MAX_SEQUENTIAL_COMMITS`, `RECONNECTION_TIMEOUT`, `SENDER_KEY_TIMEOUT`, `RECONNECTION_DEDUP_WINDOW`, and the nesting depth ceiling have no security or correctness basis for their specific values. The session cap default of 5 was a placeholder. The relay blob TTL is the relay operator's business. Several timeouts are hardware-dependent.

This creates unnecessary rigidity: independent implementations cannot tune for their deployment without breaking spec compliance. A nesting depth ceiling of 3 blocks real hierarchies. A protocol hard max chain depth of 5 prevents contexts from allowing deeper provenance chains when that is the correct tradeoff.

### Decision

Reclassify protocol constants into three tiers:

**Tier 1 — Protocol Invariants** (fixed, all implementations MUST agree):

| Constant | Value | Rationale |
|----------|-------|-----------|
| `DHT_REPUBLISH_INTERVAL` | 7200s | BEP44 constraint, not SCP's choice. |
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

4. `DID_DOCUMENT_BLOB_TTL_SECS` (resolver.rs:344) is intentionally independent from `RELAY_BLOB_TTL_SECS`. It is the identity-layer publication TTL for DID documents, used by the healing publisher, and remains unchanged.

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

### Context

Identity link attestations (§3.5) bind external platform identities to SCP DIDs. The original spec treated all attestation verification methods uniformly: OAuth, signed posts, DNS records, and challenge-response all shared the same trust model. In practice, these methods have fundamentally different trust properties:

- **OAuth and challenge-response** produce cryptographic proof of identity ownership at creation time. The SDK performs the OAuth code exchange, receives a signed ID token, and can extract a verified subject identifier. The proof is ephemeral — it exists at creation time but is not externally re-verifiable later.
- **Signed posts and DNS records** are live external resources. No cryptographic proof exists at creation time. The proof is the continued presence of the DID in the external resource, and consumers must fetch it to verify.

The original §3.5.2 defined two alternative `proof` formats for OAuth attestations: (a) the raw JWT from the OIDC provider, or (b) an SDK-signed summary. The raw JWT path is problematic:

1. **PII leakage.** Google OIDC tokens always include `email`. Apple tokens include `email` when the `email` scope is requested. Embedding raw JWTs in attestations stores PII in a protocol object that is replicated, cached, and potentially shared across untrusted consumers.
2. **Token expiry mismatch.** JWTs expire (typically in 1 hour). An attestation containing an expired JWT requires verifiers to either (a) accept expired JWTs (defeating the purpose of JWT expiry), or (b) reject the attestation after 1 hour (defeating the purpose of attestations).
3. **Verification requires JWKS.** Verifiers must fetch the OIDC provider's JWKS to validate the JWT. This creates a runtime dependency on external infrastructure for attestation verification.

Additionally, the original spec did not define how attestations are published in DID documents, leaving discovery underspecified.

### Decision

**Two attestation classes** as sub-classifications of `AttestationType::IdentityLink`:

**Class 1: Cryptographic.** Verification methods: `Oauth`, `ChallengeResponse`. The provider's confirmation was cryptographically verified at creation time. The SDK extracts the minimal claim (`provider`, `subject_id`, `verified_at`), signs the full attestation envelope with the DID key, and discards the raw token. The proof is an SDK-signed self-attestation: "I verified this at creation time." Consumers check the DID signature; no external fetch required.

**Class 2: Reference.** Verification methods: `SignedPost`, `DnsRecord`. The proof is a live external resource. The attestation points to a URL or DNS record. Consumers MUST fetch and verify the proof before granting trust weight. Unverified Reference attestations carry zero trust.

**SDK-signed proof format (Class 1).** The `evidence.proof` field contains `{ "provider": "<platform>", "subject_id": "<sub>", "verified_at": <unix_s> }`. The envelope signature covers this field. No raw JWT is stored. The SDK requests `openid` scope only — no `email`, no `profile`.

**Provider registry.** Seven initial providers: `github.com` (Class 2), `x.com` (Class 2), `google.com` (Class 1), `apple.com` (Class 1), `microsoft.com` (Class 1), `mastodon:<instance>` (Class 2), `dns` (Class 2). New providers by spec amendment only.

**DID document service entries.** Type `ScpIdentityLinkAttestation`. Fragment `attestation-<platform>--<index>`. Max 10 per DID document.

**`revocation_status` in signed scope.** The `revocation_status` field replaces the separate `revocation` object in the wire format. It is included in the signature scope, preventing replay of revoked attestations as active.

**Verification cache for Reference attestations.** Consumer-side, 1-hour TTL. Class 1 attestations need no cache (signature verification is deterministic).

### Rationale

The class distinction is not a new attestation type — it is a sub-classification within `IdentityLink`. This is deliberate. `AttestationType` has stable numeric tags (§7.4.1, `attestation_type_tag`). Adding a new variant would require a new tag and break the existing tag stability guarantee. Instead, the class is derived from the verification method, which is already a field in the wire format. Any consumer can determine the class by inspecting `evidence.method`.

The self-attestation model is acceptable for identity links specifically because issuer == subject. The DID owner is the only party with incentive to create the attestation, and the only party who can perform the OAuth flow. Falsifying a link provides no protocol benefit: shadow claiming (§3.5.5) verifies the external identity independently, and social graph import only surfaces contacts who genuinely control both identities.

### Rejected Alternatives

**1. Raw JWT embedding.** Rejected. PII exposure (Google always includes `email` in ID tokens). Token expiry creates verification timing issues. Runtime JWKS dependency for every verifier. The SDK-signed summary provides the same identity-linking function without any of these problems.

**2. Operator-witnessed attestation.** A trusted third-party operator verifies the OAuth flow and co-signs the attestation. Rejected because: (a) it requires a third party, violating the "protocol requires no operator" tenet; (b) it creates a centralized verification bottleneck; (c) the self-attestation model is sufficient for the identity-link use case (issuer == subject).

**3. Attestation class as separate `AttestationType` variant.** Adding `CryptographicIdentityLink` and `ReferenceIdentityLink` as new `AttestationType` variants. Rejected because: (a) `AttestationType` has stable numeric tags used in canonical hash computation — adding variants is a breaking protocol change; (b) the class is derivable from `evidence.method`, making a new variant redundant; (c) all existing code that handles `IdentityLink` attestations would need branching on two types instead of one.

### Security Analysis

**Self-attestation attack surface.** A malicious user could create a Class 1 attestation claiming to have performed OAuth verification without actually doing so. The attestation would have a valid DID signature. Defense: (a) the claim is "I control external account X" — the only use cases (shadow claiming, social graph import) independently verify the external identity, so a false claim has no effect; (b) the `subject_id` in the proof is meaningless without the external platform recognizing it, limiting social engineering; (c) stale attestations (past renewal interval) are degraded, forcing periodic re-verification.

**Reference attestation spoofing.** An attacker publishes a Reference attestation pointing to a URL containing another user's DID. Defense: Reference attestations carry zero trust until the consumer verifies the proof. The consumer checks that the DID in the external resource matches the attestation's `issuer`. The attacker cannot place the victim's DID in the victim's profile.

**Revocation replay.** An attacker intercepts a revoked attestation and strips `revocation_status: Revoked`. Defense: `revocation_status` is in the signature scope. Stripping it invalidates the signature. The original `Active` attestation still has a valid signature, but consumers check the revocation endpoint (§18.2.2) for the attestation ID.

### Acceptance Criteria

1. §3.5.0 defines Class 1 (Cryptographic) and Class 2 (Reference) with verification method mapping.
2. §3.5.1 defines the provider registry with 7 initial providers, platform value conventions, and creation flows for each class.
3. §3.5.2 wire format includes `revocation_status` in the signature scope (replaces separate `revocation` object).
4. §3.5.3 defines `ScpIdentityLinkAttestation` DID document service entry format with fragment naming convention and max-10 limit.
5. §3.5.4 defines class-specific verification procedures: Class 1 (signature-only), Class 2 (signature + proof fetch). Verification cache specified with 1-hour TTL.
6. §3.5.6 documents security properties: no PII, self-attestation scope limits, zero-trust for unverified Reference attestations, revocation replay prevention.
7. No new `AttestationType` variant introduced — class is derived from `evidence.method`.

**Migration note.** Changing the canonical signing bytes (replacing `revocation` with `revocation_status`) requires incrementing the domain separator from `SCP-IDENTITY-LINK-ATTESTATION-V1:` to `V2` per §9.5.1. No production attestations exist, so no backward compatibility is needed. The V2 separator is adopted in this spec change. The implementation PR uses V2 from the start.

---

## ADR-045: Fuzzing Infrastructure

**Status:** Decided
**Date:** April 2026
**PRs:** #1643 (initial 18 targets), #1644 (size-gate fixes), #1645 (CI workflows), #1652 (documentation follow-up)

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

**Four-tier target strategy.** 19 targets total across four tiers:

| Tier | Focus | Strategy | CI cadence |
|------|-------|----------|-----------|
| T1 — Wire Format Parsers | B1 relay wire, B2 post-MLS | Raw bytes + dict | Nightly, 15 min/target |
| T2 — Content Trust Boundaries | B2 inner content, B3 resolution | Raw bytes + dict | Nightly, 5 min/target |
| T3 — Invariant & Differential | Security properties, roundtrips | Mix raw + Arbitrary | Local / `workflow_dispatch` |
| T4 — Validation Depth & State | Paths requiring semantic validity | Arbitrary + real Ed25519 | Local / `workflow_dispatch` |

**Trust boundaries:**
- **B1:** Relay wire protocol — any unauthenticated TCP connection
- **B2:** Post-MLS decryption — authenticated but untrusted plaintext
- **B3:** Resolution/discovery — network adversary, DHT poisoning

**Raw bytes + dicts for T1/T2; Arbitrary only for T3/T4.**

For parser and deserializer targets (T1/T2), the fuzzer receives a raw `&[u8]` slice and a libFuzzer dictionary of field names and structural MessagePack bytes. This gives libFuzzer direct mutation-coverage feedback — every mutated byte in the input corresponds to a byte in the parser's input. Wrapping in an `Arbitrary` type would cause the fuzzer to mutate the `Arbitrary` binary encoding, not the parser input, breaking the coverage feedback loop.

`Arbitrary` is reserved for T3/T4 where raw bytes cannot reach the code path (e.g., merkle proof verification requires a structurally consistent proof, or differential targets require two semantically distinct inputs).

**Invariant catalog I1–I10 as governance artifact.** The security invariants are defined once in `fuzz/README.md` and `fuzz/.claude/CLAUDE.md`, and referenced by target. Any new target must map to at least one invariant. Adding, weakening, or removing an invariant requires human approval.

**CI cadence:**
- **Nightly** (`.github/workflows/fuzz.yml`, 03:00 UTC): T1 targets 15 min each, T2 targets 5 min each. All targets parallel. Corpus cached per-target with `actions/cache`; `cargo fuzz cmin` runs after each campaign.
- **Weekly deep-fuzz** (Saturday 00:00 UTC or `workflow_dispatch`): T1 targets only, 2 hours each, AddressSanitizer enabled (cargo-fuzz default) + UBSan on Saturdays.
- **Per-PR compilation check** (`cargo +nightly check --manifest-path fuzz/Cargo.toml`): catches API breakage without running the fuzzer. Runs in `.github/workflows/ci.yml` as `fuzz-build`.

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
| I1 | No panic on any untrusted input | All 19 targets |
| I2 | No unbounded allocation (bounded by protocol constants from ADR-043) | T1–T6, T10–T11, T14–T15 |
| I3 | Cryptographic signatures unforgeable (no structural bypass) | T16, T18 |
| I4 | Nonce replay prevention: accepted nonce never re-accepted | Future T20 (blocked: `InMemoryNonceTracker` uses `SystemClock`) |
| I5 | Epoch monotonicity: no rollback | Future T19 |
| I6 | Timestamps outside `[now - max_age, now + skew]` always rejected | T18 |
| I7 | Capabilities outside ceiling always rejected | T18 (wired but not exercised with non-empty chain) |
| I8 | Delegation chain verification terminates (depth ≤ 32) | T18 (empty `prf`, no chain walked) |
| I9 | Different `(context_id, sender_did)` → different AAD | T17 |
| I10 | Different `InnerEnvelopeParams` → different canonical hash | T16 |

I4 and I5 are blocked on clock injection into `InMemoryNonceTracker` (see `.docs/lessons/in-memory-nonce-tracker-system-clock.md`).

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
│   └── fuzz_validate_ucan_deep.rs       # T4/B3 — Arbitrary+real Ed25519, I1+I3+I6+I7+I8
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

1. `cargo +nightly fuzz list --fuzz-dir fuzz` lists all 19 targets.
2. `cargo +nightly check --manifest-path fuzz/Cargo.toml` succeeds on stable CI (nightly toolchain via `+nightly` flag).
3. Fuzz crate is NOT listed in root `Cargo.toml` `[workspace] members`.
4. `.github/workflows/fuzz.yml` runs T1 targets (15 min) and T2 targets (5 min) nightly; T1 targets with UBSan weekly.
5. `.github/workflows/ci.yml` includes a `fuzz-build` job that runs `cargo +nightly check --manifest-path fuzz/Cargo.toml`.
6. Security invariants I1–I10 are documented in `fuzz/README.md` with current coverage status.
7. `fuzz/.claude/CLAUDE.md` exists with agent-facing conventions: standalone crate caution, nightly requirement, raw-bytes-vs-Arbitrary guidance, dictionary format, invariant catalog.
8. All T1/T2 targets use raw bytes (`|data: &[u8]|`). All T3/T4 targets that require semantic structure use `Arbitrary`.
9. `fuzz/Cargo.lock` is committed (separate from root `Cargo.lock`).
10. Crash workflow documented: reproduce → minimize (`fuzz tmin`) → file issue → add regression `#[test]`.
