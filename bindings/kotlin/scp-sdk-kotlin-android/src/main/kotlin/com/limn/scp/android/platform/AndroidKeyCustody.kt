// AndroidKeyCustody.kt — KeyCustodyProvider implementation for Android (ADR-027)
//
// Ed25519 key custody using Android Keystore (TEE-backed) on API 33+ and Bouncy Castle
// software fallback on API 26-32. X25519 wrapping keys are always software-managed via
// Bouncy Castle. StrongBox is explicitly NOT used due to 10-100x latency penalty that
// is incompatible with SCP's frequent signing operations.
//
// Private keys never cross the custody boundary — all signing and DH operations happen
// inside this class. The Rust engine calls through UniFFI callback interfaces with data
// to sign and receives signatures back. Raw private key bytes stay inside the Kotlin adapter.
//
// Provenance: ADR-027 (Android Platform Adapter), ADR-006 (Platform Abstraction Layer),
// ADR-025 (Apple Platform Adapter — parallel reference), section 9.12 (Compromise Recovery),
// section 9.15 (Key Destruction Verification).

package com.limn.scp.android.platform

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.NamedParameterSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.prng.FixedSecureRandom
import java.security.SecureRandom

/**
 * Android Keystore-backed key custody provider for SCP Ed25519 and X25519 keys.
 *
 * Implements the [KeyCustodyProvider] interface (mirroring the Rust `KeyCustody` trait
 * from `scp-platform/src/traits.rs`). This class is injected into the Rust engine via
 * the UniFFI callback interface at `SCP.create()` time; all signing and key-agreement
 * operations are dispatched from Rust through the UniFFI boundary into this class.
 *
 * ## Key storage strategy
 *
 * - **Ed25519 on API 33+ (Android 13+):** Android Keystore natively supports `EdDSA`
 *   with `Ed25519` parameter spec. Keys are TEE-backed — the private key bytes never
 *   leave the Trusted Execution Environment. This is a stronger security posture than
 *   Apple's Secure Enclave (which only supports P-256). [CustodyType.HARDWARE] is reported.
 *
 * - **Ed25519 on API 26-32:** `EdDSA` is not available in Android Keystore on these API
 *   levels. Bouncy Castle provides software Ed25519. Keys are stored in [softwareKeys]
 *   in-memory. [CustodyType.SOFTWARE] is reported.
 *
 * - **X25519 (all API levels):** X25519 key agreement is not supported by Android Keystore
 *   at any API level. All X25519 wrapping keys are software-managed via Bouncy Castle,
 *   stored in [softwareKeys]. [CustodyType.SOFTWARE] is reported.
 *
 * ## TEE vs StrongBox
 *
 * TEE is the default and only option. StrongBox is NOT used. StrongBox operations are
 * 10-100x slower than TEE — latency that would visibly degrade SCP protocol participation
 * where every send operation requires a signature. See ADR-027 for the full rationale.
 *
 * ## Thread safety
 *
 * Android Keystore operations are thread-safe. The [softwareKeys] map is a
 * [ConcurrentHashMap] for safe concurrent access from multiple UniFFI callback threads.
 *
 * ## Compromise recovery
 *
 * Key rotation follows the 6-step recovery process from section 9.12:
 *   1. Generate new identity keypair via [generateKeypair]
 *   2. Publish new DID document with updated key material
 *   3. Re-join affected contexts with new identity
 *   4. Revoke UCAN delegations from compromised key
 *   5. Request admin role re-assignment in governed contexts
 *   6. Destroy compromised key via [destroyKey]
 *
 * See ADR-027 for the full Android platform adapter design.
 */
class AndroidKeyCustody : KeyCustodyProvider {

    // -----------------------------------------------------------------------
    // Software key storage — used for API 26-32 Ed25519 and all X25519 keys
    // -----------------------------------------------------------------------

    /**
     * In-memory storage for software-managed keys (Bouncy Castle).
     *
     * Key: UUID string (same as [KeyHandle.id]).
     * Value: Bouncy Castle asymmetric key pair (Ed25519 or X25519).
     *
     * This map is only used for keys that cannot be stored in Android Keystore:
     * - Ed25519 keys on API 26-32 (no Keystore EdDSA support)
     * - X25519 keys on all API levels (no Keystore X25519 support)
     */
    internal val softwareKeys = ConcurrentHashMap<String, AsymmetricCipherKeyPair>()

    /**
     * Tracks the [KeyType] for each software-managed key.
     *
     * Used to enforce type safety in [sign] and [dhAgree] operations.
     */
    private val softwareKeyTypes = ConcurrentHashMap<String, KeyType>()

    // -----------------------------------------------------------------------
    // KeyCustodyProvider implementation
    // -----------------------------------------------------------------------

    /**
     * Generates a new keypair of the specified type.
     *
     * Routing logic:
     * - [KeyType.ED25519] + API 33+: Android Keystore TEE-backed via `EdDSA` algorithm.
     * - [KeyType.ED25519] + API 26-32: Bouncy Castle software fallback.
     * - [KeyType.X25519]: Always Bouncy Castle software (Keystore has no X25519 support).
     *
     * @param keyType The type of key to generate.
     * @return [KeyHandle] with [CustodyType.HARDWARE] for Keystore keys or
     *   [CustodyType.SOFTWARE] for Bouncy Castle keys.
     */
    override fun generateKeypair(keyType: KeyType): KeyHandle {
        val keyId = UUID.randomUUID().toString()
        return when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && keyType == KeyType.ED25519 -> {
                generateKeystoreEd25519(keyId)
            }
            keyType == KeyType.ED25519 -> {
                generateSoftwareEd25519(keyId)
            }
            else -> {
                // X25519 wrapping keys are always software-managed
                generateSoftwareX25519(keyId)
            }
        }
    }

    /**
     * Signs [data] with the Ed25519 key identified by [keyHandle].
     *
     * For hardware-backed keys ([CustodyType.HARDWARE]): the signing operation happens
     * entirely inside the TEE via Android Keystore's `EdDSA` signature provider. The
     * private key bytes never leave hardware.
     *
     * For software-backed keys ([CustodyType.SOFTWARE]): Bouncy Castle's [Ed25519Signer]
     * performs the signing with key material from [softwareKeys].
     *
     * @param keyHandle Handle returned by [generateKeypair] for an Ed25519 key.
     * @param data The bytes to sign.
     * @return 64-byte Ed25519 signature.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the key is not Ed25519.
     */
    override fun sign(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            signWithKeystore(keyHandle, data)
        } else {
            signWithSoftware(keyHandle, data)
        }
    }

    /**
     * Returns the raw 32-byte public key for [keyHandle].
     *
     * For hardware-backed Ed25519 keys: extracts the raw 32-byte Ed25519 public key
     * from the X.509-encoded certificate in Android Keystore. The X.509 SubjectPublicKeyInfo
     * encoding for Ed25519 has a 12-byte header; the raw key is the last 32 bytes.
     *
     * For software-backed keys: returns the Bouncy Castle public key parameters directly.
     *
     * @param keyHandle Handle returned by [generateKeypair] or [derivePseudonym].
     * @return Raw 32-byte public key bytes.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the key is not found.
     */
    override fun publicKey(keyHandle: KeyHandle): ByteArray {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            publicKeyFromKeystore(keyHandle)
        } else {
            publicKeyFromSoftware(keyHandle)
        }
    }

    /**
     * Destroys the key material associated with [keyHandle].
     *
     * For hardware-backed keys: deletes the entry from Android Keystore and performs
     * a re-fetch to confirm deletion (section 9.15 key destruction verification).
     *
     * For software-backed keys: removes the entry from the [softwareKeys] map.
     *
     * After this call, all subsequent operations with the same handle will throw
     * [ScpException] with code `SCP-CRYPTO-4001`.
     *
     * @param keyHandle Handle to destroy.
     * @return [DestructionAttestation] confirming the destruction method and verification.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the handle is already invalid.
     * @throws ScpException with code `SCP-CRYPTO-4004` if destruction cannot be confirmed.
     */
    override fun destroyKey(keyHandle: KeyHandle): DestructionAttestation {
        return if (keyHandle.custodyType == CustodyType.HARDWARE) {
            destroyKeystoreKey(keyHandle)
        } else {
            destroySoftwareKey(keyHandle)
        }
    }

    /**
     * Performs X25519 Diffie-Hellman key agreement.
     *
     * X25519 wrapping keys are always software-managed (Bouncy Castle), as Android Keystore
     * does not support X25519. The private key never leaves the [AndroidKeyCustody] boundary
     * -- the scalar multiplication happens inside this method.
     *
     * @param keyHandle Handle to an X25519 key from [generateKeypair].
     * @param peerPublic 32-byte X25519 public key of the peer.
     * @return 32-byte X25519 shared secret.
     * @throws ScpException with code `SCP-CRYPTO-4002` if the X25519 key is not found.
     */
    override fun dhAgree(keyHandle: KeyHandle, peerPublic: ByteArray): ByteArray {
        if (peerPublic.size != 32) {
            throw ScpException(
                "peerPublic must be exactly 32 bytes (X25519 public key), got ${peerPublic.size}",
                "SCP-CRYPTO-4003",
            )
        }

        // Enforce X25519 type — passing an Ed25519 handle would cause a
        // Bouncy Castle ClassCastException when interpreting Ed25519PrivateKeyParameters
        // as X25519PrivateKeyParameters.
        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.X25519) {
            throw ScpException(
                "dhAgree requires an X25519 key; handle '${keyHandle.id}' is Ed25519",
                "SCP-CRYPTO-4003",
            )
        }

        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "X25519 key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4002",
            )
        val agreement = X25519Agreement()
        agreement.init(keyPair.private)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(
            X25519PublicKeyParameters(peerPublic, 0),
            secret,
            0,
        )
        return secret
    }

    /**
     * Derives a deterministic, context-scoped Ed25519 pseudonym keypair.
     *
     * Algorithm (identical across all `KeyCustody` implementations per ADR-006):
     *   1. Retrieve the public key material for [keyHandle] (uses public key as HMAC
     *      key material for hardware-backed keys where private bytes are inaccessible).
     *   2. Compute `seed = HMAC-SHA256(key_material, contextId || "scp-pseudonym")`.
     *   3. Derive an Ed25519 keypair from the first 32 bytes of `seed` using
     *      [FixedSecureRandom] as the entropy source for deterministic keygen.
     *   4. Store the derived keypair in [softwareKeys] under a fresh UUID.
     *   5. Return a [PseudonymKeyHandle] with [CustodyType.SOFTWARE].
     *
     * The derivation is deterministic: the same `keyHandle` + `contextId` pair always
     * produces the same pseudonym public key (given the same underlying identity key
     * material). However, each call creates a new UUID handle in [softwareKeys] —
     * callers should manage handle lifecycle.
     *
     * @param keyHandle Handle to the identity Ed25519 key (source for derivation).
     * @param contextId Raw context ID bytes.
     * @return [PseudonymKeyHandle] referencing the derived signing key.
     * @throws ScpException with code `SCP-CRYPTO-4001` if the identity key is not found.
     * @throws ScpException with code `SCP-CRYPTO-4003` if the identity key is not Ed25519.
     */
    override fun derivePseudonym(keyHandle: KeyHandle, contextId: ByteArray): PseudonymKeyHandle {
        // Enforce Ed25519 type for the source identity key
        if (keyHandle.custodyType == CustodyType.SOFTWARE) {
            val storedType = softwareKeyTypes[keyHandle.id]
            if (storedType != null && storedType != KeyType.ED25519) {
                throw ScpException(
                    "derivePseudonym requires an Ed25519 key; handle '${keyHandle.id}' is X25519",
                    "SCP-CRYPTO-4003",
                )
            }
        }

        // Use public key as HMAC key material — works for both hardware and software keys.
        // For hardware-backed keys, private bytes are inaccessible (inside TEE).
        val keyMaterial = publicKey(keyHandle)

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(keyMaterial, "HmacSHA256"))
        mac.update(contextId)
        mac.update("scp-pseudonym".toByteArray(Charsets.UTF_8))
        val seed = mac.doFinal()

        // Derive Ed25519 keypair from seed using FixedSecureRandom for determinism.
        val pseudonymKeypair = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(FixedSecureRandom(seed)))
        }.generateKeyPair()

        val pseudonymId = UUID.randomUUID().toString()
        softwareKeys[pseudonymId] = pseudonymKeypair
        softwareKeyTypes[pseudonymId] = KeyType.ED25519

        return PseudonymKeyHandle(
            id = pseudonymId,
            custodyType = CustodyType.SOFTWARE,
        )
    }

    // -----------------------------------------------------------------------
    // Private: Keystore Ed25519 operations (API 33+)
    // -----------------------------------------------------------------------

    /**
     * Generates a TEE-backed Ed25519 keypair using Android Keystore.
     *
     * Uses the `EdDSA` algorithm with `Ed25519` parameter spec, available on API 33+.
     * The private key is generated inside the TEE and never leaves it. Signing operations
     * are performed by the TEE directly.
     *
     * StrongBox is NOT requested (`setIsStrongBoxBacked` is not called) per ADR-027:
     * StrongBox operations are 10-100x slower than TEE and would degrade SCP protocol
     * participation.
     *
     * `setUserAuthenticationRequired(false)` allows background processing — SCP needs
     * to sign messages during relay connections and message processing without user
     * interaction.
     */
    private fun generateKeystoreEd25519(keyId: String): KeyHandle {
        val keystoreAlias = "scp.key.$keyId"
        val spec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
            .setDigests() // EdDSA does not require explicit digest
            .setUserAuthenticationRequired(false) // SCP requires background processing
            .build()
        val keyPairGenerator = KeyPairGenerator.getInstance("EdDSA", "AndroidKeyStore")
        keyPairGenerator.initialize(spec)
        keyPairGenerator.generateKeyPair()
        return KeyHandle(id = keyId, custodyType = CustodyType.HARDWARE)
    }

    /**
     * Signs data using a TEE-backed Ed25519 key in Android Keystore.
     *
     * The signing operation happens entirely inside the TEE — the private key bytes
     * never leave hardware.
     */
    private fun signWithKeystore(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(keystoreAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )
        return Signature.getInstance("EdDSA").apply {
            initSign(entry.privateKey)
            update(data)
        }.sign()
    }

    /**
     * Extracts the raw 32-byte Ed25519 public key from Android Keystore.
     *
     * Android Keystore returns the public key in X.509 SubjectPublicKeyInfo encoding.
     * For Ed25519, the raw 32-byte key is the last 32 bytes of the encoded form
     * (the first 12 bytes are the ASN.1 header: SEQUENCE + OID for Ed25519).
     */
    private fun publicKeyFromKeystore(keyHandle: KeyHandle): ByteArray {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(keystoreAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )
        val encoded = entry.certificate.publicKey.encoded
        // X.509 SubjectPublicKeyInfo for Ed25519 is 44 bytes: 12-byte header + 32-byte key
        return encoded.takeLast(RAW_ED25519_KEY_SIZE).toByteArray()
    }

    /**
     * Deletes a TEE-backed key from Android Keystore and verifies deletion.
     *
     * Performs the key destruction verification required by section 9.15:
     *   1. Delete the Keystore entry.
     *   2. Re-fetch to confirm the alias no longer exists.
     *   3. Return [DestructionAttestation] with [DestructionMethod.HARDWARE] and `confirmed = true`.
     *
     * Returns [DestructionMethod.HARDWARE] because the key material resided in the TEE
     * and was destroyed by the hardware security module.
     */
    private fun destroyKeystoreKey(keyHandle: KeyHandle): DestructionAttestation {
        val keystoreAlias = "scp.key.${keyHandle.id}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        if (!keyStore.containsAlias(keystoreAlias)) {
            throw ScpException(
                "Key not found in Keystore: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )
        }

        keyStore.deleteEntry(keystoreAlias)

        // Verify deletion per section 9.15 — re-fetch must confirm absence
        if (keyStore.containsAlias(keystoreAlias)) {
            throw ScpException(
                "Key destruction failed: entry persisted after deletion for ${keyHandle.id}",
                "SCP-CRYPTO-4004",
            )
        }

        return DestructionAttestation(
            method = DestructionMethod.HARDWARE,
            confirmed = true,
        )
    }

    // -----------------------------------------------------------------------
    // Private: Software key operations (Bouncy Castle)
    // -----------------------------------------------------------------------

    /**
     * Generates a software-backed Ed25519 keypair using Bouncy Castle.
     *
     * Used as fallback on API 26-32 where Android Keystore does not support EdDSA.
     * The key pair is stored in [softwareKeys] and tracked in [softwareKeyTypes].
     */
    private fun generateSoftwareEd25519(keyId: String): KeyHandle {
        val keyPair = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair()
        softwareKeys[keyId] = keyPair
        softwareKeyTypes[keyId] = KeyType.ED25519
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    /**
     * Generates a software-backed X25519 keypair using Bouncy Castle.
     *
     * X25519 wrapping keys are always software-managed because Android Keystore
     * does not support X25519 at any API level.
     */
    private fun generateSoftwareX25519(keyId: String): KeyHandle {
        val keyPair = X25519KeyPairGenerator().apply {
            init(X25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair()
        softwareKeys[keyId] = keyPair
        softwareKeyTypes[keyId] = KeyType.X25519
        return KeyHandle(id = keyId, custodyType = CustodyType.SOFTWARE)
    }

    /**
     * Signs data using a software-backed Ed25519 key from Bouncy Castle.
     */
    private fun signWithSoftware(keyHandle: KeyHandle, data: ByteArray): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )

        // Enforce Ed25519 type
        val storedType = softwareKeyTypes[keyHandle.id]
        if (storedType != null && storedType != KeyType.ED25519) {
            throw ScpException(
                "sign requires an Ed25519 key; handle '${keyHandle.id}' is X25519",
                "SCP-CRYPTO-4003",
            )
        }

        val signer = Ed25519Signer()
        signer.init(true, keyPair.private)
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /**
     * Returns the raw 32-byte public key from a software-backed key.
     */
    private fun publicKeyFromSoftware(keyHandle: KeyHandle): ByteArray {
        val keyPair = softwareKeys[keyHandle.id]
            ?: throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )

        val storedType = softwareKeyTypes[keyHandle.id]
        return when (storedType) {
            KeyType.X25519 -> {
                val pubKey = keyPair.public as org.bouncycastle.crypto.params.X25519PublicKeyParameters
                pubKey.encoded
            }
            else -> {
                // Ed25519 (default for pseudonym keys where type may not be tracked)
                val pubKey = keyPair.public as Ed25519PublicKeyParameters
                pubKey.encoded
            }
        }
    }

    /**
     * Destroys a software-backed key by removing it from the in-memory map.
     *
     * Returns [DestructionMethod.SOFTWARE_ONLY] because the key material was stored
     * in software (Bouncy Castle in-memory) without hardware protection.
     */
    private fun destroySoftwareKey(keyHandle: KeyHandle): DestructionAttestation {
        val removed = softwareKeys.remove(keyHandle.id)
        softwareKeyTypes.remove(keyHandle.id)

        if (removed == null) {
            throw ScpException(
                "Key not found: ${keyHandle.id}",
                "SCP-CRYPTO-4001",
            )
        }

        // Verify removal — key should no longer be in the map
        if (softwareKeys.containsKey(keyHandle.id)) {
            throw ScpException(
                "Key destruction failed: entry persisted after removal for ${keyHandle.id}",
                "SCP-CRYPTO-4004",
            )
        }

        return DestructionAttestation(
            method = DestructionMethod.SOFTWARE_ONLY,
            confirmed = true,
        )
    }

    companion object {
        /** Raw Ed25519 public key size in bytes. */
        private const val RAW_ED25519_KEY_SIZE = 32
    }
}
