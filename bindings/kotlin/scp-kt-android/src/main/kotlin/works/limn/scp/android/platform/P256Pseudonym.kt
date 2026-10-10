// P256Pseudonym.kt — §9.10.4 P-256 pseudonym points for AndroidKeyCustody.
//
// Provenance: spec §9.10.4 (seed-to-scalar), §9.10.4.A (pseudonym secret). Both
// derivations are the Rust `scp-crypto` ones, reached through the `scp-ffi-uniffi`
// exports in `p256_host.rs`, so this host re-implements neither. A pseudonym is its
// public point only: no scalar reaches this host.

package works.limn.scp.android.platform

import uniffi.scp.p256PseudonymPoint
import uniffi.scp.p256SoftwarePseudonymPoint
import uniffi.scp.ScpException as BridgeException

/**
 * The 33-byte SEC1 compressed pseudonym point of a context seed or of a software
 * identity seed (§9.10.4, §9.10.4.A).
 */
internal object P256Pseudonym {
    /**
     * The point of a 32-byte §9.10.4 context seed, which is wiped afterwards. The
     * hardware path computes the seed inside Keystore.
     *
     * @throws ScpException with code `SCP-VALID-7005` if [contextSeed] is not 32 bytes.
     */
    fun pointFromSeed(contextSeed: ByteArray): ByteArray = try {
        bridged { p256PseudonymPoint(contextSeed) }
    } finally {
        contextSeed.fill(0)
    }

    /**
     * The point derived from a software identity's 32-byte Ed25519 seed [ikm]
     * (§9.10.4 native interim): v1 when [epoch] is `null`, otherwise v2 at [epoch],
     * taken as an unsigned 64-bit value. The caller wipes [ikm].
     *
     * @throws ScpException with code `SCP-VALID-7005` if [ikm] is not 32 bytes.
     */
    fun softwarePoint(ikm: ByteArray, contextId: ByteArray, epoch: Long?): ByteArray =
        bridged { p256SoftwarePseudonymPoint(ikm, contextId, epoch?.toULong()) }

    /** Maps a bridge error to this package's [ScpException], keeping its code. */
    private inline fun <T> bridged(call: () -> T): T = try {
        call()
    } catch (e: BridgeException.Validation) {
        throw ScpException(e.msg, e.code, e)
    } catch (e: BridgeException.Crypto) {
        throw ScpException(e.msg, e.code, e)
    }
}
