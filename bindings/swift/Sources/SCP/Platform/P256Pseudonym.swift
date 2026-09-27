// P256Pseudonym.swift — §9.10.4.A P-256 pseudonym arithmetic for AppleKeyCustody.
//
// CryptoKit provides HKDF, HMAC and P-256, but not the two pieces of 256-bit
// integer arithmetic the recipe needs: the FIPS 186-5 A.2.1 reduction of a
// 48-byte HKDF output to a scalar, and the low-s normalization of an ECDSA
// signature (§9.5.1). Both are done here on little-endian UInt64 limbs. The
// scalar and the signature are secret-independent in shape, but this code is
// not constant-time; the reduction runs once per derivation.

import CryptoKit
import Foundation

enum P256Pseudonym {
    /// HKDF-Expand label that turns a context seed into the pseudonym scalar.
    static let scalarLabel = "SCP-PSEUDONYM-P256-V1"

    /// The P-256 group order n, little-endian limbs.
    private static let order: [UInt64] = [
        0xF3B9_CAC2_FC63_2551, 0xBCE6_FAAD_A717_9E84, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_0000_0000
    ]
    /// (n - 1) / 2, the largest low-s value.
    private static let halfOrder: [UInt64] = [
        0x79DC_E561_7E31_92A8, 0xDE73_7D56_D38B_CF42, 0x7FFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_8000_0000
    ]

    /// FIPS 186-5 A.2.1 seed-to-scalar (§9.10.4): the 48-byte
    /// HKDF-Expand-SHA256(prk = seed, info = label) read big-endian,
    /// reduced mod (n - 1), plus 1. Returns the 32-byte big-endian scalar.
    static func seedToScalar(label: String, seed: Data) -> Data {
        let wide = HKDF<SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: seed),
            info: Data(label.utf8),
            outputByteCount: 48
        )
        let wideBytes = wide.withUnsafeBytes { [UInt8]($0) }
        var modulus = order
        modulus[0] -= 1
        // Shift-subtract reduction, one bit at a time from the most
        // significant. The remainder stays below 2 * (n - 1) < 2^257, so five
        // limbs hold it.
        var rem: [UInt64] = [0, 0, 0, 0, 0]
        let mod5 = modulus + [0]
        for byte in wideBytes {
            for bit in (0 ..< 8).reversed() {
                shiftLeftOne(&rem, carryIn: UInt64((byte >> UInt8(bit)) & 1))
                if compare(rem, mod5) >= 0 {
                    subtract(&rem, mod5)
                }
            }
        }
        // rem < n - 1, so rem + 1 < n fits in four limbs.
        var scalar = Array(rem.prefix(4))
        addOne(&scalar)
        return bigEndianBytes(scalar)
    }

    /// The pseudonym private key of a 32-byte context seed.
    static func privateKey(contextSeed: Data) throws -> P256.Signing.PrivateKey {
        var scalar = seedToScalar(label: scalarLabel, seed: contextSeed)
        defer { scalar.resetBytes(in: 0 ..< scalar.count) }
        return try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }

    /// Signs a 32-byte digest without hashing it again and returns the 64-byte
    /// `r || s` with s normalized to the low half (§9.5.1).
    static func signPrehash(key: P256.Signing.PrivateKey, digest: Data) throws -> Data {
        guard digest.count == 32 else {
            throw PlatformError.custodyError(
                "P-256 pseudonym keys sign only a 32-byte digest, got \(digest.count) bytes"
            )
        }
        let raw = try key.signature(for: PrehashDigest(bytes: [UInt8](digest))).rawRepresentation
        return normalizeLowS(raw)
    }

    /// Returns `signature` (64-byte `r || s`) with s replaced by n - s when s
    /// is above (n - 1) / 2.
    static func normalizeLowS(_ signature: Data) -> Data {
        precondition(signature.count == 64, "P-256 signature must be 64 bytes")
        let sValue = limbs(bigEndian: [UInt8](signature.suffix(32)))
        guard compare(sValue, halfOrder) > 0 else { return signature }
        var negated = order
        subtract(&negated, sValue)
        return signature.prefix(32) + bigEndianBytes(negated)
    }

    // MARK: - Limb arithmetic (little-endian UInt64)

    private static func compare(_ lhs: [UInt64], _ rhs: [UInt64]) -> Int {
        for idx in (0 ..< lhs.count).reversed() where lhs[idx] != rhs[idx] {
            return lhs[idx] > rhs[idx] ? 1 : -1
        }
        return 0
    }

    private static func subtract(_ lhs: inout [UInt64], _ rhs: [UInt64]) {
        var borrow: UInt64 = 0
        for idx in 0 ..< lhs.count {
            let (diff1, over1) = lhs[idx].subtractingReportingOverflow(rhs[idx])
            let (diff2, over2) = diff1.subtractingReportingOverflow(borrow)
            lhs[idx] = diff2
            borrow = (over1 || over2) ? 1 : 0
        }
    }

    private static func shiftLeftOne(_ lhs: inout [UInt64], carryIn: UInt64) {
        var carry = carryIn
        for idx in 0 ..< lhs.count {
            let next = lhs[idx] >> 63
            lhs[idx] = (lhs[idx] << 1) | carry
            carry = next
        }
    }

    private static func addOne(_ lhs: inout [UInt64]) {
        for idx in 0 ..< lhs.count {
            let (sum, overflow) = lhs[idx].addingReportingOverflow(1)
            lhs[idx] = sum
            if !overflow {
                return
            }
        }
    }

    private static func limbs(bigEndian bytes: [UInt8]) -> [UInt64] {
        (0 ..< 4).map { limb in
            let start = 32 - (limb + 1) * 8
            return bytes[start ..< start + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
    }

    private static func bigEndianBytes(_ limbs: [UInt64]) -> Data {
        var out = Data(capacity: 32)
        for limb in limbs.reversed() {
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: limb >> UInt64(shift)))
            }
        }
        return out
    }
}

/// A caller-supplied 32-byte digest, so CryptoKit signs it without hashing it
/// again (the §9.5.1 prehash form).
private struct PrehashDigest: Digest {
    static let byteCount = 32

    let bytes: [UInt8]

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> IndexingIterator<[UInt8]> {
        bytes.makeIterator()
    }

    var description: String {
        "PrehashDigest"
    }
}
