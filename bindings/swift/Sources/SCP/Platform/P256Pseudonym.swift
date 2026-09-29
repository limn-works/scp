// P256Pseudonym.swift — §9.10.4 P-256 pseudonym keys for AppleKeyCustody.
//
// The two steps a host must not re-implement run in Rust (scp-crypto) through
// the UniFFI exports: the FIPS 186-5 A.2.1 reduction of a context seed to the
// pseudonym scalar (constant-time), and ECDSA signing with RFC 6979
// deterministic nonces and low-s output (§9.5). CryptoKit's P-256 signer draws
// a random nonce, which §9.5 forbids for software signers. The key is stored as
// its raw 32-byte big-endian scalar; no Swift code normalizes s.

import Foundation

enum P256Pseudonym {
    /// The 32-byte pseudonym scalar of a 32-byte §9.10.4 context seed; the
    /// `SCP-PSEUDONYM-P256-V1` label is fixed inside the Rust helper.
    static func scalar(contextSeed: Data) throws -> Data {
        try p256PseudonymScalar(contextSeed: contextSeed)
    }

    /// The 33-byte compressed public point of a pseudonym scalar.
    static func publicKey(scalar: Data) throws -> Data {
        try p256PublicKey(scalar: scalar)
    }

    /// Signs a 32-byte digest without hashing it again: RFC 6979 nonce,
    /// 64-byte `r || s` with low s (§9.5).
    ///
    /// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7005` if
    ///   `digest` or `scalar` is not 32 bytes, and ``ScpError/Crypto(msg:code:)``
    ///   with `SCP-CRYPTO-4001` if the scalar is out of range: the Rust
    ///   helper's checks and codes, which every binding shares.
    static func signPrehash(scalar: Data, digest: Data) throws -> Data {
        try p256SignPrehashRfc6979(scalar: scalar, digest: digest)
    }
}
