//! Authenticated convergent committer timestamp, carried in the MLS
//! `FramedContent.authenticated_data` (AAD) (ADR-057).
//!
//! # Why this module exists
//!
//! Every SCP context maps to one MLS group whose members each maintain a
//! §9.9.3 Merkle event log. A **membership** leaf (`MemberJoined`) is stamped by
//! the committer of an add-Commit and mirrored, byte-for-byte, by every existing
//! member — so for the logs to converge, the committer-assigned timestamp on that
//! leaf must be identical across all members. The committer mints it once and
//! every receiver **adopts the same value verbatim**, rather than each reading
//! its own local clock. On the native path that value rides inside a signed SCP
//! envelope (`created_at`). The in-browser participant driver (ADR-057) had no
//! equivalent: it transported the timestamp as a **loose, unauthenticated `u64`**
//! beside the ciphertext, so a hostile relay (the protocol's "dumb pipe") could
//! deliver a valid Commit with a **forged** timestamp and fork the receiver's
//! Merkle root from the honest committer's.
//!
//! # The fix: bind it into the MLS AAD
//!
//! This module encodes the committer timestamp into a fixed 13-byte AAD blob and
//! the driver sets it on the group immediately before the one add/commit call
//! ([`crate::group::add_member_with_convergent_timestamp`]). openmls folds the
//! AAD into `FramedContent.authenticated_data`, which is:
//!
//! - covered by the **committer's leaf signature** over the `FramedContentTBS`
//!   (RFC 9420 §6.1) — so no member other than the committer can author a frame
//!   carrying it, and
//! - covered by the **`PrivateMessage` AEAD tag** under the SCP `PURE_CIPHERTEXT`
//!   wire policy — so a relay that flips the timestamp breaks the tag and the
//!   frame is rejected at decrypt.
//!
//! A receiver recovers the timestamp from [`openmls`'s verified
//! `ProcessedMessage::aad()`] — i.e. *after* signature + AEAD verification — so
//! the value it stamps on its mirrored membership leaf is authenticated, not
//! trusted on the wire. The loose transported parameter is therefore **deleted,
//! not validated**.
//!
//! # Adopted verbatim — no receiver-side clock verdict
//!
//! The membership-leaf value is **adopted verbatim** by every receiver: it is
//! convergent *by construction* because (a) MLS imposes a single total order on
//! commits and (b) the AAD binding fixes exactly one authenticated value per
//! Commit that every honest receiver reads identically. There is **no**
//! receiver-side plausibility window and **no** monotonic floor: a per-receiver
//! clock verdict would itself be a §9.9.3 violation — two honest members whose
//! clocks straddle the same authenticated timestamp would reach opposite
//! accept/reject verdicts and diverge (and, on an add-Commit, partition on the
//! epoch advance). The residual — a *committer* that binds an implausible value —
//! is the pre-existing MLS insider-equivocation class (a malicious committer can
//! already fork receivers by sending different commits to different members) and
//! is bounded only once per-leaf committer signatures land (ADR-057 §23.13), not
//! by re-adjudicating the value here.
//!
//! # AAD is authenticated, not confidential
//!
//! `authenticated_data` is transmitted in the clear (it is *authenticated*
//! additional data, not encrypted). The committer timestamp is not secret — it
//! is a public event-log leaf field — so this is correct. The AAD carries
//! **only** the timestamp; nothing secret is placed here.

use crate::error::MlsError;

/// The 4-byte magic prefix identifying a convergent-timestamp AAD blob (`SCPT`).
///
/// Distinguishes an SCP convergent-timestamp AAD from an empty AAD (no timestamp
/// bound) or any other application-set AAD, so a receiver fails closed rather
/// than misreading foreign bytes as a timestamp.
pub const CONVERGENT_TIMESTAMP_AAD_MAGIC: [u8; 4] = *b"SCPT";

/// The AAD wire-format version. Bump only on an incompatible layout change; a
/// receiver rejects any version it does not recognize (fail-closed).
pub const CONVERGENT_TIMESTAMP_AAD_VERSION: u8 = 1;

/// The exact byte length of a convergent-timestamp AAD blob:
/// 4 (magic) + 1 (version) + 8 (`u64` big-endian timestamp) = 13.
pub const CONVERGENT_TIMESTAMP_AAD_LEN: usize = 13;

/// Encodes a committer timestamp (Unix seconds) into the fixed 13-byte AAD blob
/// `b"SCPT" || version(1) || timestamp_secs(u64 BE)`.
///
/// Big-endian, fixed-width, no `usize` — target-independent so a native and a
/// wasm32 member produce byte-identical AAD for the same timestamp (ADR-057
/// cross-target determinism).
#[must_use]
pub fn encode_convergent_timestamp_aad(timestamp_secs: u64) -> [u8; CONVERGENT_TIMESTAMP_AAD_LEN] {
    let mut out = [0u8; CONVERGENT_TIMESTAMP_AAD_LEN];
    out[0..4].copy_from_slice(&CONVERGENT_TIMESTAMP_AAD_MAGIC);
    out[4] = CONVERGENT_TIMESTAMP_AAD_VERSION;
    out[5..13].copy_from_slice(&timestamp_secs.to_be_bytes());
    out
}

/// Decodes a committer timestamp from a verified AAD blob, failing closed on any
/// deviation from the exact 13-byte `SCPT`/version-1 layout.
///
/// # Errors
///
/// - [`MlsError::ConvergentTimestampMissing`] if `aad` is **empty** — a frame
///   carrying no convergent timestamp at all (an old-path or forged message with
///   no `set_aad`).
/// - [`MlsError::ConvergentTimestampMalformed`] if `aad` is the wrong length, has
///   the wrong magic, or carries an unrecognized version. These are all
///   fail-closed: a receiver never guesses a timestamp from malformed bytes.
pub fn decode_convergent_timestamp_aad(aad: &[u8]) -> Result<u64, MlsError> {
    if aad.is_empty() {
        return Err(MlsError::ConvergentTimestampMissing);
    }
    if aad.len() != CONVERGENT_TIMESTAMP_AAD_LEN {
        return Err(MlsError::ConvergentTimestampMalformed(format!(
            "expected {CONVERGENT_TIMESTAMP_AAD_LEN} bytes, got {}",
            aad.len()
        )));
    }
    if aad[0..4] != CONVERGENT_TIMESTAMP_AAD_MAGIC {
        return Err(MlsError::ConvergentTimestampMalformed(
            "bad magic (not an SCP convergent-timestamp AAD)".to_owned(),
        ));
    }
    if aad[4] != CONVERGENT_TIMESTAMP_AAD_VERSION {
        return Err(MlsError::ConvergentTimestampMalformed(format!(
            "unsupported version {}, expected {CONVERGENT_TIMESTAMP_AAD_VERSION}",
            aad[4]
        )));
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&aad[5..13]);
    Ok(u64::from_be_bytes(ts_bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_exactly_thirteen_bytes_with_magic_version_and_be_timestamp() {
        let aad = encode_convergent_timestamp_aad(0x0102_0304_0506_0708);
        assert_eq!(aad.len(), CONVERGENT_TIMESTAMP_AAD_LEN);
        assert_eq!(&aad[0..4], b"SCPT");
        assert_eq!(aad[4], CONVERGENT_TIMESTAMP_AAD_VERSION);
        assert_eq!(
            &aad[5..13],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        for ts in [0u64, 1, 1_700_000_000, u64::MAX] {
            let aad = encode_convergent_timestamp_aad(ts);
            assert_eq!(decode_convergent_timestamp_aad(&aad).unwrap(), ts);
        }
    }

    #[test]
    fn decode_empty_is_missing() {
        assert!(matches!(
            decode_convergent_timestamp_aad(&[]),
            Err(MlsError::ConvergentTimestampMissing)
        ));
    }

    #[test]
    fn decode_wrong_length_is_malformed() {
        // One byte short.
        let short = &encode_convergent_timestamp_aad(42)[..12];
        assert!(matches!(
            decode_convergent_timestamp_aad(short),
            Err(MlsError::ConvergentTimestampMalformed(_))
        ));
        // One byte long.
        let mut long = encode_convergent_timestamp_aad(42).to_vec();
        long.push(0);
        assert!(matches!(
            decode_convergent_timestamp_aad(&long),
            Err(MlsError::ConvergentTimestampMalformed(_))
        ));
    }

    #[test]
    fn decode_wrong_magic_is_malformed() {
        let mut aad = encode_convergent_timestamp_aad(42);
        aad[0] ^= 0xFF;
        assert!(matches!(
            decode_convergent_timestamp_aad(&aad),
            Err(MlsError::ConvergentTimestampMalformed(_))
        ));
    }

    #[test]
    fn decode_wrong_version_is_malformed() {
        let mut aad = encode_convergent_timestamp_aad(42);
        aad[4] = CONVERGENT_TIMESTAMP_AAD_VERSION.wrapping_add(1);
        assert!(matches!(
            decode_convergent_timestamp_aad(&aad),
            Err(MlsError::ConvergentTimestampMalformed(_))
        ));
    }
}
