//! Authenticated convergent committer timestamp, carried in the MLS
//! `FramedContent.authenticated_data` (AAD) (ADR-057).
//!
//! # Why this module exists
//!
//! Every SCP context maps to one MLS group whose members each maintain a
//! §9.9.3 Merkle event log. For the logs to converge byte-for-byte, the
//! *committer-assigned* timestamp on a leaf (`MessageSent`, `MemberJoined`)
//! must be identical across all members — so the committer mints it once and
//! every receiver stamps the same value, rather than each reading its own local
//! clock. On the native path that value rides inside a signed SCP envelope
//! (`created_at`). The in-browser participant driver (ADR-057) had no equivalent:
//! it transported the timestamp as a **loose, unauthenticated `u64`** beside the
//! ciphertext, so a hostile relay (the protocol's "dumb pipe") could deliver a
//! valid ciphertext with a **forged** timestamp and fork the receiver's Merkle
//! root from the honest committer's ().
//!
//! # The fix: bind it into the MLS AAD
//!
//! This module encodes the committer timestamp into a fixed 13-byte AAD blob and
//! the driver sets it on the group immediately before the one send/commit call.
//! openmls folds the AAD into `FramedContent.authenticated_data`, which is:
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
//! the value it stamps on its mirrored leaf is authenticated, not trusted on the
//! wire. The loose transported parameter is therefore **deleted, not validated**.
//!
//! # AAD is authenticated, not confidential
//!
//! `authenticated_data` is transmitted in the clear (it is *authenticated*
//! additional data, not encrypted). The committer timestamp is not secret — it
//! is a public event-log leaf field — so this is correct. The AAD carries
//! **only** the timestamp; nothing secret is placed here.
//!
//! # Residual: a lying-but-authenticated committer
//!
//! Binding stops a *relay* and a *non-committer member* from forging the value.
//! It does not stop the **committer itself** from signing an implausible
//! timestamp (far future / far past) — that is the pre-existing MLS
//! insider-equivocation class (a malicious committer can already fork receivers
//! by sending different commits to different members). To bound the honest-clock
//! case, [`validate_convergent_timestamp`] applies a receiver-side plausibility
//! window against the injected [`Clock`](scp_clock::Clock) and **rejects**
//! (never clamps) an out-of-window value: clamping would write each receiver's
//! *local* clock into its leaf, producing divergent roots — the very failure
//! this authentication defends against. Rejection leaves every honest receiver
//! with an identical verdict.
//!
//! The window bounds ([`MAX_FUTURE_SKEW_SECS`], [`MAX_AGE_SECS`]) are
//! **deliberately distinct constants** here, mirroring — not sharing — the
//! native §9.8.2(c) freshness bounds. The two paths validate different wire
//! shapes (an MLS AAD vs. a signed SCP envelope) and must be free to diverge.

use scp_clock::Clock;

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

/// Maximum accepted **future** skew, in seconds: a committer timestamp more than
/// this far ahead of the receiver's injected clock is rejected (5 minutes).
///
/// A **distinct** constant mirroring — not unified with — the native §9.8.2(c)
/// freshness bound: the AAD path and the signed-envelope path validate different
/// wire shapes and must be free to evolve independently.
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Maximum accepted **age**, in seconds: a committer timestamp more than this far
/// behind the receiver's injected clock is rejected (7 days).
///
/// A **distinct** constant mirroring — not unified with — the native §9.8.2(c)
/// freshness bound (see [`MAX_FUTURE_SKEW_SECS`]). The 7-day window tolerates a
/// member that was offline for up to a week catching up on a backlog of leaves
/// stamped by peers while it was away (ADR-057 cold presence).
pub const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

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

/// Rejects a committer timestamp that lies outside the receiver-side plausibility
/// window around the injected [`Clock`](scp_clock::Clock).
///
/// This is the residual bound on a **lying-but-authenticated** committer (see the
/// module docs): the AAD binding proves *who* authored the value, and this proves
/// it is *plausible* against the receiver's own clock. It **rejects** an
/// out-of-window value rather than clamping it — clamping would substitute the
/// receiver's local clock reading into the leaf, diverging its Merkle root from
/// every peer that saw the same committer value. All honest receivers with
/// roughly-synced clocks compute the same accept/reject verdict.
///
/// Accepts `now - MAX_AGE_SECS <= ts <= now + MAX_FUTURE_SKEW_SECS` (inclusive on
/// both bounds). Saturating arithmetic keeps a near-zero `now`/`ts` from
/// under/overflowing.
///
/// # Errors
///
/// Returns [`MlsError::ConvergentTimestampImplausible`] (carrying `ts`, the
/// observed `now`, and both window bounds) if `ts` is more than
/// [`MAX_FUTURE_SKEW_SECS`] ahead of, or more than [`MAX_AGE_SECS`] behind, the
/// injected clock.
pub fn validate_convergent_timestamp(ts: u64, clock: &dyn Clock) -> Result<(), MlsError> {
    let now = clock.now_secs();
    let future_skew = ts.saturating_sub(now); // how far ahead `ts` is of `now`
    let age = now.saturating_sub(ts); // how far behind `ts` is of `now`
    if future_skew > MAX_FUTURE_SKEW_SECS || age > MAX_AGE_SECS {
        return Err(MlsError::ConvergentTimestampImplausible {
            timestamp_secs: ts,
            now_secs: now,
            max_future_skew_secs: MAX_FUTURE_SKEW_SECS,
            max_age_secs: MAX_AGE_SECS,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_clock::TestClock;

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

    #[test]
    fn validate_accepts_exact_now() {
        let clock = TestClock::new(1_000_000);
        assert!(validate_convergent_timestamp(1_000_000, &clock).is_ok());
    }

    #[test]
    fn validate_future_boundary_accepts_max_skew_rejects_one_past() {
        let now = 1_000_000u64;
        let clock = TestClock::new(now);
        // Exactly at the future bound: accepted.
        assert!(validate_convergent_timestamp(now + MAX_FUTURE_SKEW_SECS, &clock).is_ok());
        // One second past: rejected.
        assert!(matches!(
            validate_convergent_timestamp(now + MAX_FUTURE_SKEW_SECS + 1, &clock),
            Err(MlsError::ConvergentTimestampImplausible { .. })
        ));
    }

    #[test]
    fn validate_age_boundary_accepts_max_age_rejects_one_older() {
        let now = 10_000_000u64;
        let clock = TestClock::new(now);
        // Exactly at the age bound (7 days old): accepted.
        assert!(validate_convergent_timestamp(now - MAX_AGE_SECS, &clock).is_ok());
        // One second older: rejected.
        assert!(matches!(
            validate_convergent_timestamp(now - MAX_AGE_SECS - 1, &clock),
            Err(MlsError::ConvergentTimestampImplausible { .. })
        ));
    }

    #[test]
    fn validate_error_carries_context() {
        let now = 5_000_000u64;
        let clock = TestClock::new(now);
        let ts = now + MAX_FUTURE_SKEW_SECS + 100;
        match validate_convergent_timestamp(ts, &clock) {
            Err(MlsError::ConvergentTimestampImplausible {
                timestamp_secs,
                now_secs,
                max_future_skew_secs,
                max_age_secs,
            }) => {
                assert_eq!(timestamp_secs, ts);
                assert_eq!(now_secs, now);
                assert_eq!(max_future_skew_secs, MAX_FUTURE_SKEW_SECS);
                assert_eq!(max_age_secs, MAX_AGE_SECS);
            }
            other => panic!("expected ConvergentTimestampImplausible, got {other:?}"),
        }
    }
}
