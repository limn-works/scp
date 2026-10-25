//! §9.7.4.2 R10's signing rule: a device signs only a legal event at the
//! head it holds. [`HeldHead::check_next`] and [`SigningChange::inception`]
//! are the only constructors of [`SigningChange`], the one input a signer
//! takes.

use scp_did::Identifier;

use super::chain::ValidatedChain;
use super::change::ValidatedChange;
use super::defect::{CheckStep, Discarded};
use super::{InceptionRefusal, validate_inception};
use crate::constants::HELD_HEAD_MARKER_BYTES;
use crate::signature::KEY_EVENT_CHALLENGE_LEN;

/// The bytes of an encoded [`HeldHeadMarker`].
const MARKER_LEN: usize = HELD_HEAD_MARKER_BYTES as usize;

/// What the signing rule signs at the marked head (`03-identity.md`
/// §3.10; §9.7.4.2 R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkerMode {
    /// Every legal event.
    Any,
    /// A reveal-authorized event alone: written only by R10's third exit
    /// under `Contested`.
    RevealOnly,
}

impl MarkerMode {
    const fn byte(self) -> u8 {
        match self {
            Self::Any => 0x00,
            Self::RevealOnly => 0x01,
        }
    }
}

/// The head a device that holds a key-event member last adopted.
///
/// It persists at `HELD_HEAD_MARKER_BYTES`: the 32-byte identifier, the 8-byte
/// big-endian sequence, the 32-byte preimage digest and the 1-byte mode
/// (`03-identity.md` §3.10; §9.18.17).
///
/// Its fields are private, and it has two constructors.
/// [`adopt`](Self::adopt) takes the mode as a required argument and builds
/// the marker from a [`ValidatedChain`]'s head, so a marker a device writes
/// names a head a valid chain ended at. [`from_bytes`](Self::from_bytes)
/// decodes a persisted marker and checks only its length and its mode byte:
/// it cannot tell whether a valid chain ended at the head the bytes name,
/// so that holds for a decoded marker only as far as the device's own store
/// is intact. Neither constructor drops a `RevealOnly`.
///
/// ```compile_fail,E0451
/// # use scp_kel::{HeldHeadMarker, MarkerMode};
/// let marker = HeldHeadMarker {
///     identifier: scp_did::Identifier::ZERO,
///     sequence: 0,
///     event_digest: [0; 32],
///     mode: MarkerMode::Any,
/// };
/// ```
///
/// The positive control:
///
/// ```
/// # use scp_kel::HeldHeadMarker;
/// assert!(HeldHeadMarker::from_bytes(&[0; 73]).is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeldHeadMarker {
    identifier: Identifier,
    sequence: u64,
    event_digest: [u8; 32],
    mode: MarkerMode,
}

/// Why bytes do not decode to a [`HeldHeadMarker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeldHeadMarkerError {
    /// The bytes are not `HELD_HEAD_MARKER_BYTES` long.
    Length {
        /// Their length.
        len: usize,
    },
    /// The mode byte is neither `0x00` nor `0x01`.
    Mode {
        /// The byte.
        byte: u8,
    },
}

impl HeldHeadMarker {
    /// The marker a device writes when it adopts `chain`'s head, with the
    /// mode the signing rule signs under there (§9.7.4.2 R10).
    #[must_use]
    pub fn adopt(chain: &ValidatedChain, mode: MarkerMode) -> Self {
        Self {
            identifier: chain.identifier(),
            sequence: chain.head_sequence(),
            event_digest: chain.head_digest(),
            mode,
        }
    }

    /// The identifier.
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The head's sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The head's preimage digest.
    #[must_use]
    pub const fn event_digest(&self) -> [u8; 32] {
        self.event_digest
    }

    /// What the signing rule signs at the marked head.
    #[must_use]
    pub const fn mode(&self) -> MarkerMode {
        self.mode
    }

    /// The marker's `HELD_HEAD_MARKER_BYTES` encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MARKER_LEN] {
        let mut bytes = [0; MARKER_LEN];
        let (identifier, rest) = bytes.split_at_mut(32);
        let (sequence, rest) = rest.split_at_mut(8);
        let (digest, mode) = rest.split_at_mut(32);
        identifier.copy_from_slice(self.identifier.as_bytes());
        sequence.copy_from_slice(&self.sequence.to_be_bytes());
        digest.copy_from_slice(&self.event_digest);
        mode.fill(self.mode.byte());
        bytes
    }

    /// Decodes a `HELD_HEAD_MARKER_BYTES` encoding.
    ///
    /// # Errors
    ///
    /// [`HeldHeadMarkerError`] where the length is not
    /// `HELD_HEAD_MARKER_BYTES` or the mode byte is not `0x00` or `0x01`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeldHeadMarkerError> {
        let bytes: &[u8; MARKER_LEN] = bytes
            .try_into()
            .map_err(|_| HeldHeadMarkerError::Length { len: bytes.len() })?;
        let (identifier, rest) = bytes
            .split_first_chunk::<32>()
            .ok_or(HeldHeadMarkerError::Length { len: MARKER_LEN })?;
        let (sequence, rest) = rest
            .split_first_chunk::<8>()
            .ok_or(HeldHeadMarkerError::Length { len: MARKER_LEN })?;
        let (digest, mode) = rest
            .split_first_chunk::<32>()
            .ok_or(HeldHeadMarkerError::Length { len: MARKER_LEN })?;
        let mode = match mode {
            [0x00] => MarkerMode::Any,
            [0x01] => MarkerMode::RevealOnly,
            [byte] => return Err(HeldHeadMarkerError::Mode { byte: *byte }),
            _ => return Err(HeldHeadMarkerError::Length { len: MARKER_LEN }),
        };
        Ok(Self {
            identifier: Identifier::from_bytes(*identifier),
            sequence: u64::from_be_bytes(*sequence),
            event_digest: *digest,
            mode,
        })
    }
}

/// The head a signing device holds (§9.7.4.2 R10).
///
/// It is the head "which its `HeldHeadMarker` names".
/// [`from_marker`](Self::from_marker) is its only constructor, so the
/// marker's mode always reaches the signing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeldHead {
    marker: HeldHeadMarker,
}

/// Why [`HeldHead::check_next`] refuses to hand a candidate to a signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningRefusal {
    /// The chain handed ends at `handed`, and the device holds `held`:
    /// `IdentityError::SigningBaseStale`.
    Stale {
        /// The handed chain's head digest.
        handed: [u8; 32],
        /// The held head's digest.
        held: [u8; 32],
    },
    /// The marker's mode is `RevealOnly` and the candidate is not
    /// reveal-authorized: `IdentityError::SigningBaseStale`, with the held
    /// head as both heads.
    RevealOnly {
        /// The held head's digest.
        held: [u8; 32],
    },
    /// The candidate fails R3's check order through step 8 against the
    /// chain: `IdentityError::IllegalKeyEvent`.
    Illegal(Discarded),
}

impl SigningRefusal {
    /// The step an [`SigningRefusal::Illegal`] failed at, the `stage` of
    /// `IdentityError::IllegalKeyEvent`; `None` for a stale head.
    #[must_use]
    pub const fn stage(&self) -> Option<CheckStep> {
        match self {
            Self::Illegal(discarded) => Some(discarded.stage()),
            Self::Stale { .. } | Self::RevealOnly { .. } => None,
        }
    }
}

impl HeldHead {
    /// The head a marker names, with its mode.
    #[must_use]
    pub const fn from_marker(marker: &HeldHeadMarker) -> Self {
        Self { marker: *marker }
    }

    /// The marker that names this head.
    #[must_use]
    pub const fn marker(&self) -> HeldHeadMarker {
        self.marker
    }

    /// R10's signing rule for an event past the inception: the chain must
    /// end at the held head's digest, the candidate must pass R3's check
    /// order through step 8 against it, and under `RevealOnly` it must be
    /// reveal-authorized.
    ///
    /// Heads compare by digest alone: two chains at one height carry
    /// different digests, and the digest binds the preimage, so an equal
    /// digest is also an equal identifier and sequence.
    ///
    /// # Errors
    ///
    /// [`SigningRefusal`] naming the first rule the candidate fails.
    pub fn check_next(
        &self,
        chain: &ValidatedChain,
        candidate_preimage: &[u8],
    ) -> Result<SigningChange, SigningRefusal> {
        let handed = chain.head_digest();
        if handed != self.marker.event_digest {
            return Err(SigningRefusal::Stale {
                handed,
                held: self.marker.event_digest,
            });
        }
        let change = chain
            .validate_change(candidate_preimage)
            .map_err(SigningRefusal::Illegal)?;
        if self.marker.mode == MarkerMode::RevealOnly
            && !change.effect().kind.is_reveal_authorized()
        {
            return Err(SigningRefusal::RevealOnly {
                held: self.marker.event_digest,
            });
        }
        Ok(SigningChange { change })
    }
}

/// A candidate a device may sign: an event that passed R3's check order
/// through step 8 at the head the device holds, or an inception that passed
/// R2 (§9.7.4.2 R10).
///
/// Only [`HeldHead::check_next`] and [`SigningChange::inception`] construct
/// it.
///
/// ```compile_fail,E0451
/// # use scp_kel::{SigningChange, ValidatedChange};
/// fn forge(change: ValidatedChange) -> SigningChange {
///     SigningChange { change }
/// }
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::SigningChange;
/// let change = SigningChange::new();
/// ```
///
/// ```compile_fail,E0599
/// # use scp_kel::SigningChange;
/// let change = SigningChange::default();
/// ```
///
/// The positive control:
///
/// ```
/// # use scp_kel::SigningChange;
/// assert!(SigningChange::inception(b"SCP-KEL-EVENT-V1:").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningChange {
    change: ValidatedChange,
}

impl SigningChange {
    /// R10's signing rule for an inception: the candidate passes R2 and R3's
    /// check order through step 8 at position zero. No head is held before
    /// the identifier exists.
    ///
    /// # Errors
    ///
    /// [`InceptionRefusal`] where the candidate fails.
    pub fn inception(candidate_preimage: &[u8]) -> Result<Self, InceptionRefusal> {
        validate_inception(candidate_preimage).map(|change| Self { change })
    }

    /// The validated change a signer signs.
    #[must_use]
    pub const fn change(&self) -> &ValidatedChange {
        &self.change
    }

    /// The event digest `D` a raw-arm signer signs:
    /// [`ValidatedChange::digest`].
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.change.digest()
    }

    /// The `WebAuthn` challenge an assertion-arm signer passes to its
    /// authenticator, `"SCP-KEY-EVENT-V1:" ‖ D`:
    /// [`ValidatedChange::key_event_challenge`].
    #[must_use]
    pub const fn key_event_challenge(&self) -> [u8; KEY_EVENT_CHALLENGE_LEN] {
        self.change.key_event_challenge()
    }
}
