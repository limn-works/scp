//! The key state and its name-bound enumerations
//! (`09-security-model.md` §9.7.4.2 definitions).
//!
//! These are the field lists the spec's key-state table and the sentence
//! after it state, one name and one type each, so every SDK binding carries
//! the same names. The snapshot encoding, its decoder, and R3's semantic
//! checks live in `scp-kel`; the types here hold values and check only that
//! each one-byte discriminator is a registered value.

use std::fmt;

/// A one-byte discriminator that is not a registered value of its
/// enumeration. R3 rejects it under its unrecognized-discriminator clause
/// (`09-security-model.md` §9.7.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown {field} discriminator 0x{value:02x}")]
pub struct UnknownDiscriminator {
    /// The type name of the enumeration the byte was read as.
    pub field: &'static str,
    /// The unregistered byte.
    pub value: u8,
}

/// Defines a name-bound enumeration with registered one-byte discriminators:
/// `#[repr(u8)]`, `to_byte`, and a `TryFrom<u8>` that rejects every
/// unregistered byte with [`UnknownDiscriminator`].
macro_rules! name_bound_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $byte:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $byte ),+
        }

        impl $name {
            /// The registered one-byte discriminator this value encodes as.
            #[must_use]
            pub const fn to_byte(self) -> u8 {
                self as u8
            }
        }

        impl TryFrom<u8> for $name {
            type Error = UnknownDiscriminator;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $( $byte => Ok(Self::$variant), )+
                    _ => Err(UnknownDiscriminator { field: stringify!($name), value }),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $( Self::$variant => stringify!($variant), )+
                })
            }
        }
    };
}

name_bound_enum! {
    /// A key's role (`09-security-model.md` §9.7.4.2, "Key role"). Every key
    /// entry of a key-state snapshot carries it, and the snapshot's
    /// service-key role takes the same encoding.
    KeyRole {
        /// A member of the standing root set.
        RootMember = 0x01,
        /// The Active Signing Key `#active`, the identity's one operational role.
        Active = 0x02,
    }
}

name_bound_enum! {
    /// A key's condition at a position (`09-security-model.md` §9.7.4.2, the
    /// key-state snapshot's order).
    KeyCondition {
        /// The key is in force at this position.
        Current = 0x01,
        /// The key was replaced in the ordinary course.
        Superseded = 0x02,
        /// The key was withdrawn without a replacement.
        Retired = 0x03,
        /// The key is compromised from the position its entry's
        /// `compromised_from` names.
        Compromised = 0x04,
    }
}

name_bound_enum! {
    /// The substrate that holds a key's private half (`09-security-model.md`
    /// §9.7.4.2, "Custody type"). The value is the author's declaration and
    /// reads as `Software` unless a platform proof verifies.
    CustodyType {
        /// A passkey, the platform-synced `WebAuthn` credential.
        Passkey = 0x01,
        /// A roaming FIDO2 security key.
        Fido2Token = 0x02,
        /// A hardware security module.
        Hsm = 0x03,
        /// The Apple Secure Enclave.
        SecureEnclave = 0x04,
        /// The Android Keystore.
        AndroidKeystore = 0x05,
        /// An encrypted offline backup.
        EncryptedOfflineBackup = 0x06,
        /// Shamir secret shares.
        ShamirShares = 0x07,
        /// A paper backup.
        PaperBackup = 0x08,
        /// A key held in software.
        Software = 0x09,
    }
}

name_bound_enum! {
    /// A key's algorithm (`09-security-model.md` §9.7.4.2, "Key algorithm").
    KeyAlgorithm {
        /// ECDSA over P-256 with SHA-256, the one value registered for v1.
        EcdsaP256Sha256 = 0x01,
    }
}

/// One key the key state names (`09-security-model.md` §9.7.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyEntry {
    /// The 33-byte SEC1 compressed public key.
    pub key: [u8; 33],
    /// What the key may do.
    pub role: KeyRole,
    /// The key's condition at this position.
    pub condition: KeyCondition,
    /// The position a `Compromised` entry is compromised from, and zero for
    /// every other condition.
    pub compromised_from: u64,
    /// The substrate the author declares holds the private half.
    pub custody_type: CustodyType,
    /// The key's algorithm.
    pub key_algorithm: KeyAlgorithm,
}

/// One member of the next set's commitment list (`09-security-model.md`
/// §9.7.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommitmentEntry {
    /// `SHA-256("SCP-PREROTATION-COMMITMENT-V1:" ‖ pre_rotation_public_key)`.
    pub commitment: [u8; 32],
    /// The substrate the author declares holds the committed key.
    pub custody_type: CustodyType,
    /// The committed key's algorithm.
    pub key_algorithm: KeyAlgorithm,
}

/// The commitment list and next threshold the latest commitment-fixing event
/// at or before a position fixed (`09-security-model.md` §9.7.4.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StandingCommitment {
    /// One entry per member of the next set.
    pub commitments: Vec<CommitmentEntry>,
    /// The next threshold n a reveal must meet.
    pub next_threshold: u32,
}

/// An identity's derived key state at a position (`09-security-model.md`
/// §9.7.4.2, the key state's fields).
///
/// `IdentityBackend::resolve` returns this object to a caller
/// (`03-identity.md` §3.10.10), so every binding carries these field names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyState {
    /// The signing threshold t of the standing root.
    pub root_threshold: u32,
    /// One entry per key the state names: every root member and every
    /// operational key.
    pub keys: Vec<KeyEntry>,
    /// The designated witnesses, each a community-relay-list operator
    /// identifier.
    pub witnesses: Vec<[u8; 32]>,
    /// The cadence in seconds at which each witness cosigns the head.
    pub witnessing_interval: u32,
    /// The role whose `Current` key signs the service record.
    pub service_key_role: KeyRole,
    /// The delegating identity's identifier, all-zero where the identity is
    /// undelegated.
    pub delegator: [u8; 32],
    /// The commitment the latest reveal-authorized event at or before this
    /// position fixed.
    pub standing_commitment: StandingCommitment,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks one enumeration against the spec's literal table: each value
    /// encodes to its registered byte and decodes back, and every byte the
    /// table does not list is rejected naming the enumeration.
    fn assert_byte_table<T>(name: &'static str, table: &[(T, u8)], to_byte: fn(T) -> u8)
    where
        T: Copy + PartialEq + fmt::Debug + TryFrom<u8, Error = UnknownDiscriminator>,
    {
        for &(value, byte) in table {
            assert_eq!(
                to_byte(value),
                byte,
                "{name}::{value:?} encodes as 0x{byte:02x}"
            );
            assert_eq!(T::try_from(byte), Ok(value), "{name} decodes 0x{byte:02x}");
        }
        for byte in u8::MIN..=u8::MAX {
            if table.iter().any(|&(_, b)| b == byte) {
                continue;
            }
            assert_eq!(
                T::try_from(byte),
                Err(UnknownDiscriminator {
                    field: name,
                    value: byte
                }),
                "{name} rejects 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn name_bound_enums_map_every_registered_byte_and_reject_the_rest() {
        assert_byte_table(
            "KeyRole",
            &[(KeyRole::RootMember, 0x01), (KeyRole::Active, 0x02)],
            KeyRole::to_byte,
        );
        assert_byte_table(
            "KeyCondition",
            &[
                (KeyCondition::Current, 0x01),
                (KeyCondition::Superseded, 0x02),
                (KeyCondition::Retired, 0x03),
                (KeyCondition::Compromised, 0x04),
            ],
            KeyCondition::to_byte,
        );
        assert_byte_table(
            "CustodyType",
            &[
                (CustodyType::Passkey, 0x01),
                (CustodyType::Fido2Token, 0x02),
                (CustodyType::Hsm, 0x03),
                (CustodyType::SecureEnclave, 0x04),
                (CustodyType::AndroidKeystore, 0x05),
                (CustodyType::EncryptedOfflineBackup, 0x06),
                (CustodyType::ShamirShares, 0x07),
                (CustodyType::PaperBackup, 0x08),
                (CustodyType::Software, 0x09),
            ],
            CustodyType::to_byte,
        );
        assert_byte_table(
            "KeyAlgorithm",
            &[(KeyAlgorithm::EcdsaP256Sha256, 0x01)],
            KeyAlgorithm::to_byte,
        );
    }

    #[test]
    fn display_spells_each_variant_as_the_spec_names_it() {
        assert_eq!(KeyRole::RootMember.to_string(), "RootMember");
        assert_eq!(KeyCondition::Compromised.to_string(), "Compromised");
        assert_eq!(CustodyType::Fido2Token.to_string(), "Fido2Token");
        assert_eq!(KeyAlgorithm::EcdsaP256Sha256.to_string(), "EcdsaP256Sha256");
    }
}
