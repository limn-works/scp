//! Which pre-rotation custody methods the SDK offers on which profile, and
//! what it discloses at custody selection (`09-security-model.md` §9.7.4.1
//! item 4, "Method by profile", "The four-cell outcome table" and "One
//! disclosure rule").
//!
//! [`CustodyType::offered_on`] encodes the method-by-profile table, then the
//! build state of the methods whose custody this build does not yet ship.
//! [`CustodyDisclosure::at_selection`] states the four-cell table's columns
//! for a selection, the root and pre-rotation co-residence, and the
//! separations the SDK offers. Every type here is a unit enum or a record of
//! public fields, so each crosses every binding in one shape.

use std::fmt;

use crate::key_state::CustodyType;

/// Where an SDK runs (`09-security-model.md` §9.7.4.1 item 4, the custody
/// profile).
///
/// The SDK computes it from one question with three answers: does
/// this platform expose a `WebAuthn` credential API this process may call,
/// and if so does that API arrive through a desktop platform credential
/// provider, a mobile one, or a page's `navigator.credentials`. Whether a
/// human attends decides nothing. A profile is a property of a running SDK,
/// never of an identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CustodyProfile {
    /// The platform exposes no `WebAuthn` credential API this process may
    /// call.
    Headless,
    /// The process may call a `WebAuthn` credential API, and it arrives
    /// through a desktop platform credential provider.
    Desktop,
    /// The process may call a `WebAuthn` credential API, and it arrives
    /// through a mobile platform credential provider.
    Mobile,
    /// The process may call a `WebAuthn` credential API, and it arrives
    /// through a page's `navigator.credentials`.
    Browser {
        /// The page's origin and the relying-party identifier the passkey is
        /// registered against.
        origin: RpOrigin,
    },
}

impl fmt::Display for CustodyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Headless => "Headless",
            Self::Desktop => "Desktop",
            Self::Mobile => "Mobile",
            Self::Browser { .. } => "Browser",
        })
    }
}

/// The two names an [`RpOrigin`] is built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpOriginConfig {
    /// The page origin's effective domain: a host name such as
    /// `login.example.com`, without scheme or port.
    pub effective_domain: String,
    /// The relying-party identifier the passkey is registered against, such
    /// as `example.com`.
    pub rp_id: String,
}

/// A page origin's effective domain and the relying-party identifier a
/// passkey is registered against, each a lowercase DNS name.
///
/// [`new`](Self::new) refuses a relying-party identifier that is a public
/// suffix. The [`CustodyProfile::Browser`] cell of the `Passkey` row then
/// asks whether the identifier is the effective domain or a registrable-domain
/// suffix of it, which is the HTML Standard's "is a registrable domain suffix
/// of or is equal to" over the Public Suffix List the `psl` crate compiles
/// in, including its private section.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RpOrigin {
    effective_domain: String,
    rp_id: String,
}

impl RpOrigin {
    /// Validates both names, folding ASCII to lowercase.
    ///
    /// A name has labels of 1 to 63 characters from `a-z`, `0-9` and `-`,
    /// no label starting or ending with `-`, at most 253 characters in all,
    /// and no trailing dot. Its final label must not end in a number in the
    /// WHATWG URL Standard's sense, being all digits or `0x` followed by hex
    /// digits, since a URL parser reads such a host as an IPv4 address. The
    /// relying-party identifier must not itself be a public suffix.
    ///
    /// # Errors
    ///
    /// [`RpOriginError::EffectiveDomain`] or [`RpOriginError::RpId`], naming
    /// the first rule the value breaks.
    pub fn new(config: RpOriginConfig) -> Result<Self, RpOriginError> {
        let effective_domain =
            dns_name(config.effective_domain).map_err(RpOriginError::EffectiveDomain)?;
        let rp_id = dns_name(config.rp_id).map_err(RpOriginError::RpId)?;
        if psl::domain(rp_id.as_bytes()).is_none() {
            return Err(RpOriginError::RpId(RpDomainRefusal::PublicSuffix));
        }
        Ok(Self {
            effective_domain,
            rp_id,
        })
    }

    /// The origin's effective domain, lowercase.
    #[must_use]
    pub fn effective_domain(&self) -> &str {
        &self.effective_domain
    }

    /// The relying-party identifier, lowercase.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Whether the relying-party identifier is the effective domain or a
    /// registrable-domain suffix of it. [`new`](Self::new) has refused an
    /// identifier that is a public suffix; this refuses an identifier that
    /// reaches into the effective domain's own public suffix, as
    /// `amazonaws.com` does under `bucket.s3.amazonaws.com`.
    fn within_rp_suffix(&self) -> bool {
        if self.effective_domain == self.rp_id {
            return true;
        }
        let Some(head) = self.effective_domain.strip_suffix(self.rp_id.as_str()) else {
            return false;
        };
        if !head.ends_with('.') {
            return false;
        }
        let Some(public_suffix) = psl::suffix(self.effective_domain.as_bytes()) else {
            return false;
        };
        let public_suffix = public_suffix.as_bytes();
        let reaches_suffix = public_suffix == self.rp_id.as_bytes()
            || public_suffix
                .strip_suffix(self.rp_id.as_bytes())
                .is_some_and(|rest| rest.ends_with(b"."));
        !reaches_suffix
    }
}

/// Folds `name` to lowercase and checks the DNS-name rules
/// [`RpOrigin::new`] lists, all but the public-suffix rule.
fn dns_name(mut name: String) -> Result<String, RpDomainRefusal> {
    if name.is_empty() {
        return Err(RpDomainRefusal::Empty);
    }
    if name.len() > 253 {
        return Err(RpDomainRefusal::TooLong);
    }
    name.make_ascii_lowercase();
    let mut last = "";
    for label in name.split('.') {
        if label.is_empty() {
            return Err(RpDomainRefusal::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(RpDomainRefusal::LabelTooLong);
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RpDomainRefusal::BadCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RpDomainRefusal::HyphenAtLabelEdge);
        }
        last = label;
    }
    if ends_in_a_number(last) {
        return Err(RpDomainRefusal::EndsInANumber);
    }
    Ok(name)
}

/// The WHATWG URL Standard's "ends in a number" test on a lowercase final
/// label: all digits, or `0x` followed by zero or more hex digits.
fn ends_in_a_number(last: &str) -> bool {
    last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Which half of an [`RpOrigin`] failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpOriginError {
    /// The origin's effective domain is not a DNS name.
    #[error("the origin's effective domain is refused: {0}")]
    EffectiveDomain(RpDomainRefusal),
    /// The relying-party identifier is not a DNS name, or is a public suffix.
    #[error("the relying-party identifier is refused: {0}")]
    RpId(RpDomainRefusal),
}

/// The rule a name breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum RpDomainRefusal {
    /// The name is empty.
    #[error("the name is empty")]
    Empty,
    /// The name is longer than 253 characters.
    #[error("the name is longer than 253 characters")]
    TooLong,
    /// A label is empty, as in a leading, trailing or doubled dot.
    #[error("a label is empty")]
    EmptyLabel,
    /// A label is longer than 63 characters.
    #[error("a label is longer than 63 characters")]
    LabelTooLong,
    /// A label holds a character outside `a-z`, `0-9` and `-`.
    #[error("a label holds a character outside a-z, 0-9 and -")]
    BadCharacter,
    /// A label starts or ends with `-`.
    #[error("a label starts or ends with -")]
    HyphenAtLabelEdge,
    /// The final label ends in a number, so a URL parser reads the name as
    /// an IPv4 address.
    #[error("the final label ends in a number")]
    EndsInANumber,
    /// The relying-party identifier is a public suffix, such as `co.uk` or
    /// `github.io`.
    #[error("the name is a public suffix")]
    PublicSuffix,
}

/// Whether the SDK offers a custody method on a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodyOffer {
    /// The method conforms on the profile and this build ships it.
    Offered,
    /// The method does not conform on the profile, so the SDK MUST NOT offer
    /// it there (`09-security-model.md` §9.7.4.1 item 4, "Method by
    /// profile").
    NotConforming,
    /// `Fido2Token` or `Hsm` conforms on the profile, and this build ships no
    /// custody for it while Alec's ruling on hardware custody is open
    /// (`00-open-questions.md` §Identity and Custody, "Whether hardware
    /// next-set custody ships with SCP-311's software and callback
    /// custodies").
    HardwareCustodyAwaitingRuling,
    /// A copyable method conforms on the profile, and this build ships no
    /// custody for it while Alec's ruling on the headless floor is open
    /// (`00-open-questions.md` §Identity and Custody, "The headless
    /// pre-rotation floor").
    ServerFloorAwaitingRuling,
}

/// Which gated custodies a build ships, each `true` when it does. The crate
/// root does not export it, so only scp-did names a build state.
/// [`CustodyType::offered_on`] reads [`THIS_BUILD`]; tests reach
/// [`CustodyType::offer_under`] with other values so both states of each
/// custody stay tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustodyBuilds {
    /// The `Fido2Token` custody.
    pub fido2_token: bool,
    /// The `Hsm` custody.
    pub hsm: bool,
    /// The custody behind `EncryptedOfflineBackup`, `ShamirShares` and
    /// `PaperBackup`.
    pub headless_backup: bool,
}

/// What this build ships: none of the gated custodies.
// Stub — see SCP-311: the headless-backup custody adds a cargo feature on
// scp-did that sets `headless_backup`, and the FIDO2 and HSM
// custodies set their fields when Alec's hardware-custody ruling lets them
// ship. The state is scp-did's own, so no caller can assert it.
pub const THIS_BUILD: CustodyBuilds = CustodyBuilds {
    fido2_token: false,
    hsm: false,
    headless_backup: false,
};

impl CustodyType {
    /// Whether the SDK offers this method as pre-rotation custody on
    /// `profile` (`09-security-model.md` §9.7.4.1 item 4, "Method by
    /// profile").
    ///
    /// The table decides first: a method that does not conform on `profile`
    /// is [`CustodyOffer::NotConforming`] whatever this build ships. A
    /// `Passkey` on [`CustodyProfile::Browser`] conforms only when its
    /// origin's relying-party identifier is the effective domain or a
    /// registrable-domain suffix of it. A conforming `Fido2Token`, `Hsm` or
    /// copyable method is then refused with the open ruling its custody
    /// waits on when this build does not ship that custody.
    #[must_use]
    pub fn offered_on(self, profile: &CustodyProfile) -> CustodyOffer {
        self.offer_under(profile, THIS_BUILD)
    }

    /// [`offered_on`](Self::offered_on) under the build state `builds`.
    pub(crate) fn offer_under(
        self,
        profile: &CustodyProfile,
        builds: CustodyBuilds,
    ) -> CustodyOffer {
        use CustodyProfile::{Browser, Desktop, Headless, Mobile};
        let conforms = match self {
            Self::Passkey => match profile {
                Headless => false,
                Desktop | Mobile => true,
                Browser { origin } => origin.within_rp_suffix(),
            },
            Self::Fido2Token => true,
            Self::Hsm => match profile {
                Headless | Desktop | Mobile => true,
                Browser { .. } => false,
            },
            Self::EncryptedOfflineBackup | Self::ShamirShares | Self::PaperBackup => {
                match profile {
                    Headless => true,
                    Desktop | Mobile | Browser { .. } => false,
                }
            }
            Self::SecureEnclave | Self::AndroidKeystore | Self::Software => false,
        };
        if !conforms {
            return CustodyOffer::NotConforming;
        }
        let (built, refusal) = match self {
            Self::Fido2Token => (
                builds.fido2_token,
                CustodyOffer::HardwareCustodyAwaitingRuling,
            ),
            Self::Hsm => (builds.hsm, CustodyOffer::HardwareCustodyAwaitingRuling),
            Self::EncryptedOfflineBackup | Self::ShamirShares | Self::PaperBackup => (
                builds.headless_backup,
                CustodyOffer::ServerFloorAwaitingRuling,
            ),
            Self::Passkey | Self::SecureEnclave | Self::AndroidKeystore | Self::Software => {
                return CustodyOffer::Offered;
            }
        };
        if built {
            CustodyOffer::Offered
        } else {
            refusal
        }
    }
}

/// Where a pre-rotation credential lives relative to the platform account
/// that holds the root credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PreRotationResidence {
    /// A passkey under the platform account that holds the root credential,
    /// the default (`09-security-model.md` §9.7.4.1 item 4).
    RootPlatformAccount,
    /// A passkey under a second platform account.
    SecondPlatformAccount,
    /// Outside any platform account: a FIDO2 token, an HSM, or a copyable
    /// artifact.
    OutsidePlatformAccount,
}

/// Whether the party holding a copy of the pre-rotation key also holds the
/// standing root: the four-cell table's two columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodyCopyHolder {
    /// The copy holder holds the root.
    HoldsRoot,
    /// The copy holder holds no root.
    HoldsNoRoot,
}

/// One cell of the four-cell outcome table (`09-security-model.md`
/// §9.7.4.1 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodyFourCellOutcome {
    /// Both suffixes are rank 1; the identity is contested, terminal by key
    /// material.
    ContestedRank1,
    /// The controller wins outright.
    ControllerWins,
    /// The fork wins outright.
    ForkWins,
    /// Both suffixes are rank 2; the identity is contested, terminal by key
    /// material.
    ContestedRank2,
}

/// One column of the four-cell table: who the copy holder is, and the
/// outcome under each of the two rows, the kinds of revealing event the
/// controller can publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustodyColumn {
    /// Whether the copy holder holds the root.
    pub copy_holder: CustodyCopyHolder,
    /// The outcome when the controller's revealing event carried the
    /// standing root's signature.
    pub root_cosigned: CustodyFourCellOutcome,
    /// The outcome when the controller's revealing event carried no root
    /// signature.
    pub no_root_signature: CustodyFourCellOutcome,
}

/// The column of the four-cell table for `copy_holder`.
const fn column(copy_holder: CustodyCopyHolder) -> CustodyColumn {
    match copy_holder {
        CustodyCopyHolder::HoldsRoot => CustodyColumn {
            copy_holder,
            root_cosigned: CustodyFourCellOutcome::ContestedRank1,
            no_root_signature: CustodyFourCellOutcome::ForkWins,
        },
        CustodyCopyHolder::HoldsNoRoot => CustodyColumn {
            copy_holder,
            root_cosigned: CustodyFourCellOutcome::ControllerWins,
            no_root_signature: CustodyFourCellOutcome::ContestedRank2,
        },
    }
}

/// Whether the root and pre-rotation credentials share one platform account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodyCoResidence {
    /// Both sit behind one platform account's authentication factor. The SDK
    /// states it and offers [`CustodyDisclosure::separations`].
    OnePlatformAccount,
    /// The pre-rotation credential sits outside the root's platform account.
    Separate,
}

/// A separation the SDK MUST offer when the root and pre-rotation
/// credentials share one platform account (`09-security-model.md` §9.7.4.1
/// item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodySeparation {
    /// The pre-rotation credential on a FIDO2 security token.
    Fido2Token,
    /// The pre-rotation credential, a passkey, under a second platform
    /// account.
    SecondPlatformAccount,
}

/// What the SDK states at custody selection (`09-security-model.md`
/// §9.7.4.1 item 4, "One disclosure rule" and the co-residence paragraph).
/// [`at_selection`](Self::at_selection) computes every field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CustodyDisclosure {
    /// The four-cell columns the SDK states. A passkey has the one its
    /// residence decides. A copyable method has both, since the root's
    /// custody can sit on the host that holds the artifact. A `Fido2Token`
    /// or `Hsm` emits no copy and has none.
    pub copy_holder_column: Vec<CustodyColumn>,
    /// Whether the root and pre-rotation credentials share one platform
    /// account.
    pub co_residence: CustodyCoResidence,
    /// The separations the SDK offers: when the credentials share one
    /// platform account, each separation whose method the SDK offers on the
    /// profile; none otherwise.
    pub separations: Vec<CustodySeparation>,
}

impl CustodyDisclosure {
    /// The disclosure for selecting `custody` at `residence` on `profile`.
    ///
    /// # Errors
    ///
    /// - [`CustodyDisclosureError::NotOffered`] when
    ///   [`CustodyType::offered_on`] does not offer `custody` on `profile`.
    /// - [`CustodyDisclosureError::PasskeyOutsidePlatformAccount`] for a
    ///   passkey at [`PreRotationResidence::OutsidePlatformAccount`].
    /// - [`CustodyDisclosureError::PlatformAccountWithoutPasskey`] for any
    ///   other method under a platform account.
    pub fn at_selection(
        custody: CustodyType,
        residence: PreRotationResidence,
        profile: &CustodyProfile,
    ) -> Result<Self, CustodyDisclosureError> {
        Self::under(custody, residence, profile, THIS_BUILD)
    }

    /// [`at_selection`](Self::at_selection) under the build state `builds`.
    pub(crate) fn under(
        custody: CustodyType,
        residence: PreRotationResidence,
        profile: &CustodyProfile,
        builds: CustodyBuilds,
    ) -> Result<Self, CustodyDisclosureError> {
        use CustodyCopyHolder::{HoldsNoRoot, HoldsRoot};
        let offer = custody.offer_under(profile, builds);
        if offer != CustodyOffer::Offered {
            return Err(CustodyDisclosureError::NotOffered { custody, offer });
        }
        let (copy_holders, co_residence): (&[CustodyCopyHolder], _) = match (custody, residence) {
            (
                CustodyType::SecureEnclave | CustodyType::AndroidKeystore | CustodyType::Software,
                PreRotationResidence::RootPlatformAccount
                | PreRotationResidence::SecondPlatformAccount
                | PreRotationResidence::OutsidePlatformAccount,
            ) => return Err(CustodyDisclosureError::NotOffered { custody, offer }),
            (CustodyType::Passkey, PreRotationResidence::RootPlatformAccount) => {
                (&[HoldsRoot], CustodyCoResidence::OnePlatformAccount)
            }
            (CustodyType::Passkey, PreRotationResidence::SecondPlatformAccount) => {
                (&[HoldsNoRoot], CustodyCoResidence::Separate)
            }
            (CustodyType::Passkey, PreRotationResidence::OutsidePlatformAccount) => {
                return Err(CustodyDisclosureError::PasskeyOutsidePlatformAccount);
            }
            (
                CustodyType::Fido2Token
                | CustodyType::Hsm
                | CustodyType::EncryptedOfflineBackup
                | CustodyType::ShamirShares
                | CustodyType::PaperBackup,
                PreRotationResidence::RootPlatformAccount
                | PreRotationResidence::SecondPlatformAccount,
            ) => {
                return Err(CustodyDisclosureError::PlatformAccountWithoutPasskey(
                    custody,
                ));
            }
            (
                CustodyType::Fido2Token | CustodyType::Hsm,
                PreRotationResidence::OutsidePlatformAccount,
            ) => (&[], CustodyCoResidence::Separate),
            (
                CustodyType::EncryptedOfflineBackup
                | CustodyType::ShamirShares
                | CustodyType::PaperBackup,
                PreRotationResidence::OutsidePlatformAccount,
            ) => (&[HoldsRoot, HoldsNoRoot], CustodyCoResidence::Separate),
        };
        let separations = match co_residence {
            CustodyCoResidence::OnePlatformAccount => [
                (CustodySeparation::Fido2Token, CustodyType::Fido2Token),
                (
                    CustodySeparation::SecondPlatformAccount,
                    CustodyType::Passkey,
                ),
            ]
            .into_iter()
            .filter(|(_, method)| method.offer_under(profile, builds) == CustodyOffer::Offered)
            .map(|(separation, _)| separation)
            .collect(),
            CustodyCoResidence::Separate => Vec::new(),
        };
        Ok(Self {
            copy_holder_column: copy_holders.iter().copied().map(column).collect(),
            co_residence,
            separations,
        })
    }
}

/// Why [`CustodyDisclosure::at_selection`] refused a selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CustodyDisclosureError {
    /// The SDK does not offer the method on the profile.
    #[error("{custody} is not offered on this profile: {offer:?}")]
    NotOffered {
        /// The selected method.
        custody: CustodyType,
        /// What [`CustodyType::offered_on`] answered.
        offer: CustodyOffer,
    },
    /// A passkey always lives under a platform account.
    #[error("a passkey lives under a platform account")]
    PasskeyOutsidePlatformAccount,
    /// Only a passkey lives under a platform account.
    #[error("{0} does not live under a platform account")]
    PlatformAccountWithoutPasskey(CustodyType),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TYPES: [CustodyType; 9] = [
        CustodyType::Passkey,
        CustodyType::Fido2Token,
        CustodyType::Hsm,
        CustodyType::SecureEnclave,
        CustodyType::AndroidKeystore,
        CustodyType::EncryptedOfflineBackup,
        CustodyType::ShamirShares,
        CustodyType::PaperBackup,
        CustodyType::Software,
    ];

    const ALL_BUILT: CustodyBuilds = CustodyBuilds {
        fido2_token: true,
        hsm: true,
        headless_backup: true,
    };

    const NONE_BUILT: CustodyBuilds = CustodyBuilds {
        fido2_token: false,
        hsm: false,
        headless_backup: false,
    };

    const YES: CustodyOffer = CustodyOffer::Offered;
    const NO: CustodyOffer = CustodyOffer::NotConforming;
    const HARDWARE: CustodyOffer = CustodyOffer::HardwareCustodyAwaitingRuling;
    const FLOOR: CustodyOffer = CustodyOffer::ServerFloorAwaitingRuling;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn origin(effective_domain: &str, rp_id: &str) -> Result<RpOrigin, RpOriginError> {
        RpOrigin::new(RpOriginConfig {
            effective_domain: effective_domain.to_owned(),
            rp_id: rp_id.to_owned(),
        })
    }

    fn browser(effective_domain: &str, rp_id: &str) -> Result<CustodyProfile, RpOriginError> {
        Ok(CustodyProfile::Browser {
            origin: origin(effective_domain, rp_id)?,
        })
    }

    /// Headless, Desktop, Mobile, and Browser from an origin inside the
    /// relying-party suffix.
    fn profiles() -> Result<[CustodyProfile; 4], RpOriginError> {
        Ok([
            CustodyProfile::Headless,
            CustodyProfile::Desktop,
            CustodyProfile::Mobile,
            browser("login.Example.com", "example.com")?,
        ])
    }

    /// The table's row for `custody` across [`profiles`] under `builds`.
    fn row(
        custody: CustodyType,
        builds: CustodyBuilds,
    ) -> Result<[CustodyOffer; 4], RpOriginError> {
        Ok(profiles()?.map(|profile| custody.offer_under(&profile, builds)))
    }

    #[test]
    fn every_cell_with_every_custody_built() -> TestResult {
        for (custody, expected) in [
            (CustodyType::Passkey, [NO, YES, YES, YES]),
            (CustodyType::Fido2Token, [YES, YES, YES, YES]),
            (CustodyType::Hsm, [YES, YES, YES, NO]),
            (CustodyType::EncryptedOfflineBackup, [YES, NO, NO, NO]),
            (CustodyType::ShamirShares, [YES, NO, NO, NO]),
            (CustodyType::PaperBackup, [YES, NO, NO, NO]),
            (CustodyType::SecureEnclave, [NO, NO, NO, NO]),
            (CustodyType::AndroidKeystore, [NO, NO, NO, NO]),
            (CustodyType::Software, [NO, NO, NO, NO]),
        ] {
            assert_eq!(row(custody, ALL_BUILT)?, expected, "{custody}");
        }
        Ok(())
    }

    /// Every gated method on every profile, in both build states: a
    /// conforming cell answers the open ruling when its custody is not built
    /// and `Offered` when it is, and a non-conforming cell answers
    /// `NotConforming` in both.
    #[test]
    fn every_gated_cell_in_both_build_states() -> TestResult {
        for (custody, built, not_built) in [
            (CustodyType::Fido2Token, [YES, YES, YES, YES], [HARDWARE; 4]),
            (
                CustodyType::Hsm,
                [YES, YES, YES, NO],
                [HARDWARE, HARDWARE, HARDWARE, NO],
            ),
            (
                CustodyType::EncryptedOfflineBackup,
                [YES, NO, NO, NO],
                [FLOOR, NO, NO, NO],
            ),
            (
                CustodyType::ShamirShares,
                [YES, NO, NO, NO],
                [FLOOR, NO, NO, NO],
            ),
            (
                CustodyType::PaperBackup,
                [YES, NO, NO, NO],
                [FLOOR, NO, NO, NO],
            ),
        ] {
            assert_eq!(row(custody, ALL_BUILT)?, built, "{custody} built");
            assert_eq!(row(custody, NONE_BUILT)?, not_built, "{custody} not built");
        }
        Ok(())
    }

    #[test]
    fn this_build_ships_no_gated_custody_and_offered_on_reads_it() -> TestResult {
        assert_eq!(THIS_BUILD, NONE_BUILT);
        for custody in ALL_TYPES {
            for profile in profiles()? {
                assert_eq!(
                    custody.offered_on(&profile),
                    custody.offer_under(&profile, NONE_BUILT),
                    "{custody} on {profile}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn each_build_field_gates_only_its_own_methods() {
        let cases = [
            (
                CustodyBuilds {
                    fido2_token: false,
                    ..ALL_BUILT
                },
                vec![CustodyType::Fido2Token],
            ),
            (
                CustodyBuilds {
                    hsm: false,
                    ..ALL_BUILT
                },
                vec![CustodyType::Hsm],
            ),
            (
                CustodyBuilds {
                    headless_backup: false,
                    ..ALL_BUILT
                },
                vec![
                    CustodyType::EncryptedOfflineBackup,
                    CustodyType::ShamirShares,
                    CustodyType::PaperBackup,
                ],
            ),
        ];
        for (builds, gated) in cases {
            for custody in ALL_TYPES {
                let offer = custody.offer_under(&CustodyProfile::Headless, builds);
                if gated.contains(&custody) {
                    assert!(matches!(offer, HARDWARE | FLOOR), "{custody}: {offer:?}");
                } else {
                    assert_eq!(
                        offer,
                        custody.offer_under(&CustodyProfile::Headless, ALL_BUILT),
                        "{custody}"
                    );
                }
            }
        }
    }

    #[test]
    fn passkey_on_browser_needs_its_rp_id_to_be_a_registrable_suffix() -> TestResult {
        for (effective_domain, rp_id, expected) in [
            ("example.com", "example.com", YES),
            ("a.b.example.com", "example.com", YES),
            ("login.example.co.uk", "example.co.uk", YES),
            ("evil.com", "example.com", NO),
            ("notexample.com", "example.com", NO),
            ("example.com.evil.com", "example.com", NO),
            ("com", "example.com", NO),
            // The suffix runs one way: a parent domain is not under its child.
            ("example.com", "login.example.com", NO),
            // `amazonaws.com` is registrable, but reaches into the origin's
            // public suffix `s3.amazonaws.com`.
            ("bucket.s3.amazonaws.com", "amazonaws.com", NO),
        ] {
            let profile = browser(effective_domain, rp_id)?;
            assert_eq!(
                CustodyType::Passkey.offered_on(&profile),
                expected,
                "{effective_domain} under {rp_id}"
            );
        }
        Ok(())
    }

    #[test]
    fn rp_origin_refuses_a_public_suffix_rp_id() {
        for (effective_domain, rp_id) in [
            ("evil.github.io", "github.io"),
            ("a.co.uk", "co.uk"),
            ("example.com", "com"),
            ("bucket.s3.amazonaws.com", "s3.amazonaws.com"),
        ] {
            assert_eq!(
                origin(effective_domain, rp_id),
                Err(RpOriginError::RpId(RpDomainRefusal::PublicSuffix)),
                "{effective_domain} under {rp_id}"
            );
        }
    }

    #[test]
    fn rp_origin_refuses_non_dns_names() {
        for (domain, refusal) in [
            ("", RpDomainRefusal::Empty),
            ("a..com", RpDomainRefusal::EmptyLabel),
            ("example.com.", RpDomainRefusal::EmptyLabel),
            (".example.com", RpDomainRefusal::EmptyLabel),
            ("exa mple.com", RpDomainRefusal::BadCharacter),
            ("exämple.com", RpDomainRefusal::BadCharacter),
            ("example.com:443", RpDomainRefusal::BadCharacter),
            ("https://example.com", RpDomainRefusal::BadCharacter),
            ("-a.com", RpDomainRefusal::HyphenAtLabelEdge),
            ("a-.com", RpDomainRefusal::HyphenAtLabelEdge),
            ("192.168.0.1", RpDomainRefusal::EndsInANumber),
            ("1.2.3.0x4", RpDomainRefusal::EndsInANumber),
            ("1.2.3.0X4", RpDomainRefusal::EndsInANumber),
            ("a.0x", RpDomainRefusal::EndsInANumber),
        ] {
            assert_eq!(
                origin(domain, "example.com"),
                Err(RpOriginError::EffectiveDomain(refusal)),
                "{domain:?}"
            );
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            origin(&long_label, "example.com"),
            Err(RpOriginError::EffectiveDomain(
                RpDomainRefusal::LabelTooLong
            ))
        );
        let long_name = format!("{}com", "a.".repeat(126));
        assert_eq!(
            origin(&long_name, "example.com"),
            Err(RpOriginError::EffectiveDomain(RpDomainRefusal::TooLong))
        );
        assert_eq!(
            origin("example.com", "exa_mple.com"),
            Err(RpOriginError::RpId(RpDomainRefusal::BadCharacter))
        );
        assert_eq!(
            origin("example.com", "example.0x1f"),
            Err(RpOriginError::RpId(RpDomainRefusal::EndsInANumber))
        );
    }

    #[test]
    fn a_final_label_that_only_looks_numeric_is_a_name() -> Result<(), RpOriginError> {
        // `0xg` is not hex, and `1a` is not all digits, so neither ends in a
        // number.
        origin("a.0xg", "example.com")?;
        origin("a.1a", "example.com")?;
        Ok(())
    }

    #[test]
    fn rp_origin_folds_case() -> Result<(), RpOriginError> {
        let origin = origin("LOGIN.Example.COM", "EXAMPLE.com")?;
        assert_eq!(origin.effective_domain(), "login.example.com");
        assert_eq!(origin.rp_id(), "example.com");
        Ok(())
    }

    #[test]
    fn the_four_cells_follow_the_table() {
        assert_eq!(
            column(CustodyCopyHolder::HoldsRoot),
            CustodyColumn {
                copy_holder: CustodyCopyHolder::HoldsRoot,
                root_cosigned: CustodyFourCellOutcome::ContestedRank1,
                no_root_signature: CustodyFourCellOutcome::ForkWins,
            }
        );
        assert_eq!(
            column(CustodyCopyHolder::HoldsNoRoot),
            CustodyColumn {
                copy_holder: CustodyCopyHolder::HoldsNoRoot,
                root_cosigned: CustodyFourCellOutcome::ControllerWins,
                no_root_signature: CustodyFourCellOutcome::ContestedRank2,
            }
        );
    }

    #[test]
    fn default_passkey_states_co_residence_and_the_root_holding_column() -> TestResult {
        let disclosure = CustodyDisclosure::under(
            CustodyType::Passkey,
            PreRotationResidence::RootPlatformAccount,
            &CustodyProfile::Desktop,
            ALL_BUILT,
        )?;
        assert_eq!(
            disclosure,
            CustodyDisclosure {
                copy_holder_column: vec![column(CustodyCopyHolder::HoldsRoot)],
                co_residence: CustodyCoResidence::OnePlatformAccount,
                separations: vec![
                    CustodySeparation::Fido2Token,
                    CustodySeparation::SecondPlatformAccount
                ],
            }
        );
        Ok(())
    }

    /// A separation whose method this build does not offer is not offered:
    /// with no FIDO2 custody built, only the second platform account is.
    #[test]
    fn separations_list_only_offered_methods() -> TestResult {
        for profile in [
            CustodyProfile::Desktop,
            CustodyProfile::Mobile,
            browser("login.example.com", "example.com")?,
        ] {
            let disclosure = CustodyDisclosure::at_selection(
                CustodyType::Passkey,
                PreRotationResidence::RootPlatformAccount,
                &profile,
            )?;
            assert_eq!(
                disclosure.separations,
                vec![CustodySeparation::SecondPlatformAccount],
                "{profile}"
            );
        }
        Ok(())
    }

    #[test]
    fn second_account_passkey_still_states_a_column() -> TestResult {
        let disclosure = CustodyDisclosure::at_selection(
            CustodyType::Passkey,
            PreRotationResidence::SecondPlatformAccount,
            &CustodyProfile::Mobile,
        )?;
        assert_eq!(
            disclosure,
            CustodyDisclosure {
                copy_holder_column: vec![column(CustodyCopyHolder::HoldsNoRoot)],
                co_residence: CustodyCoResidence::Separate,
                separations: Vec::new(),
            }
        );
        Ok(())
    }

    /// The root's custody does not decide whether the holder of a copyable
    /// artifact also holds the root, so the SDK states both columns.
    #[test]
    fn copyable_methods_state_both_columns_and_hardware_states_none() -> TestResult {
        for custody in [
            CustodyType::EncryptedOfflineBackup,
            CustodyType::ShamirShares,
            CustodyType::PaperBackup,
        ] {
            let disclosure = CustodyDisclosure::under(
                custody,
                PreRotationResidence::OutsidePlatformAccount,
                &CustodyProfile::Headless,
                ALL_BUILT,
            )?;
            assert_eq!(
                disclosure,
                CustodyDisclosure {
                    copy_holder_column: vec![
                        column(CustodyCopyHolder::HoldsRoot),
                        column(CustodyCopyHolder::HoldsNoRoot)
                    ],
                    co_residence: CustodyCoResidence::Separate,
                    separations: Vec::new(),
                },
                "{custody}"
            );
        }
        for custody in [CustodyType::Fido2Token, CustodyType::Hsm] {
            let disclosure = CustodyDisclosure::under(
                custody,
                PreRotationResidence::OutsidePlatformAccount,
                &CustodyProfile::Desktop,
                ALL_BUILT,
            )?;
            assert!(disclosure.copy_holder_column.is_empty(), "{custody}");
        }
        Ok(())
    }

    #[test]
    fn disclosure_refuses_a_method_not_offered_on_the_profile() {
        for (custody, profile, offer) in [
            (CustodyType::SecureEnclave, CustodyProfile::Mobile, NO),
            (CustodyType::Software, CustodyProfile::Headless, NO),
            (CustodyType::Passkey, CustodyProfile::Headless, NO),
            (CustodyType::PaperBackup, CustodyProfile::Headless, FLOOR),
            (CustodyType::Hsm, CustodyProfile::Desktop, HARDWARE),
        ] {
            assert_eq!(
                CustodyDisclosure::at_selection(
                    custody,
                    PreRotationResidence::OutsidePlatformAccount,
                    &profile
                ),
                Err(CustodyDisclosureError::NotOffered { custody, offer }),
                "{custody} on {profile}"
            );
        }
    }

    #[test]
    fn disclosure_refuses_mismatched_residences() {
        assert_eq!(
            CustodyDisclosure::at_selection(
                CustodyType::Passkey,
                PreRotationResidence::OutsidePlatformAccount,
                &CustodyProfile::Desktop
            ),
            Err(CustodyDisclosureError::PasskeyOutsidePlatformAccount)
        );
        for (custody, profile) in [
            (CustodyType::Fido2Token, CustodyProfile::Desktop),
            (CustodyType::PaperBackup, CustodyProfile::Headless),
        ] {
            for residence in [
                PreRotationResidence::RootPlatformAccount,
                PreRotationResidence::SecondPlatformAccount,
            ] {
                assert_eq!(
                    CustodyDisclosure::under(custody, residence, &profile, ALL_BUILT),
                    Err(CustodyDisclosureError::PlatformAccountWithoutPasskey(
                        custody
                    ))
                );
            }
        }
    }
}
