//! Which pre-rotation custody methods the SDK offers on which profile, and
//! what it discloses at custody selection (`09-security-model.md` §9.7.4.1
//! item 4, "Method by profile", "The four-cell outcome table" and "One
//! disclosure rule").
//!
//! [`CustodyType::offered_on`] encodes the method-by-profile table, then the
//! build state of the methods whose custody this build does not yet ship.
//! [`CustodyDisclosure::at_selection`] encodes the four-cell table's residual
//! for a selection and the root and pre-rotation co-residence.

use std::fmt;

use crate::key_state::CustodyType;

/// Where an SDK runs (`09-security-model.md` §9.7.4.1 item 4). A profile is
/// a property of a running SDK, never of an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodyProfile {
    /// A server or other process with no attending user.
    Headless,
    /// A desktop application.
    Desktop,
    /// A mobile application.
    Mobile,
    /// The in-browser client.
    Browser,
}

impl fmt::Display for CustodyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Headless => "Headless",
            Self::Desktop => "Desktop",
            Self::Mobile => "Mobile",
            Self::Browser => "Browser",
        })
    }
}

/// The browser origin a passkey would be used from, and the relying-party
/// identifier the passkey was registered against.
///
/// [`new`](Self::new) checks that both are lowercase-folded ASCII DNS names
/// and nothing more; [`CustodyType::offered_on`] checks whether the origin's
/// effective domain falls under the identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpOrigin {
    effective_domain: String,
    rp_id: String,
}

impl RpOrigin {
    /// Validates `effective_domain` and `rp_id` as DNS names, folding ASCII
    /// to lowercase.
    ///
    /// A name has labels of 1 to 63 characters from `a-z`, `0-9` and `-`,
    /// no label starting or ending with `-`, at most 253 characters in all,
    /// no trailing dot, and a final label that is not all digits, which
    /// rejects an IPv4 literal. `rp_id` must also have at least two labels,
    /// so a single-label name such as a top-level domain is never the
    /// identifier a suffix is checked against.
    ///
    /// # Errors
    ///
    /// [`RpOriginError::EffectiveDomain`] or [`RpOriginError::RpId`], naming
    /// the first rule the value breaks.
    pub fn new(effective_domain: &str, rp_id: &str) -> Result<Self, RpOriginError> {
        let effective_domain =
            dns_name(effective_domain).map_err(RpOriginError::EffectiveDomain)?;
        let rp_id = dns_name(rp_id).map_err(RpOriginError::RpId)?;
        if !rp_id.contains('.') {
            return Err(RpOriginError::RpId(DomainRefusal::SingleLabel));
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

    /// Whether the effective domain is the relying-party identifier or a
    /// subdomain of it, which is the `WebAuthn` registrable-suffix rule the
    /// `Passkey` row's Browser cell names.
    fn within_rp_suffix(&self) -> bool {
        self.effective_domain == self.rp_id
            || self
                .effective_domain
                .strip_suffix(self.rp_id.as_str())
                .is_some_and(|head| head.ends_with('.'))
    }
}

/// Folds `name` to lowercase and checks the DNS-name rules
/// [`RpOrigin::new`] lists.
fn dns_name(name: &str) -> Result<String, DomainRefusal> {
    if name.is_empty() {
        return Err(DomainRefusal::Empty);
    }
    if name.len() > 253 {
        return Err(DomainRefusal::TooLong);
    }
    let name = name.to_ascii_lowercase();
    let mut last = "";
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DomainRefusal::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(DomainRefusal::LabelTooLong);
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DomainRefusal::BadCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainRefusal::HyphenAtLabelEdge);
        }
        last = label;
    }
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DomainRefusal::NumericFinalLabel);
    }
    Ok(name)
}

/// Which half of an [`RpOrigin`] failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpOriginError {
    /// The origin's effective domain is not a DNS name.
    #[error("the origin's effective domain is not a DNS name: {0}")]
    EffectiveDomain(DomainRefusal),
    /// The relying-party identifier is not a DNS name of two or more labels.
    #[error("the relying-party identifier is not a DNS name of two or more labels: {0}")]
    RpId(DomainRefusal),
}

/// The DNS-name rule a value breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainRefusal {
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
    /// The final label is all digits, as in an IPv4 literal.
    #[error("the final label is all digits")]
    NumericFinalLabel,
    /// The relying-party identifier has one label.
    #[error("the name has one label")]
    SingleLabel,
}

/// Whether the SDK offers a custody method on a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Offer {
    /// The method conforms on the profile and this build ships it.
    Offered,
    /// The method does not conform on the profile, so the SDK MUST NOT offer
    /// it there (`09-security-model.md` §9.7.4.1 item 4, "Method by
    /// profile").
    NotConforming,
    /// The method conforms on the profile, but this build ships no custody
    /// for it.
    NotBuilt(NotBuiltReason),
}

/// Why a build ships no custody for a conforming method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotBuiltReason {
    /// The `Fido2Token` and `Hsm` custodies wait on a ruling on hardware
    /// custody.
    HardwareCustodyAwaitingRuling,
    /// The three copyable headless methods wait on a ruling on the server
    /// floor.
    ServerFloorAwaitingRuling,
}

/// Whether a build ships one custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuildState {
    /// The build ships the custody.
    Built,
    /// The build ships no custody for the method.
    NotBuilt,
}

/// Which gated custodies a build ships. [`CustodyType::offered_on`] reads it
/// only for a method that conforms on the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BuiltCustodies {
    /// The `Fido2Token` custody.
    pub fido2_token: BuildState,
    /// The `Hsm` custody.
    pub hsm: BuildState,
    /// The custody behind `EncryptedOfflineBackup`, `ShamirShares` and
    /// `PaperBackup`.
    pub headless_backup: BuildState,
}

impl BuiltCustodies {
    /// What this build ships: none of the gated custodies.
    // Stub — see SCP-311: the FIDO2, HSM and headless-backup custodies land
    // with their own pull requests, and each flips its field to `Built`.
    #[must_use]
    pub const fn this_build() -> Self {
        Self {
            fido2_token: BuildState::NotBuilt,
            hsm: BuildState::NotBuilt,
            headless_backup: BuildState::NotBuilt,
        }
    }
}

impl CustodyType {
    /// Whether the SDK offers this method as pre-rotation custody on
    /// `profile` (`09-security-model.md` §9.7.4.1 item 4, "Method by
    /// profile").
    ///
    /// The table decides first: a method that does not conform on `profile`
    /// is [`Offer::NotConforming`] whatever `built` says. A `Passkey` on
    /// `Browser` conforms only with an `origin` whose effective domain is
    /// the relying-party identifier or a subdomain of it; without an origin
    /// it does not conform. On every other profile `origin` is not read. A
    /// conforming `Fido2Token`, `Hsm` or copyable method is then
    /// [`Offer::NotBuilt`] when `built` marks its custody not built.
    #[must_use]
    pub fn offered_on(
        self,
        profile: CustodyProfile,
        origin: Option<&RpOrigin>,
        built: BuiltCustodies,
    ) -> Offer {
        use CustodyProfile::{Browser, Desktop, Headless, Mobile};
        let conforms = match self {
            Self::Passkey => match profile {
                Headless => false,
                Desktop | Mobile => true,
                Browser => origin.is_some_and(RpOrigin::within_rp_suffix),
            },
            Self::Fido2Token => true,
            Self::Hsm => match profile {
                Headless | Desktop | Mobile => true,
                Browser => false,
            },
            Self::EncryptedOfflineBackup | Self::ShamirShares | Self::PaperBackup => {
                match profile {
                    Headless => true,
                    Desktop | Mobile | Browser => false,
                }
            }
            Self::SecureEnclave | Self::AndroidKeystore | Self::Software => false,
        };
        if !conforms {
            return Offer::NotConforming;
        }
        let (state, reason) = match self {
            Self::Fido2Token => (
                built.fido2_token,
                NotBuiltReason::HardwareCustodyAwaitingRuling,
            ),
            Self::Hsm => (built.hsm, NotBuiltReason::HardwareCustodyAwaitingRuling),
            Self::EncryptedOfflineBackup | Self::ShamirShares | Self::PaperBackup => (
                built.headless_backup,
                NotBuiltReason::ServerFloorAwaitingRuling,
            ),
            Self::Passkey | Self::SecureEnclave | Self::AndroidKeystore | Self::Software => {
                return Offer::Offered;
            }
        };
        match state {
            BuildState::Built => Offer::Offered,
            BuildState::NotBuilt => Offer::NotBuilt(reason),
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
/// standing root (the four-cell table's columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CopyHolder {
    /// The copy holder holds the root.
    HoldsRoot,
    /// The copy holder holds no root.
    HoldsNoRoot,
}

/// One cell of the four-cell outcome table (`09-security-model.md`
/// §9.7.4.1 item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FourCellOutcome {
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

/// The part of the four-cell table that applies to a selection: whether the
/// copy holder holds the root, and the outcome under each kind of revealing
/// event the controller can publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResidualRow {
    copy_holder: CopyHolder,
}

impl ResidualRow {
    /// Whether the copy holder holds the root.
    #[must_use]
    pub const fn copy_holder(&self) -> CopyHolder {
        self.copy_holder
    }

    /// The outcome when the controller's revealing event carried the
    /// standing root's signature.
    #[must_use]
    pub const fn root_cosigned(&self) -> FourCellOutcome {
        match self.copy_holder {
            CopyHolder::HoldsRoot => FourCellOutcome::ContestedRank1,
            CopyHolder::HoldsNoRoot => FourCellOutcome::ControllerWins,
        }
    }

    /// The outcome when the controller's revealing event carried no root
    /// signature.
    #[must_use]
    pub const fn no_root_signature(&self) -> FourCellOutcome {
        match self.copy_holder {
            CopyHolder::HoldsRoot => FourCellOutcome::ForkWins,
            CopyHolder::HoldsNoRoot => FourCellOutcome::ContestedRank2,
        }
    }
}

/// Whether the root and pre-rotation credentials share one platform account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoResidence {
    /// Both sit behind one platform account's authentication factor. The SDK
    /// states it and offers [`CustodyDisclosure::separations_to_offer`].
    OnePlatformAccount,
    /// The pre-rotation credential sits outside the root's platform account.
    Separate,
}

/// A separation the SDK MUST offer when the root and pre-rotation
/// credentials share one platform account (`09-security-model.md` §9.7.4.1
/// item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Separation {
    /// The pre-rotation credential on a FIDO2 security token.
    Fido2Token,
    /// The pre-rotation credential under a second platform account.
    SecondPlatformAccount,
}

/// What the SDK states at custody selection (`09-security-model.md`
/// §9.7.4.1 item 4, "One disclosure rule" and the co-residence paragraph).
///
/// Only [`at_selection`](Self::at_selection) builds one, so its fields always
/// follow the four-cell table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CustodyDisclosure {
    residual_row: Option<ResidualRow>,
    co_residence: CoResidence,
}

impl CustodyDisclosure {
    /// The disclosure for selecting `custody`, held at `residence`.
    ///
    /// A passkey carries a provider-retained copy, so it has a residual row:
    /// under the root's platform account the copy holder holds the root, and
    /// under a second account it holds none. The three copyable methods have
    /// a residual row whose copy holder holds no root. `Fido2Token` and `Hsm`
    /// emit no copy, so they have none.
    ///
    /// # Errors
    ///
    /// - [`DisclosureError::NotConformingOnAnyProfile`] for `SecureEnclave`,
    ///   `AndroidKeystore` and `Software`.
    /// - [`DisclosureError::PasskeyOutsidePlatformAccount`] for a passkey at
    ///   [`PreRotationResidence::OutsidePlatformAccount`].
    /// - [`DisclosureError::PlatformAccountWithoutPasskey`] for any other
    ///   method under a platform account.
    pub const fn at_selection(
        custody: CustodyType,
        residence: PreRotationResidence,
    ) -> Result<Self, DisclosureError> {
        let (copy_holder, co_residence) = match (custody, residence) {
            (
                CustodyType::SecureEnclave | CustodyType::AndroidKeystore | CustodyType::Software,
                PreRotationResidence::RootPlatformAccount
                | PreRotationResidence::SecondPlatformAccount
                | PreRotationResidence::OutsidePlatformAccount,
            ) => return Err(DisclosureError::NotConformingOnAnyProfile(custody)),
            (CustodyType::Passkey, PreRotationResidence::RootPlatformAccount) => {
                (Some(CopyHolder::HoldsRoot), CoResidence::OnePlatformAccount)
            }
            (CustodyType::Passkey, PreRotationResidence::SecondPlatformAccount) => {
                (Some(CopyHolder::HoldsNoRoot), CoResidence::Separate)
            }
            (CustodyType::Passkey, PreRotationResidence::OutsidePlatformAccount) => {
                return Err(DisclosureError::PasskeyOutsidePlatformAccount);
            }
            (
                CustodyType::Fido2Token
                | CustodyType::Hsm
                | CustodyType::EncryptedOfflineBackup
                | CustodyType::ShamirShares
                | CustodyType::PaperBackup,
                PreRotationResidence::RootPlatformAccount
                | PreRotationResidence::SecondPlatformAccount,
            ) => return Err(DisclosureError::PlatformAccountWithoutPasskey(custody)),
            (
                CustodyType::Fido2Token | CustodyType::Hsm,
                PreRotationResidence::OutsidePlatformAccount,
            ) => (None, CoResidence::Separate),
            (
                CustodyType::EncryptedOfflineBackup
                | CustodyType::ShamirShares
                | CustodyType::PaperBackup,
                PreRotationResidence::OutsidePlatformAccount,
            ) => (Some(CopyHolder::HoldsNoRoot), CoResidence::Separate),
        };
        let residual_row = match copy_holder {
            Some(copy_holder) => Some(ResidualRow { copy_holder }),
            None => None,
        };
        Ok(Self {
            residual_row,
            co_residence,
        })
    }

    /// The four-cell residual the SDK states, or `None` for a method that
    /// emits no copy.
    #[must_use]
    pub const fn residual_row(&self) -> Option<ResidualRow> {
        self.residual_row
    }

    /// Whether the root and pre-rotation credentials share one platform
    /// account.
    #[must_use]
    pub const fn co_residence(&self) -> CoResidence {
        self.co_residence
    }

    /// The separations the SDK MUST offer: both when the credentials share
    /// one platform account, none otherwise.
    #[must_use]
    pub const fn separations_to_offer(&self) -> &'static [Separation] {
        match self.co_residence {
            CoResidence::OnePlatformAccount => {
                &[Separation::Fido2Token, Separation::SecondPlatformAccount]
            }
            CoResidence::Separate => &[],
        }
    }
}

/// Why [`CustodyDisclosure::at_selection`] refused a selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DisclosureError {
    /// The method conforms on no profile, so it is never selected.
    #[error("{0} conforms as pre-rotation custody on no profile")]
    NotConformingOnAnyProfile(CustodyType),
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

    const PROFILES: [CustodyProfile; 4] = [
        CustodyProfile::Headless,
        CustodyProfile::Desktop,
        CustodyProfile::Mobile,
        CustodyProfile::Browser,
    ];

    const ALL_BUILT: BuiltCustodies = BuiltCustodies {
        fido2_token: BuildState::Built,
        hsm: BuildState::Built,
        headless_backup: BuildState::Built,
    };

    type TestResult = Result<(), RpOriginError>;

    fn in_suffix() -> Result<RpOrigin, RpOriginError> {
        RpOrigin::new("login.Example.com", "example.com")
    }

    /// The table's row for `custody`, Headless, Desktop, Mobile, Browser,
    /// with an in-suffix origin on Browser and every custody built.
    fn row(custody: CustodyType) -> Result<[Offer; 4], RpOriginError> {
        let origin = in_suffix()?;
        Ok(PROFILES.map(|profile| custody.offered_on(profile, Some(&origin), ALL_BUILT)))
    }

    const YES: Offer = Offer::Offered;
    const NO: Offer = Offer::NotConforming;

    #[test]
    fn passkey_row() -> TestResult {
        assert_eq!(row(CustodyType::Passkey)?, [NO, YES, YES, YES]);
        Ok(())
    }

    #[test]
    fn fido2_token_row() -> TestResult {
        assert_eq!(row(CustodyType::Fido2Token)?, [YES, YES, YES, YES]);
        Ok(())
    }

    #[test]
    fn hsm_row() -> TestResult {
        assert_eq!(row(CustodyType::Hsm)?, [YES, YES, YES, NO]);
        Ok(())
    }

    #[test]
    fn encrypted_offline_backup_row() -> TestResult {
        assert_eq!(row(CustodyType::EncryptedOfflineBackup)?, [YES, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn shamir_shares_row() -> TestResult {
        assert_eq!(row(CustodyType::ShamirShares)?, [YES, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn paper_backup_row() -> TestResult {
        assert_eq!(row(CustodyType::PaperBackup)?, [YES, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn secure_enclave_row() -> TestResult {
        assert_eq!(row(CustodyType::SecureEnclave)?, [NO, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn android_keystore_row() -> TestResult {
        assert_eq!(row(CustodyType::AndroidKeystore)?, [NO, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn software_row() -> TestResult {
        assert_eq!(row(CustodyType::Software)?, [NO, NO, NO, NO]);
        Ok(())
    }

    #[test]
    fn passkey_on_headless_is_not_offered_with_or_without_origin() -> TestResult {
        let origin = in_suffix()?;
        for origin in [None, Some(&origin)] {
            assert_eq!(
                CustodyType::Passkey.offered_on(CustodyProfile::Headless, origin, ALL_BUILT),
                Offer::NotConforming
            );
        }
        Ok(())
    }

    #[test]
    fn passkey_on_browser_needs_an_origin_under_the_rp_suffix() -> TestResult {
        let offer = |origin: Option<&RpOrigin>| {
            CustodyType::Passkey.offered_on(CustodyProfile::Browser, origin, ALL_BUILT)
        };
        assert_eq!(offer(None), Offer::NotConforming);
        for (domain, expected) in [
            ("example.com", Offer::Offered),
            ("a.b.example.com", Offer::Offered),
            ("evil.com", Offer::NotConforming),
            ("notexample.com", Offer::NotConforming),
            ("example.com.evil.com", Offer::NotConforming),
            ("com", Offer::NotConforming),
        ] {
            let origin = RpOrigin::new(domain, "example.com")?;
            assert_eq!(offer(Some(&origin)), expected, "{domain}");
        }
        // The suffix runs one way: a parent domain is not under its child.
        let parent = RpOrigin::new("example.com", "login.example.com")?;
        assert_eq!(offer(Some(&parent)), Offer::NotConforming);
        Ok(())
    }

    #[test]
    fn origin_is_not_read_off_browser() -> TestResult {
        let outside = RpOrigin::new("evil.com", "example.com")?;
        for profile in [CustodyProfile::Desktop, CustodyProfile::Mobile] {
            assert_eq!(
                CustodyType::Passkey.offered_on(profile, Some(&outside), ALL_BUILT),
                Offer::Offered
            );
        }
        Ok(())
    }

    #[test]
    fn secure_enclave_is_not_offered_on_any_profile_or_build() -> TestResult {
        let origin = in_suffix()?;
        for built in [ALL_BUILT, BuiltCustodies::this_build()] {
            for profile in PROFILES {
                assert_eq!(
                    CustodyType::SecureEnclave.offered_on(profile, Some(&origin), built),
                    Offer::NotConforming,
                    "{profile}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn hardware_custody_is_not_built_in_this_build() {
        let built = BuiltCustodies::this_build();
        for custody in [CustodyType::Fido2Token, CustodyType::Hsm] {
            assert_eq!(
                custody.offered_on(CustodyProfile::Desktop, None, built),
                Offer::NotBuilt(NotBuiltReason::HardwareCustodyAwaitingRuling),
                "{custody}"
            );
        }
        // Conformance decides before the build state.
        assert_eq!(
            CustodyType::Hsm.offered_on(CustodyProfile::Browser, None, built),
            Offer::NotConforming
        );
    }

    #[test]
    fn copyable_methods_are_not_built_in_this_build() {
        let built = BuiltCustodies::this_build();
        for custody in [
            CustodyType::EncryptedOfflineBackup,
            CustodyType::ShamirShares,
            CustodyType::PaperBackup,
        ] {
            assert_eq!(
                custody.offered_on(CustodyProfile::Headless, None, built),
                Offer::NotBuilt(NotBuiltReason::ServerFloorAwaitingRuling),
                "{custody}"
            );
            assert_eq!(
                custody.offered_on(CustodyProfile::Mobile, None, built),
                Offer::NotConforming,
                "{custody}"
            );
        }
    }

    #[test]
    fn each_build_field_gates_only_its_own_methods() -> TestResult {
        let origin = in_suffix()?;
        let cases = [
            (
                BuiltCustodies {
                    fido2_token: BuildState::NotBuilt,
                    ..ALL_BUILT
                },
                vec![CustodyType::Fido2Token],
            ),
            (
                BuiltCustodies {
                    hsm: BuildState::NotBuilt,
                    ..ALL_BUILT
                },
                vec![CustodyType::Hsm],
            ),
            (
                BuiltCustodies {
                    headless_backup: BuildState::NotBuilt,
                    ..ALL_BUILT
                },
                vec![
                    CustodyType::EncryptedOfflineBackup,
                    CustodyType::ShamirShares,
                    CustodyType::PaperBackup,
                ],
            ),
        ];
        for (built, gated) in cases {
            for custody in ALL_TYPES {
                let offer = custody.offered_on(CustodyProfile::Headless, Some(&origin), built);
                let expected =
                    custody.offered_on(CustodyProfile::Headless, Some(&origin), ALL_BUILT);
                if gated.contains(&custody) {
                    assert!(matches!(offer, Offer::NotBuilt(_)), "{custody}: {offer:?}");
                } else {
                    assert_eq!(offer, expected, "{custody}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn rp_origin_rejects_non_dns_names() {
        for (domain, refusal) in [
            ("", DomainRefusal::Empty),
            ("a..com", DomainRefusal::EmptyLabel),
            ("example.com.", DomainRefusal::EmptyLabel),
            (".example.com", DomainRefusal::EmptyLabel),
            ("exa mple.com", DomainRefusal::BadCharacter),
            ("exämple.com", DomainRefusal::BadCharacter),
            ("example.com:443", DomainRefusal::BadCharacter),
            ("-a.com", DomainRefusal::HyphenAtLabelEdge),
            ("a-.com", DomainRefusal::HyphenAtLabelEdge),
            ("192.168.0.1", DomainRefusal::NumericFinalLabel),
        ] {
            assert_eq!(
                RpOrigin::new(domain, "example.com"),
                Err(RpOriginError::EffectiveDomain(refusal)),
                "{domain:?}"
            );
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            RpOrigin::new(&long_label, "example.com"),
            Err(RpOriginError::EffectiveDomain(DomainRefusal::LabelTooLong))
        );
        let long_name = format!("{}com", "a.".repeat(126));
        assert_eq!(
            RpOrigin::new(&long_name, "example.com"),
            Err(RpOriginError::EffectiveDomain(DomainRefusal::TooLong))
        );
        assert_eq!(
            RpOrigin::new("example.com", "com"),
            Err(RpOriginError::RpId(DomainRefusal::SingleLabel))
        );
        assert_eq!(
            RpOrigin::new("example.com", "exa_mple.com"),
            Err(RpOriginError::RpId(DomainRefusal::BadCharacter))
        );
    }

    #[test]
    fn rp_origin_folds_case() -> TestResult {
        let origin = RpOrigin::new("LOGIN.Example.COM", "EXAMPLE.com")?;
        assert_eq!(origin.effective_domain(), "login.example.com");
        assert_eq!(origin.rp_id(), "example.com");
        Ok(())
    }

    #[test]
    fn the_four_cells_follow_the_table() {
        let holds_root = ResidualRow {
            copy_holder: CopyHolder::HoldsRoot,
        };
        let holds_no_root = ResidualRow {
            copy_holder: CopyHolder::HoldsNoRoot,
        };
        assert_eq!(holds_root.root_cosigned(), FourCellOutcome::ContestedRank1);
        assert_eq!(
            holds_no_root.root_cosigned(),
            FourCellOutcome::ControllerWins
        );
        assert_eq!(holds_root.no_root_signature(), FourCellOutcome::ForkWins);
        assert_eq!(
            holds_no_root.no_root_signature(),
            FourCellOutcome::ContestedRank2
        );
    }

    #[test]
    fn default_passkey_discloses_co_residence_and_the_root_holding_column()
    -> Result<(), DisclosureError> {
        let disclosure = CustodyDisclosure::at_selection(
            CustodyType::Passkey,
            PreRotationResidence::RootPlatformAccount,
        )?;
        assert_eq!(disclosure.co_residence(), CoResidence::OnePlatformAccount);
        assert_eq!(
            disclosure.separations_to_offer(),
            &[Separation::Fido2Token, Separation::SecondPlatformAccount]
        );
        assert_eq!(
            disclosure.residual_row().map(|row| row.copy_holder()),
            Some(CopyHolder::HoldsRoot)
        );
        Ok(())
    }

    #[test]
    fn second_account_passkey_still_has_a_residual() -> Result<(), DisclosureError> {
        let disclosure = CustodyDisclosure::at_selection(
            CustodyType::Passkey,
            PreRotationResidence::SecondPlatformAccount,
        )?;
        assert_eq!(disclosure.co_residence(), CoResidence::Separate);
        assert!(disclosure.separations_to_offer().is_empty());
        assert_eq!(
            disclosure.residual_row().map(|row| row.copy_holder()),
            Some(CopyHolder::HoldsNoRoot)
        );
        Ok(())
    }

    #[test]
    fn copyable_methods_disclose_a_residual_and_hardware_does_not() -> Result<(), DisclosureError> {
        for custody in [
            CustodyType::EncryptedOfflineBackup,
            CustodyType::ShamirShares,
            CustodyType::PaperBackup,
        ] {
            let disclosure = CustodyDisclosure::at_selection(
                custody,
                PreRotationResidence::OutsidePlatformAccount,
            )?;
            assert_eq!(
                disclosure.residual_row().map(|row| row.copy_holder()),
                Some(CopyHolder::HoldsNoRoot),
                "{custody}"
            );
            assert_eq!(disclosure.co_residence(), CoResidence::Separate);
        }
        for custody in [CustodyType::Fido2Token, CustodyType::Hsm] {
            let disclosure = CustodyDisclosure::at_selection(
                custody,
                PreRotationResidence::OutsidePlatformAccount,
            )?;
            assert_eq!(disclosure.residual_row(), None, "{custody}");
        }
        Ok(())
    }

    #[test]
    fn disclosure_refuses_mismatched_selections() {
        for custody in [
            CustodyType::SecureEnclave,
            CustodyType::AndroidKeystore,
            CustodyType::Software,
        ] {
            assert_eq!(
                CustodyDisclosure::at_selection(
                    custody,
                    PreRotationResidence::OutsidePlatformAccount
                ),
                Err(DisclosureError::NotConformingOnAnyProfile(custody))
            );
        }
        assert_eq!(
            CustodyDisclosure::at_selection(
                CustodyType::Passkey,
                PreRotationResidence::OutsidePlatformAccount
            ),
            Err(DisclosureError::PasskeyOutsidePlatformAccount)
        );
        for custody in [CustodyType::Fido2Token, CustodyType::PaperBackup] {
            for residence in [
                PreRotationResidence::RootPlatformAccount,
                PreRotationResidence::SecondPlatformAccount,
            ] {
                assert_eq!(
                    CustodyDisclosure::at_selection(custody, residence),
                    Err(DisclosureError::PlatformAccountWithoutPasskey(custody))
                );
            }
        }
    }
}
