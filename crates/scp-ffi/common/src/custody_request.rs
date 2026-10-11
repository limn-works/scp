//! The custody request vocabulary of spec `03-identity.md` §3.2.2
//! (`.docs/standards/sdk-common.md` §Custody request).
//!
//! A caller names the backend that holds an identity's private keys with one of
//! two request values, `encrypted_file` and `os_keystore`. A bridge built with
//! the `testing` feature also accepts `in_memory`, which is never a peer of the
//! two values. [`parse_custody_request`] maps a request to a [`CustodyRequest`]
//! or to the code §3.2.2's table gives.
//!
//! The module reads no environment and opens nothing: resolving the
//! `encrypted_file` inputs is [`crate::custody_file`]'s job, and building the
//! backend is the bridge's.

use crate::error_codes::{IDENT_1003, IDENT_1005, IDENT_1008, VALID_7005, VALID_7009};

/// The custody values a bridge accepts.
///
/// Every rejection [`parse_custody_request`] returns names them through this
/// constant (spec §3.2.2: "Every rejection message names `encrypted_file` and
/// `os_keystore` as the values the bridge accepts").
pub const ACCEPTED_CUSTODY: &str = "this bridge accepts custody \"encrypted_file\" (an \
     encrypted key file at $HOME/.scp/keys.bin, sealed under SCP_KEY_PASSPHRASE) or \
     \"os_keystore\" (the host key store, reached through a KeyCustodyProvider passed to \
     identity_create_with_custody)";

/// Longest prefix of an unrecognized request, in characters, that a rejection
/// message echoes. The request is caller input, so the echo is bounded.
const ECHO_LIMIT_CHARS: usize = 64;

/// The backend a caller requested for a new identity's private keys
/// (spec §3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyRequest {
    /// `encrypted_file`: `FileKeyCustody`, the Argon2id plus AES-256-GCM key
    /// file of spec §17.8.
    EncryptedFile,
    /// `os_keystore`: the host key store, reached only through the
    /// `KeyCustodyProvider` the caller passed.
    OsKeystore,
    /// `in_memory`: the testing-build affordance. [`parse_custody_request`]
    /// returns it only when [`CustodyRequestInput::testing_build`] is true.
    InMemory,
}

impl CustodyRequest {
    /// Every request value, in the order §3.2.2 lists them, `in_memory` last.
    pub const ALL: [Self; 3] = [Self::EncryptedFile, Self::OsKeystore, Self::InMemory];

    /// The request string a caller passes, and the string an identity
    /// handle's custody accessor reports (spec §3.2.2).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedFile => "encrypted_file",
            Self::OsKeystore => "os_keystore",
            Self::InMemory => "in_memory",
        }
    }

    /// Exact, case-sensitive lookup of a request string. Matches through
    /// [`Self::as_str`], so the spelling lives in one match.
    fn lookup(request: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == request)
    }
}

/// Everything [`parse_custody_request`] reads about one identity-creation call.
#[derive(Debug, Clone, Copy)]
pub struct CustodyRequestInput<'a> {
    /// The custody string the caller passed.
    pub request: &'a str,
    /// Whether the caller passed a `KeyCustodyProvider`, as
    /// `identity_create_with_custody` does.
    pub provider_present: bool,
    /// Whether the caller passed a `testing_seed`, after the bridge narrowed it
    /// to 32 bytes.
    pub seed_present: bool,
    /// Whether the calling bridge was compiled with its `testing` feature,
    /// passed by the bridge as `cfg!(feature = "testing")`.
    pub testing_build: bool,
}

/// A custody request §3.2.2 rejects. Each variant is one row of §3.2.2's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyRequestError {
    /// A `testing_seed` with any request other than `in_memory`
    /// (`SCP-VALID-7009`).
    SeedWithoutInMemory,
    /// `os_keystore` with no `KeyCustodyProvider` (`SCP-IDENT-1003`).
    OsKeystoreWithoutProvider,
    /// A `KeyCustodyProvider` with any request other than `os_keystore`
    /// (`SCP-IDENT-1005`).
    ProviderWithOtherRequest {
        /// The request, truncated to its first 64 characters.
        request: String,
    },
    /// `in_memory` on a bridge built without the `testing` feature
    /// (`SCP-IDENT-1008`).
    InMemoryRequiresTestingBuild,
    /// Any string outside the vocabulary, including `platform`, `software`,
    /// `file` and `callback` (`SCP-VALID-7005`).
    Unrecognized {
        /// The request, truncated to its first 64 characters.
        request: String,
    },
}

impl CustodyRequestError {
    /// The error code §3.2.2's table gives this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SeedWithoutInMemory => VALID_7009,
            Self::OsKeystoreWithoutProvider => IDENT_1003,
            Self::ProviderWithOtherRequest { .. } => IDENT_1005,
            Self::InMemoryRequiresTestingBuild => IDENT_1008,
            Self::Unrecognized { .. } => VALID_7005,
        }
    }
}

impl std::fmt::Display for CustodyRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeedWithoutInMemory => write!(
                f,
                "`testing_seed` parameter is only valid for custody \"in_memory\" — \
                 {ACCEPTED_CUSTODY}"
            ),
            Self::OsKeystoreWithoutProvider => write!(
                f,
                "custody \"os_keystore\" requires a KeyCustodyProvider, and none was passed; \
                 call identity_create_with_custody with the provider — {ACCEPTED_CUSTODY}"
            ),
            Self::ProviderWithOtherRequest { request } => write!(
                f,
                "a KeyCustodyProvider was passed with custody {request:?}; a provider serves \
                 only custody \"os_keystore\" — {ACCEPTED_CUSTODY}"
            ),
            Self::InMemoryRequiresTestingBuild => write!(
                f,
                "custody \"in_memory\" is not available in this build — {ACCEPTED_CUSTODY}"
            ),
            Self::Unrecognized { request } => {
                write!(f, "unknown custody type {request:?} — {ACCEPTED_CUSTODY}")
            }
        }
    }
}

impl std::error::Error for CustodyRequestError {}

fn bounded_echo(request: &str) -> String {
    request.chars().take(ECHO_LIMIT_CHARS).collect()
}

/// Maps one identity-creation call's custody request to the backend it names,
/// or to the rejection spec `03-identity.md` §3.2.2 gives it.
///
/// The rules run in this order, and the first that matches decides:
///
/// 1. A `testing_seed` with any request other than `in_memory` is
///    `SCP-VALID-7009`. §3.2.2 requires the seed check before the request is
///    read.
/// 2. `os_keystore` with a provider is [`CustodyRequest::OsKeystore`], and
///    without one is `SCP-IDENT-1003`.
/// 3. A provider with any other request is `SCP-IDENT-1005`.
/// 4. `encrypted_file` is [`CustodyRequest::EncryptedFile`].
/// 5. `in_memory` is [`CustodyRequest::InMemory`] when
///    [`CustodyRequestInput::testing_build`] is true, and `SCP-IDENT-1008`
///    otherwise.
/// 6. Every other string is `SCP-VALID-7005`. Matching is exact and
///    case-sensitive; no string falls back to a backend.
///
/// # Errors
///
/// Returns the [`CustodyRequestError`] for the first rule the input breaks.
/// Every error's message names `encrypted_file` and `os_keystore` through
/// [`ACCEPTED_CUSTODY`].
pub fn parse_custody_request(
    input: CustodyRequestInput<'_>,
) -> Result<CustodyRequest, CustodyRequestError> {
    let CustodyRequestInput {
        request,
        provider_present,
        seed_present,
        testing_build,
    } = input;
    let parsed = CustodyRequest::lookup(request);

    if seed_present && parsed != Some(CustodyRequest::InMemory) {
        return Err(CustodyRequestError::SeedWithoutInMemory);
    }

    match (parsed, provider_present) {
        (Some(CustodyRequest::OsKeystore), true) => Ok(CustodyRequest::OsKeystore),
        (Some(CustodyRequest::OsKeystore), false) => {
            Err(CustodyRequestError::OsKeystoreWithoutProvider)
        }
        (Some(CustodyRequest::EncryptedFile | CustodyRequest::InMemory) | None, true) => {
            Err(CustodyRequestError::ProviderWithOtherRequest {
                request: bounded_echo(request),
            })
        }
        (Some(CustodyRequest::EncryptedFile), false) => Ok(CustodyRequest::EncryptedFile),
        (Some(CustodyRequest::InMemory), false) => {
            if testing_build {
                Ok(CustodyRequest::InMemory)
            } else {
                Err(CustodyRequestError::InMemoryRequiresTestingBuild)
            }
        }
        (None, false) => Err(CustodyRequestError::Unrecognized {
            request: bounded_echo(request),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn input(
        request: &str,
        provider_present: bool,
        seed_present: bool,
        testing_build: bool,
    ) -> CustodyRequestInput<'_> {
        CustodyRequestInput {
            request,
            provider_present,
            seed_present,
            testing_build,
        }
    }

    fn code_of(i: CustodyRequestInput<'_>) -> Result<CustodyRequest, &'static str> {
        parse_custody_request(i).map_err(|e| e.code())
    }

    /// The two request values parse on both builds with no seed.
    #[test]
    fn parse_custody_request_accepts_both_values_on_every_build() {
        for testing in [true, false] {
            assert_eq!(
                code_of(input("encrypted_file", false, false, testing)),
                Ok(CustodyRequest::EncryptedFile),
            );
            assert_eq!(
                code_of(input("os_keystore", true, false, testing)),
                Ok(CustodyRequest::OsKeystore),
            );
        }
    }

    /// `in_memory` parses only on a testing build, with or without a seed.
    #[test]
    fn parse_custody_request_accepts_in_memory_only_on_a_testing_build() {
        assert_eq!(
            code_of(input("in_memory", false, false, true)),
            Ok(CustodyRequest::InMemory)
        );
        assert_eq!(
            code_of(input("in_memory", false, true, true)),
            Ok(CustodyRequest::InMemory)
        );
    }

    /// Row 1: a seed with any value other than `in_memory` is VALID-7009, on
    /// every build and whether or not a provider was passed.
    #[test]
    fn parse_custody_request_rejects_seed_without_in_memory_with_valid_7009() {
        for request in ["encrypted_file", "os_keystore", "platform", "file", ""] {
            for provider in [true, false] {
                for testing in [true, false] {
                    assert_eq!(
                        code_of(input(request, provider, true, testing)),
                        Err(VALID_7009),
                        "{request:?} provider={provider} testing={testing}",
                    );
                }
            }
        }
    }

    /// A seed with `in_memory` passes the seed rule and reaches the later rows:
    /// on a shipped build it is IDENT-1008, as §3.2.2's `in_memory` row gives,
    /// and with a provider it is IDENT-1005.
    #[test]
    fn parse_custody_request_codes_seed_with_in_memory_by_the_later_rows() {
        assert_eq!(
            code_of(input("in_memory", false, true, false)),
            Err(IDENT_1008)
        );
        assert_eq!(
            code_of(input("in_memory", true, true, false)),
            Err(IDENT_1005)
        );
        assert_eq!(
            code_of(input("in_memory", false, true, true)),
            Ok(CustodyRequest::InMemory)
        );
    }

    /// Row 2: `os_keystore` with no provider is IDENT-1003 on every build.
    #[test]
    fn parse_custody_request_rejects_os_keystore_without_provider_with_ident_1003() {
        for testing in [true, false] {
            assert_eq!(
                code_of(input("os_keystore", false, false, testing)),
                Err(IDENT_1003)
            );
        }
    }

    /// Row 3: a provider with any value other than `os_keystore` is IDENT-1005,
    /// including `in_memory` and strings outside the vocabulary.
    #[test]
    fn parse_custody_request_rejects_provider_with_other_value_with_ident_1005() {
        for request in ["encrypted_file", "in_memory", "platform", "callback", ""] {
            for testing in [true, false] {
                assert_eq!(
                    code_of(input(request, true, false, testing)),
                    Err(IDENT_1005),
                    "{request:?} testing={testing}",
                );
            }
        }
    }

    /// Row 4: `in_memory` on a shipped build is IDENT-1008.
    #[test]
    fn parse_custody_request_rejects_in_memory_on_a_shipped_build_with_ident_1008() {
        assert_eq!(
            code_of(input("in_memory", false, false, false)),
            Err(IDENT_1008)
        );
    }

    /// Row 5: every other string is VALID-7005 on every build, including the
    /// four names §3.2.2 lists and near-misses of the accepted values.
    #[test]
    fn parse_custody_request_rejects_every_other_string_with_valid_7005() {
        let others = [
            "platform",
            "software",
            "file",
            "callback",
            "",
            "Encrypted_File",
            "OS_KEYSTORE",
            " encrypted_file",
            "os_keystore\0",
            "in-memory",
            "keychain",
        ];
        for request in others {
            for testing in [true, false] {
                assert_eq!(
                    code_of(input(request, false, false, testing)),
                    Err(VALID_7005),
                    "{request:?} testing={testing}",
                );
            }
        }
    }

    /// Exhaustive sweep: every (request, provider, seed, build) input yields
    /// exactly the outcome the ordered rules give, so one input has one code.
    #[test]
    fn parse_custody_request_codes_every_input_by_the_ordered_rules() {
        let requests = ["encrypted_file", "os_keystore", "in_memory", "platform"];
        for request in requests {
            for provider in [true, false] {
                for seed in [true, false] {
                    for testing in [true, false] {
                        let want = if seed && request != "in_memory" {
                            Err(VALID_7009)
                        } else if request == "os_keystore" && provider {
                            Ok(CustodyRequest::OsKeystore)
                        } else if request == "os_keystore" {
                            Err(IDENT_1003)
                        } else if provider {
                            Err(IDENT_1005)
                        } else if request == "encrypted_file" {
                            Ok(CustodyRequest::EncryptedFile)
                        } else if request == "in_memory" && testing {
                            Ok(CustodyRequest::InMemory)
                        } else if request == "in_memory" {
                            Err(IDENT_1008)
                        } else {
                            Err(VALID_7005)
                        };
                        assert_eq!(
                            code_of(input(request, provider, seed, testing)),
                            want,
                            "{request:?} provider={provider} seed={seed} testing={testing}",
                        );
                    }
                }
            }
        }
    }

    /// Every rejection message names both accepted values through the one
    /// constant.
    #[test]
    fn parse_custody_request_every_rejection_names_the_accepted_values() {
        assert!(ACCEPTED_CUSTODY.contains("\"encrypted_file\""));
        assert!(ACCEPTED_CUSTODY.contains("\"os_keystore\""));
        let rejected = [
            input("encrypted_file", false, true, true),
            input("os_keystore", false, false, true),
            input("encrypted_file", true, false, true),
            input("in_memory", false, false, false),
            input("platform", false, false, true),
        ];
        let mut codes = Vec::new();
        for i in rejected {
            let Err(e) = parse_custody_request(i) else {
                unreachable!("{i:?} must be rejected");
            };
            assert!(e.to_string().contains(ACCEPTED_CUSTODY), "{e}");
            codes.push(e.code());
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(
            codes.len(),
            5,
            "each rejection variant is covered: {codes:?}"
        );
    }

    /// An unrecognized request is echoed, bounded to 64 characters.
    #[test]
    fn parse_custody_request_bounds_the_echoed_request() {
        let long = "x".repeat(10_000);
        let Err(e) = parse_custody_request(input(&long, false, false, true)) else {
            unreachable!("a 10 000-character request must be rejected");
        };
        assert_eq!(
            e,
            CustodyRequestError::Unrecognized {
                request: "x".repeat(ECHO_LIMIT_CHARS)
            }
        );
        assert!(e.to_string().len() < ACCEPTED_CUSTODY.len() + 128, "{e}");
    }

    /// Each value round-trips through its request string, and the strings are
    /// the ones §3.2.2 names.
    #[test]
    fn custody_request_as_str_round_trips_through_lookup() {
        let names: Vec<&str> = CustodyRequest::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names, ["encrypted_file", "os_keystore", "in_memory"]);
        for r in CustodyRequest::ALL {
            assert_eq!(CustodyRequest::lookup(r.as_str()), Some(r));
        }
    }
}
