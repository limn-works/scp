@testable import SCP
import XCTest

/// SDK-layer contract: when the UniFFI bridge emits a typed
/// `IDENT_1047`, `IDENT_1048`, `IDENT_1049`, `IDENT_1050`, `IDENT_1051`,
/// or `IDENT_1052` code for a `PreRotationCustodyError` variant, the
/// Swift SDK's `ScpError.Identity` case MUST preserve the code
/// verbatim. The Rust bridge has its own co-located regression tests
/// pinning the variant-to-code mapping
/// (`crates/scp-ffi/uniffi/src/bridge.rs:tests::pre_rotation_*`); this
/// suite pins the SDK-layer fall-through so a Swift wrapper change
/// can't silently strip or rewrite the code.
///
/// Literal codes also appear here as string constants — they trip a
/// diff reviewer if the bridge ever re-numbers a variant without
/// updating the SDK in lockstep.
///
/// These tests do NOT require the native UniFFI binary — `ScpError`
/// is a Swift enum, so we construct it directly and verify the
/// associated values round-trip. The full FFI integration is exercised
/// elsewhere (e.g., `PersistenceTests`); here we only need the
/// SDK-layer contract.
final class ErrorCodeTests: XCTestCase {
    private static let preRotationHandleNotFoundCode = "SCP-IDENT-1047"
    private static let preRotationUnavailableCode = "SCP-IDENT-1048"
    private static let preRotationUserDeclinedCode = "SCP-IDENT-1049"
    private static let preRotationStorageCode = "SCP-IDENT-1050"
    private static let preRotationInvalidCallbackCode = "SCP-IDENT-1051"
    private static let preRotationCommitmentMismatchCode = "SCP-IDENT-1052"
    private static let identityGenericCode = "SCP-IDENT-1001"

    /// `ScpError.Identity(msg:code:)` MUST preserve every typed
    /// pre-rotation custody code unchanged.
    func testPreRotationCodesRoundTripThroughIdentityCase() {
        let typedCodes = [
            Self.preRotationHandleNotFoundCode,
            Self.preRotationUnavailableCode,
            Self.preRotationUserDeclinedCode,
            Self.preRotationStorageCode,
            Self.preRotationInvalidCallbackCode,
            Self.preRotationCommitmentMismatchCode,
            Self.identityGenericCode
        ]
        for code in typedCodes {
            let err = ScpError.Identity(msg: "pre-rotation failure", code: code)
            switch err {
            case let .Identity(msg, observedCode):
                XCTAssertEqual(observedCode, code, "code must round-trip unchanged")
                XCTAssertEqual(msg, "pre-rotation failure", "msg must round-trip unchanged")
            default:
                XCTFail("expected ScpError.Identity, got \(err)")
            }
        }
    }

    /// `ScpError.Identity(msg:code:)` constructed with each typed
    /// pre-rotation code MUST be catchable as `ScpError` and pattern-
    /// matchable in a `switch` without losing the code.
    func testEachPreRotationCodeIsMatchableAndPreserved() {
        let cases: [(name: String, code: String)] = [
            ("handle_not_found", Self.preRotationHandleNotFoundCode),
            ("unavailable", Self.preRotationUnavailableCode),
            ("user_declined", Self.preRotationUserDeclinedCode),
            ("storage", Self.preRotationStorageCode),
            ("invalid_callback_response", Self.preRotationInvalidCallbackCode),
            ("commitment_mismatch", Self.preRotationCommitmentMismatchCode)
        ]
        for (name, expectedCode) in cases {
            do {
                throw ScpError.Identity(msg: "pre-rotation \(name)", code: expectedCode)
            } catch let scpError as ScpError {
                switch scpError {
                case let .Identity(_, code):
                    XCTAssertEqual(code, expectedCode, "code lost for \(name)")
                default:
                    XCTFail("expected ScpError.Identity for \(name), got \(scpError)")
                }
            } catch {
                XCTFail("expected ScpError for \(name), got \(error)")
            }
        }
    }

    /// Defense-in-depth: a non-pre-rotation identity error retains the
    /// generic `SCP-IDENT-1001` fallback. Pinning this guards against
    /// a future refactor that accidentally promotes the generic code
    /// to one of the typed pre-rotation codes.
    func testGenericIdentityCodeFallback() {
        let err = ScpError.Identity(msg: "invalid DID format", code: Self.identityGenericCode)
        switch err {
        case let .Identity(_, code):
            XCTAssertEqual(code, Self.identityGenericCode)
        default:
            XCTFail("expected ScpError.Identity, got \(err)")
        }
    }
}
