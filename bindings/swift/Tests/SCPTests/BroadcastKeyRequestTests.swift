@testable import SCP
import XCTest

/// The requester wrapping key of a broadcast key request (spec §5.14.2, §9.5)
/// is a 65-byte uncompressed P-256 point. Any other value is a caller-input
/// error that every SDK reports as the same validation class with code
/// `SCP-VALID-7007`.
///
/// The suite links the Rust binary built with `testing` and calls
/// `Context.broadcastHandleKeyRequest` against the real engine, so a bridge
/// that mapped the error to another class or code fails here.
final class BroadcastKeyRequestTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    private static let invalidFormatCode = "SCP-VALID-7007"

    /// The uncompressed P-256 base point G (SEC 2 §2.4.2), a valid point.
    private static let p256G: Data = {
        let hex = "04"
            + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index ..< next], radix: 16) ?? 0)
            index = next
        }
        return Data(bytes)
    }()

    override func setUpWithError() throws {
        try super.setUpWithError()
        scp = try SCP(storage: .inMemory)
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    private func makeBroadcastParams() -> ContextParams {
        ContextParams(
            mode: .broadcast,
            ceiling: ["messages:read"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .full,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil,
            consequenceRulesJson: nil,
            consequenceConfigJson: nil
        )
    }

    /// A 64-byte key (the point without its `0x04` tag) and a 65-byte value
    /// off the curve each throw `ScpError.Validation` with `SCP-VALID-7007`. A
    /// valid point, the positive control, is granted the sealed key.
    func testWrappingKeyThatIsNotAP256PointIsAValidationErrorWithValid7007() async throws {
        XCTAssertEqual(Self.p256G.count, 65)
        let author = try await scp.identityCreate(custody: "in_memory")
        let subscriber = try await scp.identityCreate(custody: "in_memory")
        let ctx = try await Context.create(scp: scp, identity: author, params: makeBroadcastParams())
        try await ctx.broadcastSubscribe(subscriberDid: subscriber.did())

        var offCurve = Data(count: 65)
        offCurve[0] = 0x04
        let cases: [(String, Data)] = [
            ("64 bytes", Self.p256G.subdata(in: 1 ..< 65)),
            ("off curve", offCurve)
        ]
        for (name, key) in cases {
            do {
                _ = try await ctx.broadcastHandleKeyRequest(
                    authorDid: author.did(),
                    requesterDid: subscriber.did(),
                    wrappingPubkey: key
                )
                XCTFail("\(name): expected ScpError.Validation")
            } catch let ScpError.Validation(msg, code) {
                XCTAssertEqual(code, Self.invalidFormatCode, name)
                XCTAssertTrue(
                    msg.contains("must be a 65-byte uncompressed P-256 point"),
                    "\(name): \(msg)"
                )
            } catch {
                XCTFail("\(name): expected ScpError.Validation, got \(error)")
            }
        }

        let sealed = try await ctx.broadcastHandleKeyRequest(
            authorDid: author.did(),
            requesterDid: subscriber.did(),
            wrappingPubkey: Self.p256G
        )
        XCTAssertNotNil(sealed, "a registered subscriber with a valid wrapping key is granted the key")
    }
}
