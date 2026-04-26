import Foundation
@testable import SCP
import XCTest

/// SCP-OUT-031 — Swift OutletError sealed-hierarchy + fixture round-trip.
final class OutletErrorConformanceTests: XCTestCase {
    // MARK: - Sealed-hierarchy structure

    func testEightSealedHierarchyCases() throws {
        for errorClass in OutletErrorClass.allCases {
            try roundTripEnvelope(for: errorClass)
        }
    }

    private func roundTripEnvelope(for errorClass: OutletErrorClass) throws {
        let outletId = try OutletId("outlet-1")
        let slug = canonicalSlug(for: errorClass)
        let catalogKey = try CatalogKey(slug)
        let err = try OutletError.new(
            outletId: outletId,
            catalogKey: catalogKey,
            class: errorClass,
            retry: .never,
            detail: nil
        )
        XCTAssertEqual(envelope(of: err)?.classWire, errorClass)
    }

    private func canonicalSlug(for errorClass: OutletErrorClass) -> String {
        switch errorClass {
        case .protocol: return "protocol.violation"
        case .authorization: return "authorization.denied"
        case .input: return "input.schema-violation"
        case .execution: return "execution.handler-panic"
        case .output: return "output.schema-violation"
        case .economic: return "economic.insufficient-funds"
        case .transport: return "transport.relay-unavailable"
        case .governance: return "governance.outlet-deregistered"
        }
    }

    private func envelope(of error: OutletError) -> OutletEnvelope? {
        switch error {
        case let .protocol(env), let .authorization(env), let .input(env),
             let .execution(env), let .output(env), let .economic(env),
             let .transport(env), let .governance(env):
            return env
        default:
            return nil
        }
    }

    // MARK: - Credit / CatalogKey newtypes

    func testCreditFactoryAcceptsPositive() throws {
        let creditOne = try Credit(1)
        XCTAssertEqual(creditOne.raw, 1)
        let creditMax = try Credit(UInt32.max)
        XCTAssertEqual(creditMax.raw, UInt32.max)
    }

    func testCreditFactoryRejectsZeroWithInvalidGrant() {
        do {
            _ = try Credit(0)
            XCTFail("Credit(0) should have thrown")
        } catch let error as OutletError {
            switch error {
            case let .invalidGrant(credit):
                XCTAssertEqual(credit.raw, 0)
            default:
                XCTFail("Expected invalidGrant case, got \(error)")
            }
        } catch {
            XCTFail("Expected OutletError, got \(error)")
        }
    }

    func testCatalogKeyFactoryRejectsMalformed() {
        XCTAssertThrowsError(try CatalogKey("Authorization.Denied"))
        XCTAssertThrowsError(try CatalogKey(""))
        XCTAssertNoThrow(try CatalogKey("authorization.denied"))
    }

    // MARK: - PII redaction

    func testRedactPiiEmail() {
        let raw = "denied for user@example.com world"
        let out = redactPII(raw)
        XCTAssertFalse(out.contains("user@example.com"))
        XCTAssertTrue(out.contains("[redacted]"))
    }

    func testRedactPiiDID() {
        let raw = "acting as did:dht:abc.123_xyz here"
        let out = redactPII(raw)
        XCTAssertFalse(out.contains("did:dht:"))
        XCTAssertTrue(out.contains("[redacted]"))
    }

    // MARK: - Per-class detail-shape conformance

    func testDetailShapeMismatchRejected() throws {
        let outletId = try OutletId("o1")
        let catalogKey = try CatalogKey("authorization.denied")
        XCTAssertThrowsError(
            try OutletEnvelope.makeForCreation(
                outletId: outletId,
                catalogKey: catalogKey,
                classWire: .authorization,
                retry: .never,
                detail: .protocolRule(rule: "wrong-class-detail")
            )
        )
    }

    // MARK: - Fixture round-trip

    func testFixtureSetHasAtLeast30Entries() throws {
        let fixtures = try loadFixtures()
        XCTAssertGreaterThanOrEqual(fixtures.count, 30)
    }

    func testEveryFixtureRoundTrips() throws {
        let fixtures = try loadFixtures()
        for fixture in fixtures {
            let env = try fixtureToEnvelope(fixture)
            XCTAssertEqual(env.code, fixture.code)
            XCTAssertEqual(env.slug, fixture.slug)
            XCTAssertEqual(env.classWire.rawValue, fixture.classString)
        }
    }

    func testPiiRedactionAppliesToFixture() throws {
        let fixtures = try loadFixtures()
        let pii = fixtures.first { $0.name == "redaction-pii-email-and-did" }
        XCTAssertNotNil(pii)
        guard let piiFixture = pii else { return }
        let env = try fixtureToEnvelope(piiFixture)
        XCTAssertFalse(env.message.contains("user@example.com"))
        XCTAssertFalse(env.message.contains("did:dht:"))
        XCTAssertTrue(env.message.contains("[redacted]"))
    }

    // MARK: - Fixture loader (internal)

    private struct Fixture: Decodable {
        let name: String
        let code: String
        let slug: String
        let `class`: String
        let message: String

        var classString: String {
            `class`
        }
    }

    private func loadFixtures() throws -> [Fixture] {
        let url = fixtureURL()
        let data = try Data(contentsOf: url)
        struct Outer: Decodable { let fixtures: [Fixture] }
        return try JSONDecoder().decode(Outer.self, from: data).fixtures
    }

    private func fixtureURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 8 {
            url.deleteLastPathComponent()
            let candidate = url.appendingPathComponent(
                "tests/conformance/vectors/outlet_error_fixtures.json"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return URL(
            fileURLWithPath: "tests/conformance/vectors/outlet_error_fixtures.json"
        )
    }

    private func fixtureToEnvelope(_ fixture: Fixture) throws -> OutletEnvelope {
        guard let errorClass = OutletErrorClass(rawValue: fixture.classString) else {
            XCTFail("unknown class \(fixture.classString) in fixture \(fixture.name)")
            throw NSError(domain: "OutletErrorConformance", code: 1)
        }
        return OutletEnvelope(
            classWire: errorClass,
            code: fixture.code,
            slug: fixture.slug,
            message: fixture.message,
            retry: .never,
            detail: nil,
            sourceChain: [],
            padNonce: nil,
            registrationEventId: nil
        )
    }
}
