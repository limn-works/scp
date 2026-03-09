import Foundation
@testable import SCP
import Testing

// MARK: - Discovery Tests

/// Tests for discovery operations: address parsing, query creation, and
/// address normalization via injectable bridge closures.
///
/// See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).
struct DiscoveryTests {
    // MARK: - parseAddress via injectable bridge (roundtrip)

    @Test("parseAddress calls bridge and returns parsed JSON")
    func parseAddressRoundtrip() throws {
        var receivedAddress: String?

        let mockParse: DiscoveryBridge.ParseAddressFn = { address in
            receivedAddress = address
            return #"{"type":"discovery_handle","handle":"alice","community":"cooking"}"#
        }

        let result = try parseAddress(
            address: "alice@cooking",
            parseAddressFn: mockParse
        )

        #expect(receivedAddress == "alice@cooking")
        #expect(result.contains("discovery_handle"))
        #expect(result.contains("alice"))
    }

    @Test("parseAddress propagates bridge errors")
    func parseAddressError() throws {
        let mockParse: DiscoveryBridge.ParseAddressFn = { _ in
            throw ScpError.Validation(
                message: "malformed address",
                code: "SCP-VALID-7100"
            )
        }

        do {
            _ = try parseAddress(address: "!!invalid!!", parseAddressFn: mockParse)
            Issue.record("Expected parseAddress to throw")
        } catch {
            #expect(error is ScpError)
        }
    }

    // MARK: - createDiscoveryQuery via injectable bridge (roundtrip)

    @Test("createDiscoveryQuery calls bridge with parameters")
    func createDiscoveryQueryRoundtrip() throws {
        var receivedCapabilities: [String]?
        var receivedKeywords: [String]?
        var receivedMinHistory: UInt64?

        let mockCreate: DiscoveryBridge.CreateQueryFn = { capabilities, keywords, minHistorySecs in
            receivedCapabilities = capabilities
            receivedKeywords = keywords
            receivedMinHistory = minHistorySecs
            return #"{"capabilities":["messages:write"],"keywords":["test"]}"#
        }

        let result = try createDiscoveryQuery(
            capabilities: ["messages:write"],
            keywords: ["test"],
            minHistorySecs: 3600,
            createQueryFn: mockCreate
        )

        #expect(receivedCapabilities == ["messages:write"])
        #expect(receivedKeywords == ["test"])
        #expect(receivedMinHistory == 3600)
        #expect(result.contains("messages:write"))
    }

    @Test("createDiscoveryQuery works with nil parameters")
    func createDiscoveryQueryNilParams() throws {
        let mockCreate: DiscoveryBridge.CreateQueryFn = { _, _, _ in
            #"{"capabilities":null,"keywords":null}"#
        }

        let result = try createDiscoveryQuery(createQueryFn: mockCreate)
        #expect(!result.isEmpty)
    }

    // MARK: - normalizeAddress via injectable bridge (roundtrip)

    @Test("normalizeAddress calls bridge and returns normalized string")
    func normalizeAddressRoundtrip() {
        var receivedAddress: String?

        let mockNormalize: DiscoveryBridge.NormalizeAddressFn = { address in
            receivedAddress = address
            return address.lowercased().trimmingCharacters(in: .whitespaces)
        }

        let result = normalizeAddress(
            address: "  ALICE@Cooking  ",
            normalizeAddressFn: mockNormalize
        )

        #expect(receivedAddress == "  ALICE@Cooking  ")
        #expect(result == "alice@cooking")
    }

    // MARK: - discover via injectable bridge (roundtrip)

    @Test("discover calls bridge and returns JSON results")
    func discoverRoundtrip() async throws {
        var receivedQuery: String?

        let mockDiscover: DiscoveryBridge.DiscoverFn = { query in
            receivedQuery = query
            return """
            [{"context_id":"ctx-001","relay_urls":["wss://relay.example"],"publisher_did":"did:dht:z6Mk","discovery_source":"dht","mode":null,"metadata_summary":null}]
            """
        }

        let result = try await discover(
            query: "did:dht:z6MkBob",
            discoverFn: mockDiscover
        )

        #expect(receivedQuery == "did:dht:z6MkBob")
        #expect(result.contains("ctx-001"))
        #expect(result.contains("relay.example"))
    }

    @Test("discover default throws descriptive error")
    func discoverDefaultThrows() async {
        do {
            _ = try await discover(query: "did:dht:z6MkBob")
            Issue.record("Expected discover to throw")
        } catch {
            #expect(error is ScpError)
        }
    }

    @Test("discover propagates bridge errors")
    func discoverError() async {
        let mockDiscover: DiscoveryBridge.DiscoverFn = { _ in
            throw ScpError.Context(
                message: "DID resolution failed",
                code: "SCP-CTX-2050"
            )
        }

        do {
            _ = try await discover(query: "invalid-query", discoverFn: mockDiscover)
            Issue.record("Expected discover to throw")
        } catch {
            #expect(error is ScpError)
        }
    }
} // end DiscoveryTests
