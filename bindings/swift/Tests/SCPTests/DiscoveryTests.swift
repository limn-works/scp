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
            return #"{"type":"DiscoveryHandle","handle":"alice","community":"cooking"}"#
        }

        let result = try parseAddress(
            address: "alice@cooking",
            parseAddressFn: mockParse
        )

        #expect(receivedAddress == "alice@cooking")
        #expect(result.contains("DiscoveryHandle"))
        #expect(result.contains("alice"))
    }

    @Test("parseAddress propagates bridge errors")
    func parseAddressError() throws {
        let mockParse: DiscoveryBridge.ParseAddressFn = { _ in
            throw ScpError.Validation(
                msg: "malformed address",
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

    // discover now delegates to the real UniFFI bridge (contextDiscover).
    // The "default throws" test has been removed — the injected-mock
    // roundtrip test above covers SDK logic.

    @Test("discover propagates bridge errors")
    func discoverError() async {
        let mockDiscover: DiscoveryBridge.DiscoverFn = { _ in
            throw ScpError.Context(
                msg: "DID resolution failed",
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

// MARK: - Scope Registry Tests (§22.3.5, ADR-043)

/// Tests for scope registry operations via injectable bridge closures.
struct ScopeRegistryTests {
    @Test("registerScope calls bridge and returns result JSON")
    func registerScopeRoundtrip() throws {
        var capturedScopeContextId: String?
        var capturedName: String?

        let mockRegister: DiscoveryBridge.ScopeRegisterFn = { scopeCtxId, name, _, _, _, _, _ in
            capturedScopeContextId = scopeCtxId
            capturedName = name
            return #"{"status":"registered","entry_id":"scope-1"}"#
        }

        let result = try registerScope(
            scopeContextId: "test-ctx",
            name: "my-scope",
            targetContextId: "target-ctx",
            relayUrls: ["wss://relay.example.com"],
            registrantDid: "did:dht:zTest",
            scopeRegisterFn: mockRegister
        )

        #expect(capturedScopeContextId == "test-ctx")
        #expect(capturedName == "my-scope")
        #expect(result.contains("registered"))
        #expect(result.contains("scope-1"))
    }

    @Test("lookupScope calls bridge and returns results JSON")
    func lookupScopeRoundtrip() throws {
        var capturedName: String?

        let mockLookup: DiscoveryBridge.ScopeLookupFn = { _, name in
            capturedName = name
            return #"{"results":[{"name":"my-scope","target":{"context_id":"target-ctx","relay_urls":["wss://relay.example.com"]},"owner_did":"did:dht:zTest","registered_at":1700000000,"metadata":{"description":null,"tags":null},"entry_id":"scope-1"}]}"#
        }

        let result = try lookupScope(
            scopeContextId: "test-ctx",
            name: "my-scope",
            scopeLookupFn: mockLookup
        )

        #expect(capturedName == "my-scope")
        #expect(result.contains("my-scope"))
        #expect(result.contains("target-ctx"))
    }

    @Test("deregisterScope calls bridge and returns removed status")
    func deregisterScopeRoundtrip() throws {
        var capturedDid: String?

        let mockDeregister: DiscoveryBridge.ScopeDeregisterFn = { _, _, did in
            capturedDid = did
            return #"{"removed":true}"#
        }

        let result = try deregisterScope(
            scopeContextId: "test-ctx",
            name: "my-scope",
            did: "did:dht:zTest",
            scopeDeregisterFn: mockDeregister
        )

        #expect(capturedDid == "did:dht:zTest")
        #expect(result.contains("true"))
    }

    @Test("scope register/lookup/deregister round-trip with mock bridge")
    func scopeFullRoundtrip() throws {
        // Register
        let regResult = try registerScope(
            scopeContextId: "rt-ctx",
            name: "roundtrip-scope",
            targetContextId: "target-ctx",
            relayUrls: ["wss://relay.example.com"],
            registrantDid: "did:dht:zRoundtrip",
            scopeRegisterFn: { _, _, _, _, _, _, _ in
                #"{"status":"registered","entry_id":"scope-42"}"#
            }
        )
        #expect(regResult.contains("registered"))

        // Lookup
        let lookupResult = try lookupScope(
            scopeContextId: "rt-ctx",
            name: "roundtrip-scope",
            scopeLookupFn: { _, _ in
                #"{"results":[{"name":"roundtrip-scope","target":{"context_id":"target-ctx","relay_urls":["wss://relay.example.com"]},"owner_did":"did:dht:zRoundtrip","registered_at":1700000000,"metadata":{"description":null,"tags":null},"entry_id":"scope-42"}]}"#
            }
        )
        #expect(lookupResult.contains("roundtrip-scope"))

        // Deregister
        let deregResult = try deregisterScope(
            scopeContextId: "rt-ctx",
            name: "roundtrip-scope",
            did: "did:dht:zRoundtrip",
            scopeDeregisterFn: { _, _, _ in #"{"removed":true}"# }
        )
        #expect(deregResult.contains("true"))
    }
} // end ScopeRegistryTests
