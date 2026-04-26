import Foundation
import Testing

/// Outlet capability stem parser conformance (SCP-OUT-014).
///
/// Loads `tests/conformance/vectors/outlet_capability_parse.json` and
/// asserts every positive vector parses to the expected variant and every
/// negative vector rejects to `nil`. The fixture is identical across
/// bridges \u2014 divergence between the Swift wrapper and the Rust core
/// would mean a parser-differential authorization bug.
///
/// Spec references:
/// - `.docs/specs/05-contexts.md` \u00a75.4.2.1 UCAN Capability Stem Parser
/// - `.docs/adrs/ADR-049-outlet-redesign.md` \u00a71 Rename hard break, \u00a72
struct OutletCapabilityParseConformance {
    private struct ExpectedPositive: Decodable {
        let kind: String
        let id: String?
        let name: String?
    }

    private struct PositiveVector: Decodable {
        let input: String
        let expected: ExpectedPositive
    }

    private struct NegativeVector: Decodable {
        let input: String
        let reason: String
    }

    private struct Fixture: Decodable {
        let version: String
        let story: String
        let positive: [PositiveVector]
        let negative: [NegativeVector]
    }

    private enum Parsed: Equatable {
        case messagesRead
        case messagesWrite
        case outletQuery(String)
        case outletQueryAll
        case outletCall(String)
        case outletCallAll
        case outletRegister
        case memberInvite
        case memberRemove
        case roleAssign
        case governancePropose
        case governanceVote
        case contextClose
        case childContextCreate
        case outletInterface
        case bridging
        case mediaVoice
        case mediaVideo
        case mediaScreenShare
        case memberBan
        case metadataEdit
        case custom(String)
    }

    // swiftlint:disable cyclomatic_complexity function_body_length for_where trailing_comma
    /// Reference Swift implementation of `Capability::new` from the Rust
    /// core. Mirrors the \u00a75.4.2.1 two-step parser and the ADR-049 \u00a71
    /// hard-break rejection set.
    private static func parseCapability(_ name: String) -> Parsed? {
        if name.hasPrefix("outlet:invoke:") || name.hasPrefix("outlet_invoke:") {
            return nil
        }
        if name == "outlet:invoke:*" || name == "outlet_invoke:*" {
            return nil
        }
        if name.hasPrefix("tool:invoke:") || name.hasPrefix("tool_invoke:") {
            return nil
        }
        if name == "tool:register" || name == "tool:interface"
            || name == "tool_register" || name == "tool_interface" {
            return nil
        }

        switch name {
        case "messages:read": return .messagesRead
        case "messages:write": return .messagesWrite
        case "outlet:query:*", "outlet_query:*": return .outletQueryAll
        case "outlet:call:*", "outlet_call:*": return .outletCallAll
        case "outlet:register": return .outletRegister
        case "member:invite": return .memberInvite
        case "member:remove": return .memberRemove
        case "role:assign": return .roleAssign
        case "governance:propose": return .governancePropose
        case "governance:vote": return .governanceVote
        case "context:close": return .contextClose
        case "context:child:create": return .childContextCreate
        case "outlet:interface": return .outletInterface
        case "bridging": return .bridging
        case "media:voice": return .mediaVoice
        case "media:video": return .mediaVideo
        case "media:screen_share": return .mediaScreenShare
        case "member:ban": return .memberBan
        case "metadata:edit": return .metadataEdit
        default: break
        }

        let prefixes: [(String, (String) -> Parsed)] = [
            ("outlet:query:", { .outletQuery($0) }),
            ("outlet_query:", { .outletQuery($0) }),
            ("outlet:call:", { .outletCall($0) }),
            ("outlet_call:", { .outletCall($0) }),
        ]
        for (prefix, makeKind) in prefixes {
            if name.hasPrefix(prefix) {
                let suffix = String(name.dropFirst(prefix.count))
                guard isValidOutletSuffix(suffix) else { return nil }
                return makeKind(suffix)
            }
        }

        if name.hasPrefix("custom:") {
            return .custom(String(name.dropFirst("custom:".count)))
        }
        return .custom(name)
    }

    private static func isValidOutletSuffix(_ suffix: String) -> Bool {
        let bytes = Array(suffix.utf8)
        guard !bytes.isEmpty, bytes.count <= 128 else { return false }
        for byte in bytes {
            let isLower = (0x61 ... 0x7A).contains(byte) // a-z
            let isDigit = (0x30 ... 0x39).contains(byte) // 0-9
            let isUS = byte == 0x5F // _
            let isDash = byte == 0x2D // -
            if !(isLower || isDigit || isUS || isDash) { return false }
        }
        return true
    }

    private static func locateFixture() -> URL {
        // Tests run with cwd at bindings/swift; fixture lives at the repo root
        // under tests/conformance/vectors. We walk up from #file to find it.
        let here = URL(fileURLWithPath: #file).deletingLastPathComponent() // Conformance
            .deletingLastPathComponent() // SCPTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // swift
            .deletingLastPathComponent() // bindings
        return here
            .appendingPathComponent("tests")
            .appendingPathComponent("conformance")
            .appendingPathComponent("vectors")
            .appendingPathComponent("outlet_capability_parse.json")
    }

    private static func loadFixture() throws -> Fixture {
        let url = locateFixture()
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Fixture.self, from: data)
    }

    // swiftlint:enable cyclomatic_complexity function_body_length for_where trailing_comma

    // swiftlint:disable cyclomatic_complexity
    private static func expectedToParsed(_ expected: ExpectedPositive) -> Parsed {
        switch expected.kind {
        case "MessagesRead": return .messagesRead
        case "MessagesWrite": return .messagesWrite
        case "OutletQuery": return .outletQuery(expected.id ?? "")
        case "OutletQueryAll": return .outletQueryAll
        case "OutletCall": return .outletCall(expected.id ?? "")
        case "OutletCallAll": return .outletCallAll
        case "OutletRegister": return .outletRegister
        case "MemberInvite": return .memberInvite
        case "MemberRemove": return .memberRemove
        case "RoleAssign": return .roleAssign
        case "GovernancePropose": return .governancePropose
        case "GovernanceVote": return .governanceVote
        case "ContextClose": return .contextClose
        case "ChildContextCreate": return .childContextCreate
        case "OutletInterface": return .outletInterface
        case "Bridging": return .bridging
        case "MediaVoice": return .mediaVoice
        case "MediaVideo": return .mediaVideo
        case "MediaScreenShare": return .mediaScreenShare
        case "MemberBan": return .memberBan
        case "MetadataEdit": return .metadataEdit
        case "Custom": return .custom(expected.name ?? "")
        default: fatalError("unknown expected kind: \(expected.kind)")
        }
    }

    // swiftlint:enable cyclomatic_complexity

    @Test func fixtureLoadsAndCardinality() throws {
        let fixture = try Self.loadFixture()
        #expect(fixture.story == "SCP-OUT-014")
        #expect(fixture.positive.count >= 20)
        #expect(fixture.negative.count >= 20)
    }

    @Test func positiveVectorsParse() throws {
        let fixture = try Self.loadFixture()
        for vector in fixture.positive {
            let actual = Self.parseCapability(vector.input)
            let expected = Self.expectedToParsed(vector.expected)
            #expect(actual == expected, "positive fixture failed for \(vector.input)")
        }
    }

    @Test func negativeVectorsReject() throws {
        let fixture = try Self.loadFixture()
        for vector in fixture.negative {
            let actual = Self.parseCapability(vector.input)
            #expect(actual == nil, "negative fixture must reject \(vector.input) (\(vector.reason))")
        }
    }

    @Test func hardBreakOutletInvokeDeleted() {
        #expect(Self.parseCapability("outlet:invoke:*") == nil)
        #expect(Self.parseCapability("outlet_invoke:*") == nil)
        #expect(Self.parseCapability("outlet:invoke:foo") == nil)
        #expect(Self.parseCapability("outlet_invoke:bar") == nil)
    }

    @Test func hardBreakToolInvokePreRenameRejected() {
        #expect(Self.parseCapability("tool:invoke:*") == nil)
        #expect(Self.parseCapability("tool_invoke:*") == nil)
        #expect(Self.parseCapability("tool:invoke:calculator") == nil)
        #expect(Self.parseCapability("tool:register") == nil)
        #expect(Self.parseCapability("tool:interface") == nil)
    }
}
