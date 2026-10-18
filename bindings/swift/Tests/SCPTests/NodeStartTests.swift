#if os(macOS)
    import Foundation
    @testable import SCP
    import Testing

    // `scp.nodeStart(config:)` (SCP-325): the config's wire shape against the
    // bridge fixture, delegation to the UniFFI `node_start` export, the error
    // each sdk-common.md §"Node start error codes" row throws, and the absence
    // of node start from an iOS build.
    //
    // The fixture `crates/scp-ffi/common/tests/fixtures/node_start_config.json`
    // is the one the Python SDK's tests read. The `node_start_config.rs` unit
    // tests check it against the Rust types, so a field or arm added, renamed or
    // made optional in Rust fails there until the fixture follows, and fails
    // here until the Swift encoding below follows.

    // MARK: - Fixture and encoding

    /// `bindings/swift`, the package root.
    private let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // SCPTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // bindings/swift

    private let repoRoot = packageRoot
        .deletingLastPathComponent() // bindings
        .deletingLastPathComponent()

    private struct FixtureError: Error, CustomStringConvertible {
        let description: String
    }

    /// The bridge's wire-shape fixture as a JSON object.
    private func loadWire() throws -> [String: Any] {
        let url = repoRoot.appendingPathComponent(
            "crates/scp-ffi/common/tests/fixtures/node_start_config.json"
        )
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        guard let wire = object as? [String: Any] else {
            throw FixtureError(description: "node_start_config.json is not a JSON object")
        }
        return wire
    }

    private func object(_ value: Any?, _ what: String) throws -> [String: Any] {
        guard let object = value as? [String: Any] else {
            throw FixtureError(description: "\(what) is not a JSON object")
        }
        return object
    }

    private func strings(_ value: Any?, _ what: String) throws -> [String] {
        guard let strings = value as? [String] else {
            throw FixtureError(description: "\(what) is not a list of strings")
        }
        return strings
    }

    /// `value` as canonical JSON text, so two encodings compare as strings.
    private func canonical(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(
            withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]
        )
        guard let text = String(bytes: data, encoding: .utf8) else {
            throw FixtureError(description: "JSONSerialization wrote bytes that are not UTF-8")
        }
        return text
    }

    /// `camelCase` as `snake_case`.
    private func snakeCase(_ name: String) -> String {
        name.reduce(into: "") { out, char in
            if char.isUppercase {
                out += "_" + char.lowercased()
            } else {
                out.append(char)
            }
        }
    }

    private func orNull(_ value: Any?) -> Any {
        value ?? NSNull()
    }

    // The wire form of each arm. Each switch is exhaustive, so an arm the
    // regenerated bindings add stops this file compiling until it is encoded.

    private func wire(_ reach: FfiReach) -> [String: Any] {
        switch reach {
        case let .domain(domain): ["kind": "domain", "domain": domain]
        case .natTraversal: ["kind": "nat_traversal"]
        case .local: ["kind": "local"]
        }
    }

    private func wire(_ blob: FfiBlobBackend) -> [String: Any] {
        switch blob {
        case .inMemory: ["kind": "in_memory"]
        case let .redb(path): ["kind": "redb", "path": path]
        case let .sqlite(path): ["kind": "sqlite", "path": path]
        }
    }

    private func wire(_ tls: FfiTlsMode) -> [String: Any] {
        switch tls {
        case .selfSigned: ["kind": "self_signed"]
        case let .acme(email): ["kind": "acme", "email": orNull(email)]
        case .plaintext: ["kind": "plaintext"]
        case .terminated: ["kind": "terminated"]
        }
    }

    private func wire(_ dht: FfiDhtMode) -> [String: Any] {
        switch dht {
        case .disabled: ["kind": "disabled"]
        }
    }

    private func wire(_ cors: FfiCorsOrigins) -> [String: Any] {
        switch cors {
        case .anyOrigin: ["kind": "any_origin"]
        case let .allowlist(origins): ["kind": "allowlist", "origins": origins]
        }
    }

    private func wire(_ nat: FfiNat) -> [String: Any] {
        switch nat {
        case .auto: ["kind": "auto"]
        }
    }

    /// The JSON object the bridge's `NodeStartConfig::from_json` reads for
    /// `config`: the PyO3 and napi-rs wire form, with the identity lowered to
    /// its DID, as the UniFFI bridge's `lower_node_start_config` lowers it.
    private func wire(_ config: NodeStartConfig) -> [String: Any] {
        [
            "reach": wire(config.reach),
            "identity": config.identity.did(),
            "blob_storage": wire(config.blobStorage),
            "tls": wire(config.tls),
            "dht": wire(config.dht),
            "cors_origins": wire(config.corsOrigins),
            "bind_addr": orNull(config.bindAddr),
            "http_bind_addr": orNull(config.httpBindAddr),
            "nat": orNull(config.nat.map(wire)),
            "projection_rate_limit": orNull(config.projectionRateLimit.map { Int($0) })
        ]
    }

    /// The Swift arm each fixture `field.kind` names, built from the entry's
    /// fields.
    private let armBuilders: [String: ([String: Any]) -> Any] = [
        "reach.domain": { FfiReach.domain(domain: $0["domain"] as? String ?? "") },
        "reach.nat_traversal": { _ in FfiReach.natTraversal },
        "reach.local": { _ in FfiReach.local },
        "blob_storage.in_memory": { _ in FfiBlobBackend.inMemory },
        "blob_storage.redb": { FfiBlobBackend.redb(path: $0["path"] as? String ?? "") },
        "blob_storage.sqlite": { FfiBlobBackend.sqlite(path: $0["path"] as? String ?? "") },
        "tls.self_signed": { _ in FfiTlsMode.selfSigned },
        "tls.acme": { FfiTlsMode.acme(email: $0["email"] as? String) },
        "tls.plaintext": { _ in FfiTlsMode.plaintext },
        "tls.terminated": { _ in FfiTlsMode.terminated },
        "dht.disabled": { _ in FfiDhtMode.disabled },
        "cors_origins.any_origin": { _ in FfiCorsOrigins.anyOrigin },
        "cors_origins.allowlist": { FfiCorsOrigins.allowlist(origins: $0["origins"] as? [String] ?? []) },
        "nat.auto": { _ in FfiNat.auto }
    ]

    /// The Swift arm a fixture entry of sum-typed `field` describes. An entry
    /// whose `kind` Swift has no arm for throws.
    private func arm(_ field: String, _ entry: [String: Any]) throws -> Any {
        let kind = entry["kind"] as? String ?? ""
        guard let build = armBuilders["\(field).\(kind)"] else {
            throw FixtureError(description: "Swift has no \(field) arm of kind \(kind)")
        }
        return build(entry)
    }

    /// The wire form of `value`, an arm of sum-typed `field`.
    private func wireArm(_ field: String, _ value: Any) throws -> [String: Any] {
        switch value {
        case let reach as FfiReach where field == "reach": return wire(reach)
        case let blob as FfiBlobBackend where field == "blob_storage": return wire(blob)
        case let tls as FfiTlsMode where field == "tls": return wire(tls)
        case let dht as FfiDhtMode where field == "dht": return wire(dht)
        case let cors as FfiCorsOrigins where field == "cors_origins": return wire(cors)
        case let nat as FfiNat where field == "nat": return wire(nat)
        default: throw FixtureError(description: "\(value) is not an arm of \(field)")
        }
    }

    private func typed<T>(_ value: Any, _ what: String) throws -> T {
        guard let typed = value as? T else {
            throw FixtureError(description: "\(what) is not a \(T.self)")
        }
        return typed
    }

    /// The fixture's full config as a Swift config under `identity`.
    private func fixtureConfig(_ fixture: [String: Any], identity: Identity) throws -> NodeStartConfig {
        let config = try object(fixture["config"], "config")
        let armOf = { (field: String) throws -> Any in
            try arm(field, object(config[field], "config.\(field)"))
        }
        return try NodeStartConfig(
            reach: typed(armOf("reach"), "reach"),
            identity: identity,
            blobStorage: typed(armOf("blob_storage"), "blob_storage"),
            tls: typed(armOf("tls"), "tls"),
            dht: typed(armOf("dht"), "dht"),
            corsOrigins: typed(armOf("cors_origins"), "cors_origins"),
            bindAddr: typed(config["bind_addr"] as Any, "bind_addr"),
            httpBindAddr: typed(config["http_bind_addr"] as Any, "http_bind_addr"),
            nat: typed(armOf("nat"), "nat"),
            projectionRateLimit: UInt32(typed(config["projection_rate_limit"] as Any, "projection_rate_limit") as Int)
        )
    }

    /// A config the node starts from on loopback, with no TLS and in-memory
    /// blobs, on an OS-assigned relay port unless `bindAddr` names one.
    private func localConfig(
        _ identity: Identity,
        bindAddr: String = "127.0.0.1:0",
        blobStorage: FfiBlobBackend = .inMemory
    ) -> NodeStartConfig {
        NodeStartConfig(
            reach: .local,
            identity: identity,
            blobStorage: blobStorage,
            tls: .plaintext,
            dht: .disabled,
            corsOrigins: .anyOrigin,
            bindAddr: bindAddr
        )
    }

    /// The `ScpError` case name and code of `error`.
    private func caseAndCode(_ error: Error) -> (String, String)? {
        guard let scpError = error as? ScpError else { return nil }
        return switch scpError {
        case let .Identity(_, code): ("Identity", code)
        case let .Context(_, code): ("Context", code)
        case let .Permission(_, code): ("Permission", code)
        case let .Crypto(_, code): ("Crypto", code)
        case let .Transport(_, code): ("Transport", code)
        case let .Outlet(_, code): ("Outlet", code)
        case let .Validation(_, code): ("Validation", code)
        case let .Storage(_, code): ("Storage", code)
        default: ("other", "\(scpError)")
        }
    }

    /// The `ScpError` case `name` carrying `code`.
    private func scpError(_ name: String, code: String) -> ScpError {
        switch name {
        case "Identity": .Identity(msg: "node start failed", code: code)
        case "Context": .Context(msg: "node start failed", code: code)
        case "Transport": .Transport(msg: "node start failed", code: code)
        case "Storage": .Storage(msg: "node start failed", code: code)
        default: .Validation(msg: "node start failed", code: code)
        }
    }

    /// The error `start` throws; records an issue when it returns a node.
    private func startError(_ start: () async throws -> Node) async -> (String, String)? {
        do {
            let node = try await start()
            node.shutdown()
            Issue.record("node start must fail")
            return nil
        } catch {
            return caseAndCode(error)
        }
    }

    /// Every row of sdk-common.md §"Node start error codes": the code and the
    /// `ScpError` case the bridge gives it: `.Storage` for every `SCP-STORAGE-`
    /// code, otherwise the case `server_error_class` selects.
    private let nodeStartCodes: [(code: String, errorCase: String)] = [
        ("SCP-STORAGE-8007", "Storage"),
        ("SCP-STORAGE-8008", "Storage"),
        ("SCP-STORAGE-8009", "Storage"),
        ("SCP-IDENT-1063", "Identity"),
        ("SCP-TRANS-5051", "Transport"),
        ("SCP-TRANS-5052", "Transport"),
        ("SCP-TRANS-5054", "Transport"),
        ("SCP-TRANS-5050", "Transport"),
        ("SCP-IDENT-1001", "Identity"),
        ("SCP-VALID-7004", "Validation"),
        ("SCP-CTX-2053", "Context"),
        ("SCP-TRANS-5055", "Transport"),
        ("SCP-TRANS-5056", "Transport")
    ]

    // MARK: - Config shape

    @Suite("node start config")
    struct NodeStartConfigTests {
        /// The record carries the bridge's fields in the bridge's order, and a
        /// field is optional exactly when the fixture says so.
        @Test func fieldsMatchTheBridgeStruct() async throws {
            let fixture = try loadWire()
            let scp = try SCP(storage: .inMemory)
            let config = try await localConfig(createInMemoryIdentity(scp))
            let children = Array(Mirror(reflecting: config).children)
            #expect(try children.map { snakeCase($0.label ?? "") } == strings(fixture["fields"], "fields"))
            let optional = children
                .filter { Mirror(reflecting: $0.value).displayStyle == .optional }
                .map { snakeCase($0.label ?? "") }
            #expect(try optional == strings(fixture["optional_fields"], "optional_fields"))
            try await scp.shutdown(timeoutMillis: 1000)
        }

        /// A config built from the required fields alone compiles, and each
        /// optional field it omits is `nil`, which the bridge reads as absent.
        @Test func optionalFieldsDefaultToNil() async throws {
            let fixture = try loadWire()
            let scp = try SCP(storage: .inMemory)
            let identity = try await createInMemoryIdentity(scp)
            let full = try fixtureConfig(fixture, identity: identity)
            let minimal = NodeStartConfig(
                reach: full.reach,
                identity: identity,
                blobStorage: full.blobStorage,
                tls: full.tls,
                dht: full.dht,
                corsOrigins: full.corsOrigins
            )
            var expected = try object(fixture["config"], "config")
            expected["identity"] = identity.did()
            for name in try strings(fixture["optional_fields"], "optional_fields") {
                expected[name] = NSNull()
            }
            #expect(try canonical(wire(minimal)) == canonical(expected))
            try await scp.shutdown(timeoutMillis: 1000)
        }

        /// Each sum type has every arm of the fixture, each arm built from its
        /// fixture entry encodes to that entry, and an arm field is optional
        /// exactly when the fixture says so.
        @Test func armsMatchTheBridgeEnums() throws {
            let fixture = try loadWire()
            let arms = try object(fixture["arms"], "arms")
            let optionalArmFields = try object(fixture["optional_arm_fields"], "optional_arm_fields")
            #expect(Set(arms.keys) == ["reach", "blob_storage", "tls", "dht", "cors_origins", "nat"])
            for (field, entries) in arms {
                guard let entries = entries as? [[String: Any]] else {
                    Issue.record("arms.\(field) is not a list of objects")
                    continue
                }
                for entry in entries {
                    let value = try arm(field, entry)
                    #expect(try canonical(wireArm(field, value)) == canonical(entry), "\(field)")
                    let kind = entry["kind"] as? String ?? ""
                    let optional = (optionalArmFields[field] as? [String: [String]])?[kind] ?? []
                    let armFields = entry.keys.filter { $0 != "kind" }.sorted()
                    // An arm's payload is a labelled tuple of its fields; a
                    // field is optional exactly when the fixture lists it.
                    guard let payload = Mirror(reflecting: value).children.first?.value else {
                        #expect(armFields.isEmpty, "\(field).\(kind) carries no fields")
                        continue
                    }
                    let payloadMirror = Mirror(reflecting: payload)
                    let fields: [(name: String, value: Any)] = payloadMirror.displayStyle == .tuple
                        ? payloadMirror.children.map { (snakeCase($0.label ?? ""), $0.value) }
                        : [(armFields.first ?? "", payload)]
                    #expect(fields.map(\.name).sorted() == armFields, "\(field).\(kind)")
                    let optionalFields = fields
                        .filter { Mirror(reflecting: $0.value).displayStyle == .optional }
                        .map(\.name)
                    #expect(optionalFields.sorted() == optional.sorted(), "\(field).\(kind)")
                }
            }
        }

        /// The fixture's full config encodes field for field to the fixture's
        /// wire config, with the identity lowered to its DID.
        @Test func fullConfigIsTheBridgeWireShape() async throws {
            let fixture = try loadWire()
            let scp = try SCP(storage: .inMemory)
            let identity = try await createInMemoryIdentity(scp)
            var expected = try object(fixture["config"], "config")
            expected["identity"] = identity.did()
            let config = try fixtureConfig(fixture, identity: identity)
            #expect(try canonical(wire(config)) == canonical(expected))
            try await scp.shutdown(timeoutMillis: 1000)
        }
    }

    // MARK: - Delegation and errors

    @Suite("node start delegation")
    struct NodeStartDelegationTests {
        /// The node start entry hands the bridge the record it was given, with
        /// the same `Identity` handle, and calls the bridge once.
        @Test func passesTheConfigRecordToTheBridgeUnchanged() async throws {
            let fixture = try loadWire()
            let scp = try SCP(storage: .inMemory)
            let identity = try await createInMemoryIdentity(scp)
            let config = try fixtureConfig(fixture, identity: identity)
            var received: [NodeStartConfig] = []
            let error = await startError {
                try await Node.start(config: config) { record in
                    received.append(record)
                    throw scpError("Storage", code: "SCP-STORAGE-8007")
                }
            }
            #expect(error?.1 == "SCP-STORAGE-8007")
            #expect(received.count == 1)
            let record = try #require(received.first)
            #expect(record.identity === identity)
            #expect(try canonical(wire(record)) == canonical(wire(config)))
            try await scp.shutdown(timeoutMillis: 1000)
        }

        /// The code table above names exactly the codes of sdk-common.md
        /// §"Node start error codes".
        @Test func codeTableCoversEverySdkCommonRow() throws {
            let doc = try String(
                contentsOf: repoRoot.appendingPathComponent(".docs/standards/sdk-common.md"),
                encoding: .utf8
            )
            let start = try #require(doc.range(of: "### Node start error codes"))
            var section = String(doc[start.lowerBound...])
            let next = try #require(section.range(of: "\n### "))
            section = String(section[..<next.lowerBound])
            let regex = try NSRegularExpression(
                pattern: "^\\| [^|]+ \\| `(SCP-[A-Z]+-\\d+)` \\|", options: [.anchorsMatchLines]
            )
            let range = NSRange(section.startIndex..., in: section)
            let rows = regex.matches(in: section, range: range).compactMap { match in
                Range(match.range(at: 1), in: section).map { String(section[$0]) }
            }
            #expect(rows.count == Set(rows).count)
            #expect(rows.sorted() == nodeStartCodes.map(\.code).sorted())
        }

        /// A bridge failure with each node start code reaches the caller as
        /// the same `ScpError` case with the code preserved.
        @Test(arguments: nodeStartCodes.map { [$0.code, $0.errorCase] })
        func throwsTheTypedErrorOfEachCode(row: [String]) async throws {
            let (code, errorCase) = (row[0], row[1])
            let scp = try SCP(storage: .inMemory)
            let config = try await localConfig(createInMemoryIdentity(scp))
            let error = await startError {
                try await Node.start(config: config) { _ in throw scpError(errorCase, code: code) }
            }
            #expect(error?.0 == errorCase, "\(code)")
            #expect(error?.1 == code)
            try await scp.shutdown(timeoutMillis: 1000)
        }
    }

    // MARK: - Through the built bindings

    @Suite("node start through the bindings", .serialized)
    struct NodeStartBindingTests {
        /// A valid config starts a node under the operator identity on a real
        /// relay port, and the node stops.
        @Test func startsAndStopsANodeUnderTheOperatorIdentity() async throws {
            let scp = try SCP(storage: .inMemory)
            let identity = try await createInMemoryIdentity(scp)
            let node = try await scp.nodeStart(config: localConfig(identity))
            #expect(node.did == identity.did())
            #expect(node.relayPort > 0)
            #expect(!node.isShutdown)
            node.shutdown()
            #expect(node.isShutdown)
            try await scp.shutdown(timeoutMillis: 1000)
        }

        /// Each node start failure a Swift caller can reach through the
        /// bindings throws the case and code sdk-common.md gives it.
        @Test func reachableFailuresThrowTheirCodes() async throws {
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("scp-node-start-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tmp) }
            let regularFile = tmp.appendingPathComponent("regular-file")
            try Data("x".utf8).write(to: regularFile)

            let scp = try SCP(storage: .inMemory)
            let identity = try await createInMemoryIdentity(scp)

            // An invalid config: a bind address that is not host:port.
            var error = await startError {
                try await scp.nodeStart(config: localConfig(identity, bindAddr: "not-an-address"))
            }
            #expect(error?.0 == "Storage")
            #expect(error?.1 == "SCP-STORAGE-8007")

            // A blob directory that cannot be created under a regular file.
            let blobPath = regularFile.appendingPathComponent("sub/blobs.redb").path
            error = await startError {
                try await scp.nodeStart(config: localConfig(identity, blobStorage: .redb(path: blobPath)))
            }
            #expect(error?.0 == "Storage")
            #expect(error?.1 == "SCP-STORAGE-8008")

            // A second start while a running node holds the binding.
            let node = try await scp.nodeStart(config: localConfig(identity))
            error = await startError { try await scp.nodeStart(config: localConfig(identity)) }
            #expect(error?.0 == "Transport")
            #expect(error?.1 == "SCP-TRANS-5056")

            // A relay bind on the port the running node holds.
            let other = try SCP(storage: .inMemory)
            let otherIdentity = try await createInMemoryIdentity(other)
            error = await startError {
                try await other.nodeStart(
                    config: localConfig(otherIdentity, bindAddr: "127.0.0.1:\(node.relayPort)")
                )
            }
            #expect(error?.0 == "Transport")
            #expect(error?.1 == "SCP-TRANS-5051")

            // An operator identity another instance minted.
            error = await startError { try await other.nodeStart(config: localConfig(identity)) }
            #expect(error?.0 == "Identity")
            #expect(error?.1 == "SCP-IDENT-1063")

            node.shutdown()
            try await other.shutdown(timeoutMillis: 1000)
            try await scp.shutdown(timeoutMillis: 1000)
        }
    }

    // MARK: - iOS absence

    @Suite("node start is macOS-only")
    struct NodeStartPlatformTests {
        /// Type-checks the SDK sources plus a file that calls
        /// `scp.nodeStart(config:)` for `target`; returns the compiler's exit
        /// status and its error lines.
        private func typecheck(sdk: String, target: String) throws -> (Int32, [String]) {
            let probeDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("scp-node-start-probe-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: probeDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: probeDir) }
            let probe = probeDir.appendingPathComponent("NodeStartProbe.swift")
            try Data("""
            extension SCP {
                func nodeStartProbe(_ config: NodeStartConfig) async throws -> Node {
                    try await nodeStart(config: config)
                }
            }

            """.utf8).write(to: probe)

            let sources = packageRoot.appendingPathComponent("Sources/SCP")
            let enumerator = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)
            let files = (enumerator?.allObjects as? [URL] ?? [])
                .filter { $0.pathExtension == "swift" }
                .map(\.path)
            #expect(files.count > 10, "the SDK sources were not found at \(sources.path)")

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
            process.arguments = [
                "--sdk", sdk, "swiftc", "-typecheck", "-target", target, "-swift-version", "5",
                "-module-name", "SCP", "-I", packageRoot.appendingPathComponent("Headers").path
            ] + files + [probe.path]
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            try process.run()
            let bytes = output.fileHandleForReading.readDataToEndOfFile()
            let text = try #require(String(bytes: bytes, encoding: .utf8), "swiftc wrote output that is not UTF-8")
            process.waitUntilExit()
            let errors = text.split(separator: "\n").map(String.init).filter { $0.contains(": error: ") }
            return (process.terminationStatus, errors)
        }

        /// On macOS the probe type-checks, so the probe and the compiler
        /// invocation are sound.
        @Test func macOSBuildHasNodeStart() throws {
            let (status, errors) = try typecheck(sdk: "macosx", target: "arm64-apple-macos14.0")
            #expect(errors.isEmpty)
            #expect(status == 0)
        }

        /// On iOS the rest of the SDK type-checks and the probe's one error is
        /// that `nodeStart` does not exist.
        @Test func iOSBuildHasNoNodeStart() throws {
            let (status, errors) = try typecheck(sdk: "iphoneos", target: "arm64-apple-ios17.0")
            #expect(status != 0)
            #expect(errors.count == 1, "\(errors)")
            #expect(errors.first?.contains("NodeStartProbe.swift") == true, "\(errors)")
            #expect(errors.first?.contains("cannot find 'nodeStart' in scope") == true, "\(errors)")
        }
    }
#endif
