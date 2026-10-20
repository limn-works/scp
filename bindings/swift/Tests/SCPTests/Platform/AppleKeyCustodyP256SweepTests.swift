// Abandoned-mint sweep tests for `AppleKeyCustody` (ADR-025 Key custody).
//
// A process that dies between reserving a P-256 key's companion and
// recording its public key leaves a reservation no caller can name. Every
// P-256 mint first sweeps, best-effort, the reservations whose minting process
// is gone, and a reservation reads as absent until its mint settles.
//
// Every adapter in the test process shares one Keychain, and every mint in
// any suite sweeps. So a planted reservation carries a tag that the real
// liveness check reads as alive (pid 0 is malformed), and only the adapter
// under test, through its injected liveness check, reads that tag as gone.
// The real check is tested on its own against this process, pid 1 and a pid
// that cannot exist.
//
// A Keychain scan can end early while other suites' mints change pending
// items, so no test here depends on a scan reaching its item. Candidate
// selection is tested as a pure function over attribute dictionaries, and
// removal through `sweep(_:)` on the candidates a test names.

#if os(iOS) || os(macOS)

    import Foundation
    @testable import SCP
    import Security
    import Testing

    final class AppleKeyCustodyP256SweepTests: Sendable {
        private let keyIds = KeyIdRecorder()

        deinit {
            keyIds.purge()
        }

        /// A tag only `isGone` below reads as gone.
        private static func foreignTag() -> String {
            "0:\(UUID().uuidString)"
        }

        /// An adapter over `store` whose mints sweep the reservations tagged
        /// `abandoned`, and no others.
        private func adapter(_ store: SoftwareP256KeyStore, abandoned: String) -> AppleKeyCustody {
            keyIds.custody(enclaveAvailable: true, stores: { _ in store }, processIsGone: { $0 == abandoned })
        }

        /// Leaves the state a mint that crashed after creating its key leaves:
        /// the reservation tagged `tag`, and a key under the id's tag.
        private func plantCrashedMint(
            _ custody: AppleKeyCustody, store: SoftwareP256KeyStore, tag: String
        ) async throws -> String {
            let id = keyIds.next()
            #expect(try custody.reserveP256(
                handle: id, keyType: .hpkeP256, role: .operational, mintingProcess: tag
            ) != nil)
            try await store.plant(tag: custody.applicationTag(for: id))
            return id
        }

        /// The companion of `id` under `service` as the Keychain holds it:
        /// its comment and its label.
        private static func companion(
            _ id: String, service: String = AppleKeyCustody.itemService
        ) -> (comment: String?, label: String?)? {
            var result: AnyObject?
            let status = SecItemCopyMatching([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: "scp.key.\(id)",
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ] as CFDictionary, &result)
            guard status == errSecSuccess, let attrs = result as? [String: Any] else { return nil }
            return (attrs[kSecAttrComment as String] as? String, attrs[kSecAttrLabel as String] as? String)
        }

        /// The `kSecAttrLabel` a companion of `metadata` carries.
        private static func label(_ metadata: KeyMetadata) throws -> String {
            try #require(String(data: JSONEncoder().encode(metadata), encoding: .utf8))
        }

        /// A P-256 record: pending with `process` when `publicKey` is nil,
        /// settled otherwise.
        private static func record(process: String?, publicKey: Data? = nil) -> KeyMetadata {
            KeyMetadata(
                keyType: "p256",
                publicKeyBase64: publicKey?.base64EncodedString(),
                role: "operational",
                custodyType: "hardware",
                backing: P256Backing.software.rawValue,
                mintingProcess: process
            )
        }

        /// The attribute dictionary of a companion of `id`.
        private static func attributes(
            id: String, service: String, comment: String, metadata: KeyMetadata
        ) throws -> [String: Any] {
            try [
                kSecAttrService as String: service,
                kSecAttrAccount as String: "scp.key.\(id)",
                kSecAttrComment as String: comment,
                kSecAttrLabel as String: label(metadata)
            ]
        }

        @Test("candidate selection takes a dead tag's reservation and leaves live, settled and foreign-service items")
        func abandonedMintSelection() throws {
            let service = AppleKeyCustody.itemService
            let items = try [
                Self.attributes(id: "1", service: service, comment: "scp.mint.pending",
                                metadata: Self.record(process: "live")),
                Self.attributes(id: "2", service: service, comment: "scp.mint.pending",
                                metadata: Self.record(process: "dead")),
                Self.attributes(id: "3", service: service, comment: "",
                                metadata: Self.record(process: nil, publicKey: Data(repeating: 2, count: 33))),
                Self.attributes(id: "4", service: "works.other.app", comment: "scp.mint.pending",
                                metadata: Self.record(process: "dead"))
            ]
            var asked: [String] = []
            let mints = AppleKeyCustody.abandonedMints(in: items) { process in
                asked.append(process)
                return process == "dead"
            }
            #expect(mints == [AppleKeyCustody.AbandonedMint(handle: "2", backing: .software)])
            #expect(asked == ["live", "dead"], "the settled and foreign-service items are refused before liveness")
        }

        @Test("sweeping an abandoned mint removes its key, then its reservation")
        func sweepRemovesAnAbandonedMint() async throws {
            let store = SoftwareP256KeyStore()
            let tag = Self.foreignTag()
            let custody = adapter(store, abandoned: tag)
            let orphan = try await plantCrashedMint(custody, store: store, tag: tag)

            let swept = await custody.sweep([.init(handle: orphan, backing: .secureEnclave)])

            #expect(swept == [orphan])
            #expect(!KeyIdRecorder.companionExists(orphan))
            #expect(try await !store.contains(tag: custody.applicationTag(for: orphan)))
        }

        @Test("a reservation whose process is alive survives the sweep")
        func liveReservationSurvives() async throws {
            let store = SoftwareP256KeyStore()
            let custody = adapter(store, abandoned: Self.foreignTag())
            let live = try await plantCrashedMint(custody, store: store, tag: Self.foreignTag())

            let swept = await custody.sweepAbandonedMints(isAbandoned: { _ in false })
            _ = try await custody.generateKeypair(keyType: "hpke-p256")

            #expect(!swept.contains(live))
            #expect(KeyIdRecorder.companionExists(live))
            #expect(try await store.contains(tag: custody.applicationTag(for: live)))
            try await custody.destroyKey(live)
            #expect(!KeyIdRecorder.companionExists(live))
        }

        /// The sweep deletes the companion only after the key is confirmed
        /// gone. A sweep that cannot confirm it keeps the reservation, and the
        /// mint that ran it still succeeds.
        @Test("a sweep that cannot confirm the key gone keeps the reservation, and the mint succeeds")
        func unconfirmedSweepKeepsTheReservationAndTheMintSucceeds() async throws {
            let store = SoftwareP256KeyStore()
            let tag = Self.foreignTag()
            let custody = adapter(store, abandoned: tag)
            let orphan = try await plantCrashedMint(custody, store: store, tag: tag)
            let mint = AppleKeyCustody.AbandonedMint(handle: orphan, backing: .secureEnclave)
            await store.keepKeysOnDelete(true)

            #expect(await custody.sweep([mint]).isEmpty)
            let minted = try await custody.generateKeypair(keyType: "p256")

            #expect(KeyIdRecorder.companionExists(orphan))
            #expect(try await store.contains(tag: custody.applicationTag(for: orphan)))
            #expect(KeyIdRecorder.companionExists(minted))

            await store.keepKeysOnDelete(false)
            try await custody.destroyKey(minted)
            #expect(await custody.sweep([mint]) == [orphan])
            #expect(!KeyIdRecorder.companionExists(orphan))
            #expect(try await !store.contains(tag: custody.applicationTag(for: orphan)))
        }

        /// A reservation is no key until its mint settles: every operation
        /// reads it as absent, and destroyKey still removes it.
        @Test("a pending id reads as absent: key-not-found, in_memory custody, and destroyKey removes it")
        func pendingIdReadsAsAbsent() async throws {
            let store = SoftwareP256KeyStore()
            let custody = adapter(store, abandoned: Self.foreignTag())
            let pending = try await plantCrashedMint(custody, store: store, tag: Self.foreignTag())

            #expect(custody.custodyType(pending) == "in_memory")
            for operation in ["publicKey", "sign", "dhAgree"] {
                do {
                    switch operation {
                    case "publicKey": _ = try await custody.publicKey(pending)
                    case "sign": _ = try await custody.sign(pending, data: Data(repeating: 1, count: 32))
                    default: _ = try await custody.dhAgree(pending, peerPublic: Data(repeating: 4, count: 65))
                    }
                    Issue.record("\(operation) used the pending id \(pending)")
                } catch PlatformError.keyNotFound(pending) {}
            }
            let provider: any KeyCustodyProvider = custody
            #expect(provider.custodyType(keyId: pending) == "in_memory")

            #expect(try await custody.destroyKey(pending).confirmed)
            #expect(!KeyIdRecorder.companionExists(pending))
            #expect(try await !store.contains(tag: custody.applicationTag(for: pending)))
        }

        /// The service attribute scopes every query: an item with the same
        /// account under another service is neither read nor deleted.
        @Test("an item with an SCP account under another service is neither read, destroyed nor swept")
        func foreignServiceItemIsInvisible() async throws {
            let store = SoftwareP256KeyStore()
            let tag = Self.foreignTag()
            let custody = adapter(store, abandoned: tag)
            let foreign = "works.other.app"
            let settled = keyIds.next()
            let pending = keyIds.next()
            for (id, comment, metadata) in [
                (settled, "", Self.record(process: nil, publicKey: Data(repeating: 2, count: 33))),
                (pending, "scp.mint.pending", Self.record(process: tag))
            ] {
                var item = try Self.attributes(id: id, service: foreign, comment: comment, metadata: metadata)
                item[kSecClass as String] = kSecClassGenericPassword
                item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                #expect(SecItemAdd(item as CFDictionary, nil) == errSecSuccess)
            }

            #expect(custody.custodyType(settled) == "in_memory")
            await #expect(throws: PlatformError.self) { _ = try await custody.publicKey(settled) }
            await #expect(throws: PlatformError.self) { _ = try await custody.destroyKey(settled) }
            _ = await custody.sweepAbandonedMints(isAbandoned: { $0 == tag })

            #expect(Self.companion(settled, service: foreign) != nil)
            #expect(Self.companion(pending, service: foreign) != nil)
        }

        /// A settled key carries neither the pending marker nor a minting
        /// process, so no sweep can select it whatever its liveness check
        /// answers. Checked on the stored item, since a sweep that marks
        /// every tag gone would also take other suites' in-flight mints.
        @Test("a settled key's companion carries no pending marker and no minting process")
        func settledKeyIsNoSweepCandidate() async throws {
            let store = SoftwareP256KeyStore()
            let custody = adapter(store, abandoned: Self.foreignTag())
            let pending = try await plantCrashedMint(custody, store: store, tag: Self.foreignTag())
            let reserved = try #require(Self.companion(pending))
            #expect(reserved.comment == "scp.mint.pending")
            #expect(reserved.label?.contains("mintingProcess") == true)

            for keyType in ["p256", "hpke-p256"] {
                let id = try await custody.generateKeypair(keyType: keyType)
                let settled = try #require(Self.companion(id))
                #expect(settled.comment != "scp.mint.pending")
                #expect(settled.label?.contains("mintingProcess") == false)
                try await custody.destroyKey(id)
            }
            try await custody.destroyKey(pending)
        }

        @Test("the liveness check reads this process and pid 1 as alive and a dead or reused pid as gone")
        func livenessCheck() throws {
            #expect(!AppleKeyCustody.mintingProcessIsGone(AppleKeyCustody.currentProcessTag))
            let launchdStart = try #require(AppleKeyCustody.processStartTime(1))
            #expect(!AppleKeyCustody.mintingProcessIsGone("1:\(launchdStart)"))
            #expect(AppleKeyCustody.mintingProcessIsGone("1:0.0"), "pid 1 under another start time is a reused pid")
            #expect(AppleKeyCustody.mintingProcessIsGone("999999:1.0"), "no process has pid 999999")
            for malformed in ["", "0:1.0", "-4:1.0", "abc:1.0", "999999", "999999:unknown"] {
                #expect(!AppleKeyCustody.mintingProcessIsGone(malformed), "\(malformed) must read as alive")
            }
        }
    }

#endif // os(iOS) || os(macOS)
