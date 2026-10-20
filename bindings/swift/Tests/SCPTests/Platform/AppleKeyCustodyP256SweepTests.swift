// Abandoned-mint sweep tests for `AppleKeyCustody` (ADR-025 Key custody).
//
// A process that dies between reserving a P-256 key's companion and
// recording its public key leaves a reservation no caller can name. Every
// P-256 mint first sweeps the reservations whose minting process is gone.
//
// Every adapter in the test process shares one Keychain, and every mint in
// any suite sweeps. So a planted reservation carries a tag that the real
// liveness check reads as alive (pid 0 is malformed), and only the adapter
// under test, through its injected liveness check, reads that tag as gone.
// The real check is tested on its own against this process, pid 1 and a pid
// that cannot exist.
//
// One sweep can miss a reservation while other suites' mints change pending
// items mid-scan (the file keychain ends the scan early without an error), and
// the next mint's sweep finds it. A test that needs the sweep to reach its
// reservation therefore mints up to `attempts` times.

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

        /// The most mints a test makes for its sweep to reach a reservation.
        private static let attempts = 20

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
            ))
            try await store.plant(tag: custody.applicationTag(for: id))
            return id
        }

        /// The companion of `id` as the Keychain holds it: its comment and
        /// its label.
        private static func companion(_ id: String) -> (comment: String?, label: String?)? {
            var result: AnyObject?
            let status = SecItemCopyMatching([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "scp.key.\(id)",
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ] as CFDictionary, &result)
            guard status == errSecSuccess, let attrs = result as? [String: Any] else { return nil }
            return (attrs[kSecAttrComment as String] as? String, attrs[kSecAttrLabel as String] as? String)
        }

        @Test("a mint sweeps a reservation its process abandoned, key included")
        func mintSweepsAnAbandonedReservation() async throws {
            let store = SoftwareP256KeyStore()
            let tag = Self.foreignTag()
            let custody = adapter(store, abandoned: tag)
            let orphan = try await plantCrashedMint(custody, store: store, tag: tag)
            #expect(KeyIdRecorder.companionExists(orphan))

            var minted: [String] = []
            while KeyIdRecorder.companionExists(orphan), minted.count < Self.attempts {
                try await minted.append(custody.generateKeypair(keyType: "p256"))
            }

            #expect(!KeyIdRecorder.companionExists(orphan), "no sweep in \(Self.attempts) mints removed the reservation")
            #expect(try await !store.contains(tag: custody.applicationTag(for: orphan)))
            for id in minted {
                #expect(KeyIdRecorder.companionExists(id))
                #expect(try await store.contains(tag: custody.applicationTag(for: id)))
                try await custody.destroyKey(id)
            }
        }

        @Test("a reservation whose process is alive survives the sweep")
        func liveReservationSurvives() async throws {
            let store = SoftwareP256KeyStore()
            let custody = adapter(store, abandoned: Self.foreignTag())
            let live = try await plantCrashedMint(custody, store: store, tag: Self.foreignTag())

            let swept = try await custody.sweepAbandonedMints(isAbandoned: { _ in false })
            _ = try await custody.generateKeypair(keyType: "hpke-p256")

            #expect(!swept.contains(live))
            #expect(KeyIdRecorder.companionExists(live))
            #expect(try await store.contains(tag: custody.applicationTag(for: live)))
            try await custody.destroyKey(live)
            #expect(!KeyIdRecorder.companionExists(live))
        }

        /// The sweep deletes the companion only after the key is confirmed
        /// gone, and a sweep failure fails the mint instead of being ignored.
        @Test("a sweep that cannot confirm the key gone keeps the reservation and fails the mint")
        func unconfirmedSweepFailsTheMint() async throws {
            let store = SoftwareP256KeyStore()
            let tag = Self.foreignTag()
            let custody = adapter(store, abandoned: tag)
            let orphan = try await plantCrashedMint(custody, store: store, tag: tag)
            await store.keepKeysOnDelete(true)

            // Each mint whose sweep missed the reservation succeeds; the first
            // whose sweep reaches it must fail before it creates a key.
            var failure: PlatformError?
            var minted: [String] = []
            while failure == nil, minted.count < Self.attempts {
                let createdBefore = await store.createCalls
                do {
                    try await minted.append(custody.generateKeypair(keyType: "p256"))
                } catch let error as PlatformError {
                    failure = error
                    #expect(await store.createCalls == createdBefore, "the failing mint must stop before it creates a key")
                }
            }
            guard case .destructionFailed(orphan)? = failure else {
                Issue.record("expected destructionFailed(\(orphan)) from a mint, got \(String(describing: failure))")
                return
            }
            #expect(KeyIdRecorder.companionExists(orphan))
            #expect(try await store.contains(tag: custody.applicationTag(for: orphan)))

            await store.keepKeysOnDelete(false)
            for id in minted {
                try await custody.destroyKey(id)
            }
            var rounds = 0
            while KeyIdRecorder.companionExists(orphan), rounds < Self.attempts {
                try await custody.sweepAbandonedMints(isAbandoned: { $0 == tag })
                rounds += 1
            }
            #expect(!KeyIdRecorder.companionExists(orphan))
            #expect(try await !store.contains(tag: custody.applicationTag(for: orphan)))
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
