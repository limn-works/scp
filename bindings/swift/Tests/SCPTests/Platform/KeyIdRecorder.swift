// The key id source of every custody test that mints through a
// Keychain-backed adapter. It hands `AppleKeyCustody` random canonical
// decimal ids and remembers each one, so a test asserts absence for exactly
// the ids it drew and its suite's `deinit` deletes whatever those ids left in
// the Keychain, whichever path the test exited by.

#if os(iOS) || os(macOS)

    import Foundation
    import os
    @testable import SCP
    import Security

    final class KeyIdRecorder: Sendable {
        private let ids = OSAllocatedUnfairLock<[String]>(initialState: [])

        /// Draws a fresh id and records it.
        func next() -> String {
            let id = String(UInt64.random(in: .min ... .max))
            ids.withLock { $0.append(id) }
            return id
        }

        /// Every id drawn so far, in order.
        var drawn: [String] {
            ids.withLock { $0 }
        }

        /// The adapter tests use: the internal initializer with this
        /// recorder's ids, the probe result `enclaveAvailable`, and `stores`
        /// as the store of each backing.
        func custody(
            policy: BiometricPolicy = .none,
            enclaveAvailable: Bool,
            stores: @escaping @Sendable (P256Backing) -> any P256KeyStore
        ) -> AppleKeyCustody {
            AppleKeyCustody(
                accessGroup: nil,
                biometricPolicy: policy,
                enclaveAvailable: enclaveAvailable,
                makeP256Store: stores,
                newKeyId: { [self] in next() }
            )
        }

        /// An adapter for Ed25519 and X25519 tests: no enclave, and a P-256
        /// store that holds keys in process.
        func custody(policy: BiometricPolicy = .none) -> AppleKeyCustody {
            let store = SoftwareP256KeyStore()
            return custody(policy: policy, enclaveAvailable: false, stores: { _ in store })
        }

        /// Deletes every Keychain item a drawn id names.
        func purge() {
            Self.purge(drawn)
        }

        /// Deletes the companion generic-password item and any key item of
        /// each id, in the file keychain and, on macOS, the data-protection
        /// keychain. A status other than success is not an error: the item
        /// is already gone or was never writable by this process.
        static func purge(_ handles: [String]) {
            for handle in handles {
                let account = "scp.key.\(handle)"
                SecItemDelete([
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: account
                ] as CFDictionary)
                for backing in P256Backing.allCases {
                    SecItemDelete(KeychainP256KeyStore.keyQuery(
                        tag: Data(account.utf8), backing: backing, accessGroup: nil
                    ) as CFDictionary)
                }
            }
        }

        /// Whether a companion generic-password item exists for `handle`.
        static func companionExists(_ handle: String) -> Bool {
            SecItemCopyMatching([
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "scp.key.\(handle)",
                kSecMatchLimit as String: kSecMatchLimitOne
            ] as CFDictionary, nil) == errSecSuccess
        }

        /// Whether a P-256 key item carries the tag of `handle`, under either
        /// backing's query. A query this process may not run (no
        /// entitlement) finds nothing, since the process could not have
        /// written there either.
        static func keyItemExists(_ handle: String) -> Bool {
            P256Backing.allCases.contains { backing in
                var query = KeychainP256KeyStore.keyQuery(
                    tag: Data("scp.key.\(handle)".utf8), backing: backing, accessGroup: nil
                )
                query[kSecMatchLimit as String] = kSecMatchLimitOne
                return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
            }
        }
    }

#endif // os(iOS) || os(macOS)
