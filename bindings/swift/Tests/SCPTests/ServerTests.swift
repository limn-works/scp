import Foundation
@testable import SCP
import Testing

// MARK: - Node lifecycle tests (SCP-296)

// Tests for broadcast deployment lifecycle methods on ``Node``.
//
// All tests use the injectable bridge pattern: mock closures capture arguments
// and return canned responses so no Rust binary is required.

struct NodeLifecycleTests {
    // MARK: - enableSiteProjection

    @Test("enableSiteProjection delegates context/key/author/admission/hostname")
    func enableSiteProjectionDelegatesCore() async throws {
        var capturedContextId: String?
        var capturedBroadcastKeyHex: String?
        var capturedAuthorDid: String?
        var capturedAdmission: String?
        var capturedHostname: String?

        let mockEnable: ServerBridge.EnableSiteProjectionFn = { _, cid, adm, hst, key, aut, _, _, _, _, _ in // swiftlint:disable:this line_length
            capturedContextId = cid
            capturedAdmission = adm
            capturedHostname = hst
            capturedBroadcastKeyHex = key
            capturedAuthorDid = aut
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)
        let config = try SiteConfig(
            hostname: "mysite.example.com",
            indexPath: "/app.html",
            maxAssetsPerDeploy: 5000,
            maxDeploySizeBytes: 100_000_000,
            deployRetentionCount: 4,
            cspOverride: "default-src 'self'"
        )

        try await node.enableSiteProjection(
            contextId: "ctx-123",
            admission: "open",
            config: config,
            broadcastKeyHex: String(repeating: "ab", count: 32),
            authorDid: "did:dht:z6MkAuthor",
            enableFn: mockEnable
        )

        #expect(capturedContextId == "ctx-123")
        #expect(capturedBroadcastKeyHex == String(repeating: "ab", count: 32))
        #expect(capturedAuthorDid == "did:dht:z6MkAuthor")
        #expect(capturedAdmission == "open")
        #expect(capturedHostname == "mysite.example.com")
    }

    @Test("enableSiteProjection delegates optional config fields")
    func enableSiteProjectionDelegatesOptional() async throws {
        var capturedIndexPath: String?
        var capturedMaxAssets: UInt32?
        var capturedMaxSize: UInt64?
        var capturedRetention: UInt32?
        var capturedCsp: String?

        let mockEnable: ServerBridge.EnableSiteProjectionFn = { _, _, _, _, _, _, idx, maxA, maxS, ret, csp in // swiftlint:disable:this line_length
            capturedIndexPath = idx
            capturedMaxAssets = maxA
            capturedMaxSize = maxS
            capturedRetention = ret
            capturedCsp = csp
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)
        let config = try SiteConfig(
            hostname: "mysite.example.com",
            indexPath: "/app.html",
            maxAssetsPerDeploy: 5000,
            maxDeploySizeBytes: 100_000_000,
            deployRetentionCount: 4,
            cspOverride: "default-src 'self'"
        )

        try await node.enableSiteProjection(
            contextId: "ctx-123",
            admission: "open",
            config: config,
            broadcastKeyHex: String(repeating: "ab", count: 32),
            authorDid: "did:dht:z6MkAuthor",
            enableFn: mockEnable
        )

        #expect(capturedIndexPath == "/app.html")
        #expect(capturedMaxAssets == 5000)
        #expect(capturedMaxSize == 100_000_000)
        #expect(capturedRetention == 4)
        #expect(capturedCsp == "default-src 'self'")
    }

    @Test("enableSiteProjection passes nil for default SiteConfig values")
    func enableSiteProjectionDefaults() async throws {
        var capturedIndexPath: String?
        var capturedMaxAssets: UInt32?
        var capturedMaxSize: UInt64?
        var capturedRetention: UInt32?
        var capturedCsp: String?

        let mockEnable: ServerBridge.EnableSiteProjectionFn = { _, _, _, _, _, _, idx, maxA, maxS, ret, csp in // swiftlint:disable:this line_length
            capturedIndexPath = idx
            capturedMaxAssets = maxA
            capturedMaxSize = maxS
            capturedRetention = ret
            capturedCsp = csp
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)
        let config = try SiteConfig(hostname: "example.com")

        try await node.enableSiteProjection(
            contextId: "ctx-456",
            admission: "gated",
            config: config,
            broadcastKeyHex: String(repeating: "cd", count: 32),
            authorDid: "did:dht:z6MkAuthor2",
            enableFn: mockEnable
        )

        #expect(capturedIndexPath == nil)
        #expect(capturedMaxAssets == nil)
        #expect(capturedMaxSize == nil)
        #expect(capturedRetention == nil)
        #expect(capturedCsp == nil)
    }

    // MARK: - commitDeploy

    @Test("commitDeploy returns asset count from bridge")
    func commitDeployReturnsCount() async throws {
        let mockCommit: ServerBridge.CommitDeployFn = { _, _, _ in 42 }
        let node = try await Node.startInMemory(startFn: mockNodeStart)

        let count = try await node.commitDeploy(
            contextId: "ctx-123",
            deployId: "deploy-abc",
            commitFn: mockCommit
        )

        #expect(count == 42)
    }

    @Test("commitDeploy propagates errors from bridge")
    func commitDeployPropagatesError() async throws {
        let mockCommit: ServerBridge.CommitDeployFn = { _, _, _ in
            throw ScpError.Context(msg: "not projected", code: "SCP-CTX-2080")
        }
        let node = try await Node.startInMemory(startFn: mockNodeStart)

        await #expect(throws: ScpError.self) {
            _ = try await node.commitDeploy(
                contextId: "ctx-bad",
                deployId: "deploy-xyz",
                commitFn: mockCommit
            )
        }
    }

    // MARK: - rollbackDeploy

    @Test("rollbackDeploy delegates to bridge")
    func rollbackDeployDelegates() async throws {
        var calledContextId: String?
        var calledDeployId: String?
        let mockRollback: ServerBridge.RollbackDeployFn = { _, contextId, deployId in
            calledContextId = contextId
            calledDeployId = deployId
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)

        try await node.rollbackDeploy(
            contextId: "ctx-123",
            deployId: "deploy-old",
            rollbackFn: mockRollback
        )

        #expect(calledContextId == "ctx-123")
        #expect(calledDeployId == "deploy-old")
    }

    @Test("rollbackDeploy propagates errors from bridge")
    func rollbackDeployPropagatesError() async throws {
        let mockRollback: ServerBridge.RollbackDeployFn = { _, _, _ in
            throw ScpError.Context(msg: "deploy not found", code: "SCP-CTX-2081")
        }
        let node = try await Node.startInMemory(startFn: mockNodeStart)

        await #expect(throws: ScpError.self) {
            try await node.rollbackDeploy(
                contextId: "ctx-bad",
                deployId: "deploy-nope",
                rollbackFn: mockRollback
            )
        }
    }

    // MARK: - disableSiteProjection

    @Test("disableSiteProjection delegates to bridge")
    func disableSiteProjectionDelegates() async throws {
        var calledContextId: String?
        let mockDisable: ServerBridge.DisableSiteProjectionFn = { _, contextId in
            calledContextId = contextId
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)

        try await node.disableSiteProjection(
            contextId: "ctx-123",
            disableFn: mockDisable
        )

        #expect(calledContextId == "ctx-123")
    }

    @Test("disableSiteProjection is idempotent on unprojected context")
    func disableSiteProjectionIdempotent() async throws {
        let mockDisable: ServerBridge.DisableSiteProjectionFn = { _, _ in
            // No-op, like the real implementation.
        }

        let node = try await Node.startInMemory(startFn: mockNodeStart)

        // Should not throw.
        try await node.disableSiteProjection(
            contextId: "ctx-nonexistent",
            disableFn: mockDisable
        )
    }

    // MARK: - Helpers

    /// Mock node start function that creates a fake handle.
    private var mockNodeStart: ServerBridge.NodeStartInMemoryFn {
        { NodeHandle(noPointer: .init()) }
    }
}
