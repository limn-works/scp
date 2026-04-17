import Foundation
@testable import SCP
import Testing

// MARK: - Lifecycle Tests

/// Tests for bridge lifecycle controls (``Lifecycle/suspend()`` /
/// ``Lifecycle/resume()``).
///
/// Uses injectable bridge closures so the tests can run without linking
/// against the compiled xcframework (mirrors the pattern used by
/// BridgeConnectorBridge and other injectable-bridge modules).
struct LifecycleTests {
    // MARK: - suspend

    @Test("suspend delegates to injected closure and succeeds")
    func suspendCallsInjectedClosure() throws {
        final class Counter: @unchecked Sendable {
            var value = 0
        }
        let counter = Counter()
        let suspendFn: Lifecycle.SuspendFn = {
            counter.value += 1
        }

        try Lifecycle.suspend(suspendFn: suspendFn)
        #expect(counter.value == 1)
    }

    @Test("suspend propagates thrown errors")
    func suspendPropagatesErrors() {
        struct InjectedError: Error, Equatable {}
        let suspendFn: Lifecycle.SuspendFn = {
            throw InjectedError()
        }

        #expect(throws: InjectedError.self) {
            try Lifecycle.suspend(suspendFn: suspendFn)
        }
    }

    // MARK: - resume

    @Test("resume delegates to injected closure and succeeds")
    func resumeCallsInjectedClosure() throws {
        final class Counter: @unchecked Sendable {
            var value = 0
        }
        let counter = Counter()
        let resumeFn: Lifecycle.ResumeFn = {
            counter.value += 1
        }

        try Lifecycle.resume(resumeFn: resumeFn)
        #expect(counter.value == 1)
    }

    @Test("resume propagates thrown errors")
    func resumePropagatesErrors() {
        struct InjectedError: Error, Equatable {}
        let resumeFn: Lifecycle.ResumeFn = {
            throw InjectedError()
        }

        #expect(throws: InjectedError.self) {
            try Lifecycle.resume(resumeFn: resumeFn)
        }
    }

    // MARK: - Roundtrip

    @Test("suspend then resume invokes both closures in order")
    func suspendThenResumeRoundtrip() throws {
        final class Log: @unchecked Sendable {
            var entries: [String] = []
        }
        let log = Log()
        let suspendFn: Lifecycle.SuspendFn = { log.entries.append("suspend") }
        let resumeFn: Lifecycle.ResumeFn = { log.entries.append("resume") }

        try Lifecycle.suspend(suspendFn: suspendFn)
        try Lifecycle.resume(resumeFn: resumeFn)

        #expect(log.entries == ["suspend", "resume"])
    }
}
