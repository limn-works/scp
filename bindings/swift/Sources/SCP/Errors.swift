/// SCP error hierarchy. All variants carry a human-readable ``message`` and a
/// machine-readable ``code`` in the format ``SCP-{CATEGORY}-{NUMBER}``.
public nonisolated enum ScpError: Error, Sendable {
    /// An identity operation failed (key generation, DID resolution, key rotation).
    case identity(message: String, code: String)
    /// A context operation failed (create, join, send, close).
    case context(message: String, code: String)
    /// A capability or permission check failed.
    case permission(message: String, code: String)
    /// A cryptographic operation failed (MLS, sender key, signing, verification).
    case crypto(message: String, code: String)
    /// A transport operation failed (connect, relay, adapter).
    case transport(message: String, code: String)
    /// A tool operation failed (registration, invocation, verification).
    case tool(message: String, code: String)
    /// Input validation failed.
    case validation(message: String, code: String)
}

extension ScpError: LocalizedError {
    /// A human-readable description of the error.
    public nonisolated var errorDescription: String? {
        switch self {
        case .identity(let message, _): message
        case .context(let message, _): message
        case .permission(let message, _): message
        case .crypto(let message, _): message
        case .transport(let message, _): message
        case .tool(let message, _): message
        case .validation(let message, _): message
        }
    }
}
