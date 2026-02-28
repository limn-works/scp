import Foundation

// ScpError is now defined by UniFFI in ScpBindings.swift.
// The generated enum uses uppercase case names: .Identity, .Context, .Permission,
// .Crypto, .Transport, .Tool, .Validation — each with (message: String, code: String).
//
// UniFFI also provides Foundation.LocalizedError conformance in ScpBindings.swift.
// No additional conformance is needed here.
