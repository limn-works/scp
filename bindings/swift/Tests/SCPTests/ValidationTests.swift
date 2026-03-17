import Foundation
@testable import SCP
import Testing

// MARK: - Validation Tests (SCP-297)

// Tests for client-side ContentPath, MimeType, and deploy_id validation.
// These functions mirror the Rust validation in
// `crates/scp-core/src/context/broadcast_content.rs` and run before FFI crossing.

struct ValidationTests {
    // MARK: - ContentPath

    @Test("valid root path accepted")
    func contentPathRoot() throws {
        try validateContentPath("/")
    }

    @Test("valid simple path accepted")
    func contentPathSimple() throws {
        try validateContentPath("/index.html")
    }

    @Test("valid nested path accepted")
    func contentPathNested() throws {
        try validateContentPath("/assets/css/main.css")
    }

    @Test("valid hidden file accepted")
    func contentPathHidden() throws {
        try validateContentPath("/.well-known/acme-challenge/token")
    }

    @Test("rejects path without leading slash")
    func contentPathNoLeadingSlash() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("index.html")
        }
    }

    @Test("rejects empty path")
    func contentPathEmpty() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("")
        }
    }

    @Test("rejects path exceeding 1024 bytes")
    func contentPathTooLong() throws {
        let longPath = "/" + String(repeating: "a", count: 1024)
        #expect(throws: ScpError.self) {
            try validateContentPath(longPath)
        }
    }

    @Test("rejects backslash")
    func contentPathBackslash() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path\\file")
        }
    }

    @Test("rejects percent-encoded bytes")
    func contentPathPercentEncoded() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path%20file")
        }
    }

    @Test("rejects query string")
    func contentPathQueryString() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path?key=value")
        }
    }

    @Test("rejects fragment")
    func contentPathFragment() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path#section")
        }
    }

    @Test("rejects null byte")
    func contentPathNullByte() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path\0file")
        }
    }

    @Test("rejects control character")
    func contentPathControlChar() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path\u{01}file")
        }
    }

    @Test("rejects DEL character")
    func contentPathDel() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path\u{7F}file")
        }
    }

    @Test("rejects double slash")
    func contentPathDoubleSlash() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path//file")
        }
    }

    @Test("rejects trailing slash")
    func contentPathTrailingSlash() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path/")
        }
    }

    @Test("rejects dot segment")
    func contentPathDotSegment() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path/./file")
        }
    }

    @Test("rejects dotdot segment (directory traversal)")
    func contentPathDotDotSegment() throws {
        #expect(throws: ScpError.self) {
            try validateContentPath("/path/../etc/passwd")
        }
    }

    // MARK: - MimeType

    @Test("valid text/html accepted")
    func mimeTypeTextHtml() throws {
        try validateMimeType("text/html")
    }

    @Test("valid application/json accepted")
    func mimeTypeAppJson() throws {
        try validateMimeType("application/json")
    }

    @Test("valid image/png accepted")
    func mimeTypeImagePng() throws {
        try validateMimeType("image/png")
    }

    @Test("rejects empty MIME type")
    func mimeTypeEmpty() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("")
        }
    }

    @Test("rejects MIME type without slash")
    func mimeTypeNoSlash() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("texthtml")
        }
    }

    @Test("rejects MIME type with multiple slashes")
    func mimeTypeMultipleSlashes() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/html/extra")
        }
    }

    @Test("rejects empty type part")
    func mimeTypeEmptyType() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("/html")
        }
    }

    @Test("rejects empty subtype part")
    func mimeTypeEmptySubtype() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/")
        }
    }

    @Test("rejects semicolon (parameters)")
    func mimeTypeSemicolon() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/html; charset=utf-8")
        }
    }

    @Test("rejects carriage return")
    func mimeTypeCR() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/html\r")
        }
    }

    @Test("rejects line feed")
    func mimeTypeLF() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/html\n")
        }
    }

    @Test("rejects null byte")
    func mimeTypeNull() throws {
        #expect(throws: ScpError.self) {
            try validateMimeType("text/\0html")
        }
    }

    // MARK: - deploy_id

    @Test("valid simple deploy ID accepted")
    func deployIdSimple() throws {
        try validateDeployId("deploy-1")
    }

    @Test("valid hex deploy ID accepted")
    func deployIdHex() throws {
        try validateDeployId("abc123def456")
    }

    @Test("valid underscore deploy ID accepted")
    func deployIdUnderscore() throws {
        try validateDeployId("my_deploy_id")
    }

    @Test("valid mixed deploy ID accepted")
    func deployIdMixed() throws {
        try validateDeployId("Deploy-2024_v1")
    }

    @Test("rejects empty deploy ID")
    func deployIdEmpty() throws {
        #expect(throws: ScpError.self) {
            try validateDeployId("")
        }
    }

    @Test("rejects deploy ID over 128 bytes")
    func deployIdTooLong() throws {
        let long = String(repeating: "a", count: 129)
        #expect(throws: ScpError.self) {
            try validateDeployId(long)
        }
    }

    @Test("rejects deploy ID with spaces")
    func deployIdSpaces() throws {
        #expect(throws: ScpError.self) {
            try validateDeployId("deploy 1")
        }
    }

    @Test("rejects deploy ID with special characters")
    func deployIdSpecialChars() throws {
        #expect(throws: ScpError.self) {
            try validateDeployId("deploy@1")
        }
    }

    @Test("rejects deploy ID with slash")
    func deployIdSlash() throws {
        #expect(throws: ScpError.self) {
            try validateDeployId("deploy/1")
        }
    }
}
