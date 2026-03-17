/**
 * Tests for client-side ContentPath, MimeType, and deploy_id validation (SCP-297).
 *
 * Validates that the SDK-layer validation functions produce clear, descriptive
 * error messages for invalid inputs BEFORE the FFI boundary is crossed.
 *
 * Mirrors the Rust validation in `crates/scp-core/src/context/broadcast_content.rs`.
 */

import { describe, expect, it } from "bun:test";
import { _validateContentPath, _validateDeployId, _validateMimeType } from "../src/context";
import { ValidationError } from "../src/errors";

// ---------------------------------------------------------------------------
// ContentPath validation
// ---------------------------------------------------------------------------

describe("validateContentPath (SCP-297)", () => {
  it("accepts root path", () => {
    expect(() => _validateContentPath("/")).not.toThrow();
  });

  it("accepts simple path", () => {
    expect(() => _validateContentPath("/index.html")).not.toThrow();
  });

  it("accepts nested path", () => {
    expect(() => _validateContentPath("/assets/css/main.css")).not.toThrow();
  });

  it("accepts hidden file", () => {
    expect(() => _validateContentPath("/.well-known/acme-challenge/token")).not.toThrow();
  });

  it("rejects path without leading slash", () => {
    expect(() => _validateContentPath("index.html")).toThrow(ValidationError);
    expect(() => _validateContentPath("index.html")).toThrow(/must start with '\/'/);
  });

  it("rejects empty string", () => {
    expect(() => _validateContentPath("")).toThrow(ValidationError);
  });

  it("rejects path exceeding 1024 bytes", () => {
    expect(() => _validateContentPath(`/${"a".repeat(1024)}`)).toThrow(/exceeds 1024 bytes/);
  });

  it("rejects backslash", () => {
    expect(() => _validateContentPath("/path\\file")).toThrow(/backslashes/);
  });

  it("rejects percent-encoded bytes", () => {
    expect(() => _validateContentPath("/path%20file")).toThrow(/percent-encoded/);
  });

  it("rejects query string", () => {
    expect(() => _validateContentPath("/path?key=value")).toThrow(/query strings/);
  });

  it("rejects fragment", () => {
    expect(() => _validateContentPath("/path#section")).toThrow(/fragments/);
  });

  it("rejects null byte", () => {
    expect(() => _validateContentPath("/path\0file")).toThrow(/null bytes/);
  });

  it("rejects control character", () => {
    expect(() => _validateContentPath("/path\x01file")).toThrow(/control character/);
  });

  it("rejects DEL character", () => {
    expect(() => _validateContentPath("/path\x7ffile")).toThrow(/control character/);
  });

  it("rejects double slash", () => {
    expect(() => _validateContentPath("/path//file")).toThrow(/\/\//);
  });

  it("rejects trailing slash", () => {
    expect(() => _validateContentPath("/path/")).toThrow(/trailing slash/);
  });

  it("rejects dot segment", () => {
    expect(() => _validateContentPath("/path/./file")).toThrow(/'\.' segments/);
  });

  it("rejects dotdot segment", () => {
    expect(() => _validateContentPath("/path/../etc/passwd")).toThrow(/directory traversal/);
  });

  it("rejects C1 control character (Fix 4)", () => {
    expect(() => _validateContentPath("/path\u0085file")).toThrow(/control character U\+0085/);
  });

  it("rejects zero-width space (Fix 1)", () => {
    expect(() => _validateContentPath("/path\u200Bfile")).toThrow(/whitespace\/formatting U\+200B/);
  });

  it("rejects bidi override (Fix 1)", () => {
    expect(() => _validateContentPath("/path\u202Efile")).toThrow(/whitespace\/formatting U\+202E/);
  });

  it("rejects NBSP (Fix 1)", () => {
    expect(() => _validateContentPath("/path\u00A0file")).toThrow(/whitespace\/formatting U\+00A0/);
  });

  it("NFC normalizes before validation (Fix 3)", () => {
    // U+0065 U+0301 (e + combining acute) normalizes to U+00E9 (e-acute)
    expect(() => _validateContentPath("/caf\u0065\u0301")).not.toThrow();
  });

  it("uses error code SCP-VALID-7010", () => {
    expect.assertions(2);
    try {
      _validateContentPath("no-slash");
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7010");
    }
  });
});

// ---------------------------------------------------------------------------
// MimeType validation
// ---------------------------------------------------------------------------

describe("validateMimeType (SCP-297)", () => {
  it("accepts text/html", () => {
    expect(() => _validateMimeType("text/html")).not.toThrow();
  });

  it("accepts application/json", () => {
    expect(() => _validateMimeType("application/json")).not.toThrow();
  });

  it("accepts image/png", () => {
    expect(() => _validateMimeType("image/png")).not.toThrow();
  });

  it("rejects empty string", () => {
    expect(() => _validateMimeType("")).toThrow(/must not be empty/);
  });

  it("rejects no slash", () => {
    expect(() => _validateMimeType("texthtml")).toThrow(/exactly one '\/'/);
  });

  it("rejects double slash", () => {
    expect(() => _validateMimeType("text/html/extra")).toThrow(/exactly one '\/'/);
  });

  it("rejects empty type part", () => {
    expect(() => _validateMimeType("/html")).toThrow(/both be non-empty/);
  });

  it("rejects empty subtype part", () => {
    expect(() => _validateMimeType("text/")).toThrow(/both be non-empty/);
  });

  it("rejects semicolon (parameters)", () => {
    expect(() => _validateMimeType("text/html; charset=utf-8")).toThrow(/parameters/);
  });

  it("rejects carriage return", () => {
    expect(() => _validateMimeType("text/html\r")).toThrow(/control character/);
  });

  it("rejects line feed", () => {
    expect(() => _validateMimeType("text/html\n")).toThrow(/control character/);
  });

  it("rejects null byte", () => {
    expect(() => _validateMimeType("text/\x00html")).toThrow(/control character/);
  });

  it("rejects C1 control character in MIME type (Fix 4)", () => {
    expect(() => _validateMimeType("text/\u0085html")).toThrow(/control character U\+0085/);
  });

  it("rejects non-tchar in type part (Fix 2)", () => {
    expect(() => _validateMimeType("te xt/html")).toThrow(/type part contains invalid/);
  });

  it("rejects non-tchar in subtype part (Fix 2)", () => {
    expect(() => _validateMimeType("text/ht ml")).toThrow(/subtype part contains invalid/);
  });

  it("accepts tchar special characters (Fix 2)", () => {
    expect(() => _validateMimeType("application/vnd.foo+bar")).not.toThrow();
  });

  it("uses error code SCP-VALID-7011", () => {
    expect.assertions(2);
    try {
      _validateMimeType("");
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7011");
    }
  });
});

// ---------------------------------------------------------------------------
// deploy_id validation
// ---------------------------------------------------------------------------

describe("validateDeployId (SCP-297)", () => {
  it("accepts simple deploy ID", () => {
    expect(() => _validateDeployId("deploy-1")).not.toThrow();
  });

  it("accepts hex string", () => {
    expect(() => _validateDeployId("abc123def456")).not.toThrow();
  });

  it("accepts underscore", () => {
    expect(() => _validateDeployId("my_deploy_id")).not.toThrow();
  });

  it("accepts mixed case", () => {
    expect(() => _validateDeployId("Deploy-2024_v1")).not.toThrow();
  });

  it("rejects empty string", () => {
    expect(() => _validateDeployId("")).toThrow(/must not be empty/);
  });

  it("rejects string over 128 bytes", () => {
    expect(() => _validateDeployId("a".repeat(129))).toThrow(/exceeds 128 bytes/);
  });

  it("rejects spaces", () => {
    expect(() => _validateDeployId("deploy 1")).toThrow(/ASCII alphanumeric/);
  });

  it("rejects special characters", () => {
    expect(() => _validateDeployId("deploy@1")).toThrow(/ASCII alphanumeric/);
  });

  it("rejects slash", () => {
    expect(() => _validateDeployId("deploy/1")).toThrow(/ASCII alphanumeric/);
  });

  it("uses error code SCP-VALID-7012", () => {
    expect.assertions(2);
    try {
      _validateDeployId("");
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7012");
    }
  });
});
