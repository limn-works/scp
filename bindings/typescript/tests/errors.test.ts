/**
 * Tests for the ScpError hierarchy and error mapping.
 *
 * See `.docs/standards/sdk-common.md` for the cross-SDK error hierarchy.
 */

import { describe, expect, it } from "bun:test";
import {
  AttestationError,
  ContextError,
  CryptoError,
  IdentityError,
  mapBridgeError,
  McpError,
  PermissionError,
  ScpError,
  StorageError,
  ToolError,
  TransportError,
  UcanPermissionError,
  ValidationError,
} from "../src/errors.js";

describe("ScpError hierarchy", () => {
  it("ScpError is the root error class", () => {
    const err = new ScpError("test", "SCP-TEST-0000");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ScpError);
    expect(err.name).toBe("ScpError");
    expect(err.message).toBe("test");
    expect(err.code).toBe("SCP-TEST-0000");
  });

  it("IdentityError extends ScpError", () => {
    const err = new IdentityError("identity failed", "SCP-IDENT-1001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(IdentityError);
    expect(err.name).toBe("IdentityError");
    expect(err.code).toBe("SCP-IDENT-1001");
  });

  it("ContextError extends ScpError", () => {
    const err = new ContextError("context failed", "SCP-CTX-2001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(ContextError);
    expect(err.name).toBe("ContextError");
  });

  it("UcanPermissionError extends ScpError", () => {
    const err = new UcanPermissionError("denied", "SCP-PERM-3001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect(err.name).toBe("UcanPermissionError");
  });

  it("PermissionError alias points to UcanPermissionError", () => {
    expect(PermissionError).toBe(UcanPermissionError);
    const err = new PermissionError("denied", "SCP-PERM-3001");
    expect(err).toBeInstanceOf(UcanPermissionError);
  });

  it("CryptoError extends ScpError", () => {
    const err = new CryptoError("crypto failed", "SCP-CRYPTO-4001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(CryptoError);
    expect(err.name).toBe("CryptoError");
  });

  it("TransportError extends ScpError", () => {
    const err = new TransportError("connection failed", "SCP-TRANS-5001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(TransportError);
    expect(err.name).toBe("TransportError");
  });

  it("ToolError extends ScpError", () => {
    const err = new ToolError("tool failed", "SCP-TOOL-6001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(ToolError);
    expect(err.name).toBe("ToolError");
  });

  it("ValidationError extends ScpError", () => {
    const err = new ValidationError("invalid input", "SCP-VALID-7001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.name).toBe("ValidationError");
  });

  it("StorageError extends ScpError", () => {
    const err = new StorageError("write failed", "SCP-STORAGE-8001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(StorageError);
    expect(err.name).toBe("StorageError");
  });

  it("AttestationError extends ScpError", () => {
    const err = new AttestationError("attestation failed", "SCP-ATTEST-9001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.name).toBe("AttestationError");
  });

  it("McpError extends ScpError", () => {
    const err = new McpError("mcp failed", "SCP-MCP-10001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(McpError);
    expect(err.name).toBe("McpError");
  });
});

describe("mapBridgeError", () => {
  it("maps identity error codes to IdentityError", () => {
    const err = mapBridgeError(new Error("[SCP-IDENT-1001] identity error: failed"));
    expect(err).toBeInstanceOf(IdentityError);
    expect(err.code).toBe("SCP-IDENT-1001");
  });

  it("maps context error codes to ContextError", () => {
    const err = mapBridgeError(new Error("[SCP-CTX-2001] context error: failed"));
    expect(err).toBeInstanceOf(ContextError);
    expect(err.code).toBe("SCP-CTX-2001");
  });

  it("maps permission error codes to UcanPermissionError", () => {
    const err = mapBridgeError(new Error("[SCP-PERM-3001] permission error: denied"));
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect(err.code).toBe("SCP-PERM-3001");
  });

  it("maps PRM prefix to UcanPermissionError", () => {
    const err = mapBridgeError(new Error("[SCP-PRM-4002] permission error: denied"));
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect(err.code).toBe("SCP-PRM-4002");
  });

  it("maps crypto error codes to CryptoError", () => {
    const err = mapBridgeError(new Error("[SCP-CRYPTO-4001] crypto error: failed"));
    expect(err).toBeInstanceOf(CryptoError);
    expect(err.code).toBe("SCP-CRYPTO-4001");
  });

  it("maps transport error codes to TransportError", () => {
    const err = mapBridgeError(new Error("[SCP-TRANS-5001] transport error: failed"));
    expect(err).toBeInstanceOf(TransportError);
    expect(err.code).toBe("SCP-TRANS-5001");
  });

  it("maps tool error codes to ToolError", () => {
    const err = mapBridgeError(new Error("[SCP-TOOL-6001] tool error: failed"));
    expect(err).toBeInstanceOf(ToolError);
    expect(err.code).toBe("SCP-TOOL-6001");
  });

  it("maps validation error codes to ValidationError", () => {
    const err = mapBridgeError(new Error("[SCP-VALID-7001] validation error: failed"));
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe("SCP-VALID-7001");
  });

  it("maps VAL prefix to ValidationError", () => {
    const err = mapBridgeError(new Error("[SCP-VAL-7000] validation error: failed"));
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe("SCP-VAL-7000");
  });

  it("maps storage error codes to StorageError", () => {
    const err = mapBridgeError(new Error("[SCP-STORAGE-8001] storage error: write failed"));
    expect(err).toBeInstanceOf(StorageError);
    expect(err.code).toBe("SCP-STORAGE-8001");
  });

  it("maps attestation error codes to AttestationError", () => {
    const err = mapBridgeError(new Error("[SCP-ATTEST-9001] attestation error: failed"));
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.code).toBe("SCP-ATTEST-9001");
  });

  it("maps MCP error codes to McpError", () => {
    const err = mapBridgeError(new Error("[SCP-MCP-10001] mcp error: connection failed"));
    expect(err).toBeInstanceOf(McpError);
    expect(err.code).toBe("SCP-MCP-10001");
  });

  it("falls back to ScpError for unknown error codes", () => {
    const err = mapBridgeError(new Error("[SCP-UNKNOWN-9999] something failed"));
    expect(err).toBeInstanceOf(ScpError);
    expect(err.code).toBe("SCP-UNKNOWN-9999");
  });

  it("handles plain string errors", () => {
    const err = mapBridgeError("something went wrong");
    expect(err).toBeInstanceOf(ScpError);
    expect(err.code).toBe("SCP-UNKNOWN-0000");
  });

  it("handles errors without bracketed codes", () => {
    const err = mapBridgeError(new Error("no code here"));
    expect(err).toBeInstanceOf(ScpError);
    expect(err.code).toBe("SCP-UNKNOWN-0000");
  });
});
