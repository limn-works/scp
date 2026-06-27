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
  EconomyError,
  GovernanceError,
  IdentityError,
  McpError,
  mapBridgeError,
  PermissionError,
  ScpError,
  StorageError,
  ToolError,
  TransportError,
  UcanPermissionError,
  ValidationError,
} from "../src/errors";
import { wrapBridgeErrors } from "../src/internal/bridge";

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
    const err = new AttestationError("attestation failed", "SCP-ATTEST-9010");
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

  it("GovernanceError extends ScpError", () => {
    const err = new GovernanceError("gov failed", "SCP-GOV-11001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(GovernanceError);
    expect(err.name).toBe("GovernanceError");
  });

  it("EconomyError extends ScpError", () => {
    const err = new EconomyError("econ failed", "SCP-ECON-12001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(EconomyError);
    expect(err.name).toBe("EconomyError");
  });
});

describe("mapBridgeError", () => {
  it("maps identity error codes to IdentityError", () => {
    const err = mapBridgeError(new Error("[SCP-IDENT-1001] identity error: failed"));
    expect(err).toBeInstanceOf(IdentityError);
    expect(err.code).toBe("SCP-IDENT-1001");
  });

  it("maps the missing-signing-custody code to IdentityError", () => {
    // SCP-IDENT-1017 is surfaced by the NAPI-backed mint /
    // event-log-checkpoint paths (and the UniFFI-only delegate path) when the
    // creator/identity retains no signing custody (externally loaded). The
    // NAPI delegate path is registry-based and surfaces SCP-IDENT-1001 instead.
    // It must route to IdentityError, not the permission/nonce family it was
    // formerly overloaded onto.
    const err = mapBridgeError(
      new Error("[SCP-IDENT-1017] identity error: UCAN minting requires retained signing custody"),
    );
    expect(err).toBeInstanceOf(IdentityError);
    expect(err.code).toBe("SCP-IDENT-1017");
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

  it("maps PERM error codes in correct range to UcanPermissionError", () => {
    const err = mapBridgeError(new Error("[SCP-PERM-3021] permission error: denied"));
    expect(err).toBeInstanceOf(UcanPermissionError);
    expect(err.code).toBe("SCP-PERM-3021");
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

  it("maps VALID error codes to ValidationError", () => {
    const err = mapBridgeError(new Error("[SCP-VALID-7000] validation error: failed"));
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe("SCP-VALID-7000");
  });

  it("maps storage error codes to StorageError", () => {
    const err = mapBridgeError(new Error("[SCP-STORAGE-8001] storage error: write failed"));
    expect(err).toBeInstanceOf(StorageError);
    expect(err.code).toBe("SCP-STORAGE-8001");
  });

  it("maps attestation error codes to AttestationError", () => {
    const err = mapBridgeError(new Error("[SCP-ATTEST-9010] attestation error: failed"));
    expect(err).toBeInstanceOf(AttestationError);
    expect(err.code).toBe("SCP-ATTEST-9010");
  });

  it("maps MCP error codes to McpError", () => {
    const err = mapBridgeError(new Error("[SCP-MCP-10001] mcp error: connection failed"));
    expect(err).toBeInstanceOf(McpError);
    expect(err.code).toBe("SCP-MCP-10001");
  });

  it("maps governance error codes to GovernanceError", () => {
    const err = mapBridgeError(new Error("[SCP-GOV-11001] governance error: failed"));
    expect(err).toBeInstanceOf(GovernanceError);
    expect(err.code).toBe("SCP-GOV-11001");
  });

  it("maps generic economy error codes to EconomyError", () => {
    const err = mapBridgeError(new Error("[SCP-ECON-12001] economy error: failed"));
    expect(err).toBeInstanceOf(EconomyError);
    expect(err.code).toBe("SCP-ECON-12001");
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

// ---------------------------------------------------------------------------
// Finding N: the already-typed pass-through guard is security-load-bearing.
//
// `mapBridgeError` short-circuits when its argument is already an `ScpError`
// (errors.ts) — without it, a typed guard error whose message has no
// `[SCP-CAT-NNNN]` bracket (the code lives on `.code`, not in the message)
// would be re-derived to the generic `SCP-UNKNOWN-0000` fallback, DOWNGRADING
// a precise typed error. That guard had ZERO coverage, so a future deletion
// would silently re-open the downgrade with the suite green. These tests pin
// it directly AND through the `wrapBridgeErrors` Proxy dispatch surface.
// ---------------------------------------------------------------------------

describe("mapBridgeError already-typed pass-through (Finding N)", () => {
  it("returns the SAME instance for an already-typed ScpError (no downgrade)", () => {
    // A bracket-less message: the code is ONLY on `.code`. Re-deriving from the
    // message would fall back to SCP-UNKNOWN-0000.
    const typed = new TransportError("relay connection refused", "SCP-TRANS-5099");
    const mapped = mapBridgeError(typed);
    // Identity-preserving: not re-wrapped, not re-constructed.
    expect(mapped).toBe(typed);
    expect(mapped).toBeInstanceOf(TransportError);
    expect(mapped.code).toBe("SCP-TRANS-5099");
    // Crucially NOT downgraded to the unknown fallback.
    expect(mapped.code).not.toBe("SCP-UNKNOWN-0000");
  });

  it("preserves a bracket-less EconomicPolicyUnsupportedOnWasm subclass + code", () => {
    const typed = new EconomicPolicyUnsupportedOnWasm(
      "economic policy is unsupported on WASM",
      "SCP-ECON-12095",
    );
    const mapped = mapBridgeError(typed);
    expect(mapped).toBe(typed);
    expect(mapped).toBeInstanceOf(EconomicPolicyUnsupportedOnWasm);
    expect(mapped.code).toBe("SCP-ECON-12095");
  });

  it("keeps an already-typed throw intact when routed through wrapBridgeErrors", async () => {
    // A minimal bridge stub whose async method throws a typed error with a
    // bracket-LESS message. `wrapBridgeErrors` re-maps rejections through
    // `mapBridgeError`; the typed error must survive the round-trip with its
    // subclass and code intact (NOT downgraded to SCP-UNKNOWN-0000).
    const thrown = new TransportError("relay down", "SCP-TRANS-5099");
    const stub = {
      async failing(): Promise<never> {
        throw thrown;
      },
    } as unknown as Parameters<typeof wrapBridgeErrors>[0];
    const guarded = wrapBridgeErrors(stub) as unknown as { failing: () => Promise<never> };

    let caught: unknown;
    try {
      await guarded.failing();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TransportError);
    expect((caught as ScpError).code).toBe("SCP-TRANS-5099");
    expect((caught as ScpError).code).not.toBe("SCP-UNKNOWN-0000");
  });

  it("keeps a synchronous already-typed throw intact through wrapBridgeErrors", () => {
    // The Proxy must also map synchronous throws (e.g. an argument guard firing
    // before the first await). A pre-typed sync throw must pass through untouched.
    const thrown = new EconomicPolicyUnsupportedOnWasm("unsupported", "SCP-ECON-12095");
    const stub = {
      failing(): never {
        throw thrown;
      },
    } as unknown as Parameters<typeof wrapBridgeErrors>[0];
    const guarded = wrapBridgeErrors(stub) as unknown as { failing: () => never };

    let caught: unknown;
    try {
      guarded.failing();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(EconomicPolicyUnsupportedOnWasm);
    expect((caught as ScpError).code).toBe("SCP-ECON-12095");
  });
});

// ---------------------------------------------------------------------------
// PreRotationCustodyError typed-code round-trip
//
// SDK-layer contract: when the NAPI bridge emits a typed
// IDENT_1047, IDENT_1048, IDENT_1049, IDENT_1050, IDENT_1051, or
// IDENT_1052 code for a PreRotationCustodyError variant, the TS SDK's
// `mapBridgeError` and the `IdentityError` class MUST preserve the code
// verbatim. The Rust bridge has its own co-located regression tests
// pinning the variant-to-code mapping; this suite pins the SDK-layer
// fall-through so a TypeScript wrapper change can't silently strip or
// rewrite the code.
//
// Literal codes also appear here as string constants — they trip a diff
// reviewer if the bridge ever re-numbers a variant without updating the
// SDK in lockstep.
// ---------------------------------------------------------------------------

const PRE_ROTATION_HANDLE_NOT_FOUND_CODE = "SCP-IDENT-1047";
const PRE_ROTATION_UNAVAILABLE_CODE = "SCP-IDENT-1048";
const PRE_ROTATION_USER_DECLINED_CODE = "SCP-IDENT-1049";
const PRE_ROTATION_STORAGE_CODE = "SCP-IDENT-1050";
const PRE_ROTATION_INVALID_CALLBACK_CODE = "SCP-IDENT-1051";
const PRE_ROTATION_COMMITMENT_MISMATCH_CODE = "SCP-IDENT-1052";

describe("PreRotationCustodyError typed codes round-trip", () => {
  it.each([
    PRE_ROTATION_HANDLE_NOT_FOUND_CODE,
    PRE_ROTATION_UNAVAILABLE_CODE,
    PRE_ROTATION_USER_DECLINED_CODE,
    PRE_ROTATION_STORAGE_CODE,
    PRE_ROTATION_INVALID_CALLBACK_CODE,
    PRE_ROTATION_COMMITMENT_MISMATCH_CODE,
  ])("IdentityError preserves typed code %s", (code) => {
    // SDK-layer construction — pins that the IdentityError class itself
    // does not strip, rewrite, or normalize the code.
    const err = new IdentityError("pre-rotation failure", code);
    expect(err).toBeInstanceOf(IdentityError);
    expect(err).toBeInstanceOf(ScpError);
    expect(err.code).toBe(code);
    expect(err.message).toBe("pre-rotation failure");
  });

  it.each([
    PRE_ROTATION_HANDLE_NOT_FOUND_CODE,
    PRE_ROTATION_UNAVAILABLE_CODE,
    PRE_ROTATION_USER_DECLINED_CODE,
    PRE_ROTATION_STORAGE_CODE,
    PRE_ROTATION_INVALID_CALLBACK_CODE,
    PRE_ROTATION_COMMITMENT_MISMATCH_CODE,
  ])("mapBridgeError routes %s to IdentityError with preserved code", (code) => {
    // Bridge-emitted format: "[{code}] identity error: {message}".
    // The TS SDK's parser must extract the code, route to IdentityError,
    // and surface the same code on `.code` — never rewrite it to a
    // generic SCP-IDENT-1001 fallback.
    const bridgeError = new Error(`[${code}] identity error: pre-rotation failure`);
    const mapped = mapBridgeError(bridgeError);
    expect(mapped).toBeInstanceOf(IdentityError);
    expect(mapped.code).toBe(code);
  });

  it("non-pre-rotation identity errors retain SCP-IDENT-1001 fallback", () => {
    // Defense-in-depth: pin the generic-envelope fallback so a future
    // refactor that accidentally promotes SCP-IDENT-1001 to one of the
    // typed pre-rotation codes is caught at test time.
    const bridgeError = new Error("[SCP-IDENT-1001] identity error: invalid DID format");
    const mapped = mapBridgeError(bridgeError);
    expect(mapped).toBeInstanceOf(IdentityError);
    expect(mapped.code).toBe("SCP-IDENT-1001");
  });
});
