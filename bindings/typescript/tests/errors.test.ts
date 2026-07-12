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
  mapSagaError,
  OutletError,
  PermissionError,
  SagaAbortedError,
  SagaBusyError,
  SagaNeedsRepairError,
  ScpError,
  StorageError,
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

  it("OutletError extends ScpError", () => {
    const err = new OutletError("outlet failed", "SCP-OUTLET-6001");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).toBeInstanceOf(OutletError);
    expect(err.name).toBe("OutletError");
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

  it("maps outlet error codes to OutletError", () => {
    const err = mapBridgeError(new Error("[SCP-OUTLET-6001] outlet error: failed"));
    expect(err).toBeInstanceOf(OutletError);
    expect(err.code).toBe("SCP-OUTLET-6001");
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
    const thrown = new TransportError("relay down", "SCP-TRANS-5099");
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
    expect(caught).toBeInstanceOf(TransportError);
    expect((caught as ScpError).code).toBe("SCP-TRANS-5099");
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

// ---------------------------------------------------------------------------
// mapSagaError — §6.2.4 saga terminal Display-string reversal
// ---------------------------------------------------------------------------

describe("mapSagaError", () => {
  it("maps a saga-aborted Display string to SagaAbortedError", () => {
    const err = mapSagaError(
      new Error("[SCP-SAGA-13067] saga aborted: rate limited (retry_after_ms=2500)"),
    );
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect(err.code).toBe("SCP-SAGA-13067");
    expect((err as SagaAbortedError).retryAfterMs).toBe(2500);
  });

  it("maps a saga-needs-repair Display string to SagaNeedsRepairError", () => {
    const err = mapSagaError(
      new Error("[SCP-SAGA-13065] saga needs repair: diverged (saga_id=repair-77)"),
    );
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect(err.code).toBe("SCP-SAGA-13065");
    expect((err as SagaNeedsRepairError).sagaId).toBe("repair-77");
  });

  it("maps a saga-busy Display string to SagaBusyError", () => {
    const err = mapSagaError(
      new Error("[SCP-SAGA-13066] saga busy: overlap (contended_context=ctx-shared)"),
    );
    expect(err).toBeInstanceOf(SagaBusyError);
    expect(err.code).toBe("SCP-SAGA-13066");
    expect((err as SagaBusyError).contendedContext).toBe("ctx-shared");
  });

  it("reads the LAST retry_after_ms, ignoring a decoy embedded in the message", () => {
    // The Display suffix is always terminal, so the end-anchored regex is
    // last-anchored: a decoy `(retry_after_ms=999)` inside `{message}` is
    // non-terminal and cannot match — only the genuine trailing 2500 does.
    const err = mapSagaError(
      new Error(
        "[SCP-SAGA-13026] saga aborted: limiter (retry_after_ms=999) tripped (retry_after_ms=2500)",
      ),
    );
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).retryAfterMs).toBe(2500);
  });

  it("reads the LAST saga_id, ignoring a decoy embedded in the message", () => {
    const err = mapSagaError(
      new Error("[SCP-SAGA-13065] saga needs repair: id (saga_id=decoy) here (saga_id=real-88)"),
    );
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect((err as SagaNeedsRepairError).sagaId).toBe("real-88");
  });

  it("reads the LAST contended_context, ignoring a decoy embedded in the message", () => {
    const err = mapSagaError(
      new Error(
        "[SCP-SAGA-13066] saga busy: ctx (contended_context=decoy) then (contended_context=real-ctx)",
      ),
    );
    expect(err).toBeInstanceOf(SagaBusyError);
    expect((err as SagaBusyError).contendedContext).toBe("real-ctx");
  });

  it("maps a null retry_after_ms suffix to retryAfterMs null (never 0)", () => {
    const err = mapSagaError(
      new Error("[SCP-SAGA-13067] saga aborted: hard limit (retry_after_ms=null)"),
    );
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).retryAfterMs).toBeNull();
  });

  it("maps an absent retry_after_ms suffix to retryAfterMs null", () => {
    // Defensive: even if the suffix is somehow missing, the datum is null,
    // never 0 (a `0` would read as "retry immediately" and re-trip the limit).
    const err = mapSagaError(new Error("[SCP-SAGA-13067] saga aborted: no suffix"));
    expect(err).toBeInstanceOf(SagaAbortedError);
    expect((err as SagaAbortedError).retryAfterMs).toBeNull();
  });

  it("dispatches on the prefix-anchored phrase, not a body decoy (needs repair)", () => {
    // A NeedsRepair terminal whose {message} embeds the decoy phrase
    // "] saga aborted:" must classify on the prefix-anchored phrase
    // ("saga needs repair"), NOT the body decoy — otherwise the
    // load-bearing sagaId repair handle would be silently dropped.
    const err = mapSagaError(
      new Error("[SCP-SAGA-13065] saga needs repair: a] saga aborted: b (saga_id=SID123)"),
    );
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect((err as SagaNeedsRepairError).sagaId).toBe("SID123");
  });

  it("dispatches on the prefix-anchored phrase, not a body decoy (busy)", () => {
    // Symmetric: a Busy terminal whose {message} embeds "] saga aborted:"
    // must classify as busy and preserve contendedContext.
    const err = mapSagaError(
      new Error("[SCP-SAGA-13066] saga busy: x] saga aborted: y (contended_context=ctxABC)"),
    );
    expect(err).toBeInstanceOf(SagaBusyError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect((err as SagaBusyError).contendedContext).toBe("ctxABC");
  });

  it("delegates a non-saga error to mapBridgeError", () => {
    const err = mapSagaError(new Error("[SCP-OUTLET-6011] outlet error: target not active"));
    expect(err).toBeInstanceOf(OutletError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err).not.toBeInstanceOf(SagaNeedsRepairError);
    expect(err).not.toBeInstanceOf(SagaBusyError);
    expect(err.code).toBe("SCP-OUTLET-6011");
  });

  it("delegates a code-less string to mapBridgeError", () => {
    const err = mapSagaError("something went wrong");
    expect(err).toBeInstanceOf(ScpError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err.code).toBe("SCP-UNKNOWN-0000");
  });

  it("reads the code from the START-anchored bracket, not a body decoy", () => {
    // The code regex is start-anchored (`^\s*\[`), so a non-saga error whose
    // {message} embeds a literal `[SCP-SAGA-…]` cannot be hijacked into a saga
    // subclass: only the leading bracket is read as the code, which here is a
    // SCP-OUTLET code, so the error delegates to mapBridgeError as a OutletError.
    const err = mapSagaError(
      new Error("[SCP-OUTLET-6011] outlet error: see [SCP-SAGA-13067] note"),
    );
    expect(err).toBeInstanceOf(OutletError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err).not.toBeInstanceOf(SagaNeedsRepairError);
    expect(err).not.toBeInstanceOf(SagaBusyError);
    expect(err.code).toBe("SCP-OUTLET-6011");
  });

  it("falls to the default arm for a valid SCP-SAGA code with an unrecognized phrase", () => {
    // A genuine SCP-SAGA code whose phrase matches none of the three known
    // terminals falls to the `default` arm → a generic OutletError that preserves
    // the code, rather than silently dropping it or mis-classifying it as a saga
    // subclass.
    const err = mapSagaError(new Error("[SCP-SAGA-13099] saga vanished: weird state (x=1)"));
    expect(err).toBeInstanceOf(OutletError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err).not.toBeInstanceOf(SagaNeedsRepairError);
    expect(err).not.toBeInstanceOf(SagaBusyError);
    expect(err.code).toBe("SCP-SAGA-13099");
  });

  it("does not over-capture saga_id across an unbalanced inner paren", () => {
    // The caller-influenced {message} body embeds an unbalanced `(saga_id=`
    // before the genuine trailing suffix. With a `[^)]*` capture the regex
    // would cross the inner `(` and read "spoof here (saga_id=GENUINE",
    // corrupting the repair handle. The `[^()]*` capture cannot cross a `(`,
    // so only the genuine trailing UUID-shaped value is read.
    const err = mapSagaError(
      new Error("[SCP-SAGA-13065] saga needs repair: evil (saga_id=spoof here (saga_id=GENUINE)"),
    );
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect((err as SagaNeedsRepairError).sagaId).toBe("GENUINE");
  });

  it("does not over-capture contended_context across an unbalanced inner paren", () => {
    // Symmetric to the saga_id case: an unbalanced `(contended_context=` in the
    // body must not let the capture cross the inner `(` and corrupt the value.
    const err = mapSagaError(
      new Error(
        "[SCP-SAGA-13066] saga busy: evil (contended_context=spoof (contended_context=CTXHEX)",
      ),
    );
    expect(err).toBeInstanceOf(SagaBusyError);
    expect((err as SagaBusyError).contendedContext).toBe("CTXHEX");
  });

  it("phrase dispatch is start-anchored against a full-bracket body decoy", () => {
    // The {message} embeds a full `[SCP-SAGA-13067] saga aborted: …` decoy after
    // the genuine prefix. The phrase regex is start-anchored (`^\s*\[`), so the
    // leading SCP-SAGA-13099 "vanished" phrase (unrecognized) forces the default
    // arm → a generic OutletError preserving the leading code. Without the anchor,
    // the body decoy would forge SagaAbortedError + retryAfterMs.
    const err = mapSagaError(
      new Error(
        "[SCP-SAGA-13099] saga vanished: oops [SCP-SAGA-13067] saga aborted: x (retry_after_ms=999)",
      ),
    );
    expect(err).toBeInstanceOf(OutletError);
    expect(err).not.toBeInstanceOf(SagaAbortedError);
    expect(err.code).toBe("SCP-SAGA-13099");
  });

  it("falls back to an empty sagaId when the needs-repair suffix is absent", () => {
    // No `(saga_id=…)` suffix at all ⇒ the `?? ""` fallback yields "", never a
    // fabricated handle.
    const err = mapSagaError(new Error("[SCP-SAGA-13065] saga needs repair: no suffix"));
    expect(err).toBeInstanceOf(SagaNeedsRepairError);
    expect((err as SagaNeedsRepairError).sagaId).toBe("");
  });

  it("falls back to an empty contendedContext when the busy suffix is absent", () => {
    // No `(contended_context=…)` suffix at all ⇒ the `?? ""` fallback yields "".
    const err = mapSagaError(new Error("[SCP-SAGA-13066] saga busy: no suffix"));
    expect(err).toBeInstanceOf(SagaBusyError);
    expect((err as SagaBusyError).contendedContext).toBe("");
  });
});
