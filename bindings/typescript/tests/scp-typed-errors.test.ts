/**
 * Typed-error mapping for the `SCP` class surface.
 *
 * Every `SCP` method that forwards to the native NAPI bridge wraps the call in
 * `try { ... } catch (err) { throw mapBridgeError(err); }`, so a raw NAPI
 * `Error` (a plain `Error` whose message carries a `[SCP-XXX-NNNN]` code) is
 * surfaced to SDK callers as the matching typed {@link ScpError} subclass
 * rather than a bare `Error`. These tests pin that contract across the async,
 * sync, `getBridge`-routed, and `nativeFreeFn`-routed shapes.
 *
 * `ucanValidate` and `eventLogQuery` are wrapped like every other method.
 * Their sole SDK consumer (`evaluateTrust` in trust.ts) classifies errors by
 * inspecting the `[SCP-...]` code prefix on the error message — and
 * `mapBridgeError` preserves the original message verbatim, so the typed
 * {@link ScpError} subclass it produces still carries the prefix and trust
 * classification is unaffected.
 */

import { describe, expect, it } from "bun:test";
import {
  ContextError,
  GovernanceError,
  IdentityError,
  OutletError,
  ScpError,
  UcanPermissionError,
} from "../src/errors";
import type { Bridge } from "../src/internal/bridge";
import { __setBridgeForTests, wrapBridgeErrors } from "../src/internal/bridge";
import { mountMockScp } from "./mock-bridge";

/** Build a plain NAPI-style error: a bare `Error` carrying a code prefix. */
function rawBridgeError(message: string): Error {
  return new Error(message);
}

/**
 * Properties that the JS runtime probes on objects (Promise interop,
 * inspection, coercion). Spy bridges must return `undefined` for these
 * so `await` and `util.inspect` don't chase thenable / iterator paths.
 */
const PROBE_PROPS = new Set<string | symbol>([
  "then",
  "catch",
  "finally",
  Symbol.toPrimitive,
  Symbol.toStringTag,
  Symbol.iterator,
  Symbol.asyncIterator,
]);

/**
 * Build a minimal spy Bridge Proxy that rejects the named method with the
 * given raw error, and throws for any other unexpected call. Wrap with
 * `wrapBridgeErrors` before injecting so error mapping runs as it does in
 * production (`createNativeBridge` also wraps the bridge).
 */
function makeSpyBridge(method: string, error: Error): Bridge {
  const spy = new Proxy({} as Bridge, {
    get(_t, prop) {
      if (PROBE_PROPS.has(prop)) return undefined;
      if (prop === method) {
        return (..._args: unknown[]) => Promise.reject(error);
      }
      throw new Error(`Spy bridge: unexpected call to Bridge.${String(prop)}`);
    },
  });
  return wrapBridgeErrors(spy);
}

describe("SCP typed-error mapping", () => {
  it("contextSend surfaces a typed ContextError with the documented SCP-CTX-2095 code", async () => {
    // The contextSend JSDoc promises a typed `ContextError` with code
    // `SCP-CTX-2095` when a multi-member encrypted send fails closed.
    const { scp } = mountMockScp();
    __setBridgeForTests(
      scp,
      makeSpyBridge(
        "contextSend",
        rawBridgeError(
          "[SCP-CTX-2095] context error: no peer routing id announced yet — retry after pseudonym announcement",
        ),
      ),
    );

    let thrown: unknown;
    try {
      await scp.contextSend({}, "did:dht:z6MkAlice", new Uint8Array([1, 2, 3]));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ContextError);
    expect((thrown as ContextError).code).toBe("SCP-CTX-2095");
  });

  it("maps an async governance error to GovernanceError", async () => {
    const { scp } = mountMockScp();
    __setBridgeForTests(
      scp,
      makeSpyBridge(
        "contextGovernancePropose",
        rawBridgeError("[SCP-GOV-11001] governance error: proposer is not a member"),
      ),
    );

    let thrown: unknown;
    try {
      await scp.contextGovernancePropose({}, "{}", "did:dht:z6MkAlice");
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GovernanceError);
    expect((thrown as GovernanceError).code).toBe("SCP-GOV-11001");
  });

  it("maps an async outlet error to OutletError", async () => {
    const { scp } = mountMockScp();
    __setBridgeForTests(
      scp,
      makeSpyBridge(
        "outletInvoke",
        rawBridgeError("[SCP-OUTLET-6002] outlet error: outlet not registered"),
      ),
    );

    let thrown: unknown;
    try {
      await scp.outletInvoke({}, "calculator", "{}", "did:dht:z6MkAlice", "ucan-token");
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(OutletError);
    expect((thrown as OutletError).code).toBe("SCP-OUTLET-6002");
  });

  it("maps a sync identity error from a sync method (identityRemove)", () => {
    const { scp, native } = mountMockScp();
    native.__stub("identityRemove", () => {
      throw rawBridgeError("[SCP-IDENT-1003] identity error: unknown DID");
    });

    let thrown: unknown;
    try {
      scp.identityRemove("did:dht:z6MkUnknown");
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(IdentityError);
    expect((thrown as IdentityError).code).toBe("SCP-IDENT-1003");
  });

  it("maps a sync permission error from a sync method (identityExecuteRecovery)", () => {
    const { scp, native } = mountMockScp();
    native.__stub("identityExecuteRecovery", () => {
      throw rawBridgeError(
        "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance",
      );
    });

    let thrown: unknown;
    try {
      scp.identityExecuteRecovery("did:dht:z6MkAlice", "full", ["ctx-1"]);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(UcanPermissionError);
    expect((thrown as UcanPermissionError).code).toBe("SCP-PERM-3030");
  });

  it("falls back to the base ScpError for a code with no registered class", async () => {
    const { scp } = mountMockScp();
    __setBridgeForTests(
      scp,
      makeSpyBridge(
        "contextMemberCount",
        rawBridgeError("[SCP-UNKNOWN-9999] something unmapped happened"),
      ),
    );

    let thrown: unknown;
    try {
      await scp.contextMemberCount({});
    } catch (err) {
      thrown = err;
    }
    // Must be exactly ScpError, not a subclass — TransportError extends ScpError
    // so toBeInstanceOf(ScpError) alone would pass vacuously on a transport failure.
    expect((thrown as ScpError).constructor).toBe(ScpError);
    expect((thrown as ScpError).code).toBe("SCP-UNKNOWN-9999");
  });
});

describe("SCP typed-error mapping (trust.ts consumers)", () => {
  it("maps a ucanValidate PERM-3030 error to UcanPermissionError with the prefix preserved", async () => {
    const { scp } = mountMockScp();
    const message = "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance";
    __setBridgeForTests(scp, makeSpyBridge("ucanValidate", rawBridgeError(message)));

    let thrown: unknown;
    try {
      await scp.ucanValidate({}, "token", "*", "did:key:testpresenter");
    } catch (err) {
      thrown = err;
    }
    // Re-typed to UcanPermissionError, but `mapBridgeError` keeps the message
    // verbatim — so trust.ts's `[SCP-PERM-3030]` prefix classification still
    // matches.
    expect(thrown).toBeInstanceOf(UcanPermissionError);
    expect((thrown as UcanPermissionError).code).toBe("SCP-PERM-3030");
    expect((thrown as UcanPermissionError).message).toBe(message);
  });

  it("maps an eventLogQuery CTX error to ContextError with the prefix preserved", async () => {
    const { scp, native } = mountMockScp();
    const message = "[SCP-CTX-2001] context error: not a member";
    native.__stub("eventLogQuery", () => Promise.reject(rawBridgeError(message)));

    let thrown: unknown;
    try {
      await scp.eventLogQuery({});
    } catch (err) {
      thrown = err;
    }
    // Re-typed to ContextError, but the verbatim message keeps the
    // `[SCP-CTX-]` prefix that trust.ts Layer 2 classifies on.
    expect(thrown).toBeInstanceOf(ContextError);
    expect((thrown as ContextError).code).toBe("SCP-CTX-2001");
    expect((thrown as ContextError).message).toBe(message);
  });
});
