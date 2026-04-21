/**
 * Integration-level tests for the SCP TypeScript SDK (post Phase 4 PR 4).
 *
 * After ADR-048 / #1549 Phase 4 PR 4 the SDK's namespace classes
 * (`Identity`, `Context`, `Relay`, `Node`) collapsed to pure handle
 * types, all stateful operations moved onto the {@link SCP} class, and
 * the flat `Bridge` interface was deleted from the SDK surface. The
 * previous integration suite exercised an in-memory mock `Bridge`
 * implementation that simulated the whole protocol state machine
 * (member join events, tool handlers, UCAN revocation, broadcast
 * subscribers, etc.). Those assertions tested the mock, not the SDK.
 *
 * What remains — and what this file now covers — is the SDK-level
 * behavior that can be exercised without a live native bridge:
 *
 * 1. **Pure-function validators** (`_validateEconomicPolicyJson`) and
 *    wire-format encoders (`encodeConsequenceRules`,
 *    `encodeConsequenceConfig`, the discriminated-union variant
 *    pinning exports).
 * 2. **Forwarder-dispatch plumbing** on the `SCP` class: methods route
 *    to the underlying native handle with the expected arguments.
 *    Verified via the Proxy-backed mock native `Scp` handle from
 *    `./mock-bridge`.
 *
 * End-to-end behavior (relay transport, real MLS encryption, event
 * log semantics, governance flow, etc.) is covered by:
 *
 * - `real-napi.test.ts` — real NAPI bridge + in-process relay
 * - `e2e-relay.test.ts` — full send pipeline through the real relay
 * - `e2e-fullstack.test.ts` — FullStackNetwork A+ decrypt roundtrip
 * - `e2e-cross-bridge.test.ts` — NAPI Node + WASM interop
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and ADR-048.
 */

import { describe, expect, it } from "bun:test";
import { _validateEconomicPolicyJson } from "../src/context";
import { ValidationError } from "../src/errors";
import type { ConsequenceRule as ConsequenceRuleTypeAlias } from "../src/types";
import { createMockNativeScp, mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// 1. EconomicPolicy schema validation (§19.3, ADR-034)
//
// `_validateEconomicPolicyJson` is the defense-in-depth validator the
// WASM path runs before forwarding the JSON to the Rust parser. These
// tests pin the accept/reject surface so schema drift is caught at
// the SDK layer instead of silently landing in the bridge.
// ---------------------------------------------------------------------------

describe("EconomicPolicy schema validation (_validateEconomicPolicyJson)", () => {
  it("accepts valid policy JSON", () => {
    const valid = JSON.stringify({
      locked: false,
      cost_schedule: { currency: [85, 83, 68, 0] },
      payment_adapters: [],
      pricing_formula: null,
      payee: "did:dht:z6MkPayee",
    });
    // Should not throw.
    _validateEconomicPolicyJson(valid);
  });

  it("rejects non-JSON input", () => {
    expect(() => _validateEconomicPolicyJson("not json")).toThrow(ValidationError);
  });

  it("rejects JSON array", () => {
    expect(() => _validateEconomicPolicyJson("[]")).toThrow(/expected an object/);
  });

  it("rejects JSON null", () => {
    expect(() => _validateEconomicPolicyJson("null")).toThrow(/expected an object/);
  });

  it("rejects missing locked field", () => {
    const json = JSON.stringify({ cost_schedule: {}, payment_adapters: [], payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'locked' must be a boolean/);
  });

  it("rejects non-boolean locked field", () => {
    const json = JSON.stringify({
      locked: "no",
      cost_schedule: {},
      payment_adapters: [],
      payee: "did:test",
    });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'locked' must be a boolean/);
  });

  it("rejects missing cost_schedule", () => {
    const json = JSON.stringify({ locked: false, payment_adapters: [], payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'cost_schedule' must be an object/);
  });

  it("rejects missing payment_adapters", () => {
    const json = JSON.stringify({ locked: false, cost_schedule: {}, payee: "did:test" });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payment_adapters' must be an array/);
  });

  it("rejects non-array payment_adapters", () => {
    const json = JSON.stringify({
      locked: false,
      cost_schedule: {},
      payment_adapters: "not-array",
      payee: "did:test",
    });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payment_adapters' must be an array/);
  });

  it("rejects missing payee", () => {
    const json = JSON.stringify({ locked: false, cost_schedule: {}, payment_adapters: [] });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payee' must be a string/);
  });

  it("rejects non-string payee", () => {
    const json = JSON.stringify({
      locked: false,
      cost_schedule: {},
      payment_adapters: [],
      payee: 42,
    });
    expect(() => _validateEconomicPolicyJson(json)).toThrow(/'payee' must be a string/);
  });
});

// ---------------------------------------------------------------------------
// 2. ConsequenceRule / ConsequenceConfig wire-format encoding (H15)
//
// The SDK's `encodeConsequenceRules` / `encodeConsequenceConfig` produce
// the Rust-serde-compatible JSON the native bridge parses. These tests
// freeze the translation from the TS-facing discriminated union to the
// Rust tag/variant shape so a wire-format regression at the SDK layer
// trips immediately.
// ---------------------------------------------------------------------------

describe("ConsequenceRule wire-format encoding (encodeConsequenceRules)", () => {
  it("encodes a typed ConsequenceRule[] to the Rust serde wire format", async () => {
    const { encodeConsequenceRules } = await import("../src/types");
    const rules: ConsequenceRuleTypeAlias[] = [
      {
        trigger: { kind: "MessageVelocity" },
        action: {
          kind: "Enforcement",
          severity: {
            kind: "SuspendCapability",
            capabilities: [
              "MessagesWrite",
              { kind: "ToolInvoke", toolId: "calculator" },
              { kind: "Custom", name: "my-custom-cap" },
            ],
          },
        },
        threshold: 5,
        windowSecs: 3600,
      },
      {
        trigger: { kind: "Custom", key: "spammy" },
        action: { kind: "AssignRole", toRole: "viewer" },
        threshold: 3,
        windowSecs: 600,
      },
      {
        trigger: { kind: "WarningCount" },
        action: {
          kind: "Enforcement",
          severity: {
            kind: "RevokeAccess",
            did: "did:dht:z6MkSubject",
            access: "Both",
          },
        },
        threshold: 10,
        windowSecs: 86_400,
      },
    ];

    const json = encodeConsequenceRules(rules);
    const decoded = JSON.parse(json) as Array<{
      trigger: unknown;
      action: unknown;
      threshold: number;
      window: { secs: number; nanos: number };
    }>;
    expect(decoded).toHaveLength(3);

    // Rule 0: MessageVelocity / Enforcement(SuspendCapability { ToolInvoke + Custom + unit })
    expect(decoded[0]?.trigger).toBe("MessageVelocity");
    expect(decoded[0]?.threshold).toBe(5);
    expect(decoded[0]?.window).toEqual({ secs: 3600, nanos: 0 });
    const action0 = decoded[0]?.action as {
      Enforcement?: { SuspendCapability?: { capabilities: unknown[] } };
    };
    expect(action0.Enforcement?.SuspendCapability?.capabilities).toEqual([
      "MessagesWrite",
      { ToolInvoke: "calculator" },
      { Custom: "my-custom-cap" },
    ]);

    // Rule 1: Custom trigger / AssignRole
    expect(decoded[1]?.trigger).toEqual({ Custom: "spammy" });
    expect(decoded[1]?.action).toEqual({ AssignRole: { to_role: "viewer" } });

    // Rule 2: WarningCount / Enforcement(RevokeAccess)
    expect(decoded[2]?.trigger).toBe("WarningCount");
    const action2 = decoded[2]?.action as {
      Enforcement?: { RevokeAccess?: { did: string; access: string } };
    };
    expect(action2.Enforcement?.RevokeAccess).toEqual({
      did: "did:dht:z6MkSubject",
      access: "Both",
    });
  });

  it("encodes RemoveMember severity with optional reason field", async () => {
    const { encodeConsequenceRules } = await import("../src/types");
    const json = encodeConsequenceRules([
      {
        trigger: { kind: "WarningCount" },
        action: {
          kind: "Enforcement",
          severity: {
            kind: "RemoveMember",
            did: "did:dht:z6MkBad",
            reason: "spam",
          },
        },
        threshold: 100,
        windowSecs: 60,
      },
    ]);
    const decoded = JSON.parse(json) as Array<{
      action: { Enforcement: { RemoveMember: { did: string; reason: string | null } } };
    }>;
    expect(decoded[0]?.action.Enforcement.RemoveMember).toEqual({
      did: "did:dht:z6MkBad",
      reason: "spam",
    });

    // Reason omitted serializes to explicit null (matches Rust Option<String>).
    const jsonNoReason = encodeConsequenceRules([
      {
        trigger: { kind: "WarningCount" },
        action: {
          kind: "Enforcement",
          severity: { kind: "RemoveMember", did: "did:dht:z6MkBad" },
        },
        threshold: 100,
        windowSecs: 60,
      },
    ]);
    const decodedNoReason = JSON.parse(jsonNoReason) as Array<{
      action: { Enforcement: { RemoveMember: { did: string; reason: string | null } } };
    }>;
    expect(decodedNoReason[0]?.action.Enforcement.RemoveMember.reason).toBeNull();
  });

  it("pins the discriminated-union variant names so renames trip a compile error", async () => {
    const types = await import("../src/types");
    expect(types.CONSEQUENCE_TRIGGER_VARIANTS).toEqual([
      "MessageVelocity",
      "ToolRateExceeded",
      "WarningCount",
      "Custom",
    ]);
    expect(types.CONSEQUENCE_ACTION_VARIANTS).toEqual(["Enforcement", "AssignRole"]);
    expect(types.ENFORCEMENT_SEVERITY_VARIANTS).toEqual([
      "SuspendCapability",
      "SuspendAccess",
      "RevokeAccess",
      "RemoveMember",
    ]);
  });

  it("encodeConsequenceConfig snake-cases the wire field", async () => {
    const { encodeConsequenceConfig } = await import("../src/types");
    const encoded = encodeConsequenceConfig({ allowAutomaticAccessRevocation: true });
    expect(JSON.parse(encoded)).toEqual({ allow_automatic_access_revocation: true });
  });
});

// ---------------------------------------------------------------------------
// 3. SCP forwarder plumbing (mountMockScp)
//
// The SDK's `SCP` class is a thin forwarder: every public method
// dispatches to the matching method on the underlying native handle.
// These tests verify the dispatch wiring — method name, argument
// ordering, and handle threading — without a real native addon, via
// the Proxy-backed mock from `./mock-bridge`. Tests that require live
// protocol state (MLS decrypt, relay delivery, governance execution)
// live in the real-*.test.ts files.
// ---------------------------------------------------------------------------

describe("SCP forwarder dispatch (mountMockScp)", () => {
  it("constructs an SCP with a pre-seeded mock native handle", () => {
    const { scp, native } = mountMockScp();
    // instanceId read on the SDK wrapper passes through to the mock.
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).toBe(native.instanceId);
  });

  it("two fresh mountMockScp calls produce distinct instance IDs", () => {
    const a = mountMockScp();
    const b = mountMockScp();
    expect(a.scp.instanceId).not.toBe(b.scp.instanceId);
  });

  it("identityCreate forwards the custody string and returns the Identity wrapper", async () => {
    const { scp, native } = mountMockScp();
    const fakeHandle = { did: "did:dht:z6MkForwardTest", custodyType: "in_memory" };
    native.__stub("identityCreate", () => Promise.resolve(fakeHandle));

    const identity = await scp.identityCreate("in_memory");

    expect(identity.did).toBe(fakeHandle.did);
    expect(identity.custodyType).toBe(fakeHandle.custodyType);

    // The mock recorded a single call to identityCreate with the
    // custody string passed through verbatim.
    const call = native.__lastCall("identityCreate");
    expect(call).toBeDefined();
    expect(call?.args).toEqual(["in_memory"]);
  });

  it("identityCreate defaults custody to 'in_memory' when omitted", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("identityCreate", () =>
      Promise.resolve({ did: "did:dht:z6MkDefault", custodyType: "in_memory" }),
    );

    await scp.identityCreate();

    expect(native.__lastCall("identityCreate")?.args).toEqual(["in_memory"]);
  });

  it("contextSend forwards handle, did, payload array, and null spending ucan by default", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("contextSend", () => Promise.resolve(undefined));

    // Synthesize a bare handle shape — the SDK forwards the reference
    // verbatim; the Proxy dispatcher sees the exact object.
    const handle = { contextId: "ctx-abc" };
    const payload = new Uint8Array([1, 2, 3, 255]);

    await scp.contextSend(handle, "did:dht:z6MkSender", payload);

    const call = native.__lastCall("contextSend");
    expect(call).toBeDefined();
    expect(call?.args[0]).toBe(handle);
    expect(call?.args[1]).toBe("did:dht:z6MkSender");
    // The SDK normalizes typed arrays to number[] before crossing FFI.
    expect(call?.args[2]).toEqual([1, 2, 3, 255]);
    // spendingUcanJwt defaults to null, not undefined.
    expect(call?.args[3]).toBeNull();
  });

  it("contextSend forwards a caller-supplied spendingUcanJwt unchanged", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("contextSend", () => Promise.resolve(undefined));

    const handle = { contextId: "ctx-paid" };
    await scp.contextSend(
      handle,
      "did:dht:z6MkSender",
      new Uint8Array([0]),
      "eyJhbGciOiJFZERTQSJ9.spending.jwt",
    );

    expect(native.__lastCall("contextSend")?.args[3]).toBe("eyJhbGciOiJFZERTQSJ9.spending.jwt");
  });

  it("contextJoin normalizes undefined spendingUcanJwt to null", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("contextJoin", () => Promise.resolve(undefined));

    const handle = { contextId: "ctx-join" };
    await scp.contextJoin(handle, "did:dht:z6MkJoiner");

    expect(native.__lastCall("contextJoin")?.args).toEqual([handle, "did:dht:z6MkJoiner", null]);
  });

  it("contextCreate returns a Context wrapper seeded from the native handle", async () => {
    const { scp, native } = mountMockScp();
    const rawCtx = { contextId: "ctx-created-42" };
    native.__stub("contextCreate", () => Promise.resolve(rawCtx));
    // identityCreate is the simplest way to produce a real Identity
    // wrapper that the SDK contextCreate accepts.
    native.__stub("identityCreate", () =>
      Promise.resolve({ did: "did:dht:z6MkCreator", custodyType: "in_memory" }),
    );

    const identity = await scp.identityCreate("in_memory");
    const paramsJson = JSON.stringify({ ceiling: ["messages:read"] });
    const ctx = await scp.contextCreate(identity, paramsJson);

    expect(ctx.contextId).toBe("ctx-created-42");
    expect(ctx.identityDid).toBe(identity.did);
    // contextCreate forwards the identity's raw handle plus paramsJson.
    const call = native.__lastCall("contextCreate");
    expect(call).toBeDefined();
    expect(call?.args[0]).toBe(identity._rawHandle);
    expect(call?.args[1]).toBe(paramsJson);
  });

  it("relayStartInMemory returns a Relay wrapper around the native handle", async () => {
    const { scp, native } = mountMockScp();
    const rawRelay = {
      relayUrl: "ws://127.0.0.1:9999/scp/v1",
      relayPort: 9999,
      isShutdown: false,
      shutdown: () => {},
    };
    native.__stub("relayStartInMemory", () => Promise.resolve(rawRelay));

    const relay = await scp.relayStartInMemory();

    expect(relay.relayUrl).toBe(rawRelay.relayUrl);
    expect(relay.relayPort).toBe(rawRelay.relayPort);
    expect(relay.isShutdown).toBe(false);
    expect(native.__lastCall("relayStartInMemory")?.args).toEqual([]);
  });

  it("nodeStartInMemory forwards null when identity DID is omitted", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("nodeStartInMemory", () =>
      Promise.resolve({
        relayUrl: "ws://127.0.0.1:8000/scp/v1",
        relayPort: 8000,
        did: "did:dht:z6MkNode",
        isShutdown: false,
        shutdown: () => {},
        serve: () => Promise.resolve("127.0.0.1:8000"),
        httpUrl: () => Promise.resolve(null),
        enableSiteProjection: () => Promise.resolve(),
        commitDeploy: () => Promise.resolve(0),
        rollbackDeploy: () => Promise.resolve(),
        disableSiteProjection: () => Promise.resolve(),
      }),
    );

    const node = await scp.nodeStartInMemory();

    expect(node.did).toBe("did:dht:z6MkNode");
    expect(native.__lastCall("nodeStartInMemory")?.args).toEqual([null]);
  });

  it("ucanValidate forwards all five positional arguments", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanValidate", () => Promise.resolve(undefined));

    const handle = { contextId: "ctx-ucan" };
    await scp.ucanValidate(handle, "token.jwt", "messages:read", "did:dht:z6MkAgent", ["proof1"]);

    const call = native.__lastCall("ucanValidate");
    expect(call?.args).toEqual([
      handle,
      "token.jwt",
      "messages:read",
      "did:dht:z6MkAgent",
      ["proof1"],
    ]);
  });

  it("ucanMint forwards handle, memberDid, capabilities, and optional proofs", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanMint", () => Promise.resolve({ id: "ucan-1", capabilities: ["read"] }));

    const handle = { contextId: "ctx-mint" };
    await scp.ucanMint(handle, "did:dht:z6MkMember", ["messages:read"]);

    const call = native.__lastCall("ucanMint");
    expect(call?.args[0]).toBe(handle);
    expect(call?.args[1]).toBe("did:dht:z6MkMember");
    expect(call?.args[2]).toEqual(["messages:read"]);
    // proofs is the fourth positional — left as undefined.
    expect(call?.args[3]).toBeUndefined();
  });

  it("suspend dispatches synchronously and does not call resume", () => {
    const { scp, native } = mountMockScp();
    native.__stub("suspend", () => undefined);

    scp.suspend();

    expect(native.__calls("suspend").length).toBe(1);
    expect(native.__calls("resume").length).toBe(0);
  });

  it("shutdown forwards a BigInt millisecond deadline to the native bridge", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("shutdown", () => Promise.resolve(undefined));

    await scp.shutdown(5);

    const call = native.__lastCall("shutdown");
    expect(call).toBeDefined();
    expect(typeof call?.args[0]).toBe("bigint");
    expect(call?.args[0]).toBe(5000n);
  });

  it("scpidChallenge is forwarded synchronously with audience + ttl", () => {
    const { scp, native } = mountMockScp();
    native.__stub("scpidChallenge", () => "challenge-json");

    const result = scp.scpidChallenge("https://example.org", 120);

    expect(result).toBe("challenge-json");
    expect(native.__lastCall("scpidChallenge")?.args).toEqual(["https://example.org", 120]);
  });
});

// ---------------------------------------------------------------------------
// 4. Mock-bridge harness sanity
//
// The Proxy-backed mock is the scaffolding that the forwarder tests
// above depend on. A regression in its default return or call-recording
// shape would silently weaken every forwarder assertion, so a handful
// of direct tests pin the contract.
// ---------------------------------------------------------------------------

describe("createMockNativeScp / mountMockScp (harness contract)", () => {
  it("default unstubbed methods resolve to undefined without throwing", async () => {
    const mock = createMockNativeScp();
    // Method that isn't stubbed — should return a promise resolving to undefined.
    const result = await (
      mock as unknown as { someUnstubbedMethod: () => Promise<unknown> }
    ).someUnstubbedMethod();
    expect(result).toBeUndefined();
  });

  it("suspend is a synchronous no-op by default", () => {
    const mock = createMockNativeScp();
    // `suspend` is in the SYNC_METHODS set — returns undefined synchronously.
    const result = (mock as unknown as { suspend: () => unknown }).suspend();
    expect(result).toBeUndefined();
  });

  it("__calls with no argument returns every recorded invocation in order", () => {
    const mock = createMockNativeScp();
    (mock as unknown as { a: () => unknown }).a();
    (mock as unknown as { b: () => unknown }).b();
    (mock as unknown as { a: (x: number) => unknown }).a(42);

    const all = mock.__calls();
    expect(all.map((c) => c.method)).toEqual(["a", "b", "a"]);
    expect(all[2]?.args).toEqual([42]);
  });

  it("__calls(name) filters to a single method", () => {
    const mock = createMockNativeScp();
    (mock as unknown as { a: () => unknown }).a();
    (mock as unknown as { b: () => unknown }).b();
    (mock as unknown as { a: (x: number) => unknown }).a(42);

    const onlyA = mock.__calls("a");
    expect(onlyA).toHaveLength(2);
    expect(onlyA[1]?.args).toEqual([42]);
  });

  it("__reset clears stubs and call log", () => {
    const mock = createMockNativeScp();
    mock.__stub("foo", () => "stubbed");
    (mock as unknown as { foo: () => unknown }).foo();
    expect(mock.__calls("foo")).toHaveLength(1);

    mock.__reset();
    expect(mock.__calls()).toHaveLength(0);
    // Stub is cleared — a further call returns the default promise.
    const after = (mock as unknown as { foo: () => Promise<unknown> }).foo();
    expect(after).toBeInstanceOf(Promise);
  });

  it("__stub(name, null) removes a previously configured stub", () => {
    const mock = createMockNativeScp();
    mock.__stub("bar", () => "first");
    expect((mock as unknown as { bar: () => unknown }).bar()).toBe("first");
    mock.__stub("bar", null);
    expect((mock as unknown as { bar: () => Promise<unknown> }).bar()).toBeInstanceOf(Promise);
  });
});
