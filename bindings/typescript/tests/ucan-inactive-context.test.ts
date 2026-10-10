/**
 * Every UCAN operation on the `SCP` class surfaces the NAPI bridge's
 * pre-authorization refusal for a context that is not active as a typed
 * {@link ContextError} carrying `SCP-CTX-2023`.
 *
 * The NAPI bridge withholds the context's lifecycle state from that refusal, so
 * the code is the only signal a caller gets; a wrapper that let the raw `Error`
 * through would leave the caller parsing prose.
 */

import { describe, expect, it } from "bun:test";
import { ContextError } from "../src/errors";
import type { Bridge } from "../src/internal/bridge";
import { __setBridgeForTests, wrapBridgeErrors } from "../src/internal/bridge";
import { mountMockScp } from "./mock-bridge";

const INACTIVE = (verb: string): Error =>
  new Error(
    `[SCP-CTX-2023] context error: cannot ${verb} a UCAN in context: context is not active`,
  );

/** Properties the JS runtime probes on objects during `await` and inspection. */
const PROBE_PROPS = new Set<string | symbol>([
  "then",
  "catch",
  "finally",
  Symbol.toPrimitive,
  Symbol.toStringTag,
  Symbol.iterator,
  Symbol.asyncIterator,
]);

/** A bridge whose `method` rejects with `error`, wrapped as production wraps it. */
function rejectingBridge(method: string, error: Error): Bridge {
  const spy = new Proxy({} as Bridge, {
    get(_t, prop) {
      if (PROBE_PROPS.has(prop)) return undefined;
      if (prop === method) return (..._args: unknown[]) => Promise.reject(error);
      throw new Error(`Spy bridge: unexpected call to Bridge.${String(prop)}`);
    },
  });
  return wrapBridgeErrors(spy);
}

async function expectInactiveContextError(call: () => Promise<unknown>): Promise<void> {
  let thrown: unknown;
  try {
    await call();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(ContextError);
  expect((thrown as ContextError).code).toBe("SCP-CTX-2023");
}

describe("UCAN operations on an inactive context", () => {
  it("ucanValidate throws ContextError SCP-CTX-2023", async () => {
    const { scp } = mountMockScp();
    __setBridgeForTests(scp, rejectingBridge("ucanValidate", INACTIVE("validate")));
    await expectInactiveContextError(() =>
      scp.ucanValidate({}, "token", "scp:ctx:c/messages:read", "did:key:z6MkPresenter"),
    );
  });

  it("ucanEvaluate throws ContextError SCP-CTX-2023", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanEvaluate", () => Promise.reject(INACTIVE("evaluate")));
    await expectInactiveContextError(() => scp.ucanEvaluate({}, "token", "did:key:z6MkPresenter"));
  });

  it("ucanMint throws ContextError SCP-CTX-2023", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanMint", () => Promise.reject(INACTIVE("mint")));
    await expectInactiveContextError(() =>
      scp.ucanMint({}, "did:key:z6MkMember", ["messages:read"]),
    );
  });

  it("ucanDelegate throws ContextError SCP-CTX-2023", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanDelegate", () => Promise.reject(INACTIVE("delegate")));
    await expectInactiveContextError(() =>
      scp.ucanDelegate({}, "did:key:z6MkFrom", "did:key:z6MkTo", "parent", [
        "scp:ctx:c/messages:read",
      ]),
    );
  });

  it("ucanRevoke throws ContextError SCP-CTX-2023", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanRevoke", () => Promise.reject(INACTIVE("revoke")));
    await expectInactiveContextError(() => scp.ucanRevoke({}, "token", "did:key:z6MkRevoker"));
  });

  it("evaluateTrust propagates the ucanEvaluate refusal as ContextError SCP-CTX-2023", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanEvaluate", () => Promise.reject(INACTIVE("evaluate")));
    await expectInactiveContextError(() => scp.evaluateTrust({}, "did:key:z6MkSubject", ["token"]));
  });
});
