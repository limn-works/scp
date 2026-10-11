/**
 * Runtime check of the public `SCP` handle parameters.
 *
 * Every public `SCP` method that takes a handle takes the SDK object the SDK
 * returned (`Context`, `Identity`, `TransportManager`, `McpServer`,
 * `McpClient`). A caller that bypasses the type checker, and passes a raw
 * native handle, a look-alike object, `null`, or the wrong SDK class, gets a
 * `ValidationError` with code `SCP-VALID-7005` before any bridge call. The
 * mock native here is strict, so a call that slipped past the check would
 * throw the mock's "unstubbed method" error instead, and these tests would
 * fail on the error class.
 *
 * `tests/public-handle-params.test.ts` holds the matching compile-time check.
 */

import { describe, expect, it } from "bun:test";
import { Context } from "../src/context";
import { ValidationError } from "../src/errors";
import { Identity } from "../src/identity";
import type { BridgeContextHandle } from "../src/internal/bridge";
import { McpClient, McpServer } from "../src/mcp";
import type { SCP } from "../src/scp";
import { TransportManager } from "../src/transport";
import { mountMockScp } from "./mock-bridge";

/** Runs `call` and returns what it threw or rejected with. */
async function thrownBy(call: () => unknown): Promise<unknown> {
  try {
    await call();
  } catch (err) {
    return err;
  }
  return undefined;
}

async function expectValid7005(call: () => unknown, method: string, param: string) {
  const err = await thrownBy(call);
  expect(err).toBeInstanceOf(ValidationError);
  expect((err as ValidationError).code).toBe("SCP-VALID-7005");
  expect((err as ValidationError).message).toContain(`${method}() ${param} must be a`);
}

function fixtures(scp: SCP) {
  const rawContext = { contextId: "ctx-1" } as unknown as BridgeContextHandle;
  const context = Context._fromHandle(scp, rawContext, "did:dht:z6MkOwner");
  const rawIdentity = { did: "did:dht:z6MkOwner", custodyType: "in_memory" };
  const identity = Identity._fromHandle(scp, rawIdentity);
  const manager = TransportManager._fromHandle({ relay: "r" });
  const server = McpServer._fromHandle({ server: "s" });
  const client = McpClient._fromHandle({ client: "c" });
  return { rawContext, context, rawIdentity, identity, manager, server, client };
}

/** Values that are not an SDK-constructed handle object of any class. */
function wrongValues(scp: SCP): [string, unknown][] {
  const f = fixtures(scp);
  return [
    ["null", null],
    ["undefined", undefined],
    ["a string", "ctx-1"],
    ["an empty object", {}],
    ["a raw context handle", f.rawContext],
    ["a raw identity handle", f.rawIdentity],
    [
      "an object copying a Context's public fields",
      {
        contextId: f.context.contextId,
        identityDid: f.context.identityDid,
        _rawHandle: f.rawContext,
        outlets: f.context.outlets,
      },
    ],
    ["an object built from Context.prototype", Object.create(Context.prototype)],
  ];
}

describe("public SCP handle parameters reject what the SDK did not return", () => {
  it("Context parameters throw SCP-VALID-7005", async () => {
    const { scp } = mountMockScp();
    const f = fixtures(scp);
    const asContext = (v: unknown) => v as Context;
    for (const [, value] of [...wrongValues(scp), ["an Identity", f.identity] as const]) {
      await expectValid7005(
        () => scp.contextSend(asContext(value), "did:dht:z6MkA", new Uint8Array([1])),
        "contextSend",
        "context",
      );
      await expectValid7005(
        () => scp.contextJoin(asContext(value), "did:dht:z6MkA"),
        "contextJoin",
        "context",
      );
      await expectValid7005(
        () => scp.evaluateTrust(asContext(value), "did:dht:z6MkA"),
        "evaluateTrust",
        "context",
      );
      await expectValid7005(
        () => scp.outletInvokeCrossContext(asContext(value), f.context, "o", "{}", "did:a", "u", 0),
        "outletInvokeCrossContext",
        "sourceContext",
      );
      await expectValid7005(
        () => scp.outletInvokeCrossContext(f.context, asContext(value), "o", "{}", "did:a", "u", 0),
        "outletInvokeCrossContext",
        "targetContext",
      );
    }
  });

  it("Identity parameters throw SCP-VALID-7005", async () => {
    const { scp } = mountMockScp();
    const f = fixtures(scp);
    const asIdentity = (v: unknown) => v as Identity;
    for (const [, value] of [...wrongValues(scp), ["a Context", f.context] as const]) {
      await expectValid7005(
        () => scp.contextCreate(asIdentity(value), "{}"),
        "contextCreate",
        "identity",
      );
      await expectValid7005(
        () => scp.identityRotateKey(asIdentity(value)),
        "identityRotateKey",
        "identity",
      );
    }
  });

  it("TransportManager, McpServer, and McpClient parameters throw SCP-VALID-7005", async () => {
    const { scp } = mountMockScp();
    const f = fixtures(scp);
    for (const [, value] of [...wrongValues(scp), ["a Context", f.context] as const]) {
      await expectValid7005(
        () => scp.transportStatus(value as TransportManager),
        "transportStatus",
        "manager",
      );
      await expectValid7005(() => scp.mcpServerStop(value as McpServer), "mcpServerStop", "server");
      await expectValid7005(
        () => scp.mcpClientListTools(value as McpClient),
        "mcpClientListTools",
        "client",
      );
    }
    // The wrapper classes do not stand in for one another.
    await expectValid7005(
      () => scp.mcpServerStop(f.client as unknown as McpServer),
      "mcpServerStop",
      "server",
    );
    await expectValid7005(
      () => scp.mcpClientListTools(f.server as unknown as McpClient),
      "mcpClientListTools",
      "client",
    );
  });

  it("an SDK-returned handle passes the check and reaches the bridge as its raw handle", async () => {
    // Positive control: without it, a check that rejected everything would
    // also pass the tests above.
    const { scp, native } = mountMockScp();
    const f = fixtures(scp);
    native.__stub("contextJoin", () => Promise.resolve(undefined));
    native.__stub("transportStatus", () => Promise.resolve("connected"));
    native.__stub("mcpServerStop", () => Promise.resolve(undefined));
    native.__stub("mcpClientListTools", () => Promise.resolve([]));

    await scp.contextJoin(f.context, "did:dht:z6MkA");
    expect(native.__lastCall("contextJoin")?.args[0]).toBe(f.rawContext);
    expect(await scp.transportStatus(f.manager)).toBe("connected");
    expect(native.__lastCall("transportStatus")?.args[0]).toBe(f.manager._rawHandle);
    await scp.mcpServerStop(f.server);
    expect(native.__lastCall("mcpServerStop")?.args[0]).toBe(f.server._rawHandle);
    await scp.mcpClientListTools(f.client);
    expect(native.__lastCall("mcpClientListTools")?.args[0]).toBe(f.client._rawHandle);
  });
});
