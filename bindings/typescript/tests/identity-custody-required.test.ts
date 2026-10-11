/**
 * Every identity-creating `SCP` method takes custody as a required argument
 * and names no default key store (SCP-294). `tsc` rejects the omission; an
 * untyped caller that passes nothing, `undefined`, or `null` gets an
 * `IdentityError` carrying `SCP-IDENT-1116` before any bridge call.
 */

import { describe, expect, it } from "bun:test";
import { IdentityError, ValidationError } from "../src/errors";
import type { CustodyType } from "../src/identity";
import { CUSTODY_REQUIRED_CODE, type KeyCustodyProvider, type SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";

const METHODS = [
  "identityCreate",
  "identityCreateWithAgentKey",
  "identityCreateWithCustody",
] as const;
type Method = (typeof METHODS)[number];

/**
 * The remedy each method's SCP-IDENT-1116 message must open with: the argument
 * that method takes, never the other method's argument.
 */
const REMEDIES: Record<Method, string> = {
  identityCreate: 'pass "in_memory"',
  identityCreateWithAgentKey: 'pass "in_memory"',
  identityCreateWithCustody: "pass a KeyCustodyProvider",
};

/** Calls `method` the way an untyped JavaScript caller would. */
function callUntyped(scp: SCP, method: Method, ...args: unknown[]): Promise<unknown> {
  const fn = (scp as unknown as Record<Method, (...a: unknown[]) => Promise<unknown>>)[method];
  return fn.apply(scp, args);
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  throw new Error("expected the call to reject");
}

describe("identity-creating methods require custody", () => {
  it("pins the code to SCP-IDENT-1116", () => {
    expect(CUSTODY_REQUIRED_CODE).toBe("SCP-IDENT-1116");
  });

  for (const method of METHODS) {
    for (const [label, args] of [
      ["nothing", []],
      ["undefined", [undefined]],
      ["null", [null]],
    ] as const) {
      it(`${method} given ${label} rejects with SCP-IDENT-1116 before any bridge call`, async () => {
        const { scp, native } = mountMockScp();
        native.__stub(method, () => {
          throw new Error(`bridge ${method} must not be reached`);
        });

        const err = await rejection(callUntyped(scp, method, ...args));

        expect(err).toBeInstanceOf(IdentityError);
        expect((err as IdentityError).code).toBe("SCP-IDENT-1116");
        const message = (err as IdentityError).message;
        expect(message.startsWith(`${method}() requires a custody argument`)).toBe(true);
        expect(message).toContain(`store: ${REMEDIES[method]}`);
        for (const other of new Set(Object.values(REMEDIES))) {
          if (other !== REMEDIES[method]) expect(message).not.toContain(other);
        }
        expect(native.__calls(method)).toHaveLength(0);
      });
    }
  }

  for (const method of ["identityCreate", "identityCreateWithAgentKey"] as const) {
    it(`${method} given a non-string custody rejects with SCP-VALID-7005 before any bridge call`, async () => {
      const { scp, native } = mountMockScp();
      native.__stub(method, () => {
        throw new Error(`bridge ${method} must not be reached`);
      });

      const err = await rejection(callUntyped(scp, method, 42));

      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).code).toBe("SCP-VALID-7005");
      expect(native.__calls(method)).toHaveLength(0);
    });

    it(`${method} forwards a named custody string to the bridge`, async () => {
      const { scp, native } = mountMockScp();
      native.__stub(method, () =>
        Promise.resolve({ did: "did:dht:z6MkCustodyNamed", custodyType: "in_memory" }),
      );

      const custody: CustodyType = "in_memory";
      const identity = await scp[method](custody);

      expect(identity.did).toBe("did:dht:z6MkCustodyNamed");
      expect(native.__lastCall(method)?.args).toEqual(["in_memory"]);
    });
  }

  it("the type checker rejects an omitted custody", () => {
    // Each line below fails `tsc` without its directive, so `bun run check`
    // fails if a default ever returns ("Unused '@ts-expect-error' directive").
    const typeOnly = (scp: SCP, provider: KeyCustodyProvider) => {
      // @ts-expect-error custody is required
      void scp.identityCreate();
      // @ts-expect-error custody is required
      void scp.identityCreateWithAgentKey();
      // @ts-expect-error the custody union carries only the strings the bridge builds
      void scp.identityCreate("file");
      void scp.identityCreateWithCustody(provider);
    };
    expect(typeof typeOnly).toBe("function");
  });
});
