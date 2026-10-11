/**
 * Every identity-creating `SCP` method takes custody as a required argument
 * and names no default key store (SCP-294). `tsc` rejects the omission; an
 * untyped caller that passes nothing, `undefined`, or `null` gets an
 * `IdentityError` carrying `SCP-IDENT-1116` before any bridge call.
 *
 * The custody strings are the request vocabulary of spec `03-identity.md`
 * §3.2.2: the SDK forwards each accepted value unchanged, and the real addon
 * answers each rejected one with the code §3.2.2's table gives.
 */

import { describe, expect, it } from "bun:test";
import { IdentityError, ValidationError } from "../src/errors";
import type { CustodyType } from "../src/identity";
import { CUSTODY_REQUIRED_CODE, type KeyCustodyProvider, SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";
import { skipReasonIfAddonAbsent } from "./napi-guard";

/** Every custody request value the union carries (spec §3.2.2). */
const CUSTODY_VALUES: readonly CustodyType[] = ["encrypted_file", "os_keystore", "in_memory"];

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
  identityCreate: 'pass "encrypted_file"',
  identityCreateWithAgentKey: 'pass "encrypted_file"',
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

    for (const custody of CUSTODY_VALUES) {
      it(`${method} forwards custody ${custody} to the bridge unchanged`, async () => {
        const { scp, native } = mountMockScp();
        native.__stub(method, () =>
          Promise.resolve({ did: "did:dht:z6MkCustodyNamed", custodyType: custody }),
        );

        const identity = await scp[method](custody);

        expect(identity.did).toBe("did:dht:z6MkCustodyNamed");
        expect(identity.custodyType).toBe(custody);
        expect(native.__lastCall(method)?.args).toEqual([custody]);
      });
    }
  }

  it("the type checker rejects an omitted custody", () => {
    // Each line below fails `tsc` without its directive, so `bun run check`
    // fails if a default ever returns ("Unused '@ts-expect-error' directive").
    const typeOnly = (scp: SCP, provider: KeyCustodyProvider) => {
      // @ts-expect-error custody is required
      void scp.identityCreate();
      // @ts-expect-error custody is required
      void scp.identityCreateWithAgentKey();
      // @ts-expect-error the custody union carries only the §3.2.2 request values
      void scp.identityCreate("file");
      // @ts-expect-error the custody union carries only the §3.2.2 request values
      void scp.identityCreate("platform");
      // @ts-expect-error the custody union carries only the §3.2.2 request values
      void scp.identityCreateWithAgentKey("callback");
      void scp.identityCreateWithCustody(provider);
    };
    expect(typeof typeOnly).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// The real addon's §3.2.2 codes
// ---------------------------------------------------------------------------

let addonReason = "";
try {
  new SCP({ storage: { type: "in_memory" } }).shutdown(1).catch(() => {});
} catch (e: unknown) {
  addonReason = skipReasonIfAddonAbsent(e);
}

/** The `code` an `SCP` call rejected with. */
async function rejectionCode(p: Promise<unknown>): Promise<string> {
  const err = await rejection(p);
  expect(err).toBeInstanceOf(Error);
  return (err as { code: string }).code;
}

if (addonReason !== "") {
  describe("custody request codes (real NAPI) (SKIPPED)", () => {
    it.skip(addonReason, () => {});
  });
} else {
  // Like `real-napi.test.ts`, this suite runs against an addon built with the
  // bridge's `testing` feature, the only build that accepts `in_memory`.
  describe("custody request codes (real NAPI)", () => {
    async function withScp<T>(body: (scp: SCP) => Promise<T>): Promise<T> {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        return await body(scp);
      } finally {
        await scp.shutdown(1000).catch(() => {});
      }
    }

    for (const method of ["identityCreate", "identityCreateWithAgentKey"] as const) {
      it(`${method}("os_keystore") rejects with SCP-IDENT-1003: it needs a provider`, async () => {
        const code = await withScp((scp) => rejectionCode(scp[method]("os_keystore")));
        expect(code).toBe("SCP-IDENT-1003");
      });

      for (const retired of ["platform", "software", "file", "callback"]) {
        it(`${method}(${JSON.stringify(retired)}) rejects with SCP-VALID-7005`, async () => {
          const code = await withScp((scp) => rejectionCode(callUntyped(scp, method, retired)));
          expect(code).toBe("SCP-VALID-7005");
        });
      }

      it(`${method}("encrypted_file") without SCP_KEY_PASSPHRASE rejects with SCP-VALID-7001`, async () => {
        // With the variable set, the call would open the key file under the
        // real HOME, so the test refuses to run rather than touch it.
        expect(process.env.SCP_KEY_PASSPHRASE).toBeUndefined();
        const err = await withScp((scp) => rejection(scp[method]("encrypted_file")));
        expect((err as { code: string }).code).toBe("SCP-VALID-7001");
        expect((err as Error).message).toContain("SCP_KEY_PASSPHRASE");
      });

      it(`${method}("in_memory") creates an identity on a testing addon`, async () => {
        const identity = await withScp((scp) => scp[method]("in_memory"));
        expect(identity.did).toMatch(/^did:dht:/);
        expect(identity.custodyType).toBe("in_memory");
      });
    }
  });
}
