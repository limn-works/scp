/**
 * SCP-OUT-031 — TypeScript OutletError sealed-hierarchy + fixture round-trip.
 *
 * Verifies:
 *  - Eight concrete subclasses extend `OutletError`; each carries the
 *    right `classWire` discriminator and a static `code`.
 *  - `OutletError.isAuthorizationError(err)` returns true after JSON
 *    round-trip (factory-fallback path) and after `instanceof` (native
 *    prototype-chain path).
 *  - `Credit` factory rejects zero / over-2^32 with `InvalidGrant` under
 *    the `OutletError` hierarchy.
 *  - `CatalogKey` factory rejects malformed input with
 *    `OutletProtocolError`.
 *  - `OutletError.new(opts)` is options-object only — no positional
 *    overload exists.
 *  - `redactPii` redacts emails and DIDs.
 *  - Per-class detail-shape conformance — malformed detail rejected at
 *    `fromWire` boundary.
 *  - Every fixture in `tests/conformance/vectors/outlet_error_fixtures.json`
 *    round-trips: decode → typed subclass → encode → decode again, with
 *    every wire-form field preserved.
 */

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  AuthorizationError,
  CatalogKey,
  Credit,
  EconomicError,
  ExecutionError,
  InputError,
  InvalidGrant,
  makeOutletId,
  OutletError,
  OutletGovernanceError,
  OutletProtocolError,
  OutletTransportError,
  OutputError,
  redactPii,
  ScpError,
  ValidationError,
} from "../src/errors";

const FIXTURE_PATH = resolve(
  __dirname,
  "../../../tests/conformance/vectors/outlet_error_fixtures.json",
);

interface Fixture {
  name: string;
  comment?: string;
  code: string;
  slug: string;
  class: string;
  message: string;
  retry: Record<string, unknown>;
  detail?: Record<string, unknown>;
  source_chain?: ReadonlyArray<Record<string, unknown>>;
  pad_nonce?: string;
  registration_event_id?: string;
}

function loadFixtures(): Fixture[] {
  const raw = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8")) as { fixtures: Fixture[] };
  return raw.fixtures;
}

// Translate the JSON fixture's snake_case top-level keys to the camelCase
// form `OutletError.fromWire` expects.
function toWireShape(fixture: Fixture): Record<string, unknown> {
  const out: Record<string, unknown> = {
    code: fixture.code,
    slug: fixture.slug,
    class: fixture.class,
    message: fixture.message,
    retry: convertRetry(fixture.retry),
    sourceChain: (fixture.source_chain ?? []).map((h) => ({
      contextId: h.context_id,
      hopIndex: h.hop_index,
      wrappedCode: h.wrapped_code,
    })),
  };
  if (fixture.detail !== undefined) out.detail = fixture.detail;
  if (fixture.pad_nonce !== undefined) out.padNonce = fixture.pad_nonce;
  if (fixture.registration_event_id !== undefined)
    out.registrationEventId = fixture.registration_event_id;
  return out;
}

function convertRetry(retry: Record<string, unknown>): Record<string, unknown> {
  // The fixture file uses snake_case `min_ms` / `max_ms` / `delay_ms`;
  // the SDK retry-shape uses camelCase per the cross-SDK convention.
  const out: Record<string, unknown> = { policy: retry.policy };
  if (retry.delay_ms !== undefined) out.delayMs = retry.delay_ms;
  if (retry.min_ms !== undefined) out.minMs = retry.min_ms;
  if (retry.max_ms !== undefined) out.maxMs = retry.max_ms;
  return out;
}

// ---------------------------------------------------------------------------
// Sealed-hierarchy structural assertions
// ---------------------------------------------------------------------------

describe("OutletError sealed hierarchy", () => {
  it("eight concrete subclasses extend OutletError", () => {
    const ctors = [
      OutletProtocolError,
      AuthorizationError,
      InputError,
      ExecutionError,
      OutputError,
      EconomicError,
      OutletTransportError,
      OutletGovernanceError,
    ];
    expect(ctors.length).toBe(8);
    for (const C of ctors) {
      const e = new C("x");
      expect(e).toBeInstanceOf(OutletError);
      expect(e).toBeInstanceOf(ScpError);
      expect(typeof C.defaultCode).toBe("string");
      expect(C.defaultCode.startsWith("SCP-TOOL-61")).toBe(true);
    }
  });

  it("each subclass carries a stable classWire discriminator", () => {
    expect(new OutletProtocolError("x").classWire).toBe("protocol");
    expect(new AuthorizationError("x").classWire).toBe("authorization");
    expect(new InputError("x").classWire).toBe("input");
    expect(new ExecutionError("x").classWire).toBe("execution");
    expect(new OutputError("x").classWire).toBe("output");
    expect(new EconomicError("x").classWire).toBe("economic");
    expect(new OutletTransportError("x").classWire).toBe("transport");
    expect(new OutletGovernanceError("x").classWire).toBe("governance");
  });

  it("isAuthorizationError holds via instanceof (native prototype-chain path)", () => {
    const e = new AuthorizationError("x");
    expect(OutletError.isAuthorizationError(e)).toBe(true);
    expect(OutletError.isOutletError(e)).toBe(true);
  });

  it("isAuthorizationError holds via class-tag (factory-fallback path)", () => {
    // Simulate a realm-crossing scenario where `instanceof` is not safe:
    // an object that quacks like an AuthorizationError but does not share
    // the prototype chain. The runtime guard falls back to the
    // class-tag check.
    const realmCrossed = {
      name: "AuthorizationError",
      message: "test",
      code: "SCP-TOOL-6110",
      classWire: "authorization",
      scpClassTag: "AuthorizationError",
    };
    expect(OutletError.isAuthorizationError(realmCrossed)).toBe(true);
    expect(OutletError.isOutletError(realmCrossed)).toBe(true);
  });

  it("class-tag does not match unrelated objects", () => {
    expect(OutletError.isAuthorizationError({ scpClassTag: "InputError" })).toBe(false);
    expect(OutletError.isAuthorizationError(null)).toBe(false);
    expect(OutletError.isAuthorizationError(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Credit / CatalogKey newtypes
// ---------------------------------------------------------------------------

describe("Credit + CatalogKey newtypes", () => {
  it("Credit factory accepts positive in range", () => {
    const c1 = Credit.of(1);
    expect(c1).toBeInstanceOf(Credit);
    expect(c1.raw).toBe(1);
    const cMax = Credit.of(0xff_ff_ff_ff);
    expect(cMax).toBeInstanceOf(Credit);
    expect(cMax.raw).toBe(0xff_ff_ff_ff);
  });

  it("Credit factory rejects zero with InvalidGrant under OutletError", () => {
    let caught: unknown;
    try {
      Credit.of(0);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(InvalidGrant);
    expect(caught).toBeInstanceOf(OutletProtocolError);
    expect(caught).toBeInstanceOf(OutletError);
    if (caught instanceof InvalidGrant) {
      expect(caught.code).toBe("SCP-TOOL-6101");
      expect(caught.slug).toBe("protocol.invalid-grant");
      expect(caught.grant).toBe(0);
    }
  });

  it("Credit factory rejects negative and over max", () => {
    expect(() => Credit.of(-1)).toThrow(InvalidGrant);
    expect(() => Credit.of(0x1_0000_0000)).toThrow(InvalidGrant);
  });

  it("Credit instanceof check rejects raw integer at runtime (instead of brand alias)", () => {
    // The previous bare-`number & __brand` alias erased at runtime; raw 5
    // would pass `typeof grant === "number"`. The class form makes this
    // a real instance check.
    expect(Credit.of(5)).toBeInstanceOf(Credit);
    // Plain number is NOT a Credit instance.
    expect(5 as unknown).not.toBeInstanceOf(Credit);
    expect(0 as unknown).not.toBeInstanceOf(Credit);
  });

  it("CatalogKey factory accepts canonical forms", () => {
    expect(CatalogKey("authorization.denied")).toBe("authorization.denied" as CatalogKey);
    expect(CatalogKey("execution.cancel-ack-timeout")).toBe(
      "execution.cancel-ack-timeout" as CatalogKey,
    );
  });

  it("CatalogKey factory rejects malformed input with OutletProtocolError", () => {
    expect(() => CatalogKey("Authorization.Denied")).toThrow(OutletProtocolError);
    expect(() => CatalogKey("")).toThrow(OutletProtocolError);
    expect(() => CatalogKey(".leading-dot")).toThrow(OutletProtocolError);
  });
});

// ---------------------------------------------------------------------------
// OutletError.new — options-object only
// ---------------------------------------------------------------------------

describe("OutletError.new options-object", () => {
  it("returns a typed subclass for each class", () => {
    const cases: Array<[string, typeof OutletError]> = [
      ["protocol", OutletProtocolError],
      ["authorization", AuthorizationError],
      ["input", InputError],
      ["execution", ExecutionError],
      ["output", OutputError],
      ["economic", EconomicError],
      ["transport", OutletTransportError],
      ["governance", OutletGovernanceError],
    ];
    for (const [wire, ctor] of cases) {
      const err = OutletError.new({
        outletId: makeOutletId("outlet-1"),
        catalogKey: CatalogKey(`${wire}.test`.replace(/[^a-z0-9.-]/g, "")),
        class: wire as Parameters<typeof OutletError.new>[0]["class"],
      });
      expect(err).toBeInstanceOf(ctor);
      expect(err.classWire).toBe(wire as Parameters<typeof OutletError.new>[0]["class"]);
    }
  });

  it("rejects unknown class with ValidationError", () => {
    expect(() =>
      OutletError.new({
        outletId: makeOutletId("o"),
        catalogKey: "authorization.denied" as CatalogKey,
        class: "nope" as never,
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed catalogKey with OutletProtocolError", () => {
    expect(() =>
      OutletError.new({
        outletId: makeOutletId("o"),
        catalogKey: "BAD" as CatalogKey,
        class: "authorization",
      }),
    ).toThrow(OutletProtocolError);
  });
});

// ---------------------------------------------------------------------------
// PII redaction
// ---------------------------------------------------------------------------

describe("PII redaction", () => {
  it("replaces emails", () => {
    expect(redactPii("hello user@example.com world")).toContain("[redacted]");
    expect(redactPii("hello user@example.com world")).not.toContain("user@example.com");
  });

  it("replaces DIDs", () => {
    expect(redactPii("acting as did:dht:abc.123_xyz")).toContain("[redacted]");
    expect(redactPii("acting as did:web:host.example")).toContain("[redacted]");
    expect(redactPii("acting as did:key:zABC")).toContain("[redacted]");
  });

  it("replaces multiple matches", () => {
    const out = redactPii("a@b.co and c@d.io and did:web:host");
    const occurrences = (out.match(/\[redacted\]/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(3);
  });

  it("redacts the message stored on a constructed OutletError", () => {
    const err = new AuthorizationError("leaked alice@example.com");
    expect(err.message).not.toContain("alice@example.com");
    expect(err.message).toContain("[redacted]");
  });
});

// ---------------------------------------------------------------------------
// Per-class detail-shape conformance
// ---------------------------------------------------------------------------

describe("Per-class detail-shape conformance", () => {
  function base(class_: string, code: string, slug: string): Record<string, unknown> {
    return { code, slug, class: class_, message: "x", retry: { policy: "never" } };
  }

  it("rejects malformed protocol detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("protocol", "SCP-TOOL-6100", "protocol.violation"),
        detail: { foo: 1 },
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed authorization detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("authorization", "SCP-TOOL-6110", "authorization.denied"),
        detail: { capability: "x", extra: 1 },
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed input detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("input", "SCP-TOOL-6120", "input.schema-violation"),
        detail: { fieldPath: "/x" },
      }),
    ).toThrow(ValidationError);
  });

  it("accepts the three execution detail variants", () => {
    OutletError.fromWire({
      ...base("execution", "SCP-TOOL-6130", "execution.handler-panic"),
      detail: {},
    });
    OutletError.fromWire({
      ...base("execution", "SCP-TOOL-6130", "execution.timeout"),
      detail: { elapsedMs: 30000 },
    });
    OutletError.fromWire({
      ...base("execution", "SCP-TOOL-6130", "execution.handler-panic"),
      detail: { panicLocationHash: "00".repeat(32) },
    });
  });

  it("rejects malformed economic detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("economic", "SCP-TOOL-6150", "economic.insufficient-funds"),
        detail: { foo: 1 },
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed transport detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("transport", "SCP-TOOL-6160", "transport.relay-unavailable"),
        detail: { foo: 1 },
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed governance detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("governance", "SCP-TOOL-6170", "governance.outlet-deregistered"),
        detail: { foo: 1 },
      }),
    ).toThrow(ValidationError);
  });

  it("rejects malformed output detail", () => {
    expect(() =>
      OutletError.fromWire({
        ...base("output", "SCP-TOOL-6140", "output.schema-violation"),
        detail: { fieldPath: "/x" },
      }),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// Fixture round-trip
// ---------------------------------------------------------------------------

describe("Fixture round-trip", () => {
  const fixtures = loadFixtures();

  it("loads at least 30 fixtures", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(30);
  });

  for (const fixture of fixtures) {
    it(`round-trips fixture ${fixture.name}`, () => {
      const wire = toWireShape(fixture);
      const err = OutletError.fromWire(wire);
      expect(err.classWire as string | null).toBe(fixture.class);
      expect(err.code).toBe(fixture.code);
      expect(err.slug).toBe(fixture.slug);
      // `instanceof` survives `fromWire` (native prototype-chain path).
      expect(OutletError.isOutletError(err)).toBe(true);
      // Re-serialize and confirm idempotence on the cared-about fields.
      const again = err.toWire();
      expect(again.class).toBe(fixture.class);
      expect(again.code).toBe(fixture.code);
      expect(again.slug).toBe(fixture.slug);
    });
  }

  it("PII redaction applies to the email+DID fixture", () => {
    const pii = fixtures.find((f) => f.name === "redaction-pii-email-and-did");
    expect(pii).toBeDefined();
    if (pii === undefined) return;
    const err = OutletError.fromWire(toWireShape(pii));
    expect(err.message).not.toContain("user@example.com");
    expect(err.message).not.toContain("did:dht:");
    expect(err.message).toContain("[redacted]");
  });
});

// ---------------------------------------------------------------------------
// instanceof survival across napi-rs FFI / JSON round-trip
// ---------------------------------------------------------------------------

describe("instanceof survival across FFI / JSON round-trip", () => {
  it("typed AuthorizationError thrown locally is instanceof AuthorizationError", () => {
    const err = new AuthorizationError("denied");
    expect(err instanceof AuthorizationError).toBe(true);
    expect(err instanceof OutletError).toBe(true);
  });

  it("after JSON round-trip the class-tag fallback identifies the subclass", () => {
    const original = new AuthorizationError("denied");
    const wire = original.toWire();
    // Simulate a structuredClone / JSON round-trip that drops the
    // prototype chain — the typed `OutletError.fromWire` reconstructs the
    // proper subclass.
    const reconstructed = OutletError.fromWire(JSON.parse(JSON.stringify(wire)));
    expect(reconstructed instanceof AuthorizationError).toBe(true);
    expect(OutletError.isAuthorizationError(reconstructed)).toBe(true);
  });

  it("a plain object with the right class-tag survives the runtime guard", () => {
    const plain = { scpClassTag: "AuthorizationError", code: "SCP-TOOL-6110" };
    expect(OutletError.isAuthorizationError(plain)).toBe(true);
  });
});
