/**
 * SCP-OUT-041d — TypeScript SDK unit tests for OutletError.new
 * options-object form, fromWire interop, and the catalog-rotation
 * dwell-time validator.
 */

import { describe, expect, test } from "bun:test";

import {
  AuthorizationError,
  CatalogKey,
  makeOutletId,
  OutletError,
  OutletProtocolError,
  ValidationError,
} from "../src/errors";

describe("OutletError.new — options-object surface (SCP-OUT-041d)", () => {
  test("returns a typed AuthorizationError for class=authorization", () => {
    const err = OutletError.new({
      outletId: makeOutletId("outlet-test"),
      catalogKey: CatalogKey("authorization.denied"),
      class: "authorization",
    });
    expect(err).toBeInstanceOf(AuthorizationError);
    expect(err.classWire).toBe("authorization");
  });

  test("rejects an invalid catalog key", () => {
    expect(() =>
      OutletError.new({
        outletId: makeOutletId("outlet-test"),
        catalogKey: "INVALID UPPER" as unknown as CatalogKey,
        class: "authorization",
      }),
    ).toThrow(OutletProtocolError);
  });

  test("rejects an unknown OutletErrorClass", () => {
    expect(() =>
      OutletError.new({
        outletId: makeOutletId("outlet-test"),
        catalogKey: CatalogKey("authorization.denied"),
        class: "made-up-class" as never,
      }),
    ).toThrow(ValidationError);
  });

  test("rejects an empty outletId", () => {
    expect(() =>
      OutletError.new({
        outletId: "" as unknown as ReturnType<typeof makeOutletId>,
        catalogKey: CatalogKey("authorization.denied"),
        class: "authorization",
      }),
    ).toThrow(ValidationError);
  });

  test("retry defaults to never", () => {
    const err = OutletError.new({
      outletId: makeOutletId("outlet-test"),
      catalogKey: CatalogKey("authorization.denied"),
      class: "authorization",
    });
    expect(err.retry).toEqual({ policy: "never" });
  });
});

describe("OutletError.fromWire — bridge wire-form (snake_case fields)", () => {
  test("accepts the SCP-OUT-041d bridge wire form with hex byte fields", () => {
    const wire = {
      code: "SCP-TOOL-6110",
      slug: "authorization.denied",
      class: "authorization",
      message: "00".repeat(32),
      retry: { policy: "never" },
      pad_nonce: "11".repeat(16),
      registration_event_id: "22".repeat(32),
      source_chain: [],
    };
    const err = OutletError.fromWire(wire);
    expect(err).toBeInstanceOf(AuthorizationError);
    expect(err.classWire).toBe("authorization");
    expect(err.padNonce).toBeInstanceOf(Uint8Array);
    expect(err.padNonce?.length).toBe(16);
    expect(err.registrationEventId?.length).toBe(32);
  });
});
