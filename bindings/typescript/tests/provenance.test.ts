/**
 * Tests for the provenance record decoder.
 *
 * Verifies that `decodeProvenanceRecord` converts the raw snake_case JSON wire
 * string (as emitted by the native bridge) into the SDK's typed camelCase
 * {@link ProvenanceRecord}, and — per ADR-060 — parses the `payment_amount`
 * decimal string into a `bigint` that round-trips a > 2^53 value exactly.
 */

import { describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import { decodeProvenanceRecord } from "../src/provenance";

describe("decodeProvenanceRecord", () => {
  it("maps every snake_case wire field to its camelCase counterpart", () => {
    const wire = JSON.stringify({
      source_context: "ctx-src",
      source_type: "Persistent",
      chain_depth: 2,
      counterparties: ["did:dht:z6MkAlice", "did:dht:z6MkBob"],
      age_secs: 42,
      memory_scope: "Full",
      chain_path: ["ctx-hop-1", "ctx-hop-2"],
      purpose: "recipe sharing",
      discovery_method: { SharedContext: "ctx-shared" },
      payment_amount: "1000",
      payment_adapter: "lightning",
      payment_receipt_id: "ab".repeat(32),
    });

    const record = decodeProvenanceRecord(wire);

    expect(record.sourceContext).toBe("ctx-src");
    expect(record.sourceType).toBe("Persistent");
    expect(record.chainDepth).toBe(2);
    expect(record.counterparties).toEqual(["did:dht:z6MkAlice", "did:dht:z6MkBob"]);
    expect(record.ageSecs).toBe(42);
    expect(record.memoryScope).toBe("Full");
    expect(record.chainPath).toEqual(["ctx-hop-1", "ctx-hop-2"]);
    expect(record.purpose).toBe("recipe sharing");
    expect(record.discoveryMethod).toEqual({ SharedContext: "ctx-shared" });
    expect(record.paymentAmount).toBe(1000n);
    expect(record.paymentAdapter).toBe("lightning");
    expect(record.paymentReceiptId).toBe("ab".repeat(32));
  });

  it("round-trips a payment_amount above 2^53 exactly (ADR-060)", () => {
    // 2^53 + 1 is the first integer a JS `number` cannot represent exactly.
    const big = (2n ** 53n + 1n).toString();
    const wire = JSON.stringify({
      source_context: "ctx-src",
      source_type: "Persistent",
      chain_depth: 0,
      counterparties: [],
      age_secs: 0,
      memory_scope: "Full",
      chain_path: null,
      purpose: null,
      discovery_method: "OutOfBand",
      payment_amount: big,
      payment_adapter: "stripe",
      payment_receipt_id: null,
    });

    const record = decodeProvenanceRecord(wire);

    expect(record.paymentAmount).toBe(2n ** 53n + 1n);
    // The value survives a full string round-trip with no precision loss.
    expect(record.paymentAmount?.toString()).toBe(big);
  });

  it("round-trips the full u64 max exactly", () => {
    const u64Max = (2n ** 64n - 1n).toString();
    const wire = JSON.stringify({
      source_context: "ctx-src",
      source_type: "Persistent",
      chain_depth: 0,
      counterparties: [],
      age_secs: 0,
      memory_scope: "Full",
      chain_path: null,
      purpose: null,
      discovery_method: "OutOfBand",
      payment_amount: u64Max,
      payment_adapter: null,
      payment_receipt_id: null,
    });

    expect(decodeProvenanceRecord(wire).paymentAmount).toBe(2n ** 64n - 1n);
  });

  it("surfaces null payment fields as null", () => {
    const wire = JSON.stringify({
      source_context: "ctx-src",
      source_type: "Persistent",
      chain_depth: 0,
      counterparties: [],
      age_secs: 0,
      memory_scope: "Full",
      chain_path: null,
      purpose: null,
      discovery_method: "OutOfBand",
      payment_amount: null,
      payment_adapter: null,
      payment_receipt_id: null,
    });

    const record = decodeProvenanceRecord(wire);

    expect(record.paymentAmount).toBeNull();
    expect(record.paymentAdapter).toBeNull();
    expect(record.paymentReceiptId).toBeNull();
    expect(record.chainPath).toBeNull();
    expect(record.purpose).toBeNull();
    expect(record.discoveryMethod).toBe("OutOfBand");
  });

  it("throws ValidationError on malformed JSON", () => {
    expect(() => decodeProvenanceRecord("{not json}")).toThrow(ValidationError);
  });

  it("throws ValidationError when payment_amount is not a decimal string", () => {
    const wire = JSON.stringify({
      source_context: "ctx-src",
      source_type: "Persistent",
      chain_depth: 0,
      counterparties: [],
      age_secs: 0,
      memory_scope: "Full",
      chain_path: null,
      purpose: null,
      discovery_method: "OutOfBand",
      payment_amount: "not-a-number",
      payment_adapter: null,
      payment_receipt_id: null,
    });

    expect(() => decodeProvenanceRecord(wire)).toThrow(ValidationError);
  });

  it("rejects a bare-number payment_amount (must be a decimal string)", () => {
    const wire = '{"payment_amount": 1000, "discovery_method": "OutOfBand"}';
    expect(() => decodeProvenanceRecord(wire)).toThrow(ValidationError);
  });
});
