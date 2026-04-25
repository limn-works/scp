/**
 * Tests for SCP TypeScript SDK identity link attestation wrappers (§3.5).
 *
 * Covers:
 * - IdentityAttestation construction and serialization
 * - _fromRecord / _fromJson / _toBridgeRecord round-trip
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, `IdentityAttestation`
 * and `RevocationStatus` are pure value types with no `SCP` backing —
 * the old `(data, scp)` constructor signature collapsed to `(data,
 * rawJson?)`. All bridge-touching verification lives on `SCP`.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ValidationError } from "../src/errors";
import { IdentityAttestation, RevocationStatus } from "../src/identity";
import { SCP } from "../src/scp";

// ---------------------------------------------------------------------------
// IdentityAttestation class tests
// ---------------------------------------------------------------------------

describe("IdentityAttestation", () => {
  let scp: SCP;

  beforeEach(() => {
    scp = new SCP();
  });

  afterEach(async () => {
    await scp.shutdown(1);
  });

  const sampleData = {
    id: "abc123",
    platform: "github.com",
    platformHandle: "alice",
    verificationMethod: "did:dht:z6Mk...#active",
    verifiedAt: 1700000000,
    revocationStatus: RevocationStatus.active(),
  };

  it("constructs with all required fields", () => {
    const att = new IdentityAttestation(sampleData);
    expect(att.id).toBe("abc123");
    expect(att.platform).toBe("github.com");
    expect(att.platformHandle).toBe("alice");
    expect(att.verificationMethod).toBe("did:dht:z6Mk...#active");
    expect(att.verifiedAt).toBe(1700000000);
    expect(att.revocationStatus.status).toBe("active");
    expect(att.platformId).toBeUndefined();
  });

  it("constructs with optional platformId", () => {
    const att = new IdentityAttestation({ ...sampleData, platformId: "42" });
    expect(att.platformId).toBe("42");
  });

  it("_fromRecord handles snake_case keys", () => {
    const record = {
      id: "abc123",
      platform: "github.com",
      platform_handle: "alice",
      verification_method: "did:dht:z6Mk...#active",
      verified_at: 1700000000,
      revocation_status: "active",
      platform_id: "42",
    };
    const att = IdentityAttestation._fromRecord(record);
    expect(att.platformHandle).toBe("alice");
    expect(att.verificationMethod).toBe("did:dht:z6Mk...#active");
    expect(att.verifiedAt).toBe(1700000000);
    expect(att.platformId).toBe("42");
  });

  it("_fromRecord handles camelCase keys", () => {
    const record = {
      id: "abc123",
      platform: "github.com",
      platformHandle: "alice",
      verificationMethod: "did:dht:z6Mk...#active",
      verifiedAt: 1700000000,
      revocationStatus: "Active",
    };
    const att = IdentityAttestation._fromRecord(record);
    expect(att.platformHandle).toBe("alice");
    expect(att.revocationStatus.status).toBe("active");
  });

  it("_fromRecord defaults revocationStatus to active", () => {
    const record = {
      id: "abc123",
      platform: "github.com",
      platform_handle: "alice",
      verification_method: "did:dht:z6Mk...#active",
      verified_at: 1700000000,
    };
    const att = IdentityAttestation._fromRecord(record);
    expect(att.revocationStatus.status).toBe("active");
  });

  it("_fromJson parses JSON string with Revoked status", () => {
    const json = JSON.stringify({
      id: "abc123",
      platform: "github.com",
      platform_handle: "alice",
      verification_method: "did:dht:z6Mk...#active",
      verified_at: 1700000000,
      revocation_status: { Revoked: { revoked_at: 1700000100, reason: "test" } },
    });
    const att = IdentityAttestation._fromJson(json);
    expect(att.id).toBe("abc123");
    expect(att.revocationStatus.status).toBe("revoked");
    expect(att.revocationStatus.revokedAt).toBe(1700000100);
    expect(att.revocationStatus.reason).toBe("test");
  });

  it("_toBridgeRecord produces snake_case keys", () => {
    const att = new IdentityAttestation(sampleData);
    const rec = att._toBridgeRecord();
    expect(rec.id).toBe("abc123");
    expect(rec.platform).toBe("github.com");
    expect(rec.platform_handle).toBe("alice");
    expect(rec.verification_method).toBe("did:dht:z6Mk...#active");
    expect(rec.verified_at).toBe(1700000000);
    expect(rec.revocation_status).toBe("Active");
    expect(rec.platform_id).toBeUndefined();
  });

  it("_toBridgeRecord includes platformId when present", () => {
    const att = new IdentityAttestation({ ...sampleData, platformId: "99" });
    const rec = att._toBridgeRecord();
    expect(rec.platform_id).toBe("99");
  });

  it("round-trips through _toBridgeRecord and _fromRecord", () => {
    const att = new IdentityAttestation({ ...sampleData, platformId: "99" });
    const rec = att._toBridgeRecord();
    const roundtrip = IdentityAttestation._fromRecord(rec);
    expect(roundtrip.id).toBe(att.id);
    expect(roundtrip.platform).toBe(att.platform);
    expect(roundtrip.platformHandle).toBe(att.platformHandle);
    expect(roundtrip.verificationMethod).toBe(att.verificationMethod);
    expect(roundtrip.verifiedAt).toBe(att.verifiedAt);
    expect(roundtrip.revocationStatus.status).toBe(att.revocationStatus.status);
    expect(roundtrip.platformId).toBe(att.platformId);
  });

  it("SCP instance constructs and shuts down cleanly alongside attestations", () => {
    // Confirms the test-scoped SCP plumbing from beforeEach/afterEach
    // still exercises an SCP instance — attestations themselves are
    // now pure value types and no longer hold an SCP reference.
    expect(typeof scp.instanceId).toBe("string");
  });

  it("RevocationStatus.active() creates active status", () => {
    const rs = RevocationStatus.active();
    expect(rs.status).toBe("active");
    expect(rs.revokedAt).toBeUndefined();
    expect(rs.reason).toBeUndefined();
  });

  it("RevocationStatus.revoked() creates revoked status", () => {
    const rs = RevocationStatus.revoked(1700000100, "compromised");
    expect(rs.status).toBe("revoked");
    expect(rs.revokedAt).toBe(1700000100);
    expect(rs.reason).toBe("compromised");
  });

  it("RevocationStatus round-trips through bridge value", () => {
    const active = RevocationStatus.active();
    const activeRt = RevocationStatus._fromBridgeValue(active._toBridgeValue());
    expect(activeRt.status).toBe("active");

    const revoked = RevocationStatus.revoked(1700000100, "test");
    const revokedRt = RevocationStatus._fromBridgeValue(revoked._toBridgeValue());
    expect(revokedRt.status).toBe("revoked");
    expect(revokedRt.revokedAt).toBe(1700000100);
    expect(revokedRt.reason).toBe("test");
  });

  // ---------------------------------------------------------------------------
  // NaN / Infinity guard tests (SCP-VALID-7005)
  // ---------------------------------------------------------------------------

  it("_fromRecord throws ValidationError SCP-VALID-7005 for NaN verified_at", () => {
    expect(() =>
      IdentityAttestation._fromRecord({
        id: "abc123",
        platform: "github.com",
        platform_handle: "alice",
        verification_method: "did:dht:z6Mk...#active",
        verified_at: Number.NaN,
      }),
    ).toThrow(ValidationError);
    try {
      IdentityAttestation._fromRecord({
        id: "abc123",
        platform: "github.com",
        platform_handle: "alice",
        verification_method: "did:dht:z6Mk...#active",
        verified_at: Number.NaN,
      });
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7005");
    }
  });

  it("_fromRecord throws ValidationError SCP-VALID-7005 for Infinity verified_at", () => {
    try {
      IdentityAttestation._fromRecord({
        id: "abc123",
        platform: "github.com",
        platform_handle: "alice",
        verification_method: "did:dht:z6Mk...#active",
        verified_at: Infinity,
      });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7005");
    }
  });

  it("RevocationStatus._fromBridgeValue throws ValidationError SCP-VALID-7005 for NaN revoked_at", () => {
    try {
      RevocationStatus._fromBridgeValue({ Revoked: { revoked_at: Number.NaN } });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
      expect((e as ValidationError).code).toBe("SCP-VALID-7005");
    }
  });

  it("RevocationStatus.revoked() factory throws ValidationError for NaN revokedAt", () => {
    expect(() => RevocationStatus.revoked(Number.NaN, "reason")).toThrow(ValidationError);
  });

  it("IdentityAttestation constructor throws ValidationError for NaN verifiedAt", () => {
    expect(
      () =>
        new IdentityAttestation({
          id: "abc123",
          platform: "github.com",
          platformHandle: "alice",
          verificationMethod: "did:dht:z6Mk...#active",
          verifiedAt: Number.NaN,
          revocationStatus: RevocationStatus.active(),
        }),
    ).toThrow(ValidationError);
  });

  it("RevocationStatus.revoked() factory throws for negative revokedAt", () => {
    expect(() => RevocationStatus.revoked(-1, "reason")).toThrow(ValidationError);
  });

  it("IdentityAttestation constructor throws for negative verifiedAt", () => {
    expect(
      () =>
        new IdentityAttestation({
          id: "abc123",
          platform: "github.com",
          platformHandle: "alice",
          verificationMethod: "did:dht:z6Mk...#active",
          verifiedAt: -1,
          revocationStatus: RevocationStatus.active(),
        }),
    ).toThrow(ValidationError);
  });

  it("RevocationStatus.revoked() factory throws for non-integer float", () => {
    expect(() => RevocationStatus.revoked(1.5, "reason")).toThrow(ValidationError);
  });
});
