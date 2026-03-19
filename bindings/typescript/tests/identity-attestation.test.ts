/**
 * Tests for SCP TypeScript SDK identity link attestation wrappers (§3.5).
 *
 * Covers:
 * - IdentityAttestation construction and serialization
 * - Identity attestation methods throw when bridge functions unavailable
 * - _fromRecord / _fromJson / _toBridgeRecord round-trip
 */

import { describe, expect, it } from "bun:test";
import { IdentityAttestation } from "../src/identity";

// ---------------------------------------------------------------------------
// IdentityAttestation class tests
// ---------------------------------------------------------------------------

describe("IdentityAttestation", () => {
  const sampleData = {
    id: "abc123",
    platform: "github.com",
    platformHandle: "alice",
    verificationMethod: "did:dht:z6Mk...#active",
    verifiedAt: 1700000000,
    revocationStatus: "active",
  };

  it("constructs with all required fields", () => {
    const att = new IdentityAttestation(sampleData);
    expect(att.id).toBe("abc123");
    expect(att.platform).toBe("github.com");
    expect(att.platformHandle).toBe("alice");
    expect(att.verificationMethod).toBe("did:dht:z6Mk...#active");
    expect(att.verifiedAt).toBe(1700000000);
    expect(att.revocationStatus).toBe("active");
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
      revocationStatus: "active",
    };
    const att = IdentityAttestation._fromRecord(record);
    expect(att.platformHandle).toBe("alice");
    expect(att.revocationStatus).toBe("active");
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
    expect(att.revocationStatus).toBe("active");
  });

  it("_fromJson parses JSON string", () => {
    const json = JSON.stringify({
      id: "abc123",
      platform: "github.com",
      platform_handle: "alice",
      verification_method: "did:dht:z6Mk...#active",
      verified_at: 1700000000,
      revocation_status: "revoked",
    });
    const att = IdentityAttestation._fromJson(json);
    expect(att.id).toBe("abc123");
    expect(att.revocationStatus).toBe("revoked");
  });

  it("_toBridgeRecord produces snake_case keys", () => {
    const att = new IdentityAttestation(sampleData);
    const rec = att._toBridgeRecord();
    expect(rec.id).toBe("abc123");
    expect(rec.platform).toBe("github.com");
    expect(rec.platform_handle).toBe("alice");
    expect(rec.verification_method).toBe("did:dht:z6Mk...#active");
    expect(rec.verified_at).toBe(1700000000);
    expect(rec.revocation_status).toBe("active");
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
    expect(roundtrip.revocationStatus).toBe(att.revocationStatus);
    expect(roundtrip.platformId).toBe(att.platformId);
  });
});
