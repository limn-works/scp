/**
 * Custody selection is required on `identityCreate` and
 * `identityCreateWithAgentKey`.
 *
 * Persistence spec §17.17.1 (`SCP-CAPSEL-8000`) forbids "an
 * omit-the-field form … that silently selects an implementation", and §17:658
 * of that spec classifies `InMemoryKeyCustody` as a security nullifier. Kotlin
 * and Swift require this argument; these tests pin TypeScript to that same
 * requirement at both layers:
 *
 * - TypeScript's compiler rejects a call that omits this argument (each
 *   `@ts-expect-error` assertion below fails `bun run check` if a default
 *   parameter returns, because an expectation with no error is itself an
 *   error);
 * - a runtime guard rejects `undefined` and an empty string, which a JavaScript
 *   caller can still pass.
 */

import { describe, expect, it } from "bun:test";
import { GovernanceError, IdentityError, UnknownGovernanceOutcomeError } from "../src/errors";
import type { CustodyType } from "../src/identity";
import { GOVERNANCE_ACTION_RESULTS } from "../src/types";
import { mountMockScp } from "./mock-bridge";

describe("custody selection is required", () => {
  it("rejects a call that omits custody at compile time", () => {
    const { scp } = mountMockScp();

    // @ts-expect-error — custody is a required parameter, so omitting it must
    // not compile. Restoring `custody: string = "in_memory"` removes this
    // error and fails `tsc --noEmit -p tsconfig.test.json`.
    const created = scp.identityCreate();
    // @ts-expect-error — same requirement on an agent-key constructor.
    const createdWithAgentKey = scp.identityCreateWithAgentKey();

    // Consume both promises so no rejection escapes this test.
    expect(created).rejects.toBeInstanceOf(IdentityError);
    expect(createdWithAgentKey).rejects.toBeInstanceOf(IdentityError);
  });

  it("rejects an undefined custody at runtime", async () => {
    const { scp } = mountMockScp();
    const untyped = scp as unknown as {
      identityCreate(custody?: unknown): Promise<unknown>;
      identityCreateWithAgentKey(custody?: unknown): Promise<unknown>;
    };

    for (const call of [
      () => untyped.identityCreate(undefined),
      () => untyped.identityCreateWithAgentKey(undefined),
    ]) {
      const err = await call().then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(err).toBeInstanceOf(IdentityError);
      expect((err as IdentityError).code).toBe("SCP-IDENT-1064");
      expect((err as IdentityError).message).toContain("custody selection is required");
      // A shipped addon answers every custody name with SCP-IDENT-1059, so the
      // message recommends none and states that instead.
      for (const name of ['"file"', '"platform"', '"software"', '"in_memory"']) {
        expect((err as IdentityError).message).not.toContain(name);
      }
      expect((err as IdentityError).message).toContain("SCP-IDENT-1059");
    }
  });

  it("types every custody name the napi bridge accepts", () => {
    // Each element must be assignable to `CustodyType`, so dropping a name the
    // bridge's `validate_custody_type` accepts from the union fails
    // `tsc --noEmit -p tsconfig.test.json`.
    const names: CustodyType[] = ["file", "platform", "software", "in_memory"];
    expect(new Set(names).size).toBe(4);
  });

  it("rejects an empty custody string at runtime", async () => {
    const { scp } = mountMockScp();
    const err = await scp.identityCreate("   ").then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(err).toBeInstanceOf(IdentityError);
    expect((err as IdentityError).code).toBe("SCP-IDENT-1064");
  });

  it("carries a code no other condition already raises", async () => {
    // `SCP-IDENT-1060`, `SCP-IDENT-1061`, and `SCP-IDENT-1062` name three
    // identity-link attestation verification failures, and `SCP-IDENT-1063` is
    // what Kotlin's `CoroutineBridge.resolveIdentityHandle` raises when a
    // broadcast call names no identity handle. One code naming two conditions
    // sends an operator whose handler keys on the string to the wrong remedy,
    // so this guard carries `SCP-IDENT-1064`, which
    // `crates/scp-ffi/common/src/error_codes.rs` allocates to it. Phase 2 of
    // `scripts/check-error-codes.sh` reads only the four FFI bridge source
    // directories, so it sees neither SDK literal.
    const { scp } = mountMockScp();
    const err = await scp.identityCreate("").then(
      () => undefined,
      (caught: unknown) => caught,
    );
    for (const taken of ["SCP-IDENT-1060", "SCP-IDENT-1061", "SCP-IDENT-1062", "SCP-IDENT-1063"]) {
      expect((err as IdentityError).code).not.toBe(taken);
    }
    expect((err as IdentityError).code).toBe("SCP-IDENT-1064");
  });

  it("passes a named custody backend through to a bridge", async () => {
    const { scp, native } = mountMockScp();
    let received: unknown;
    native.__stub("identityCreate", async (custody: unknown) => {
      received = custody;
      return { did: "did:dht:z6MkCustodySelection", custodyType: "in_memory" };
    });

    await scp.identityCreate("in_memory");
    expect(received).toBe("in_memory");
  });
});

describe("governance outcome parsing fails closed", () => {
  it("returns a named outcome a bridge reported", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("contextExecuteGovernanceAction", async () => "RoleChanged");

    const outcome = await scp.contextExecuteGovernanceAction({}, "ab".repeat(16));
    expect(outcome).toBe("RoleChanged");
  });

  it("rejects an outcome this SDK version cannot name", async () => {
    // An SDK older than its bridge reads a name no entry matches. Reporting
    // that as a success would tell a caller a governance action succeeded while
    // this SDK cannot say which one ran, so parsing throws instead. Deleting
    // that parse from `contextExecuteGovernanceAction` makes this call resolve,
    // so this assertion fails.
    const { scp, native } = mountMockScp();
    native.__stub("contextExecuteGovernanceAction", async () => "SomethingThisSdkDoesNotKnow");

    const err = await scp.contextExecuteGovernanceAction({}, "ab".repeat(16)).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(err).toBeInstanceOf(UnknownGovernanceOutcomeError);
    // A caller catching a governance failure catches this one too.
    expect(err).toBeInstanceOf(GovernanceError);
    expect((err as UnknownGovernanceOutcomeError).code).toBe("SCP-GOV-11040");
    expect((err as UnknownGovernanceOutcomeError).rawOutcome).toBe("SomethingThisSdkDoesNotKnow");
    expect((err as UnknownGovernanceOutcomeError).message).toContain("SomethingThisSdkDoesNotKnow");
  });

  it("rejects an auto-executed propose outcome this SDK version cannot name", async () => {
    // A `single_admin` proposal auto-executes, so its outcome arrives in the
    // propose response's `execution_result`. Deleting the check from
    // `contextGovernancePropose` makes this call resolve, so this assertion fails.
    const { scp, native } = mountMockScp();
    native.__stub("contextGovernancePropose", async () =>
      JSON.stringify({
        proposal_id: "ab".repeat(16),
        status: "Executed",
        execution_result: "SomethingThisSdkDoesNotKnow",
      }),
    );

    const err = await scp.contextGovernancePropose({}, "{}", "did:dht:z6MkAlice").then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(err).toBeInstanceOf(UnknownGovernanceOutcomeError);
    expect((err as UnknownGovernanceOutcomeError).code).toBe("SCP-GOV-11040");
    expect((err as UnknownGovernanceOutcomeError).rawOutcome).toBe("SomethingThisSdkDoesNotKnow");
  });

  it("returns a propose response whose outcome it can name, or that awaits votes", async () => {
    for (const executionResult of ["RoleChanged", null]) {
      const { scp, native } = mountMockScp();
      const raw = JSON.stringify({
        proposal_id: "ab".repeat(16),
        status: executionResult === null ? "Pending" : "Executed",
        execution_result: executionResult,
      });
      native.__stub("contextGovernancePropose", async () => raw);

      expect(await scp.contextGovernancePropose({}, "{}", "did:dht:z6MkAlice")).toBe(raw);
    }
  });

  it("rejects a propose response it cannot check", async () => {
    for (const raw of ["not json", "[]", JSON.stringify({ execution_result: 7 })]) {
      const { scp, native } = mountMockScp();
      native.__stub("contextGovernancePropose", async () => raw);

      const err = await scp.contextGovernancePropose({}, "{}", "did:dht:z6MkAlice").then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(err).toBeInstanceOf(GovernanceError);
      expect((err as GovernanceError).code).toBe("SCP-GOV-11040");
    }
  });

  it("names every outcome that Rust enum defines", () => {
    // `scp_core::context::state::GovernanceActionResult` defines 29 variants,
    // and one shared bridge mapping reports each by its variant name.
    expect(GOVERNANCE_ACTION_RESULTS.length).toBe(29);
    expect(GOVERNANCE_ACTION_RESULTS).toContain("MigrationProposed");
    expect(GOVERNANCE_ACTION_RESULTS).toContain("MigrationCancelled");
    expect(GOVERNANCE_ACTION_RESULTS).toContain("ContextTombstoned");
  });
});
