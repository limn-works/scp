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
      expect((err as IdentityError).code).toBe("SCP-IDENT-1060");
      expect((err as IdentityError).message).toContain("custody selection is required");
    }
  });

  it("rejects an empty custody string at runtime", async () => {
    const { scp } = mountMockScp();
    const err = await scp.identityCreate("   ").then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(err).toBeInstanceOf(IdentityError);
    expect((err as IdentityError).code).toBe("SCP-IDENT-1060");
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

  it("names every outcome that Rust enum defines", () => {
    // `scp_core::context::state::GovernanceActionResult` defines 29 variants,
    // and one shared bridge mapping reports each by its variant name.
    expect(GOVERNANCE_ACTION_RESULTS.length).toBe(29);
    expect(GOVERNANCE_ACTION_RESULTS).toContain("MigrationProposed");
    expect(GOVERNANCE_ACTION_RESULTS).toContain("MigrationCancelled");
    expect(GOVERNANCE_ACTION_RESULTS).toContain("ContextTombstoned");
  });
});
