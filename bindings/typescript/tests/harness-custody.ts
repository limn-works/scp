/**
 * Test-harness custody: reaching the in-memory key store the SDK cannot name.
 *
 * Section 3.2.2 of the identity spec, "The Custody Vocabulary", states that a
 * caller names one of two backends, `"encrypted_file"` and `"os_keystore"`,
 * and that the vocabulary "holds no third value". It states separately that a
 * build carrying the bridge's `testing` cargo feature "additionally accepts
 * the string `in_memory` at the bridge, which reaches that test-only
 * backend", that the string "is a test-harness affordance and not a value of
 * this vocabulary", and that "no SDK enum spells it, a test that needs it
 * passes the raw string to the bridge".
 *
 * {@link SCP.identityCreate} therefore takes `CustodyType`, which spells only
 * the two vocabulary values, and the helpers below reach the native addon
 * directly with the raw string. Each one wraps the handle the addon returns
 * the same way the SDK method does, so a test reads an `Identity` either way.
 */

import { Identity } from "../src/identity";
import { __getNativeScp, type SCP } from "../src/scp";

/** The addon methods these helpers call, typed to take a raw custody string. */
interface RawIdentityCreate {
  identityCreate(custody: string): Promise<unknown>;
  identityCreateWithAgentKey(custody: string): Promise<unknown>;
}

function rawAddon(scp: SCP): RawIdentityCreate {
  return __getNativeScp(scp) as unknown as RawIdentityCreate;
}

/**
 * Create an identity whose keys live in the test-only in-memory key store.
 *
 * A build without the bridge's `testing` cargo feature answers the raw string
 * with `SCP-IDENT-1008` and builds nothing, so this helper only reaches a key
 * store in a test build.
 */
export async function createInMemoryIdentity(scp: SCP): Promise<Identity> {
  return Identity._fromHandle(scp, await rawAddon(scp).identityCreate("in_memory"));
}

/**
 * Create an identity carrying an `#agent` signing key (ADR-039, the shared-DID
 * agent binding) in the test-only in-memory key store.
 */
export async function createInMemoryIdentityWithAgentKey(scp: SCP): Promise<Identity> {
  return Identity._fromHandle(scp, await rawAddon(scp).identityCreateWithAgentKey("in_memory"));
}
