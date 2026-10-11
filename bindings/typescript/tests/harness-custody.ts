/**
 * Test-harness custody: the one place a test reaches the in-memory key store.
 *
 * Spec `03-identity.md` §3.2.2 says an SDK's custody type carries
 * `encrypted_file` and `os_keystore` and no other member, and that `in_memory`
 * is a testing-build affordance a test harness reaches outside the SDK's
 * custody type. {@link CustodyType} therefore has no `"in_memory"` member, and
 * every test that needs in-memory custody sends the raw string to the native
 * addon through this module.
 *
 * Only an addon built with the bridge's `testing` feature accepts the string;
 * a shipped addon answers it with `SCP-IDENT-1008` and builds nothing. This
 * file lives under `tests/`, which `src/index.ts` never imports and the
 * package's `files` list (`dist/`) never ships.
 */

import { mapBridgeError } from "../src/errors";
import { Identity } from "../src/identity";
import { __getNativeScp, type SCP } from "../src/scp";

/**
 * The raw custody string a `testing` addon maps to its in-memory key store.
 * Tests that drive the internal bridge (`createNativeBridge`), whose
 * `identityCreate` takes a plain string, pass this constant.
 */
export const HARNESS_IN_MEMORY_CUSTODY = "in_memory";

/** The addon methods these helpers call, typed to take a raw custody string. */
interface RawIdentityCreate {
  identityCreate(custody: string): Promise<unknown>;
  identityCreateWithAgentKey(custody: string): Promise<unknown>;
}

function rawAddon(scp: SCP): RawIdentityCreate {
  return __getNativeScp(scp) as unknown as RawIdentityCreate;
}

/**
 * Creates an identity whose keys live in the testing addon's in-memory key
 * store, wrapped and error-mapped the way {@link SCP.identityCreate} wraps it.
 */
export async function createInMemoryIdentity(scp: SCP): Promise<Identity> {
  try {
    return Identity._fromHandle(scp, await rawAddon(scp).identityCreate(HARNESS_IN_MEMORY_CUSTODY));
  } catch (err) {
    throw mapBridgeError(err);
  }
}

/**
 * Same as {@link createInMemoryIdentity}, and the identity also carries an
 * `#agent` signing key (ADR-039), as {@link SCP.identityCreateWithAgentKey}
 * builds it.
 */
export async function createInMemoryIdentityWithAgentKey(scp: SCP): Promise<Identity> {
  try {
    return Identity._fromHandle(
      scp,
      await rawAddon(scp).identityCreateWithAgentKey(HARNESS_IN_MEMORY_CUSTODY),
    );
  } catch (err) {
    throw mapBridgeError(err);
  }
}
