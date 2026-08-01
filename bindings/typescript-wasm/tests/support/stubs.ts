/**
 * Test doubles for the EXTERNAL ports (never for the client under test).
 *
 * The custody double implements the {@link JsKeyCustody} contract but only its
 * one wired method, `did()`, is exercised by the driver in this slice — exactly
 * the surface a real embedder custody exposes today (the sign/dhAgree seams are
 * #1980, unwired). Storage/socket use the real production adapters.
 */

import type { JsKeyCustody } from "../../src/index";

/**
 * A custody double whose `did()` returns the given DID (the only method with a
 * driver call site this slice). The seam methods throw — they must never be
 * reached on a driver path.
 */
export function stubCustody(did: string): JsKeyCustody {
  const seam = (): never => {
    throw new Error("custody seam reached — it has no driver call site in this slice (#1980)");
  };
  return {
    did: () => did,
    sign: seam,
    getPublicKey: seam,
    generateKeypair: seam,
    destroyKey: () => {},
    dhAgree: seam,
  };
}
