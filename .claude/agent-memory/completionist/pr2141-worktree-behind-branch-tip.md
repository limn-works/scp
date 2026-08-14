---
name: pr2141-worktree-behind-branch-tip
description: PR #2141 python error-code/class invariant COMPLETE at branch tip 98d905617 — but worktree was checked out at PARENT e4cb632b4 where the fix is absent; read the stated HEAD, not the worktree files
metadata:
  type: project
---

PR #2141 (fix/sdk-coverage-fail-closed-and-parity) invariant "code prefix predicts exception class": every `raise X(..., "SCP-CAT-*")` in bindings/python/scp_sdk/ raises X == CODE_PREFIX_MAP["SCP-CAT"].

**Verdict at stated HEAD 98d905617: COMPLETE, 0 violations.** 67 literal-code raise sites all conform. The 4 attestation sites scp.py:675/836/921/985 raise AttestationError w/ SCP-ATTEST-9010/11/13/12 (fixed by commit 98d905617 "reconcile attestation preflight raise sites to AttestationError"). test_identity_attestation.py updated to `pytest.raises(AttestationError, match="SCP-ATTEST-90xx")`. All 20 errors.__all__ classes imported+re-exported in __init__.__all__ (from scp_sdk import X works for all). ProtocolError/InvalidGrant/StreamAlreadyClosed/StreamGap raise SCP-OUTLET codes = subclasses of OutletError (IS-A the mapped class, by design per errors.py Protocol sub-hierarchy). Dynamic OutletError from chunk.payload code (outlets.py ~683) = base OUTLET family, consistent.

**CRITICAL PROCESS TRAP (this cost the whole first pass):** worktree /tmp/scp-2141 was on DETACHED HEAD e4cb632b4 = the PARENT of branch tip 98d905617. `git rev-parse HEAD` != stated task HEAD. At e4cb632b4 the 4 attestation sites STILL raise IdentityError (fix is one commit AHEAD). Reading worktree files directly = FALSE "invariant violated" finding. `git merge-base --is-ancestor HEAD 98d905617` = YES proved worktree was behind. Had to review via `git show 98d905617:path`.
**Why:** worktree checkout can lag the pushed branch tip by ≥1 commit; the worktree's own HEAD is not guaranteed to be the stated review target.
**How to apply:** FIRST action on any commit-scoped review = `git rev-parse HEAD` and compare to the stated SHA. If they differ, `git show <statedSHA>:path` (or checkout the SHA) — never trust the working-tree files. Sharper corollary to [[verify-against-commit-not-worktree]].

**Enforcement gap (obs, not a PR-2141 gap):** the class↔prefix invariant is NOT machine-enforced — scripts/check-error-codes.sh only validates the numeric range per prefix (SCP-ATTEST => 9000-9999), never that the raised CLASS matches the prefix. Only unit tests lock it in. Latent drift risk if a future raise uses the wrong class with an in-range code.
