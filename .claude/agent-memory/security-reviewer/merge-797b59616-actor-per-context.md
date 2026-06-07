# Merge 797b59616 — ADR-049 actor branch ⇄ origin/main (#1700 per-instance bridges)

Reviewed 2026-06-04. Branch: refactor/actor-per-context.

## Parent topology (task labels were SWAPPED — verify with git cat-file)
- ^1 f1f37ef75 = ADR-049 ACTOR BRANCH (has supervisor.rs, mailbox, PyO3 passphrase storage). HEAD mainline.
- ^2 a94b742376 = origin/main (#1752 cross-bridge ports; NO actor subsystem; NO PyO3 passphrase).
- Always confirm which parent is which via `git cat-file -e <p>:crates/scp-runtime/src/context/supervisor/supervisor.rs`.

## FINDING (HIGH, open): PyO3 storage lost Argon2id passphrase mode in merge
- Actor branch PyO3 had SqliteKeyMaterial::{Raw,Passphrase}; merge took main's raw-key-only StorageConfig{path,key}, dropping passphrase.
- passphrase refs: actor=15, main=0, HEAD=0 in crates/scp-ffi/src/scp.rs. runtime.rs StorageConfig has only `key`.
- NAPI (16 refs) + UniFFI (48 refs) STILL have passphrase → PyO3 asymmetrically weaker (reference bridge!).
- Python SDK scp.py:256 + crates/scp-ffi/CLAUDE.md STILL document passphrase → broken/dead contract (caller gets "missing key 'key'").
- PyO3 raw path still fails closed (StorageInitError::SqliteOpen, no in-memory degrade) — capability loss, not fail-open.
- FIX: restore actor-branch PyO3 passphrase path (SqliteStorage::with_passphrase survived in scp-platform).

## Confirmed survivors (clean)
- sqlite/mod.rs UNIONED correctly: Argon2id passphrase+salt fail-closed (12 with_passphrase) AND fs2 advisory lock (2 try_lock_exclusive). Salt-missing brick prevention double-guarded (with_passphrase L232 + load_or_init_salt L336). Wrong-len/symlink salt rejected. Lock File local in new(), releases on err.
- Custody caller-side: dispatch_broadcast_command_with_custody<C: KeyCustody>(cmd, &custody) — custody by ref, never in mailbox. Two-phase Reserve→sign-in-supervisor→Apply; mailbox carries only ctx_id/author_did/reservation_id/signature(public)/payload. signing_key_handle = opaque KeyHandle, not bytes. All 3 bridges.
- Governance/access-key auth: `git diff f1f37ef75..797b59616 -- crates/scp-runtime/src/context/` EMPTY (byte-identical). member_has_capability intact. Merge runtime deltas are test-only.
- Enforcement STRENGTHENED: check-no-bridge-globals == main (stricter: removed DEFAULT_BRIDGE_INSTANCE allowlist, added fn-local sharing-primitive scan #1699). check-deleted-primitives added. ffi_conformance every_exemption_reason_cites_durable_provenance present. validate_storage_path preserved all 3 bridges.

## Observation (pre-existing, not merge): SqliteKeyMaterial derives Debug over Zeroizing<key/passphrase>
- Zeroizing Debug forwards to inner → {:?} would leak. Not currently reached. Pre-existing on actor branch. Custom redacting Debug recommended.

## Lesson: 3-way merges can silently pick the WEAKER side
When a security feature lives on the branch being merged INTO and the other side lacks it, conflict resolution may take the lacking side. Diff security-load-bearing files against BOTH parents; a feature present in only one parent and absent in HEAD is a regression even when HEAD "matches main."
