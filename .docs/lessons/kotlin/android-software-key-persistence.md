# Android Software Key Persistence — EncryptedSharedPreferences Required

**Problem**: Android Keystore does not support Ed25519 on API 26-32, so `AndroidKeyCustody`
generates software Ed25519 keys with Bouncy Castle. These keys must survive process death.
On Android, processes are killed routinely by the OS for memory pressure or when the device
restarts.

A naive implementation stores software keys only in a `ConcurrentHashMap` in-memory. This passes
all JVM unit tests but silently loses all API 26-32 identity keys when the process dies. The next
`SCP.create()` call generates a brand-new identity key, producing a different DID. The user
effectively loses their SCP identity without any error.

**Correct pattern**:
- On `generateSoftwareEd25519` / `generateSoftwareX25519`: serialize the Bouncy Castle key pair
  and write it to `EncryptedSharedPreferences` (Jetpack Security) under key `scp.key.<id>`.
- On `AndroidKeyCustody` init: scan all `scp.key.*` entries in EncryptedSharedPreferences and
  re-populate `softwareKeys` from them.
- On `destroySoftwareKey`: remove from `softwareKeys` AND delete from EncryptedSharedPreferences.
- On `destroySoftwareKey` verification: check EncryptedSharedPreferences absence, not just
  ConcurrentHashMap absence.

**Side effect**: `AndroidKeyCustody` must accept an Android `Context` constructor parameter
(the other three providers already do). Update `AndroidPlatformAdapter.make()` to pass context
to `AndroidKeyCustody(context)`.

**Reference**: ADR-027 rationale states "Keys are stored encrypted in EncryptedSharedPreferences
(Jetpack Security) as the next-best alternative to hardware backing" — this was the design intent.
