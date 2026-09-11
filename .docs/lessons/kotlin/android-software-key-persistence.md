# Android Software Key Persistence — EncryptedSharedPreferences Required

**Problem**: where `AndroidKeyCustody` holds a key in software rather than in the Android
Keystore, that key must survive process death. Android kills processes routinely for memory
pressure, and the device restarts.

A naive implementation stores software keys only in an in-memory `ConcurrentHashMap`. This
passes every JVM unit test and silently loses each software-held identity key when the process
dies. The next `SCP.create()` call generates a new identity key under a new identifier, so the
user loses their SCP identity with no error.

**Correct pattern**:
- On generating a software key: serialize the Bouncy Castle key pair and write it to
  `EncryptedSharedPreferences` (Jetpack Security) under `scp.key.<id>`.
- On `AndroidKeyCustody` init: scan every `scp.key.*` entry in EncryptedSharedPreferences and
  re-populate `softwareKeys` from them.
- On destroying a software key: remove it from `softwareKeys` AND delete it from
  EncryptedSharedPreferences.
- When verifying a destroy: check EncryptedSharedPreferences absence, not `ConcurrentHashMap`
  absence alone.

**Side effect**: `AndroidKeyCustody` must accept an Android `Context` constructor parameter
(the other three providers already do). Update `AndroidPlatformAdapter.make()` to pass context
to `AndroidKeyCustody(context)`.

**Reference**: ADR-027 rationale states "Keys are stored encrypted in EncryptedSharedPreferences
(Jetpack Security) as the next-best alternative to hardware backing" — this was the design intent.
