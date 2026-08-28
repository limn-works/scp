# Device Attestation Proves a Device, Not a Gesture

**Source:** the primary-source check ADR-063, the context-declared user-authentication gate, rests on, run 2026-08-28 against the pages each row of the table below cites.
**Applies to:** any design that would gate a protocol action on a biometric, a passcode entry, or any other user-presence check, and that reaches for a platform attestation to carry the proof.

## The Claim That Is Wrong

"An App Attest assertion or a Play Integrity token proves that a person authenticated before this action." Neither vendor documents anything of the kind. A designer reaches the wrong answer easily, because both APIs run on a device that also offers biometric APIs, and both return a signed object whose name suggests a per-action proof.

Apple describes `DCAppAttestService.generateAssertion` as producing "a block of data that demonstrates the legitimacy of an instance of your app running on a device". The assertion's authenticator data is the WebAuthn 37-byte structure — a 32-byte relying-party-identifier hash, a flags byte, and a 4-byte counter — and Apple's stated verification steps read the hash and the counter. Apple documents no meaning for the flags byte in App Attest, so a verifier that read its user-present and user-verified bits would read a value Apple never specified.

Google's Play Integrity payload carries `requestDetails`, `accountDetails`, `appIntegrity`, `deviceIntegrity`, and `environmentDetails`, and the `deviceIntegrity` verdict `MEETS_DEVICE_INTEGRITY` reads "The app is running on a genuine and certified Android device. On Android 13 and higher, there is hardware-backed proof that the device bootloader is locked and the loaded Android OS is a certified device manufacturer image." No verdict field reports a user-authentication event.

Both APIs report the same two facts: whether the device is genuine, and whether the app build is genuine. Neither reports whether a person was present.

## What Each Primitive Does Prove

| Primitive | What a remote verifier learns | Source |
|---|---|---|
| Apple App Attest assertion | The app instance is legitimate, the challenge binds to the request, and a counter increments. Nothing about a person. | https://developer.apple.com/documentation/devicecheck/dcappattestservice/generateassertion(_:clientdatahash:completionhandler:) and https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server |
| Google Play Integrity verdict | The device and the app build are genuine, and the account holds a Play entitlement. Nothing about a person. Google states that a Standard request's token "must" be decrypted on Google's servers. | https://developer.android.com/google/play/integrity/verdicts and https://developer.android.com/google/play/integrity/standard |
| Apple Secure Enclave key with `SecAccessControl` | Nothing. Apple defines `biometryCurrentSet` as a "Constraint to access an item with Touch ID for currently enrolled fingers, or from Face ID with the currently enrolled user", and `biometryAny` as a "Constraint to access an item with Touch ID for any enrolled fingers, or Face ID". Each flag constrains the local system. The signature the key produces is identical whether or not a flag was set, and Apple publishes no certificate carrying the flags, so no evidence of the enforcement leaves the device. | https://developer.apple.com/documentation/security/secaccesscontrolcreateflags |
| Android Keystore key with Key Attestation | The key's creation-time policy: the `KeyDescription` extension encodes `noAuthRequired`, `userAuthType` (`FINGERPRINT` or `PASSWORD`), and `authTimeout`, and a Trusted Execution Environment signs the enclosing chain. This attests the *requirement*, not a specific gesture — the `HardwareAuthToken` that satisfies the requirement is HMAC-verified inside KeyMint and never reaches the caller. Google's verification procedure also includes a revocation check against a Google-hosted status list, so a verifier validates the chain without contacting a server only by skipping that step. | https://source.android.com/docs/security/features/keystore/attestation and https://developer.android.com/privacy-and-security/security-key-attestation |
| WebAuthn / FIDO2 authenticator data | A signed per-ceremony User Verified bit. W3C defines user verification as instigated "through various authorization gesture modalities; for example, through a touch plus pin code, password entry, or biometric recognition", so the bit names no modality, and W3C states it "does not give the Relying Party a concrete identification of the user". | https://www.w3.org/TR/webauthn-3/ |

## The Rule

**Name a mechanism for what its evidence carries, not for the gesture that may have produced the evidence.** A parameter called `biometric_required` whose verifier reads a device-integrity token states a guarantee the token does not carry, and a reader of the spec then believes a fingerprint gated the action. A parameter named for user authentication, whose verifier reads an attested key policy, states what the verifier checks.

**Ask which platforms can carry the claim to a remote reader, and check that more than one can.** Android Key Attestation carries a user-authentication policy; Apple carries none; macOS, Linux, and Windows carry neither App Attest nor Play Integrity, which §9.3 of `.docs/specs/09-security-model.md` records at line 189. A design that needs the claim on every platform has no primitive, and a numbered open question is what a spec writes instead. A spec clause that reads as if the primitive existed is the failure `CLAUDE.md` names under "Never write your extrapolation as the contract".

**Check the verification path against the "protocol requires no operator" tenet, and check every candidate against it.** Google requires its own servers to decrypt a Standard Play Integrity token, and Google's own procedure for an Android Key Attestation chain fetches a Google-hosted revocation list. Apple's App Attest keys are per-bundle-identifier, so a peer running a different app holds no public key to check an assertion against — §9.3 of the security spec states both the Google dependency and the bundle-identifier limit at line 187. A comparison that applies the tenet to one candidate and not another decides nothing.

## What Prompted This Lesson

`DeviceAttestationProvider::assert_request(request_hash) -> Vec<u8>` has shipped since ADR-021, the UniFFI bridge definitions (`crates/scp-ffi/uniffi/src/lib.rs:573`), and its signature reads as a per-action proof. No Rust code calls it, and the trait declares no verification method. The Android adapter implements it by requesting a fresh Play Integrity token, and its own comment says why: "Play Integrity does not have a per-request assertion flow equivalent to App Attest assertions" (`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidDeviceAttestation.kt:127`). A design that took the method name as its contract would have specified a gate no verifier could satisfy.
