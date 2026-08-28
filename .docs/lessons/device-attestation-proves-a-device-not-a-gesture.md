# Device Attestation Proves a Device, Not a Gesture

**Source:** the primary-source check that ADR-063 (context-declared user-authentication gate) rests on, run 2026-08-28 against Apple's DeviceCheck documentation, Google's Play Integrity documentation, the AOSP key-attestation schema, and W3C Web Authentication Level 3.
**Applies to:** any design that would gate a protocol action on a biometric, a passcode entry, or any other user-presence check, and that reaches for a platform attestation to carry the proof.

## The Claim That Is Wrong

"An App Attest assertion or a Play Integrity token proves that a person authenticated before this action." Neither vendor documents anything of the kind, and the shape of the mistake is easy to reach because both APIs sit next to biometric APIs on the same device.

Apple describes `DCAppAttestService.generateAssertion` as producing "a block of data that demonstrates the legitimacy of an instance of your app running on a device", and the decoded assertion Apple publishes carries a signature plus an authenticator-data block holding a relying-party identifier and a counter. Google's Play Integrity payload carries `requestDetails`, `accountDetails`, `appIntegrity`, `deviceIntegrity`, and `environmentDetails`, and its strongest device verdict, `MEETS_DEVICE_INTEGRITY`, reads "The app is running on a genuine and certified Android device." Neither payload carries a biometric field, a user-presence field, or a user-verified bit.

Both APIs answer one question: is this a genuine device running a genuine copy of this app. They never answer whether a human was standing in front of it.

## What Each Primitive Does Prove

| Primitive | What a remote verifier learns |
|---|---|
| Apple App Attest assertion | The app instance is legitimate, the challenge is bound, and a counter is monotonic. Nothing about a person. |
| Google Play Integrity verdict | The device and the app build are genuine, and the account holds a Play entitlement. Nothing about a person. Verifying a Standard request means decrypting the token on Google's servers. |
| Apple Secure Enclave key with `SecAccessControl` | Nothing. Apple's flags instruct the local system "to make the key available only when the system can authenticate the user with Touch ID or Face ID (or a fallback passcode)". The signature the key produces is bit-identical whether or not a flag was set, and Apple publishes no certificate carrying the flags. The enforcement is real and local; the evidence does not leave the device. |
| Android Keystore key with Key Attestation | The key's creation-time policy: the `KeyDescription` extension encodes `noAuthRequired`, `userAuthType` (`FINGERPRINT` or `PASSWORD`), and `authTimeout`, and the Trusted Execution Environment signs the enclosing chain, which a reader validates offline. This attests the *requirement*, not a specific gesture — the `HardwareAuthToken` that satisfies the requirement is HMAC-verified inside KeyMint and never reaches the caller. |
| WebAuthn / FIDO2 authenticator data | A signed per-ceremony user-verified bit. W3C defines user verification as instigated "through a touch plus pin code, password entry, or biometric recognition", so the bit does not distinguish a biometric from a PIN, and W3C states it "does not give the Relying Party a concrete identification of the user". |

## The Rule

**Name a mechanism for what its evidence carries, not for the gesture you hope produced the evidence.** A parameter called `biometric_required` whose verifier reads a device-integrity token states a guarantee the token does not carry, and a reader of the spec then believes a fingerprint gated the action. A parameter named for user authentication, whose verifier reads an attested key policy, states what the verifier can actually check.

**Ask which platform can carry the claim to a remote reader, and check that the answer is not "one of them".** Android Key Attestation carries a user-authentication policy offline; Apple carries none; macOS, Linux, and Windows carry neither App Attest nor Play Integrity, which §9.3 of `.docs/specs/09-security-model.md` records at line 189. A design that needs the claim on every platform has no primitive, and the honest response is a numbered open question rather than a spec clause that reads as if the primitive existed.

**Check the verification path against the "protocol requires no operator" tenet before designing around a vendor attestation.** Google requires its own servers to decrypt a Standard Play Integrity token. Apple's App Attest keys are per-bundle-identifier, so a peer running a different app holds no public key to check an assertion against — §9.3 of the security spec states both constraints at line 187.

## What This Cost To Learn

`DeviceAttestationProvider::assert_request(request_hash) -> Vec<u8>` has shipped since ADR-021 (`crates/scp-ffi/uniffi/src/lib.rs:573`) and reads, from its signature, like a per-action proof. No Rust code calls it and the trait declares no verifier. The Android adapter implements it by requesting a fresh Play Integrity token, and its own comment says why: "Play Integrity does not have a per-request assertion flow equivalent to App Attest assertions" (`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/AndroidDeviceAttestation.kt:117`). A design that took the method name as its contract would have specified a gate that no verifier could ever close.
