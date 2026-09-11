# An inherited premise is not a hardware constraint

## The criterion

Trace every load-bearing constraint to its author before you write it down as a constraint. A premise that arrived as an earlier default, that no artifact argues and no human chose, is a **decision still to be made** — not a wall. Where two facts meet and one of them is ours, the constraint is ours.

The test: name the author and the date of the fact you are calling fixed. Where you can name them for one side of the collision and not the other, the side you cannot attribute is the side to reopen.

## The instance

ADR-025, the Apple platform adapter, wrote this into its Context as "the key constraint shaping this ADR":

> **Apple's Secure Enclave only supports P-256 (NIST P-256 / secp256r1) key operations**. SCP uses Ed25519 for signing and X25519 for key agreement — neither is natively supported in the Secure Enclave. This is not a limitation the protocol can design around; it is a hardware constraint.

Two facts collide in that paragraph. Apple fixed the first: the enclave performs P-256 operations. SCP chose the second: the signature algorithm. The paragraph attributes the collision to the hardware and concludes that the protocol cannot design around it, which inverts cause and effect, because SCP chose the half it was free to choose.

**Nobody chose Ed25519.** It arrived in February 2026 as the joint default of three things: did:dht, whose identifier was an Ed25519 key; the MLS baseline ciphersuite; and the one-algorithm rule in `09-security-model.md` §9.5, which SCP itself wrote. No ADR, no planning session, and no issue argued it against an alternative.

**The research that would have caught it was requested and never done.** Issue #392 asked for Secure Enclave key custody. An agent closed it on the curve mismatch. Alec reopened it, writing that the "design space was not explored… Needs full research and a proper design decision". The same analysis was reposted forty minutes later, the issue was rescoped to biometric gating, and closed. ADR-025 then wrote the outcome up as a permanent hardware constraint, and ADR-027, the Android platform adapter, built a comparative claim on top of it — that hardware-backed Ed25519 at API 33 was "a direct win over Apple". Both adapters carried the inverted premise for six months.

The premise fell on 2026-09-10, when Alec ruled that every SCP key is an ECDSA key on P-256. None of the three inherited reasons survived: ADR-063, the inception-derived key-event-log identity substrate, retired the identity method; an MLS leaf key is ephemeral, so the MLS baseline never bound an identity key; and the one-algorithm rule was SCP's own. Under the ruling both platform adapters hold every SCP signing key in hardware, and the "direct win over Apple" paragraph is withdrawn.

## The fix

1. **Write the attribution beside the constraint.** A sentence calling something fixed names who fixed it. The quoted paragraph attributes Apple's curve and leaves SCP's own choice unattributed, and that missing attribution is the signal.
2. **Never write "not a limitation X can design around" about a collision X is half of.** State each side, name its author, and say which side is open. Where both sides turn out to be someone else's, the sentence is safe; where one is yours, you have written a decision as a wall.
3. **A reopened issue that closes with no research done is a live defect, not a closed one.** Issue #392 was reopened by Alec for research and closed after a rescope, so the record showed a closed issue and an unanswered question. A closure that does not answer the question the reopening asked leaves the question open.
4. **When an inherited premise falls, sweep the artifacts that built arguments on it.** ADR-027's comparative claim was not about the curve on its face; it was a consequence of the curve, and a search for the curve's name alone would have found it while a search for its arguments would not. Correcting the premise means correcting every conclusion drawn from it, and a dated amendment on each artifact records which is which.
