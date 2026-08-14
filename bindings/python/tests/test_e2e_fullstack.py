"""A+ Full-stack encrypt/decrypt roundtrip tests via real PyO3 bridge.

These tests exercise the COMPLETE protocol stack through the real native
extension: FullStackNetwork -> E2eCryptoProvider (real MLS + sender keys) ->
ContextManager -> CapturingTransport -> decrypt.

Prerequisites:
- The PyO3 bridge must be compiled with `testing` feature.
  Run: `maturin develop --release --features testing`

If the native extension is not available, all tests are skipped gracefully.

Run:
    PYTHONPATH=bindings/python python3.12 -m pytest bindings/python/tests/test_e2e_fullstack.py -v
"""

from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if the native extension or fullstack functions are
# not available.
# ---------------------------------------------------------------------------

try:
    from scp_sdk import _scp_core

    # The fullstack operations were migrated from flat ``py_fullstack_*``
    # module functions to ``SCP`` methods (Phase 4 PR 4 sub-slice E, #1549)
    # and are feature-gated behind ``testing``. Probe a
    # throwaway ``_scp_core.SCP`` instance for the migrated method rather than
    # the module — the free functions no longer exist.
    _probe = _scp_core.SCP({"type": "in_memory"})
    if not hasattr(_probe, "fullstack_create_node"):
        pytest.skip(
            "fullstack methods not available — rebuild with testing feature",
            allow_module_level=True,
        )
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk import SCP

CEILING_JSON = json.dumps(
    {
        "ceiling": [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
            "governance:propose",
            "context:close",
        ],
        "governance": "single_admin",
    }
)


class TestAliceToBobEncryptedRoundtrip:
    """The flagship A+ test: Alice sends, Bob decrypts, plaintext matches."""

    def test_alice_sends_bob_decrypts(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAlicePy")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBobPy")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-alice-bob", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, bob.did, bytes([0x42] * 32))

        plaintext = b"Hello from Alice via Python!"
        ciphertext = scp._native.fullstack_send_message(alice, ctx_id, plaintext)

        # Ciphertext must differ from plaintext.
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

        # Bob decrypts -- THE A+ ASSERTION
        decrypted = scp._native.fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
        assert bytes(decrypted) == plaintext


class TestBobSendsAliceDecrypts:
    """Bob sends a message and Alice decrypts it (bidirectional).

    This proves the §9.16 (sender-key) + §9.17 (content-access-key) crypto and
    protocol compose end-to-end for a bidirectional spawn-from-Welcome joiner
    over the harness's simulated transport: Bob (the joiner) acquires every
    member's access key through the REAL §9.17 pull the creator answers, so his
    live actor can wrap CEKs for Alice on send, and Alice unwraps with her own
    §9.17 key on receive. The PRODUCTION actor-loop key distribution this stands
    in for (running that pull inside the context actor's run loop and
    distributing keys on join) is tracked in #2049 (§9.16 actor-loop pull) and
    #2050 (§9.17 production distribution); it is not exercised here.
    """

    def test_bidirectional_roundtrip(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAliceBidirPy")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBobBidirPy")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-bidir", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        # Bob is a Welcome-joiner: the spawn-from-Welcome entrypoint activates
        # his lifecycle handle (ADR-049 §9(b)), so his actor is live and
        # send-capable. Mirror the sibling A->B test exactly with the send
        # direction reversed. Bob is the sender, so seed Alice's per-member
        # pseudonym into Bob's node for fan-out (§9.10.4).
        scp._native.fullstack_seed_peer_pseudonym(bob, ctx_id, alice.did, bytes([0x42] * 32))

        plaintext = b"Hello from Bob via Python!"
        ciphertext = scp._native.fullstack_send_message(bob, ctx_id, plaintext)

        # Ciphertext must differ from plaintext.
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

        # Alice decrypts Bob's message -- the bidirectional assertion.
        decrypted = scp._native.fullstack_decrypt_message(alice, ctx_id, ciphertext, bob.did)
        assert bytes(decrypted) == plaintext


class TestThreePartyGroup:
    """Alice sends, Bob and Carol both decrypt the same ciphertext."""

    def test_three_party_decrypt(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAlice3Py")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBob3Py")
        carol = scp._native.fullstack_create_node("did:dht:z6MkCarol3Py")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-3party", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        scp._native.fullstack_add_member(alice, ctx_id, carol.did)
        scp._native.fullstack_join_from_welcome(carol, ctx_id)

        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, bob.did, bytes([0x42] * 32))
        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, carol.did, bytes([0x43] * 32))

        plaintext = b"Hello everyone from Python!"
        ciphertext = scp._native.fullstack_send_message(alice, ctx_id, plaintext)

        bob_decrypted = scp._native.fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
        assert bytes(bob_decrypted) == plaintext

        carol_decrypted = scp._native.fullstack_decrypt_message(
            carol, ctx_id, ciphertext, alice.did
        )
        assert bytes(carol_decrypted) == plaintext


class TestMultipleMessagesRoundtrip:
    """Multiple messages all roundtrip correctly in sequence."""

    def test_five_messages(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAliceMultiPy")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBobMultiPy")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-multi", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, bob.did, bytes([0x42] * 32))

        for i in range(5):
            plaintext = f"Message number {i}".encode()
            ciphertext = scp._native.fullstack_send_message(alice, ctx_id, plaintext)
            decrypted = scp._native.fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
            assert bytes(decrypted) == plaintext, f"message {i} roundtrip failed"


class TestRemovedMemberCannotDecrypt:
    """After removal, the removed member cannot decrypt new messages."""

    def test_forward_secrecy_after_removal(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAliceRemPy")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBobRemPy")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-remove", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, bob.did, bytes([0x42] * 32))

        # Bob can decrypt a pre-removal message.
        pre_msg = b"Before removal"
        pre_ct = scp._native.fullstack_send_message(alice, ctx_id, pre_msg)
        pre_dec = scp._native.fullstack_decrypt_message(bob, ctx_id, pre_ct, alice.did)
        assert bytes(pre_dec) == pre_msg

        # Remove Bob. Removal purges his pseudonym from the peer registry
        # (§9.10.4), leaving Alice the lone member.
        scp._native.fullstack_remove_member(alice, ctx_id, bob.did)

        # §9.10.4 forward secrecy: a post-removal app-data send addresses no
        # peer (Alice is now alone), so it is a no-op that produces NO ciphertext
        # — Bob receives no post-removal application data at all, a strictly
        # stronger guarantee than "Bob gets an undecryptable blob". The send
        # helper surfaces the lone-member no-op as "no ciphertext captured".
        post_msg = b"After removal"
        with pytest.raises(RuntimeError, match="no ciphertext captured"):
            scp._native.fullstack_send_message(alice, ctx_id, post_msg)


class TestCiphertextNonDeterministic:
    """Two encryptions of the same plaintext produce different ciphertexts."""

    def test_ind_cpa_property(self, scp: SCP) -> None:
        alice = scp._native.fullstack_create_node("did:dht:z6MkAliceINDPy")
        bob = scp._native.fullstack_create_node("did:dht:z6MkBobINDPy")

        ctx_id = scp._native.fullstack_create_context(alice, "py-ctx-indcpa", CEILING_JSON)

        scp._native.fullstack_add_member(alice, ctx_id, bob.did)
        scp._native.fullstack_join_from_welcome(bob, ctx_id)

        scp._native.fullstack_seed_peer_pseudonym(alice, ctx_id, bob.did, bytes([0x42] * 32))

        plaintext = b"same message twice"

        ct1 = scp._native.fullstack_send_message(alice, ctx_id, plaintext)
        ct2 = scp._native.fullstack_send_message(alice, ctx_id, plaintext)

        # IND-CPA: different ciphertexts for same plaintext.
        assert ct1 != ct2

        # Both decrypt to the same plaintext.
        d1 = scp._native.fullstack_decrypt_message(bob, ctx_id, ct1, alice.did)
        d2 = scp._native.fullstack_decrypt_message(bob, ctx_id, ct2, alice.did)
        assert bytes(d1) == plaintext
        assert bytes(d2) == plaintext
