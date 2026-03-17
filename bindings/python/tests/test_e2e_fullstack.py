"""A+ Full-stack encrypt/decrypt roundtrip tests via real PyO3 bridge.

These tests exercise the COMPLETE protocol stack through the real native
extension: FullStackNetwork -> E2eCryptoProvider (real MLS + sender keys) ->
ContextManager -> CapturingTransport -> decrypt.

Prerequisites:
- The PyO3 bridge must be compiled with `allow_in_memory_custody` feature.
  Run: `maturin develop --release --features allow_in_memory_custody`

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

    # Verify that fullstack functions are available (feature-gated).
    if not hasattr(_scp_core, "py_fullstack_create_node"):
        pytest.skip(
            "fullstack functions not available — rebuild with allow_in_memory_custody feature",
            allow_module_level=True,
        )
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )


CEILING_JSON = json.dumps(
    {
        "ceiling": [
            "messages:read",
            "messages:write",
            "role:assign",
            "member:invite",
            "member:remove",
            "context:close",
        ],
        "governance": "single_admin",
    }
)


class TestAliceToBobEncryptedRoundtrip:
    """The flagship A+ test: Alice sends, Bob decrypts, plaintext matches."""

    def test_alice_sends_bob_decrypts(self) -> None:
        alice = _scp_core.py_fullstack_create_node("did:dht:z6MkAlicePy")
        bob = _scp_core.py_fullstack_create_node("did:dht:z6MkBobPy")

        ctx_id = _scp_core.py_fullstack_create_context(alice, "py-ctx-alice-bob", CEILING_JSON)

        _scp_core.py_fullstack_add_member(alice, ctx_id, bob.did)
        _scp_core.py_fullstack_join_from_welcome(bob, ctx_id)

        plaintext = b"Hello from Alice via Python!"
        ciphertext = _scp_core.py_fullstack_send_message(alice, ctx_id, plaintext)

        # Ciphertext must differ from plaintext.
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

        # Bob decrypts -- THE A+ ASSERTION
        decrypted = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
        assert bytes(decrypted) == plaintext


class TestThreePartyGroup:
    """Alice sends, Bob and Carol both decrypt the same ciphertext."""

    def test_three_party_decrypt(self) -> None:
        alice = _scp_core.py_fullstack_create_node("did:dht:z6MkAlice3Py")
        bob = _scp_core.py_fullstack_create_node("did:dht:z6MkBob3Py")
        carol = _scp_core.py_fullstack_create_node("did:dht:z6MkCarol3Py")

        ctx_id = _scp_core.py_fullstack_create_context(alice, "py-ctx-3party", CEILING_JSON)

        _scp_core.py_fullstack_add_member(alice, ctx_id, bob.did)
        _scp_core.py_fullstack_join_from_welcome(bob, ctx_id)

        _scp_core.py_fullstack_add_member(alice, ctx_id, carol.did)
        _scp_core.py_fullstack_join_from_welcome(carol, ctx_id)

        plaintext = b"Hello everyone from Python!"
        ciphertext = _scp_core.py_fullstack_send_message(alice, ctx_id, plaintext)

        bob_decrypted = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
        assert bytes(bob_decrypted) == plaintext

        carol_decrypted = _scp_core.py_fullstack_decrypt_message(
            carol, ctx_id, ciphertext, alice.did
        )
        assert bytes(carol_decrypted) == plaintext


class TestMultipleMessagesRoundtrip:
    """Multiple messages all roundtrip correctly in sequence."""

    def test_five_messages(self) -> None:
        alice = _scp_core.py_fullstack_create_node("did:dht:z6MkAliceMultiPy")
        bob = _scp_core.py_fullstack_create_node("did:dht:z6MkBobMultiPy")

        ctx_id = _scp_core.py_fullstack_create_context(alice, "py-ctx-multi", CEILING_JSON)

        _scp_core.py_fullstack_add_member(alice, ctx_id, bob.did)
        _scp_core.py_fullstack_join_from_welcome(bob, ctx_id)

        for i in range(5):
            plaintext = f"Message number {i}".encode()
            ciphertext = _scp_core.py_fullstack_send_message(alice, ctx_id, plaintext)
            decrypted = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, ciphertext, alice.did)
            assert bytes(decrypted) == plaintext, f"message {i} roundtrip failed"


class TestRemovedMemberCannotDecrypt:
    """After removal, the removed member cannot decrypt new messages."""

    def test_forward_secrecy_after_removal(self) -> None:
        alice = _scp_core.py_fullstack_create_node("did:dht:z6MkAliceRemPy")
        bob = _scp_core.py_fullstack_create_node("did:dht:z6MkBobRemPy")

        ctx_id = _scp_core.py_fullstack_create_context(alice, "py-ctx-remove", CEILING_JSON)

        _scp_core.py_fullstack_add_member(alice, ctx_id, bob.did)
        _scp_core.py_fullstack_join_from_welcome(bob, ctx_id)

        # Bob can decrypt a pre-removal message.
        pre_msg = b"Before removal"
        pre_ct = _scp_core.py_fullstack_send_message(alice, ctx_id, pre_msg)
        pre_dec = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, pre_ct, alice.did)
        assert bytes(pre_dec) == pre_msg

        # Remove Bob.
        _scp_core.py_fullstack_remove_member(alice, ctx_id, bob.did)

        # Alice sends after removal.
        post_msg = b"After removal"
        post_ct = _scp_core.py_fullstack_send_message(alice, ctx_id, post_msg)

        # Bob MUST NOT be able to decrypt (MLS forward secrecy).
        with pytest.raises(RuntimeError):
            _scp_core.py_fullstack_decrypt_message(bob, ctx_id, post_ct, alice.did)


class TestCiphertextNonDeterministic:
    """Two encryptions of the same plaintext produce different ciphertexts."""

    def test_ind_cpa_property(self) -> None:
        alice = _scp_core.py_fullstack_create_node("did:dht:z6MkAliceINDPy")
        bob = _scp_core.py_fullstack_create_node("did:dht:z6MkBobINDPy")

        ctx_id = _scp_core.py_fullstack_create_context(alice, "py-ctx-indcpa", CEILING_JSON)

        _scp_core.py_fullstack_add_member(alice, ctx_id, bob.did)
        _scp_core.py_fullstack_join_from_welcome(bob, ctx_id)

        plaintext = b"same message twice"

        ct1 = _scp_core.py_fullstack_send_message(alice, ctx_id, plaintext)
        ct2 = _scp_core.py_fullstack_send_message(alice, ctx_id, plaintext)

        # IND-CPA: different ciphertexts for same plaintext.
        assert ct1 != ct2

        # Both decrypt to the same plaintext.
        d1 = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, ct1, alice.did)
        d2 = _scp_core.py_fullstack_decrypt_message(bob, ctx_id, ct2, alice.did)
        assert bytes(d1) == plaintext
        assert bytes(d2) == plaintext
