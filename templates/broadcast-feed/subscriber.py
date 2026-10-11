"""SCP broadcast feed subscriber.

Demonstrates the subscriber side of the broadcast pattern: creating an
identity, generating the wrapping key a publisher seals its broadcast key
to, and opening the sealed key the publisher returns (spec section 5.14.2).

Key requests have no network path yet, so this script prints its DID and
wrapping key for the publisher, then reads the sealed key the publisher
printed. The wrapping secret never leaves this process.

Usage:
    pip install -e ../../bindings/python
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database

    python subscriber.py
    # Pass the printed DID and wrapping key to feed.py, then paste the
    # sealed key it prints here.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from scp_sdk import SCP, CustodyType, StorageConfig

BROADCAST_KEY_BYTES = 32


def node_storage(name: str) -> StorageConfig:
    """Return SQLCipher storage at ``$HOME/.scp/<name>``.

    ``SCP_STORAGE_PASSPHRASE`` derives the database key. An unset variable
    raises ``KeyError`` here, before any database opens.
    """
    path = Path.home() / ".scp" / name
    path.mkdir(parents=True, exist_ok=True)
    return {
        "type": "sqlite",
        "path": str(path),
        "passphrase": os.environ["SCP_STORAGE_PASSPHRASE"],
    }


def generate_wrapping_key() -> tuple[bytes, bytes]:
    """Return a DHKEM(P-256) key pair as ``(public_point, secret_scalar)``.

    The public half is the 65-byte uncompressed point a publisher seals to;
    the secret half is the 32-byte big-endian scalar that opens the seal.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_point = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    secret = private_key.private_numbers().private_value.to_bytes(32, "big")
    return public_point, secret


async def run_subscriber() -> None:
    """Run the subscriber lifecycle."""
    async with SCP(storage=node_storage("broadcast-feed-subscriber")) as node:
        # 1. Create the subscriber identity.
        subscriber = await node.identity_create(CustodyType.ENCRYPTED_FILE)

        # 2. Generate the wrapping key the publisher seals its key to.
        wrapping_public, wrapping_secret = generate_wrapping_key()

        print("--- Pass these to the publisher ---")
        print(f"  --subscriber {subscriber.did}")
        print(f"  --wrapping-key {wrapping_public.hex()}")
        print("--- ---")

        # 3. Read the sealed key the publisher printed. An empty line or EOF
        #    stops the script without a key.
        print("\nPaste the sealed key from the publisher, then press Enter:")
        loop = asyncio.get_running_loop()
        sealed = (await loop.run_in_executor(None, sys.stdin.readline)).strip()
        if not sealed:
            raise SystemExit("No sealed key received.")

        # 4. Open the sealed key. A seal made for another wrapping key, or a
        #    tampered one, raises instead of returning a key.
        broadcast_key = await node.broadcast_open_key(sealed, wrapping_secret)
        if len(broadcast_key) != BROADCAST_KEY_BYTES:
            raise RuntimeError(
                f"broadcast key is {len(broadcast_key)} bytes, expected 32"
            )
        print(f"\nOpened the author's {len(broadcast_key)}-byte broadcast key.")

    print("Subscriber stopped.")


def main() -> None:
    """Entry point for the broadcast subscriber."""
    asyncio.run(run_subscriber())


if __name__ == "__main__":
    main()
