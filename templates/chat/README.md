# SCP Chat Template

Two-party encrypted chat over the Shared Context Protocol. Provides a Python CLI client that uses real SCP SDK APIs: DID identity creation, encrypted context creation, the invite-and-join handshake, and async message send/receive over a relay.

A browser chat client is not included yet. In-browser SCP is a real in-tab participant — the full MLS protocol runs in the tab with keys on-device (ADR-057, which amends ADR-055's earlier remote-thin-client model), not a remote thin client to a server-side `scp-node`. A functional two-party browser chat template (`templates/chat/typescript/`) is forthcoming under #2187, once relay-mediated invitation-join is available in the wasm tier. In the meantime, `scaffolds/typescript-web/` demonstrates the single-tab in-browser client over `@limn-works/scp-ts-wasm` today.

## Architecture

The client performs the following protocol flow:

1. **Create an identity** whose keys live in `$HOME/.scp/keys.bin` (`identity_create(CustodyType.FILE)`), and attach the relay transport (`configure_relay_transport`, `transport_connect`).
2. **Create** an encrypted context (`context_create`), or **reserve** a single-use KeyPackage to be invited with (`reserve_key_package`).
3. **Invite and join**: the creator seals an invitation to the joiner's KeyPackage (`invite_member`), and the joiner opens it (`context_join_from_welcome`).
4. **Send messages** from user input (`context_send`), retrying while the peer's routing announcement has not yet arrived (`SCP-CTX-2095`).
5. **Receive messages** via an async iterator and display them (`context_receive`).
6. **Leave the context** on exit (`context_leave`).

Messages are end-to-end encrypted via MLS. The relay is an untrusted transport pipe -- it never sees plaintext.

## What runs today

The Python SDK does not yet subscribe a context to the relay, so a Python node never receives what its peer sends, including the routing announcement a send waits for (#2856). Until that lands, sends keep failing with `SCP-CTX-2095` and the receive stream stays empty. The template is written against the calls that fix will make work.

## Python CLI

### Prerequisites

Install the SCP Python SDK from source. The build needs a Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus make on Linux) for the OpenSSL the build compiles; `bindings/python/README.md` §Requirements has the details. From the repository root:

```sh
cd templates/chat/python
pip install -e ../../../bindings/python
```

Each side keeps its keys in `$HOME/.scp/keys.bin`, so run the two sides on different machines or user accounts. Set these on each side:

```sh
export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
```

`CustodyType.IN_MEMORY` works only in a build compiled with the `testing` feature; a shipped build rejects it with `SCP-IDENT-1008`.

Run the commands below from `templates/chat/python`.

### Run

```sh
# Side 1 -- create a new chat context:
python chat.py --relay wss://relay.example.com create

# Side 2 -- join it:
python chat.py --relay wss://relay.example.com join
```

The invitation crosses by copy and paste:

1. The joiner prints a request line holding its DID and KeyPackage. Paste it into the creator.
2. The creator prints an invitation line. Paste it into the joiner.
3. Both sides start chatting.

### Commands

- Type text and press Enter to send.
- `/quit` or `/exit` to leave.
- Ctrl-D (EOF) to leave.

## Customization

- **Capabilities**: add `OUTLET_QUERY_ALL`, `GOVERNANCE_VOTE`, etc. to the ceiling for richer contexts.
- **Memory scope**: change `MemoryScope.EPHEMERAL` to `MemoryScope.FULL` to retain chat history after the context closes.
- **Custody**: pass a `KeyCustodyProvider` to `identity_create_with_custody` to keep keys in your own key store instead of `keys.bin`.
- **Invitation delivery**: the creator passes the relay URL to `invite_member`; when the returned outcome's `delivered` is true, the runtime has already published the sealed invitation to the joiner's routing ID.
