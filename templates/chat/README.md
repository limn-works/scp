# SCP Chat Template

Two-party encrypted chat over the Shared Context Protocol. Provides a Python CLI client that uses real SCP SDK APIs: DID identity creation, encrypted context lifecycle, and async message send/receive.

A browser client is not included: in-browser SCP runs as a remote thin client to a server-side `scp-node` (ADR-055), which is being added separately.

## Architecture

The client performs the following protocol flow:

1. **Create an identity** with in-memory key custody (`Identity.create`).
2. **Create or join an encrypted context** with messaging capabilities (`Context.create`, `Context.join`).
3. **Send messages** from user input (`Context.send`).
4. **Receive messages** via an async iterator and display them (`Context.receive`).
5. **Leave the context** on exit (automatic via context manager / `AsyncDisposable`).

Messages are end-to-end encrypted via MLS. The relay (if connected) is an untrusted transport pipe -- it never sees plaintext.

## Python CLI

### Prerequisites

```sh
pip install -e ../../../bindings/python
```

### Run

```sh
# Terminal 1 -- create a new chat context:
python chat.py create

# Terminal 2 -- join with the context ID printed by terminal 1:
python chat.py join <context-id>

# With a relay:
python chat.py --relay wss://relay.example.com create
```

### Commands

- Type text and press Enter to send.
- `/quit` or `/exit` to leave.
- Ctrl-D (EOF) to leave.

## Connecting two participants

Both participants must be able to reach the same SCP relay to exchange messages. Pass `--relay wss://relay.example.com` to the Python CLI on each side.

Without a relay, the template demonstrates the SDK API patterns locally -- each participant creates its own local context state. In a deployment with a shared relay, messages sent by one participant appear in the other's receive stream.

## Customization

- **Capabilities**: add `OUTLET_CALL_ALL`, `GOVERNANCE_PROPOSE`, etc. to the ceiling for richer contexts.
- **Memory scope**: change `"ephemeral"` to `"full"` to retain chat history after the context closes.
- **Governance**: pass `governance="threshold"` for multi-admin contexts that require voting.
- **Custody**: replace `"in_memory"` with `"platform"` for production key storage.
- **Relay**: wire up `Transport.connect` / `TransportConfig` to connect both participants through the same relay.
