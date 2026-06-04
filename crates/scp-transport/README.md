# scp-transport

Transport abstraction layer for [SCP](https://github.com/limn/scp) (Shared Context Protocol).

Native relay client (`WebSocket`), blob storage adapters (`SQLite`, `redb`, `Postgres`, `S3`), and optional protocol adapters (`QUIC`, `HTTP/3`, `UDP`, `CoAP`, `Nostr`, `WebRTC`, `WebTransport`).

## Subscription maps

`TransportSubscriptionMap<V>` (in `subscription.rs`) is the 1:1 routing-id → adapter-state map shared by client-side transport adapters (QUIC, native relay client, WebTransport). It is **not** the same shape as `relay::SubscriptionRegistry`, which is the server-side 1:N fan-out registry. Adapters consume `TransportSubscriptionMap<V>` for capacity-bounded, duplicate-detecting subscription state with reconnect snapshot helpers; the registry is for the relay's per-routing-id subscriber set.

## License

Apache-2.0
