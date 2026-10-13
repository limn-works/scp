# scp-relay

Standalone relay server for [SCP](https://github.com/limn/scp) (Shared Context Protocol).

Minimal, untrusted relay that routes encrypted messages between SCP participants. Install via `cargo install scp-relay`.

## Push wake signals

The relay can wake a registered mobile device through APNs or FCM when a message arrives for it (spec §10.7.1). The operator names the platforms in `SCP_RELAY_PUSH_PLATFORMS`, which has no default: `none`, `apns`, `fcm` or `apns,fcm`. An unset or empty value exits 1 (SCP-CAPSEL-8000).

The relay also requires `SCP_RELAY_URL`, its public WebSocket URL, which has no default. The relay derives its reserved push routing ID from that URL (spec §10.7.1), so set it to the URL clients connect to. An unset or empty value exits 1.

A listed platform needs `SCP_RELAY_PUSH_STORE=sqlite` and an absolute `SCP_RELAY_PUSH_STORE_PATH`, and its credentials:

- **APNs:** `SCP_RELAY_APNS_KEY_PATH` (the `.p8` key file), `SCP_RELAY_APNS_KEY_ID`, `SCP_RELAY_APNS_TEAM_ID`, `SCP_RELAY_APNS_TOPIC` (the app's bundle ID) and `SCP_RELAY_APNS_ENVIRONMENT` (`production` or `sandbox`).
- **FCM:** `SCP_RELAY_FCM_SERVICE_ACCOUNT_PATH` (the service-account JSON), and `SCP_RELAY_FCM_PROJECT_ID` when the JSON names no `project_id`.

A missing or invalid variable exits 1 with an error naming it. Credentials load only from files that grant nothing to their group or to others (`chmod 600`), and no log line carries key bytes. One relay serves one Apple team, topic and environment, and one Firebase project.

This build validates a push configuration and then exits 1 on any value but `none`, because the relay's push role is not built yet. The relay operations guide (`docs/guides/relay-operations.md`, section 3) has the full table.

## License

Apache-2.0
