//! Host a static website on SCP with `scp_node::host_site`.
//!
//! UNTIL A PRODUCTION `PreRotationCustody` BACKEND EXISTS, NO BUILD RUNS THIS
//! EXAMPLE WITHOUT A TEST-HARNESS STAND-IN. `cargo run -p scp-node --example
//! website` compiles, then exits 1 on every run with
//! `IdentityError::NoPreRotationBackend`, whose message begins:
//!
//! ```text
//! Error: NodeBuild("identity error: no production pre-rotation custody backend
//! available; pre-rotation recovery custody is not yet implemented
//! ```
//!
//! A `testing` build is not a way to run it: `testing` mints the identity
//! through `scp_platform::testing::InMemoryPreRotationCustody`, which holds the
//! pre-rotation key only in process memory, so spec §9.7.4.1 recovery from `#0`
//! compromise is unreachable for that identity. `README.md` beside this file
//! states the same limit.
//!
//! `host_site` asks for `IdentitySource::Persisted`, which `Node::start`
//! resolves by loading the stored identity or, when the directory holds none,
//! creating one on its `Generate` path. Every run uses a new, empty directory
//! (below), so every run takes `Generate`. On a build without `testing` that path
//! returns `NoPreRotationBackend` whatever custody or storage is supplied: it
//! takes no `PreRotationCustody` input, the backend spec §9.7.4.1 §3 requires,
//! so it fails closed here instead of minting a nullifier-backed identity.
//!
//! The `PORT` env var overrides the listen port, which defaults to 8080.
//!
//! Each run stores its identity in a new directory under the system temporary
//! directory, never in the `scp-node` binary's default storage directory.
//! `tempfile::TempDir` creates that directory with a new random name, never
//! reuses an existing directory, and removes it when `main` returns. `main`
//! returns after the exit-1 error above, and after a Ctrl-C or SIGTERM once the
//! site is serving. `host_site` installs its signal handlers only when it starts
//! serving, so a Ctrl-C during startup (opening storage, building the node,
//! deploying the site) ends the process through the default signal action and
//! leaves the directory behind, still mode 0700, under a name no later run reuses.
//! On Unix the example sets the directory's mode to 0700 through
//! `tempfile::Builder::permissions`, because `tempfile` otherwise uses the process
//! default mode, and exits with an error if the mode it reads back grants any
//! group or other bit.
//! A run therefore never reloads an identity an earlier run or another local
//! user left behind. A `testing` run mints its identity with that test-harness
//! custody, and the binary reloads whatever identity its storage directory holds
//! without checking how it was created, so writing to the binary's directory
//! would put a test-harness identity behind a shipped `scp-node --self-host`.
//!
//! This is a safe LOCAL demo: it uses `TlsMode::Plaintext` (plain HTTP),
//! `Reach::Local` (no NAT/UPnP probe, loopback-only addressing), and
//! `DhtMode::Disabled` — so NO router port is opened and NOTHING is published to
//! the network. (The listener binds `0.0.0.0`, so it is also reachable on the
//! LAN at the host's local IP, but never beyond it.) For PUBLIC hosting, pass
//! `Reach::NatTraversal` or `Reach::Tunnel { public_url }` to `defaults(...)`, set
//! `tls: TlsMode::SelfSigned` (the default), and opt into `DhtMode::Production`
//! (which publishes the host's address bound to its DID to the DHT — a location
//! disclosure). See the guide: `.docs/guides/self-hosting-a-website-on-scp.md`.

use scp_node::{DhtMode, HostSiteConfig, Reach, TlsMode, host_site};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use 8080 (not the 8443 HostSiteConfig default) to avoid colliding with a real node.
    let port: u16 = std::env::var("PORT").map_or(8080, |raw| {
        raw.parse::<u16>().unwrap_or_else(|_| {
            eprintln!("PORT={raw:?} is not a valid u16 port number; using 8080");
            8080
        })
    });
    // A new, owner-only, randomly named directory per run, removed when
    // `storage` drops at the end of `main`. See the doc comment for why this
    // example never uses the default storage directory the binary shares.
    // `tempfile` creates a directory with the process default mode (0755 under
    // umask 022) unless `permissions` is set, so the mode is set and then checked.
    let mut builder = tempfile::Builder::new();
    builder.prefix("scp-website-example-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let storage = builder.tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(storage.path())?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} has mode {:o}; refusing to store an identity where another local user can read it",
                storage.path().display(),
                mode & 0o777
            )
            .into());
        }
    }
    host_site(HostSiteConfig {
        tls: TlsMode::Plaintext,
        dht: DhtMode::Disabled,
        // `CARGO_MANIFEST_DIR` makes the sample-site path independent of the
        // directory `cargo run` is invoked from.
        site_dir: Some(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/website-site").into()),
        storage_path: Some(storage.path().to_path_buf()),
        port,
        on_ready: Some(Box::new(|ready| {
            let scheme = if ready.plaintext { "http" } else { "https" };
            println!("Site is live — open: {scheme}://localhost:{}/", ready.port);
        })),
        ..HostSiteConfig::defaults(Reach::Local)
    })
    .await?;
    Ok(())
}
