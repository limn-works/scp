# Build from the repository ROOT, not from this directory:
#
#     docker build -f templates/personal-relay/Dockerfile -t scp-personal-relay .
#
# `scp-personal-relay` declares its own `[workspace]` in `templates/personal-relay/Cargo.toml`,
# so `cargo build -p scp-personal-relay` finds no such package at the root; and its manifest
# names six `crates/*` path dependencies, which a build context rooted at this directory
# cannot reach. Naming the manifest by path from a root context satisfies both.
#
# Keep the Rust version equal to `channel` in `rust-toolchain.toml`, and keep this builder
# stage and the runtime stage on the same Debian release: glibc is backward compatible only,
# so a binary linked against a newer release's glibc cannot exec on an older one.
# `scripts/check-toolchain-pin.sh` enforces both, and its permitted-line set has to change
# with this file.
FROM rust:1.98.0-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --manifest-path templates/personal-relay/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/templates/personal-relay/target/release/scp-personal-relay /usr/local/bin/
EXPOSE 443
VOLUME /data
ENV SCP_RELAY_STORAGE_PATH=/data
HEALTHCHECK CMD ["/usr/local/bin/scp-personal-relay", "--health"]
ENTRYPOINT ["/usr/local/bin/scp-personal-relay"]
