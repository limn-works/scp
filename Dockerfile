# Stage 1: Chef — install cargo-chef
#
# Keep the version equal to `channel` in `rust-toolchain.toml`, patch component
# included; `scripts/check-toolchain-pin.sh` requires exact equality. A floating
# tag such as `rust:1.98-slim` resolves to the newest 1.98.x, so the day 1.98.1
# ships the container would compile on a compiler the pin does not name.
#
# Name the Debian release too. `rust:1.98.0-slim` and `rust:1.98.0-slim-trixie`
# are the same image (Debian 13, glibc 2.41), while the runtime stage below runs
# `debian:bookworm-slim` (Debian 12, glibc 2.36). glibc is backward compatible
# only, so a binary linked against 2.41 fails to exec against 2.36 — the runtime
# container would die at startup with "version `GLIBC_2.xx' not found". The
# unsuffixed tag hid that: `rust:1.85-slim`, which this file used before the
# pin, was a bookworm image, so bumping the version alone silently changed the
# distribution. Move both stages together or neither.
#
# The builder stage copies `rust-toolchain.toml` before `cargo chef cook`, so the
# dependency build and the final build use one compiler. Without that copy the
# cook step runs on the base image's compiler and `cargo build` runs on the
# pinned one, which discards the layer cache the chef stages exist to build.
FROM rust:1.98.0-slim-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Planner — generate recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — cook deps then build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Give the cook step the pin, so a future tag naming a compiler other than the
# pinned one cannot split the dependency build from the final build. The gate
# rejects that tag today, which makes this a second line of defence rather than
# the thing that keeps the two steps on one compiler.
COPY rust-toolchain.toml rust-toolchain.toml
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p scp-relay -p scp-node

# Stage 4: Runtime — minimal Debian with both binaries
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/scp-relay /usr/local/bin/scp-relay
COPY --from=builder /app/target/release/scp-node /usr/local/bin/scp-node
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/scp-relay"]
