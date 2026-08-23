# Stage 1: Chef — install cargo-chef
#
# Keep this tag equal to `channel` in `rust-toolchain.toml`. `COPY . .` carries
# that file into the build, and rustup honours it over the base image's own
# compiler, so a mismatched tag makes every cargo step download a second
# toolchain — and makes `cargo chef cook` compile dependencies with a different
# compiler than `cargo build` uses, which discards the layer cache the chef
# stages exist to build.
FROM rust:1.98-slim AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Planner — generate recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — cook deps then build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
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
