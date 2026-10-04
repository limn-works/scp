# Builds the `scp-relay` and `scp-node` binaries into a Debian runtime image.
#
# WHERE THE RUST VERSION COMES FROM. This file names none. `rust-toolchain.toml` — the
# one place this repository names a Rust version — is copied into the builder before any
# cargo command runs. The official `rust` image ships rustup, and rustup reads that file
# for every cargo invocation in the directory holding it, so it downloads and uses the
# pinned compiler, its components, and every target that file lists. The image's own
# preinstalled compiler decides nothing. The ASSERT-PINNED-RUSTC block below makes the
# build prove that, by comparing the compiler this image actually resolved against the
# channel in the copied-in file and failing the build when they differ.
#
# WHY THIS TAG FLOATS WHILE `.mise.toml` PINS EVERY OTHER TOOL EXACTLY. The tag still
# selects things: a Debian package baseline, a rustup version, an image digest that moves
# under it. It no longer selects the compiler that compiles this workspace, which is the
# only property a pinned tag bought and the only one that broke the merge queue. Pinning
# `rust:1.98.0-slim-bookworm` would put a Rust version back into this file and reopen the
# two-declarations defect; pinning a digest would put a second thing to bump beside the
# pin. Neither buys back a property the copied-in file does not already give.
#
# Installing the pin's cross-compilation targets costs bandwidth this image never links
# against, and it buys the property that the container and a developer's shell resolve one
# compiler from one file. The download lands in a layer keyed on that file, so it repeats
# only when the pin moves.
#
# WHY BOTH STAGES NAME bookworm. glibc is backward compatible only, so a binary the
# builder links against a newer release's glibc cannot exec against an older one, and
# the runtime container dies at startup with "version `GLIBC_2.xx' not found". The
# unsuffixed tag hides that: `rust:1.85-slim`, which this file used before the pin,
# was a bookworm image, while `rust:1.98.0-slim` is a trixie one. Move both stages
# together or neither.

# cargo-chef comes from its upstream release at a pinned version, checked against the
# sha256 that release publishes in `sha256.sum`, instead of from `cargo install`. The
# install compiled cargo-chef from source in 46 s whenever the chef stage rebuilt, and it
# took whatever version crates.io served that day. The musl build is static, so it runs
# on bookworm's glibc and on any other. One stage per architecture, because the URL and
# checksum differ per target; BuildKit builds only the stage `TARGETARCH` selects. To move
# the pin, change the version in both URLs and both checksums together.
ARG TARGETARCH
FROM scratch AS cargo-chef-amd64
ADD --checksum=sha256:aca691abfbfbbe00d482e0ed2249eec3091b65e96a0ce92947fb5b254d48b16d \
    https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.78/cargo-chef-x86_64-unknown-linux-musl.tar.xz \
    /cargo-chef.tar.xz
FROM scratch AS cargo-chef-arm64
ADD --checksum=sha256:cd59b90fce5fa84c4189648fec33404ec5491791eebdb812df5e7fca8336408d \
    https://github.com/LukeMathWalker/cargo-chef/releases/download/v0.1.78/cargo-chef-aarch64-unknown-linux-musl.tar.xz \
    /cargo-chef.tar.xz
FROM cargo-chef-${TARGETARCH} AS cargo-chef

# Stage 1: Chef — install the pinned toolchain and cargo-chef
FROM rust:slim-bookworm AS chef
WORKDIR /app
# Build-script dependencies of `scp-relay` and `scp-node` that the slim image omits:
# `aws-lc-sys` runs cmake, `ring` runs perl, and `libsqlite3-sys` compiles SQLCipher,
# whose amalgamation includes <openssl/crypto.h> and links against libcrypto. `xz-utils`
# unpacks the cargo-chef release archive.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl pkg-config libssl-dev xz-utils \
    && rm -rf /var/lib/apt/lists/*
# Before the pin is copied in, so moving the Rust version does not redo this layer.
COPY --from=cargo-chef /cargo-chef.tar.xz /tmp/cargo-chef.tar.xz
RUN tar -xJf /tmp/cargo-chef.tar.xz -C /usr/local/bin --strip-components=1 --wildcards '*/cargo-chef' \
    && rm /tmp/cargo-chef.tar.xz
# Copy the pin before the first cargo command, so rustup installs the pinned compiler
# here and every stage inheriting from `chef` finds it already present. This layer
# rebuilds when the pin changes and at no other time.
COPY rust-toolchain.toml rust-toolchain.toml
# ASSERT-PINNED-RUSTC — every container build of this workspace carries these three lines
# verbatim, and `scripts/check-toolchain-wiring.sh` fails on one that does not. They make
# the image prove which compiler it resolved, so no reading of COPY lines has to.
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }

# Stage 2: Planner — generate recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — cook deps then build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# The cook compiles SQLCipher, and `.cargo/config.toml` sets the build flag it needs
# (lookaside off); without the file here the cook builds it once without the flag and
# the final build compiles it again.
COPY .cargo/config.toml .cargo/config.toml
# Cook only the two binaries' dependencies. Cooking the whole workspace pulls in
# `scp-ffi`, whose `pyo3-build-config` build script fails with "no Python 3.x
# interpreter found" — and this image ships neither Python bindings nor a Python.
RUN cargo chef cook --release --recipe-path recipe.json -p scp-relay -p scp-node
COPY . .
RUN cargo build --release -p scp-relay -p scp-node

# Stage 4: Runtime — minimal Debian with both binaries
#
# Both binaries link `libcrypto.so.3` dynamically, because `libsqlite3-sys` builds
# SQLCipher against OpenSSL. `libssl3` is named explicitly rather than left to arrive as
# a dependency of `ca-certificates`, which is what supplied it before.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/scp-relay /usr/local/bin/scp-relay
COPY --from=builder /app/target/release/scp-node /usr/local/bin/scp-node
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/scp-relay"]
