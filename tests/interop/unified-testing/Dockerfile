# Transport test app image for libp2p/unified-testing.
# Build context: the repository root.
#   docker build -f tests/interop/unified-testing/Dockerfile -t minip2p-transport .
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src
# The root manifest supplies the `workspace = true` fields the crates inherit.
COPY Cargo.toml ./
COPY crates crates
COPY transports transports
COPY tests/interop/unified-testing tests/interop/unified-testing
RUN cargo build --release --locked \
      --manifest-path tests/interop/unified-testing/Cargo.toml

FROM debian:bookworm-slim
COPY --from=build /src/tests/interop/unified-testing/target/release/minip2p-unified-testing /usr/local/bin/
ENTRYPOINT ["minip2p-unified-testing"]
