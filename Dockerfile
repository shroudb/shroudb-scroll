ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=registry_token \
    mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "shroudb-cratesio"\n\n[source.shroudb-cratesio]\nregistry = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\n\n[registries.shroudb-cratesio]\nindex = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\ncredential-provider = ["cargo:token"]\n\n[registries.shroudb]\nindex = "sparse+https://crates.shroudb.dev/api/v1/crates/"\ncredential-provider = ["cargo:token"]\n' > /root/.cargo/config.toml && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    CARGO_REGISTRIES_SHROUDB_CRATESIO_TOKEN="$(cat /run/secrets/registry_token)" \
    CARGO_REGISTRIES_SHROUDB_TOKEN="$(cat /run/secrets/registry_token)" \
    cargo build --release --target "$RUST_TARGET" -p shroudb-scroll-server -p shroudb-scroll-cli && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-scroll" /out/ && \
    cp "target/$RUST_TARGET/release/shroudb-scroll-cli" /out/

FROM alpine:3.21 AS shroudb-scroll
RUN adduser -D -u 65532 shroudb && \
    apk add --no-cache su-exec && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Scroll" \
      org.opencontainers.image.description="Durable append-only event log with cursored readers and reader groups" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
COPY --from=builder /out/shroudb-scroll /shroudb-scroll
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
VOLUME /data
WORKDIR /data
EXPOSE 7200
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/shroudb-scroll"]

FROM alpine:3.21 AS shroudb-scroll-cli
RUN adduser -D -u 65532 shroudb
LABEL org.opencontainers.image.title="ShrouDB Scroll CLI" \
      org.opencontainers.image.description="CLI tool for the Scroll event log engine" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"
COPY --from=builder /out/shroudb-scroll-cli /shroudb-scroll-cli
USER shroudb
ENTRYPOINT ["/shroudb-scroll-cli"]
