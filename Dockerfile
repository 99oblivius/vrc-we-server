# syntax=docker/dockerfile:1.7

FROM rust:1.99.0-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock EULA.md ./
COPY crates ./crates
ARG APP_VERSION
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p server && \
    cp /src/target/release/vrc-we-server /tmp/vrc-we-server
# The certificate cache, owned by nonroot: a fresh volume mounted there
# takes this ownership, so the relay can write to it.
RUN mkdir -p /out/var/lib/vrc-we/acme

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="vrc-we-server" \
      org.opencontainers.image.description="The vrc-WiredExpressions relay" \
      org.opencontainers.image.source="https://github.com/99oblivius/vrc-we-server" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Shield-1.0.0-with-Additional-Permission"
COPY --from=build /tmp/vrc-we-server /usr/local/bin/vrc-we-server
COPY --from=build --chown=65532:65532 /out/var/lib/vrc-we /var/lib/vrc-we
COPY LICENSE EULA.md THIRD-PARTY-NOTICES.txt /usr/share/doc/vrc-we-server/
USER nonroot
ENV VRC_WE_BIND=0.0.0.0:8443 \
    VRC_WE_TLS_CACHE=/var/lib/vrc-we/acme
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --start-interval=5s --retries=3 \
    CMD ["/usr/local/bin/vrc-we-server", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/vrc-we-server"]
