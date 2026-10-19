# Build only with scripts/hosted-context.py; the context is an immutable source allowlist.
# Caddy's upstream executable carries cap_net_bind_service. Remove it because this proxy
# listens on 8443 and must run with an empty capability bounding set (otherwise exec is EPERM).
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f AS proxy
RUN setcap -r /usr/bin/caddy
USER 10001:10001

# The toolchain pin is part of every generated Wasm's identity.
FROM rust:1.91.1-slim-trixie@sha256:f75071363e7f4771769d4cf81b1b7b290e607f4d4459e8731f6abdcee9982dc8 AS build
ARG TARGETARCH
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY contracts/golden-transfer-policy ./contracts/golden-transfer-policy
COPY .github/workflows/nightly-live.yml ./.github/workflows/nightly-live.yml
COPY deployment ./deployment
# The official Stellar CLI links libdbus even when only its build/version commands are used.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates pkg-config libssl-dev libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/* \
    && sh deployment/install-tools.sh "$TARGETARCH" \
    && cargo build --locked --release -p ozpb-cli -p ozpb-mcp-server -p ozpb-build-runner \
    && cargo vendor --locked --manifest-path contracts/golden-transfer-policy/Cargo.toml /opt/ozpb/vendor >/dev/null

FROM rust:1.91.1-slim-trixie@sha256:f75071363e7f4771769d4cf81b1b7b290e607f4d4459e8731f6abdcee9982dc8 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 libssl3t64 libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ozpb && useradd --uid 10001 --gid 10001 --home-dir /tmp/ozpb --no-create-home ozpb \
    && mkdir -p /opt/ozpb /var/cache/ozpb /tmp/ozpb /run/ozpb \
    && chown 10001:10001 /var/cache/ozpb /tmp/ozpb
COPY --from=build /usr/local/rustup /usr/local/rustup
COPY --from=build /usr/local/bin/stellar /usr/local/bin/stellar
COPY --from=build /src/target/release/ozpb /src/target/release/ozpb-mcp-server /src/target/release/ozpb-build-worker /usr/local/bin/
COPY --from=build /opt/ozpb/vendor /opt/ozpb/vendor
COPY deployment/entrypoint.sh deployment/verify-offline.sh /opt/ozpb/
COPY deployment/cargo-config.toml /opt/ozpb/cargo-config.toml
COPY docs/examples/subscription-spec.json /opt/ozpb/subscription-spec.json
COPY LICENSE-APACHE LICENSE-MIT /opt/ozpb/licenses/
RUN chmod 0555 /opt/ozpb/entrypoint.sh /opt/ozpb/verify-offline.sh \
    && chmod -R a+rX /usr/local/rustup /opt/ozpb
ENV CARGO_HOME=/var/cache/ozpb/cargo RUSTUP_HOME=/usr/local/rustup \
    CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 TMPDIR=/tmp/ozpb \
    OZPB_BUILD_CACHE_DIR=/var/cache/ozpb/target OZPB_BUILD_JOBS=1 OZPB_BUILD_TIMEOUT_SECS=600
WORKDIR /opt/ozpb
USER 10001:10001
ENTRYPOINT ["/opt/ozpb/entrypoint.sh"]
CMD ["serve"]
