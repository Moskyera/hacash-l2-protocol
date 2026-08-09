# Hacash L2 Channel Chain hub (seed / CSP / global mesh)
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY Cargo.lock* ./
COPY src ./src
COPY static ./static
RUN if [ -f Cargo.lock ]; then cargo build --release; else cargo generate-lockfile && cargo build --release; fi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin hacash \
    && mkdir -p /app /data && chown -R hacash:hacash /app /data
WORKDIR /app
COPY --from=build /src/target/release/hacash-l2-hub /usr/local/bin/hacash-l2-hub
COPY l2-hub.example.ini /app/l2-hub.example.ini
COPY seeds.example.json /app/seeds.example.json
ENV HACASH_L2_BIND=0.0.0.0:9090
ENV HACASH_L2_PUBLIC_URL=""
ENV HACASH_L2_PROVIDER_ID=SeedHub
ENV HACASH_L2_FULLNODE=host.docker.internal:8080
ENV HACASH_L2_ALLOW_PRIVATE_PEERS=false
ENV HACASH_L2_STATE_PATH=/data/hub-state.json
ENV HACASH_L2_ANNOUNCE_ON_START=false
USER hacash
VOLUME ["/data"]
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:9090/health || exit 1
ENTRYPOINT ["hacash-l2-hub"]
