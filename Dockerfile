# OpenManuals server image: openmanuals-server, the om CLI, git (the ledger is a
# git repository), Node with doipjs (identity proof checks) and sqlite3 (backups).
#
#   docker build -t openmanuals-server .
#
# State lives in /var/lib/openmanuals (mount a persistent volume there):
#   data/    inbox.db, keywrap.db, avatars.db, snapshots/
#   ledger/  the git ledger (and build.toml unless OM_TRUST points elsewhere)

FROM rust:1.99-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
# The server embeds the logo.
COPY brand/logo.svg brand/logo.svg
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p openmanuals-server -p openmanuals-cli \
 && install -D target/release/openmanuals-server target/release/om -t /out

FROM node:24-trixie-slim AS doip
WORKDIR /opt/doip-verify
COPY tools/doip-verify/package.json tools/doip-verify/package-lock.json ./
RUN npm ci --omit=dev
COPY tools/doip-verify/index.js ./

FROM node:24-trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tini sqlite3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/openmanuals --create-home openmanuals
COPY --from=build /out/ /usr/local/bin/
COPY --from=doip /opt/doip-verify /opt/doip-verify
ENV OM_DATA_DIR=/var/lib/openmanuals/data \
    OM_LEDGER_DIR=/var/lib/openmanuals/ledger \
    OM_DOIP_SCRIPT=/opt/doip-verify/index.js \
    OM_BIND=0.0.0.0:8000 \
    OM_HOME=/var/lib/openmanuals/om
USER 10001
WORKDIR /var/lib/openmanuals
EXPOSE 8000
# tini reaps the scan workers and git processes the server starts.
ENTRYPOINT ["/usr/bin/tini", "--", "openmanuals-server"]
CMD ["serve"]
