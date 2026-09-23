# syntax=docker/dockerfile:1
# Образ стенда: control-plane, runner и CLI (нужен для keygen) в одном образе,
# бинарь выбирает compose.
# Контекст сборки — корень репозитория (см. stand/compose.yml).
FROM rust:1.90-bookworm AS build

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# См. Dockerfile.ci: иначе rustup докачивает канал 1.90 из rust-toolchain.toml.
ENV RUSTUP_TOOLCHAIN=1.90.0

WORKDIR /src
COPY . .
# Кэш-маунты BuildKit держат реестр и target между передеплоями стенда.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p asmodeus-control-plane -p asmodeus-runner -p asmodeus-cli \
    && install -D -m 755 -t /out \
        target/release/asmodeus-control-plane target/release/asmodeus-runner \
        target/release/asmodeus

FROM debian:bookworm-slim

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1001 --create-home asmodeus \
    && mkdir /data /secrets && chown asmodeus:asmodeus /data /secrets

COPY --from=build /out/ /usr/local/bin/

USER asmodeus
