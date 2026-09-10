# syntax=docker/dockerfile:1.6

FROM rust:1.89-bookworm AS build
WORKDIR /workspace
# BoringSSL (pulled in by wreq) is built from source and needs cmake plus a
# libclang for bindgen.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang libclang-dev perl \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY data ./data
RUN cargo build --release --bin rust_click

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /workspace/target/release/rust_click /app/rust_click

ENV HOST=0.0.0.0
ENV PORT=18001
EXPOSE 18001

ENTRYPOINT ["/app/rust_click"]
