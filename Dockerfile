# syntax=docker/dockerfile:1.6

FROM rust:1.82-bookworm AS build
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY src ./src
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
