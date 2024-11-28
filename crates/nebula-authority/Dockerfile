FROM lukemathwalker/cargo-chef:latest-rust-1.82-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --package nebula-authority --release --recipe-path recipe.json

COPY . .


RUN cargo build --release --package nebula-authority

FROM debian:bookworm-slim as runtime
WORKDIR /app

RUN apt-get update
RUN apt-get install ca-certificates -y
RUN update-ca-certificates
RUN apt install -y build-essential pkg-config libclang-dev libssl-dev \
    && apt-get -y autoremove \
    && apt-get clean autoclean \
    && rm -fr /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

COPY --from=builder /app/target/release/nebula-authority /usr/local/bin/nebula-authority
CMD ["nebula-authority"]
