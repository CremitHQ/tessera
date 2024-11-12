FROM lukemathwalker/cargo-chef:latest-rust-1.80-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --bin nebula-backbone --release --recipe-path recipe.json

COPY . .


RUN cargo build --release --bin nebula-backbone

FROM debian:bookworm-slim as runtime
WORKDIR /app

RUN apt-get update
RUN apt-get install ca-certificates -y
RUN update-ca-certificates
RUN apt install -y build-essential pkg-config libclang-dev \
  && apt-get -y autoremove \
  && apt-get clean autoclean \
  && rm -fr /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

COPY --from=builder /app/target/release/nebula-backbone /usr/local/bin/nebula-backbone
CMD ["nebula-backbone"]
