FROM rust:1.75 AS builder

WORKDIR /app

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system dspm && adduser --system --group dspm

COPY --from=builder /app/target/release/dspm-collector /usr/local/bin/dspm-collector

COPY --from=builder /app/config/ /app/config/

RUN chown -R dspm:dspm /app && chown dspm:dspm /usr/local/bin/dspm-collector

USER dspm

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/usr/local/bin/dspm-collector"]