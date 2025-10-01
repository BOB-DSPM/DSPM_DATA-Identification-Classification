FROM rust:latest AS builder

WORKDIR /app

# Copy source code and build directly
COPY . .

# Build the application
RUN cargo build --release

FROM ubuntu:24.04

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system dspm && useradd --system --gid dspm dspm

COPY --from=builder /app/target/release/dspm-collector /usr/local/bin/dspm-collector

COPY --from=builder /app/config/ /app/config/

RUN chown -R dspm:dspm /app && chown dspm:dspm /usr/local/bin/dspm-collector

USER dspm

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/usr/local/bin/dspm-collector"]