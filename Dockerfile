# ==============================================================================
# STAGE 1: Builder
# ==============================================================================
FROM rust:1.97-slim-bookworm AS builder

WORKDIR /usr/src/arkion-identity-proxy

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy dependency definitions and source code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config

# Build optimized release binary
RUN cargo build --release --bin arkion-identity-proxy

# ==============================================================================
# STAGE 2: Minimal Production Runtime
# ==============================================================================
FROM debian:bookworm-slim AS runner

# Create non-root system user and group
RUN groupadd -g 10001 proxyuser && \
    useradd -u 10001 -g proxyuser -s /bin/false -m proxyuser && \
    apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /usr/src/arkion-identity-proxy/target/release/arkion-identity-proxy /app/arkion-identity-proxy

# Set permissions
RUN chown -R proxyuser:proxyuser /app

# Switch to non-root user
USER proxyuser:proxyuser

# Environment default configuration
ENV ARKION_PROXY_HOST=0.0.0.0 \
    ARKION_PROXY_PORT=8443 \
    ARKION_UPSTREAM_URL=http://backend:8080 \
    ARKION_SERVER_CERT_PATH=/app/certs/server.crt \
    ARKION_SERVER_KEY_PATH=/app/certs/server.key \
    ARKION_CLIENT_CA_CERT_PATH=/app/certs/ca.crt \
    ARKION_POLICY_PATH=/app/config/policy.yaml

# Expose HTTPS listener port
EXPOSE 8443

# Run the proxy server binary
ENTRYPOINT ["/app/arkion-identity-proxy"]
