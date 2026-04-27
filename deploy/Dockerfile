# =============================================================================
# Build Stage
# =============================================================================
FROM rust:1.95.0-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev gcc libc-dev

WORKDIR /usr/src/indidus-relay-signaling
COPY . .

# Compile as a static binary for minimal runtime requirements
RUN cargo build --release

# =============================================================================
# Runtime Stage (Production Ready)
# =============================================================================
FROM alpine:latest

# Metadata
LABEL maintainer="ashimksaha" \
      org.opencontainers.image.source="https://github.com/ashim-kr-saha/indidus-password-manager" \
      org.opencontainers.image.description="Indidus Relay & Signaling Server - Unified production image with Caddy SSL"

# Install Caddy and security dependencies
RUN apk add --no-cache caddy ca-certificates nss-tools

# Set up installation directory
WORKDIR /opt/indidus-relay-signaling
RUN mkdir -p data/shares

# Copy binary from builder
COPY --from=builder /usr/src/indidus-relay-signaling/target/release/indidus-relay-signaling .

# Copy orchestration scripts
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Environment defaults
ENV RUST_LOG=info
ENV RELAY_PORT=8080

# Caddy handles 80/443, Relay runs internally on 8080
EXPOSE 80 443

# Use the orchestration entrypoint to manage both Relay + Caddy
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
