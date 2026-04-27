#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# 1. Configuration Setup
# ---------------------------------------------------------------------------
CONFIG_PATH="/opt/indidus-relay-signaling/config.toml"
DATA_DIR="/opt/indidus-relay-signaling/data"

# Ensure data directory exists
mkdir -p "$DATA_DIR/shares"

# Generate a default config.toml if it doesn't exist
if [ ! -f "$CONFIG_PATH" ]; then
    echo "[signaling] Generating default configuration..."
    
    if [ -z "$TURN_SECRET" ]; then
        TURN_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
        [ -n "$TURN_SECRET" ] || (echo "[signaling] ERROR: Failed to generate TURN_SECRET" && exit 1)
        echo "[signaling] !! IMPORTANT !! Auto-generated ephemeral TURN_SECRET: $TURN_SECRET"
    fi
    
    cat > "$CONFIG_PATH" <<EOF
[server]
host = "127.0.0.1"
port = ${RELAY_PORT:-8080}

[database]
path = "$DATA_DIR/signaling.db"

[auth]
registration_difficulty = 16

[turn]
secret = "${TURN_SECRET}"
realm = "indidus"

[relay]
storage_path = "$DATA_DIR/shares"
max_share_size = 10485760
default_ttl = 3600
EOF
fi

# ---------------------------------------------------------------------------
# 2. Caddy Configuration (SSL Proxy)
# ---------------------------------------------------------------------------
CADDY_PATH="/etc/caddy/Caddyfile"

echo "[signaling] Configuring Caddy proxy..."
TARGET_PORT="${RELAY_PORT:-8080}"
if [ -n "$RELAY_DOMAIN" ]; then
    # Full HTTPS mode with automatic Let's Encrypt cert
    cat > "$CADDY_PATH" <<EOF
${RELAY_DOMAIN} {
    reverse_proxy localhost:${TARGET_PORT}
    encode gzip
    log {
        output stderr
        format json
    }
}
EOF
else
    # IP-only mode — Always HTTPS using internal self-signed cert
    echo "[signaling] No RELAY_DOMAIN set. Using internal self-signed SSL."
    cat > "$CADDY_PATH" <<EOF
:443 {
    tls internal
    reverse_proxy localhost:${TARGET_PORT}
    encode gzip
}
EOF
fi

# ---------------------------------------------------------------------------
# 3. Diagnostics & Pre-flight Checks
# ---------------------------------------------------------------------------
echo "[signaling] Pre-flight checks..."
RELAY_BIN="/opt/indidus-relay-signaling/indidus-relay-signaling"

if [ ! -x "$RELAY_BIN" ]; then
    echo "[signaling] ERROR: Binary not found or not executable at $RELAY_BIN"
    ls -l "$RELAY_BIN" || echo "Binary missing entirely."
    exit 1
fi

# Check for shared library issues (common in Alpine)
echo "[signaling] Checking binary dependencies..."
if command -v ldd >/dev/null 2>&1; then
    ldd "$RELAY_BIN" || echo "[signaling] Note: ldd reported issues, binary might be statically linked (this is usually fine)."
else
    echo "[signaling] Note: ldd not found (skipping dependency check)."
fi

# Format Caddyfile
echo "[signaling] Formatting Caddyfile..."
caddy fmt --overwrite "$CADDY_PATH" || echo "[signaling] Warning: caddy fmt failed."

# ---------------------------------------------------------------------------
# 4. Process Orchestration
# ---------------------------------------------------------------------------

# Start the signaling server in the background
echo "[signaling] Starting indidus-relay-signaling (localhost:${TARGET_PORT})..."
"$RELAY_BIN" --config "$CONFIG_PATH" 2>&1 &
RELAY_PID=$!

# Health check: Wait for the binary to start and listen on the port
MAX_RETRIES=10
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if kill -0 $RELAY_PID 2>/dev/null; then
        if netstat -tuln | grep -q ":${TARGET_PORT}"; then
            echo "[signaling] Server is up and listening."
            break
        fi
    else
        echo "[signaling] ERROR: Server process died unexpectedly."
        exit 1
    fi
    echo "[signaling] Waiting for server to start... ($((RETRY_COUNT+1))/$MAX_RETRIES)"
    sleep 1
    RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "[signaling] ERROR: Server timed out starting."
    kill -TERM "$RELAY_PID" 2>/dev/null || true
    exit 1
fi

# Trap signals for graceful shutdown
trap_handler() {
    echo "[signaling] Shutting down services..."
    kill -TERM "$RELAY_PID" 2>/dev/null || true
    exit 0
}
trap trap_handler INT TERM

# Start Caddy in the foreground
echo "[signaling] Starting Caddy production proxy..."
caddy run --config "$CADDY_PATH" --adapter caddyfile
