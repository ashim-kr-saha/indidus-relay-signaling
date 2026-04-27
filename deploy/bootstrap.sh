#!/usr/bin/env bash
# =============================================================================
# Indidus Relay & Signaling Bootstrap Script
# Targets: Ubuntu 22.04 LTS (GCP e2-micro, Always Free tier)
#
# Usage:
#   RELAY_DOMAIN=signaling.example.com \
#   bash <(curl -fsSL https://raw.githubusercontent.com/ashim-kr-saha/indidus-relay-signaling/main/deploy/bootstrap.sh)
#
# All variables have sane defaults; RELAY_DOMAIN is the only required one when
# you want automatic HTTPS via Caddy.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment variables or CLI flags)
# ---------------------------------------------------------------------------
RELAY_DOMAIN="${RELAY_DOMAIN:-}"
TURN_SECRET="${TURN_SECRET:-}" # Will auto-generate if empty later

# Support CLI flags for better sudo compatibility
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --domain) RELAY_DOMAIN="$2"; shift ;;
        --turn-secret) TURN_SECRET="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

TURN_SECRET="${TURN_SECRET:-$(openssl rand -hex 32)}"
RELAY_PORT="${RELAY_PORT:-8080}"
INSTALL_DIR="/opt/indidus-relay-signaling"
SERVICE_USER="indidus-signaling"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  BINARY_ARCH="x86_64-unknown-linux-musl" ;;
  aarch64) BINARY_ARCH="aarch64-unknown-linux-musl" ;;
  *)        err "Unsupported architecture: $ARCH. This script only supports x86_64 and aarch64." ;;
esac

# Release binary URL (Update this when releases are set up)
BINARY_URL="https://github.com/ashim-kr-saha/indidus-relay-signaling/releases/download/nightly/indidus-relay-signaling-${BINARY_ARCH}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;32m[signaling]\033[0m $*"; }
warn() { echo -e "\033[1;33m[signaling]\033[0m $*"; }
err()  { echo -e "\033[1;31m[signaling]\033[0m $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || err "This script must be run as root. Try: sudo bash ..."
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require_root

log "Detected architecture: $ARCH → $BINARY_ARCH"

# Ensure we have openssl for secret generation
if ! command -v openssl &>/dev/null; then
  log "Installing openssl..."
  apt-get update -qq && apt-get install -y -qq openssl
fi

# Check for port conflicts (80, 443)
if [[ -n "$RELAY_DOMAIN" ]]; then
  if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null || lsof -Pi :443 -sTCP:LISTEN -t >/dev/null; then
    err "Port 80 or 443 is already in use. Please stop any existing web servers (like Nginx or Apache) before running this script."
  fi
fi

# ---------------------------------------------------------------------------
# 1. Install Caddy (automatic HTTPS, reverse-proxy)
# ---------------------------------------------------------------------------
if ! command -v caddy &>/dev/null; then
  log "Installing Caddy..."
  apt-get update -qq
  apt-get install -y -qq apt-transport-https curl gnupg
  
  apt-get install -y -qq debian-keyring debian-archive-keyring || warn "debian-keyring not found, skipping..."

  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy
  log "Caddy installed."
else
  log "Caddy already installed, skipping."
fi

# ---------------------------------------------------------------------------
# 2. Create service user and install directory
# ---------------------------------------------------------------------------
if ! id "$SERVICE_USER" &>/dev/null; then
  log "Creating system user: $SERVICE_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR/data/shares"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# 3. Download indidus-relay-signaling binary
# ---------------------------------------------------------------------------
log "Downloading indidus-relay-signaling binary for $BINARY_ARCH..."
if ! curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/indidus-relay-signaling"; then
    err "Failed to download binary from $BINARY_URL. Please check your internet connection or repository permissions."
fi
chmod +x "$INSTALL_DIR/indidus-relay-signaling"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/indidus-relay-signaling"
log "Binary installed at $INSTALL_DIR/indidus-relay-signaling"

# ---------------------------------------------------------------------------
# 4. Write config.toml configuration
# ---------------------------------------------------------------------------
log "Writing configuration..."
cat > "$INSTALL_DIR/config.toml" <<EOF
[server]
host = "127.0.0.1"
port = ${RELAY_PORT}

[database]
path = "${INSTALL_DIR}/data/signaling.db"

[auth]
registration_difficulty = 16

[turn]
secret = "${TURN_SECRET}"
realm = "indidus"

[relay]
storage_path = "${INSTALL_DIR}/data/shares"
max_share_size = 10485760
default_ttl = 3600
EOF
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/config.toml"
chmod 640 "$INSTALL_DIR/config.toml"

# ---------------------------------------------------------------------------
# 5. Configure Caddy (HTTPS reverse proxy)
# ---------------------------------------------------------------------------
log "Configuring Caddy..."
if [[ -n "$RELAY_DOMAIN" ]]; then
  # Full HTTPS mode with automatic Let's Encrypt cert
  cat > /etc/caddy/Caddyfile <<EOF
${RELAY_DOMAIN} {
    reverse_proxy 127.0.0.1:${RELAY_PORT}
    encode gzip
    log {
        output stderr
        format json
    }
}
EOF
  RELAY_URL="https://${RELAY_DOMAIN}"
else
  # IP-only mode — Always HTTPS using internal self-signed cert
  warn "No RELAY_DOMAIN set. Running in HTTPS mode with internal self-signed certificate."
  EXTERNAL_IP="$(curl -s -4 https://ifconfig.me || echo 'YOUR_IP')"
  cat > /etc/caddy/Caddyfile <<EOF
:443 {
    tls internal
    reverse_proxy 127.0.0.1:${RELAY_PORT}
    encode gzip
}
EOF
  RELAY_URL="https://${EXTERNAL_IP}"
fi

# ---------------------------------------------------------------------------
# 6. Create systemd service
# ---------------------------------------------------------------------------
log "Creating systemd service..."
cat > /etc/systemd/system/indidus-signaling.service <<EOF
[Unit]
Description=Indidus Relay & Signaling Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/indidus-relay-signaling --config ${INSTALL_DIR}/config.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=indidus-signaling

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/data
ProtectHome=yes

# Log management (prevent disk exhaustion)
LogRetentionMax=50M
LogRetentionAgeSec=7d

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# 7. Open Firewall Ports (OS level)
# ---------------------------------------------------------------------------
log "Opening firewall ports (80, 443)..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
  log "Configuring UFW..."
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw reload
fi

if command -v iptables &>/dev/null; then
  log "Ensuring iptables rules..."
  iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT || true
  iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT || true
  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save || true
  elif [[ -d "/etc/iptables" ]]; then
    iptables-save > /etc/iptables/rules.v4 || true
  fi
fi

# ---------------------------------------------------------------------------
# 8. Enable and start services
# ---------------------------------------------------------------------------
log "Starting services..."
systemctl daemon-reload
systemctl enable --now indidus-signaling
systemctl enable --now caddy
systemctl restart caddy

# Wait for service to come up
sleep 2
if systemctl is-active --quiet indidus-signaling; then
  log "indidus-signaling service is active."
else
  warn "indidus-signaling failed to start. Check logs: journalctl -u indidus-signaling -n 50"
fi

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      Indidus Relay & Signaling deployed successfully!    ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  URL:         ${RELAY_URL}"
echo "║  TURN Secret: ${TURN_SECRET}"
echo "║                                                          ║"
echo "║  Service status:  systemctl status indidus-signaling     ║"
echo "║  View logs:       journalctl -u indidus-signaling -f     ║"
echo "║  Config file:     ${INSTALL_DIR}/config.toml              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
