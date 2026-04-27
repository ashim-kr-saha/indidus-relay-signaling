#!/usr/bin/env bash
# =============================================================================
# Indidus Relay & Signaling Cleanup Script
# Targets: Ubuntu 22.04 LTS (Generic Linux VPS)
#
# Usage:
#   sudo bash cleanup.sh
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;32m[cleanup]\033[0m $*"; }
warn() { echo -e "\033[1;33m[cleanup]\033[0m $*"; }
err()  { echo -e "\033[1;31m[cleanup]\033[0m $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || err "This script must be run as root. Try: sudo bash ..."
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require_root

warn "This script will completely REMOVE the indidus-signaling server and PURGE Caddy."
warn "All data in /opt/indidus-relay-signaling will be PERMANENTLY DELETED."
# Check if we are in an interactive terminal
if [[ -t 0 ]]; then
    read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Cleanup aborted."
        exit 0
    fi
else
    log "Non-interactive shell detected. Proceeding with cleanup as requested..."
fi

# ---------------------------------------------------------------------------
# 1. Stop and disable services
# ---------------------------------------------------------------------------
log "Stopping services..."
systemctl stop indidus-signaling 2>/dev/null || true
systemctl stop caddy 2>/dev/null || true
systemctl disable indidus-signaling 2>/dev/null || true
systemctl disable caddy 2>/dev/null || true
log "Services stopped and disabled."

# ---------------------------------------------------------------------------
# 2. Remove indidus-signaling files and user
# ---------------------------------------------------------------------------
log "Removing indidus-signaling files..."
rm -f /etc/systemd/system/indidus-signaling.service
systemctl daemon-reload

if [[ -d "/opt/indidus-relay-signaling" ]]; then
    rm -rf /opt/indidus-relay-signaling
    log "Deleted /opt/indidus-relay-signaling"
fi

if id "indidus-signaling" &>/dev/null; then
    log "Removing system user: indidus-signaling"
    userdel -r indidus-signaling 2>/dev/null || userdel indidus-signaling 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Purge Caddy
# ---------------------------------------------------------------------------
log "Purging Caddy and its configuration..."
apt-get purge -y -qq caddy 2>/dev/null || true
apt-get autoremove -y -qq 2>/dev/null || true

rm -rf /etc/caddy
rm -f /etc/apt/sources.list.d/caddy-stable.list
rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
log "Caddy purged."

# ---------------------------------------------------------------------------
# 4. Final Cleanup
# ---------------------------------------------------------------------------
log "Factory reset complete."
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      Indidus Relay & Signaling has been removed.         ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  - Services:    Removed                                  ║"
echo "║  - Data:        Deleted (/opt/indidus-relay-signaling)   ║"
echo "║  - User:        Removed (indidus-signaling)              ║"
echo "║  - Caddy:       Purged (including configs and keys)      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
