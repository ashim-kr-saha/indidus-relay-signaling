# Indidus Relay & Signaling — Linux Server Installation Guide

This guide covers deploying the Indidus Relay & Signaling server on any standard Linux VPS (Ubuntu 22.04 LTS recommended). 

## Prerequisites

- **A Linux Server**: x86_64 or ARM64 architecture (GCP, AWS, DigitalOcean, Linode, etc.).
- **Public Access**: A static public IP address.
- **Firewall**: Ports **80** and **443** must be open to the public internet.
- **SSH Access**: Ability to run commands as `root` or via `sudo`.

---

## Step 1 — Provision your Server

You can use any provider. If you don't have one, we recommend:
- **GCP (Google Cloud)**: `e2-micro` instances in `us-central1` are "Always Free".
- **AWS (Amazon)**: `t4g.nano` instances are often eligible for the Free Tier.
- **DigitalOcean**: $4 or $6 "Droplets" are excellent for stable performance.

**Important:** Ensure you enable "Allow HTTP traffic" and "Allow HTTPS traffic" (Ports 80 and 443) in your provider's firewall settings.

---

## Step 2 — Run the Bootstrap Script

### A. Recommended: Using a Domain (Automatic SSL)
If you have a domain (e.g., `signaling.example.com`), Caddy will automatically fetch a Let's Encrypt certificate for you.

```bash
sudo sh -c 'curl -fsSL https://raw.githubusercontent.com/ashim-kr-saha/indidus-relay-signaling/main/deploy/bootstrap.sh | \
  bash -s -- --domain "signaling.example.com"'
```

### B. IP-Only: Using a Static IP (Internal SSL)
If you don't have a domain, the server will still use HTTPS via an internal self-signed certificate.

```bash
sudo sh -c 'curl -fsSL https://raw.githubusercontent.com/ashim-kr-saha/indidus-relay-signaling/main/deploy/bootstrap.sh | bash'
```

---

## Step 3 — Uninstallation & Factory Reset

If you want to completely remove the signaling server and purge Caddy from your instance:

```bash
sudo sh -c 'curl -fsSL https://raw.githubusercontent.com/ashim-kr-saha/indidus-relay-signaling/main/deploy/cleanup.sh | bash'
```

This will delete all data, remove the `indidus-signaling` user, and completely uninstall the Caddy package.

---

## Alternative: Deployment via Docker

If you prefer using containers, you can deploy the signaling server as a single lightweight image.

- **Guide**: [deploy/DOCKER.md](DOCKER.md)
- **Command**: `docker run -p 80:80 -p 443:443 -e RELAY_DOMAIN=signaling.example.com ashimksaha/indidus-relay-signaling:latest`

---

## Step 4 — Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Using an IP address | This is expected with self-signed IP certs. |
| Connection Refused | Firewall blocked | Ensure ports 80/443 are open in your cloud provider's console (GCP Firewall / AWS Security Groups). |
| `sudo-rs: I'm sorry...` | Restricted sudo | Ensure you use the `sudo sh -c '...'` wrapper as shown above to bypass environment restrictions. |

---

## Management Commands

```bash
# Check status
sudo systemctl status indidus-signaling

# View live logs
sudo journalctl -u indidus-signaling -f

# View config
sudo cat /opt/indidus-relay-signaling/config.toml

# Update binary (re-run bootstrap)
sudo sh -c 'curl -fsSL https://raw.githubusercontent.com/ashim-kr-saha/indidus-relay-signaling/main/deploy/bootstrap.sh | bash -s -- --domain "..."'
```
