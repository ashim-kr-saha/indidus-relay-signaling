# Indidus Relay & Signaling — Docker Deployment Guide

The Indidus Relay & Signaling server is available as a **production-ready, unified Docker image**. This image includes both the server and Caddy internally, handling process orchestration and automatic SSL termination in a single unit.

## Building from Source

If you want to build the production image yourself:

1. **Build locally**:
   ```bash
   docker build -t ashimksaha/indidus-relay-signaling:latest -f deploy/Dockerfile .
   ```

2. **Run the container (Production with Domain)**:
   ```bash
   docker run -d \
     --name indidus-signaling \
     -p 80:80 -p 443:443 \
     -v $(pwd)/data:/opt/indidus-relay-signaling/data \
     -e RELAY_DOMAIN="signaling.example.com" \
     ashimksaha/indidus-relay-signaling:latest
   ```

3. **Run the container (IP-only / Testing)**:
   ```bash
   docker run -d \
     --name indidus-signaling \
     -p 443:443 \
     -v $(pwd)/data:/opt/indidus-relay-signaling/data \
     ashimksaha/indidus-relay-signaling:latest
   ```
   *Note: In IP-only mode, Caddy will use internal self-signed certificates.*

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `RELAY_DOMAIN` | Your public domain (triggers Let's Encrypt) | (Empty -> IP Mode) |
| `TURN_SECRET` | Secret for TURN credentials | (Auto-generated if missing) |
| `RUST_LOG` | Logging verbosity (info, debug, trace) | `info` |

### Persistence
The container stores data in `/opt/indidus-relay-signaling/data`. For persistent storage, always mount a host volume to this path:
`-v /path/to/local/data:/opt/indidus-relay-signaling/data`

## Features

- **Integrated SSL**: Automatic HTTPS via Caddy (Let's Encrypt or ZeroSSL).
- **Process Orchestration**: Internal health checks and graceful shutdown management.
- **Minimal Footprint**: Multi-stage build based on Alpine Linux (~20MB image).
- **Multi-Arch**: Native support for `x86_64` and `arm64` (Apple Silicon/Raspberry Pi).

## UNINSTALLATION
To stop and remove the container:
```bash
docker stop indidus-signaling
docker rm indidus-signaling
```
