# Indidus Relay Signaling Server (v4.5)

A high-performance, unified server for the **Indidus Password Manager** ecosystem. This crate handles both **P2P Signaling** (for device sync) and **Zero-Knowledge Relay** (for secure sharing).

## 🛡️ Security Architecture: mTLS & Private CA

As of v4.5, the signaling server has transitioned to a **Mutual TLS (mTLS)** security model. This ensures that only devices with a valid certificate issued by your private **Indidus Gate** server can communicate with the infrastructure.

### 1. Identity Verification
- **mTLS Primary**: The server expects a reverse proxy (e.g., Caddy) to verify client certificates and forward the identity via `X-Client-Cert-CN` (Common Name) and `X-Client-Cert-Serial` headers.
- **X-Signature Protocol**: Every request is cryptographically signed (`METHOD|PATH|TIMESTAMP|BODY_HASH`) using the device's Ed25519 private key, verified against the public key stored during registration.
- **Zero-Trust**: Even with a valid TLS certificate, the server still validates every request signature to prevent impersonation.

### 2. Backward Compatibility (Self-Hosters)
- **Optional PoW**: For self-hosted deployments where mTLS is not required, the server supports a legacy **Proof-of-Work (PoW)** registration model.
- **Configurable Difficulty**: Set `rate_limit.enabled = true` and `auth.registration_difficulty` in `config.toml` to protect against spam in non-mTLS environments.

## 🚀 Dual-Role Features

### 1. Stateless Signaling (WebSockets)
- **Low-Latency Routing**: Facilitates P2P connections between Indidus devices for vault synchronization.
- **Lock-Free Scaling**: Uses `DashMap` for concurrent peer tracking, achieving sub-microsecond routing latencies.
- **Offline Mailbox**: Encrypted signaling messages are queued in a local SQLite database if the target device is offline.

### 2. Zero-Knowledge Relay (HTTP)
- **Encrypted Share Blobs**: Stores AES-GCM-256 encrypted shares for cross-device data transfer.
- **Blind Storage**: The server never sees decryption keys; it only serves the blob.
- **Automatic Pruning**: Shares automatically expire based on TTL or view counts.
- **Embedded Viewer**: Serves the [indidus-wasm-share-client](../indidus-wasm-share-client) directly for secure browser-based decryption.

## 📊 Benchmarks (Production Profile)

| Operation | Latency | Performance |
| :--- | :--- | :--- |
| **WS Message Routing** | **129 ns** | 1000 active peers |
| **Identity Registration** | **192 µs** | Difficulty 8 PoW |
| **Device Listing** | **144 µs** | SQLite lookup |
| **Relay Write (64KB)** | **50 µs** | SQLite storage |
| **Relay Read (64KB)** | **6.6 µs** | SQLite retrieval |

## 🛠️ Configuration

The server is configured via `config.toml`. Key sections:

```toml
[server]
host = "127.0.0.1"
port = 8080

[gate]
mtls_required = true
# Headers forwarded by Caddy
cn_header = "X-Client-Cert-CN"
serial_header = "X-Client-Cert-Serial"

[rate_limit]
enabled = true
requests_per_second = 1
burst_size = 5
```

## 📈 Scalability
Designed to run on **1-vCPU / 2GB RAM** instances, capable of handling 100k+ clients with minimal memory footprint.

## ⚖️ License
Apache-2.0
