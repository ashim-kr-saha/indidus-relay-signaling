# Indidus Relay Signaling Server (v5.0)

A high-performance, **strictly binary-only** unified server for the **Indidus Password Manager** ecosystem. This crate handles both **P2P Signaling** (for device sync) and **Zero-Knowledge Relay** (for secure sharing) using a unified **Protobuf** wire protocol.

## 🛡️ Security Architecture: Strict Protobuf & mTLS

As of v5.0, the signaling server has transitioned to a **strictly binary-only** transport. All legacy JSON endpoints have been purged to improve performance, reduce memory pressure, and minimize the attack surface.

### 1. Identity Verification
- **mTLS Primary**: The server expects a reverse proxy (e.g., Caddy) to verify client certificates and forward the identity via `X-Client-Cert-CN` and `X-Client-Cert-Serial` headers.
- **X-Signature Protocol**: Every request is cryptographically signed (`METHOD|PATH|TIMESTAMP|BODY_HASH`) using the device's Ed25519 private key.
- **Binary Hardening**: Signaling messages are exclusively transmitted as binary Protobuf frames via WebSockets, eliminating UTF-8 validation and text-based injection risks.

### 2. Backward Compatibility (Self-Hosters)
- **Optional PoW**: For self-hosted deployments where mTLS is not required, the server supports a **Proof-of-Work (PoW)** registration model.
- **Configurable Difficulty**: Set `rate_limit.enabled = true` and `auth.registration_difficulty` in `config.toml`.

## 🚀 Unified Features

### 1. Stateless Signaling (WebSockets)
- **Binary Routing**: Facilitates P2P connections using strictly-typed Protobuf frames.
- **Lock-Free Scaling**: Uses `DashMap` for concurrent peer tracking, achieving sub-microsecond routing latencies.
- **Offline Mailbox**: Encrypted signaling messages are queued in a local SQLite database if the target device is offline.

### 2. Zero-Knowledge Relay (HTTP)
- **Encrypted Share Blobs**: Stores AES-GCM-256 encrypted shares for cross-device data transfer.
- **Blind Storage**: The server only manages binary blobs; it never sees decryption keys.
- **Automatic Pruning**: Shares automatically expire based on TTL or view counts.
- **Embedded Viewer**: Serves the [indidus-wasm-share-client](../indidus-wasm-share-client) directly.

## 📊 Benchmarks (Strict Protobuf Profile)

| Operation | Latency | Protocol |
| :--- | :--- | :--- |
| **Identity Registration** | **199 µs** | **Protobuf (Binary)** |
| **Device Listing** | **147 µs** | **Protobuf (Binary)** |
| **WS Message Routing** | **130 ns** | **Binary Frame** |
| **Relay Write (64KB)** | **50 µs** | Binary Blob |
| **Relay Read (64KB)** | **6.6 µs** | Binary Blob |

## 🛠️ Configuration

The server is configured via `config.toml`.

```toml
[server]
host = "127.0.0.1"
port = 8080

[gate]
mtls_required = true

[rate_limit]
enabled = true
requests_per_second = 1
burst_size = 5
```

## 📈 Scalability
Capable of handling **100k+ clients** on a single vCPU with minimal memory footprint, leveraging `mimalloc` and zero-copy binary serialization.

## ⚖️ License
Apache-2.0
