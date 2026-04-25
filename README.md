# Indidus Relay Signaling Server (v4.0)

A high-performance, unified server for the **Indidus Password Manager** ecosystem. This crate handles both **P2P Signaling** (for device sync) and **Zero-Knowledge Relay** (for secure sharing).

## 🚀 Dual-Role Architecture

### 1. Stateless Signaling (WebSockets)
- Facilitates P2P connections between Indidus devices for vault synchronization.
- **Stateless Identity**: Uses the v4.0 protocol where devices identify via Ed25519 public keys.
- **Lock-Free Scaling**: Uses `DashMap` for concurrent peer tracking, optimized for multi-core performance on low-resource VPS.

### 2. Zero-Knowledge Relay (HTTP)
- Stores encrypted "share blobs" for secure data transfer.
- **Blind Storage**: The server never sees decryption keys or unencrypted content.
- **Automatic Pruning**: Shares automatically expire based on TTL or view counts.

## 🛡️ Security Features

- **Proof-of-Work (PoW)**: Registration requires solving a cryptographic challenge (Difficulty 16+) to prevent spam and DDoS.
- **X-Signature Protocol**: Every request is signed with the device's private key (`METHOD|PATH|TIMESTAMP|BODY_HASH`).
- **Async Integrity**: All database operations are isolated in `spawn_blocking` to prevent executor starvation in 1-vCPU environments.
- **Embedded Viewer**: Serves the [indidus-wasm-share-client](../indidus-wasm-share-client) directly for browser-based decryption.

## 🛠️ Getting Started

### Prerequisites
- Rust 1.75+
- SQLite 3 (bundled version supported)

### Running Locally
```bash
cargo run --release
```

### Configuration
The server looks for `config.toml`. Default settings:
- Host: `127.0.0.1`
- Port: `8080`
- PoW Difficulty: `16`

## 📊 Benchmarks
The v4.0 architecture is designed for "Zero-Waste" performance:
- **Routing**: ~234ns per message (1000 peers).
- **Concurrent Access**: Verified with `DashMap` for high-throughput signaling.

## ⚖️ License
Apache-2.0
