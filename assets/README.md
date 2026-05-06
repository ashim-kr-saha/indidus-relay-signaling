# Indidus WASM Share Client

A WebAssembly-powered web client for the **Zero-Knowledge Decryption** of Indidus shares.

## 💡 Overview
This crate is designed to run in a web browser. It allows recipients of Indidus share links to decrypt and download contents without needing to install the full Indidus application.

### Key Logic
- **Local Decryption**: Uses `AES-GCM-256` via the `aes-gcm` Rust crate.
- **Key Fragment Handling**: Decryption keys are extracted from the URL fragment (`#`), ensuring the server never receives the key.
- **WASM Performance**: High-performance cryptographic operations compiled from Rust.

## 🛠️ Build Instructions

This crate requires `wasm-pack` to build the assets for the relay server.

```bash
# Build for production
wasm-pack build --target web --release

# The output in ./pkg/ should be copied to the relay server's assets folder
cp -r pkg/ ../indidus-relay-signaling/assets/
```

## 📂 Structure
- `index.html`: The entry point for the browser-based viewer.
- `src/lib.rs`: The Rust logic for decryption and JS bindings.
- `pkg/`: Generated WASM and JS glue code (after build).

## 🛡️ Security Model
1.  Browser fetches the encrypted blob from the relay.
2.  Browser retrieves the decryption key from `window.location.hash`.
3.  WASM module decrypts the blob in memory.
4.  Decrypted content is presented to the user for download/viewing.

## ⚖️ License
Apache-2.0
