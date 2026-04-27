# Security Policy

## Indidus Relay & Signaling Security Model

The Indidus Relay & Signaling server is a core component of the Indidus zero-knowledge architecture. It facilitates secure device synchronization and temporary encrypted data storage.

### Zero-Knowledge Guarantee

1.  **Encryption at Rest**: All share data stored on the relay is encrypted using `AES-GCM-256`. The server does **not** possess the decryption keys.
2.  **Blind Transport**: Decryption keys are managed via URL fragments (e.g., `https://signaling.com/v/ID#KEY`). Standard browsers do not send the fragment part of the URL to the server, ensuring the server never logs or sees the key.
3.  **Ephemeral Storage**: Shares are automatically deleted after they expire (TTL) or reach their view limit.

### Authentication & Authorization

- **X-Signature Protocol**: Every request is cryptographically signed using the device's Ed25519 private key. The server verifies the signature against the registered public key.
- **Proof-of-Work (PoW)**: Identity registration requires solving a cryptographic challenge to prevent sybil attacks and spam.
- **Signaling Security**: Signaling messages are encrypted end-to-end between devices; the server only facilitates the routing of encrypted packets.

### Reported Vulnerabilities

If you discover a security vulnerability within the Indidus Relay & Signaling Server, please email [security@indidus.com](mailto:security@indidus.com). We treat security reports with the highest priority.

**Please do NOT open public issues for security vulnerabilities.**

## Auditing

Since this crate is part of the Indidus ecosystem, we encourage independent security audits. Key areas for audit:
- `src/auth/`: Identity and signature verification logic.
- `src/signaling/`: WebSocket routing and peer tracking.
- `src/relay/`: Data storage and lifecycle management.
- `src/db/`: Persistence layer and query safety.
