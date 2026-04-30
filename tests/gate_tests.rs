mod common;
use common::{TestServer, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use indidus_proto::signaling::RegisterIdentityRequest;
use prost::Message;

async fn register_proto(client: &Client, url: &str, username: &str, pk_hex: &str, pow: u64, gate_header: Option<&str>) -> reqwest::Response {
    let req = RegisterIdentityRequest {
        username: username.to_string(),
        root_public_key: pk_hex.to_string(),
        pow_nonce: pow,
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();

    let mut builder = client.post(url).header("Content-Type", "application/x-protobuf");
    if let Some(h) = gate_header {
        builder = builder.header("X-Client-Cert-Verified", h);
    }
    builder.body(buf).send().await.unwrap()
}

/// When `gate.mtls_required = false` (default), registration works
/// without the X-Client-Cert-Verified header — PoW only.
#[tokio::test]
async fn test_registration_gate_disabled() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "gate_off_user";

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    let resp = register_proto(&client, &server.url("/register"), username, &public_key_hex, pow_nonce, None).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// When `gate.mtls_required = true`, registration WITHOUT the
/// X-Client-Cert-Verified header is rejected.
#[tokio::test]
async fn test_registration_gate_enabled_no_cert_rejected() {
    let server = TestServer::spawn_with_gate().await;
    let client = Client::new();
    let username = "gate_on_no_cert";

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    let resp = register_proto(&client, &server.url("/register"), username, &public_key_hex, pow_nonce, None).await;
    // Should be rejected — no client cert header
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// When `gate.mtls_required = true`, registration WITH the
/// X-Client-Cert-Verified: true header succeeds.
#[tokio::test]
async fn test_registration_gate_enabled_with_cert_succeeds() {
    let server = TestServer::spawn_with_gate().await;
    let client = Client::new();
    let username = "gate_on_with_cert";

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    let resp = register_proto(&client, &server.url("/register"), username, &public_key_hex, pow_nonce, Some("true")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// When `gate.mtls_required = true`, a spoofed header value
/// (anything other than "true") is rejected.
#[tokio::test]
async fn test_registration_gate_enabled_spoofed_header_rejected() {
    let server = TestServer::spawn_with_gate().await;
    let client = Client::new();
    let username = "gate_on_spoofed";

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    // Try with "True" (wrong case)
    let resp = register_proto(&client, &server.url("/register"), username, &public_key_hex, pow_nonce, Some("True")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// When `registration_difficulty = 0`, PoW is skipped entirely.
/// This verifies the optional PoW mechanism for mTLS-gated deployments.
#[tokio::test]
async fn test_registration_pow_disabled() {
    let server = TestServer::spawn_with_no_pow().await;
    let client = Client::new();
    let username = "no_pow_user";

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Send pow_nonce = 0 (wrong nonce) — should still succeed because difficulty = 0
    let resp = register_proto(&client, &server.url("/register"), username, &public_key_hex, 0, None).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}
