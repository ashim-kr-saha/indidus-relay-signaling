mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};
use indidus_proto::signaling::RegisterIdentityRequest;
use prost::Message;

#[tokio::test]
async fn test_registration_and_device_management() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "alice";

    // 1. Generate Key
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(public_key.as_bytes());

    // 2. Solve PoW
    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    // 3. Register
    let req = RegisterIdentityRequest {
        username: username.to_string(),
        root_public_key: public_key_hex.clone(),
        pow_nonce,
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();

    let resp = client
        .post(server.url("/register"))
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Test authenticated request (Get Device)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(&signing_key.to_bytes(), "GET", "/devices", timestamp, &[]);

    let resp = client
        .get(server.url("/devices"))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bad_pow_rejection() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let req = RegisterIdentityRequest {
        username: "bot".to_string(),
        root_public_key: public_key_hex,
        pow_nonce: 0, // Wrong nonce
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();

    let resp = client
        .post(server.url("/register"))
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
