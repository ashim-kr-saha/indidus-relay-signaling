mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let resp = client
        .post(server.url("/register"))
        .json(&json!({
            "username": username,
            "root_public_key": public_key_hex,
            "pow_nonce": pow_nonce
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Test authenticated request (Get Device)
    // In v4.0, /devices returns list of devices for identity
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

    let resp = client
        .post(server.url("/register"))
        .json(&json!({
            "username": "bot",
            "root_public_key": public_key_hex,
            "pow_nonce": 0 // Wrong nonce
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
