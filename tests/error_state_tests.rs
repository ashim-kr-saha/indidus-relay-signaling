mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_invalid_pow_rejection() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "bad_pow_user";

    // 1. Generate Key
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Send a wrong nonce (0 is unlikely to work for difficulty 2)
    let resp = client
        .post(server.url("/register"))
        .json(&json!({
            "username": username,
            "root_public_key": public_key_hex,
            "pow_nonce": 0
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Insufficient Proof-of-Work"));
}

#[tokio::test]
async fn test_expired_share_retrieval() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    // 1. Register to get identity
    let username = "alice";
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);
    let resp = client
        .post(server.url("/register"))
        .json(&json!({
            "username": username,
            "root_public_key": &public_key_hex,
            "pow_nonce": pow_nonce
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2. Upload share with 1 second TTL
    let payload = b"test_payload";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "POST",
        "/shares",
        timestamp,
        payload,
    );

    let resp = client
        .post(server.url("/shares"))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .header("X-Share-TTL", "1")
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let share_data: serde_json::Value = resp.json().await.unwrap();
    let share_id = share_data["id"].as_str().unwrap();

    // 3. Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 4. Attempt retrieval
    let resp = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_unauthorized_access() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    // Attempt to access a protected route without authentication headers
    let resp = client.get(server.url("/devices")).send().await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
