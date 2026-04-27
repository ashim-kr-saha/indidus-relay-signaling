mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

#[tokio::test]
async fn test_mailbox_and_signaling() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    // 1. Setup Alice
    let alice_key = SigningKey::generate(&mut rand::thread_rng());
    let alice_pk_hex = hex::encode(alice_key.verifying_key().as_bytes());
    let alice_pow = solve_pow("alice", server.config.auth.registration_difficulty);
    let resp = client
        .post(server.url("/register"))
        .json(
            &json!({"username": "alice", "root_public_key": alice_pk_hex, "pow_nonce": alice_pow}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let _ = resp.json::<serde_json::Value>().await.unwrap();

    // 2. Setup Bob
    let bob_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_pk_hex = hex::encode(bob_key.verifying_key().as_bytes());
    let bob_pow = solve_pow("bob", server.config.auth.registration_difficulty);
    let resp = client
        .post(server.url("/register"))
        .json(&json!({"username": "bob", "root_public_key": bob_pk_hex, "pow_nonce": bob_pow}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bob_data: serde_json::Value = resp.json().await.unwrap();
    let bob_id = bob_data["id"].as_str().unwrap().to_string();

    // Fetch device ID for Bob
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(&bob_key.to_bytes(), "GET", "/devices", timestamp, &[]);
    let resp = client
        .get(server.url("/devices"))
        .header("X-Identity", "bob")
        .header("X-Public-Key", &bob_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bob_devices: Vec<serde_json::Value> = resp.json().await.unwrap();
    let bob_device_id = bob_devices[0]["id"].as_str().unwrap().to_string();

    // 3. Alice sends message to Bob while Bob is offline
    let msg_payload = b"hello bob";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = json!({
        "target_device_id": bob_device_id,
        "payload": msg_payload.to_vec()
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let signature = generate_signature(
        &alice_key.to_bytes(),
        "POST",
        "/mailbox",
        timestamp,
        &body_bytes,
    );

    let resp = client
        .post(server.url("/mailbox"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Bob connects via WebSocket
    let (mut ws_stream, _) = connect_async(server.ws_url()).await.unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Correct signature for WS_INIT: format!("WS_INIT:{}:{}:{}", device_id, identity_id, timestamp)
    use ed25519_dalek::Signer;
    let msg_to_sign = format!("WS_INIT:{}:{}:{}", bob_device_id, bob_id, timestamp);
    let signature = bob_key.sign(msg_to_sign.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    ws_stream
        .send(Message::Text(
            json!({
                "type": "init",
                "identity_id": bob_id,
                "device_id": bob_device_id,
                "timestamp": timestamp,
                "signature": sig_hex
            })
            .to_string(),
        ))
        .await
        .unwrap();

    // Bob should get the mailbox push or an init success
    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout waiting for WS message")
        .expect("Stream closed")
        .expect("WS error");

    println!("Received: {}", msg);
    assert!(msg.to_text().unwrap().contains("init_success"));

    // Bob should also get the mailbox push
    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout waiting for mailbox push")
        .expect("Stream closed")
        .expect("WS error");

    println!("Received: {}", msg);
    assert!(msg.to_text().unwrap().contains("mailbox_push"));
}
