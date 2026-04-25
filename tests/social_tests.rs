mod common;
use common::{TestServer, solve_pow, generate_signature};
use reqwest::{Client, StatusCode};
use serde_json::json;
use ed25519_dalek::SigningKey;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_friend_request_lifecycle() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    
    // 1. Setup Alice
    let alice_key = SigningKey::generate(&mut rand::thread_rng());
    let alice_pk_hex = hex::encode(alice_key.verifying_key().as_bytes());
    let alice_pow = solve_pow("alice", server.config.auth.registration_difficulty);
    client.post(server.url("/register"))
        .json(&json!({"username": "alice", "root_public_key": alice_pk_hex, "pow_nonce": alice_pow}))
        .send().await.unwrap();

    // 2. Setup Bob
    let bob_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_pk_hex = hex::encode(bob_key.verifying_key().as_bytes());
    let bob_pow = solve_pow("bob", server.config.auth.registration_difficulty);
    client.post(server.url("/register"))
        .json(&json!({"username": "bob", "root_public_key": bob_pk_hex, "pow_nonce": bob_pow}))
        .send().await.unwrap();

    // 3. Alice sends friend request to Bob
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let body = json!({ "friend_username": "bob" });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let signature = generate_signature(
        &alice_key.to_bytes(),
        "POST",
        "/friends",
        timestamp,
        &body_bytes
    );

    let resp = client.post(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .json(&body)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Bob accepts friend request
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let path = "/friends/accept/alice";
    let signature = generate_signature(
        &bob_key.to_bytes(),
        "POST",
        path,
        timestamp,
        &[]
    );

    let resp = client.post(server.url(path))
        .header("X-Identity", "bob")
        .header("X-Public-Key", &bob_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Alice lists friends
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signature = generate_signature(
        &alice_key.to_bytes(),
        "GET",
        "/friends",
        timestamp,
        &[]
    );

    let resp = client.get(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let friends: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(friends.iter().any(|f| f["username"] == "bob" && f["status"] == "confirmed"));

    // 6. Alice removes Bob
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let path = "/friends/bob";
    let signature = generate_signature(
        &alice_key.to_bytes(),
        "DELETE",
        path,
        timestamp,
        &[]
    );

    let resp = client.delete(server.url(path))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 7. Verify Bob is gone
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signature = generate_signature(
        &alice_key.to_bytes(),
        "GET",
        "/friends",
        timestamp,
        &[]
    );
    let resp = client.get(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send().await.unwrap();
    let friends: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(!friends.iter().any(|f| f["username"] == "bob"));
}
