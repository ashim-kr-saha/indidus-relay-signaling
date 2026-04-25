mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_relay_blob_storage() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "alice";

    // 1. Setup Identity
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let pow = solve_pow(username, server.config.auth.registration_difficulty);

    client
        .post(server.url("/register"))
        .json(&json!({"username": username, "root_public_key": public_key_hex, "pow_nonce": pow}))
        .send()
        .await
        .unwrap();

    // 2. Upload blob
    let payload = vec![1, 2, 3, 4, 5];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "POST",
        "/shares",
        timestamp,
        &payload,
    );

    let resp = client
        .post(server.url("/shares"))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .header("X-Share-TTL", "3600")
        .header("X-Share-Views", "2")
        .body(payload.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let upload_res: serde_json::Value = resp.json().await.unwrap();
    let share_id = upload_res["id"].as_str().unwrap().to_string();

    // 3. Download blob (View 1)
    let resp = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let downloaded = resp.bytes().await.unwrap().to_vec();
    assert_eq!(downloaded, payload);

    // 4. Download blob (View 2)
    let resp = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Download blob (View 3 - should fail due to max_views)
    let resp = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_relay_revocation() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "bob";

    // Setup user
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let pow = solve_pow(username, server.config.auth.registration_difficulty);

    client
        .post(server.url("/register"))
        .json(&json!({"username": username, "root_public_key": public_key_hex, "pow_nonce": pow}))
        .send()
        .await
        .unwrap();

    // Upload blob
    let payload = vec![1, 2, 3];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "POST",
        "/shares",
        timestamp,
        &payload,
    );

    let resp = client
        .post(server.url("/shares"))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .body(payload)
        .send()
        .await
        .unwrap();

    let share_id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Revoke
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = format!("/shares/{}", share_id);
    let signature = generate_signature(&signing_key.to_bytes(), "DELETE", &path, timestamp, &[]);

    let resp = client
        .delete(server.url(&path))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify gone
    let resp = client.get(server.url(&path)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
