mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_full_lifecycle_v4() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "testuser_e2e";

    // 1. Generate Identity
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(public_key.as_bytes());

    // 2. Register
    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);
    let res = client
        .post(server.url("/register"))
        .json(&json!({
            "username": username,
            "root_public_key": &public_key_hex,
            "pow_nonce": pow_nonce
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);

    // 3. Upload Share
    let body = b"test_payload";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(&signing_key.to_bytes(), "POST", "/shares", timestamp, body);

    let res = client
        .post(server.url("/shares"))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
    let upload_res: serde_json::Value = res.json().await.unwrap();
    let share_id = upload_res["id"].as_str().unwrap().to_string();

    // 4. Download
    let res = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.bytes().await.unwrap(), body.as_slice());

    // 5. Revoke
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "DELETE",
        &format!("/shares/{}", share_id),
        timestamp,
        &[],
    );

    let res = client
        .delete(server.url(&format!("/shares/{}", share_id)))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 204);

    // 6. Verify Deleted
    let res = client
        .get(server.url(&format!("/shares/{}", share_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
