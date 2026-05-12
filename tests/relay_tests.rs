mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use indidus_relay_proto::relay::UploadResponse;
use indidus_relay_proto::signaling::RegisterIdentityRequest;
use prost::Message;
use reqwest::{Client, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};

async fn register_user(
    client: &Client,
    url: &str,
    username: &str,
    difficulty: u32,
) -> (String, SigningKey) {
    let mut rng = rand::thread_rng();
    let sk = SigningKey::generate(&mut rng);
    let pk_hex = hex::encode(sk.verifying_key().as_bytes());
    let pow = solve_pow(username, difficulty);

    let req = RegisterIdentityRequest {
        username: username.to_string(),
        root_public_key: pk_hex.clone(),
        pow_nonce: pow,
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();

    client
        .post(url)
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .unwrap();
    (pk_hex, sk)
}

#[tokio::test]
async fn test_relay_blob_storage() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "alice";

    // 1. Setup Identity
    let (public_key_hex, signing_key) = register_user(
        &client,
        &server.url("/register"),
        username,
        server.config.auth.registration_difficulty,
    )
    .await;

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
    let bytes = resp.bytes().await.unwrap();
    let upload_res = UploadResponse::decode(bytes).unwrap();
    let share_id = upload_res.id;

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
    let (public_key_hex, signing_key) = register_user(
        &client,
        &server.url("/register"),
        username,
        server.config.auth.registration_difficulty,
    )
    .await;

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

    let bytes = resp.bytes().await.unwrap();
    let upload_res = UploadResponse::decode(bytes).unwrap();
    let share_id = upload_res.id;

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
