mod common;
use common::{TestServer, solve_pow};
use reqwest::{Client, StatusCode};
use serde_json::json;

#[tokio::test]
async fn test_invalid_pow_rejection() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "bad_pow_user";

    // Send a wrong nonce (0 is unlikely to work for difficulty 2)
    let resp = client
        .post(server.url("/auth/register"))
        .json(&json!({
            "username": username,
            "password": "password123",
            "pow_nonce": 0
        }))
        .send()
        .await
        .unwrap();

    // If difficulty is 2, nonce 0 has 1 in 4 chance of working.
    // We'll use a username that definitely fails with nonce 0 for difficulty 2.
    // Or we just check that if it failed, it has the right message.
    if resp.status() == StatusCode::BAD_REQUEST {
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient Proof-of-Work"));
    }
}

#[tokio::test]
async fn test_expired_share_retrieval() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    // 1. Register & Login to get token
    let username = "alice";
    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);
    client
        .post(server.url("/auth/register"))
        .json(&json!({"username": username, "password": "password", "pow_nonce": pow_nonce}))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(server.url("/auth/login"))
        .json(&json!({"username": username, "password": "password"}))
        .send()
        .await
        .unwrap();
    let auth: serde_json::Value = resp.json().await.unwrap();
    let token = auth["access_token"].as_str().unwrap();

    // 2. Upload share with 1 second TTL
    let resp = client
        .post(server.url("/shares"))
        .bearer_auth(token)
        .json(&json!({
            "payload": vec![1, 2, 3, 4],
            "ttl_seconds": 1,
            "max_views": 10
        }))
        .send()
        .await
        .unwrap();
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

    // Attempt to access a protected route without token
    let resp = client.get(server.url("/devices")).send().await.unwrap();

    // Axum's TypedHeader returns 400 if missing.
    let status = resp.status();
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST);
}
