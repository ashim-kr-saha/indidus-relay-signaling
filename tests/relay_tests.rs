mod common;
use common::{TestServer, solve_pow};
use reqwest::{Client, StatusCode};
use serde_json::json;

#[tokio::test]
async fn test_relay_blob_storage() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    
    // 1. Setup user
    let pow = solve_pow("alice", server.config.auth.registration_difficulty);
    client.post(server.url("/auth/register"))
        .json(&json!({"username": "alice", "password": "password", "pow_nonce": pow}))
        .send().await.unwrap();
    
    let resp = client.post(server.url("/auth/login"))
        .json(&json!({"username": "alice", "password": "password"}))
        .send().await.unwrap();
    let auth_data: serde_json::Value = resp.json().await.unwrap();
    let token = auth_data["access_token"].as_str().unwrap();

    // 2. Upload blob
    let payload = vec![1, 2, 3, 4, 5];
    let resp = client.post(server.url("/shares"))
        .bearer_auth(token)
        .json(&json!({
            "payload": payload,
            "ttl_seconds": 3600,
            "max_views": 2
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let upload_res: serde_json::Value = resp.json().await.unwrap();
    let share_id = upload_res["id"].as_str().unwrap();

    // 3. Download blob (View 1)
    let resp = client.get(server.url(&format!("/shares/{}", share_id)))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let downloaded = resp.bytes().await.unwrap().to_vec();
    assert_eq!(downloaded, payload);

    // 4. Download blob (View 2)
    let resp = client.get(server.url(&format!("/shares/{}", share_id)))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Download blob (View 3 - should fail due to max_views)
    let resp = client.get(server.url(&format!("/shares/{}", share_id)))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_relay_revocation() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    
    // Setup user
    let pow = solve_pow("bob", server.config.auth.registration_difficulty);
    client.post(server.url("/auth/register"))
        .json(&json!({"username": "bob", "password": "password", "pow_nonce": pow}))
        .send().await.unwrap();
    
    let resp = client.post(server.url("/auth/login"))
        .json(&json!({"username": "bob", "password": "password"}))
        .send().await.unwrap();
    let auth_data: serde_json::Value = resp.json().await.unwrap();
    let token = auth_data["access_token"].as_str().unwrap();

    // Upload blob
    let resp = client.post(server.url("/shares"))
        .bearer_auth(token)
        .json(&json!({
            "payload": vec![1, 2, 3],
        }))
        .send().await.unwrap();
    let share_id = resp.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    // Revoke
    let resp = client.delete(server.url(&format!("/shares/{}", share_id)))
        .bearer_auth(token)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify gone
    let resp = client.get(server.url(&format!("/shares/{}", share_id)))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
