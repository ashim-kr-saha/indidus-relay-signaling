mod common;
use common::{TestServer, solve_pow};
use reqwest::{Client, StatusCode};
use serde_json::json;

#[tokio::test]
async fn test_registration_and_login() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "alice";
    let password = "password123";

    // 1. Solve PoW
    let pow_nonce = solve_pow(username, server.config.auth.registration_difficulty);

    // 2. Register
    let resp = client.post(server.url("/auth/register"))
        .json(&json!({
            "username": username,
            "password": password,
            "pow_nonce": pow_nonce
        }))
        .send()
        .await
        .unwrap();
    
    let status = resp.status();
    assert_eq!(status, StatusCode::CREATED, "Registration failed: {}", resp.text().await.unwrap());

    // 3. Login
    let resp = client.post(server.url("/auth/login"))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .unwrap();
    
    assert_eq!(resp.status(), StatusCode::OK);
    let auth_data: serde_json::Value = resp.json().await.unwrap();
    let access_token = auth_data["access_token"].as_str().unwrap();
    let refresh_token = auth_data["refresh_token"].as_str().unwrap();

    // 4. Test authenticated request
    let resp = client.get(server.url("/friends"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Logout (Revoke)
    let resp = client.post(server.url("/auth/logout"))
        .bearer_auth(access_token)
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 6. Try refresh (should fail)
    let resp = client.post(server.url("/auth/refresh"))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bad_pow_rejection() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    let resp = client.post(server.url("/auth/register"))
        .json(&json!({
            "username": "bot",
            "password": "password",
            "pow_nonce": 0
        }))
        .send()
        .await
        .unwrap();
    
    let status = resp.status();
    if status != StatusCode::BAD_REQUEST {
        let body = resp.text().await.unwrap();
        panic!("Expected 400, got {}. Body: {}", status, body);
    }
}
