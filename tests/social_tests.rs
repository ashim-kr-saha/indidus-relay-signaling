mod common;
use common::{TestServer, solve_pow};
use reqwest::{Client, StatusCode};
use serde_json::json;

#[tokio::test]
async fn test_social_and_vaults() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    
    let alice_token = setup_user(&server, &client, "alice").await;
    let bob_token = setup_user(&server, &client, "bob").await;

    // 1. Alice sends friend request to Bob
    let resp = client.post(server.url("/friends"))
        .bearer_auth(&alice_token)
        .json(&json!({ "friend_username": "bob" }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "Friend request failed");

    // 2. Bob accepts friend request
    let resp = client.post(server.url(format!("/friends/accept/{}", "alice").as_str()))
        .bearer_auth(&bob_token)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Accept friend request failed");

    // 3. Alice invites Bob to a vault
    let vault_id = "vault-123";
    let resp = client.post(server.url("/vaults/invite"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "vault_id": vault_id,
            "invitee_username": "bob",
            "role": "editor"
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Vault invite failed");
    let invite_id: String = resp.json().await.unwrap();

    // 4. Bob accepts vault invite
    let resp = client.post(server.url(format!("/vaults/invites/{}/accept", invite_id).as_str()))
        .bearer_auth(&bob_token)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Accept vault invite failed");

    // 5. Alice checks vault members
    let resp = client.get(server.url(format!("/vaults/{}/members", vault_id).as_str()))
        .bearer_auth(&alice_token)
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let members: serde_json::Value = resp.json().await.unwrap();
    assert!(members.as_array().unwrap().iter().any(|m| m["username"] == "bob"), "Bob not in vault members");
}

async fn setup_user(server: &TestServer, client: &Client, username: &str) -> String {
    let pow = solve_pow(username, server.config.auth.registration_difficulty);
    let resp = client.post(server.url("/auth/register"))
        .json(&json!({"username": username, "password": "password", "pow_nonce": pow}))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "Setup user registration failed for {}", username);
    
    let resp = client.post(server.url("/auth/login"))
        .json(&json!({"username": username, "password": "password"}))
        .send().await.unwrap();
    assert!(resp.status().is_success(), "Setup user login failed for {}", username);
    
    let data: serde_json::Value = resp.json().await.unwrap();
    data["access_token"].as_str().unwrap().to_string()
}
