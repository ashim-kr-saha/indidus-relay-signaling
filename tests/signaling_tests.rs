mod common;
use common::{TestServer, solve_pow};
use reqwest::Client;
use serde_json::json;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures::{SinkExt, StreamExt};

#[tokio::test]
async fn test_mailbox_and_signaling() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    
    // 1. Setup Alice and Bob
    let (alice_token, _alice_id) = setup_user(&server, &client, "alice").await;
    let (bob_token, _bob_id) = setup_user(&server, &client, "bob").await;

    // 2. Register devices
    let _alice_device_id = register_device(&server, &client, &alice_token, "alice-phone").await;
    let bob_device_id = register_device(&server, &client, &bob_token, "bob-phone").await;

    // 3. Alice sends message to Bob while Bob is offline
    let msg_payload = json!({
        "type": "offer",
        "sdp": "v=0..."
    });

    let resp = client.post(server.url("/mailbox"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "target_device_id": bob_device_id,
            "payload": serde_json::to_vec(&msg_payload).unwrap()
        }))
        .send()
        .await
        .unwrap();
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        panic!("Mailbox enqueue failed: {}. Body: {}", status, body);
    }

    // 4. Bob connects via WebSocket and should receive the mailbox message
    let (mut ws_stream, _) = connect_async(server.ws_url()).await.unwrap();
    
    // Init command
    ws_stream.send(Message::Text(json!({
        "type": "init",
        "token": bob_token,
        "device_id": bob_device_id
    }).to_string())).await.unwrap();

    // Bob should get the mailbox push
    let msg = ws_stream.next().await.unwrap().unwrap();
    let msg_text = msg.to_text().unwrap();
    println!("Received message: {}", msg_text);
    assert!(msg_text.contains("mailbox_push") || msg_text.contains("offer"));
}

async fn setup_user(server: &TestServer, client: &Client, username: &str) -> (String, String) {
    let pow = solve_pow(username, server.config.auth.registration_difficulty);
    client.post(server.url("/auth/register"))
        .json(&json!({"username": username, "password": "password", "pow_nonce": pow}))
        .send().await.unwrap();
    
    let resp = client.post(server.url("/auth/login"))
        .json(&json!({"username": username, "password": "password"}))
        .send().await.unwrap();
    
    let data: serde_json::Value = resp.json().await.unwrap();
    (data["access_token"].as_str().unwrap().to_string(), username.to_string())
}

async fn register_device(server: &TestServer, client: &Client, token: &str, name: &str) -> String {
    let resp = client.post(server.url("/devices"))
        .bearer_auth(token)
        .json(&json!({
            "public_key": vec![0u8; 32],
            "name": name
        }))
        .send().await.unwrap();
    
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        panic!("Device registration failed: {}. Body: {}", status, body);
    }

    let data: serde_json::Value = resp.json().await.unwrap();
    data["id"].as_str().unwrap().to_string()
}
