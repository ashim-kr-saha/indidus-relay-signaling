mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use indidus_proto::signaling::{
    DeviceListResponse, Init, RegisterIdentityRequest, RegisterIdentityResponse, SignalingMessage,
    signaling_message::Content,
};
use prost::Message as _;
use reqwest::{Client, StatusCode};
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

    let mut alice_reg_buf = Vec::new();
    RegisterIdentityRequest {
        username: "alice".to_string(),
        root_public_key: alice_pk_hex.clone(),
        pow_nonce: alice_pow,
    }
    .encode(&mut alice_reg_buf)
    .unwrap();

    let resp = client
        .post(server.url("/register"))
        .header("Content-Type", "application/x-protobuf")
        .body(alice_reg_buf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2. Setup Bob
    let bob_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_pk_hex = hex::encode(bob_key.verifying_key().as_bytes());
    let bob_pow = solve_pow("bob", server.config.auth.registration_difficulty);

    let mut bob_reg_buf = Vec::new();
    RegisterIdentityRequest {
        username: "bob".to_string(),
        root_public_key: bob_pk_hex.clone(),
        pow_nonce: bob_pow,
    }
    .encode(&mut bob_reg_buf)
    .unwrap();

    let resp = client
        .post(server.url("/register"))
        .header("Content-Type", "application/x-protobuf")
        .body(bob_reg_buf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let bytes = resp.bytes().await.unwrap();
    let bob_reg_res = RegisterIdentityResponse::decode(bytes).unwrap();
    let bob_identity_id = bob_reg_res.id;

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
        .header("Accept", "application/x-protobuf")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp.bytes().await.unwrap();
    let bob_devices = DeviceListResponse::decode(bytes).unwrap();
    let bob_device_id = bob_devices.devices[0].id.clone();

    // 3. Bob connects via WebSocket
    let (mut ws_stream, _) = connect_async(server.ws_url()).await.unwrap();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    use ed25519_dalek::Signer;
    let msg_to_sign = format!(
        "WS_INIT:{}:{}:{}",
        bob_device_id, bob_identity_id, timestamp
    );
    let signature = bob_key.sign(msg_to_sign.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    let init_msg = SignalingMessage {
        content: Some(Content::Init(Init {
            identity_id: bob_identity_id,
            device_id: bob_device_id,
            timestamp,
            signature: sig_hex,
        })),
    };
    let mut buf = Vec::new();
    init_msg.encode(&mut buf).unwrap();

    ws_stream.send(Message::Binary(buf.into())).await.unwrap();

    // Bob should get the init success
    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout waiting for WS message")
        .expect("Stream closed")
        .expect("WS error");

    match msg {
        Message::Binary(bin) => {
            let res = SignalingMessage::decode(&bin[..]).unwrap();
            match res.content {
                Some(Content::InitSuccess(_)) => {}
                _ => panic!("Expected InitSuccess, got {:?}", res.content),
            }
        }
        _ => panic!("Expected Binary message, got {:?}", msg),
    }
}
