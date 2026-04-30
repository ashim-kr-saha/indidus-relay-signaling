mod common;
use common::{TestServer, generate_signature, solve_pow};
use ed25519_dalek::SigningKey;
use reqwest::{Client, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};
use indidus_proto::signaling::{RegisterIdentityRequest, FriendRequest, FriendsList};
use prost::Message;

async fn register_user(client: &Client, url: &str, username: &str, difficulty: u32) -> (String, SigningKey) {
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

    client.post(url)
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send().await.unwrap();
    (pk_hex, sk)
}

#[tokio::test]
async fn test_friend_request_lifecycle() {
    let server = TestServer::spawn().await;
    let client = Client::new();

    // 1. Setup Alice
    let (alice_pk_hex, alice_key) = register_user(&client, &server.url("/register"), "alice", server.config.auth.registration_difficulty).await;

    // 2. Setup Bob
    let (bob_pk_hex, bob_key) = register_user(&client, &server.url("/register"), "bob", server.config.auth.registration_difficulty).await;

    // 3. Alice sends friend request to Bob
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let freq = FriendRequest { target_username: "bob".to_string() };
    let mut fbuf = Vec::new();
    freq.encode(&mut fbuf).unwrap();

    let signature = generate_signature(
        &alice_key.to_bytes(),
        "POST",
        "/friends",
        timestamp,
        &fbuf,
    );

    let resp = client
        .post(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .header("Content-Type", "application/x-protobuf")
        .body(fbuf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Bob accepts friend request
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = "/friends/accept/alice";
    let signature = generate_signature(&bob_key.to_bytes(), "POST", path, timestamp, &[]);

    let resp = client
        .post(server.url(path))
        .header("X-Identity", "bob")
        .header("X-Public-Key", &bob_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. Alice lists friends
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(&alice_key.to_bytes(), "GET", "/friends", timestamp, &[]);

    let resp = client
        .get(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .header("Accept", "application/x-protobuf")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    
    let bytes = resp.bytes().await.unwrap();
    let friends = FriendsList::decode(bytes).unwrap();
    assert!(
        friends.friends
            .iter()
            .any(|f| f.username == "bob" && f.status == "confirmed")
    );

    // 6. Alice removes Bob
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = "/friends/bob";
    let signature = generate_signature(&alice_key.to_bytes(), "DELETE", path, timestamp, &[]);

    let resp = client
        .delete(server.url(path))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 7. Verify Bob is gone
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signature = generate_signature(&alice_key.to_bytes(), "GET", "/friends", timestamp, &[]);
    let resp = client
        .get(server.url("/friends"))
        .header("X-Identity", "alice")
        .header("X-Public-Key", &alice_pk_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .header("Accept", "application/x-protobuf")
        .send()
        .await
        .unwrap();
    
    let bytes = resp.bytes().await.unwrap();
    let friends = FriendsList::decode(bytes).unwrap();
    assert!(!friends.friends.iter().any(|f| f.username == "bob"));
}
