mod common;
use common::{TestServer, solve_pow};
use indidus_relay_proto::signaling::RegisterIdentityRequest;
use prost::Message;
use reqwest::{Client, StatusCode};

#[tokio::test]
async fn test_registration_rate_limiting() {
    let server = TestServer::spawn().await;
    let client = Client::new();
    let username = "rate_limit_user";

    // We have a burst size of 5. Let's try 10 requests rapidly.

    let mut success_count = 0;
    let mut throttled_count = 0;
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    for i in 0..10 {
        let unique_username = format!("{}_{}", username, i);
        let pow_nonce = solve_pow(&unique_username, server.config.auth.registration_difficulty);

        let req = RegisterIdentityRequest {
            username: unique_username,
            root_public_key: public_key_hex.clone(),
            pow_nonce,
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        let resp = client
            .post(server.url("/register"))
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send()
            .await
            .unwrap();

        match resp.status() {
            StatusCode::CREATED => success_count += 1,
            StatusCode::TOO_MANY_REQUESTS => throttled_count += 1,
            _ => panic!("Unexpected status code: {}", resp.status()),
        }
    }

    println!("Success: {}, Throttled: {}", success_count, throttled_count);

    // Burst is 5, so we expect around 5-6 successes and some throttled
    assert!(success_count >= 5, "Expected at least 5 successes (burst)");
    assert!(
        throttled_count > 0,
        "Expected at least some requests to be throttled"
    );
}
