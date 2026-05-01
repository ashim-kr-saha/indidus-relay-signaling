use ed25519_dalek::{SigningKey, Signer};
use indidus_proto::signaling::{RegisterIdentityRequest, RegisterIdentityResponse};
use indidus_proto::relay::UploadResponse;
use prost::Message;
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// A modern, Protobuf-only example showing how to interact with the Indidus Signaling & Relay server.
/// 
/// Usage: 
/// 1. Start the server: cargo run
/// 2. Run this example: cargo run --example relay_client
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_url = "http://127.0.0.1:8080";
    let username = "example_user";
    let client = Client::new();

    println!("🚀 Starting Indidus Protobuf Client Example");

    // 1. Generate Ed25519 Identity
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(public_key.as_bytes());

    println!("🔑 Generated Identity: {}", public_key_hex);

    // 2. Solve Proof-of-Work (Difficulty 8 for quick example, server might require more)
    println!("⏳ Solving Proof-of-Work for '{}'...", username);
    let pow_nonce = solve_pow(username, 8); 
    println!("✅ PoW Solved: {}", pow_nonce);

    // 3. Register Identity
    let reg_req = RegisterIdentityRequest {
        username: username.to_string(),
        root_public_key: public_key_hex.clone(),
        pow_nonce,
    };
    let mut reg_buf = Vec::new();
    reg_req.encode(&mut reg_buf)?;

    let resp = client.post(format!("{}/register", server_url))
        .header("Content-Type", "application/x-protobuf")
        .body(reg_buf)
        .send()?;

    if resp.status().is_success() {
        let body = resp.bytes()?;
        let reg_res = RegisterIdentityResponse::decode(body)?;
        println!("✨ Registration Successful! Identity ID: {}", reg_res.id);
    } else {
        println!("❌ Registration Failed: {}", resp.text()?);
        return Ok(());
    }

    // 4. Upload an Encrypted Share
    let payload = b"This is a zero-knowledge encrypted blob.";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().to_string();
    
    // Sign the request: METHOD|PATH|TIMESTAMP|BODY_HASH
    let signature = generate_signature(&signing_key, "POST", "/shares", &timestamp, payload);

    println!("📤 Uploading Share...");
    let resp = client.post(format!("{}/shares", server_url))
        .header("X-Identity", username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", &timestamp)
        .header("X-Signature", signature)
        .header("Content-Type", "application/octet-stream")
        .body(payload.to_vec())
        .send()?;

    if resp.status().is_success() {
        let body = resp.bytes()?;
        let upload_res = UploadResponse::decode(body)?;
        let share_id = upload_res.id;
        println!("✅ Share Uploaded! ID: {}", share_id);

        // 5. Download the Share
        println!("📥 Downloading Share back...");
        let resp = client.get(format!("{}/shares/{}", server_url, share_id)).send()?;
        if resp.status().is_success() {
            let downloaded_payload = resp.bytes()?;
            println!("🎉 Download Successful! Content: {}", String::from_utf8_lossy(&downloaded_payload));
        }
    } else {
        println!("❌ Upload Failed: {}", resp.text()?);
    }

    Ok(())
}

fn solve_pow(username: &str, difficulty: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let hash = hasher.finalize();
        
        let first_64 = u64::from_be_bytes(hash[0..8].try_into().unwrap());
        if first_64.leading_zeros() >= difficulty {
            return nonce;
        }
        nonce += 1;
    }
}

fn generate_signature(key: &SigningKey, method: &str, path: &str, timestamp: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());

    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash_hex);
    let signature = key.sign(signed_data.as_bytes());
    hex::encode(signature.to_bytes())
}
