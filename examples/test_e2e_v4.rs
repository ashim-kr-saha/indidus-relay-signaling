use reqwest::blocking::Client;
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::json;

fn solve_pow(username: &str, difficulty: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();
        
        let mut zero_bits = 0;
        for byte in result {
            if byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
        }
        
        if zero_bits >= difficulty {
            return nonce;
        }
        nonce += 1;
    }
}

fn generate_signature(
    private_key_bytes: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());
    
    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);
    
    let signing_key = SigningKey::from_bytes(private_key_bytes.try_into().unwrap());
    let signature = signing_key.sign(signed_data.as_bytes());
    hex::encode(signature.to_bytes())
}

fn main() {
    let client = Client::new();
    let base_url = "http://127.0.0.1:8080";
    let username = format!("testuser_{}", uuid::Uuid::new_v4());
    
    println!("Testing E2E v4.0 for user: {}", username);
    
    // 1. Generate Identity
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(public_key.as_bytes());
    
    // 2. Solve PoW
    println!("Solving PoW (difficulty 16)...");
    let pow_nonce = solve_pow(&username, 16);
    println!("PoW solved: {}", pow_nonce);
    
    // 3. Register Identity
    println!("Registering identity...");
    let res = client.post(format!("{}/register", base_url))
        .json(&json!({
            "username": username,
            "root_public_key": public_key_hex,
            "pow_nonce": pow_nonce
        }))
        .send().expect("Failed to send register request");
    
    let status = res.status();
    if status != 201 {
        panic!("Registration failed with status {}: {}", status, res.text().unwrap());
    }
    println!("Registration successful!");
    
    // 4. Upload Share
    let body = b"encrypted_payload_here";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    println!("Uploading share...");
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "POST",
        "/shares",
        timestamp,
        body
    );
    
    let res = client.post(format!("{}/shares", base_url))
        .header("X-Identity", &username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .body(body.to_vec())
        .send().expect("Failed to upload share");
    
    let status = res.status();
    if status != 201 {
        panic!("Upload failed with status {}: {}", status, res.text().unwrap());
    }
    let upload_res: serde_json::Value = res.json().unwrap();
    let share_id = upload_res["id"].as_str().unwrap().to_string();
    println!("Upload successful! Share ID: {}", share_id);
    
    // 5. Download Share (Anonymous)
    println!("Downloading share...");
    let res = client.get(format!("{}/shares/{}", base_url, share_id))
        .send().expect("Failed to download share");
    
    assert_eq!(res.status(), 200, "Download failed");
    assert_eq!(res.bytes().unwrap(), body.as_slice());
    println!("Download successful!");

    // 6. Test Viewer Routes
    println!("Testing viewer routes...");
    let res = client.get(format!("{}/v/{}", base_url, share_id))
        .send().expect("Failed to get viewer");
    assert_eq!(res.status(), 200);
    println!("Viewer HTML route works!");

    // Note: We might not have the exact filename, but we can check if /pkg/ exists
    // Let's try the common one from wasm-pack
    let res = client.get(format!("{}/pkg/indidus_wasm_share_client.js", base_url))
        .send().expect("Failed to get JS asset");
    if res.status() == 200 {
        println!("Viewer JS asset route works!");
    } else {
        println!("Viewer JS asset route returned {}, (this is expected if wasm is not yet built in assets/pkg/)", res.status());
    }
    
    // 7. Revoke Share (Authenticated)
    println!("Revoking share...");
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let signature = generate_signature(
        &signing_key.to_bytes(),
        "DELETE",
        &format!("/shares/{}", share_id),
        timestamp,
        &[]
    );

    let res = client.delete(format!("{}/shares/{}", base_url, share_id))
        .header("X-Identity", &username)
        .header("X-Public-Key", &public_key_hex)
        .header("X-Timestamp", timestamp.to_string())
        .header("X-Signature", signature)
        .send().expect("Failed to revoke share");

    assert_eq!(res.status(), 204, "Revocation failed");
    println!("Revocation successful!");

    // Verify it's gone
    let res = client.get(format!("{}/shares/{}", base_url, share_id))
        .send().expect("Failed to check deleted share");
    assert_eq!(res.status(), 404);
    println!("Verification: Share is gone.");

    println!("E2E Test Passed!");
}
