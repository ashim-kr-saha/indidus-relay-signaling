use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use serde_json::json;
use std::env;
use reqwest::blocking::Client;

fn main() {
    let args: Vec<String> = env::args().collect();
    let pin = args.iter().position(|r| r == "--pin").and_then(|i| args.get(i + 1)).map(|s| s.as_str()).unwrap_or("1234");
    let data = args.iter().position(|r| r == "--data").and_then(|i| args.get(i + 1)).map(|s| s.as_str()).unwrap_or("Hello from Indidus!");
    let server_url = "http://127.0.0.1:8080";

    println!("--- Indidus Share Generator ---");
    println!("PIN: {}", pin);
    println!("Data: {}", data);

    // 1. Generate random URL key (the one in # fragment)
    let key_url = "testkey1234567890123456789012345"; // 32 chars
    let key_url_bytes = key_url.as_bytes();

    // 2. Derive Blob Key from PIN + key_url (Salt)
    let salt = SaltString::encode_b64(key_url_bytes).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).unwrap(),
    );
    let hash = argon2.hash_password(pin.as_bytes(), &salt).expect("Argon2 failed");
    let blob_key_bytes = hash.hash.unwrap();

    // 3. Encrypt data
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(blob_key_bytes.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).expect("Encryption failed");

    // 4. Prepare payload (Nonce + Ciphertext)
    let mut full_payload = nonce.to_vec();
    full_payload.extend_from_slice(&ciphertext);

    // 5. Upload to local server
    println!("\nEnter a valid access token (get it from auth_tests or manual login):");
    let mut token = String::new();
    std::io::stdin().read_line(&mut token).unwrap();
    let token = token.trim();

    let client = Client::new();
    let resp = client.post(format!("{}/shares", server_url))
        .bearer_auth(token)
        .json(&json!({
            "payload": full_payload,
            "ttl_seconds": 3600,
            "max_views": 1
        }))
        .send().expect("Request failed");

    if resp.status().is_success() {
        let res: serde_json::Value = resp.json().unwrap();
        let id = res["id"].as_str().unwrap();
        println!("\nSUCCESS!");
        println!("Share ID: {}", id);
        println!("Test URL: http://localhost:3000/index.html#key={}&pin=1", hex::encode(key_url_bytes));
    } else {
        println!("Failed to upload: {}", resp.text().unwrap());
    }
}
