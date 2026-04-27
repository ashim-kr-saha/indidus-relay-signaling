use crate::{Error, Result, server::AppState};
use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RegisterIdentityRequest {
    pub username: String,
    pub root_public_key: String, // Hex encoded
    pub pow_nonce: u64,
}

pub async fn register_identity(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterIdentityRequest>,
) -> Result<impl IntoResponse> {
    // 1. Verify Proof-of-Work
    verify_pow(
        &payload.username,
        payload.pow_nonce,
        state.config.auth.registration_difficulty,
    )?;

    // 2. Decode Public Key
    let public_key_bytes = hex::decode(&payload.root_public_key)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    if public_key_bytes.len() != 32 {
        return Err(Error::BadRequest("Public key must be 32 bytes".to_string()));
    }

    let username = payload.username.clone();
    let pk = public_key_bytes.clone();
    let identity_id = state
        .db_call(move |db| db.create_identity_with_primary_device(&username, &pk))
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": identity_id })),
    ))
}

/// Validates a request signature.
///
/// Payload string to sign: METHOD|PATH|TIMESTAMP|BODY_HASH
pub fn validate_request_signature(
    public_key_bytes: &[u8],
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
    signature_hex: &str,
) -> Result<()> {
    // 1. Check timestamp drift (+/- 60 seconds)
    let req_time = timestamp
        .parse::<i64>()
        .map_err(|_| Error::Auth("Invalid timestamp".to_string()))?;
    let now = Utc::now().timestamp();
    if (now - req_time).abs() > 60 {
        return Err(Error::Auth("Request expired".to_string()));
    }

    // 2. Parse Public Key and Signature
    let public_key = VerifyingKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| Error::Internal("Invalid key length".to_string()))?,
    )
    .map_err(|e| Error::Auth(format!("Invalid public key: {}", e)))?;

    let signature_bytes =
        hex::decode(signature_hex).map_err(|_| Error::Auth("Invalid signature hex".to_string()))?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Auth("Invalid signature length".to_string()))?,
    );

    // 3. Reconstruct signed data (METHOD|PATH|TIMESTAMP|BODY_HASH)
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_bytes = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash_bytes);

    let mut signed_data = String::with_capacity(
        method.len() + path.len() + timestamp.len() + body_hash_hex.len() + 4,
    );
    signed_data.push_str(method);
    signed_data.push('|');
    signed_data.push_str(path);
    signed_data.push('|');
    signed_data.push_str(timestamp);
    signed_data.push('|');
    signed_data.push_str(&body_hash_hex);

    // 4. Verify
    public_key
        .verify(signed_data.as_bytes(), &signature)
        .map_err(|_| Error::Auth("Signature verification failed".to_string()))?;

    Ok(())
}

/// Helper for identity-authenticated endpoints.
///
/// Returns identity_id if successful.
pub async fn authenticate_identity(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String> {
    let identity_id = headers
        .get("X-Identity")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Identity".to_string()))?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Timestamp".to_string()))?;

    let signature = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Signature".to_string()))?;

    let device_pk_hex = headers
        .get("X-Public-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Public-Key".to_string()))?;

    let device_pk_bytes = hex::decode(device_pk_hex)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    // 1. Verify signature
    validate_request_signature(&device_pk_bytes, method, path, timestamp, body, signature)?;

    // 2. Check if device key belongs to identity
    let pk = device_pk_bytes.clone();
    let info = state
        .db_call(move |db| db.get_identity_by_public_key(&pk))
        .await?
        .ok_or_else(|| Error::Auth("Device not recognized".to_string()))?;

    if info.username != identity_id {
        return Err(Error::Auth("Identity mismatch".to_string()));
    }

    Ok(info.id)
}

fn verify_pow(username: &str, nonce: u64, difficulty: u32) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(nonce.to_be_bytes());
    let result = hasher.finalize();

    if !check_difficulty_fast(&result, difficulty) {
        return Err(Error::BadRequest("Insufficient Proof-of-Work".to_string()));
    }

    Ok(())
}

#[inline(always)]
fn check_difficulty_fast(hash: &[u8], difficulty: u32) -> bool {
    let first_64 = u64::from_be_bytes(hash[0..8].try_into().unwrap());

    if difficulty <= 64 {
        return first_64.leading_zeros() >= difficulty;
    }

    if first_64 != 0 {
        return false;
    }

    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    for &byte in &hash[8..full_bytes] {
        if byte != 0 {
            return false;
        }
    }

    if remaining_bits > 0 && (hash[full_bytes] >> (8 - remaining_bits)) != 0 {
        return false;
    }

    true
}

pub fn verify_signature(message: &str, public_key_bytes: &[u8], signature_bytes: &[u8]) -> bool {
    let public_key =
        match VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap_or(&[0u8; 32])) {
            Ok(k) => k,
            Err(_) => return false,
        };
    let signature = Signature::from_bytes(signature_bytes.try_into().unwrap_or(&[0u8; 64]));
    public_key.verify(message.as_bytes(), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::thread_rng;

    #[test]
    fn test_pow_verification() {
        let username = "testuser";
        let difficulty = 8; // Small difficulty for fast test

        // Solve it
        let mut nonce: u64 = 0;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(username.as_bytes());
            hasher.update(nonce.to_be_bytes());
            let result = hasher.finalize();

            let mut leading_zeros = 0;
            for byte in result {
                let zeros = byte.leading_zeros();
                leading_zeros += zeros;
                if zeros < 8 {
                    break;
                }
            }
            if leading_zeros >= difficulty {
                break;
            }
            nonce += 1;
        }

        assert!(verify_pow(username, nonce, difficulty).is_ok());
        assert!(verify_pow(username, nonce + 1, difficulty).is_err());
    }

    #[test]
    fn test_signature_validation() {
        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key();
        let pk_bytes = public_key.as_bytes();

        let method = "POST";
        let path = "/test";
        let timestamp = Utc::now().timestamp() as u64;
        let body = b"hello world";

        let mut hasher = Sha256::new();
        hasher.update(body);
        let body_hash = hex::encode(hasher.finalize());

        let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);
        let signature = signing_key.sign(signed_data.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        let ts_str = timestamp.to_string();
        assert!(
            validate_request_signature(pk_bytes, method, path, &ts_str, body, &sig_hex).is_ok()
        );

        // Invalid method
        assert!(
            validate_request_signature(pk_bytes, "GET", path, &ts_str, body, &sig_hex).is_err()
        );
        // Invalid body
        assert!(
            validate_request_signature(pk_bytes, method, path, &ts_str, b"wrong", &sig_hex)
                .is_err()
        );
        // Expired
        let old_timestamp = (timestamp - 400).to_string();
        assert!(
            validate_request_signature(pk_bytes, method, path, &old_timestamp, body, &sig_hex)
                .is_err()
        );
    }
}
