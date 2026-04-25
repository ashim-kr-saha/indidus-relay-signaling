use crate::{Error, Result, server::AppState};
use serde::Deserialize;
use chrono::{Utc};
use axum::{
    extract::{State, Json},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
};
use std::sync::Arc;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Sha256, Digest};

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
    verify_pow(&payload.username, payload.pow_nonce, state.config.auth.registration_difficulty)?;

    // 2. Decode Public Key
    let public_key_bytes = hex::decode(&payload.root_public_key)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    if public_key_bytes.len() != 32 {
        return Err(Error::BadRequest("Public key must be 32 bytes".to_string()));
    }

    // 3. Create Identity
    let username = payload.username.clone();
    let pk1 = public_key_bytes.clone();
    let pk2 = public_key_bytes.clone();
    let identity_id = state.db_call(move |db| db.create_identity(&username, &pk1)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    // 4. Register the root key as the first device
    let id = identity_id.clone();
    state.db_call(move |db| db.create_device(&id, &pk2, Some("Primary Device"))).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
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
    let req_time = timestamp.parse::<i64>()
        .map_err(|_| Error::Auth("Invalid timestamp".to_string()))?;
    let now = Utc::now().timestamp();
    if (now - req_time).abs() > 60 {
        return Err(Error::Auth("Request expired".to_string()));
    }

    // 2. Parse Public Key and Signature
    let public_key = VerifyingKey::from_bytes(
        public_key_bytes.try_into().map_err(|_| Error::Internal("Invalid key length".to_string()))?
    ).map_err(|e| Error::Auth(format!("Invalid public key: {}", e)))?;

    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| Error::Auth("Invalid signature hex".to_string()))?;
    let signature = Signature::from_bytes(
        signature_bytes.as_slice().try_into().map_err(|_| Error::Auth("Invalid signature length".to_string()))?
    );

    // 3. Reconstruct signed data
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());

    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);

    // 4. Verify
    public_key.verify(signed_data.as_bytes(), &signature)
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
    let identity_id = headers.get("X-Identity")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Identity".to_string()))?;
    
    let timestamp = headers.get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Timestamp".to_string()))?;

    let signature = headers.get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Signature".to_string()))?;

    let device_pk_hex = headers.get("X-Public-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::Auth("Missing X-Public-Key".to_string()))?;

    let device_pk_bytes = hex::decode(device_pk_hex)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    // 1. Verify signature
    validate_request_signature(&device_pk_bytes, method, path, timestamp, body, signature)?;

    // 2. Check if device key belongs to identity
    let pk = device_pk_bytes.clone();
    let info = state.db_call(move |db| db.get_identity_by_public_key(&pk)).await
        .map_err(|e| Error::Internal(e.to_string()))?
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
    
    let mut leading_zeros = 0;
    for byte in result {
        let zeros = byte.leading_zeros();
        leading_zeros += zeros;
        if zeros < 8 {
            break;
        }
    }
    
    if leading_zeros < difficulty {
        return Err(Error::BadRequest("Insufficient Proof-of-Work".to_string()));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
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
        assert!(validate_request_signature(pk_bytes, method, path, &ts_str, body, &sig_hex).is_ok());
        
        // Invalid method
        assert!(validate_request_signature(pk_bytes, "GET", path, &ts_str, body, &sig_hex).is_err());
        // Invalid body
        assert!(validate_request_signature(pk_bytes, method, path, &ts_str, b"wrong", &sig_hex).is_err());
        // Expired
        let old_timestamp = (timestamp - 400).to_string();
        assert!(validate_request_signature(pk_bytes, method, path, &old_timestamp, body, &sig_hex).is_err());
    }
}
