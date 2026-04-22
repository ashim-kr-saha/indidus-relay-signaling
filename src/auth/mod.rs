use crate::{Error, Result, server::AppState};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;
use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub pow_nonce: u64,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Internal(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let argon2 = Argon2::default();
    let parsed_hash = argon2::password_hash::PasswordHash::new(hash)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

pub fn create_jwt(user_id: &str, secret: &str, ttl_seconds: u64) -> Result<String> {
    let iat = Utc::now();
    let exp = iat + Duration::seconds(ttl_seconds as i64);

    let claims = Claims {
        sub: user_id.to_string(),
        iat: iat.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| Error::Internal(e.to_string()))
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse> {
    // 1. Verify Proof-of-Work
    verify_pow(&payload.username, payload.pow_nonce, state.config.auth.registration_difficulty)?;

    let password_hash = hash_password(&payload.password)?;
    
    state.db.create_user(&payload.username, &password_hash)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    let (user_id, password_hash) = state.db.get_user_by_username(&payload.username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::Auth("Invalid username or password".to_string()))?;

    if !verify_password(&payload.password, &password_hash)? {
        return Err(Error::Auth("Invalid username or password".to_string()));
    }

    let access_token = create_jwt(&user_id, &state.config.auth.jwt_secret, state.config.auth.access_token_ttl)?;
    let refresh_token = Uuid::new_v4().to_string();
    
    let expires_at = Utc::now() + Duration::seconds(state.config.auth.refresh_token_ttl as i64);
    state.db.create_session(&user_id, &refresh_token, expires_at)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse> {
    let (user_id, expires_at, revoked) = state.db.get_session_by_token(&payload.refresh_token)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::Auth("Invalid refresh token".to_string()))?;

    if revoked {
        return Err(Error::Auth("Session revoked".to_string()));
    }

    if Utc::now() > expires_at {
        return Err(Error::Auth("Session expired".to_string()));
    }

    let access_token = create_jwt(&user_id, &state.config.auth.jwt_secret, state.config.auth.access_token_ttl)?;
    
    Ok(Json(json!({
        "access_token": access_token,
    })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<impl IntoResponse> {
    let _user_id = crate::devices::validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    state.db.revoke_session(&payload.refresh_token)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

fn verify_pow(username: &str, nonce: u64, difficulty: u32) -> Result<()> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(nonce.to_be_bytes());
    let result = hasher.finalize();
    
    // Check leading zero bits
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
