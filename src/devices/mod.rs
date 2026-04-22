use crate::{Error, Result, server::AppState, auth::Claims};
use axum::{
    extract::{State, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub public_key: Vec<u8>,
    pub name: Option<String>,
}

// Middleware-like function to validate JWT
pub fn validate_token(token: &str, secret: &str) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| Error::Auth("Invalid token".to_string()))?;

    Ok(token_data.claims.sub)
}

pub async fn register_device(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let device_id = state.db.create_device(&user_id, &payload.public_key, payload.name.as_deref())
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok((StatusCode::CREATED, Json(json!({ "id": device_id }))))
}

pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let devices = state.db.get_devices_by_user(&user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(devices))
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    state.db.delete_device(&device_id, &user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

use serde_json::json;
