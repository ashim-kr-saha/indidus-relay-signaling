use crate::{Error, Result, server::AppState, devices::validate_token};
use axum::{
    extract::State,
    Json,
};
use serde::{Serialize};
use std::sync::Arc;
use chrono::{Utc};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use base64::prelude::*;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Serialize)]
pub struct TurnResponse {
    pub username: String,
    pub password: String,
    pub ttl: u64,
    pub uris: Vec<String>,
}

pub async fn get_turn_credentials(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<TurnResponse>> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;

    // TURN REST API implementation (Time-Limited Credentials)
    // See: https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00
    
    let ttl = 3600; // 1 hour
    let timestamp = Utc::now().timestamp() + ttl;
    let username = format!("{}:{}", timestamp, _user_id);
    
    let mut mac = HmacSha1::new_from_slice(state.config.turn.secret.as_bytes())
        .map_err(|e| Error::Internal(e.to_string()))?;
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let password = BASE64_STANDARD.encode(result.into_bytes());

    Ok(Json(TurnResponse {
        username,
        password,
        ttl: ttl as u64,
        uris: vec![format!("turn:{}", state.config.turn.realm)], // simplified, usually includes port
    }))
}
