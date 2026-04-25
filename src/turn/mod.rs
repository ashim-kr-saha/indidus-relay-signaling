use crate::{Error, Result, server::AppState};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Method, Uri},
};
use base64::prelude::*;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use std::sync::Arc;

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
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<Json<TurnResponse>> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    // TURN REST API implementation (Time-Limited Credentials)
    // See: https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00

    let ttl = 3600; // 1 hour
    let timestamp = Utc::now().timestamp() + ttl;
    let username = format!("{}:{}", timestamp, identity_id);

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
