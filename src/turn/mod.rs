use crate::{Error, Result, server::AppState, proto::Protobuf};
use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
};
use base64::prelude::*;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::sync::Arc;
use indidus_proto::signaling::TurnResponse;

type HmacSha1 = Hmac<Sha1>;

pub async fn get_turn_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    // TURN REST API implementation (Time-Limited Credentials)
    // See: https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00

    let ttl = 3600; // 1 hour
    let timestamp = Utc::now().timestamp() + ttl;
    let username = format!("{}:{}", timestamp, identity_id);

    let mut mac = HmacSha1::new_from_slice(state.config.turn.secret.as_bytes())
        .map_err(|e: hmac::digest::InvalidLength| Error::Internal(e.to_string()))?;
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let password = BASE64_STANDARD.encode(result.into_bytes());

    Ok(Protobuf(TurnResponse {
        username,
        password,
        ttl: ttl as u64,
        uris: vec![format!("turn:{}", state.config.turn.realm)], // simplified, usually includes port
    }))
}
