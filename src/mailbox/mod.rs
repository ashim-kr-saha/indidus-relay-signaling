use crate::{Error, Result, server::AppState, devices::validate_token};
use axum::{
    extract::{State, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};

#[derive(Debug, Deserialize)]
pub struct EnqueueRequest {
    pub target_device_id: String,
    pub payload: Vec<u8>, // encrypted
}

#[derive(Debug, Serialize)]
pub struct MailboxMessage {
    pub id: String,
    pub payload: Vec<u8>,
    pub created_at: String,
}

pub async fn enqueue_message(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<EnqueueRequest>,
) -> Result<impl IntoResponse> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    state.db.enqueue_mailbox_message(&payload.target_device_id, &payload.payload)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn get_mailbox(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let messages = state.db.get_mailbox_messages(&device_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    // Atomically clear mailbox after retrieval
    state.db.clear_mailbox(&device_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(messages))
}
