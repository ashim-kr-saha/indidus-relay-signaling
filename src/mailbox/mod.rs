use crate::{Error, Result, server::AppState};
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap, Method, Uri},
    response::IntoResponse,
    body::Bytes,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let _identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body).await?;
    
    let payload: EnqueueRequest = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    state.db.enqueue_mailbox_message(&payload.target_device_id, &payload.payload)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn get_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse> {
    let _identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    // TODO: Verify identity_id owns device_id
    
    let messages = state.db.get_mailbox_messages(&device_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    // Atomically clear mailbox after retrieval
    state.db.clear_mailbox(&device_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(axum::Json(messages))
}
