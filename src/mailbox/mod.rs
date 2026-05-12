use crate::{Error, Result, proto::Protobuf, server::AppState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
};
use indidus_relay_proto::signaling::{MailboxEnqueueRequest, MailboxEntry, MailboxResponse};
use prost::Message;
use std::sync::Arc;

pub async fn enqueue_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    if body.len() > 1024 * 1024 {
        return Err(Error::BadRequest(
            "Mailbox message too large (max 1MB)".to_string(),
        ));
    }
    let _identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body)
            .await?;

    let payload =
        MailboxEnqueueRequest::decode(body).map_err(|e| Error::BadRequest(e.to_string()))?;

    let t_id = payload.target_device_id.clone();
    let data = payload.payload.clone();
    state
        .db_call(move |db| db.enqueue_mailbox_message(&t_id, &data))
        .await?;

    Ok(StatusCode::CREATED)
}

pub async fn get_mailbox(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse> {
    let _identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    // TODO: Verify identity_id owns device_id

    let d_id = device_id.clone();
    let messages = state
        .db_call(move |db| db.get_and_clear_mailbox(&d_id))
        .await?;

    let entries = messages
        .into_iter()
        .map(|m| MailboxEntry {
            id: m.id,
            payload: m.payload,
            created_at: m.created_at,
        })
        .collect();

    let response = MailboxResponse { messages: entries };
    Ok(Protobuf(response))
}
