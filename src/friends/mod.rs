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
pub struct FriendRequest {
    pub friend_username: String,
}

#[derive(Debug, Serialize)]
pub struct FriendResponse {
    pub username: String,
    pub status: String,
    pub last_active: Option<String>,
}

pub async fn send_friend_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body).await?;
    
    let payload: FriendRequest = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    let friend_identity_id = state.db.get_identity_id_by_username(&payload.friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    if identity_id == friend_identity_id {
        return Err(Error::BadRequest("Cannot add yourself as friend".to_string()));
    }

    state.db.create_friend_request(&identity_id, &friend_identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn list_friends(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let friends = state.db.get_friends(&identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(axum::Json(friends))
}

pub async fn accept_friend_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let friend_identity_id = state.db.get_identity_id_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.confirm_friendship(&friend_identity_id, &identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

pub async fn remove_friend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let friend_identity_id = state.db.get_identity_id_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.delete_friend(&identity_id, &friend_identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn block_friend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let friend_identity_id = state.db.get_identity_id_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.block_friend(&identity_id, &friend_identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}
