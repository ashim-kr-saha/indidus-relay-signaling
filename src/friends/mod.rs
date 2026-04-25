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

    let friend_username = payload.friend_username.clone();
    let friend_identity_id = state.db_call(move |db| db.get_identity_id_by_username(&friend_username)).await
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    if identity_id == friend_identity_id {
        return Err(Error::BadRequest("Cannot add yourself as friend".to_string()));
    }

    let id = identity_id.clone();
    let f_id = friend_identity_id.clone();
    state.db_call(move |db| db.create_friend_request(&id, &f_id)).await
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
    
    let id = identity_id.clone();
    let friends = state.db_call(move |db| db.get_friends(&id)).await
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
    
    let f_name = friend_username.clone();
    let friend_identity_id = state.db_call(move |db| db.get_identity_id_by_username(&f_name)).await
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    let f_id = friend_identity_id.clone();
    let id = identity_id.clone();
    state.db_call(move |db| db.confirm_friendship(&f_id, &id)).await
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
    
    let f_name = friend_username.clone();
    let friend_identity_id = state.db_call(move |db| db.get_identity_id_by_username(&f_name)).await
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    let id = identity_id.clone();
    let f_id = friend_identity_id.clone();
    state.db_call(move |db| db.delete_friend(&id, &f_id)).await
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

    let id = identity_id.clone();
    let f_id = friend_identity_id.clone();
    state.db_call(move |db| db.block_friend(&id, &f_id)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}
