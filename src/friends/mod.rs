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
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<FriendRequest>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let (friend_id, _) = state.db.get_user_by_username(&payload.friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    if user_id == friend_id {
        return Err(Error::BadRequest("Cannot add yourself as friend".to_string()));
    }

    state.db.create_friend_request(&user_id, &friend_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn list_friends(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let friends = state.db.get_friends(&user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(friends))
}

pub async fn accept_friend_request(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let (friend_id, _) = state.db.get_user_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.confirm_friendship(&friend_id, &user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

pub async fn remove_friend(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let (friend_id, _) = state.db.get_user_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.delete_friend(&user_id, &friend_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn block_friend(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let (friend_id, _) = state.db.get_user_by_username(&friend_username)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    state.db.block_friend(&user_id, &friend_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}
