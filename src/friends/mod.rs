use crate::{Error, Result, proto::Protobuf, server::AppState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
};
use indidus_relay_proto::signaling::{FriendRequest, FriendResponse, FriendsList};
use prost::Message;
use std::sync::Arc;

pub async fn send_friend_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body)
            .await?;

    let payload = FriendRequest::decode(body).map_err(|e| Error::BadRequest(e.to_string()))?;

    let friend_username = payload.target_username.clone();
    let friend_identity_id = state
        .db_call(move |db| db.get_identity_id_by_username(&friend_username))
        .await?
        .ok_or_else(|| Error::NotFound)?;

    if identity_id == friend_identity_id {
        return Err(Error::BadRequest(
            "Cannot add yourself as friend".to_string(),
        ));
    }

    let id = identity_id.clone();
    let f_id = friend_identity_id.clone();
    state
        .db_call(move |db| db.create_friend_request(&id, &f_id))
        .await?;

    Ok(StatusCode::CREATED)
}

pub async fn list_friends(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let id = identity_id.clone();
    let friends = state.db_call(move |db| db.get_friends(&id)).await?;

    let entries = friends
        .into_iter()
        .map(|f| FriendResponse {
            username: f.username,
            status: f.status,
            last_active: f.last_active,
        })
        .collect();

    Ok(Protobuf(FriendsList { friends: entries }))
}

pub async fn accept_friend_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let f_id = state
        .db_call(move |db| db.get_identity_id_by_username(&friend_username))
        .await?
        .ok_or_else(|| Error::NotFound)?;

    let id = identity_id.clone();
    state
        .db_call(move |db| db.confirm_friendship(&f_id, &id))
        .await?;

    Ok(StatusCode::OK)
}

pub async fn remove_friend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let f_id = state
        .db_call(move |db| db.get_identity_id_by_username(&friend_username))
        .await?
        .ok_or_else(|| Error::NotFound)?;

    let id = identity_id.clone();
    state
        .db_call(move |db| db.delete_friend(&id, &f_id))
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn block_friend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(friend_username): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let f_id = state
        .db_call(move |db| db.get_identity_id_by_username(&friend_username))
        .await?
        .ok_or_else(|| Error::NotFound)?;

    let id = identity_id.clone();
    state.db_call(move |db| db.block_friend(&id, &f_id)).await?;

    Ok(StatusCode::OK)
}
