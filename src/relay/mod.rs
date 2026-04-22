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
use chrono::{Utc, Duration};

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    pub payload: Vec<u8>,
    pub ttl_seconds: Option<u64>,
    pub max_views: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub id: String,
}

pub async fn upload_share(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<UploadRequest>,
) -> Result<impl IntoResponse> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let expires_at = payload.ttl_seconds
        .map(|s| Utc::now() + Duration::seconds(s as i64))
        .or_else(|| Some(Utc::now() + Duration::seconds(state.config.relay.default_ttl as i64)));

    let id = state.db.create_share(&payload.payload, expires_at, payload.max_views)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok((StatusCode::CREATED, Json(UploadResponse { id })))
}

pub async fn download_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let share = state.db.get_share(&id)
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    if share.expires_at.is_some_and(|exp| Utc::now() > exp) {
        state.db.delete_share(&id).ok();
        return Err(Error::NotFound);
    }

    if share.max_views.is_some_and(|max| share.view_count >= max) {
        state.db.delete_share(&id).ok();
        return Err(Error::NotFound);
    }

    state.db.increment_share_view_count(&id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(share.payload)
}

pub async fn revoke_share(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    state.db.delete_share(&id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
