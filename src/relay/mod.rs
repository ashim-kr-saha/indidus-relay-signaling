use crate::{Error, Result, server::AppState};
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap, Method, Uri},
    response::IntoResponse,
    body::Bytes,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body).await?;
    
    let ttl_seconds = headers.get("X-Share-TTL")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    
    let max_views = headers.get("X-Share-Views")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<i32>().ok());

    let expires_at = ttl_seconds
        .map(|s| Utc::now() + Duration::seconds(s as i64))
        .or_else(|| Some(Utc::now() + Duration::seconds(state.config.relay.default_ttl as i64)));

    let id_clone = identity_id.clone();
    let id = state.db_call(move |db| db.create_share(&body, Some(&id_clone), expires_at, max_views)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok((StatusCode::CREATED, axum::Json(UploadResponse { id })))
}

pub async fn download_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let s_id = id.clone();
    let share = state.db_call(move |db| db.get_share(&s_id)).await
        .map_err(|e| Error::Internal(e.to_string()))?
        .ok_or_else(|| Error::NotFound)?;

    if share.expires_at.is_some_and(|exp| Utc::now() > exp) {
        let s_id = id.clone();
        state.db_call(move |db| { db.delete_share(&s_id).ok(); }).await;
        return Err(Error::NotFound);
    }

    if share.max_views.is_some_and(|max| share.view_count >= max) {
        let s_id = id.clone();
        state.db_call(move |db| { db.delete_share(&s_id).ok(); }).await;
        return Err(Error::NotFound);
    }

    let s_id = id.clone();
    state.db_call(move |db| db.increment_share_view_count(&s_id)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(share.payload)
}

pub async fn acknowledge_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let s_id = id.clone();
    state.db_call(move |db| db.delete_share(&s_id)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::OK)
}

pub async fn revoke_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let _identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    // TODO: Verify identity_id owns the share
    
    let s_id = id.clone();
    state.db_call(move |db| db.delete_share(&s_id)).await
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
