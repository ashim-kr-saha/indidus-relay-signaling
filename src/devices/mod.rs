use crate::{Error, Result, server::AppState};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub identity_id: String, // Which identity to link to
    pub public_key: String,  // Hex encoded
    pub name: Option<String>,
}

// v4.0 uses Stateless Identity

pub async fn register_device(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse> {
    let method_str = method.as_str();
    let path = uri.path();

    let payload: RegisterDeviceRequest =
        serde_json::from_slice(&body).map_err(|e| Error::BadRequest(e.to_string()))?;

    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method_str, path, &body).await?;

    if identity_id != payload.identity_id {
        return Err(Error::Auth("Identity mismatch".to_string()));
    }

    let pk_bytes = hex::decode(&payload.public_key)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    let id = identity_id.clone();
    let name = payload.name.clone();
    let device_id = state
        .db_call(move |db| db.create_device(&id, &pk_bytes, name.as_deref()))
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": device_id })),
    ))
}

pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let id = identity_id.clone();
    let devices = state
        .db_call(move |db| db.get_devices_by_identity(&id))
        .await?;

    Ok(Json(devices))
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let d_id = device_id.clone();
    let id = identity_id.clone();
    state
        .db_call(move |db| db.delete_device(&d_id, &id))
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
