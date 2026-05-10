use crate::{Error, Result, proto::Protobuf, server::AppState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
};
use indidus_proto::signaling::{
    DeviceInfo, DeviceListResponse, RegisterDeviceRequest, RegisterDeviceResponse,
};
use prost::Message;
use std::sync::Arc;

pub async fn register_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let payload = RegisterDeviceRequest::decode(body.clone())
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body)
            .await?;

    if identity_id != payload.identity_id {
        return Err(Error::Auth("Identity mismatch".to_string()));
    }

    let pk_bytes = hex::decode(&payload.public_key)
        .map_err(|_| Error::BadRequest("Invalid public key hex".to_string()))?;

    let id = identity_id.clone();
    let name = payload.name.clone();
    let version = payload.protocol_version;
    let device_id = state
        .db_call(move |db| db.create_device(&id, &pk_bytes, name.as_deref(), version))
        .await?;

    let response = RegisterDeviceResponse { id: device_id };
    Ok((StatusCode::CREATED, Protobuf(response)))
}

pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let id = identity_id.clone();
    let devices = state
        .db_call(move |db| db.get_devices_by_identity(&id))
        .await?;

    let device_infos = devices
        .into_iter()
        .map(|d| DeviceInfo {
            id: d.id,
            public_key: d.public_key,
            name: d.name,
            last_active: d.last_active,
            protocol_version: d.protocol_version,
        })
        .collect();

    let response = DeviceListResponse {
        devices: device_infos,
    };
    Ok(Protobuf(response))
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
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
