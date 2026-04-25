use crate::{Error, Result, server::AppState};
use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let logs = state.db.get_audit_logs(&identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(logs))
}
