use crate::{Result, server::AppState};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
};
use std::sync::Arc;

pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let id = identity_id.clone();
    let logs = state.db_call(move |db| db.get_audit_logs(&id)).await?;

    Ok(Json(logs))
}
