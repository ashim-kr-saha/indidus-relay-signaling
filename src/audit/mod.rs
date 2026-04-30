use crate::{Result, server::AppState, proto::Protobuf};
use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::IntoResponse,
};
use std::sync::Arc;
use indidus_proto::signaling::{AuditLog, AuditLogsList};

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

    let entries = logs.into_iter().map(|l| AuditLog {
        id: l.id,
        event_type: l.event_type,
        metadata: l.metadata,
        created_at: l.created_at,
    }).collect();

    Ok(Protobuf(AuditLogsList { logs: entries }))
}
