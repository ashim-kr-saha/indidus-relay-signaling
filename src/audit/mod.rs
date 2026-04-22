use crate::{Error, Result, server::AppState, devices::validate_token};
use axum::{
    extract::{State, Json},
    response::IntoResponse,
};
use std::sync::Arc;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};

pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let logs = state.db.get_audit_logs(&user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(logs))
}
