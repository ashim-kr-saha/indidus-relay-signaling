use crate::{Error, Result, server::AppState};
use axum::{
    extract::{State, Path},
    http::{HeaderMap, Method, Uri},
    Json,
    body::Bytes,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct VaultInviteRequest {
    pub vault_id: String,
    pub invitee_username: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct VaultMemberResponse {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Debug, Serialize)]
pub struct VaultInviteResponse {
    pub id: String,
    pub vault_id: String,
    pub inviter_username: String,
    pub status: String,
    pub created_at: String,
    pub role: String,
}

pub async fn invite_to_vault(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<String>> {
    let inviter_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body).await?;
    
    let payload: VaultInviteRequest = serde_json::from_slice(&body)
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    let invite_id = state.db.create_vault_invite(
        &payload.vault_id,
        &inviter_id,
        &payload.invitee_username,
        &payload.role,
    ).map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(invite_id))
}

pub async fn list_vault_invites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<Json<Vec<VaultInviteResponse>>> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let invites = state.db.get_pending_vault_invites(&identity_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(invites))
}

pub async fn accept_vault_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(invite_id): Path<String>,
) -> Result<Json<()>> {
    let identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    state.db.respond_to_vault_invite(&invite_id, &identity_id, "accepted")
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(()))
}

pub async fn list_vault_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<VaultMemberResponse>>> {
    let _identity_id = crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[]).await?;
    
    let members = state.db.get_vault_members(&vault_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(members))
}
