use crate::{Error, Result, server::AppState, devices::validate_token};
use axum::{
    extract::{State, Path},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};

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
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(payload): Json<VaultInviteRequest>,
) -> Result<Json<String>> {
    let inviter_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
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
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<Vec<VaultInviteResponse>>> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let invites = state.db.get_pending_vault_invites(&user_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(invites))
}

pub async fn accept_vault_invite(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(invite_id): Path<String>,
) -> Result<Json<()>> {
    let user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    state.db.respond_to_vault_invite(&invite_id, &user_id, "accepted")
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(()))
}

pub async fn list_vault_members(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<VaultMemberResponse>>> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;
    
    let members = state.db.get_vault_members(&vault_id)
        .map_err(|e| Error::Internal(e.to_string()))?;

    Ok(Json(members))
}
