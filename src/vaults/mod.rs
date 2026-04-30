use crate::{Error, Result, server::AppState, proto::Protobuf};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
};
use std::sync::Arc;
use indidus_proto::signaling::{
    VaultInviteRequest, VaultInvitesList, VaultInviteResponse, 
    VaultMembersList, VaultMemberResponse
};
use prost::Message;

pub async fn invite_to_vault(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<impl IntoResponse> {
    let inviter_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &body)
            .await?;

    let payload = VaultInviteRequest::decode(body).map_err(|e| Error::BadRequest(e.to_string()))?;

    let v_id = payload.vault_id.clone();
    let i_id = inviter_id.clone();
    let i_user = payload.invitee_username.clone();
    let role = payload.role.clone();
    let invite_id = state
        .db_call(move |db| db.create_vault_invite(&v_id, &i_id, &i_user, &role))
        .await?;

    Ok((StatusCode::CREATED, invite_id))
}

pub async fn list_vault_invites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let id = identity_id.clone();
    let invites = state
        .db_call(move |db| db.get_pending_vault_invites(&id))
        .await?;

    let entries = invites.into_iter().map(|i| VaultInviteResponse {
        id: i.id,
        vault_id: i.vault_id,
        inviter_username: i.inviter_username,
        status: i.status,
        created_at: i.created_at,
        role: i.role,
    }).collect();

    Ok(Protobuf(VaultInvitesList { invites: entries }))
}

pub async fn accept_vault_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(invite_id): Path<String>,
) -> Result<impl IntoResponse> {
    let identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let inv_id = invite_id.clone();
    let id = identity_id.clone();
    state
        .db_call(move |db| db.respond_to_vault_invite(&inv_id, &id, "accepted"))
        .await?;

    Ok(StatusCode::OK)
}

pub async fn list_vault_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(vault_id): Path<String>,
) -> Result<impl IntoResponse> {
    let _identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let v_id = vault_id.clone();
    let members = state.db_call(move |db| db.get_vault_members(&v_id)).await?;

    let entries = members.into_iter().map(|m| VaultMemberResponse {
        user_id: m.user_id,
        username: m.username,
        role: m.role,
        joined_at: m.joined_at,
    }).collect();

    Ok(Protobuf(VaultMembersList { members: entries }))
}
