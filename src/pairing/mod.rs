use crate::{Error, Result, server::AppState};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct InitiatePairingRequest {
    pub message: Vec<u8>, // SPAKE2 Message A
}

#[derive(Debug, Serialize)]
pub struct InitiatePairingResponse {
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RespondPairingRequest {
    pub message: Vec<u8>, // SPAKE2 Message B
}

#[derive(Debug, Serialize)]
pub struct RespondPairingResponse {
    pub message: Vec<u8>, // SPAKE2 Message A
}

pub async fn initiate_pairing(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InitiatePairingRequest>,
) -> Result<Json<InitiatePairingResponse>> {
    let session_id = Uuid::new_v4().to_string();
    state
        .pairing_sessions
        .insert(session_id.clone(), (payload.message, None));

    Ok(Json(InitiatePairingResponse { session_id }))
}

pub async fn respond_pairing(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<RespondPairingRequest>,
) -> Result<Json<RespondPairingResponse>> {
    if let Some(mut session) = state.pairing_sessions.get_mut(&session_id) {
        let msg_a = session.0.clone();
        session.1 = Some(payload.message);
        Ok(Json(RespondPairingResponse { message: msg_a }))
    } else {
        Err(Error::NotFound)
    }
}

pub async fn poll_pairing(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<u8>>> {
    if let Some(session) = state.pairing_sessions.get(&session_id) {
        if let Some(msg_b) = &session.1 {
            Ok(Json(msg_b.clone()))
        } else {
            Err(Error::BadRequest("Pending response".to_string()))
        }
    } else {
        Err(Error::NotFound)
    }
}
