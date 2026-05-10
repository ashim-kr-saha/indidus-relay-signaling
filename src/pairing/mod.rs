use crate::{Error, Result, proto::Protobuf, server::AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use indidus_proto::signaling::{
    InitiatePairingRequest, InitiatePairingResponse, PairingPollResponse, RespondPairingRequest,
    RespondPairingResponse,
};
use std::sync::Arc;
use uuid::Uuid;

pub async fn initiate_pairing(
    State(state): State<Arc<AppState>>,
    Protobuf(payload): Protobuf<InitiatePairingRequest>,
) -> Result<impl IntoResponse> {
    let session_id = Uuid::new_v4().to_string();
    state
        .pairing_sessions
        .insert(session_id.clone(), (payload.message, None));

    Ok(Protobuf(InitiatePairingResponse { session_id }))
}

pub async fn respond_pairing(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Protobuf(payload): Protobuf<RespondPairingRequest>,
) -> Result<impl IntoResponse> {
    if let Some(session) = state.pairing_sessions.get(&session_id) {
        let msg_a = session.0.clone();
        state
            .pairing_sessions
            .insert(session_id, (msg_a.clone(), Some(payload.message)));
        Ok(Protobuf(RespondPairingResponse { message: msg_a }))
    } else {
        Err(Error::NotFound)
    }
}

pub async fn poll_pairing(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse> {
    if let Some(session) = state.pairing_sessions.get(&session_id) {
        if let Some(msg_b) = &session.1 {
            Ok(Protobuf(PairingPollResponse {
                message: msg_b.clone(),
            }))
        } else {
            Err(Error::BadRequest("Pending response".to_string()))
        }
    } else {
        Err(Error::NotFound)
    }
}
