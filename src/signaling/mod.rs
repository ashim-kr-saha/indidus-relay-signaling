use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::server::AppState;
use futures::{sink::SinkExt, stream::StreamExt};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    #[serde(rename = "init")]
    Init {
        device_id: String,
        identity_id: String,
        timestamp: String,
        public_key: String, // Hex encoded Device Public Key
        signature: String,  // Hex encoded signature over "WS_INIT|device_id|identity_id|timestamp"
    },
    #[serde(rename = "offer")]
    Offer {
        target_device_id: String,
        sdp: String,
        from_device_id: Option<String>,
    },
    #[serde(rename = "answer")]
    Answer {
        target_device_id: String,
        sdp: String,
        from_device_id: Option<String>,
    },
    #[serde(rename = "candidate")]
    Candidate {
        target_device_id: String,
        candidate: String,
        from_device_id: Option<String>,
    },
    #[serde(rename = "init_success")]
    InitSuccess,
    #[serde(rename = "error")]
    Error {
        message: String,
    },
    #[serde(rename = "mailbox_push")]
    MailboxPush {
        payload: Vec<u8>,
    },
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<SignalingMessage>();

    let mut current_device_id: Option<String> = None;

    // Task for sending messages to this WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let text = serde_json::to_string(&msg).unwrap();
            if ws_sender.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(msg)) = ws_receiver.next().await {
        let text = match msg {
            Message::Text(t) => t,
            _ => continue,
        };

        if let Ok(sig_msg) = serde_json::from_str::<SignalingMessage>(&text) {
            match sig_msg {
                SignalingMessage::Init { device_id, identity_id, timestamp, public_key, signature } => {
                    let pk_bytes = hex::decode(&public_key).unwrap_or_default();
                    
                    let mut is_valid = false;
                    if let Ok(Some(info)) = state.db.get_identity_by_public_key(&pk_bytes) {
                        if info.username == identity_id && crate::auth::validate_request_signature(&pk_bytes, "WS_INIT", &device_id, &timestamp, identity_id.as_bytes(), &signature).is_ok() {
                            is_valid = true;
                        }
                    }

                    if is_valid {
                        current_device_id = Some(device_id.clone());
                        state.peers.insert(device_id.clone(), tx.clone());
                        tracing::info!("Device {} registered for signaling", device_id);
                        
                        let _ = tx.send(SignalingMessage::InitSuccess);

                        let state_clone = Arc::clone(&state);
                        let d_id = device_id.clone();
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let s_c = Arc::clone(&state_clone);
                            let d_id_c = d_id.clone();
                            if let Ok(messages) = tokio::task::spawn_blocking(move || s_c.db.get_mailbox_messages(&d_id_c)).await.unwrap() {
                                for msg in messages {
                                    let _ = tx_clone.send(SignalingMessage::MailboxPush {
                                        payload: msg.payload,
                                    });
                                }
                                let s_c2 = Arc::clone(&state_clone);
                                let d_id_c2 = d_id.clone();
                                let _ = tokio::task::spawn_blocking(move || s_c2.db.clear_mailbox(&d_id_c2)).await;
                            }
                        });
                    } else {
                        let _ = tx.send(SignalingMessage::Error { message: "Invalid signature or device key".to_string() });
                    }
                }
                SignalingMessage::Offer { target_device_id, sdp, .. } => {
                    if let Some(from_id) = &current_device_id {
                        route_message(&state, target_device_id.clone(), SignalingMessage::Offer {
                            target_device_id: target_device_id.clone(),
                            sdp,
                            from_device_id: Some(from_id.clone()),
                        }).await;
                    }
                }
                SignalingMessage::Answer { target_device_id, sdp, .. } => {
                    if let Some(from_id) = &current_device_id {
                        route_message(&state, target_device_id.clone(), SignalingMessage::Answer {
                            target_device_id: target_device_id.clone(),
                            sdp,
                            from_device_id: Some(from_id.clone()),
                        }).await;
                    }
                }
                SignalingMessage::Candidate { target_device_id, candidate, .. } => {
                    if let Some(from_id) = &current_device_id {
                        route_message(&state, target_device_id.clone(), SignalingMessage::Candidate {
                            target_device_id: target_device_id.clone(),
                            candidate,
                            from_device_id: Some(from_id.clone()),
                        }).await;
                    }
                }
                _ => {}
            }
        }
    }

    // Cleanup
    if let Some(device_id) = current_device_id {
        state.peers.remove(&device_id);
        tracing::info!("Device {} disconnected from signaling", device_id);
    }
    send_task.abort();
}

pub async fn route_message(state: &Arc<AppState>, target_id: String, msg: SignalingMessage) {
    if let Some(tx) = state.peers.get(&target_id) {
        let _ = tx.send(msg);
    } else {
        tracing::warn!("Target device {} not found for signaling, enqueuing to mailbox", target_id);
        // Queue in Offline Mailbox
        let payload = serde_json::to_vec(&msg).unwrap_or_default();
        if !payload.is_empty() {
            let state_clone = Arc::clone(state);
            let t_id = target_id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                state_clone.db.enqueue_mailbox_message(&t_id, &payload)
            }).await;
        }
    }
}
