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
        token: String,
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
                SignalingMessage::Init { device_id, token } => {
                    if crate::devices::validate_token(&token, &state.config.auth.jwt_secret).is_ok() {
                        current_device_id = Some(device_id.clone());
                        let mut peers = state.peers.lock().await;
                        peers.insert(device_id.clone(), tx.clone());
                        tracing::info!("Device {} registered for signaling", device_id);
                        
                        if let Ok(messages) = state.db.get_mailbox_messages(&device_id) {
                            for msg in messages {
                                let _ = tx.send(SignalingMessage::MailboxPush {
                                    payload: msg.payload,
                                });
                            }
                            let _ = state.db.clear_mailbox(&device_id);
                        }
                    } else {
                        let _ = tx.send(SignalingMessage::Error { message: "Invalid token".to_string() });
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
        let mut peers = state.peers.lock().await;
        peers.remove(&device_id);
        tracing::info!("Device {} disconnected from signaling", device_id);
    }
    send_task.abort();
}

async fn route_message(state: &Arc<AppState>, target_id: String, msg: SignalingMessage) {
    let peers = state.peers.lock().await;
    if let Some(tx) = peers.get(&target_id) {
        let _ = tx.send(msg);
    } else {
        tracing::warn!("Target device {} not found for signaling, enqueuing to mailbox", target_id);
        // Queue in Offline Mailbox
        let payload = serde_json::to_vec(&msg).unwrap_or_default();
        if !payload.is_empty() {
            let _ = state.db.enqueue_mailbox_message(&target_id, &payload);
        }
    }
}
