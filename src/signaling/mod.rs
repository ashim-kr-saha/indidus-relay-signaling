use crate::server::AppState;
use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingMessage {
    Init {
        device_id: String,
        identity_id: String,
        timestamp: u64,
        signature: String,
    },
    InitSuccess,
    Offer {
        target_device_id: String,
        sdp: String,
        from_device_id: Option<String>,
    },
    Answer {
        target_device_id: String,
        sdp: String,
        from_device_id: Option<String>,
    },
    Candidate {
        target_device_id: String,
        candidate: String,
        from_device_id: Option<String>,
    },
    MailboxPush {
        payload: Vec<u8>,
    },
    Error {
        message: String,
    },
}

pub async fn signaling_handler(
    ws: WebSocketUpgrade,
    _headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<SignalingMessage>(100);

    // Send task
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json = serde_json::to_string(&msg).unwrap_or_default();
            if sender.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    let mut current_device_id: Option<String> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            // Enforce 128KB limit per message
            if text.len() > 128 * 1024 {
                let _ = tx
                    .send(SignalingMessage::Error {
                        message: "Message too large".to_string(),
                    })
                    .await;
                continue;
            }

            let sig_msg: SignalingMessage = match serde_json::from_str(&text) {
                Ok(m) => m,
                Err(_) => continue,
            };

            match sig_msg {
                SignalingMessage::Init {
                    device_id,
                    identity_id,
                    timestamp,
                    signature,
                } => {
                    let d_id = device_id.clone();
                    let device = match state.db_call(move |db| db.get_device_by_id(&d_id)).await {
                        Ok(Some(d)) => d,
                        _ => {
                            let _ = tx
                                .send(SignalingMessage::Error {
                                    message: "Device not recognized".to_string(),
                                })
                                .await;
                            continue;
                        }
                    };

                    if device.user_id != identity_id {
                        let _ = tx
                            .send(SignalingMessage::Error {
                                message: "Identity mismatch".to_string(),
                            })
                            .await;
                        continue;
                    }

                    let msg_to_sign =
                        format!("WS_INIT:{}:{}:{}", device_id, identity_id, timestamp);
                    let sig_bytes = hex::decode(&signature).unwrap_or_default();

                    if crate::auth::verify_signature(&msg_to_sign, &device.public_key, &sig_bytes) {
                        current_device_id = Some(device_id.clone());
                        state.peers.insert(device_id.clone(), tx.clone());
                        tracing::info!("Device {} registered for signaling", device_id);

                        let _ = tx.send(SignalingMessage::InitSuccess).await;

                        let state_clone = Arc::clone(&state);
                        let d_id = device_id.clone();
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let s_c = Arc::clone(&state_clone);
                            let d_id_c = d_id.clone();
                            if let Ok(messages) = s_c
                                .db_call(move |db| db.get_and_clear_mailbox(&d_id_c))
                                .await
                            {
                                for msg in messages {
                                    let _ = tx_clone
                                        .send(SignalingMessage::MailboxPush {
                                            payload: msg.payload,
                                        })
                                        .await;
                                }
                            }
                        });
                    } else {
                        let _ = tx
                            .send(SignalingMessage::Error {
                                message: "Invalid signature or device key".to_string(),
                            })
                            .await;
                    }
                }
                SignalingMessage::Offer {
                    target_device_id,
                    sdp,
                    ..
                } => {
                    if let Some(from_id) = &current_device_id {
                        let f_id = from_id.clone();
                        let t_id = target_device_id.clone();
                        let authorized = state
                            .db_call(move |db| db.is_authorized_to_message(&f_id, &t_id))
                            .await
                            .unwrap_or(false);

                        if authorized {
                            route_message(
                                &state,
                                &target_device_id,
                                SignalingMessage::Offer {
                                    target_device_id: target_device_id.clone(),
                                    sdp,
                                    from_device_id: Some(from_id.clone()),
                                },
                            )
                            .await;
                        }
                    }
                }
                SignalingMessage::Answer {
                    target_device_id,
                    sdp,
                    ..
                } => {
                    if let Some(from_id) = &current_device_id {
                        let f_id = from_id.clone();
                        let t_id = target_device_id.clone();
                        let authorized = state
                            .db_call(move |db| db.is_authorized_to_message(&f_id, &t_id))
                            .await
                            .unwrap_or(false);

                        if authorized {
                            route_message(
                                &state,
                                &target_device_id,
                                SignalingMessage::Answer {
                                    target_device_id: target_device_id.clone(),
                                    sdp,
                                    from_device_id: Some(from_id.clone()),
                                },
                            )
                            .await;
                        }
                    }
                }
                SignalingMessage::Candidate {
                    target_device_id,
                    candidate,
                    ..
                } => {
                    if let Some(from_id) = &current_device_id {
                        let f_id = from_id.clone();
                        let t_id = target_device_id.clone();
                        let authorized = state
                            .db_call(move |db| db.is_authorized_to_message(&f_id, &t_id))
                            .await
                            .unwrap_or(false);

                        if authorized {
                            route_message(
                                &state,
                                &target_device_id,
                                SignalingMessage::Candidate {
                                    target_device_id: target_device_id.clone(),
                                    candidate,
                                    from_device_id: Some(from_id.clone()),
                                },
                            )
                            .await;
                        }
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

pub async fn route_message(state: &Arc<AppState>, target_id: &str, msg: SignalingMessage) {
    let tx = state.peers.get(target_id).map(|r| r.value().clone());

    if let Some(tx) = tx {
        let _ = tx.send(msg).await;
    } else {
        tracing::warn!(
            "Target device {} not found for signaling, enqueuing to mailbox",
            target_id
        );
        // Queue in Offline Mailbox
        let payload = serde_json::to_vec(&msg).unwrap_or_default();
        if !payload.is_empty() {
            let state_clone = Arc::clone(state);
            let t_id = target_id.to_string();
            let _ = state_clone
                .db_call(move |db| db.enqueue_mailbox_message(&t_id, &payload))
                .await;
        }
    }
}
