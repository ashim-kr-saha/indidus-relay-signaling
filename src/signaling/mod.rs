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
use std::sync::Arc;
use tokio::sync::mpsc;
use indidus_proto::signaling::{
    SignalingMessage, 
    signaling_message::Content,
    InitSuccess, Offer, Answer, Candidate, MailboxPush, ErrorMessage
};
use prost::Message as _;

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
            let mut buf = Vec::new();
            if msg.encode(&mut buf).is_ok() {
                if sender.send(Message::Binary(buf.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut current_device_id: Option<String> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        let sig_msg: SignalingMessage = match msg {
            Message::Binary(bin) => {
                match SignalingMessage::decode(bin) {
                    Ok(m) => m,
                    Err(_) => continue,
                }
            }
            _ => continue,
        };

        if let Some(content) = sig_msg.content {
            handle_signaling_message(
                &state,
                content,
                &tx,
                &mut current_device_id,
            ).await;
        }
    }

    // Cleanup
    if let Some(device_id) = current_device_id {
        state.peers.remove(&device_id);
        tracing::info!("Device {} disconnected from signaling", device_id);
    }
    send_task.abort();
}

#[async_recursion::async_recursion]
async fn handle_signaling_message(
    state: &Arc<AppState>,
    content: Content,
    tx: &mpsc::Sender<SignalingMessage>,
    current_device_id: &mut Option<String>,
) {
    match content {
        Content::Init(init) => {
            // 1. Capacity Check: Prevent memory exhaustion
            let max_peers = state.config.rate_limit.max_concurrent_connections.unwrap_or(50_000);
            if state.peers.len() >= max_peers && !state.peers.contains_key(&init.device_id) {
                let _ = tx.send(SignalingMessage {
                    content: Some(Content::ErrorMessage(ErrorMessage {
                        message: "Server at maximum capacity. Please retry later.".to_string(),
                    }))
                }).await;
                return;
            }

            // 2. Admission Control: Prevent CPU saturation during reconnection spikes
            let handshake_timeout = std::time::Duration::from_secs(5);
            let _permit = match tokio::time::timeout(handshake_timeout, state.handshake_semaphore.acquire()).await {
                Ok(Ok(p)) => p,
                _ => {
                    tracing::warn!("Handshake timeout or throttle active for {}", init.device_id);
                    let _ = tx.send(SignalingMessage {
                        content: Some(Content::ErrorMessage(ErrorMessage {
                            message: "Server busy. Please backoff and retry.".to_string(),
                        }))
                    }).await;
                    return;
                }
            };

            let d_id = init.device_id.clone();
            let device = match state.db_call(move |db| db.get_device_by_id(&d_id)).await {
                Ok(Some(d)) => d,
                _ => {
                    let _ = tx.send(SignalingMessage {
                        content: Some(Content::ErrorMessage(ErrorMessage {
                            message: "Device not recognized".to_string(),
                        }))
                    }).await;
                    return;
                }
            };

            if device.user_id != init.identity_id {
                let _ = tx.send(SignalingMessage {
                    content: Some(Content::ErrorMessage(ErrorMessage {
                        message: "Identity mismatch".to_string(),
                    }))
                }).await;
                return;
            }

            let msg_to_sign = format!("WS_INIT:{}:{}:{}", init.device_id, init.identity_id, init.timestamp);
            let sig_bytes = hex::decode(&init.signature).unwrap_or_default();
            let pub_key_hex = device.public_key.clone();

            // CPU Intensive Signature Verification with timeout
            let sig_verified = match tokio::time::timeout(handshake_timeout, tokio::task::spawn_blocking(move || {
                crate::auth::verify_signature(&msg_to_sign, &pub_key_hex, &sig_bytes)
            })).await {
                Ok(Ok(v)) => v,
                _ => false,
            };

            if sig_verified {
                *current_device_id = Some(init.device_id.clone());
                state.peers.insert(init.device_id.clone(), tx.clone());
                tracing::info!("Device {} registered for signaling", init.device_id);

                let _ = tx.send(SignalingMessage {
                    content: Some(Content::InitSuccess(InitSuccess {}))
                }).await;

                let state_clone = Arc::clone(state);
                let d_id = init.device_id.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    if let Ok(messages) = state_clone.db_call(move |db| db.get_and_clear_mailbox(&d_id)).await {
                        if !messages.is_empty() {
                            let batch = messages.into_iter().map(|msg| SignalingMessage {
                                content: Some(Content::MailboxPush(MailboxPush {
                                    payload: msg.payload,
                                }))
                            }).collect();

                            let _ = tx_clone.send(SignalingMessage {
                                content: Some(Content::Batch(indidus_proto::signaling::Batch {
                                    messages: batch,
                                }))
                            }).await;
                        }
                    }
                });
            } else {
                let _ = tx.send(SignalingMessage {
                    content: Some(Content::ErrorMessage(ErrorMessage {
                        message: "Invalid signature or device key".to_string(),
                    }))
                }).await;
            }
        }
        Content::Offer(offer) => {
            if let Some(from_id) = current_device_id {
                let f_id = from_id.clone();
                let t_id = offer.target_device_id.clone();
                let authorized = state.db_call(move |db| db.is_authorized_to_message(&f_id, &t_id)).await.unwrap_or(false);

                if authorized {
                    route_message(state, &offer.target_device_id, SignalingMessage {
                        content: Some(Content::Offer(Offer {
                            target_device_id: offer.target_device_id.clone(),
                            sdp: offer.sdp,
                            from_device_id: Some(from_id.clone()),
                        }))
                    }).await;
                }
            }
        }
        Content::Answer(answer) => {
            if let Some(from_id) = current_device_id {
                let f_id = from_id.clone();
                let t_id = answer.target_device_id.clone();
                let authorized = state.db_call(move |db| db.is_authorized_to_message(&f_id, &t_id)).await.unwrap_or(false);

                if authorized {
                    route_message(state, &answer.target_device_id, SignalingMessage {
                        content: Some(Content::Answer(Answer {
                            target_device_id: answer.target_device_id.clone(),
                            sdp: answer.sdp,
                            from_device_id: Some(from_id.clone()),
                        }))
                    }).await;
                }
            }
        }
        Content::Candidate(candidate) => {
            if let Some(from_id) = current_device_id {
                let f_id = from_id.clone();
                let t_id = candidate.target_device_id.clone();
                let authorized = state.db_call(move |db| db.is_authorized_to_message(&f_id, &t_id)).await.unwrap_or(false);

                if authorized {
                    route_message(state, &candidate.target_device_id, SignalingMessage {
                        content: Some(Content::Candidate(Candidate {
                            target_device_id: candidate.target_device_id.clone(),
                            candidate: candidate.candidate,
                            from_device_id: Some(from_id.clone()),
                        }))
                    }).await;
                }
            }
        }
        Content::Batch(batch) => {
            for msg in batch.messages {
                if let Some(content) = msg.content {
                    handle_signaling_message(state, content, tx, current_device_id).await;
                }
            }
        }
        _ => {}
    }
}

pub async fn route_message(state: &Arc<AppState>, target_id: &str, msg: SignalingMessage) {
    let tx = state.peers.get(target_id).map(|r| r.value().clone());

    if let Some(tx) = tx {
        let _ = tx.send(msg).await;
    } else {
        tracing::warn!("Target device {} not found for signaling, enqueuing to mailbox", target_id);
        let mut payload = Vec::new();
        if msg.encode(&mut payload).is_ok() {
            let state_clone = Arc::clone(state);
            let t_id = target_id.to_string();
            let _ = state_clone.db_call(move |db| db.enqueue_mailbox_message(&t_id, &payload)).await;
        }
    }
}
