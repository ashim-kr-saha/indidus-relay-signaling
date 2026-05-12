use crate::{Result, server::AppState};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, Uri},
    response::sse::{Event, KeepAlive, Sse},
};
use base64::prelude::*;
use futures::stream::{self, Stream};
use indidus_relay_proto::signaling::{MailboxEntry, MailboxResponse};
use prost::Message;
use std::sync::Arc;
use std::{convert::Infallible, time::Duration};

pub async fn push_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    Path(device_id): Path<String>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let _identity_id =
        crate::auth::authenticate_identity(&state, &headers, method.as_str(), uri.path(), &[])
            .await?;

    let stream = stream::unfold((state, device_id), |(state, device_id)| async move {
        loop {
            // Check mailbox
            if let Ok(messages) = state.db.get_and_clear_mailbox(&device_id)
                && !messages.is_empty()
            {
                let entries = messages
                    .into_iter()
                    .map(|m| MailboxEntry {
                        id: m.id,
                        payload: m.payload,
                        created_at: m.created_at,
                    })
                    .collect();

                let response = MailboxResponse { messages: entries };
                let mut buf = Vec::new();
                response.encode(&mut buf).unwrap();
                let b64 = BASE64_STANDARD.encode(buf);

                let event = Event::default().data(b64).event("mailbox_update");

                return Some((Ok(event), (state, device_id)));
            }

            // Wait before next poll
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
