use crate::{Result, server::AppState, devices::validate_token};
use axum::{
    extract::{State, Path},
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::{self, Stream};
use std::{convert::Infallible, time::Duration};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use std::sync::Arc;

pub async fn push_stream(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(device_id): Path<String>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let _user_id = validate_token(auth.token(), &state.config.auth.jwt_secret)?;

    let stream = stream::unfold((state, device_id), |(state, device_id)| async move {
        loop {
            // Check mailbox
            if let Ok(messages) = state.db.get_mailbox_messages(&device_id) && !messages.is_empty() {
                let event = Event::default()
                    .data(serde_json::to_string(&messages).unwrap_or_default())
                    .event("mailbox_update");
                
                let _ = state.db.clear_mailbox(&device_id);
                return Some((Ok(event), (state, device_id)));
            }
            
            // Wait before next poll
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
