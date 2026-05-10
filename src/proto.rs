use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use prost::Message;

pub struct Protobuf<T>(pub T);

impl<S, T> FromRequest<S> for Protobuf<T>
where
    T: Message + Default,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to read body: {}", e),
            )
        })?;

        let message = T::decode(bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode protobuf: {}", e),
            )
        })?;

        Ok(Protobuf(message))
    }
}

impl<T> IntoResponse for Protobuf<T>
where
    T: Message,
{
    fn into_response(self) -> Response {
        let mut buf = Vec::new();
        if let Err(e) = self.0.encode(&mut buf) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode protobuf: {}", e),
            )
                .into_response();
        }

        let mut res = buf.into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-protobuf"),
        );
        res
    }
}
