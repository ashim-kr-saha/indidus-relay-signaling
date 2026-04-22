use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Error::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Error::Auth(e) => (StatusCode::UNAUTHORIZED, e),
            Error::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            Error::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            Error::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
