use rust_embed::RustEmbed;
use axum::{
    body::Body,
    extract::Path,
    http::{header, StatusCode, Response},
    response::IntoResponse,
};
use mime_guess;

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

pub async fn serve_viewer() -> impl IntoResponse {
    serve_asset("index.html".to_string()).await
}

pub async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    serve_asset(format!("pkg/{}", path)).await
}

async fn serve_asset(path: String) -> impl IntoResponse {
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("404 Not Found"))
            .unwrap(),
    }
}
