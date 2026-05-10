use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode, header},
    response::IntoResponse,
};
use mime_guess;
use rust_embed::RustEmbed;

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
            let mut builder = Response::builder().header(header::CONTENT_TYPE, mime.as_ref());

            // Add long-term caching for static assets in /pkg/ (WASM, JS, etc)
            if path.starts_with("pkg/") {
                builder =
                    builder.header(header::CACHE_CONTROL, "public, max-age=31536000, immutable");
            } else {
                // Short cache for HTML/index
                builder = builder.header(header::CACHE_CONTROL, "no-cache");
            }

            builder.body(Body::from(content.data)).unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("404 Not Found"))
            .unwrap(),
    }
}
