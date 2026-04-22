use crate::{Config, db::Db};
use axum::{
    routing::{get, post},
    Router,
    extract::State,
    response::IntoResponse,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

type PeerMap = Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::signaling::SignalingMessage>>>>;
type PairingMap = Arc<tokio::sync::Mutex<std::collections::HashMap<String, (Vec<u8>, Option<Vec<u8>>)>>>;

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub peers: PeerMap,
    pub pairing_sessions: PairingMap,
    pub prometheus_handle: PrometheusHandle,
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    run_with_listener(config, listener).await
}

pub async fn run_with_listener(config: Config, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    // Initialize Prometheus exporter
    let prometheus_handle = match PrometheusBuilder::new().install_recorder() {
        Ok(h) => h,
        Err(_) => PrometheusBuilder::new().build_recorder().handle(),
    };

    let db = Db::open(&config.database.path)?;
    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        peers: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        pairing_sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        prometheus_handle,
    });

    // Rate limiting configuration: 1 request every 2 seconds (30/min) per IP
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/auth/register", post(crate::auth::register).layer(GovernorLayer { config: governor_config.clone() }))
        .route("/auth/login", post(crate::auth::login).layer(GovernorLayer { config: governor_config.clone() }))
        .route("/auth/refresh", post(crate::auth::refresh))
        .route("/auth/logout", post(crate::auth::logout))
        .route("/devices", post(crate::devices::register_device).get(crate::devices::list_devices))
        .route("/devices/:id", post(crate::devices::revoke_device))
        .route("/friends", post(crate::friends::send_friend_request).get(crate::friends::list_friends))
        .route("/friends/accept/:username", post(crate::friends::accept_friend_request))
        .route("/turn", get(crate::turn::get_turn_credentials))
        .route("/audit", get(crate::audit::get_audit_logs))
        .route("/push/:device_id", get(crate::push::push_stream))
        .route("/vaults/invite", post(crate::vaults::invite_to_vault))
        .route("/vaults/invites", get(crate::vaults::list_vault_invites))
        .route("/vaults/invites/:id/accept", post(crate::vaults::accept_vault_invite))
        .route("/vaults/:id/members", get(crate::vaults::list_vault_members))
        .route("/ws", get(crate::signaling::ws_handler))
        .route("/mailbox", post(crate::mailbox::enqueue_message))
        .route("/mailbox/:device_id", get(crate::mailbox::get_mailbox))
        .route("/pairing/initiate", post(crate::pairing::initiate_pairing).layer(GovernorLayer { config: governor_config.clone() }))
        .route("/pairing/:session_id/respond", post(crate::pairing::respond_pairing))
        .route("/pairing/:session_id/poll", get(crate::pairing::poll_pairing))
        .route("/shares", post(crate::relay::upload_share))
        .route("/shares/:id", get(crate::relay::download_share).delete(crate::relay::revoke_share))
        .route("/metrics", get(metrics_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!("Starting server on {}", listener.local_addr()?);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.prometheus_handle.render()
}
