use crate::{Config, Error, Result, db::Db, signaling::SignalingMessage, viewer};
use dashmap::DashMap;
use tokio::sync::mpsc;

use axum::{
    Router,
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::trace::TraceLayer;

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub peers: DashMap<String, mpsc::Sender<SignalingMessage>>,
    pub pairing_sessions: mini_moka::sync::Cache<String, (Vec<u8>, Option<Vec<u8>>)>,
    pub prometheus_handle: PrometheusHandle,
}

impl AppState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let db = Db::open(&config.database.path)?;
        let prometheus_handle = match PrometheusBuilder::new().install_recorder() {
            Ok(h) => h,
            Err(_) => PrometheusBuilder::new().build_recorder().handle(),
        };

        let pairing_sessions = mini_moka::sync::Cache::builder()
            .max_capacity(1000)
            .time_to_live(std::time::Duration::from_secs(300)) // 5 minute TTL
            .build();

        Ok(Self {
            config,
            db,
            peers: DashMap::new(),
            pairing_sessions,
            prometheus_handle,
        })
    }

    pub async fn db_call<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Db) -> anyhow::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(|e| Error::Internal(format!("DB task error: {}", e)))?
            .map_err(|e| Error::Internal(e.to_string()))
    }
}

pub fn create_app(state: Arc<AppState>) -> Router {
    // Rate limiting configuration: 1 request every 2 seconds (30/min) per IP
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    Router::new()
        .route("/health", get(health_check))
        .route(
            "/register",
            post(crate::auth::register_identity).layer(GovernorLayer {
                config: governor_config.clone(),
            }),
        )
        .route(
            "/devices",
            post(crate::devices::register_device)
                .get(crate::devices::list_devices)
                .layer(GovernorLayer {
                    config: governor_config.clone(),
                }),
        )
        .route(
            "/devices/:id",
            post(crate::devices::revoke_device).layer(GovernorLayer {
                config: governor_config.clone(),
            }),
        )
        .route(
            "/friends",
            post(crate::friends::send_friend_request)
                .get(crate::friends::list_friends)
                .layer(GovernorLayer {
                    config: governor_config.clone(),
                }),
        )
        .route(
            "/friends/accept/:username",
            post(crate::friends::accept_friend_request),
        )
        .route("/friends/:username", delete(crate::friends::remove_friend))
        .route("/turn", get(crate::turn::get_turn_credentials))
        .route("/audit", get(crate::audit::get_audit_logs))
        .route("/push/:device_id", get(crate::push::push_stream))
        .route(
            "/vaults/invite",
            post(crate::vaults::invite_to_vault).layer(GovernorLayer {
                config: governor_config.clone(),
            }),
        )
        .route("/vaults/invites", get(crate::vaults::list_vault_invites))
        .route(
            "/vaults/invites/:id/accept",
            post(crate::vaults::accept_vault_invite),
        )
        .route(
            "/vaults/:id/members",
            get(crate::vaults::list_vault_members),
        )
        .route("/ws", get(crate::signaling::signaling_handler))
        .route("/mailbox", post(crate::mailbox::enqueue_message))
        .route("/mailbox/:device_id", get(crate::mailbox::get_mailbox))
        .route(
            "/pairing/initiate",
            post(crate::pairing::initiate_pairing).layer(GovernorLayer {
                config: governor_config.clone(),
            }),
        )
        .route(
            "/pairing/:session_id/respond",
            post(crate::pairing::respond_pairing),
        )
        .route(
            "/pairing/:session_id/poll",
            get(crate::pairing::poll_pairing),
        )
        .route("/shares", post(crate::relay::upload_share))
        .route(
            "/shares/:id",
            get(crate::relay::download_share).delete(crate::relay::revoke_share),
        )
        .route(
            "/shares/:id/acknowledge",
            post(crate::relay::acknowledge_share),
        )
        .route("/v/:id", get(viewer::serve_viewer))
        .route("/pkg/*path", get(viewer::static_handler))
        .route("/metrics", get(metrics_handler))
        .layer(TraceLayer::new_for_http())
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB global limit
        .with_state(state)
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    run_with_listener(config, listener).await
}

pub async fn run_with_listener(
    config: Config,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(config)?);
    let app = create_app(state);

    tracing::info!("Starting server on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.prometheus_handle.render()
}
