use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub turn: TurnConfig,
    pub relay: RelayConfig,
    #[serde(default)]
    pub gate: GateConfig,
    pub rate_limit: RateLimitConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                path: "signaling.db".to_string(),
            },
            auth: AuthConfig {
                registration_difficulty: 16,
            },
            turn: TurnConfig {
                secret: "turn_secret_change_me".to_string(),
                realm: "indidus".to_string(),
            },
            relay: RelayConfig {
                storage_path: "./data/shares".to_string(),
                max_share_size: 10 * 1024 * 1024, // 10MB
                default_ttl: 3600,                // 1 hour
            },
            gate: GateConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub registration_difficulty: u32, // number of leading zero bits
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnConfig {
    pub secret: String,
    pub realm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub storage_path: String,
    pub max_share_size: usize,
    pub default_ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub max_concurrent_connections: Option<usize>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 1,
            burst_size: 5,
            max_concurrent_connections: Some(50_000), // Default safe limit for 4GB RAM
        }
    }
}

/// Configuration for Gate server mTLS integration.
/// When `mtls_required` is true, the signaling server expects the reverse proxy
/// (Caddy) to verify client certificates and forward the result via headers.
/// When false, PoW-only mode is used (for self-hosters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    /// When true, registration requires a valid client certificate
    /// verified by the reverse proxy (X-Client-Cert-Verified header).
    pub mtls_required: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            mtls_required: false,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        if let Some(p) = path {
            let content = std::fs::read_to_string(p).map_err(|e| Error::Internal(e.to_string()))?;
            toml::from_str(&content).map_err(|e| Error::Internal(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }
}
