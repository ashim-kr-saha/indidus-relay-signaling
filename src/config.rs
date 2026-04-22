use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::{Result, Error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub turn: TurnConfig,
    pub relay: RelayConfig,
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
                jwt_secret: "dev_secret_change_me".to_string(),
                access_token_ttl: 900,
                refresh_token_ttl: 2592000,
                registration_difficulty: 16,
            },
            turn: TurnConfig {
                secret: "turn_secret_change_me".to_string(),
                realm: "indidus".to_string(),
            },
            relay: RelayConfig {
                storage_path: "./data/shares".to_string(),
                max_share_size: 10 * 1024 * 1024, // 10MB
                default_ttl: 3600, // 1 hour
            },
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
    pub jwt_secret: String,
    pub access_token_ttl: u64, // seconds
    pub refresh_token_ttl: u64, // seconds
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
