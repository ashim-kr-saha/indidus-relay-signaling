use indidus_relay_signaling::{Config, server::run_with_listener};
use std::net::SocketAddr;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

pub struct TestServer {
    pub addr: SocketAddr,
    pub config: Config,
    _temp_db: NamedTempFile,
}

impl TestServer {
    pub async fn spawn() -> Self {
        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap().to_string();

        let mut config = Config::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.port = 0; // OS picks free port
        config.database.path = db_path;
        config.auth.registration_difficulty = 2; // Low for fast tests

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config_clone = config.clone();
        tokio::spawn(async move {
            let _ = run_with_listener(config_clone, listener).await;
        });

        // Wait for server to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        Self {
            addr,
            config,
            _temp_db: temp_db,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.addr.port(), path)
    }

    #[allow(dead_code)]
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/ws", self.addr.port())
    }
}

pub fn solve_pow(username: &str, difficulty: u32) -> u64 {
    use sha2::{Digest, Sha256};
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();

        let mut leading_zeros = 0;
        for &byte in result.as_slice() {
            let zeros = byte.leading_zeros();
            leading_zeros += zeros;
            if zeros < 8 {
                break;
            }
        }

        if leading_zeros >= difficulty {
            return nonce;
        }
        nonce += 1;
    }
}

#[allow(dead_code)]
pub fn generate_signature(
    private_key_bytes: &[u8],
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());

    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);

    let signing_key = SigningKey::from_bytes(private_key_bytes.try_into().unwrap());
    let signature = signing_key.sign(signed_data.as_bytes());
    hex::encode(signature.to_bytes())
}
