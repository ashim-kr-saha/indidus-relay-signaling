use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indidus_relay_signaling::{Config, server::AppState};
use tokio::runtime::Runtime;
use tokio::net::TcpListener;
use tempfile::NamedTempFile;
use reqwest::Client;
use ed25519_dalek::{SigningKey, Signer};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use rand::{Rng, thread_rng};
use std::sync::Arc;
use indidus_proto::signaling::RegisterIdentityRequest;
use prost::Message;

pub struct TestServer {
    pub url: String,
    pub config: Config,
    _temp_db: NamedTempFile,
    pub runtime: Runtime,
}

impl TestServer {
    pub fn setup() -> Self {
        let rt = Runtime::new().unwrap();
        let temp_db = NamedTempFile::new().unwrap();
        let db_path = temp_db.path().to_str().unwrap().to_string();

        let mut config = Config::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.port = 0;
        config.database.path = db_path;
        config.auth.registration_difficulty = 8; // Low for endpoint bench
        config.rate_limit.enabled = false;

        let listener = rt.block_on(async {
            TcpListener::bind("127.0.0.1:0").await.unwrap()
        });
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);

        let config_clone = config.clone();
        rt.spawn(async move {
            let state = Arc::new(AppState::new(config_clone).unwrap());
            let app = indidus_relay_signaling::server::create_app(state);
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });

        Self {
            url,
            config,
            _temp_db: temp_db,
            runtime: rt,
        }
    }
}

fn solve_pow(username: &str, difficulty: u32) -> u64 {
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
            if zeros < 8 { break; }
        }
        if leading_zeros >= difficulty { return nonce; }
        nonce += 1;
    }
}

fn generate_signature(pk_bytes: &[u8], method: &str, path: &str, timestamp: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());
    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);
    let signing_key = SigningKey::from_bytes(pk_bytes.try_into().unwrap());
    let signature = signing_key.sign(signed_data.as_bytes());
    hex::encode(signature.to_bytes())
}

fn bench_signaling_endpoints(c: &mut Criterion) {
    let server = TestServer::setup();
    let client = Client::new();

    // 1. /register
    c.bench_function("endpoint_signaling_register", |b| {
        b.to_async(&server.runtime).iter(|| async {
            let mut rng = thread_rng();
            let username = format!("user_{}", rng.r#gen::<u64>());
            let signing_key = SigningKey::generate(&mut rng);
            let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
            
            let pow_nonce = solve_pow(&username, server.config.auth.registration_difficulty);
            
            let req = RegisterIdentityRequest {
                username: username.clone(),
                root_public_key: pk_hex,
                pow_nonce,
            };
            let mut buf = Vec::new();
            req.encode(&mut buf).unwrap();

            let resp = client.post(format!("{}/register", server.url))
                .header("Content-Type", "application/x-protobuf")
                .body(buf)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 201);
            black_box(resp);
        });
    });

    // 2. /devices (list)
    let (fixed_username, fixed_signing_key) = server.runtime.block_on(async {
        let username = "fixed_user";
        let mut rng = rand::thread_rng();
        let sk = SigningKey::generate(&mut rng);
        let pk_hex = hex::encode(sk.verifying_key().as_bytes());
        let pow = solve_pow(username, server.config.auth.registration_difficulty);
        
        let req = RegisterIdentityRequest {
            username: username.to_string(),
            root_public_key: pk_hex,
            pow_nonce: pow,
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        client.post(format!("{}/register", server.url))
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send().await.unwrap();
        (username.to_string(), sk)
    });
    let fixed_pk_hex = hex::encode(fixed_signing_key.verifying_key().as_bytes());

    c.bench_function("endpoint_signaling_list_devices", |b| {
        b.to_async(&server.runtime).iter(|| async {
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
            let signature = generate_signature(&fixed_signing_key.to_bytes(), "GET", "/devices", &timestamp, &[]);
            let resp = client.get(format!("{}/devices", server.url))
                .header("X-Identity", &fixed_username)
                .header("X-Public-Key", &fixed_pk_hex)
                .header("X-Timestamp", &timestamp)
                .header("X-Signature", &signature)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            black_box(resp);
        });
    });
}

fn bench_endpoints(c: &mut Criterion) {
    bench_signaling_endpoints(c);
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_endpoints
}
criterion_main!(benches);
