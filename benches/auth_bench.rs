use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indidus_relay_signaling::auth::validate_request_signature;
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Sha256, Digest};
use rand::thread_rng;

fn bench_auth_validation(c: &mut Criterion) {
    let mut rng = thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key();
    let pk_bytes = public_key.as_bytes();
    
    let method = "POST";
    let path = "/api/test/path/long/enough/to/be/realistic";
    let timestamp = "1714077600"; // Fixed timestamp
    let body = vec![0u8; 1024]; // 1KB body
    
    // Pre-calculate signature
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let body_hash = hex::encode(hasher.finalize());
    let signed_data = format!("{}|{}|{}|{}", method, path, timestamp, body_hash);
    let signature = signing_key.sign(signed_data.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    c.bench_function("validate_request_signature_1kb", |b| {
        b.iter(|| {
            let _ = validate_request_signature(
                black_box(pk_bytes),
                black_box(method),
                black_box(path),
                black_box(timestamp),
                black_box(&body),
                black_box(&sig_hex),
            );
        })
    });
}

criterion_group!(benches, bench_auth_validation);
criterion_main!(benches);
