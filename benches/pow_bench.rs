use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sha2::{Digest, Sha256};

fn solve_pow(username: &str, difficulty: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();

        let mut leading_zeros = 0;
        for byte in result {
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

fn pow_benchmark(c: &mut Criterion) {
    c.bench_function("solve_pow_d16", |b| {
        b.iter(|| solve_pow(black_box("testuser"), black_box(16)))
    });
}

criterion_group!(benches, pow_benchmark);
criterion_main!(benches);
