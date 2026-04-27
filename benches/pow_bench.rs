use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use rayon::prelude::*;
use rayon::iter::IntoParallelIterator;

fn solve_pow(username: &str, difficulty: u32) -> u64 {
    let base_hasher = Sha256::new().chain_update(username.as_bytes());

    (0..u64::MAX)
        .into_par_iter()
        .find_map_any(|nonce: u64| {
            let mut hasher = base_hasher.clone();
            hasher.update(nonce.to_be_bytes());
            let result = hasher.finalize();

            if check_difficulty_fast(&result, difficulty) {
                Some(nonce)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn solve_pow_single(username: &str, difficulty: u32) -> u64 {
    let base_hasher = Sha256::new().chain_update(username.as_bytes());
    let mut nonce = 0u64;

    loop {
        for _ in 0..4 {
            let mut hasher = base_hasher.clone();
            hasher.update(nonce.to_be_bytes());
            let result = hasher.finalize();
            if check_difficulty_fast(&result, difficulty) {
                return nonce;
            }
            nonce += 1;
        }
    }
}

#[inline(always)]
fn check_difficulty_fast(hash: &[u8], difficulty: u32) -> bool {
    let first_64 = u64::from_be_bytes(hash[0..8].try_into().unwrap());
    
    if difficulty <= 64 {
        return first_64.leading_zeros() >= difficulty;
    }
    
    if first_64 != 0 { return false; }
    
    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    for &byte in &hash[8..full_bytes] {
        if byte != 0 {
            return false;
        }
    }

    if remaining_bits > 0 && (hash[full_bytes] >> (8 - remaining_bits)) != 0 {
        return false;
    }

    true
}


fn pow_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("PoW (D16)");
    group.bench_function("single_optimized", |b| {
        b.iter(|| solve_pow_single(black_box("testuser"), black_box(16)))
    });
    group.bench_function("parallel", |b| {
        b.iter(|| solve_pow(black_box("testuser"), black_box(16)))
    });
    group.finish();

    let mut group = c.benchmark_group("PoW (D20)");
    group.bench_function("single_optimized", |b| {
        b.iter(|| solve_pow_single(black_box("testuser"), black_box(20)))
    });
    group.bench_function("parallel", |b| {
        b.iter(|| solve_pow(black_box("testuser"), black_box(20)))
    });
    group.finish();
}

criterion_group!(benches, pow_benchmark);
criterion_main!(benches);
