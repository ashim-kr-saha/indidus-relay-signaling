use criterion::{Criterion, black_box, criterion_group, criterion_main};
use indidus_relay_signaling::db::Db;
use std::time::Duration;

fn bench_relay_db(c: &mut Criterion) {
    let db = Db::open(":memory:").unwrap();
    let payload = vec![0u8; 64 * 1024]; // 64KB payload

    c.bench_function("db_create_share_64kb", |b| {
        b.iter(|| {
            let _ = db.create_share(
                black_box(&payload),
                black_box(None),
                black_box(None),
                black_box(None),
            );
        })
    });

    let share_id = db.create_share(&payload, None, None, None).unwrap();

    c.bench_function("db_get_share_64kb", |b| {
        b.iter(|| {
            let _ = db.get_share(black_box(&share_id));
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = bench_relay_db
}
criterion_main!(benches);
