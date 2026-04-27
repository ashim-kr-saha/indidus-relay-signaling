use criterion::{Criterion, criterion_group, criterion_main};
use indidus_relay_signaling::{
    Config,
    server::AppState,
    signaling::{SignalingMessage, route_message},
};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

fn bench_signaling_routing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Setup AppState with 1000 "online" peers
    let mut config = Config::default();
    config.database.path = ":memory:".to_string();
    let state = Arc::new(AppState::new(config).unwrap());

    let mut peer_ids = Vec::new();
    for i in 0..1000 {
        let device_id = format!("device_{}", i);
        let (tx, _rx) = mpsc::channel(100);
        state.peers.insert(device_id.clone(), tx);
        peer_ids.push(device_id);
    }

    let target_id = peer_ids[500].clone();
    let msg = SignalingMessage::Offer {
        target_device_id: target_id.clone(),
        sdp: "v=0...".to_string(),
        from_device_id: Some("device_0".to_string()),
    };

    c.bench_function("route_message_1000_peers", |b| {
        b.iter(|| {
            rt.block_on(async { route_message(&state, &target_id, msg.clone()).await })
        })
    });
}

criterion_group!(benches, bench_signaling_routing);
criterion_main!(benches);
